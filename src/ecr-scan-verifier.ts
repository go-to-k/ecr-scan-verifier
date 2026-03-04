import { join } from 'path';
import { Annotations, Aspects, CustomResource, Duration, IgnoreMode, Stack } from 'aws-cdk-lib';
import { IRepository } from 'aws-cdk-lib/aws-ecr';
import { Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import {
  Architecture,
  AssetCode,
  Handler,
  Runtime,
  SingletonFunction,
} from 'aws-cdk-lib/aws-lambda';
import { ILogGroup } from 'aws-cdk-lib/aws-logs';
import { ITopic } from 'aws-cdk-lib/aws-sns';
import { Provider } from 'aws-cdk-lib/custom-resources';
import { Construct, IConstruct } from 'constructs';
import { ScannerCustomResourceProps } from './custom-resource-props';
import { ScanConfig } from './scan-config';
import { ScanLogsOutput } from './scan-logs-output';
import { SignatureVerification } from './signature-verification';
import { Severity } from './types';

/**
 * Properties for EcrScanVerifier Construct.
 */
export interface EcrScanVerifierProps {
  /**
   * ECR Repository to scan.
   */
  readonly repository: IRepository;

  /**
   * Image tag or digest to scan.
   *
   * You can specify a tag (e.g., 'v1.0', 'latest') or a digest (e.g., 'sha256:abc123...').
   * If the value starts with 'sha256:', it is treated as a digest.
   *
   * @default 'latest'
   */
  readonly imageTag?: string;

  /**
   * Scan configuration — choose based on your ECR repository/account settings:
   *
   * - `ScanConfig.basic()` (default: `startScan: true`) — starts a scan via the ECR API.
   *   No additional ECR configuration required.
   * - `ScanConfig.basic({ startScan: false })` — polls for existing results.
   *   Requires Basic scan-on-push to be enabled on the repository.
   * - `ScanConfig.enhanced()` — uses Amazon Inspector enhanced scanning.
   *   Requires Enhanced scanning to be enabled on the account.
   *
   * If the required scanning configuration is not in place and no prior scan results exist,
   * the deployment will fail.
   */
  readonly scanConfig: ScanConfig;

  /**
   * Severity threshold for vulnerability detection.
   *
   * If vulnerabilities at or above any of the specified severity levels are found,
   * the scan will be considered as having found vulnerabilities.
   *
   * @default [Severity.CRITICAL]
   */
  readonly severity?: Severity[];

  /**
   * Whether to fail the CloudFormation deployment if vulnerabilities are detected
   * above the severity threshold.
   *
   * @default true
   */
  readonly failOnVulnerability?: boolean;

  /**
   * Finding IDs to ignore during vulnerability evaluation.
   *
   * For basic scanning: CVE IDs (e.g., 'CVE-2023-37920')
   * For enhanced scanning: finding ARNs or CVE IDs
   *
   * @default - no findings ignored
   */
  readonly ignoreFindings?: string[];

  /**
   * Configuration for scan logs output.
   *
   * @default - scan logs output to default log group created by Scanner Lambda.
   */
  readonly scanLogsOutput?: ScanLogsOutput;

  /**
   * Signature verification configuration for the container image.
   *
   * Verifies the image signature before scanning using Notation (AWS Signer) or Cosign (Sigstore).
   * Requires Docker to be available at deploy time for building the Lambda function.
   *
   * @default - no signature verification
   */
  readonly signatureVerification?: SignatureVerification;

  /**
   * The Scanner Lambda function's default log group.
   *
   * If you use EcrScanVerifier construct multiple times in the same stack,
   * you must specify the same log group for each construct.
   *
   * @default - Scanner Lambda creates the default log group.
   */
  readonly defaultLogGroup?: ILogGroup;

  /**
   * Suppress errors during rollback scanner Lambda execution.
   *
   * @default true
   */
  readonly suppressErrorOnRollback?: boolean;

  /**
   * SNS topic for vulnerability notification.
   *
   * Supports AWS Chatbot message format.
   *
   * @default - no notification
   */
  readonly vulnsNotificationTopic?: ITopic;

  /**
   * Constructs to block if vulnerabilities are detected.
   *
   * @default - no constructs to block
   */
  readonly blockConstructs?: IConstruct[];
}

/**
 * A Construct that verifies container image scan findings with ECR image scanning.
 * It uses a Lambda function as a Custom Resource provider to call ECR scan APIs
 * and evaluate scan findings.
 */
export class EcrScanVerifier extends Construct {
  private readonly defaultLogGroup?: ILogGroup;

  constructor(scope: Construct, id: string, props: EcrScanVerifierProps) {
    super(scope, id);

    this.defaultLogGroup = props.defaultLogGroup;
    const lambdaPurpose = 'Custom::EcrScanVerifierCustomResourceLambda';

    const customResourceLambda = new SingletonFunction(this, 'CustomResourceLambda', {
      uuid: 'c56cee6b-6775-541b-d179-c1535d88a0c8',
      lambdaPurpose,
      runtime: Runtime.FROM_IMAGE,
      handler: Handler.FROM_IMAGE,
      code: AssetCode.fromAssetImage(join(__dirname, '../assets/lambda'), {
        platform: Platform.LINUX_ARM64,
        ignoreMode: IgnoreMode.DOCKER,
      }),
      architecture: Architecture.ARM_64,
      timeout: Duration.seconds(900),
      retryAttempts: 0,
      logGroup: this.defaultLogGroup,
    });

    const imageTag = props.imageTag ?? 'latest';

    const scanConfigOutput = props.scanConfig.bind();

    // Validate: signatureOnly requires signatureVerification
    if (scanConfigOutput.scanType === 'SIGNATURE_ONLY' && !props.signatureVerification) {
      throw new Error(
        'ScanConfig.signatureOnly() requires signatureVerification to be specified. ' +
          'Use SignatureVerification.notation(), SignatureVerification.cosignPublicKey(), or SignatureVerification.cosignKms().',
      );
    }

    const outputOptions = props.scanLogsOutput?.bind(customResourceLambda);

    // SBOM output (from scanConfigOutput)
    const sbomConfig = scanConfigOutput.sbomOutput?.bind(customResourceLambda);

    // Signature verification
    const signatureVerificationConfig = props.signatureVerification?.bind(customResourceLambda);

    // ECR permissions
    // DescribeImages is always required (for digest resolution)
    // DescribeImageScanFindings is only required for scanning modes
    const ecrActions = ['ecr:DescribeImages'];
    if (scanConfigOutput.scanType !== 'SIGNATURE_ONLY') {
      ecrActions.push('ecr:DescribeImageScanFindings');
    }
    customResourceLambda.addToRolePolicy(
      new PolicyStatement({
        actions: ecrActions,
        resources: [props.repository.repositoryArn],
      }),
    );

    if (scanConfigOutput.scanType === 'ENHANCED') {
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['inspector2:ListCoverage', 'inspector2:ListFindings'],
          resources: ['*'],
        }),
      );
    }

    if (scanConfigOutput.startScan) {
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['ecr:StartImageScan'],
          resources: [props.repository.repositoryArn],
        }),
      );
    }

    // Signature verification permissions
    if (signatureVerificationConfig) {
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['ecr:GetAuthorizationToken'],
          resources: ['*'],
        }),
      );
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'],
          resources: [props.repository.repositoryArn],
        }),
      );

      if (signatureVerificationConfig.type === 'NOTATION') {
        customResourceLambda.addToRolePolicy(
          new PolicyStatement({
            actions: ['signer:GetRevocationStatus'],
            resources: ['*'],
          }),
        );
      }
      // Cosign KMS permissions are granted by key.grant() in bind()
    }

    // SBOM export permissions (Inspector CreateSbomExport)
    if (sbomConfig) {
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['inspector2:CreateSbomExport', 'inspector2:GetSbomExport'],
          resources: ['*'],
        }),
      );
    }

    if (props.vulnsNotificationTopic) {
      props.vulnsNotificationTopic.grantPublish(customResourceLambda);
    }

    const suppressErrorOnRollback = props.suppressErrorOnRollback ?? true;
    if (suppressErrorOnRollback) {
      customResourceLambda.addToRolePolicy(
        new PolicyStatement({
          actions: ['cloudformation:DescribeStacks'],
          resources: [Stack.of(this).stackId],
        }),
      );
    }

    // Check for defaultLogGroup consistency across multiple instances in the same stack
    Aspects.of(Stack.of(this)).add({
      visit: (node) => {
        if (
          node instanceof EcrScanVerifier &&
          node._defaultLogGroup?.node.path !== this.defaultLogGroup?.node.path
        ) {
          Annotations.of(this).addWarningV2(
            '@ecr-scan-verifier:duplicateLambdaDefaultLogGroup',
            "You have to set the same log group for 'defaultLogGroup' for each EcrScanVerifier construct in the same stack.",
          );
        }
      },
    });

    const verifierProvider = new Provider(this, 'Provider', {
      onEventHandler: customResourceLambda,
    });

    const verifierProperties: ScannerCustomResourceProps = {
      addr: this.node.addr,
      repositoryName: props.repository.repositoryName,
      imageTag,
      scanType: scanConfigOutput.scanType,
      startScan: String(scanConfigOutput.startScan),
      severity: props.severity ?? [Severity.CRITICAL],
      failOnVulnerability: String(props.failOnVulnerability ?? true),
      ignoreFindings: props.ignoreFindings ?? [],
      output: outputOptions,
      sbom: sbomConfig,
      signatureVerification: signatureVerificationConfig
        ? {
            type: signatureVerificationConfig.type,
            trustedIdentities: signatureVerificationConfig.trustedIdentities,
            publicKey: signatureVerificationConfig.publicKey,
            kmsKeyArn: signatureVerificationConfig.kmsKeyArn,
            failOnUnsigned: String(signatureVerificationConfig.failOnUnsigned),
            cosignIgnoreTlog:
              signatureVerificationConfig.cosignIgnoreTlog !== undefined
                ? String(signatureVerificationConfig.cosignIgnoreTlog)
                : undefined,
          }
        : undefined,
      suppressErrorOnRollback: String(suppressErrorOnRollback),
      vulnsTopicArn: props.vulnsNotificationTopic?.topicArn,
      defaultLogGroupName:
        this.defaultLogGroup?.logGroupName ?? `/aws/lambda/${customResourceLambda.functionName}`,
    };

    new CustomResource(this, 'Resource', {
      resourceType: 'Custom::EcrScanVerifier',
      properties: verifierProperties,
      serviceToken: verifierProvider.serviceToken,
    });

    props.blockConstructs?.forEach((construct) => {
      construct.node.addDependency(this);
    });
  }

  /** @internal */
  get _defaultLogGroup(): ILogGroup | undefined {
    return this.defaultLogGroup;
  }
}
