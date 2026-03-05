import { CdkCustomResourceHandler, CdkCustomResourceResponse } from 'aws-lambda';
import { ScannerCustomResourceProps } from '../../../src/custom-resource-props';
import {
  ScanLogsOutputOptions,
  ScanLogsOutputType,
  CloudWatchLogsOutputOptions,
  S3OutputOptions,
} from '../../../src/scan-logs-output';
import { startAndWaitForScan, waitForScanResults, ScanFindings } from './ecr-scan';
import { evaluateFindings, formatScanSummary } from './findings-evaluator';
import { outputScanLogsToCWLogs, outputSignatureVerificationLogsToCWLogs } from './cloudwatch-logs';
import { outputScanLogsToS3, outputSignatureVerificationLogsToS3, SbomContent } from './s3-output';
import { sendVulnsNotification } from './sns-notification';
import { isRollbackInProgress } from './cloudformation-utils';
import { exportSbom } from './sbom-export';
import { verifySignature, SignatureVerificationResult } from './signature-verification';
import { ScanLogsDetails, SignatureVerificationLogsDetails } from './types';
import { Logger } from './logger';

export const handler: CdkCustomResourceHandler = async function (event) {
  const requestType = event.RequestType;
  const props = event.ResourceProperties as unknown as ScannerCustomResourceProps;

  if (!props.addr || !props.repositoryName) {
    throw new Error('addr and repositoryName are required.');
  }

  const funcResponse: CdkCustomResourceResponse = {
    PhysicalResourceId: props.addr,
    Data: {} as { [key: string]: string },
  };

  if (requestType !== 'Create' && requestType !== 'Update') {
    return funcResponse;
  }

  const pollingIntervalSeconds = 5;
  const pollingMaxRetries = 60;
  const imageIdentifier = `${props.repositoryName}:${props.imageTag}`;

  // Create logger with context
  const logger = new Logger({
    repositoryName: props.repositoryName,
    imageTag: props.imageTag,
  });

  // 0. Signature verification (before scan)
  if (props.signatureVerification) {
    try {
      const verificationResult = await verifySignature(
        props.repositoryName,
        props.imageTag,
        props.signatureVerification,
        logger,
      );
      await outputSignatureVerificationLogs(
        verificationResult,
        props.repositoryName,
        props.imageTag,
        props.output,
        props.defaultLogGroupName,
        logger,
      );

      // If signature verification failed (failOnUnsigned=false), log warning and continue to scan
      if (!verificationResult.verified) {
        const warningMessage =
          `Signature verification failed for image: ${imageIdentifier}\n` +
          `${verificationResult.message}\n` +
          `Continuing to scan despite unsigned image (failOnUnsigned=false).`;

        logger.warn(warningMessage);

        if (props.vulnsTopicArn) {
          await sendVulnsNotification(props.vulnsTopicArn, warningMessage, imageIdentifier, {
            type: 'default',
            logGroupName: props.defaultLogGroupName,
          }, logger);
        }

        // Continue to scan
      }
    } catch (error: any) {
      const errorMessage =
        `Signature verification failed for image: ${imageIdentifier}\n` +
        `${error.message || error}`;

      if (props.vulnsTopicArn) {
        await sendVulnsNotification(props.vulnsTopicArn, errorMessage, imageIdentifier, {
          type: 'default',
          logGroupName: props.defaultLogGroupName,
        }, logger);
      }

      if (props.suppressErrorOnRollback === 'true' && (await isRollbackInProgress(event.StackId))) {
        logger.log(
          `Signature verification failed, but suppressing errors during rollback.\n${errorMessage}`,
        );
        return funcResponse;
      }

      throw new Error(errorMessage);
    }
  }

  // Skip scan if signatureOnly mode
  if (props.scanType === 'SIGNATURE_ONLY') {
    logger.log('Vulnerability scanning skipped (ScanConfig.signatureOnly() mode).');
    return funcResponse;
  }

  // 1. Execute scan / poll for results
  let scanFindings: ScanFindings;
  if (props.startScan === 'true') {
    scanFindings = await startAndWaitForScan(
      props.repositoryName,
      props.imageTag,
      props.scanType,
      pollingIntervalSeconds,
      pollingMaxRetries,
      logger,
    );
  } else {
    scanFindings = await waitForScanResults(
      props.repositoryName,
      props.imageTag,
      props.scanType,
      pollingIntervalSeconds,
      pollingMaxRetries,
      logger,
    );
  }

  // 2. Evaluate findings
  const evaluation = evaluateFindings(scanFindings, props.severity, props.ignoreFindings);

  // 3. Export SBOM if configured (only with Enhanced scanning)
  let sbomContent: SbomContent | undefined;
  if (props.sbom) {
    if (props.scanType === 'ENHANCED') {
      const sbomResult = await exportSbom(
        props.repositoryName,
        props.imageTag,
        props.sbom.format,
        props.sbom.bucketName,
        props.sbom.kmsKeyArn,
        logger,
      );
      sbomContent = {
        content: sbomResult.sbomContent,
        format: sbomResult.format,
      };
    } else {
      logger.log('SBOM export is only available with Enhanced scanning. Skipping SBOM generation.');
    }
  }

  // 4. Format and output scan logs
  const findings = scanFindings.enhancedFindings.length > 0
    ? scanFindings.enhancedFindings
    : scanFindings.basicFindings;
  const findingsJson = JSON.stringify(findings, null, 2);
  const summaryText = formatScanSummary(
    scanFindings,
    evaluation,
    props.repositoryName,
    props.imageTag,
  );

  const logsDetails = await outputScanLogs(
    findingsJson,
    summaryText,
    imageIdentifier,
    props.output,
    props.defaultLogGroupName,
    sbomContent,
    logger,
  );

  // 5. If no vulnerabilities, return success
  if (!evaluation.hasVulnerabilities) {
    return funcResponse;
  }

  // 6. Vulnerability detected
  const errorMessage =
    `ECR Image Scan found vulnerabilities.\n` +
    `Image: ${imageIdentifier}\n` +
    `Scan Type: ${scanFindings.scanType}\n` +
    `Findings: ${evaluation.summary}\n` +
    `See scan logs for details.`;

  if (props.vulnsTopicArn) {
    await sendVulnsNotification(props.vulnsTopicArn, errorMessage, imageIdentifier, logsDetails, logger);
  }

  if (props.failOnVulnerability === 'false') {
    return funcResponse;
  }

  if (props.suppressErrorOnRollback === 'true' && (await isRollbackInProgress(event.StackId))) {
    logger.log(
      `Vulnerabilities detected, but suppressing errors during rollback (suppressErrorOnRollback=true).\n${errorMessage}`,
    );
    return funcResponse;
  }

  throw new Error(errorMessage);
};

const outputScanLogs = async (
  findingsJson: string,
  summaryText: string,
  imageIdentifier: string,
  output: ScanLogsOutputOptions | undefined,
  defaultLogGroupName: string,
  sbomContent: SbomContent | undefined,
  logger: Logger,
): Promise<ScanLogsDetails> => {
  switch (output?.type) {
    case ScanLogsOutputType.CLOUDWATCH_LOGS:
      return await outputScanLogsToCWLogs(
        findingsJson,
        summaryText,
        output as CloudWatchLogsOutputOptions,
        imageIdentifier,
        logger,
      );
    case ScanLogsOutputType.S3:
      return await outputScanLogsToS3(
        findingsJson,
        summaryText,
        output as S3OutputOptions,
        imageIdentifier,
        sbomContent,
        logger,
      );
    default:
      logger.log('summary:\n' + summaryText);
      logger.log('findings:\n' + findingsJson);
      return {
        type: 'default',
        logGroupName: defaultLogGroupName,
      };
  }
};

const outputSignatureVerificationLogs = async (
  verificationResult: SignatureVerificationResult,
  repositoryName: string,
  imageTag: string,
  output: ScanLogsOutputOptions | undefined,
  defaultLogGroupName: string,
  logger: Logger,
): Promise<SignatureVerificationLogsDetails> => {
  switch (output?.type) {
    case ScanLogsOutputType.CLOUDWATCH_LOGS:
      return await outputSignatureVerificationLogsToCWLogs(
        verificationResult,
        output as CloudWatchLogsOutputOptions,
        repositoryName,
        imageTag,
        logger,
      );
    case ScanLogsOutputType.S3:
      return await outputSignatureVerificationLogsToS3(
        verificationResult,
        output as S3OutputOptions,
        repositoryName,
        imageTag,
        logger,
      );
    default:
      logger.log('Signature verification result:\n' + JSON.stringify(verificationResult, null, 2));
      return {
        type: 'default',
        logGroupName: defaultLogGroupName,
      };
  }
};
