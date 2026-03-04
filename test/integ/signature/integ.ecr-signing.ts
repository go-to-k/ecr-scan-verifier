import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { ECRDeployment, DockerImageName } from 'cdk-ecr-deployment';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for ECR managed signing (signing-configuration feature).
 *
 * This test verifies images that have been automatically signed by ECR's
 * managed signing feature using AWS Signer and Notation.
 *
 * Prerequisites:
 *   1. Create repository with signing configuration enabled:
 *      aws ecr create-repository --repository-name ecr-scan-verifier-integ-ecr-signing --region us-east-1
 *
 *   2. Create AWS Signer signing profile (if not exists):
 *      aws signer put-signing-profile \
 *        --profile-name EcrScanVerifierTest \
 *        --platform-id Notation-OCI-SHA384-ECDSA
 *
 *   3. Enable ECR managed signing:
 *      (see test/integ/README.md for full setup instructions)
 *
 * Run:
 *   pnpm integ:signature:update --language javascript --test-regex integ.ecr-signing.js
 *
 * Note: ECRDeployment Lambda role needs signer:SignPayload permission for
 * ECR managed signing to work automatically on image push.
 */

const app = new App();
const stack = new Stack(app, 'EcrSigningStack');

// Build Docker image asset (pushed to CDK bootstrap ECR repository)
const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Reference the existing repository (created via CLI with signing-configuration enabled)
const targetRepository = Repository.fromRepositoryName(
  stack,
  'TestRepository',
  'ecr-scan-verifier-integ-ecr-signing',
);

// Copy image from CDK bootstrap repo to signing-enabled repo
// ECR managed signing will automatically sign the image on push
const ecrDeployment = new ECRDeployment(stack, 'DeployImage', {
  src: new DockerImageName(image.imageUri),
  dest: new DockerImageName(`${targetRepository.repositoryUri}:${image.assetHash}`),
});

// Add signer:SignPayload permission to ECRDeployment Lambda role
// This is required for ECR managed signing to work
ecrDeployment.addToPrincipalPolicy(
  new PolicyStatement({
    actions: ['signer:SignPayload'],
    resources: ['*'],
  }),
);

// Use CFn pseudo parameters to build signing profile ARN (avoids hardcoding account ID)
const signingProfileArn = `arn:aws:signer:${stack.region}:${stack.account}:/signing-profiles/EcrScanVerifierTest`;

const verifier = new EcrScanVerifier(stack, 'Scanner', {
  repository: targetRepository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: [signingProfileArn],
  }),
});
// Ensure image is deployed before verifier tries to verify signature
verifier.node.addDependency(ecrDeployment);

new IntegTest(app, 'EcrSigningTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
