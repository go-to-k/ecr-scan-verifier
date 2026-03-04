import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { DockerImageName, ECRDeployment } from 'cdk-ecr-deployment';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for ECR managed signing (signing-configuration feature).
 *
 * This test uses ECR's built-in signing-configuration feature to automatically
 * sign images on push, then verifies the signatures using Notation.
 *
 * Prerequisites:
 *   1. Install notation CLI + AWS Signer plugin
 *      (see test/integ/README.md for installation instructions)
 *
 *   2. Create an AWS Signer signing profile and ECR repository via CLI
 *      (see test/integ/README.md for full setup)
 *
 * Run:
 *   SIGNING_PROFILE_ARN=<arn> pnpm integ:signature:update --language javascript --test-regex integ.ecr-signing.js
 */

const app = new App();
const stack = new Stack(app, 'EcrSigningStack');

// Get repository name from environment variable
const repoNameFromEnv = process.env.REPO_NAME || 'ecr-scan-verifier-integ-ecr-signing';

// Reference the existing repository (created via CLI with signing-configuration enabled)
const repository = Repository.fromRepositoryName(stack, 'TestRepository', repoNameFromEnv);

// Create a DockerImageAsset (pushes to CDK bootstrap repository)
const image = new DockerImageAsset(stack, 'TestImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Copy image from CDK bootstrap repository to signing-enabled repository
// ECR managed signing will automatically sign the image on push
const ecrDeployment = new ECRDeployment(stack, 'DeployImage', {
  src: new DockerImageName(image.imageUri),
  dest: new DockerImageName(`${repository.repositoryUri}:${image.assetHash}`),
});

// Get signing profile ARN from environment variable
const signingProfileArnFromEnv = process.env.SIGNING_PROFILE_ARN;
if (!signingProfileArnFromEnv) {
  throw new Error(
    'Missing required env: SIGNING_PROFILE_ARN. ' +
      'Get it via: aws signer get-signing-profile --profile-name EcrScanVerifierTest --query arn --output text',
  );
}

const verifier = new EcrScanVerifier(stack, 'Scanner', {
  repository: repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: [signingProfileArnFromEnv],
  }),
});

// Ensure image is deployed before verifier tries to verify signature
verifier.node.addDependency(ecrDeployment);

new IntegTest(app, 'EcrSigningTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
