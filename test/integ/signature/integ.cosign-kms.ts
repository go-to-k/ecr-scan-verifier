import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Key } from 'aws-cdk-lib/aws-kms';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for Cosign (KMS) signature verification.
 *
 * Prerequisites:
 *   1. Install cosign CLI:
 *     brew install cosign   # macOS
 *     # or see https://docs.sigstore.dev/cosign/system_config/installation/
 *
 *   2. Create a KMS key for signing (or reuse an existing one):
 *     KMS_KEY_ARN=$(aws kms create-key \
 *       --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
 *       --query 'KeyMetadata.Arn' --output text)
 *
 *   3. Build, synth, and publish the Docker image asset, then sign it
 *      (see test/integ/README.md for full commands)
 *
 * Run:
 *   COSIGN_KMS_KEY_ARN=arn:aws:kms:... pnpm integ:signature:update --language javascript --test-regex integ.cosign-kms.js
 */

const app = new App();
const stack = new Stack(app, 'CosignKmsSignatureStack');

// Get KMS key ARN from environment variable (required for signing)
const kmsKeyArnFromEnv = process.env.COSIGN_KMS_KEY_ARN;
if (!kmsKeyArnFromEnv) {
  throw new Error(
    'Missing required env: COSIGN_KMS_KEY_ARN. ' +
      'Pass it via: COSIGN_KMS_KEY_ARN=arn:aws:kms:... pnpm integ:signature:update',
  );
}

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

const kmsKey = Key.fromKeyArn(stack, 'CosignKey', kmsKeyArnFromEnv);

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignKms({
    key: kmsKey,
  }),
});

new IntegTest(app, 'CosignKmsSignatureTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
