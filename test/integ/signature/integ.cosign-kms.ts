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
 * Rekor Transparency Log:
 *   This implementation always skips Rekor transparency log verification for
 *   reliability in AWS Lambda environments. The cryptographic signature is still
 *   verified using the KMS key.
 *
 *   Sign with: cosign sign --tlog-upload=false --key "awskms:///${KMS_KEY_ARN}" IMAGE
 *
 * Run:
 *   COSIGN_KMS_KEY_ID=<key-id> pnpm integ:signature:update --language javascript --test-regex integ.cosign-kms.js
 */

const app = new App();
const stack = new Stack(app, 'CosignKmsSignatureStack');

// Get KMS key ID from environment variable (not full ARN to avoid exposing account ID in snapshot)
const kmsKeyIdFromEnv = process.env.COSIGN_KMS_KEY_ID;
if (!kmsKeyIdFromEnv) {
  throw new Error(
    'Missing required env: COSIGN_KMS_KEY_ID. ' +
      'Pass key ID only (e.g., 7aabc831-9b9a-45e6-8d25-172fe86efebd): ' +
      'COSIGN_KMS_KEY_ID=<key-id> pnpm integ:signature:update',
  );
}

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Build full ARN using Stack's account and region to avoid hardcoding account ID in snapshot
const kmsKey = Key.fromKeyArn(
  stack,
  'CosignKey',
  `arn:aws:kms:${stack.region}:${stack.account}:key/${kmsKeyIdFromEnv}`,
);

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.cosignKms({
    key: kmsKey,
  }),
});

new IntegTest(app, 'CosignKmsSignatureTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
