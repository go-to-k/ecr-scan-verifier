import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for Cosign (public key) signature verification.
 *
 * Prerequisites:
 *   1. Install cosign CLI:
 *     brew install cosign   # macOS
 *     # or see https://docs.sigstore.dev/cosign/system_config/installation/
 *
 *   2. Generate a key pair:
 *     cosign generate-key-pair
 *     # This creates cosign.key (private) and cosign.pub (public)
 *
 *   3. Build, synth, and publish the Docker image asset, then sign it
 *      (see test/integ/README.md for full commands)
 *
 * Rekor Transparency Log:
 *   This implementation always skips Rekor transparency log verification for
 *   reliability in AWS Lambda environments. The cryptographic signature is still
 *   verified using the public key.
 *
 *   Sign with: cosign sign --tlog-upload=false --key cosign.key IMAGE
 *
 * Run:
 *   COSIGN_PUBLIC_KEY="$(cat cosign.pub)" pnpm integ:signature:update --language javascript --test-regex integ.cosign-publickey.js
 */

const app = new App();
const stack = new Stack(app, 'CosignPublicKeySignatureStack');

// Get public key from environment variable (required for verification)
const publicKeyFromEnv = process.env.COSIGN_PUBLIC_KEY;
if (!publicKeyFromEnv) {
  throw new Error(
    'Missing required env: COSIGN_PUBLIC_KEY. ' +
      'Pass it via: COSIGN_PUBLIC_KEY="$(cat cosign.pub)" pnpm integ:signature:update',
  );
}

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.cosignPublicKey({
    publicKey: publicKeyFromEnv,
  }),
});

new IntegTest(app, 'CosignPublicKeySignatureTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
