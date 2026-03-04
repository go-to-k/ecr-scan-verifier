import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for Cosign (public key) signature verification.
 *
 * Prerequisites:
 *   1. Install cosign CLI:
 *     brew install cosign   # macOS
 *     # or see https://docs.sigstore.dev/cosign/system_config/installation/
 *
 *   2. Generate a key pair and store the public key in SSM Parameter Store:
 *     cosign generate-key-pair
 *     aws ssm put-parameter \
 *       --name /ecr-scan-verifier/cosign-public-key \
 *       --value "$(cat cosign.pub)" --type String --overwrite
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
 *   pnpm integ:signature:update --language javascript --test-regex integ.cosign-publickey.js
 */

const COSIGN_PUBLIC_KEY_PARAMETER = '/ecr-scan-verifier/cosign-public-key';

const app = new App();
const stack = new Stack(app, 'CosignPublicKeySignatureStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Look up public key from SSM Parameter Store to avoid environment variables.
// CloudFormation resolves the parameter at deploy time.
const publicKey = StringParameter.valueForStringParameter(stack, COSIGN_PUBLIC_KEY_PARAMETER);

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.cosignPublicKey({
    publicKey,
  }),
});

new IntegTest(app, 'CosignPublicKeySignatureTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
