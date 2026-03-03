import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for Notation (AWS Signer) signature verification.
 *
 * Prerequisites:
 *   1. Create an AWS Signer signing profile:
 *     aws signer put-signing-profile \
 *       --profile-name EcrScanVerifierTest \
 *       --platform-id Notation-OCI-SHA384-ECDSA
 *
 *   2. Install notation CLI + AWS Signer plugin:
 *     https://docs.aws.amazon.com/signer/latest/developerguide/install-notation-client.html
 *
 *   3. Push the Docker image asset and sign it with notation
 *      (see test/integ/README.md for full commands)
 *
 * Run:
 *   SIGNER_PROFILE_ARN="${PROFILE_ARN}" pnpm integ:signature:update \
 *     --language javascript --test-regex integ.notation.js
 */

const app = new App();
const stack = new Stack(app, 'NotationSignatureStack');

const signerProfileArn = process.env.SIGNER_PROFILE_ARN;
if (!signerProfileArn) {
  throw new Error(
    'Missing required env: SIGNER_PROFILE_ARN. ' +
      'Pass it via: SIGNER_PROFILE_ARN=arn:aws:signer:... pnpm integ:signature:update',
  );
}

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: [signerProfileArn],
  }),
});

new IntegTest(app, 'NotationSignatureTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
