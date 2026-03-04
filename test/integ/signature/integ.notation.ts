import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack, Aws } from 'aws-cdk-lib';
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
 *   pnpm integ:signature:update --language javascript --test-regex integ.notation.js
 */

const app = new App();
const stack = new Stack(app, 'NotationSignatureStack');

// Use CFn pseudo parameters to avoid hardcoding account ID in snapshots
const signerProfileArn = `arn:aws:signer:${Aws.REGION}:${Aws.ACCOUNT_ID}:/signing-profiles/EcrScanVerifierTest`;

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
