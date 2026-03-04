import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Key } from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for Cosign (KMS) signature verification.
 *
 * Prerequisites:
 *   1. Install cosign CLI:
 *     brew install cosign   # macOS
 *     # or see https://docs.sigstore.dev/cosign/system_config/installation/
 *
 *   2. Create a KMS key for signing and store key ID in SSM Parameter Store:
 *     KMS_KEY_ID=$(aws kms create-key \
 *       --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 \
 *       --query 'KeyMetadata.KeyId' --output text)
 *     aws ssm put-parameter \
 *       --name /ecr-scan-verifier/cosign-kms-key-id \
 *       --value "${KMS_KEY_ID}" --type String --overwrite
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
 *   pnpm integ:signature:update --language javascript --test-regex integ.cosign-kms.js
 */

const COSIGN_KMS_KEY_ID_PARAMETER = '/ecr-scan-verifier/cosign-kms-key-id';

const app = new App();
const stack = new Stack(app, 'CosignKmsSignatureStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Look up KMS key ID from SSM Parameter Store to avoid environment variables.
// CloudFormation resolves the parameter at deploy time, so the IAM policy
// uses the actual key ARN (not an alias ARN).
const kmsKeyId = StringParameter.valueForStringParameter(stack, COSIGN_KMS_KEY_ID_PARAMETER);
const kmsKey = Key.fromKeyArn(
  stack,
  'CosignKey',
  `arn:aws:kms:${stack.region}:${stack.account}:key/${kmsKeyId}`,
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
