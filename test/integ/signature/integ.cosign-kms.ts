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
 *   3. Push the test image to ECR manually and sign it:
 *     # First, do a cdk deploy --no-execute or cdk synth to push the Docker image asset
 *     # Then sign the image:
 *     ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
 *     REGION=$(aws configure get region)
 *     REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
 *     aws ecr get-login-password | cosign login --username AWS --password-stdin "${REGISTRY}"
 *     cosign sign --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/<repo>@<digest>"
 *     # Replace <repo> and <digest> with the values from the cdk synth output.
 *
 *   4. Enhanced scanning must be DISABLED:
 *     aws inspector2 disable --resource-types ECR
 *
 * Run:
 *   pnpm integ:signature:update -- --test integ.cosign-kms -c cosignKmsKeyArn="${KMS_KEY_ARN}"
 */

const app = new App();
const stack = new Stack(app, 'CosignKmsSignatureStack');

const cosignKmsKeyArn = app.node.tryGetContext('cosignKmsKeyArn');
if (!cosignKmsKeyArn) {
  throw new Error(
    'Missing required context: cosignKmsKeyArn. ' +
      'Pass it via: -c cosignKmsKeyArn=arn:aws:kms:...',
  );
}

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

const kmsKey = Key.fromKeyArn(stack, 'CosignKey', cosignKmsKeyArn);

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
