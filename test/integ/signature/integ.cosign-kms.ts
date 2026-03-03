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
 *   3. Build, synth, and publish the Docker image asset only (no deploy):
 *     tsc -p tsconfig.dev.json
 *     cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd -
 *     COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" npx cdk synth \
 *       --app 'node test/integ/signature/integ.cosign-kms.js' -o cdk.out
 *     npx cdk-assets -p cdk.out/CosignKmsSignatureStack.assets.json publish
 *
 *   4. Sign the pushed image with cosign:
 *     ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
 *     REGION=$(aws configure get region)
 *     REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
 *     REPO="cdk-hnb659fds-container-assets-${ACCOUNT}-${REGION}"
 *     DIGEST=$(aws ecr describe-images --repository-name "${REPO}" \
 *       --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageDigest' --output text)
 *     aws ecr get-login-password | cosign login --username AWS --password-stdin "${REGISTRY}"
 *     cosign sign --key "awskms:///${KMS_KEY_ARN}" "${REGISTRY}/${REPO}@${DIGEST}"
 *
 *   5. Enhanced scanning must be DISABLED:
 *     aws inspector2 disable --resource-types ECR
 *
 * Run:
 *   COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" pnpm integ:signature:update \
 *     --language javascript --test-regex integ.cosign-kms.js
 */

const app = new App();
const stack = new Stack(app, 'CosignKmsSignatureStack');

const cosignKmsKeyArn = process.env.COSIGN_KMS_KEY_ARN;
if (!cosignKmsKeyArn) {
  throw new Error(
    'Missing required env: COSIGN_KMS_KEY_ARN. ' +
      'Pass it via: COSIGN_KMS_KEY_ARN=arn:aws:kms:... pnpm integ:signature:update',
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
