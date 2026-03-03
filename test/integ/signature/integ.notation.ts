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
 *     VERSION_ARN=$(aws signer put-signing-profile \
 *       --profile-name EcrScanVerifierTest \
 *       --platform-id Notation-OCI-SHA384-ECDSA \
 *       --query 'profileVersionArn' --output text)
 *
 *   2. Enable ECR Managed Signing on the CDK staging ECR repository (cdk-xxx-container-assets-xxx):
 *     aws ecr put-account-setting --name CONTAINER_REGISTRAR_SIGNING --value ENABLED
 *     aws ecr put-registry-signing-configuration \
 *       --signing-profiles "[{\"signingProfileName\": \"EcrScanVerifierTest\", \"signingProfileVersionArn\": \"${VERSION_ARN}\"}]"
 *
 *     Alternatively, configure signing per-repository:
 *     aws ecr put-image-signing-configuration \
 *       --repository-name <cdk-staging-repo> \
 *       --image-signing-configuration "{\"signingProfileVersionArn\":\"${VERSION_ARN}\"}"
 *
 *   3. After enabling, push a test image and verify it gets signed:
 *     aws ecr describe-image-signing-status \
 *       --repository-name <repo-name> \
 *       --image-id imageDigest=<digest>
 *
 *   4. Enhanced scanning must be DISABLED:
 *     aws inspector2 disable --resource-types ECR
 *
 * Run:
 *   PROFILE_ARN=$(aws signer get-signing-profile --profile-name EcrScanVerifierTest --query 'arn' --output text)
 *   pnpm integ:signature:update -- --test integ.notation -c signerProfileArn="${PROFILE_ARN}"
 */

const app = new App();
const stack = new Stack(app, 'NotationSignatureStack');

const signerProfileArn = app.node.tryGetContext('signerProfileArn');
if (!signerProfileArn) {
  throw new Error(
    'Missing required context: signerProfileArn. ' +
      'Pass it via: -c signerProfileArn=arn:aws:signer:...',
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
