import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { DockerImageName, ECRDeployment } from 'cdk-ecr-deployment';
import { EcrScanVerifier, ScanConfig } from '../../../src';

/**
 * Integration test for scan-on-push behavior (startScan: false).
 *
 * This test verifies that the scanner can poll for existing scan results
 * without explicitly calling StartImageScan API.
 *
 * Prerequisites (run manually before deploying):
 *   1. Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *      If Inspector is enabled, disable it before deploying:
 *        aws inspector2 disable --resource-types ECR
 *        # Wait until status becomes DISABLED:
 *        aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 *
 *   2. Enable scan-on-push for the CDK assets repository:
 *        REPO="cdk-hnb659fds-container-assets-<ACCOUNT_ID>-<REGION>"
 *        aws ecr put-image-scanning-configuration --repository-name $REPO --image-scanning-configuration scanOnPush=true
 *
 * Cleanup (run after destroying):
 *   aws ecr put-image-scanning-configuration --repository-name $REPO --image-scanning-configuration scanOnPush=false
 */

const app = new App();
const stack = new Stack(app, 'ScanOnPushStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Poll for existing scan results without calling StartImageScan.
// Relies on scan-on-push being enabled on the CDK asset ECR repository.
new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic({ startScan: false }),
});

// Repository level scan-on-push
const scanOnPushRepository = new Repository(stack, 'ScanOnPushRepository', {
  imageScanOnPush: true,
  emptyOnDelete: true,
  removalPolicy: RemovalPolicy.DESTROY,
});
const ecrDeployment = new ECRDeployment(stack, 'DeployImage', {
  src: new DockerImageName(image.imageUri),
  dest: new DockerImageName(`${scanOnPushRepository.repositoryUri}:${image.assetHash}`),
});
const verifier = new EcrScanVerifier(stack, 'ScannerOnPush', {
  repository: scanOnPushRepository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic({ startScan: false }),
});
// Ensure image is deployed before verifier tries to poll for scan results
verifier.node.addDependency(ecrDeployment);

new IntegTest(app, 'ScanOnPushTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
