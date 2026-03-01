import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { EcrScanVerifier, ScanConfig } from '../../../src';

/**
 * Integration test for Enhanced scanning (Amazon Inspector).
 *
 * Prerequisites (run manually before deploying):
 *   aws inspector2 enable --resource-types ECR
 *   # Wait until status becomes ENABLED:
 *   aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 *
 * Cleanup (run after destroying, if Inspector was not originally enabled):
 *   aws inspector2 disable --resource-types ECR
 */

const app = new App();
const stack = new Stack(app, 'EnhancedScanningStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.enhanced(),
});

new IntegTest(app, 'EnhancedScanningTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
