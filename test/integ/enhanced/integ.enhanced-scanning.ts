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

const IGNORE_FOR_PASSING_TESTS = [
  'GMS-2020-2',
  'CVE-2025-22871',
  'CVE-2025-68121',
  'CVE-2025-7783',
  'CVE-2023-42282',
  'CVE-2023-26136',
];

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
  ignoreFindings: IGNORE_FOR_PASSING_TESTS,
});

new IntegTest(app, 'EnhancedScanningTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
