import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { EcrScanVerifier, ScanConfig } from '../../../src';

/**
 * Integration test for Basic scanning with minimal options.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *   If Inspector is enabled, disable it before deploying:
 *     aws inspector2 disable --resource-types ECR
 *     # Wait until status becomes DISABLED:
 *     aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 */

const app = new App();
const stack = new Stack(app, 'MinimalOptionsStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(), // start scan by default for basic scanning
});

new IntegTest(app, 'MinimalOptionsTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
