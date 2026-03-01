import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Queue } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { EcrScanVerifier, ScanConfig, Severity } from '../../../src';

/**
 * Integration test for Basic scanning with all options.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *   If Inspector is enabled, disable it before deploying:
 *     aws inspector2 disable --resource-types ECR
 *     # Wait until status becomes DISABLED:
 *     aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 */

const IGNORE_FOR_PASSING_TESTS = [
  'CVE-2023-37920',
  'CVE-2025-7783',
  'CVE-2025-68121',
  'CVE-2026-25896',
];

const app = new App();
const stack = new Stack(app, 'AllOptionsStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

const blockedConstruct = new Construct(stack, 'BlockedConstruct');
new Queue(blockedConstruct, 'BlockedQueue');

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic({ startScan: true }),
  severity: [Severity.CRITICAL],
  failOnVulnerability: true,
  ignoreFindings: IGNORE_FOR_PASSING_TESTS,
  defaultLogGroup: new LogGroup(stack, 'DefaultLogGroup', {
    removalPolicy: RemovalPolicy.DESTROY,
    retention: RetentionDays.ONE_DAY,
  }),
  suppressErrorOnRollback: true,
  blockConstructs: [blockedConstruct],
});

new IntegTest(app, 'AllOptionsTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
