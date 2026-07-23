import { resolve } from 'path';
import { ExpectedResult, IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { EcrScanVerifier, ScanConfig, ScanLogsOutput } from '../../../src';

/**
 * Integration test for scan logs output to CloudWatch Logs.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *   If Inspector is enabled, disable it before deploying:
 *     aws inspector2 disable --resource-types ECR
 *     # Wait until status becomes DISABLED:
 *     aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 */

const app = new App();
const stack = new Stack(app, 'ScanLogsOutputCWStack');

const scanLogsOutputLogGroup = new LogGroup(stack, 'ScanLogsOutputLogGroup', {
  removalPolicy: RemovalPolicy.DESTROY,
});

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(), // start scan by default for basic scanning
  scanLogsOutput: ScanLogsOutput.cloudWatchLogs({ logGroup: scanLogsOutputLogGroup }),
});

const test = new IntegTest(app, 'ScanLogsOutputCWTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});

// Read the summary stream directly with getLogEvents instead of searching
// with filterLogEvents: the search path can return empty first pages with a
// nextToken (which the assertion cannot follow), making the test hang until
// timeout even though the events exist.
const summaryLogStreamName = `${image.repository.repositoryName},${image.assetHash}/summary`;
test.assertions
  .awsApiCall('CloudWatchLogs', 'getLogEvents', {
    logGroupName: scanLogsOutputLogGroup.logGroupName,
    logStreamName: summaryLogStreamName,
    startFromHead: true,
    limit: 10,
  })
  .assertAtPath('events.0.message', ExpectedResult.stringLikeRegexp('Severity Summary'))
  .waitForAssertions();

// Assert that two log streams (findings and summary) exist
test.assertions
  .awsApiCall('CloudWatchLogs', 'describeLogStreams', {
    logGroupName: scanLogsOutputLogGroup.logGroupName,
  })
  .assertAtPath('logStreams.0.logStreamName', ExpectedResult.stringLikeRegexp('findings'))
  .assertAtPath('logStreams.1.logStreamName', ExpectedResult.stringLikeRegexp('summary'))
  .waitForAssertions();
