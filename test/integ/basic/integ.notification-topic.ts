import { resolve } from 'path';
import { ExpectedResult, IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { SqsSubscription } from 'aws-cdk-lib/aws-sns-subscriptions';
import { Queue } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { EcrScanVerifier, ScanConfig, ScanLogsOutput, Severity } from '../../../src';

/**
 * Integration test for vulnerability notification via SNS topic.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *   If Inspector is enabled, disable it before deploying:
 *     aws inspector2 disable --resource-types ECR
 *     # Wait until status becomes DISABLED:
 *     aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 */

class NotificationTestSetup extends Construct {
  public readonly topic: Topic;
  public readonly queue: Queue;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.topic = new Topic(this, 'Topic');
    this.queue = new Queue(this, 'Queue');
    this.topic.addSubscription(new SqsSubscription(this.queue));
  }
}

const app = new App();
const stack = new Stack(app, 'NotificationTopicStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

// Test 1: Default CloudWatch Logs (no scanLogsOutput specified)
const defaultTest = new NotificationTestSetup(stack, 'DefaultTest');
new EcrScanVerifier(stack, 'ImageScannerDefault', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(), // start scan by default for basic scanning
  severity: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM], // to ensure we detect some vulnerabilities for testing notifications
  failOnVulnerability: false, // Intentionally detect vulnerabilities to test SNS topic notifications
  vulnsNotificationTopic: defaultTest.topic,
});

// Test 2: CloudWatch Logs with custom log group
const cloudwatchTest = new NotificationTestSetup(stack, 'CloudWatchTest');
const customLogGroup = new LogGroup(stack, 'CustomLogGroup', {
  retention: RetentionDays.ONE_WEEK,
  removalPolicy: RemovalPolicy.DESTROY,
});
new EcrScanVerifier(stack, 'ImageScannerCloudWatch', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  severity: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
  failOnVulnerability: false,
  vulnsNotificationTopic: cloudwatchTest.topic,
  scanLogsOutput: ScanLogsOutput.cloudWatchLogs({ logGroup: customLogGroup }),
});

// Test 3: S3 output
const s3Test = new NotificationTestSetup(stack, 'S3Test');
const logsBucket = new Bucket(stack, 'LogsBucket', {
  removalPolicy: RemovalPolicy.DESTROY,
  autoDeleteObjects: true,
});
new EcrScanVerifier(stack, 'ImageScannerS3', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  severity: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
  failOnVulnerability: false,
  vulnsNotificationTopic: s3Test.topic,
  scanLogsOutput: ScanLogsOutput.s3({ bucket: logsBucket, prefix: 'scan-logs/' }),
});

const test = new IntegTest(app, 'NotificationTopicTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});

// Verify that SNS notification was sent for default CloudWatch Logs
test.assertions
  .awsApiCall('SQS', 'receiveMessage', {
    QueueUrl: defaultTest.queue.queueUrl,
    WaitTimeSeconds: 20,
  })
  .assertAtPath('Messages.0.Body.Message', ExpectedResult.stringLikeRegexp('aws logs tail'))
  .waitForAssertions({
    interval: Duration.seconds(5),
    totalTimeout: Duration.minutes(3),
  });

// Verify that SNS notification was sent for custom CloudWatch Logs
test.assertions
  .awsApiCall('SQS', 'receiveMessage', {
    QueueUrl: cloudwatchTest.queue.queueUrl,
    WaitTimeSeconds: 20,
  })
  .assertAtPath('Messages.0.Body.Message', ExpectedResult.stringLikeRegexp('aws logs tail'))
  .waitForAssertions({
    interval: Duration.seconds(5),
    totalTimeout: Duration.minutes(3),
  });

// Verify that SNS notification was sent for S3 output
test.assertions
  .awsApiCall('SQS', 'receiveMessage', {
    QueueUrl: s3Test.queue.queueUrl,
    WaitTimeSeconds: 20,
  })
  .assertAtPath('Messages.0.Body.Message', ExpectedResult.stringLikeRegexp('aws s3 cp'))
  .waitForAssertions({
    interval: Duration.seconds(5),
    totalTimeout: Duration.minutes(3),
  });
