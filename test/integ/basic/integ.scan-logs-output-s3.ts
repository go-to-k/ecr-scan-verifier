import { resolve } from 'path';
import { AwsApiCall, ExpectedResult, IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { EcrScanVerifier, ScanConfig, ScanLogsOutput } from '../../../src';

/**
 * Integration test for scan logs output to S3.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 *   If Inspector is enabled, disable it before deploying:
 *     aws inspector2 disable --resource-types ECR
 *     # Wait until status becomes DISABLED:
 *     aws inspector2 batch-get-account-status --query 'accounts[0].resourceState.ecr.status'
 */

const app = new App();
const stack = new Stack(app, 'ScanLogsOutputS3Stack');

const scanLogsOutputS3Bucket = new Bucket(stack, 'ScanLogsOutputS3Bucket', {
  removalPolicy: RemovalPolicy.DESTROY,
  autoDeleteObjects: true,
});

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(), // start scan by default for basic scanning
  scanLogsOutput: ScanLogsOutput.s3({ bucket: scanLogsOutputS3Bucket }),
});

const test = new IntegTest(app, 'ScanLogsOutputS3Test', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});

const s3ApiCall = test.assertions
  .awsApiCall('S3', 'listObjectsV2', {
    Bucket: scanLogsOutputS3Bucket.bucketName,
    MaxKeys: 2,
  })
  .expect(
    ExpectedResult.objectLike({
      KeyCount: 2,
    }),
  )
  .waitForAssertions({
    interval: Duration.seconds(5),
    totalTimeout: Duration.minutes(2),
  });

if (s3ApiCall instanceof AwsApiCall && s3ApiCall.waiterProvider) {
  s3ApiCall.waiterProvider.addToRolePolicy({
    Effect: 'Allow',
    Action: ['s3:GetObject', 's3:ListBucket'],
    Resource: ['*'],
  });
}
