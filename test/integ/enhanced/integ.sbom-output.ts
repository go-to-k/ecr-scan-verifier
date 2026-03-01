import { resolve } from 'path';
import { AwsApiCall, ExpectedResult, IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { EcrScanVerifier, SbomOutput, ScanConfig } from '../../../src';

/**
 * Integration test for SBOM output with Enhanced scanning.
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
  'CVE-2023-37920',
  'CVE-2025-7783',
  'CVE-2025-68121',
  'CVE-2026-25896',
];

const app = new App();
const stack = new Stack(app, 'SbomOutputStack');

const sbomBucket = new Bucket(stack, 'SbomBucket', {
  removalPolicy: RemovalPolicy.DESTROY,
  autoDeleteObjects: true,
});

const sbomKey = new Key(stack, 'SbomKey', {
  removalPolicy: RemovalPolicy.DESTROY,
});

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.enhanced(),
  ignoreFindings: IGNORE_FOR_PASSING_TESTS,
  sbomOutput: SbomOutput.cycloneDx14({ bucket: sbomBucket, encryptionKey: sbomKey }),
});

const test = new IntegTest(app, 'SbomOutputTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});

const s3ApiCall = test.assertions
  .awsApiCall('S3', 'listObjectsV2', {
    Bucket: sbomBucket.bucketName,
    MaxKeys: 1,
  })
  .expect(
    ExpectedResult.objectLike({
      KeyCount: 1,
    }),
  )
  .waitForAssertions({
    interval: Duration.seconds(10),
    totalTimeout: Duration.minutes(5),
  });

if (s3ApiCall instanceof AwsApiCall && s3ApiCall.waiterProvider) {
  s3ApiCall.waiterProvider.addToRolePolicy({
    Effect: 'Allow',
    Action: ['s3:GetObject', 's3:ListBucket'],
    Resource: ['*'],
  });
}
