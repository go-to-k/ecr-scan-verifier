import { App, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { EcrScanVerifier, ScanConfig, ScanLogsOutput } from '../src';

const getCloudWatchLogsTemplate = (): Template => {
  const app = new App();
  const stack = new Stack(app, 'TestStack');

  const repository = new Repository(stack, 'ImageRepository', {});

  new EcrScanVerifier(stack, 'EcrScanVerifier', {
    repository: repository,
    scanConfig: ScanConfig.basic(),
    scanLogsOutput: ScanLogsOutput.cloudWatchLogs({ logGroup: new LogGroup(stack, 'LogGroup') }),
  });
  return Template.fromStack(stack);
};

const getS3Template = (prefix?: string): Template => {
  const app = new App();
  const stack = new Stack(app, 'TestStack');

  const repository = new Repository(stack, 'ImageRepository', {});
  const bucket = new Bucket(stack, 'ScanLogsBucket');

  new EcrScanVerifier(stack, 'EcrScanVerifier', {
    repository: repository,
    scanConfig: ScanConfig.basic(),
    scanLogsOutput: ScanLogsOutput.s3({ bucket, prefix }),
  });
  return Template.fromStack(stack);
};

describe('CloudWatch Logs', () => {
  const template = getCloudWatchLogsTemplate();

  test('correctly sets output configuration to cloudwatch logs', () => {
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      output: {
        type: 'cloudWatchLogs',
        logGroupName: {
          Ref: 'LogGroupF5B46931',
        },
      },
    });
  });

  test('grants write permission to log group', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: Match.arrayWith([
          {
            Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
            Effect: 'Allow',
            Resource: {
              'Fn::GetAtt': ['LogGroupF5B46931', 'Arn'],
            },
          },
        ]),
      },
    });
  });
});

describe('S3', () => {
  test('correctly sets output configuration to S3', () => {
    const template = getS3Template();

    template.hasResourceProperties('Custom::EcrScanVerifier', {
      output: {
        type: 's3',
        bucketName: {
          Ref: 'ScanLogsBucketD650306F',
        },
      },
    });
  });

  test('grants write and read permissions to S3 bucket', () => {
    const template = getS3Template();

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: Match.arrayWith([
          {
            Action: [
              's3:DeleteObject*',
              's3:PutObject',
              's3:PutObjectLegalHold',
              's3:PutObjectRetention',
              's3:PutObjectTagging',
              's3:PutObjectVersionTagging',
              's3:Abort*',
            ],
            Effect: 'Allow',
            Resource: [
              {
                'Fn::GetAtt': ['ScanLogsBucketD650306F', 'Arn'],
              },
              {
                'Fn::Join': [
                  '',
                  [
                    {
                      'Fn::GetAtt': ['ScanLogsBucketD650306F', 'Arn'],
                    },
                    '/*',
                  ],
                ],
              },
            ],
          },
        ]),
      },
    });
  });

  test('correctly sets output configuration to S3 with prefix', () => {
    const template = getS3Template('scan-logs/');

    template.hasResourceProperties('Custom::EcrScanVerifier', {
      output: {
        type: 's3',
        bucketName: {
          Ref: 'ScanLogsBucketD650306F',
        },
        prefix: 'scan-logs/',
      },
    });
  });
});
