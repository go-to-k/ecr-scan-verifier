import { App, Stack } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { Key } from 'aws-cdk-lib/aws-kms';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Topic } from 'aws-cdk-lib/aws-sns';
import {
  EcrScanVerifier,
  ScanConfig,
  Severity,
  ScanLogsOutput,
  SbomOutput,
  SignatureVerification,
} from '../src';

describe('EcrScanVerifier', () => {
  let app: App;
  let stack: Stack;
  let repository: Repository;

  beforeEach(() => {
    app = new App();
    stack = new Stack(app, 'TestStack');
    repository = new Repository(stack, 'TestRepo');
  });

  test('Snapshot - minimal options', () => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
    });

    const template = Template.fromStack(stack);
    expect(template.toJSON()).toMatchSnapshot();
  });

  test('Snapshot - all options', () => {
    const logGroup = new LogGroup(stack, 'LogGroup');
    const topic = new Topic(stack, 'Topic');
    const bucket = new Bucket(stack, 'Bucket');
    const blockedConstruct = new Bucket(stack, 'BlockedBucket');

    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      imageTag: 'v1.0',
      scanConfig: ScanConfig.enhanced({
        sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: new Key(stack, 'SbomKey') }),
      }),
      severity: [Severity.CRITICAL, Severity.HIGH],
      failOnVulnerability: true,
      ignoreFindings: ['CVE-2023-37920'],
      scanLogsOutput: ScanLogsOutput.s3({ bucket, prefix: 'scan-logs' }),
      defaultLogGroup: logGroup,
      suppressErrorOnRollback: true,
      vulnsNotificationTopic: topic,
      blockConstructs: [blockedConstruct],
    });

    const template = Template.fromStack(stack);
    expect(template.toJSON()).toMatchSnapshot();
  });

  test('Snapshot - signature only', () => {
    const kmsKey = new Key(stack, 'SigningKey');
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.signatureOnly(),
      signatureVerification: SignatureVerification.cosignKms({ key: kmsKey }),
    });

    const template = Template.fromStack(stack);
    expect(template.toJSON()).toMatchSnapshot();
  });

  test('creates Custom Resource with default values', () => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      repositoryName: { Ref: Match.stringLikeRegexp('TestRepo') },
      imageTag: 'latest',
      scanType: 'BASIC',
      startScan: 'true',
      severity: ['CRITICAL'],
      failOnVulnerability: 'true',
      suppressErrorOnRollback: 'true',
    });
  });

  describe('grants', () => {
    test('ECR scan permissions', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['ecr:DescribeImages', 'ecr:DescribeImageScanFindings'],
              Effect: 'Allow',
            }),
          ]),
        },
      });
    });

    test('Inspector2 permissions for enhanced scan', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: ['inspector2:ListCoverage', 'inspector2:ListFindings'],
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        1,
      );
    });

    test('no Inspector2 permissions for basic scan', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: ['inspector2:ListCoverage', 'inspector2:ListFindings'],
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        0,
      );
    });

    test('StartImageScan for basic scan with startScan true', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic({ startScan: true }),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'ecr:StartImageScan',
                Effect: 'Allow',
                Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
              },
            ]),
          },
        },
        1,
      );
    });

    test('no StartImageScan for basic scan with startScan false', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic({ startScan: false }),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'ecr:StartImageScan',
                Effect: 'Allow',
                Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
              },
            ]),
          },
        },
        0,
      );
    });

    test('no StartImageScan for enhanced scan', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'ecr:StartImageScan',
                Effect: 'Allow',
                Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
              },
            ]),
          },
        },
        0,
      );
    });

    test('signature only scan has DescribeImages but not DescribeImageScanFindings', () => {
      const kmsKey = new Key(stack, 'SigningKey');
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.signatureOnly(),
        signatureVerification: SignatureVerification.cosignKms({ key: kmsKey }),
      });

      const template = Template.fromStack(stack);

      // Should NOT have both DescribeImageScanFindings and DescribeImages together
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: ['ecr:DescribeImageScanFindings', 'ecr:DescribeImages'],
                Effect: 'Allow',
                Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
              },
            ]),
          },
        },
        0,
      );

      // Should have only DescribeImages (as a string, not array, when optimized by CDK)
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'ecr:DescribeImages',
                Effect: 'Allow',
                Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
              },
            ]),
          },
        },
        1,
      );
    });

    test('CloudFormation DescribeStacks permission', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'cloudformation:DescribeStacks',
                Effect: 'Allow',
                Resource: { Ref: 'AWS::StackId' },
              },
            ]),
          },
        },
        1,
      );
    });

    test('no CloudFormation permission when suppressErrorOnRollback is false', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        suppressErrorOnRollback: false,
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'cloudformation:DescribeStacks',
                Effect: 'Allow',
                Resource: { Ref: 'AWS::StackId' },
              },
            ]),
          },
        },
        0,
      );
    });

    test('SNS publish permission when topic is specified', () => {
      const topic = new Topic(stack, 'Topic');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        vulnsNotificationTopic: topic,
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'sns:Publish',
                Effect: 'Allow',
                Resource: { Ref: Match.stringLikeRegexp('Topic') },
              },
            ]),
          },
        },
        1,
      );
    });

    test('no SNS publish permission when topic is not specified', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'sns:Publish',
                Effect: 'Allow',
                Resource: { Ref: Match.stringLikeRegexp('Topic') },
              },
            ]),
          },
        },
        0,
      );
    });

    test('SBOM export permissions when sbomOutput is specified', () => {
      const bucket = new Bucket(stack, 'SbomBucket');
      const key = new Key(stack, 'SbomKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced({
          sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
        }),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: ['inspector2:CreateSbomExport', 'inspector2:GetSbomExport'],
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        1,
      );
    });

    test('no SBOM export permissions when sbomOutput is not specified', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced(),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: ['inspector2:CreateSbomExport', 'inspector2:GetSbomExport'],
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        0,
      );
    });

    test('S3 bucket policy for Inspector2 with ArnLike condition when sbomOutput is specified', () => {
      const bucket = new Bucket(stack, 'SbomBucket');
      const key = new Key(stack, 'SbomKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced({
          sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::S3::BucketPolicy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['s3:PutObject', 's3:AbortMultipartUpload'],
              Effect: 'Allow',
              Principal: {
                Service: 'inspector2.amazonaws.com',
              },
              Condition: {
                StringEquals: {
                  'aws:SourceAccount': { Ref: 'AWS::AccountId' },
                },
                ArnLike: {
                  'aws:SourceArn': {
                    'Fn::Join': Match.arrayWith([
                      Match.arrayWith([
                        Match.stringLikeRegexp('arn:'),
                        Match.stringLikeRegexp(':inspector2:'),
                      ]),
                    ]),
                  },
                },
              },
            }),
          ]),
        },
      });
    });

    test('KMS key policy for Inspector2 with ArnLike condition when sbomOutput is specified', () => {
      const bucket = new Bucket(stack, 'SbomBucket');
      const key = new Key(stack, 'SbomKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.enhanced({
          sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::KMS::Key', {
        KeyPolicy: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['kms:Decrypt', 'kms:GenerateDataKey*'],
              Effect: 'Allow',
              Principal: {
                Service: 'inspector2.amazonaws.com',
              },
              Condition: {
                StringEquals: {
                  'aws:SourceAccount': { Ref: 'AWS::AccountId' },
                },
                ArnLike: {
                  'aws:SourceArn': {
                    'Fn::Join': Match.arrayWith([
                      Match.arrayWith([
                        Match.stringLikeRegexp('arn:'),
                        Match.stringLikeRegexp(':inspector2:'),
                      ]),
                    ]),
                  },
                },
              },
            }),
          ]),
        },
      });
    });
  });

  test('sets up blockConstructs dependency', () => {
    const blockedBucket = new Bucket(stack, 'BlockedBucket');

    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
      blockConstructs: [blockedBucket],
    });

    const template = Template.fromStack(stack);
    template.hasResource('AWS::S3::Bucket', {
      DependsOn: Match.anyValue(),
    });
  });

  test('uses enhanced scan config', () => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.enhanced(),
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      scanType: 'ENHANCED',
      startScan: 'false',
    });
  });

  test('uses CloudWatch Logs output', () => {
    const logGroup = new LogGroup(stack, 'ScanLogGroup');

    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
      scanLogsOutput: ScanLogsOutput.cloudWatchLogs({ logGroup }),
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      output: Match.objectLike({
        type: 'cloudWatchLogs',
      }),
    });
  });

  test('uses imageTag with digest', () => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
      imageTag: 'sha256:abc123',
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      imageTag: 'sha256:abc123',
    });
  });

  test('uses imageTag with custom tag', () => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
      imageTag: 'v2.0',
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      imageTag: 'v2.0',
    });
  });

  test('sets sbom config in custom resource properties', () => {
    const bucket = new Bucket(stack, 'SbomBucket');
    const key = new Key(stack, 'SbomKey');

    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.enhanced({
        sbomOutput: SbomOutput.spdx23({ bucket, encryptionKey: key }),
      }),
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('Custom::EcrScanVerifier', {
      sbom: Match.objectLike({
        format: 'SPDX_2_3',
      }),
    });
  });

  describe('ScanConfig.signatureOnly() validation', () => {
    test('throws error when signatureOnly without signatureVerification', () => {
      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
        });
      }).toThrow(/signatureOnly.*requires signatureVerification/);
    });

    test('allows signatureOnly with notation verification', () => {
      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.notation({
            trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/test'],
          }),
        });
      }).not.toThrow();
    });

    test('allows signatureOnly with cosign public key verification', () => {
      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.cosignPublicKey({
            publicKey: 'test-key',
          }),
        });
      }).not.toThrow();
    });

    test('allows signatureOnly with cosign KMS verification', () => {
      const key = new Key(stack, 'CosignKey');
      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.cosignKms({ key }),
        });
      }).not.toThrow();
    });
  });
});
