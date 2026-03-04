import { App, Stack } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { Key } from 'aws-cdk-lib/aws-kms';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../src';

const MOCK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----';

describe('SignatureVerification', () => {
  let app: App;
  let stack: Stack;
  let repository: Repository;

  beforeEach(() => {
    app = new App();
    stack = new Stack(app, 'TestStack');
    repository = new Repository(stack, 'TestRepo');
  });

  describe('Notation', () => {
    test('Snapshot - notation verification', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        }),
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });

    test('sets signatureVerification props in Custom Resource', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: {
          type: 'NOTATION',
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
          failOnUnsigned: 'true',
        },
      });
    });

    test('grants ECR auth and image pull permissions', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            {
              Action: 'ecr:GetAuthorizationToken',
              Effect: 'Allow',
              Resource: '*',
            },
          ]),
        },
      });
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            {
              Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'],
              Effect: 'Allow',
              Resource: { 'Fn::GetAtt': [Match.stringLikeRegexp('TestRepo'), 'Arn'] },
            },
          ]),
        },
      });
    });

    test('grants signer:GetRevocationStatus permission', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            {
              Action: 'signer:GetRevocationStatus',
              Effect: 'Allow',
              Resource: '*',
            },
          ]),
        },
      });
    });

    test('throws error when trustedIdentities is empty', () => {
      expect(() => {
        SignatureVerification.notation({
          trustedIdentities: [],
        });
      }).toThrow('trustedIdentities must contain at least one signing profile ARN.');
    });

    test('failOnUnsigned defaults to true', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          failOnUnsigned: 'true',
        }),
      });
    });

    test('failOnUnsigned can be set to false', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
          failOnUnsigned: false,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          failOnUnsigned: 'false',
        }),
      });
    });
  });

  describe('Cosign (publicKey)', () => {
    test('Snapshot - cosign public key verification', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
        }),
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });

    test('sets signatureVerification props with publicKey content', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: {
          type: 'COSIGN',
          publicKey: MOCK_PUBLIC_KEY,
          failOnUnsigned: 'true',
        },
      });
    });

    test('grants ECR auth and image pull permissions', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            {
              Action: 'ecr:GetAuthorizationToken',
              Effect: 'Allow',
              Resource: '*',
            },
          ]),
        },
      });
    });

    test('does not grant signer permissions', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
        }),
      });

      const template = Template.fromStack(stack);
      template.resourcePropertiesCountIs(
        'AWS::IAM::Policy',
        {
          PolicyDocument: {
            Statement: Match.arrayWith([
              {
                Action: 'signer:GetRevocationStatus',
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        0,
      );
    });

    test('ignoreTlog defaults to false (Rekor verification enabled)', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          cosignIgnoreTlog: 'false',
        }),
      });
    });

    test('ignoreTlog can be set to true', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignPublicKey({
          publicKey: MOCK_PUBLIC_KEY,
          ignoreTlog: true,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          cosignIgnoreTlog: 'true',
        }),
      });
    });
  });

  describe('Cosign (KMS)', () => {
    test('Snapshot - cosign KMS verification', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
        }),
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });

    test('sets signatureVerification props with kmsKeyArn', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          kmsKeyArn: { 'Fn::GetAtt': [Match.stringLikeRegexp('CosignKey'), 'Arn'] },
          failOnUnsigned: 'true',
        }),
      });
    });

    test('grants KMS permissions via key.grant()', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: ['kms:GetPublicKey', 'kms:Verify'],
              Effect: 'Allow',
            }),
          ]),
        },
      });
    });

    test('ignoreTlog defaults to false (Rekor verification enabled)', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          cosignIgnoreTlog: 'false',
        }),
      });
    });

    test('ignoreTlog can be set to true', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
          ignoreTlog: true,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          cosignIgnoreTlog: 'true',
        }),
      });
    });

    test('ignoreTlog can be set to false explicitly', () => {
      const key = new Key(stack, 'CosignKey');

      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
        signatureVerification: SignatureVerification.cosignKms({
          key,
          ignoreTlog: false,
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.objectLike({
          type: 'COSIGN',
          cosignIgnoreTlog: 'false',
        }),
      });
    });
  });

  describe('no signatureVerification', () => {
    test('does not include signatureVerification in Custom Resource props', () => {
      new EcrScanVerifier(stack, 'Scanner', {
        repository,
        scanConfig: ScanConfig.basic(),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('Custom::EcrScanVerifier', {
        signatureVerification: Match.absent(),
      });
    });

    test('does not grant ECR auth permissions when no signatureVerification', () => {
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
                Action: 'ecr:GetAuthorizationToken',
                Effect: 'Allow',
                Resource: '*',
              },
            ]),
          },
        },
        0,
      );
    });
  });
});
