import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { mockClient } from 'aws-sdk-client-mock';
import { sendVulnsNotification } from '../lib/sns-notification';

const snsMock = mockClient(SNSClient);

describe('sns-notification', () => {
  beforeEach(() => {
    snsMock.reset();
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('sendVulnsNotification', () => {
    const topicArn = 'arn:aws:sns:us-east-1:123456789012:test-topic';
    const errorMessage = 'Test error message';
    const imageIdentifier = 'my-repo:latest';

    test('should generate scan logs location for default CloudWatch Logs', async () => {
      snsMock.on(PublishCommand).resolves({});

      const logsDetails = {
        type: 'default' as const,
        logGroupName: '/aws/lambda/default-log-group',
      };

      await sendVulnsNotification(topicArn, errorMessage, imageIdentifier, logsDetails);

      const call = snsMock.call(0);
      const messageStructure = JSON.parse((call.args[0] as PublishCommand).input.Message!);

      expect(messageStructure.default).toContain(
        'aws logs tail /aws/lambda/default-log-group --since 1h',
      );
    });

    test('should generate scan logs location for CloudWatch Logs with stream details', async () => {
      snsMock.on(PublishCommand).resolves({});

      const logsDetails = {
        type: 'cloudwatch' as const,
        logGroupName: '/custom/log/group',
        findingsLogStreamName: 'my-repo,latest/findings',
        summaryLogStreamName: 'my-repo,latest/summary',
      };

      await sendVulnsNotification(topicArn, errorMessage, imageIdentifier, logsDetails);

      const call = snsMock.call(0);
      const messageStructure = JSON.parse((call.args[0] as PublishCommand).input.Message!);

      expect(messageStructure.default).toContain(
        'aws logs tail /custom/log/group --log-stream-names my-repo,latest/findings --since 1h',
      );
      expect(messageStructure.default).toContain(
        'aws logs tail /custom/log/group --log-stream-names my-repo,latest/summary --since 1h',
      );
    });

    test('should generate scan logs location for S3 with detailed keys', async () => {
      snsMock.on(PublishCommand).resolves({});

      const logsDetails = {
        type: 's3' as const,
        bucketName: 'test-bucket',
        findingsKey: 'scan-logs/my-repo/latest/2024-01-01T00:00:00.000Z/findings.json',
        summaryKey: 'scan-logs/my-repo/latest/2024-01-01T00:00:00.000Z/summary.txt',
      };

      await sendVulnsNotification(topicArn, errorMessage, imageIdentifier, logsDetails);

      const call = snsMock.call(0);
      const messageStructure = JSON.parse((call.args[0] as PublishCommand).input.Message!);

      expect(messageStructure.default).toContain(
        'aws s3 cp s3://test-bucket/scan-logs/my-repo/latest/2024-01-01T00:00:00.000Z/findings.json -',
      );
      expect(messageStructure.default).toContain(
        'aws s3 cp s3://test-bucket/scan-logs/my-repo/latest/2024-01-01T00:00:00.000Z/summary.txt -',
      );
    });

    test('should handle SNS publish errors gracefully', async () => {
      snsMock.on(PublishCommand).rejects(new Error('SNS publish failed'));

      const logsDetails = {
        type: 'default' as const,
        logGroupName: '/aws/lambda/default-log-group',
      };

      await expect(
        sendVulnsNotification(topicArn, errorMessage, imageIdentifier, logsDetails),
      ).resolves.not.toThrow();
    });
  });
});
