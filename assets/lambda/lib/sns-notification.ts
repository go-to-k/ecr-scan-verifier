import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { ScanLogsDetails } from './types';

const snsClient = new SNSClient();

export const sendVulnsNotification = async (
  topicArn: string,
  errorMessage: string,
  imageIdentifier: string,
  logsDetails: ScanLogsDetails,
) => {
  let scanLogsLocation = '';
  let awsCliCommand = '';

  if (logsDetails.type === 'cloudwatch') {
    scanLogsLocation = `CloudWatch Logs:\n  Log Group: ${logsDetails.logGroupName}\n  Findings Stream: ${logsDetails.findingsLogStreamName}\n  Summary Stream: ${logsDetails.summaryLogStreamName}`;
    awsCliCommand = `- View findings:\n\`\`\`\naws logs tail ${logsDetails.logGroupName} --log-stream-names ${logsDetails.findingsLogStreamName} --since 1h\n\`\`\`\n\n- View summary:\n\`\`\`\naws logs tail ${logsDetails.logGroupName} --log-stream-names ${logsDetails.summaryLogStreamName} --since 1h\n\`\`\``;
  } else if (logsDetails.type === 's3') {
    const sbomInfo = logsDetails.sbomKey
      ? `\n  SBOM: s3://${logsDetails.bucketName}/${logsDetails.sbomKey}`
      : '';
    scanLogsLocation = `S3:\n  Bucket: ${logsDetails.bucketName}\n  findings: s3://${logsDetails.bucketName}/${logsDetails.findingsKey}\n  summary: s3://${logsDetails.bucketName}/${logsDetails.summaryKey}${sbomInfo}`;
    const sbomCommand = logsDetails.sbomKey
      ? `\n\n- View SBOM:\n\`\`\`\naws s3 cp s3://${logsDetails.bucketName}/${logsDetails.sbomKey} -\n\`\`\``
      : '';
    awsCliCommand = `- View findings:\n\`\`\`\naws s3 cp s3://${logsDetails.bucketName}/${logsDetails.findingsKey} -\n\`\`\`\n\n- View summary:\n\`\`\`\naws s3 cp s3://${logsDetails.bucketName}/${logsDetails.summaryKey} -\n\`\`\`${sbomCommand}`;
  } else if (logsDetails.type === 'default') {
    scanLogsLocation = `CloudWatch Logs:\n  Log Group: ${logsDetails.logGroupName}`;
    awsCliCommand = `\`\`\`\naws logs tail ${logsDetails.logGroupName} --since 1h\n\`\`\``;
  }

  const logsInfo = `${scanLogsLocation}\n\nHow to view logs:\n${awsCliCommand}`;

  const chatbotMessage = {
    version: '1.0',
    source: 'custom',
    content: {
      title: 'Ecr Scan Verifier - Vulnerability Alert',
      description: `## Scanned Image\n${imageIdentifier}\n\n## Scan Logs\n${logsInfo}\n\n## Details\n${errorMessage}`,
    },
  };

  const plainTextMessage = `Ecr Scan Verifier detected vulnerabilities in ${imageIdentifier}\n\n${logsInfo}\n\n${errorMessage}`;

  const messageStructure = {
    default: plainTextMessage,
    email: plainTextMessage,
    https: JSON.stringify(chatbotMessage),
  };

  try {
    await snsClient.send(
      new PublishCommand({
        TopicArn: topicArn,
        Message: JSON.stringify(messageStructure),
        MessageStructure: 'json',
      }),
    );
    console.log(`Vulnerability notification sent to SNS topic: ${topicArn}`);
  } catch (error) {
    console.error(`Failed to send vulnerability notification to SNS: ${error}`);
  }
};
