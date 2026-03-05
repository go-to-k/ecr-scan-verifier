import {
  CloudWatchLogsClient,
  CreateLogStreamCommand,
  PutLogEventsCommand,
  PutLogEventsCommandInput,
  ResourceAlreadyExistsException,
} from '@aws-sdk/client-cloudwatch-logs';
import { CloudWatchLogsOutputOptions } from '../../../src/scan-logs-output';
import { CloudWatchLogsDetails, SignatureVerificationCloudWatchLogsDetails } from './types';
import { SignatureVerificationResult } from './signature-verification';
import { Logger } from './logger';

const cwClient = new CloudWatchLogsClient();

export const outputScanLogsToCWLogs = async (
  findingsJson: string,
  summaryText: string,
  output: CloudWatchLogsOutputOptions,
  imageIdentifier: string,
  logger: Logger,
): Promise<CloudWatchLogsDetails> => {
  const sanitized = imageIdentifier.replace(/:/g, ',').replace(/\//g, '_');
  const findingsLogStreamName = `${sanitized}/findings`;
  const summaryLogStreamName = `${sanitized}/summary`;

  const timestamp = new Date().getTime();

  await createLogStreamAndPutEvents(
    output.logGroupName,
    findingsLogStreamName,
    timestamp,
    findingsJson,
    logger,
  );

  await createLogStreamAndPutEvents(
    output.logGroupName,
    summaryLogStreamName,
    timestamp,
    summaryText,
    logger,
  );

  logger.log(
    `Scan logs output to the log group: ${output.logGroupName}\n  findings stream: ${findingsLogStreamName}\n  summary stream: ${summaryLogStreamName}`,
  );

  return {
    type: 'cloudwatch',
    logGroupName: output.logGroupName,
    findingsLogStreamName,
    summaryLogStreamName,
  };
};

/**
 * CloudWatch Logs has a limit of 1 MB per log event.
 * If the message exceeds this limit, it will be split into multiple log events.
 * Each chunk will be prefixed with [part X/Y] to indicate the sequence.
 */
const MAX_LOG_EVENT_SIZE = 1048576; // 1 MB in bytes

const splitMessageIntoChunks = (message: string): string[] => {
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(message);

  if (messageBytes.length <= MAX_LOG_EVENT_SIZE) {
    return [message];
  }

  const chunks: string[] = [];
  let currentPosition = 0;

  const prefixReserve = 20;
  const chunkSize = MAX_LOG_EVENT_SIZE - prefixReserve;

  while (currentPosition < messageBytes.length) {
    const chunkBytes = messageBytes.slice(currentPosition, currentPosition + chunkSize);
    const decoder = new TextDecoder('utf-8', { fatal: false });
    chunks.push(decoder.decode(chunkBytes));
    currentPosition += chunkSize;
  }

  return chunks;
};

const createLogStreamAndPutEvents = async (
  logGroupName: string,
  logStreamName: string,
  timestamp: number,
  message: string,
  logger: Logger,
) => {
  try {
    await cwClient.send(
      new CreateLogStreamCommand({
        logGroupName,
        logStreamName,
      }),
    );
  } catch (e) {
    if (e instanceof ResourceAlreadyExistsException) {
      logger.log(`Log stream ${logStreamName} already exists in log group ${logGroupName}.`);
    } else {
      throw e;
    }
  }

  const chunks = splitMessageIntoChunks(message);
  const totalChunks = chunks.length;

  if (totalChunks > 1) {
    logger.log(`Message size exceeds 1 MB limit. Splitting into ${totalChunks} chunks.`);
  }

  const logEvents = chunks.map((chunk, index) => ({
    timestamp: timestamp + index,
    message: totalChunks > 1 ? `[part ${index + 1}/${totalChunks}] ${chunk}` : chunk,
  }));

  const input: PutLogEventsCommandInput = {
    logGroupName,
    logStreamName,
    logEvents,
  };
  const command = new PutLogEventsCommand(input);
  await cwClient.send(command);
};

export const outputSignatureVerificationLogsToCWLogs = async (
  verificationResult: SignatureVerificationResult,
  output: CloudWatchLogsOutputOptions,
  repositoryName: string,
  imageTag: string,
  logger: Logger,
): Promise<SignatureVerificationCloudWatchLogsDetails> => {
  const sanitized = `${repositoryName}/${imageTag}`.replace(/:/g, ',').replace(/\//g, '_');
  const logStreamName = `${sanitized}/signature-verification`;

  const timestamp = new Date().getTime();
  const message = JSON.stringify(verificationResult, null, 2);

  await createLogStreamAndPutEvents(
    output.logGroupName,
    logStreamName,
    timestamp,
    message,
    logger,
  );

  logger.log(
    `Signature verification result output to the log group: ${output.logGroupName}\n  stream: ${logStreamName}`,
  );

  return {
    type: 'cloudwatch',
    logGroupName: output.logGroupName,
    logStreamName,
  };
};
