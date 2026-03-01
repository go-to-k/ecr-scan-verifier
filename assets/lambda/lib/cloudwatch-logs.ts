import {
  CloudWatchLogsClient,
  CreateLogStreamCommand,
  PutLogEventsCommand,
  PutLogEventsCommandInput,
  ResourceAlreadyExistsException,
} from '@aws-sdk/client-cloudwatch-logs';
import { CloudWatchLogsOutputOptions } from '../../../src/scan-logs-output';
import { CloudWatchLogsDetails } from './types';

const cwClient = new CloudWatchLogsClient();

export const outputScanLogsToCWLogs = async (
  findingsJson: string,
  summaryText: string,
  output: CloudWatchLogsOutputOptions,
  imageIdentifier: string,
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
  );

  await createLogStreamAndPutEvents(
    output.logGroupName,
    summaryLogStreamName,
    timestamp,
    summaryText,
  );

  console.log(
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
      console.log(`Log stream ${logStreamName} already exists in log group ${logGroupName}.`);
    } else {
      throw e;
    }
  }

  const chunks = splitMessageIntoChunks(message);
  const totalChunks = chunks.length;

  if (totalChunks > 1) {
    console.log(`Message size exceeds 1 MB limit. Splitting into ${totalChunks} chunks.`);
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
