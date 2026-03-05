import {
  CloudWatchLogsClient,
  CreateLogStreamCommand,
  PutLogEventsCommand,
  ResourceAlreadyExistsException,
} from '@aws-sdk/client-cloudwatch-logs';
import { mockClient } from 'aws-sdk-client-mock';
import { outputScanLogsToCWLogs, outputSignatureVerificationLogsToCWLogs } from '../lib/cloudwatch-logs';
import { ScanLogsOutputType } from '../../../src/scan-logs-output';
import { Logger } from '../lib/logger';

const MAX_LOG_EVENT_SIZE = 1048576; // 1 MB in bytes

const cwMock = mockClient(CloudWatchLogsClient);
const mockLogger = new Logger({ repositoryName: 'my-repo', imageTag: 'v1.0' });

describe('cloudwatch-logs', () => {
  beforeEach(() => {
    cwMock.reset();
    jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('outputScanLogsToCWLogs', () => {
    test('should generate log stream names for findings and summary', async () => {
      cwMock.on(CreateLogStreamCommand).resolves({});
      cwMock.on(PutLogEventsCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      const result = await outputScanLogsToCWLogs(
        '{"findings": []}',
        'No vulnerabilities found.',
        output,
        'my-repo:v1.0',
        mockLogger,
      );

      expect(result).toEqual({
        type: 'cloudwatch',
        logGroupName: '/aws/lambda/test',
        findingsLogStreamName: 'my-repo,v1.0/findings',
        summaryLogStreamName: 'my-repo,v1.0/summary',
      });
    });

    test('should handle image identifier without tag', async () => {
      cwMock.on(CreateLogStreamCommand).resolves({});
      cwMock.on(PutLogEventsCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      const result = await outputScanLogsToCWLogs(
        '{"findings": []}',
        'summary',
        output,
        'my-repo',
        mockLogger,
      );

      expect(result.findingsLogStreamName).toBe('my-repo/findings');
      expect(result.summaryLogStreamName).toBe('my-repo/summary');
    });

    test('should handle ResourceAlreadyExistsException gracefully', async () => {
      cwMock.on(CreateLogStreamCommand).rejects(
        new ResourceAlreadyExistsException({
          message: 'Log stream already exists',
          $metadata: {},
        }),
      );
      cwMock.on(PutLogEventsCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      await expect(
        outputScanLogsToCWLogs('{}', 'summary', output, 'my-repo:v1.0', mockLogger),
      ).resolves.not.toThrow();

      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('already exists'));
    });

    test('should split and send large messages', async () => {
      cwMock.on(CreateLogStreamCommand).resolves({});
      cwMock.on(PutLogEventsCommand).resolves({});

      const largeFindingsJson = 'a'.repeat(2 * MAX_LOG_EVENT_SIZE);
      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      await outputScanLogsToCWLogs(largeFindingsJson, 'summary', output, 'my-repo:v1.0', mockLogger);

      const putLogEventsCalls = cwMock.commandCalls(PutLogEventsCommand);
      expect(putLogEventsCalls.length).toBe(2); // findings + summary

      const findingsCall = putLogEventsCalls.find(
        (call) => call.args[0].input.logStreamName === 'my-repo,v1.0/findings',
      );
      expect(findingsCall).toBeDefined();
      const logEvents = findingsCall?.args[0].input.logEvents;
      expect(logEvents).toBeDefined();
      expect(logEvents!.length).toBeGreaterThan(1);

      logEvents!.forEach((event: any) => {
        expect(event.message).toMatch(/^\[part \d+\/\d+\]/);
      });
    });
  });

  describe('outputSignatureVerificationLogsToCWLogs', () => {
    test('should create log stream and put signature verification result', async () => {
      cwMock.on(CreateLogStreamCommand).resolves({});
      cwMock.on(PutLogEventsCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      const verificationResult = {
        verified: true,
        message: 'Signature verification succeeded',
        verificationType: 'NOTATION' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      const result = await outputSignatureVerificationLogsToCWLogs(
        verificationResult,
        output,
        'my-repo',
        'v1.0',
        mockLogger,
      );

      expect(result).toEqual({
        type: 'cloudwatch',
        logGroupName: '/aws/lambda/test',
        logStreamName: 'my-repo_v1.0/signature-verification',
      });

      const createLogStreamCalls = cwMock.commandCalls(CreateLogStreamCommand);
      expect(createLogStreamCalls).toHaveLength(1);
      expect(createLogStreamCalls[0].args[0].input).toEqual({
        logGroupName: '/aws/lambda/test',
        logStreamName: 'my-repo_v1.0/signature-verification',
      });

      const putLogEventsCalls = cwMock.commandCalls(PutLogEventsCommand);
      expect(putLogEventsCalls).toHaveLength(1);
      const logEvents = putLogEventsCalls[0].args[0].input.logEvents;
      expect(logEvents).toHaveLength(1);
      expect(JSON.parse((logEvents![0] as any).message)).toEqual(verificationResult);
    });

    test('should sanitize repository name and image tag', async () => {
      cwMock.on(CreateLogStreamCommand).resolves({});
      cwMock.on(PutLogEventsCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      const verificationResult = {
        verified: false,
        message: 'Signature verification failed',
        verificationType: 'COSIGN' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      await outputSignatureVerificationLogsToCWLogs(
        verificationResult,
        output,
        'my-org/my-repo',
        'v1.0:latest',
        mockLogger,
      );

      const createLogStreamCalls = cwMock.commandCalls(CreateLogStreamCommand);
      expect(createLogStreamCalls[0].args[0].input.logStreamName).toBe(
        'my-org_my-repo_v1.0,latest/signature-verification',
      );
    });

    test('should handle existing log stream', async () => {
      cwMock
        .on(CreateLogStreamCommand)
        .rejects(new ResourceAlreadyExistsException({ $metadata: {}, message: 'already exists' }));
      cwMock.on(PutLogEventsCommand).resolves({});
      jest.spyOn(console, 'log').mockImplementation();

      const output = {
        type: ScanLogsOutputType.CLOUDWATCH_LOGS,
        logGroupName: '/aws/lambda/test',
      };

      const verificationResult = {
        verified: true,
        message: 'Signature verification succeeded',
        verificationType: 'NOTATION' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      await expect(
        outputSignatureVerificationLogsToCWLogs(verificationResult, output, 'my-repo', 'v1.0', mockLogger),
      ).resolves.not.toThrow();

      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Log stream my-repo_v1.0/signature-verification already exists'),
      );
    });
  });
});
