import {
  CloudWatchLogsClient,
  CreateLogStreamCommand,
  PutLogEventsCommand,
  ResourceAlreadyExistsException,
} from '@aws-sdk/client-cloudwatch-logs';
import { mockClient } from 'aws-sdk-client-mock';
import { outputScanLogsToCWLogs } from '../lib/cloudwatch-logs';
import { ScanLogsOutputType } from '../../../src/scan-logs-output';

const MAX_LOG_EVENT_SIZE = 1048576; // 1 MB in bytes

const cwMock = mockClient(CloudWatchLogsClient);

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
        outputScanLogsToCWLogs('{}', 'summary', output, 'my-repo:v1.0'),
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

      await outputScanLogsToCWLogs(largeFindingsJson, 'summary', output, 'my-repo:v1.0');

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
});
