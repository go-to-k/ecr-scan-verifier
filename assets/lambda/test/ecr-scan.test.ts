import {
  ECRClient,
  StartImageScanCommand,
  DescribeImageScanFindingsCommand,
} from '@aws-sdk/client-ecr';
import { mockClient } from 'aws-sdk-client-mock';
import { startAndWaitForScan, waitForScanResults } from '../lib/ecr-scan';
import { Logger } from '../lib/logger';

const ecrMock = mockClient(ECRClient);

const createMockLogger = (): Logger => ({
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
} as any);

describe('ecr-scan', () => {
  beforeEach(() => {
    ecrMock.reset();
    jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const imageTag = 'v1.0';

  describe('startAndWaitForScan', () => {
    test('should start scan and return findings on COMPLETE', async () => {
      ecrMock.on(StartImageScanCommand).resolves({});
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'COMPLETE' },
        imageScanFindings: {
          findings: [
            { name: 'CVE-2023-1234', severity: 'HIGH' },
          ],
          findingSeverityCounts: { HIGH: 1 },
        },
      });

      const result = await startAndWaitForScan('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.status).toBe('COMPLETE');
      expect(result.basicFindings).toHaveLength(1);
      expect(result.severityCounts).toEqual({ HIGH: 1 });
      expect(ecrMock.commandCalls(StartImageScanCommand)).toHaveLength(1);
    });

    test('should continue when LimitExceededException occurs on StartImageScan', async () => {
      const limitError = new Error('scan frequency limit exceeded');
      limitError.name = 'LimitExceededException';
      ecrMock.on(StartImageScanCommand).rejects(limitError);
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'COMPLETE' },
        imageScanFindings: {
          findings: [],
          findingSeverityCounts: {},
        },
      });

      const result = await startAndWaitForScan('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.status).toBe('COMPLETE');
    });

    test('should throw when Enhanced scanning disables StartImageScan', async () => {
      const validationError = new Error('This feature is disabled');
      validationError.name = 'ValidationException';
      ecrMock.on(StartImageScanCommand).rejects(validationError);

      await expect(
        startAndWaitForScan('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger()),
      ).rejects.toThrow('Use ScanConfig.enhanced() instead of ScanConfig.basic().');
    });

    test('should throw non-LimitExceededException errors from StartImageScan', async () => {
      ecrMock.on(StartImageScanCommand).rejects(new Error('Access denied'));

      await expect(
        startAndWaitForScan('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger()),
      ).rejects.toThrow('Access denied');
    });

    test('should use imageDigest when sha256: prefix is provided', async () => {
      ecrMock.on(StartImageScanCommand).resolves({});
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'COMPLETE' },
        imageScanFindings: {
          findings: [],
          findingSeverityCounts: {},
        },
      });

      await startAndWaitForScan(
        'my-repo',
        'sha256:abc123',
        'BASIC',
        0,
        3,
        createMockLogger(),
      );

      const startCall = ecrMock.commandCalls(StartImageScanCommand)[0];
      expect(startCall.args[0].input.imageId).toEqual({
        imageDigest: 'sha256:abc123',
      });
    });
  });

  describe('waitForScanResults', () => {
    test('should return findings when scan status is COMPLETE', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'COMPLETE' },
        imageScanFindings: {
          findings: [
            { name: 'CVE-2023-5678', severity: 'CRITICAL' },
          ],
          findingSeverityCounts: { CRITICAL: 1 },
        },
      });

      const result = await waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.status).toBe('COMPLETE');
      expect(result.basicFindings).toHaveLength(1);
    });

    test('should return findings when scan status is ACTIVE (enhanced)', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'ACTIVE' },
        imageScanFindings: {
          enhancedFindings: [
            {
              severity: 'HIGH',
              findingArn: 'arn:aws:inspector2:us-east-1:123456789012:finding/abc',
              packageVulnerabilityDetails: {
                vulnerabilityId: 'CVE-2023-1234',
              },
            },
          ],
          findingSeverityCounts: { HIGH: 1 },
        },
      });

      const result = await waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 3, createMockLogger());

      expect(result.status).toBe('ACTIVE');
      expect(result.enhancedFindings).toHaveLength(1);
      expect(result.scanType).toBe('ENHANCED');
    });

    test('should throw error when scan status is FAILED', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: {
          status: 'FAILED',
          description: 'Internal error',
        },
        imageScanFindings: {},
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger()),
      ).rejects.toThrow('ECR image scan failed: Internal error');
    });

    test('should throw error when scan status is UNSUPPORTED_IMAGE', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'UNSUPPORTED_IMAGE' },
        imageScanFindings: {},
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger()),
      ).rejects.toThrow('Image is not supported for scanning');
    });

    test('should retry on ScanNotFoundException and eventually succeed', async () => {
      const scanNotFoundError = new Error('Scan not found');
      scanNotFoundError.name = 'ScanNotFoundException';

      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .rejectsOnce(scanNotFoundError)
        .rejectsOnce(scanNotFoundError)
        .resolves({
          imageScanStatus: { status: 'ACTIVE' },
          imageScanFindings: {
            enhancedFindings: [
              {
                severity: 'HIGH',
                findingArn: 'arn:aws:inspector2:us-east-1:123456789012:finding/abc',
                packageVulnerabilityDetails: {
                  vulnerabilityId: 'CVE-2023-1234',
                },
              },
            ],
            findingSeverityCounts: { HIGH: 1 },
          },
        });

      const result = await waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 5, createMockLogger());

      expect(result.status).toBe('ACTIVE');
      expect(result.enhancedFindings).toHaveLength(1);
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(3);
    });

    test('should throw after all retries on ScanNotFoundException', async () => {
      const scanNotFoundError = new Error('Scan not found');
      scanNotFoundError.name = 'ScanNotFoundException';

      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);

      await expect(
        waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger()),
      ).rejects.toThrow('No scan results found for the image after');
    });

    test('should poll until scan completes', async () => {
      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .resolvesOnce({
          imageScanStatus: { status: 'IN_PROGRESS' },
          imageScanFindings: {},
        })
        .resolves({
          imageScanStatus: { status: 'COMPLETE' },
          imageScanFindings: {
            findings: [],
            findingSeverityCounts: {},
          },
        });

      const result = await waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.status).toBe('COMPLETE');
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(2);
    });

    test('should timeout after max retries', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'IN_PROGRESS' },
        imageScanFindings: {},
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'BASIC', 0, 2, createMockLogger()),
      ).rejects.toThrow('ECR image scan timed out');
    });

    test('should handle pagination with nextToken', async () => {
      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .resolvesOnce({
          imageScanStatus: { status: 'COMPLETE' },
          imageScanFindings: {
            findings: [
              { name: 'CVE-2023-0001', severity: 'HIGH' },
            ],
            findingSeverityCounts: { HIGH: 2 },
          },
          nextToken: 'token-1',
        })
        .resolves({
          imageScanStatus: { status: 'COMPLETE' },
          imageScanFindings: {
            findings: [
              { name: 'CVE-2023-0002', severity: 'HIGH' },
            ],
            findingSeverityCounts: { HIGH: 2 },
          },
        });

      const result = await waitForScanResults('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.basicFindings).toHaveLength(2);
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(2);
    });

    test('should use tag as-is when no sha256: prefix', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'COMPLETE' },
        imageScanFindings: {
          findings: [],
          findingSeverityCounts: {},
        },
      });

      await waitForScanResults('my-repo', 'latest', 'BASIC', 0, 3, createMockLogger());

      const call = ecrMock.commandCalls(DescribeImageScanFindingsCommand)[0];
      expect(call.args[0].input.imageId).toEqual({ imageTag: 'latest' });
    });
  });
});
