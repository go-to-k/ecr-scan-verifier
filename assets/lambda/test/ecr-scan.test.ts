import {
  ECRClient,
  StartImageScanCommand,
  DescribeImageScanFindingsCommand,
  GetRegistryScanningConfigurationCommand,
  BatchGetRepositoryScanningConfigurationCommand,
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

    test('should throw immediately when scan status is SCAN_ELIGIBILITY_EXPIRED', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).resolves({
        imageScanStatus: { status: 'SCAN_ELIGIBILITY_EXPIRED' },
        imageScanFindings: {},
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 100, createMockLogger()),
      ).rejects.toThrow('scan eligibility for the image has expired');

      // Fails on the first poll instead of exhausting all retries
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(1);
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

    test('should not check scan coverage when checkScanCoverage is not set', async () => {
      const scanNotFoundError = new Error('Scan not found');
      scanNotFoundError.name = 'ScanNotFoundException';

      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);

      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 2, createMockLogger()),
      ).rejects.toThrow('No scan results found for the image after');

      expect(ecrMock.commandCalls(GetRegistryScanningConfigurationCommand as any)).toHaveLength(0);
      expect(ecrMock.commandCalls(BatchGetRepositoryScanningConfigurationCommand)).toHaveLength(0);
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

  describe('waitForScanResults with checkScanCoverage', () => {
    const scanNotFoundError = new Error('Scan not found');
    scanNotFoundError.name = 'ScanNotFoundException';

    test('should fail fast when the repository is not covered by Enhanced scanning filters', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'ENHANCED', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [
          {
            repositoryName: 'my-repo',
            scanOnPush: false,
            scanFrequency: 'MANUAL',
            appliedScanFilters: [],
          },
        ],
        failures: [],
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 100, createMockLogger(), true),
      ).rejects.toThrow("Repository 'my-repo' is not covered by any Enhanced scanning filter");

      // Fails on the first poll instead of exhausting all retries
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(1);
    });

    test('should fail fast when Enhanced scanning is requested but the registry uses BASIC', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'BASIC', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [
          { repositoryName: 'my-repo', scanOnPush: true, appliedScanFilters: [] },
        ],
        failures: [],
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 100, createMockLogger(), true),
      ).rejects.toThrow('Enhanced scanning (Amazon Inspector) is not enabled for this registry');
    });

    test('should fail fast when scan on push is disabled for BASIC scanning', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'BASIC', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [
          { repositoryName: 'my-repo', scanOnPush: false, appliedScanFilters: [] },
        ],
        failures: [],
      });

      await expect(
        waitForScanResults('my-repo', imageTag, 'BASIC', 0, 100, createMockLogger(), true),
      ).rejects.toThrow("Scan on push is not enabled for repository 'my-repo'");
    });

    test('should continue polling when the repository is covered by Enhanced scanning filters', async () => {
      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .rejectsOnce(scanNotFoundError)
        .rejectsOnce(scanNotFoundError)
        .resolves({
          imageScanStatus: { status: 'ACTIVE' },
          imageScanFindings: {
            enhancedFindings: [],
            findingSeverityCounts: {},
          },
        });
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'ENHANCED', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [
          {
            repositoryName: 'my-repo',
            scanOnPush: false,
            scanFrequency: 'CONTINUOUS_SCAN',
            appliedScanFilters: [{ filter: 'my-*', filterType: 'WILDCARD' }],
          },
        ],
        failures: [],
      });

      const result = await waitForScanResults(
        'my-repo', imageTag, 'ENHANCED', 0, 5, createMockLogger(), true,
      );

      expect(result.status).toBe('ACTIVE');
      // The coverage check runs only once even across multiple ScanNotFoundException retries
      expect(ecrMock.commandCalls(GetRegistryScanningConfigurationCommand as any)).toHaveLength(1);
      expect(ecrMock.commandCalls(BatchGetRepositoryScanningConfigurationCommand)).toHaveLength(1);
    });

    test('should continue polling when scan on push is enabled for BASIC scanning', async () => {
      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .rejectsOnce(scanNotFoundError)
        .resolves({
          imageScanStatus: { status: 'COMPLETE' },
          imageScanFindings: {
            findings: [],
            findingSeverityCounts: {},
          },
        });
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'BASIC', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [
          { repositoryName: 'my-repo', scanOnPush: true, appliedScanFilters: [] },
        ],
        failures: [],
      });

      const result = await waitForScanResults(
        'my-repo', imageTag, 'BASIC', 0, 5, createMockLogger(), true,
      );

      expect(result.status).toBe('COMPLETE');
    });

    test('should continue polling when the coverage check API call fails', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).rejects(new Error('Access denied'));

      const logger = createMockLogger();
      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 3, logger, true),
      ).rejects.toThrow('No scan results found for the image after');

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Could not verify the registry scanning configuration'),
      );
      expect(ecrMock.commandCalls(DescribeImageScanFindingsCommand)).toHaveLength(3);
    });

    test('should continue polling when the repository scanning configuration returns a failure', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({
        scanningConfiguration: { scanType: 'ENHANCED', rules: [] },
      });
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [],
        failures: [
          {
            repositoryName: 'my-repo',
            failureCode: 'REPOSITORY_NOT_FOUND',
            failureReason: 'Repository not found',
          },
        ],
      });

      const logger = createMockLogger();
      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 3, logger, true),
      ).rejects.toThrow('No scan results found for the image after');

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("Could not verify the scanning configuration for repository 'my-repo'"),
      );
    });

    test('should continue polling when the registry scan type cannot be determined', async () => {
      ecrMock.on(DescribeImageScanFindingsCommand).rejects(scanNotFoundError);
      ecrMock.on(GetRegistryScanningConfigurationCommand).resolves({});
      ecrMock.on(BatchGetRepositoryScanningConfigurationCommand).resolves({
        scanningConfigurations: [],
        failures: [],
      });

      const logger = createMockLogger();
      await expect(
        waitForScanResults('my-repo', imageTag, 'ENHANCED', 0, 3, logger, true),
      ).rejects.toThrow('No scan results found for the image after');

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Could not determine the registry scan type'),
      );
    });

    test('startAndWaitForScan should never check scan coverage', async () => {
      ecrMock.on(StartImageScanCommand).resolves({});
      ecrMock
        .on(DescribeImageScanFindingsCommand)
        .rejectsOnce(scanNotFoundError)
        .resolves({
          imageScanStatus: { status: 'COMPLETE' },
          imageScanFindings: {
            findings: [],
            findingSeverityCounts: {},
          },
        });

      const result = await startAndWaitForScan('my-repo', imageTag, 'BASIC', 0, 3, createMockLogger());

      expect(result.status).toBe('COMPLETE');
      expect(ecrMock.commandCalls(GetRegistryScanningConfigurationCommand as any)).toHaveLength(0);
      expect(ecrMock.commandCalls(BatchGetRepositoryScanningConfigurationCommand)).toHaveLength(0);
    });
  });
});
