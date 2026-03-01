import { CdkCustomResourceEvent, Context } from 'aws-lambda';
import { handler } from '../lib/handler';
import * as ecrScan from '../lib/ecr-scan';
import * as findingsEvaluator from '../lib/findings-evaluator';
import * as cloudwatchLogs from '../lib/cloudwatch-logs';
import * as s3Output from '../lib/s3-output';
import * as snsNotification from '../lib/sns-notification';
import * as cloudformationUtils from '../lib/cloudformation-utils';
import * as sbomExport from '../lib/sbom-export';
import { ScanLogsOutputType } from '../../../src/scan-logs-output';

jest.mock('../lib/ecr-scan');
jest.mock('../lib/findings-evaluator');
jest.mock('../lib/cloudwatch-logs');
jest.mock('../lib/s3-output');
jest.mock('../lib/sns-notification');
jest.mock('../lib/cloudformation-utils');
jest.mock('../lib/sbom-export');

describe('handler', () => {
  const mockContext = {} as Context;
  const mockCallback = jest.fn();

  const mockScanFindings: ecrScan.ScanFindings = {
    scanType: 'BASIC',
    status: 'COMPLETE',
    basicFindings: [],
    enhancedFindings: [],
    severityCounts: {},
    rawResponse: {
      $metadata: {},
      imageScanFindings: {
        findings: [],
        findingSeverityCounts: {},
      },
    },
  };

  const baseEvent: CdkCustomResourceEvent = {
    RequestType: 'Create',
    ServiceToken: 'token',
    ResponseURL: 'https://example.com',
    StackId: 'stack-id',
    RequestId: 'request-id',
    LogicalResourceId: 'logical-id',
    ResourceType: 'Custom::EcrScanVerifier',
    ResourceProperties: {
      ServiceToken: 'token',
      addr: 'test-addr',
      repositoryName: 'my-repo',
      imageTag: 'v1.0',
      scanType: 'BASIC',
      startScan: 'true',
      severity: ['CRITICAL'],
      failOnVulnerability: 'true',
      ignoreFindings: [],
      suppressErrorOnRollback: 'true',
      defaultLogGroupName: '/aws/lambda/default',
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation();
    (ecrScan.startAndWaitForScan as jest.Mock).mockResolvedValue(mockScanFindings);
    (ecrScan.waitForScanResults as jest.Mock).mockResolvedValue(mockScanFindings);
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: false,
      summary: '',
      filteredSeverityCounts: {},
    });
    (findingsEvaluator.formatScanSummary as jest.Mock).mockReturnValue('summary text');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('should throw error when addr is missing', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        addr: undefined,
      },
    };

    await expect(handler(event, mockContext, mockCallback)).rejects.toThrow(
      'addr and repositoryName are required.',
    );
  });

  test('should throw error when repositoryName is missing', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        repositoryName: undefined,
      },
    };

    await expect(handler(event, mockContext, mockCallback)).rejects.toThrow(
      'addr and repositoryName are required.',
    );
  });

  test('should return early for Delete request', async () => {
    const event = {
      ...baseEvent,
      RequestType: 'Delete' as const,
      PhysicalResourceId: 'test-addr',
    };

    const result = await handler(event, mockContext, mockCallback);

    expect(result?.PhysicalResourceId).toBe('test-addr');
    expect(ecrScan.startAndWaitForScan).not.toHaveBeenCalled();
  });

  test('should call startAndWaitForScan when startScan is true', async () => {
    await handler(baseEvent, mockContext, mockCallback);

    expect(ecrScan.startAndWaitForScan).toHaveBeenCalledWith(
      'my-repo',
      'v1.0',
      'BASIC',
      5,
      60,
    );
  });

  test('should call waitForScanResults when startScan is false', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        startScan: 'false',
      },
    };

    await handler(event, mockContext, mockCallback);

    expect(ecrScan.waitForScanResults).toHaveBeenCalled();
    expect(ecrScan.startAndWaitForScan).not.toHaveBeenCalled();
  });

  test('should return successfully when no vulnerabilities found', async () => {
    const result = await handler(baseEvent, mockContext, mockCallback);

    expect(result?.PhysicalResourceId).toBe('test-addr');
    expect(snsNotification.sendVulnsNotification).not.toHaveBeenCalled();
  });

  test('should return successfully when failOnVulnerability is false', async () => {
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: true,
      summary: 'CRITICAL: 1',
      filteredSeverityCounts: { CRITICAL: 1 },
    });

    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        failOnVulnerability: 'false',
      },
    };

    const result = await handler(event, mockContext, mockCallback);

    expect(result?.PhysicalResourceId).toBe('test-addr');
  });

  test('should suppress error when suppressErrorOnRollback is true and rollback is in progress', async () => {
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: true,
      summary: 'CRITICAL: 1',
      filteredSeverityCounts: { CRITICAL: 1 },
    });
    (cloudformationUtils.isRollbackInProgress as jest.Mock).mockResolvedValue(true);

    const result = await handler(baseEvent, mockContext, mockCallback);

    expect(result?.PhysicalResourceId).toBe('test-addr');
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining('suppressing errors during rollback'),
    );
  });

  test('should throw error when vulnerabilities found and failOnVulnerability is true', async () => {
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: true,
      summary: 'CRITICAL: 1',
      filteredSeverityCounts: { CRITICAL: 1 },
    });
    (cloudformationUtils.isRollbackInProgress as jest.Mock).mockResolvedValue(false);

    await expect(handler(baseEvent, mockContext, mockCallback)).rejects.toThrow(
      'ECR Image Scan found vulnerabilities.',
    );
  });

  test('should send SNS notification when vulnsTopicArn is provided', async () => {
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: true,
      summary: 'CRITICAL: 1',
      filteredSeverityCounts: { CRITICAL: 1 },
    });
    (cloudformationUtils.isRollbackInProgress as jest.Mock).mockResolvedValue(false);

    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        vulnsTopicArn: 'arn:aws:sns:us-east-1:123456789012:test-topic',
      },
    };

    await expect(handler(event, mockContext, mockCallback)).rejects.toThrow(
      'ECR Image Scan found vulnerabilities.',
    );

    expect(snsNotification.sendVulnsNotification).toHaveBeenCalledWith(
      'arn:aws:sns:us-east-1:123456789012:test-topic',
      expect.stringContaining('ECR Image Scan found vulnerabilities.'),
      'my-repo:v1.0',
      expect.objectContaining({ type: 'default' }),
    );
  });

  test('should not send SNS notification when vulnsTopicArn is not provided', async () => {
    (findingsEvaluator.evaluateFindings as jest.Mock).mockReturnValue({
      hasVulnerabilities: true,
      summary: 'CRITICAL: 1',
      filteredSeverityCounts: { CRITICAL: 1 },
    });
    (cloudformationUtils.isRollbackInProgress as jest.Mock).mockResolvedValue(false);

    await expect(handler(baseEvent, mockContext, mockCallback)).rejects.toThrow();

    expect(snsNotification.sendVulnsNotification).not.toHaveBeenCalled();
  });

  test('should call outputScanLogsToCWLogs when output type is CLOUDWATCH_LOGS', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        output: {
          type: ScanLogsOutputType.CLOUDWATCH_LOGS,
          logGroupName: '/aws/lambda/test',
        },
      },
    };

    await handler(event, mockContext, mockCallback);

    expect(cloudwatchLogs.outputScanLogsToCWLogs).toHaveBeenCalled();
  });

  test('should call outputScanLogsToS3 when output type is S3', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        output: {
          type: ScanLogsOutputType.S3,
          bucketName: 'test-bucket',
        },
      },
    };

    await handler(event, mockContext, mockCallback);

    expect(s3Output.outputScanLogsToS3).toHaveBeenCalled();
  });

  test('should call exportSbom when sbom is configured with ENHANCED scan', async () => {
    const mockEnhancedScanFindings: ecrScan.ScanFindings = {
      ...mockScanFindings,
      scanType: 'ENHANCED',
    };
    (ecrScan.startAndWaitForScan as jest.Mock).mockResolvedValue(mockEnhancedScanFindings);
    (sbomExport.exportSbom as jest.Mock).mockResolvedValue({
      sbomContent: '{"bomFormat": "CycloneDX"}',
      format: 'CYCLONEDX_1_4',
    });

    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        scanType: 'ENHANCED',
        sbom: {
          format: 'CYCLONEDX_1_4',
          bucketName: 'sbom-bucket',
        },
        output: {
          type: ScanLogsOutputType.S3,
          bucketName: 'sbom-bucket',
        },
      },
    };

    await handler(event, mockContext, mockCallback);

    expect(sbomExport.exportSbom).toHaveBeenCalledWith(
      'my-repo',
      'v1.0',
      'CYCLONEDX_1_4',
      'sbom-bucket',
      undefined,
    );
    expect(s3Output.outputScanLogsToS3).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ type: ScanLogsOutputType.S3 }),
      'my-repo:v1.0',
      { content: '{"bomFormat": "CycloneDX"}', format: 'CYCLONEDX_1_4' },
    );
  });

  test('should skip SBOM export for BASIC scan type even when sbom is set', async () => {
    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        scanType: 'BASIC',
        sbom: {
          format: 'CYCLONEDX_1_4',
          bucketName: 'sbom-bucket',
        },
      },
    };

    await handler(event, mockContext, mockCallback);

    expect(sbomExport.exportSbom).not.toHaveBeenCalled();
  });

  test('should throw error when SBOM export fails', async () => {
    const mockEnhancedScanFindings: ecrScan.ScanFindings = {
      ...mockScanFindings,
      scanType: 'ENHANCED',
    };
    (ecrScan.startAndWaitForScan as jest.Mock).mockResolvedValue(mockEnhancedScanFindings);
    (sbomExport.exportSbom as jest.Mock).mockRejectedValue(new Error('SBOM export failed'));

    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        scanType: 'ENHANCED',
        sbom: {
          format: 'CYCLONEDX_1_4',
          bucketName: 'sbom-bucket',
        },
      },
    };

    await expect(handler(event, mockContext, mockCallback)).rejects.toThrow(
      'SBOM export failed',
    );
  });

  test('should not call exportSbom when sbom is not set', async () => {
    await handler(baseEvent, mockContext, mockCallback);

    expect(sbomExport.exportSbom).not.toHaveBeenCalled();
  });

  test('should log enhanced findings instead of empty basic findings for Enhanced scanning', async () => {
    const enhancedFinding = {
      packageVulnerabilityDetails: { vulnerabilityId: 'CVE-2024-0001' },
      severity: 'HIGH',
      status: 'ACTIVE',
      title: 'Test vulnerability',
    };
    const mockEnhancedScanFindings: ecrScan.ScanFindings = {
      scanType: 'ENHANCED',
      status: 'ACTIVE',
      basicFindings: [],
      enhancedFindings: [enhancedFinding],
      severityCounts: { HIGH: 1 },
      rawResponse: {
        $metadata: {},
        imageScanFindings: {
          findings: [],
          findingSeverityCounts: {},
        },
      },
    };
    (ecrScan.startAndWaitForScan as jest.Mock).mockResolvedValue(mockEnhancedScanFindings);

    const event = {
      ...baseEvent,
      ResourceProperties: {
        ...baseEvent.ResourceProperties,
        scanType: 'ENHANCED',
      },
    };

    await handler(event, mockContext, mockCallback);

    const findingsLog = (console.log as jest.Mock).mock.calls.find(
      (call: unknown[]) => typeof call[0] === 'string' && call[0].startsWith('findings:'),
    );
    expect(findingsLog).toBeDefined();
    expect(findingsLog![0]).toContain('CVE-2024-0001');
  });

  test('should log basic findings for Basic scanning', async () => {
    const basicFinding = {
      name: 'CVE-2024-0002',
      severity: 'CRITICAL' as const,
      uri: 'https://example.com',
    };
    const mockBasicScanFindings: ecrScan.ScanFindings = {
      scanType: 'BASIC',
      status: 'COMPLETE',
      basicFindings: [basicFinding],
      enhancedFindings: [],
      severityCounts: { CRITICAL: 1 },
      rawResponse: {
        $metadata: {},
        imageScanFindings: {
          findings: [basicFinding],
          findingSeverityCounts: { CRITICAL: 1 },
        },
      },
    };
    (ecrScan.startAndWaitForScan as jest.Mock).mockResolvedValue(mockBasicScanFindings);

    await handler(baseEvent, mockContext, mockCallback);

    const findingsLog = (console.log as jest.Mock).mock.calls.find(
      (call: unknown[]) => typeof call[0] === 'string' && call[0].startsWith('findings:'),
    );
    expect(findingsLog).toBeDefined();
    expect(findingsLog![0]).toContain('CVE-2024-0002');
  });
});
