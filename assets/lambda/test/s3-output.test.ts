import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { mockClient } from 'aws-sdk-client-mock';
import { outputScanLogsToS3, outputSignatureVerificationLogsToS3 } from '../lib/s3-output';
import { ScanLogsOutputType } from '../../../src/scan-logs-output';

const s3Mock = mockClient(S3Client);

describe('s3-output', () => {
  beforeEach(() => {
    s3Mock.reset();
    jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('outputScanLogsToS3', () => {
    test('should add trailing slash when prefix does not end with slash', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
        prefix: 'scan-logs',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
      );

      expect(result.type).toBe('s3');
      expect(result.findingsKey).toMatch(/^scan-logs\//);
      expect(result.findingsKey).not.toMatch(/^scan-logs\/\//);
      expect(result.summaryKey).toMatch(/^scan-logs\//);
      expect(result.summaryKey).not.toMatch(/^scan-logs\/\//);
    });

    test('should not duplicate trailing slash when prefix ends with slash', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
        prefix: 'scan-logs/',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
      );

      expect(result.type).toBe('s3');
      expect(result.findingsKey).toMatch(/^scan-logs\//);
      expect(result.findingsKey).not.toMatch(/^scan-logs\/\//);
    });

    test('should upload findings.json and summary.txt', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
      );

      expect(s3Mock.calls()).toHaveLength(2);
      const calls = s3Mock.calls();
      const findingsCall = calls.find((call) =>
        (call.args[0] as PutObjectCommand).input.Key?.includes('findings.json'),
      );
      const summaryCall = calls.find((call) =>
        (call.args[0] as PutObjectCommand).input.Key?.includes('summary.txt'),
      );

      expect(findingsCall).toBeDefined();
      expect(summaryCall).toBeDefined();
      expect((findingsCall!.args[0] as PutObjectCommand).input.ContentType).toBe(
        'application/json',
      );
      expect((summaryCall!.args[0] as PutObjectCommand).input.ContentType).toBe('text/plain');

      expect(result).toEqual({
        type: 's3',
        bucketName: 'test-bucket',
        findingsKey: result.findingsKey,
        summaryKey: result.summaryKey,
      });
    });

    test('should handle empty prefix', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
      );

      expect(result.findingsKey).not.toMatch(/^\//);
      expect(result.summaryKey).not.toMatch(/^\//);
    });

    test('should upload SBOM alongside findings and summary when sbomContent provided', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const sbomContent = {
        content: '{"bomFormat": "CycloneDX"}',
        format: 'CYCLONEDX_1_4',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
        sbomContent,
      );

      expect(s3Mock.calls()).toHaveLength(3);
      const sbomCall = s3Mock.calls().find((call) =>
        (call.args[0] as PutObjectCommand).input.Key?.includes('sbom.cyclonedx.json'),
      );
      expect(sbomCall).toBeDefined();
      expect((sbomCall!.args[0] as PutObjectCommand).input.ContentType).toBe('application/json');
      expect((sbomCall!.args[0] as PutObjectCommand).input.Body).toBe(
        '{"bomFormat": "CycloneDX"}',
      );

      expect(result.sbomKey).toBeDefined();
      expect(result.sbomKey).toMatch(/sbom\.cyclonedx\.json$/);
    });

    test('should use spdx.json extension for SPDX format', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const sbomContent = {
        content: '{"spdxVersion": "SPDX-2.3"}',
        format: 'SPDX_2_3',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
        sbomContent,
      );

      expect(result.sbomKey).toBeDefined();
      expect(result.sbomKey).toMatch(/sbom\.spdx\.json$/);
    });

    test('should not upload SBOM when sbomContent is undefined', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const result = await outputScanLogsToS3(
        '{"findings": []}',
        'summary text',
        output,
        'my-repo:v1.0',
        undefined,
      );

      expect(s3Mock.calls()).toHaveLength(2);
      expect(result.sbomKey).toBeUndefined();
    });
  });

  describe('outputSignatureVerificationLogsToS3', () => {
    test('should upload signature verification result to S3', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
      };

      const verificationResult = {
        verified: true,
        message: 'Signature verification succeeded',
        verificationType: 'NOTATION' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      const result = await outputSignatureVerificationLogsToS3(
        verificationResult,
        output,
        'my-repo',
        'v1.0',
      );

      expect(s3Mock.calls()).toHaveLength(1);
      const call = s3Mock.calls()[0];
      const input = (call.args[0] as PutObjectCommand).input;

      expect(input.Bucket).toBe('test-bucket');
      expect(input.Key).toMatch(/^signature-verification\/my-repo\/v1.0\/2024-01-01T00:00:00.000Z\.json$/);
      expect(input.ContentType).toBe('application/json');
      expect(JSON.parse(input.Body as string)).toEqual(verificationResult);

      expect(result).toEqual({
        type: 's3',
        bucketName: 'test-bucket',
        key: expect.stringMatching(/^signature-verification\/my-repo\/v1.0\/2024-01-01T00:00:00.000Z\.json$/),
      });
    });

    test('should handle prefix with trailing slash', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
        prefix: 'logs/',
      };

      const verificationResult = {
        verified: false,
        message: 'Signature verification failed',
        verificationType: 'COSIGN' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      const result = await outputSignatureVerificationLogsToS3(
        verificationResult,
        output,
        'my-repo',
        'v1.0',
      );

      expect(result.key).toMatch(/^logs\/signature-verification\//);
      expect(result.key).not.toMatch(/^logs\/\/signature-verification\//);
    });

    test('should handle prefix without trailing slash', async () => {
      s3Mock.on(PutObjectCommand).resolves({});

      const output = {
        type: ScanLogsOutputType.S3,
        bucketName: 'test-bucket',
        prefix: 'logs',
      };

      const verificationResult = {
        verified: true,
        message: 'Signature verification succeeded',
        verificationType: 'NOTATION' as const,
        timestamp: '2024-01-01T00:00:00.000Z',
      };

      const result = await outputSignatureVerificationLogsToS3(
        verificationResult,
        output,
        'my-repo',
        'v1.0',
      );

      expect(result.key).toMatch(/^logs\/signature-verification\//);
      expect(result.key).not.toMatch(/^logs\/\/signature-verification\//);
    });
  });
});
