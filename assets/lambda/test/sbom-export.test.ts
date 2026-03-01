import {
  Inspector2Client,
  CreateSbomExportCommand,
  GetSbomExportCommand,
} from '@aws-sdk/client-inspector2';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { mockClient } from 'aws-sdk-client-mock';
import { Readable } from 'stream';
import { sdkStreamMixin } from '@smithy/util-stream';
import { exportSbom } from '../lib/sbom-export';

const inspectorMock = mockClient(Inspector2Client);
const s3Mock = mockClient(S3Client);

const createMockStream = (content: string) => {
  const stream = new Readable();
  stream.push(content);
  stream.push(null);
  return sdkStreamMixin(stream);
};

describe('sbom-export', () => {
  beforeEach(() => {
    inspectorMock.reset();
    s3Mock.reset();
    jest.useFakeTimers();
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe('exportSbom', () => {
    test('should export SBOM in CycloneDX format', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-123',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'SUCCEEDED',
        s3Destination: {
          bucketName: 'test-bucket',
          keyPrefix: 'sbom-exports/my-repo/report.json',
        },
      });
      s3Mock.on(GetObjectCommand).resolves({
        Body: createMockStream('{"bomFormat": "CycloneDX"}'),
      });

      const result = await exportSbom(
        'my-repo',
        'v1.0',
        'CYCLONEDX_1_4',
        'test-bucket',
        'arn:aws:kms:us-east-1:123456789012:key/test-key',
      );

      expect(result.format).toBe('CYCLONEDX_1_4');
      expect(result.sbomContent).toBe('{"bomFormat": "CycloneDX"}');

      const createCall = inspectorMock.commandCalls(CreateSbomExportCommand)[0];
      expect(createCall.args[0].input.reportFormat).toBe('CYCLONEDX_1_4');
      expect(createCall.args[0].input.s3Destination?.bucketName).toBe('test-bucket');
    });

    test('should export SBOM in SPDX format', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-456',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'SUCCEEDED',
        s3Destination: {
          bucketName: 'test-bucket',
          keyPrefix: 'sbom-exports/my-repo/report.json',
        },
      });
      s3Mock.on(GetObjectCommand).resolves({
        Body: createMockStream('{"spdxVersion": "SPDX-2.3"}'),
      });

      const result = await exportSbom(
        'my-repo',
        'v1.0',
        'SPDX_2_3',
        'test-bucket',
        'arn:aws:kms:us-east-1:123456789012:key/test-key',
      );

      expect(result.format).toBe('SPDX_2_3');

      const createCall = inspectorMock.commandCalls(CreateSbomExportCommand)[0];
      expect(createCall.args[0].input.reportFormat).toBe('SPDX_2_3');
    });

    test('should include imageTag in resource filter', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-789',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'SUCCEEDED',
        s3Destination: {
          bucketName: 'test-bucket',
          keyPrefix: 'sbom-exports/my-repo/report.json',
        },
      });
      s3Mock.on(GetObjectCommand).resolves({
        Body: createMockStream('{}'),
      });

      await exportSbom('my-repo', 'v1.0', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key');

      const createCall = inspectorMock.commandCalls(CreateSbomExportCommand)[0];
      expect(createCall.args[0].input.resourceFilterCriteria?.ecrImageTags).toEqual([
        { comparison: 'EQUALS', value: 'v1.0' },
      ]);
    });

    test('should include imageTag in filter even for digest-style values', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-abc',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'SUCCEEDED',
        s3Destination: {
          bucketName: 'test-bucket',
          keyPrefix: 'sbom-exports/my-repo/report.json',
        },
      });
      s3Mock.on(GetObjectCommand).resolves({
        Body: createMockStream('{}'),
      });

      await exportSbom('my-repo', 'sha256:abc', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key');

      const createCall = inspectorMock.commandCalls(CreateSbomExportCommand)[0];
      expect(createCall.args[0].input.resourceFilterCriteria?.ecrImageTags).toEqual([
        { comparison: 'EQUALS', value: 'sha256:abc' },
      ]);
    });

    test('should throw when CreateSbomExport returns no reportId', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({});

      await expect(
        exportSbom('my-repo', 'v1.0', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key'),
      ).rejects.toThrow('CreateSbomExport did not return a reportId.');
    });

    test('should throw when SBOM export status is FAILED', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-fail',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'FAILED',
      });

      await expect(
        exportSbom('my-repo', 'v1.0', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key'),
      ).rejects.toThrow('SBOM export failed.');
    });

    test('should throw when SBOM export status is CANCELLED', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-cancel',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'CANCELLED',
      });

      await expect(
        exportSbom('my-repo', 'v1.0', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key'),
      ).rejects.toThrow('SBOM export was cancelled.');
    });

    test('should poll until SBOM export succeeds', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-poll',
      });
      inspectorMock
        .on(GetSbomExportCommand)
        .resolvesOnce({ status: 'IN_PROGRESS' })
        .resolves({
          status: 'SUCCEEDED',
          s3Destination: {
            bucketName: 'test-bucket',
            keyPrefix: 'sbom-exports/my-repo/report.json',
          },
        });
      s3Mock.on(GetObjectCommand).resolves({
        Body: createMockStream('{}'),
      });

      const promise = exportSbom(
        'my-repo',
        'v1.0',
        'CYCLONEDX_1_4',
        'test-bucket',
        'arn:aws:kms:us-east-1:123456789012:key/test-key',
      );

      // Advance past the sleep between polls
      await jest.advanceTimersByTimeAsync(5000);

      const result = await promise;

      expect(result.sbomContent).toBe('{}');
      expect(inspectorMock.commandCalls(GetSbomExportCommand)).toHaveLength(2);
    });

    test('should throw when S3 destination is missing on success', async () => {
      inspectorMock.on(CreateSbomExportCommand).resolves({
        reportId: 'report-no-s3',
      });
      inspectorMock.on(GetSbomExportCommand).resolves({
        status: 'SUCCEEDED',
        s3Destination: {},
      });

      await expect(
        exportSbom('my-repo', 'v1.0', 'CYCLONEDX_1_4', 'test-bucket', 'arn:aws:kms:us-east-1:123456789012:key/test-key'),
      ).rejects.toThrow('SBOM export succeeded but S3 destination is missing.');
    });
  });
});
