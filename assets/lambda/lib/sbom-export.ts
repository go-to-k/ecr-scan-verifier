import {
  Inspector2Client,
  CreateSbomExportCommand,
  GetSbomExportCommand,
  SbomReportFormat,
} from '@aws-sdk/client-inspector2';
import { S3Client, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { Logger } from './logger';

const inspectorClient = new Inspector2Client();
const s3Client = new S3Client();

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface SbomExportResult {
  sbomContent: string;
  format: string;
}

export const exportSbom = async (
  repositoryName: string,
  imageTag: string,
  sbomFormat: string,
  s3BucketName: string,
  s3KeyPrefix: string | undefined,
  kmsKeyArn: string,
  logger: Logger,
): Promise<SbomExportResult> => {
  const reportFormat =
    sbomFormat === 'SPDX_2_3' ? SbomReportFormat.SPDX_2_3 : SbomReportFormat.CYCLONEDX_1_4;

  logger.log(`Starting SBOM export for ${repositoryName} with format ${sbomFormat}...`);

  // Build resource filter for the specific ECR image
  const resourceFilterCriteria = {
    ecrRepositoryName: [{ comparison: 'EQUALS' as const, value: repositoryName }],
    ...(imageTag
      ? { ecrImageTags: [{ comparison: 'EQUALS' as const, value: imageTag }] }
      : {}),
  };

  const createResponse = await inspectorClient.send(
    new CreateSbomExportCommand({
      reportFormat,
      s3Destination: {
        bucketName: s3BucketName,
        // Omitted when no prefix is configured, so Inspector writes to the bucket root.
        keyPrefix: s3KeyPrefix,
        kmsKeyArn,
      },
      resourceFilterCriteria,
    }),
  );

  const reportId = createResponse.reportId;
  if (!reportId) {
    throw new Error('CreateSbomExport did not return a reportId.');
  }

  logger.log(`SBOM export started with reportId: ${reportId}`);

  // Poll for completion
  const maxRetries = 60;
  const intervalSeconds = 5;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const getResponse = await inspectorClient.send(
      new GetSbomExportCommand({ reportId }),
    );

    const status = getResponse.status;
    logger.log(`SBOM export status: ${status} (attempt ${attempt + 1}/${maxRetries})`);

    if (status === 'SUCCEEDED') {
      const bucketName = getResponse.s3Destination?.bucketName;

      if (!bucketName) {
        throw new Error('SBOM export succeeded but S3 destination is missing.');
      }

      // Use the configured prefix instead of the response: the response only
      // echoes the request back, so keyPrefix is absent when none was configured.
      const searchPrefix = s3KeyPrefix ?? '';

      // Find the actual S3 key under the prefix
      const actualKey = await findS3Object(bucketName, searchPrefix);
      if (!actualKey) {
        throw new Error(
          searchPrefix
            ? `SBOM export succeeded but no file found in S3 under prefix: ${searchPrefix}`
            : `SBOM export succeeded but no file found in S3 bucket: ${bucketName}`,
        );
      }

      // Download SBOM from S3
      const sbomContent = await downloadFromS3(bucketName, actualKey);
      return {
        sbomContent,
        format: sbomFormat,
      };
    }

    if (status === 'FAILED') {
      const filterErrors = getResponse.filterCriteria;
      throw new Error(
        `SBOM export failed. Filter criteria: ${JSON.stringify(filterErrors)}`,
      );
    }

    if (status === 'CANCELLED') {
      throw new Error('SBOM export was cancelled.');
    }

    await sleep(intervalSeconds * 1000);
  }

  throw new Error(
    `SBOM export timed out after ${maxRetries * intervalSeconds} seconds.`,
  );
};

const findS3Object = async (
  bucketName: string,
  prefix: string,
): Promise<string | undefined> => {
  const response = await s3Client.send(
    new ListObjectsV2Command({
      Bucket: bucketName,
      Prefix: prefix,
      MaxKeys: 1,
    }),
  );

  return response.Contents?.[0]?.Key;
};

const downloadFromS3 = async (
  bucketName: string,
  key: string,
): Promise<string> => {
  const response = await s3Client.send(
    new GetObjectCommand({
      Bucket: bucketName,
      Key: key,
    }),
  );

  return (await response.Body?.transformToString()) ?? '';
};
