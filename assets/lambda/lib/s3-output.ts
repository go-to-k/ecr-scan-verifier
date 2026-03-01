import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { S3OutputOptions } from '../../../src/scan-logs-output';
import { SbomFormat } from '../../../src/types';
import { S3LogsDetails } from './types';

const s3Client = new S3Client();

export interface SbomContent {
  content: string;
  format: string;
}

export const outputScanLogsToS3 = async (
  findingsJson: string,
  summaryText: string,
  output: S3OutputOptions,
  imageIdentifier: string,
  sbomContent?: SbomContent,
): Promise<S3LogsDetails> => {
  const timestamp = new Date().toISOString();
  const sanitized = imageIdentifier.replace(/:/g, '/').replace(/\//g, '_');

  const prefix = output.prefix
    ? output.prefix.endsWith('/')
      ? output.prefix
      : `${output.prefix}/`
    : '';
  const basePath = `${prefix}${sanitized}/${timestamp}`;

  const findingsKey = `${basePath}/findings.json`;
  const summaryKey = `${basePath}/summary.txt`;

  const uploads: Promise<unknown>[] = [
    s3Client.send(
      new PutObjectCommand({
        Bucket: output.bucketName,
        Key: findingsKey,
        Body: findingsJson,
        ContentType: 'application/json',
      }),
    ),
    s3Client.send(
      new PutObjectCommand({
        Bucket: output.bucketName,
        Key: summaryKey,
        Body: summaryText,
        ContentType: 'text/plain',
      }),
    ),
  ];

  let sbomKey: string | undefined;

  if (sbomContent) {
    const extension = sbomContent.format === SbomFormat.SPDX_2_3 ? 'spdx.json' : 'cyclonedx.json';
    sbomKey = `${basePath}/sbom.${extension}`;

    uploads.push(
      s3Client.send(
        new PutObjectCommand({
          Bucket: output.bucketName,
          Key: sbomKey,
          Body: sbomContent.content,
          ContentType: 'application/json',
        }),
      ),
    );
  }

  await Promise.all(uploads);

  if (sbomKey) {
    console.log(
      `Scan logs and SBOM output to S3:\n  findings: s3://${output.bucketName}/${findingsKey}\n  summary: s3://${output.bucketName}/${summaryKey}\n  SBOM: s3://${output.bucketName}/${sbomKey}`,
    );
  } else {
    console.log(
      `Scan logs output to S3:\n  findings: s3://${output.bucketName}/${findingsKey}\n  summary: s3://${output.bucketName}/${summaryKey}`,
    );
  }

  return {
    type: 's3',
    bucketName: output.bucketName,
    findingsKey,
    summaryKey,
    sbomKey,
  };
};
