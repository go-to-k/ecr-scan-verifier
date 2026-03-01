import { IGrantable } from 'aws-cdk-lib/aws-iam';
import { ILogGroup } from 'aws-cdk-lib/aws-logs';
import { IBucket } from 'aws-cdk-lib/aws-s3';

/**
 * Enum for ScanLogsOutputType
 */
export enum ScanLogsOutputType {
  /**
   * Output scan logs to CloudWatch Logs.
   */
  CLOUDWATCH_LOGS = 'cloudWatchLogs',
  /**
   * Output scan logs to S3 bucket.
   */
  S3 = 's3',
}

/**
 * Output configurations for scan logs.
 */
export interface ScanLogsOutputOptions {
  /**
   * The type of scan logs output.
   */
  readonly type: ScanLogsOutputType;
}

/**
 * Output configuration for scan logs to CloudWatch Logs.
 */
export interface CloudWatchLogsOutputOptions extends ScanLogsOutputOptions {
  /**
   * The name of the CloudWatch Logs log group.
   */
  readonly logGroupName: string;
}

/**
 * Configuration for scan logs output to CloudWatch Logs log group.
 */
export interface CloudWatchLogsOutputProps {
  /**
   * The log group to output scan logs.
   */
  readonly logGroup: ILogGroup;
}

/**
 * Output configuration for scan logs to S3 bucket.
 */
export interface S3OutputOptions extends ScanLogsOutputOptions {
  /**
   * The name of the S3 bucket.
   */
  readonly bucketName: string;
  /**
   * Optional prefix for S3 objects.
   */
  readonly prefix?: string;
}

/**
 * Configuration for scan logs output to S3 bucket.
 */
export interface S3OutputProps {
  /**
   * The S3 bucket to output scan logs.
   */
  readonly bucket: IBucket;
  /**
   * Optional prefix for S3 objects.
   */
  readonly prefix?: string;
}

/**
 * Represents the output of the scan logs.
 */
export abstract class ScanLogsOutput {
  /**
   * Scan logs output to CloudWatch Logs log group.
   *
   * **Note on Large Scan Results**: CloudWatch Logs has a limit of 1 MB per log event.
   * If scan results exceed this limit, they will be automatically
   * split into multiple log events. Each chunk will be prefixed with `[part X/Y]` to
   * indicate the sequence, ensuring no data loss while staying within CloudWatch Logs quotas.
   * **For large scan results, we recommend using S3 output instead** to avoid fragmentation
   * and make it easier to view complete results.
   */
  public static cloudWatchLogs(options: CloudWatchLogsOutputProps): ScanLogsOutput {
    return new CloudWatchLogsOutput(options);
  }

  /**
   * Scan logs output to S3 bucket.
   */
  public static s3(options: S3OutputProps): ScanLogsOutput {
    return new S3Output(options);
  }

  /**
   * Returns the output configuration for scan logs.
   */
  public abstract bind(grantee: IGrantable): ScanLogsOutputOptions;
}

class CloudWatchLogsOutput extends ScanLogsOutput {
  private readonly logGroup: ILogGroup;

  constructor(options: CloudWatchLogsOutputProps) {
    super();

    this.logGroup = options.logGroup;
  }

  public bind(grantee: IGrantable): CloudWatchLogsOutputOptions {
    this.logGroup.grantWrite(grantee);

    return {
      type: ScanLogsOutputType.CLOUDWATCH_LOGS,
      logGroupName: this.logGroup.logGroupName,
    };
  }
}

class S3Output extends ScanLogsOutput {
  private readonly bucket: IBucket;
  private readonly prefix?: string;

  constructor(options: S3OutputProps) {
    super();

    this.bucket = options.bucket;
    this.prefix = options.prefix;
  }

  public bind(grantee: IGrantable): S3OutputOptions {
    this.bucket.grantWrite(grantee);
    this.bucket.grantRead(grantee);

    return {
      type: ScanLogsOutputType.S3,
      bucketName: this.bucket.bucketName,
      prefix: this.prefix,
    };
  }
}
