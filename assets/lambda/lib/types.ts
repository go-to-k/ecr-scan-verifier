export interface CloudWatchLogsDetails {
  type: 'cloudwatch';
  logGroupName: string;
  findingsLogStreamName: string;
  summaryLogStreamName: string;
}

export interface S3LogsDetails {
  type: 's3';
  bucketName: string;
  findingsKey: string;
  summaryKey: string;
  sbomKey?: string;
}

export interface DefaultLogsDetails {
  type: 'default';
  logGroupName: string;
}

export type ScanLogsDetails = CloudWatchLogsDetails | S3LogsDetails | DefaultLogsDetails;
