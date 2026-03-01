import { SbomOutputConfig } from './sbom-output';
import { ScanLogsOutputOptions } from './scan-logs-output';

/**
 * Lambda function event object for Scanner Custom Resource.
 */
export interface ScannerCustomResourceProps {
  readonly addr: string;
  readonly repositoryName: string;
  readonly imageTag: string;
  readonly scanType: string;
  readonly startScan: string;
  readonly severity: string[];
  readonly failOnVulnerability: string;
  readonly ignoreFindings: string[];
  readonly output?: ScanLogsOutputOptions;
  readonly suppressErrorOnRollback: string;
  readonly vulnsTopicArn?: string;
  readonly defaultLogGroupName: string;
  readonly sbom?: SbomOutputConfig;
}
