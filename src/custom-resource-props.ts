import { SbomOutputConfig } from './sbom-output';
import { ScanLogsOutputOptions } from './scan-logs-output';

/**
 * Signature verification configuration passed to Lambda.
 */
export interface SignatureVerificationConfig {
  readonly type: string;
  readonly trustedIdentities?: string[];
  readonly publicKey?: string;
  readonly kmsKeyArn?: string;
  readonly failOnUnsigned: string;
  readonly cosignIgnoreTlog?: string;
}

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
  readonly signatureVerification?: SignatureVerificationConfig;
}
