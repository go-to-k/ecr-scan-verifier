/**
 * ECR severity levels for vulnerability findings.
 *
 * @see https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-basic.html
 */
export enum Severity {
  INFORMATIONAL = 'INFORMATIONAL',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
  UNDEFINED = 'UNDEFINED',
}

/**
 * SBOM (Software Bill of Materials) output format.
 *
 * Only available with Enhanced scanning (Amazon Inspector).
 * Uses the Inspector CreateSbomExport API to generate SBOM.
 */
export enum SbomFormat {
  /**
   * CycloneDX 1.4 JSON format.
   */
  CYCLONEDX_1_4 = 'CYCLONEDX_1_4',

  /**
   * SPDX 2.3 JSON format.
   */
  SPDX_2_3 = 'SPDX_2_3',
}
