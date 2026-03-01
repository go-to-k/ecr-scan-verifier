/**
 * Options for basic ECR image scanning.
 */
export interface BasicScanConfigOptions {
  /**
   * Whether to start an image scan via StartImageScan API.
   *
   * If false, the construct will poll for existing scan results
   * (useful when scan-on-push is configured).
   *
   * **Note**: If `startScan` is false and no scan has been performed
   * (e.g., scan-on-push is not configured), the deployment will fail
   * after polling times out.
   *
   * **Note**: If scan-on-push is configured and `startScan` is true,
   * the `StartImageScan` API may return a `LimitExceededException`
   * because a scan has already been performed. The construct handles
   * this gracefully by falling back to polling for the existing results.
   *
   * **Note**: If Enhanced scanning (Amazon Inspector) is enabled on your account,
   * the `StartImageScan` API is disabled. In that case, you must use
   * `ScanConfig.enhanced()` instead. Using `ScanConfig.basic()` with an
   * Enhanced scanning account will result in a deployment error.
   *
   * @default true
   */
  readonly startScan?: boolean;
}

/**
 * Options for enhanced ECR image scanning (Amazon Inspector).
 */
export interface EnhancedScanConfigOptions {
  // Reserved for future enhanced scanning options.
}

/**
 * Output of ScanConfig.bind().
 */
export interface ScanConfigBindOutput {
  /**
   * The scan type ('BASIC' or 'ENHANCED').
   */
  readonly scanType: string;

  /**
   * Whether to start an image scan via StartImageScan API.
   */
  readonly startScan: boolean;
}

/**
 * Configuration for ECR image scan type.
 *
 * Use `ScanConfig.basic()` for ECR native basic scanning,
 * or `ScanConfig.enhanced()` for Amazon Inspector enhanced scanning.
 */
export abstract class ScanConfig {
  /**
   * Basic scanning using Amazon ECR native scanning.
   *
   * Basic scanning scans for known CVEs in the OS packages of your container image.
   */
  public static basic(options?: BasicScanConfigOptions): ScanConfig {
    return new BasicScanConfig(options);
  }

  /**
   * Enhanced scanning using Amazon Inspector.
   *
   * Enhanced scanning provides more detailed findings including
   * programming language package vulnerabilities.
   * Ensure Amazon Inspector is enabled for your registry.
   */
  public static enhanced(options?: EnhancedScanConfigOptions): ScanConfig {
    return new EnhancedScanConfig(options);
  }

  /**
   * Returns the scan configuration.
   */
  public abstract bind(): ScanConfigBindOutput;
}

class BasicScanConfig extends ScanConfig {
  private readonly startScan: boolean;

  constructor(options?: BasicScanConfigOptions) {
    super();
    this.startScan = options?.startScan ?? true;
  }

  public bind(): ScanConfigBindOutput {
    return {
      scanType: 'BASIC',
      startScan: this.startScan,
    };
  }
}

class EnhancedScanConfig extends ScanConfig {
  constructor(_options?: EnhancedScanConfigOptions) {
    super();
  }

  public bind(): ScanConfigBindOutput {
    return {
      scanType: 'ENHANCED',
      startScan: false,
    };
  }
}
