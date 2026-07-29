import {
  ECRClient,
  StartImageScanCommand,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  GetRegistryScanningConfigurationCommand,
  BatchGetRepositoryScanningConfigurationCommand,
  ImageIdentifier,
  ImageScanFinding,
  EnhancedImageScanFinding,
  RepositoryScanningConfiguration,
  ScanFrequency,
  ScanType,
} from '@aws-sdk/client-ecr';
import { Logger } from './logger';

const ecrClient = new ECRClient();

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface ScanFindings {
  scanType: string;
  status: string;
  basicFindings: ImageScanFinding[];
  enhancedFindings: EnhancedImageScanFinding[];
  severityCounts: Record<string, number>;
  rawResponse: DescribeImageScanFindingsCommandOutput;
}

const buildImageIdentifier = (imageTag: string): ImageIdentifier => {
  if (imageTag.startsWith('sha256:')) {
    return { imageDigest: imageTag };
  }
  return { imageTag };
};

export const startAndWaitForScan = async (
  repositoryName: string,
  imageTag: string,
  scanType: string,
  pollingIntervalSeconds: number,
  pollingMaxRetries: number,
  logger: Logger,
): Promise<ScanFindings> => {
  const imageIdentifier = buildImageIdentifier(imageTag);

  logger.log(`Starting image scan for ${repositoryName}...`);
  try {
    await ecrClient.send(
      new StartImageScanCommand({
        repositoryName,
        imageId: imageIdentifier,
      }),
    );
    logger.log('Image scan started successfully.');
  } catch (error: any) {
    if (
      error.name === 'LimitExceededException' ||
      (error.message && error.message.includes('scan frequency limit'))
    ) {
      logger.log('Scan already in progress or recently completed, polling for results...');
    } else if (
      error.name === 'ValidationException' &&
      error.message && error.message.includes('This feature is disabled')
    ) {
      throw new Error(
        `StartImageScan is disabled because Enhanced scanning (Amazon Inspector) is enabled on this account. ` +
          `Use ScanConfig.enhanced() instead of ScanConfig.basic().`,
      );
    } else {
      throw error;
    }
  }

  return waitForScanResults(
    repositoryName,
    imageTag,
    scanType,
    pollingIntervalSeconds,
    pollingMaxRetries,
    logger,
  );
};

export const waitForScanResults = async (
  repositoryName: string,
  imageTag: string,
  scanType: string,
  pollingIntervalSeconds: number,
  pollingMaxRetries: number,
  logger: Logger,
  checkScanCoverage: boolean = false,
): Promise<ScanFindings> => {
  const imageIdentifier = buildImageIdentifier(imageTag);
  let scanCoverageChecked = false;

  for (let attempt = 0; attempt < pollingMaxRetries; attempt++) {
    logger.log(`Polling scan results (attempt ${attempt + 1}/${pollingMaxRetries})...`);

    try {
      const result = await getAllFindings(repositoryName, imageIdentifier);
      const status = result.rawResponse.imageScanStatus?.status;

      if (status === 'COMPLETE' || status === 'ACTIVE') {
        logger.log(`Scan completed with status: ${status}`);
        return result;
      }

      if (status === 'FAILED') {
        const description =
          result.rawResponse.imageScanStatus?.description || 'Unknown error';
        throw new Error(`ECR image scan failed: ${description}`);
      }

      if (status === 'UNSUPPORTED_IMAGE') {
        throw new Error(
          'ECR image scan failed: Image is not supported for scanning.',
        );
      }

      if (status === 'SCAN_ELIGIBILITY_EXPIRED') {
        throw new Error(
          'ECR image scan failed: scan eligibility for the image has expired. ' +
            "The image is older than Amazon Inspector's ECR re-scan duration, " +
            'so its findings are no longer available. Push the image again, or extend ' +
            'the re-scan duration (aws inspector2 update-configuration).',
        );
      }

      logger.log(`Scan status: ${status}, waiting ${pollingIntervalSeconds}s...`);
    } catch (error: any) {
      if (error.name === 'ScanNotFoundException') {
        if (checkScanCoverage && !scanCoverageChecked) {
          scanCoverageChecked = true;
          await verifyScanCoverage(repositoryName, scanType, logger);
        }
        if (attempt < pollingMaxRetries - 1) {
          logger.log(
            `Scan not found yet (attempt ${attempt + 1}/${pollingMaxRetries}), ` +
              `waiting ${pollingIntervalSeconds}s before retrying...`,
          );
          await sleep(pollingIntervalSeconds * 1000);
          continue;
        }
        throw new Error(
          `No scan results found for the image after ${pollingMaxRetries * pollingIntervalSeconds} seconds. ` +
            `Ensure that image scanning is enabled for this repository. ` +
            `If using Enhanced scanning (Amazon Inspector), verify that the repository is included in Inspector's coverage.`,
        );
      }
      throw error;
    }

    await sleep(pollingIntervalSeconds * 1000);
  }

  throw new Error(
    `ECR image scan timed out after ${pollingMaxRetries * pollingIntervalSeconds} seconds. ` +
      `The scan may still be in progress. Check the ECR console for results.`,
  );
};

/**
 * Fails fast when the repository will never be scanned, instead of letting the
 * caller poll until the timeout (up to 14 minutes) for a scan that cannot happen.
 *
 * Called once, on the first ScanNotFoundException. Throws only when the scanning
 * configuration definitively shows the scan will never run; any inconclusive
 * response or API error falls back to the previous behavior (keep polling), so
 * a false positive can never block a deployment that would otherwise succeed.
 */
const verifyScanCoverage = async (
  repositoryName: string,
  scanType: string,
  logger: Logger,
): Promise<void> => {
  let registryScanType: string | undefined;
  let repositoryConfig: RepositoryScanningConfiguration | undefined;

  try {
    const [registryResponse, repositoryResponse] = await Promise.all([
      ecrClient.send(new GetRegistryScanningConfigurationCommand({})),
      ecrClient.send(
        new BatchGetRepositoryScanningConfigurationCommand({
          repositoryNames: [repositoryName],
        }),
      ),
    ]);

    registryScanType = registryResponse.scanningConfiguration?.scanType;
    repositoryConfig = repositoryResponse.scanningConfigurations?.find(
      (config) => config.repositoryName === repositoryName,
    );

    const failure = repositoryResponse.failures?.[0];
    if (failure) {
      logger.warn(
        `Could not verify the scanning configuration for repository '${repositoryName}' ` +
          `(${failure.failureCode}: ${failure.failureReason}). Continuing to poll.`,
      );
      return;
    }
  } catch (error: any) {
    logger.warn(
      `Could not verify the registry scanning configuration: ${error.message || error}. ` +
        'Continuing to poll.',
    );
    return;
  }

  if (registryScanType === ScanType.ENHANCED) {
    const appliedScanFilters = repositoryConfig?.appliedScanFilters ?? [];
    const scanFrequency = repositoryConfig?.scanFrequency;
    const covered =
      appliedScanFilters.length > 0 ||
      scanFrequency === ScanFrequency.SCAN_ON_PUSH ||
      scanFrequency === ScanFrequency.CONTINUOUS_SCAN;

    if (repositoryConfig && !covered) {
      throw new Error(
        `Repository '${repositoryName}' is not covered by any Enhanced scanning filter, ` +
          'so it will never be scanned. Check the registry scanning configuration ' +
          '(aws ecr get-registry-scanning-configuration) and add a filter rule that matches this repository.',
      );
    }

    logger.log(
      `Repository '${repositoryName}' is covered by the Enhanced scanning configuration ` +
        `(scan frequency: ${scanFrequency}). Waiting for the scan to start...`,
    );
    return;
  }

  if (registryScanType === ScanType.BASIC) {
    if (scanType === 'ENHANCED') {
      throw new Error(
        'Enhanced scanning (Amazon Inspector) is not enabled for this registry ' +
          `(current scan type: BASIC), so the scan for repository '${repositoryName}' will never run. ` +
          'Enable Enhanced scanning on the registry (aws ecr put-registry-scanning-configuration ' +
          '--scan-type ENHANCED) or use ScanConfig.basic().',
      );
    }

    if (repositoryConfig?.scanOnPush === false) {
      throw new Error(
        `Scan on push is not enabled for repository '${repositoryName}' and no existing scan results were found, ` +
          'so no scan results will ever appear. Enable scan on push for the repository, ' +
          'or use ScanConfig.basic() with startScan: true (default) to start a scan explicitly.',
      );
    }

    logger.log(
      `Scan on push is enabled for repository '${repositoryName}'. Waiting for the scan to start...`,
    );
    return;
  }

  logger.warn(
    `Could not determine the registry scan type (got: ${registryScanType}). Continuing to poll.`,
  );
};

const getAllFindings = async (
  repositoryName: string,
  imageIdentifier: ImageIdentifier,
): Promise<ScanFindings> => {
  const allBasicFindings: ImageScanFinding[] = [];
  const allEnhancedFindings: EnhancedImageScanFinding[] = [];
  let nextToken: string | undefined;
  let lastResponse: DescribeImageScanFindingsCommandOutput | undefined;

  do {
    const response = await ecrClient.send(
      new DescribeImageScanFindingsCommand({
        repositoryName,
        imageId: imageIdentifier,
        nextToken,
        maxResults: 1000,
      }),
    );

    lastResponse = response;

    if (response.imageScanFindings?.findings) {
      allBasicFindings.push(...response.imageScanFindings.findings);
    }
    if (response.imageScanFindings?.enhancedFindings) {
      allEnhancedFindings.push(...response.imageScanFindings.enhancedFindings);
    }

    nextToken = response.nextToken;
  } while (nextToken);

  const severityCounts: Record<string, number> =
    lastResponse?.imageScanFindings?.findingSeverityCounts
      ? Object.fromEntries(
          Object.entries(lastResponse.imageScanFindings.findingSeverityCounts).map(
            ([k, v]) => [k, v ?? 0],
          ),
        )
      : {};

  const scanType = allEnhancedFindings.length > 0 ? 'ENHANCED' : 'BASIC';

  return {
    scanType,
    status: lastResponse?.imageScanStatus?.status ?? 'UNKNOWN',
    basicFindings: allBasicFindings,
    enhancedFindings: allEnhancedFindings,
    severityCounts,
    rawResponse: lastResponse!,
  };
};
