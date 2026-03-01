import {
  ECRClient,
  StartImageScanCommand,
  DescribeImageScanFindingsCommand,
  DescribeImageScanFindingsCommandOutput,
  ImageIdentifier,
  ImageScanFinding,
  EnhancedImageScanFinding,
} from '@aws-sdk/client-ecr';

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
): Promise<ScanFindings> => {
  const imageIdentifier = buildImageIdentifier(imageTag);

  console.log(`Starting image scan for ${repositoryName}...`);
  try {
    await ecrClient.send(
      new StartImageScanCommand({
        repositoryName,
        imageId: imageIdentifier,
      }),
    );
    console.log('Image scan started successfully.');
  } catch (error: any) {
    if (
      error.name === 'LimitExceededException' ||
      (error.message && error.message.includes('scan frequency limit'))
    ) {
      console.log('Scan already in progress or recently completed, polling for results...');
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
  );
};

export const waitForScanResults = async (
  repositoryName: string,
  imageTag: string,
  _scanType: string,
  pollingIntervalSeconds: number,
  pollingMaxRetries: number,
): Promise<ScanFindings> => {
  const imageIdentifier = buildImageIdentifier(imageTag);

  for (let attempt = 0; attempt < pollingMaxRetries; attempt++) {
    console.log(`Polling scan results (attempt ${attempt + 1}/${pollingMaxRetries})...`);

    try {
      const result = await getAllFindings(repositoryName, imageIdentifier);
      const status = result.rawResponse.imageScanStatus?.status;

      if (status === 'COMPLETE' || status === 'ACTIVE') {
        console.log(`Scan completed with status: ${status}`);
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

      console.log(`Scan status: ${status}, waiting ${pollingIntervalSeconds}s...`);
    } catch (error: any) {
      if (error.name === 'ScanNotFoundException') {
        if (attempt < pollingMaxRetries - 1) {
          console.log(
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
