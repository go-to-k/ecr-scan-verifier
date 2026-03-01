# ecr-scan-verifier

## What is

This is an AWS CDK Construct that allows you to **verify container image scan findings using ECR Image Scanning (Basic/Enhanced) in CDK deployment layer**.

If it detects vulnerabilities, it can **block deployments** to ECS, Lambda, and other services, or prevent the image from being pushed to the application ECR. You can also choose to receive **notifications without failing the deployment**.

- **Block deployments on vulnerability detection** — works with ECS, Lambda, application ECR push, or any construct
- **Notify without failing** — get alerts via SNS without blocking deployment. Great for gradual adoption
- **Scan logs output** — results go to CloudWatch Logs or S3
- **SBOM generation** — output Software Bill of Materials in CycloneDX or SPDX format to S3 via Amazon Inspector
- **Basic and Enhanced scanning** — use ECR native basic scanning or Amazon Inspector enhanced scanning

## Usage

### Install

```sh
npm install ecr-scan-verifier
```

### CDK Code

The following code is a minimal example that scans the image and blocks the ECS deployment if vulnerabilities are detected.

```ts
import { EcrScanVerifier, ScanConfig } from 'ecr-scan-verifier';

// Target image to scan
const image = new DockerImageAsset(this, 'DockerImage', {
  directory: resolve(__dirname, './'),
});

// Example of an ECS construct that uses the image
const ecs = new YourECSConstruct(this, 'YourECSConstruct', {
  dockerImage: image,
});

// Scan the image before deploying to ECS
new EcrScanVerifier(this, 'ImageScanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  // If vulnerabilities are detected, the ECS deployment will be blocked
  blockConstructs: [ecs],
});
```

### Image Tag

You can specify which image to scan by tag or digest:

```ts
// Scan by tag (default: 'latest')
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  imageTag: 'v1.0',
});

// Scan by digest (if the value starts with 'sha256:', it is treated as a digest)
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  imageTag: 'sha256:abc123...',
});
```

### Scan Configuration

Use `ScanConfig` to choose between Basic and Enhanced scanning:

```ts
import { ScanConfig } from 'ecr-scan-verifier';

// Basic scanning (default) — starts a manual scan via StartImageScan API
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic({ startScan: true }),
});

// Basic scanning — polls for existing scan results (useful when scan-on-push is configured)
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic({ startScan: false }),
});

// Enhanced scanning — uses Amazon Inspector (scan-on-push, no manual start)
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.enhanced(),
});
```

When using `startScan: false`, the construct polls for existing scan results instead of starting a new scan. This is useful when scan-on-push is configured on your ECR repository. If scan-on-push is not configured and no scan has been previously performed, the construct will time out waiting for scan results.

> **Note**: If scan-on-push is already configured and `startScan: true` is used, the `StartImageScan` API may return a `LimitExceededException` because the image has already been scanned. The construct handles this gracefully by falling back to polling for the existing scan results.
>
> **Important**: If Enhanced scanning (Amazon Inspector) is enabled on your account, you must use `ScanConfig.enhanced()`. Using `ScanConfig.basic()` with an Enhanced scanning account will result in a deployment error.

### Severity

You can specify which severity levels trigger a failure:

```ts
import { Severity } from 'ecr-scan-verifier';

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  severity: [Severity.CRITICAL, Severity.HIGH],
});
```

Available severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`, `UNDEFINED`.

### Ignore Findings

You can ignore specific CVEs:

```ts
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  ignoreFindings: ['CVE-2023-37920', 'CVE-2024-12345'],
});
```

### Default Log Group

If you want to use a custom log group for the Scanner Lambda function's default log group, you can specify the `defaultLogGroup` option.

If you use EcrScanVerifier construct multiple times in the same stack, you have to set the same log group for `defaultLogGroup` for each construct. When you set different log groups for each construct, a warning message will be displayed.

```ts
const logGroup = new LogGroup(this, 'LogGroup');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  defaultLogGroup: logGroup,
});
```

### Scan Logs Output

You can choose where to output the scan logs using `ScanLogsOutput`.

#### CloudWatch Logs

```ts
import { ScanLogsOutput } from 'ecr-scan-verifier';

const scanLogsLogGroup = new LogGroup(this, 'ScanLogsLogGroup');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  scanLogsOutput: ScanLogsOutput.cloudWatchLogs({ logGroup: scanLogsLogGroup }),
});
```

#### S3

```ts
const scanLogsBucket = new Bucket(this, 'ScanLogsBucket');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  scanLogsOutput: ScanLogsOutput.s3({
    bucket: scanLogsBucket,
    prefix: 'scan-logs/', // Optional
  }),
});
```

### SBOM Output

You can generate SBOM (Software Bill of Materials) using Amazon Inspector's CreateSbomExport API. This is independent from scan logs output.

**Note**: SBOM export is only available with Enhanced scanning. Using with Basic scanning will throw an error.

```ts
import { SbomOutput, ScanConfig } from 'ecr-scan-verifier';

const sbomBucket = new Bucket(this, 'SbomBucket');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.enhanced(),
  sbomOutput: SbomOutput.cycloneDx14({
    bucket: sbomBucket,
    prefix: 'sbom/', // Optional
    kmsKeyArn: 'arn:aws:kms:...', // Optional: KMS key for encryption
  }),
});
```

Available SBOM formats:

- `SbomOutput.cycloneDx14()` — CycloneDX 1.4 JSON format
- `SbomOutput.spdx23()` — SPDX 2.3 JSON format

### SNS Notification for Vulnerabilities

You can configure an SNS topic to receive notifications when vulnerabilities are detected.

The notification is sent **regardless of the `failOnVulnerability` setting**. This means you can receive notifications even when you don't want the deployment to fail.

```ts
const notificationTopic = new Topic(this, 'VulnerabilityNotificationTopic');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  vulnsNotificationTopic: notificationTopic,
  failOnVulnerability: false, // Notify but don't fail deployment
});
```
