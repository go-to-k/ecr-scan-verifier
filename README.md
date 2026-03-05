# ecr-scan-verifier

An AWS CDK Construct that **blocks deployments when ECR Image Scanning detects vulnerabilities**, and optionally **verifies container image signatures**.

It scans container images during CDK deployment using Basic or Enhanced (Amazon Inspector) scanning, and can verify image signatures with Notation (AWS Signer) or Cosign (Sigstore).

- **Block any construct's deployment** — block ECS, Lambda, or any CDK construct on vulnerability detection via `blockConstructs`
- **Signature verification** — verify image signatures with Notation (AWS Signer) or Cosign (Sigstore) before scanning
- **Notify without failing** — get alerts via SNS without blocking deployment. Great for gradual adoption
- **Scan logs output** — results go to S3 or CloudWatch Logs
- **SBOM generation** — output Software Bill of Materials in CycloneDX or SPDX format to S3 via Amazon Inspector

## Scanning Modes

This construct supports three scanning modes.

With **Basic scanning**, the construct starts a scan via API during deployment, or checks existing scan-on-push results.

**Enhanced scanning** (Amazon Inspector) only supports scan-on-push, but additionally enables SBOM generation.

**Signature Only mode** skips vulnerability scanning entirely and only verifies image signatures.

| Feature | Basic Scanning | Enhanced Scanning | Signature Only |
| --- | --- | --- | --- |
| Start scan via API | ✅ (`startScan: true`) | — | — |
| Check scan-on-push results | ✅ (`startScan: false`) | ✅ | — |
| SBOM generation | — | ✅ | — |
| Signature verification | ✅ (optional) | ✅ (optional) | ✅ (required) |

### Prerequisites

When using `ScanConfig.basic({ startScan: true })` (the default), the construct starts a scan via the ECR `StartImageScan` API during deployment — no additional ECR configuration is required.

For the following modes, **scan-on-push must be enabled** on your ECR repository or account before deployment:

- **`ScanConfig.basic({ startScan: false })`** — requires Basic scan-on-push to be enabled on the repository
- **`ScanConfig.enhanced()`** — requires Enhanced scanning (Amazon Inspector) to be enabled on the account, with the repository included in Inspector's coverage

`ScanConfig.signatureOnly()` does not require scan-on-push, as it only verifies image signatures without scanning.

If scan-on-push is not configured and no prior scan results exist, the deployment will fail with an error.

> **Tip**: `startScan: true` works even when scan-on-push is already enabled. If a scan has already been triggered, the construct simply uses the existing scan results.

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

// Basic scanning (default) — starts a scan via StartImageScan API
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic({ startScan: true }),
});

// Basic scanning — polls for existing scan results (useful when scan-on-push is configured)
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic({ startScan: false }),
});

// Enhanced scanning — uses Amazon Inspector (scan-on-push only)
new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.enhanced(),
});
```

See [Prerequisites](#prerequisites) for the scan-on-push requirements of each mode.

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

### Scan Logs Output

You can choose where to output the scan logs using `ScanLogsOutput`: S3 or CloudWatch Logs. If not specified, scan logs are written to the Scanner Lambda function's default log group.

#### S3

```ts
import { ScanLogsOutput } from 'ecr-scan-verifier';

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

#### Default Log Group

You can customize the Scanner Lambda function's log group with `defaultLogGroup`.

If you use `EcrScanVerifier` construct multiple times in the same stack, you have to set the same log group for `defaultLogGroup` for each construct. When you set different log groups for each construct, a warning message will be displayed.

```ts
const logGroup = new LogGroup(this, 'LogGroup');

new EcrScanVerifier(this, 'Scanner1', {
  repository,
  scanConfig: ScanConfig.basic(),
  defaultLogGroup: logGroup,
});

new EcrScanVerifier(this, 'Scanner2', {
  repository,
  scanConfig: ScanConfig.basic(),
  defaultLogGroup: new LogGroup(this, 'AnotherLogGroup'), // NG: different log group from Scanner1
  defaultLogGroup: logGroup, // OK: Use the same log group as Scanner1 to avoid warning
});
```

### SBOM Output

You can generate SBOM (Software Bill of Materials) using Amazon Inspector's CreateSbomExport API. This is independent from scan logs output.

**Note**: SBOM export is only available with Enhanced scanning. Using with Basic scanning will throw an error.

```ts
import { SbomOutput, ScanConfig } from 'ecr-scan-verifier';

const sbomBucket = new Bucket(this, 'SbomBucket');
const sbomEncryptionKey = new Key(this, 'SbomEncryptionKey');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.enhanced(),
  sbomOutput: SbomOutput.cycloneDx14({
    bucket: sbomBucket,
    prefix: 'sbom/', // Optional
    encryptionKey: sbomEncryptionKey,
  }),
});
```

Available SBOM formats:

- `SbomOutput.cycloneDx14()` — CycloneDX 1.4 JSON format
- `SbomOutput.spdx23()` — SPDX 2.3 JSON format

### Signature Verification

You can verify container image signatures before scanning using Notation (AWS Signer) or Cosign (Sigstore).

Signature verification is performed before the vulnerability scan during deployment. If verification fails and `failOnUnsigned` is `true` (the default), the deployment will fail.

> **Note**: This feature requires Docker to be available at deploy time, as the Lambda function is built via `AssetCode.fromAssetImage()` to bundle the Notation and Cosign CLI binaries.

#### Notation (AWS Signer)

```ts
import { SignatureVerification, ScanConfig } from 'ecr-scan-verifier';

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
  }),
});
```

#### Cosign with Public Key

```ts
import { readFileSync } from 'fs';

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignPublicKey({
    publicKey: readFileSync('path/to/cosign.pub', 'utf-8'),
  }),
});
```

#### Cosign with KMS

```ts
import { Key } from 'aws-cdk-lib/aws-kms';

const cosignKey = Key.fromKeyArn(this, 'CosignKey', 'arn:aws:kms:...');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignKms({
    key: cosignKey,
  }),
});
```

### SNS Notification for Vulnerabilities

You can configure an SNS topic via `vulnsNotificationTopic` to receive notifications when vulnerabilities are detected.

By default, the construct fails the deployment when vulnerabilities are found.
You can set `failOnVulnerability: false` to receive SNS notifications without blocking the deployment.

```ts
const notificationTopic = new Topic(this, 'VulnerabilityNotificationTopic');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.basic(),
  vulnsNotificationTopic: notificationTopic,
  failOnVulnerability: false, // Notify but don't fail deployment
});
```
