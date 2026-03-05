# API Reference <a name="API Reference" id="api-reference"></a>

## Constructs <a name="Constructs" id="Constructs"></a>

### EcrScanVerifier <a name="EcrScanVerifier" id="ecr-scan-verifier.EcrScanVerifier"></a>

A Construct that verifies container image scan findings with ECR image scanning.

It uses a Lambda function as a Custom Resource provider to call ECR scan APIs
and evaluate scan findings.

#### Initializers <a name="Initializers" id="ecr-scan-verifier.EcrScanVerifier.Initializer"></a>

```typescript
import { EcrScanVerifier } from 'ecr-scan-verifier'

new EcrScanVerifier(scope: Construct, id: string, props: EcrScanVerifierProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.props">props</a></code> | <code><a href="#ecr-scan-verifier.EcrScanVerifierProps">EcrScanVerifierProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Required</sup> <a name="props" id="ecr-scan-verifier.EcrScanVerifier.Initializer.parameter.props"></a>

- *Type:* <a href="#ecr-scan-verifier.EcrScanVerifierProps">EcrScanVerifierProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.with">with</a></code> | Applies one or more mixins to this construct. |

---

##### `toString` <a name="toString" id="ecr-scan-verifier.EcrScanVerifier.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `with` <a name="with" id="ecr-scan-verifier.EcrScanVerifier.with"></a>

```typescript
public with(mixins: ...IMixin[]): IConstruct
```

Applies one or more mixins to this construct.

Mixins are applied in order. The list of constructs is captured at the
start of the call, so constructs added by a mixin will not be visited.
Use multiple `with()` calls if subsequent mixins should apply to added
constructs.

###### `mixins`<sup>Required</sup> <a name="mixins" id="ecr-scan-verifier.EcrScanVerifier.with.parameter.mixins"></a>

- *Type:* ...constructs.IMixin[]

The mixins to apply.

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |

---

##### `isConstruct` <a name="isConstruct" id="ecr-scan-verifier.EcrScanVerifier.isConstruct"></a>

```typescript
import { EcrScanVerifier } from 'ecr-scan-verifier'

EcrScanVerifier.isConstruct(x: any)
```

Checks if `x` is a construct.

Use this method instead of `instanceof` to properly detect `Construct`
instances, even when the construct library is symlinked.

Explanation: in JavaScript, multiple copies of the `constructs` library on
disk are seen as independent, completely different libraries. As a
consequence, the class `Construct` in each copy of the `constructs` library
is seen as a different class, and an instance of one class will not test as
`instanceof` the other class. `npm install` will not create installations
like this, but users may manually symlink construct libraries together or
use a monorepo tool: in those cases, multiple copies of the `constructs`
library can be accidentally installed, and `instanceof` will behave
unpredictably. It is safest to avoid using `instanceof`, and using
this type-testing method instead.

###### `x`<sup>Required</sup> <a name="x" id="ecr-scan-verifier.EcrScanVerifier.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.EcrScanVerifier.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |

---

##### `node`<sup>Required</sup> <a name="node" id="ecr-scan-verifier.EcrScanVerifier.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---


## Structs <a name="Structs" id="Structs"></a>

### BasicScanConfigOptions <a name="BasicScanConfigOptions" id="ecr-scan-verifier.BasicScanConfigOptions"></a>

Options for basic ECR image scanning.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.BasicScanConfigOptions.Initializer"></a>

```typescript
import { BasicScanConfigOptions } from 'ecr-scan-verifier'

const basicScanConfigOptions: BasicScanConfigOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.BasicScanConfigOptions.property.startScan">startScan</a></code> | <code>boolean</code> | Whether to start an image scan via StartImageScan API. |

---

##### `startScan`<sup>Optional</sup> <a name="startScan" id="ecr-scan-verifier.BasicScanConfigOptions.property.startScan"></a>

```typescript
public readonly startScan: boolean;
```

- *Type:* boolean
- *Default:* true

Whether to start an image scan via StartImageScan API.

If false, the construct will poll for existing scan results
(useful when scan-on-push is configured).

**Note**: If `startScan` is false and no scan has been performed
(e.g., scan-on-push is not configured), the deployment will fail
after polling times out.

**Note**: If scan-on-push is configured and `startScan` is true,
the `StartImageScan` API may return a `LimitExceededException`
because a scan has already been performed. The construct handles
this gracefully by falling back to polling for the existing results.

**Note**: If Enhanced scanning (Amazon Inspector) is enabled on your account,
the `StartImageScan` API is disabled. In that case, you must use
`ScanConfig.enhanced()` instead. Using `ScanConfig.basic()` with an
Enhanced scanning account will result in a deployment error.

---

### CloudWatchLogsOutputOptions <a name="CloudWatchLogsOutputOptions" id="ecr-scan-verifier.CloudWatchLogsOutputOptions"></a>

Output configuration for scan logs to CloudWatch Logs.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.CloudWatchLogsOutputOptions.Initializer"></a>

```typescript
import { CloudWatchLogsOutputOptions } from 'ecr-scan-verifier'

const cloudWatchLogsOutputOptions: CloudWatchLogsOutputOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.CloudWatchLogsOutputOptions.property.type">type</a></code> | <code><a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a></code> | The type of scan logs output. |
| <code><a href="#ecr-scan-verifier.CloudWatchLogsOutputOptions.property.logGroupName">logGroupName</a></code> | <code>string</code> | The name of the CloudWatch Logs log group. |

---

##### `type`<sup>Required</sup> <a name="type" id="ecr-scan-verifier.CloudWatchLogsOutputOptions.property.type"></a>

```typescript
public readonly type: ScanLogsOutputType;
```

- *Type:* <a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a>

The type of scan logs output.

---

##### `logGroupName`<sup>Required</sup> <a name="logGroupName" id="ecr-scan-verifier.CloudWatchLogsOutputOptions.property.logGroupName"></a>

```typescript
public readonly logGroupName: string;
```

- *Type:* string

The name of the CloudWatch Logs log group.

---

### CloudWatchLogsOutputProps <a name="CloudWatchLogsOutputProps" id="ecr-scan-verifier.CloudWatchLogsOutputProps"></a>

Configuration for scan logs output to CloudWatch Logs log group.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.CloudWatchLogsOutputProps.Initializer"></a>

```typescript
import { CloudWatchLogsOutputProps } from 'ecr-scan-verifier'

const cloudWatchLogsOutputProps: CloudWatchLogsOutputProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.CloudWatchLogsOutputProps.property.logGroup">logGroup</a></code> | <code>aws-cdk-lib.aws_logs.ILogGroup</code> | The log group to output scan logs. |

---

##### `logGroup`<sup>Required</sup> <a name="logGroup" id="ecr-scan-verifier.CloudWatchLogsOutputProps.property.logGroup"></a>

```typescript
public readonly logGroup: ILogGroup;
```

- *Type:* aws-cdk-lib.aws_logs.ILogGroup

The log group to output scan logs.

---

### CosignKmsVerificationOptions <a name="CosignKmsVerificationOptions" id="ecr-scan-verifier.CosignKmsVerificationOptions"></a>

Options for Cosign signature verification using an AWS KMS key.

**Note on Rekor Transparency Log:**
This implementation skips Rekor transparency log verification and verifies only
the cryptographic signature using the KMS key.
The Lambda function always uses the `--insecure-ignore-tlog` flag when running cosign verify.

> [https://docs.sigstore.dev/cosign/key_management/overview/](https://docs.sigstore.dev/cosign/key_management/overview/)

#### Initializer <a name="Initializer" id="ecr-scan-verifier.CosignKmsVerificationOptions.Initializer"></a>

```typescript
import { CosignKmsVerificationOptions } from 'ecr-scan-verifier'

const cosignKmsVerificationOptions: CosignKmsVerificationOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.CosignKmsVerificationOptions.property.key">key</a></code> | <code>aws-cdk-lib.aws_kms.IKey</code> | AWS KMS key used to verify the image signature. |
| <code><a href="#ecr-scan-verifier.CosignKmsVerificationOptions.property.failOnUnsigned">failOnUnsigned</a></code> | <code>boolean</code> | Whether to fail the deployment if the image is unsigned or signature verification fails. |

---

##### `key`<sup>Required</sup> <a name="key" id="ecr-scan-verifier.CosignKmsVerificationOptions.property.key"></a>

```typescript
public readonly key: IKey;
```

- *Type:* aws-cdk-lib.aws_kms.IKey

AWS KMS key used to verify the image signature.

The Lambda function is automatically granted `kms:DescribeKey`, `kms:GetPublicKey`,
and `kms:Verify` permissions on this key.

---

##### `failOnUnsigned`<sup>Optional</sup> <a name="failOnUnsigned" id="ecr-scan-verifier.CosignKmsVerificationOptions.property.failOnUnsigned"></a>

```typescript
public readonly failOnUnsigned: boolean;
```

- *Type:* boolean
- *Default:* true

Whether to fail the deployment if the image is unsigned or signature verification fails.

---

### CosignPublicKeyVerificationOptions <a name="CosignPublicKeyVerificationOptions" id="ecr-scan-verifier.CosignPublicKeyVerificationOptions"></a>

Options for Cosign signature verification using a public key.

**Note on Rekor Transparency Log:**
This implementation skips Rekor transparency log verification and verifies only
the cryptographic signature using the public key.
The Lambda function always uses the `--insecure-ignore-tlog` flag when running cosign verify.

> [https://docs.sigstore.dev/cosign/key_management/overview/](https://docs.sigstore.dev/cosign/key_management/overview/)

#### Initializer <a name="Initializer" id="ecr-scan-verifier.CosignPublicKeyVerificationOptions.Initializer"></a>

```typescript
import { CosignPublicKeyVerificationOptions } from 'ecr-scan-verifier'

const cosignPublicKeyVerificationOptions: CosignPublicKeyVerificationOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.CosignPublicKeyVerificationOptions.property.publicKey">publicKey</a></code> | <code>string</code> | The PEM-encoded public key content used to verify the image signature. |
| <code><a href="#ecr-scan-verifier.CosignPublicKeyVerificationOptions.property.failOnUnsigned">failOnUnsigned</a></code> | <code>boolean</code> | Whether to fail the deployment if the image is unsigned or signature verification fails. |

---

##### `publicKey`<sup>Required</sup> <a name="publicKey" id="ecr-scan-verifier.CosignPublicKeyVerificationOptions.property.publicKey"></a>

```typescript
public readonly publicKey: string;
```

- *Type:* string

The PEM-encoded public key content used to verify the image signature.

---

*Example*

```typescript
'-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----'
```


##### `failOnUnsigned`<sup>Optional</sup> <a name="failOnUnsigned" id="ecr-scan-verifier.CosignPublicKeyVerificationOptions.property.failOnUnsigned"></a>

```typescript
public readonly failOnUnsigned: boolean;
```

- *Type:* boolean
- *Default:* true

Whether to fail the deployment if the image is unsigned or signature verification fails.

---

### EcrScanVerifierProps <a name="EcrScanVerifierProps" id="ecr-scan-verifier.EcrScanVerifierProps"></a>

Properties for EcrScanVerifier Construct.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.EcrScanVerifierProps.Initializer"></a>

```typescript
import { EcrScanVerifierProps } from 'ecr-scan-verifier'

const ecrScanVerifierProps: EcrScanVerifierProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.repository">repository</a></code> | <code>aws-cdk-lib.aws_ecr.IRepository</code> | ECR Repository to scan. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.scanConfig">scanConfig</a></code> | <code><a href="#ecr-scan-verifier.ScanConfig">ScanConfig</a></code> | Scan configuration — choose based on your ECR repository/account settings:. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.blockConstructs">blockConstructs</a></code> | <code>constructs.IConstruct[]</code> | Constructs to block if vulnerabilities are detected. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.defaultLogGroup">defaultLogGroup</a></code> | <code>aws-cdk-lib.aws_logs.ILogGroup</code> | The Scanner Lambda function's default log group. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.failOnVulnerability">failOnVulnerability</a></code> | <code>boolean</code> | Whether to fail the CloudFormation deployment if vulnerabilities are detected above the severity threshold. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.ignoreFindings">ignoreFindings</a></code> | <code>string[]</code> | Finding IDs to ignore during vulnerability evaluation. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.imageTag">imageTag</a></code> | <code>string</code> | Image tag or digest to scan. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.scanLogsOutput">scanLogsOutput</a></code> | <code><a href="#ecr-scan-verifier.ScanLogsOutput">ScanLogsOutput</a></code> | Configuration for scan logs output. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.severity">severity</a></code> | <code><a href="#ecr-scan-verifier.Severity">Severity</a>[]</code> | Severity threshold for vulnerability detection. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.signatureVerification">signatureVerification</a></code> | <code><a href="#ecr-scan-verifier.SignatureVerification">SignatureVerification</a></code> | Signature verification configuration for the container image. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.suppressErrorOnRollback">suppressErrorOnRollback</a></code> | <code>boolean</code> | Suppress errors during rollback scanner Lambda execution. |
| <code><a href="#ecr-scan-verifier.EcrScanVerifierProps.property.vulnsNotificationTopic">vulnsNotificationTopic</a></code> | <code>aws-cdk-lib.aws_sns.ITopic</code> | SNS topic for vulnerability notification. |

---

##### `repository`<sup>Required</sup> <a name="repository" id="ecr-scan-verifier.EcrScanVerifierProps.property.repository"></a>

```typescript
public readonly repository: IRepository;
```

- *Type:* aws-cdk-lib.aws_ecr.IRepository

ECR Repository to scan.

---

##### `scanConfig`<sup>Required</sup> <a name="scanConfig" id="ecr-scan-verifier.EcrScanVerifierProps.property.scanConfig"></a>

```typescript
public readonly scanConfig: ScanConfig;
```

- *Type:* <a href="#ecr-scan-verifier.ScanConfig">ScanConfig</a>

Scan configuration — choose based on your ECR repository/account settings:.

`ScanConfig.basic()` (default: `startScan: true`) — starts a scan via the ECR API.
  No additional ECR configuration required.
- `ScanConfig.basic({ startScan: false })` — polls for existing results.
  Requires Basic scan-on-push to be enabled on the repository.
- `ScanConfig.enhanced()` — uses Amazon Inspector enhanced scanning.
  Requires Enhanced scanning to be enabled on the account.

If the required scanning configuration is not in place and no prior scan results exist,
the deployment will fail.

---

##### `blockConstructs`<sup>Optional</sup> <a name="blockConstructs" id="ecr-scan-verifier.EcrScanVerifierProps.property.blockConstructs"></a>

```typescript
public readonly blockConstructs: IConstruct[];
```

- *Type:* constructs.IConstruct[]
- *Default:* no constructs to block

Constructs to block if vulnerabilities are detected.

---

##### `defaultLogGroup`<sup>Optional</sup> <a name="defaultLogGroup" id="ecr-scan-verifier.EcrScanVerifierProps.property.defaultLogGroup"></a>

```typescript
public readonly defaultLogGroup: ILogGroup;
```

- *Type:* aws-cdk-lib.aws_logs.ILogGroup
- *Default:* Scanner Lambda creates the default log group.

The Scanner Lambda function's default log group.

If you use EcrScanVerifier construct multiple times in the same stack,
you must specify the same log group for each construct.

---

##### `failOnVulnerability`<sup>Optional</sup> <a name="failOnVulnerability" id="ecr-scan-verifier.EcrScanVerifierProps.property.failOnVulnerability"></a>

```typescript
public readonly failOnVulnerability: boolean;
```

- *Type:* boolean
- *Default:* true

Whether to fail the CloudFormation deployment if vulnerabilities are detected above the severity threshold.

---

##### `ignoreFindings`<sup>Optional</sup> <a name="ignoreFindings" id="ecr-scan-verifier.EcrScanVerifierProps.property.ignoreFindings"></a>

```typescript
public readonly ignoreFindings: string[];
```

- *Type:* string[]
- *Default:* no findings ignored

Finding IDs to ignore during vulnerability evaluation.

For basic scanning: CVE IDs (e.g., 'CVE-2023-37920')
For enhanced scanning: finding ARNs or CVE IDs

---

##### `imageTag`<sup>Optional</sup> <a name="imageTag" id="ecr-scan-verifier.EcrScanVerifierProps.property.imageTag"></a>

```typescript
public readonly imageTag: string;
```

- *Type:* string
- *Default:* 'latest'

Image tag or digest to scan.

You can specify a tag (e.g., 'v1.0', 'latest') or a digest (e.g., 'sha256:abc123...').
If the value starts with 'sha256:', it is treated as a digest.

---

##### `scanLogsOutput`<sup>Optional</sup> <a name="scanLogsOutput" id="ecr-scan-verifier.EcrScanVerifierProps.property.scanLogsOutput"></a>

```typescript
public readonly scanLogsOutput: ScanLogsOutput;
```

- *Type:* <a href="#ecr-scan-verifier.ScanLogsOutput">ScanLogsOutput</a>
- *Default:* scan logs output to default log group created by Scanner Lambda.

Configuration for scan logs output.

---

##### `severity`<sup>Optional</sup> <a name="severity" id="ecr-scan-verifier.EcrScanVerifierProps.property.severity"></a>

```typescript
public readonly severity: Severity[];
```

- *Type:* <a href="#ecr-scan-verifier.Severity">Severity</a>[]
- *Default:* [Severity.CRITICAL]

Severity threshold for vulnerability detection.

If vulnerabilities at or above any of the specified severity levels are found,
the scan will be considered as having found vulnerabilities.

---

##### `signatureVerification`<sup>Optional</sup> <a name="signatureVerification" id="ecr-scan-verifier.EcrScanVerifierProps.property.signatureVerification"></a>

```typescript
public readonly signatureVerification: SignatureVerification;
```

- *Type:* <a href="#ecr-scan-verifier.SignatureVerification">SignatureVerification</a>
- *Default:* no signature verification

Signature verification configuration for the container image.

Verifies the image signature before scanning using Notation (AWS Signer) or Cosign (Sigstore).

---

##### `suppressErrorOnRollback`<sup>Optional</sup> <a name="suppressErrorOnRollback" id="ecr-scan-verifier.EcrScanVerifierProps.property.suppressErrorOnRollback"></a>

```typescript
public readonly suppressErrorOnRollback: boolean;
```

- *Type:* boolean
- *Default:* true

Suppress errors during rollback scanner Lambda execution.

---

##### `vulnsNotificationTopic`<sup>Optional</sup> <a name="vulnsNotificationTopic" id="ecr-scan-verifier.EcrScanVerifierProps.property.vulnsNotificationTopic"></a>

```typescript
public readonly vulnsNotificationTopic: ITopic;
```

- *Type:* aws-cdk-lib.aws_sns.ITopic
- *Default:* no notification

SNS topic for vulnerability notification.

Supports AWS Chatbot message format.

---

### EnhancedScanConfigOptions <a name="EnhancedScanConfigOptions" id="ecr-scan-verifier.EnhancedScanConfigOptions"></a>

Options for enhanced ECR image scanning (Amazon Inspector).

#### Initializer <a name="Initializer" id="ecr-scan-verifier.EnhancedScanConfigOptions.Initializer"></a>

```typescript
import { EnhancedScanConfigOptions } from 'ecr-scan-verifier'

const enhancedScanConfigOptions: EnhancedScanConfigOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.EnhancedScanConfigOptions.property.sbomOutput">sbomOutput</a></code> | <code><a href="#ecr-scan-verifier.SbomOutput">SbomOutput</a></code> | SBOM (Software Bill of Materials) output configuration. |

---

##### `sbomOutput`<sup>Optional</sup> <a name="sbomOutput" id="ecr-scan-verifier.EnhancedScanConfigOptions.property.sbomOutput"></a>

```typescript
public readonly sbomOutput: SbomOutput;
```

- *Type:* <a href="#ecr-scan-verifier.SbomOutput">SbomOutput</a>
- *Default:* no SBOM output

SBOM (Software Bill of Materials) output configuration.

SBOM export uses Amazon Inspector's CreateSbomExport API to generate SBOM
and uploads it to S3.

---

### NotationVerificationOptions <a name="NotationVerificationOptions" id="ecr-scan-verifier.NotationVerificationOptions"></a>

Options for Notation (AWS Signer) signature verification.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.NotationVerificationOptions.Initializer"></a>

```typescript
import { NotationVerificationOptions } from 'ecr-scan-verifier'

const notationVerificationOptions: NotationVerificationOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.NotationVerificationOptions.property.trustedIdentities">trustedIdentities</a></code> | <code>string[]</code> | Trusted signing profile ARNs. |
| <code><a href="#ecr-scan-verifier.NotationVerificationOptions.property.failOnUnsigned">failOnUnsigned</a></code> | <code>boolean</code> | Whether to fail the deployment if the image is unsigned or signature verification fails. |

---

##### `trustedIdentities`<sup>Required</sup> <a name="trustedIdentities" id="ecr-scan-verifier.NotationVerificationOptions.property.trustedIdentities"></a>

```typescript
public readonly trustedIdentities: string[];
```

- *Type:* string[]

Trusted signing profile ARNs.

At least one signing profile ARN must be specified.

---

*Example*

```typescript
['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile']
```


##### `failOnUnsigned`<sup>Optional</sup> <a name="failOnUnsigned" id="ecr-scan-verifier.NotationVerificationOptions.property.failOnUnsigned"></a>

```typescript
public readonly failOnUnsigned: boolean;
```

- *Type:* boolean
- *Default:* true

Whether to fail the deployment if the image is unsigned or signature verification fails.

---

### S3OutputOptions <a name="S3OutputOptions" id="ecr-scan-verifier.S3OutputOptions"></a>

Output configuration for scan logs to S3 bucket.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.S3OutputOptions.Initializer"></a>

```typescript
import { S3OutputOptions } from 'ecr-scan-verifier'

const s3OutputOptions: S3OutputOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.S3OutputOptions.property.type">type</a></code> | <code><a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a></code> | The type of scan logs output. |
| <code><a href="#ecr-scan-verifier.S3OutputOptions.property.bucketName">bucketName</a></code> | <code>string</code> | The name of the S3 bucket. |
| <code><a href="#ecr-scan-verifier.S3OutputOptions.property.prefix">prefix</a></code> | <code>string</code> | Optional prefix for S3 objects. |

---

##### `type`<sup>Required</sup> <a name="type" id="ecr-scan-verifier.S3OutputOptions.property.type"></a>

```typescript
public readonly type: ScanLogsOutputType;
```

- *Type:* <a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a>

The type of scan logs output.

---

##### `bucketName`<sup>Required</sup> <a name="bucketName" id="ecr-scan-verifier.S3OutputOptions.property.bucketName"></a>

```typescript
public readonly bucketName: string;
```

- *Type:* string

The name of the S3 bucket.

---

##### `prefix`<sup>Optional</sup> <a name="prefix" id="ecr-scan-verifier.S3OutputOptions.property.prefix"></a>

```typescript
public readonly prefix: string;
```

- *Type:* string

Optional prefix for S3 objects.

---

### S3OutputProps <a name="S3OutputProps" id="ecr-scan-verifier.S3OutputProps"></a>

Configuration for scan logs output to S3 bucket.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.S3OutputProps.Initializer"></a>

```typescript
import { S3OutputProps } from 'ecr-scan-verifier'

const s3OutputProps: S3OutputProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.S3OutputProps.property.bucket">bucket</a></code> | <code>aws-cdk-lib.aws_s3.IBucket</code> | The S3 bucket to output scan logs. |
| <code><a href="#ecr-scan-verifier.S3OutputProps.property.prefix">prefix</a></code> | <code>string</code> | Optional prefix for S3 objects. |

---

##### `bucket`<sup>Required</sup> <a name="bucket" id="ecr-scan-verifier.S3OutputProps.property.bucket"></a>

```typescript
public readonly bucket: IBucket;
```

- *Type:* aws-cdk-lib.aws_s3.IBucket

The S3 bucket to output scan logs.

---

##### `prefix`<sup>Optional</sup> <a name="prefix" id="ecr-scan-verifier.S3OutputProps.property.prefix"></a>

```typescript
public readonly prefix: string;
```

- *Type:* string

Optional prefix for S3 objects.

---

### SbomOutputConfig <a name="SbomOutputConfig" id="ecr-scan-verifier.SbomOutputConfig"></a>

Output of SbomOutput.bind().

#### Initializer <a name="Initializer" id="ecr-scan-verifier.SbomOutputConfig.Initializer"></a>

```typescript
import { SbomOutputConfig } from 'ecr-scan-verifier'

const sbomOutputConfig: SbomOutputConfig = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.SbomOutputConfig.property.bucketName">bucketName</a></code> | <code>string</code> | The S3 bucket name for SBOM output. |
| <code><a href="#ecr-scan-verifier.SbomOutputConfig.property.format">format</a></code> | <code><a href="#ecr-scan-verifier.SbomFormat">SbomFormat</a></code> | The SBOM format. |
| <code><a href="#ecr-scan-verifier.SbomOutputConfig.property.kmsKeyArn">kmsKeyArn</a></code> | <code>string</code> | The KMS key ARN for encrypting SBOM output in S3. |
| <code><a href="#ecr-scan-verifier.SbomOutputConfig.property.prefix">prefix</a></code> | <code>string</code> | Optional prefix for S3 objects. |

---

##### `bucketName`<sup>Required</sup> <a name="bucketName" id="ecr-scan-verifier.SbomOutputConfig.property.bucketName"></a>

```typescript
public readonly bucketName: string;
```

- *Type:* string

The S3 bucket name for SBOM output.

---

##### `format`<sup>Required</sup> <a name="format" id="ecr-scan-verifier.SbomOutputConfig.property.format"></a>

```typescript
public readonly format: SbomFormat;
```

- *Type:* <a href="#ecr-scan-verifier.SbomFormat">SbomFormat</a>

The SBOM format.

---

##### `kmsKeyArn`<sup>Required</sup> <a name="kmsKeyArn" id="ecr-scan-verifier.SbomOutputConfig.property.kmsKeyArn"></a>

```typescript
public readonly kmsKeyArn: string;
```

- *Type:* string

The KMS key ARN for encrypting SBOM output in S3.

---

##### `prefix`<sup>Optional</sup> <a name="prefix" id="ecr-scan-verifier.SbomOutputConfig.property.prefix"></a>

```typescript
public readonly prefix: string;
```

- *Type:* string

Optional prefix for S3 objects.

---

### SbomOutputProps <a name="SbomOutputProps" id="ecr-scan-verifier.SbomOutputProps"></a>

Properties for SBOM output.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.SbomOutputProps.Initializer"></a>

```typescript
import { SbomOutputProps } from 'ecr-scan-verifier'

const sbomOutputProps: SbomOutputProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.SbomOutputProps.property.bucket">bucket</a></code> | <code>aws-cdk-lib.aws_s3.IBucket</code> | The S3 bucket to output SBOM. |
| <code><a href="#ecr-scan-verifier.SbomOutputProps.property.encryptionKey">encryptionKey</a></code> | <code>aws-cdk-lib.aws_kms.IKey</code> | The KMS key used to encrypt the SBOM report in S3. |
| <code><a href="#ecr-scan-verifier.SbomOutputProps.property.prefix">prefix</a></code> | <code>string</code> | Optional prefix for S3 objects. |

---

##### `bucket`<sup>Required</sup> <a name="bucket" id="ecr-scan-verifier.SbomOutputProps.property.bucket"></a>

```typescript
public readonly bucket: IBucket;
```

- *Type:* aws-cdk-lib.aws_s3.IBucket

The S3 bucket to output SBOM.

The bucket is used as the destination for Amazon Inspector's
CreateSbomExport API and for storing the final SBOM file.

---

##### `encryptionKey`<sup>Required</sup> <a name="encryptionKey" id="ecr-scan-verifier.SbomOutputProps.property.encryptionKey"></a>

```typescript
public readonly encryptionKey: IKey;
```

- *Type:* aws-cdk-lib.aws_kms.IKey

The KMS key used to encrypt the SBOM report in S3.

Amazon Inspector's CreateSbomExport API requires a customer managed
symmetric encryption KMS key. AWS managed keys are not supported.

The construct automatically adds the required key policy for
the `inspector2.amazonaws.com` service principal.

---

##### `prefix`<sup>Optional</sup> <a name="prefix" id="ecr-scan-verifier.SbomOutputProps.property.prefix"></a>

```typescript
public readonly prefix: string;
```

- *Type:* string
- *Default:* no prefix

Optional prefix for S3 objects.

---

### ScanConfigBindOutput <a name="ScanConfigBindOutput" id="ecr-scan-verifier.ScanConfigBindOutput"></a>

Output of ScanConfig.bind().

#### Initializer <a name="Initializer" id="ecr-scan-verifier.ScanConfigBindOutput.Initializer"></a>

```typescript
import { ScanConfigBindOutput } from 'ecr-scan-verifier'

const scanConfigBindOutput: ScanConfigBindOutput = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.ScanConfigBindOutput.property.scanType">scanType</a></code> | <code>string</code> | The scan type ('BASIC', 'ENHANCED', or 'SIGNATURE_ONLY'). |
| <code><a href="#ecr-scan-verifier.ScanConfigBindOutput.property.startScan">startScan</a></code> | <code>boolean</code> | Whether to start an image scan via StartImageScan API. |
| <code><a href="#ecr-scan-verifier.ScanConfigBindOutput.property.sbomOutput">sbomOutput</a></code> | <code><a href="#ecr-scan-verifier.SbomOutput">SbomOutput</a></code> | SBOM output configuration (Enhanced scanning only). |

---

##### `scanType`<sup>Required</sup> <a name="scanType" id="ecr-scan-verifier.ScanConfigBindOutput.property.scanType"></a>

```typescript
public readonly scanType: string;
```

- *Type:* string

The scan type ('BASIC', 'ENHANCED', or 'SIGNATURE_ONLY').

---

##### `startScan`<sup>Required</sup> <a name="startScan" id="ecr-scan-verifier.ScanConfigBindOutput.property.startScan"></a>

```typescript
public readonly startScan: boolean;
```

- *Type:* boolean

Whether to start an image scan via StartImageScan API.

---

##### `sbomOutput`<sup>Optional</sup> <a name="sbomOutput" id="ecr-scan-verifier.ScanConfigBindOutput.property.sbomOutput"></a>

```typescript
public readonly sbomOutput: SbomOutput;
```

- *Type:* <a href="#ecr-scan-verifier.SbomOutput">SbomOutput</a>

SBOM output configuration (Enhanced scanning only).

---

### ScanLogsOutputOptions <a name="ScanLogsOutputOptions" id="ecr-scan-verifier.ScanLogsOutputOptions"></a>

Output configurations for scan logs.

#### Initializer <a name="Initializer" id="ecr-scan-verifier.ScanLogsOutputOptions.Initializer"></a>

```typescript
import { ScanLogsOutputOptions } from 'ecr-scan-verifier'

const scanLogsOutputOptions: ScanLogsOutputOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.ScanLogsOutputOptions.property.type">type</a></code> | <code><a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a></code> | The type of scan logs output. |

---

##### `type`<sup>Required</sup> <a name="type" id="ecr-scan-verifier.ScanLogsOutputOptions.property.type"></a>

```typescript
public readonly type: ScanLogsOutputType;
```

- *Type:* <a href="#ecr-scan-verifier.ScanLogsOutputType">ScanLogsOutputType</a>

The type of scan logs output.

---

### SignatureOnlyConfigOptions <a name="SignatureOnlyConfigOptions" id="ecr-scan-verifier.SignatureOnlyConfigOptions"></a>

Options for signature-only verification (no scanning).

#### Initializer <a name="Initializer" id="ecr-scan-verifier.SignatureOnlyConfigOptions.Initializer"></a>

```typescript
import { SignatureOnlyConfigOptions } from 'ecr-scan-verifier'

const signatureOnlyConfigOptions: SignatureOnlyConfigOptions = { ... }
```


### SignatureVerificationBindOutput <a name="SignatureVerificationBindOutput" id="ecr-scan-verifier.SignatureVerificationBindOutput"></a>

Output of SignatureVerification.bind().

#### Initializer <a name="Initializer" id="ecr-scan-verifier.SignatureVerificationBindOutput.Initializer"></a>

```typescript
import { SignatureVerificationBindOutput } from 'ecr-scan-verifier'

const signatureVerificationBindOutput: SignatureVerificationBindOutput = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#ecr-scan-verifier.SignatureVerificationBindOutput.property.failOnUnsigned">failOnUnsigned</a></code> | <code>boolean</code> | Whether to fail the deployment on unsigned images. |
| <code><a href="#ecr-scan-verifier.SignatureVerificationBindOutput.property.type">type</a></code> | <code>string</code> | The verification type. |
| <code><a href="#ecr-scan-verifier.SignatureVerificationBindOutput.property.kmsKeyArn">kmsKeyArn</a></code> | <code>string</code> | KMS key ARN (Cosign KMS only). |
| <code><a href="#ecr-scan-verifier.SignatureVerificationBindOutput.property.publicKey">publicKey</a></code> | <code>string</code> | Public key content (Cosign public key only). |
| <code><a href="#ecr-scan-verifier.SignatureVerificationBindOutput.property.trustedIdentities">trustedIdentities</a></code> | <code>string[]</code> | Trusted signing profile ARNs (Notation only). |

---

##### `failOnUnsigned`<sup>Required</sup> <a name="failOnUnsigned" id="ecr-scan-verifier.SignatureVerificationBindOutput.property.failOnUnsigned"></a>

```typescript
public readonly failOnUnsigned: boolean;
```

- *Type:* boolean

Whether to fail the deployment on unsigned images.

---

##### `type`<sup>Required</sup> <a name="type" id="ecr-scan-verifier.SignatureVerificationBindOutput.property.type"></a>

```typescript
public readonly type: string;
```

- *Type:* string

The verification type.

---

##### `kmsKeyArn`<sup>Optional</sup> <a name="kmsKeyArn" id="ecr-scan-verifier.SignatureVerificationBindOutput.property.kmsKeyArn"></a>

```typescript
public readonly kmsKeyArn: string;
```

- *Type:* string

KMS key ARN (Cosign KMS only).

---

##### `publicKey`<sup>Optional</sup> <a name="publicKey" id="ecr-scan-verifier.SignatureVerificationBindOutput.property.publicKey"></a>

```typescript
public readonly publicKey: string;
```

- *Type:* string

Public key content (Cosign public key only).

---

##### `trustedIdentities`<sup>Optional</sup> <a name="trustedIdentities" id="ecr-scan-verifier.SignatureVerificationBindOutput.property.trustedIdentities"></a>

```typescript
public readonly trustedIdentities: string[];
```

- *Type:* string[]

Trusted signing profile ARNs (Notation only).

---

## Classes <a name="Classes" id="Classes"></a>

### SbomOutput <a name="SbomOutput" id="ecr-scan-verifier.SbomOutput"></a>

Configuration for SBOM (Software Bill of Materials) output.

SBOM export is only available with Enhanced scanning (Amazon Inspector).
Uses the Inspector CreateSbomExport API to generate SBOM and uploads it to S3.

**Note**: Using with Basic scanning will throw an error.

#### Initializers <a name="Initializers" id="ecr-scan-verifier.SbomOutput.Initializer"></a>

```typescript
import { SbomOutput } from 'ecr-scan-verifier'

new SbomOutput()
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.SbomOutput.bind">bind</a></code> | Returns the SBOM output configuration. |

---

##### `bind` <a name="bind" id="ecr-scan-verifier.SbomOutput.bind"></a>

```typescript
public bind(grantee: IGrantable): SbomOutputConfig
```

Returns the SBOM output configuration.

###### `grantee`<sup>Required</sup> <a name="grantee" id="ecr-scan-verifier.SbomOutput.bind.parameter.grantee"></a>

- *Type:* aws-cdk-lib.aws_iam.IGrantable

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.SbomOutput.cycloneDx14">cycloneDx14</a></code> | Output SBOM in CycloneDX 1.4 JSON format. |
| <code><a href="#ecr-scan-verifier.SbomOutput.spdx23">spdx23</a></code> | Output SBOM in SPDX 2.3 JSON format. |

---

##### `cycloneDx14` <a name="cycloneDx14" id="ecr-scan-verifier.SbomOutput.cycloneDx14"></a>

```typescript
import { SbomOutput } from 'ecr-scan-verifier'

SbomOutput.cycloneDx14(props: SbomOutputProps)
```

Output SBOM in CycloneDX 1.4 JSON format.

###### `props`<sup>Required</sup> <a name="props" id="ecr-scan-verifier.SbomOutput.cycloneDx14.parameter.props"></a>

- *Type:* <a href="#ecr-scan-verifier.SbomOutputProps">SbomOutputProps</a>

---

##### `spdx23` <a name="spdx23" id="ecr-scan-verifier.SbomOutput.spdx23"></a>

```typescript
import { SbomOutput } from 'ecr-scan-verifier'

SbomOutput.spdx23(props: SbomOutputProps)
```

Output SBOM in SPDX 2.3 JSON format.

###### `props`<sup>Required</sup> <a name="props" id="ecr-scan-verifier.SbomOutput.spdx23.parameter.props"></a>

- *Type:* <a href="#ecr-scan-verifier.SbomOutputProps">SbomOutputProps</a>

---



### ScanConfig <a name="ScanConfig" id="ecr-scan-verifier.ScanConfig"></a>

Configuration for ECR image scan type.

Use `ScanConfig.basic()` for ECR native basic scanning,
`ScanConfig.enhanced()` for Amazon Inspector enhanced scanning,
or `ScanConfig.signatureOnly()` for signature verification without scanning.

#### Initializers <a name="Initializers" id="ecr-scan-verifier.ScanConfig.Initializer"></a>

```typescript
import { ScanConfig } from 'ecr-scan-verifier'

new ScanConfig()
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.ScanConfig.bind">bind</a></code> | Returns the scan configuration. |

---

##### `bind` <a name="bind" id="ecr-scan-verifier.ScanConfig.bind"></a>

```typescript
public bind(): ScanConfigBindOutput
```

Returns the scan configuration.

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.ScanConfig.basic">basic</a></code> | Basic scanning using Amazon ECR native scanning. |
| <code><a href="#ecr-scan-verifier.ScanConfig.enhanced">enhanced</a></code> | Enhanced scanning using Amazon Inspector. |
| <code><a href="#ecr-scan-verifier.ScanConfig.signatureOnly">signatureOnly</a></code> | Signature verification only (no vulnerability scanning). |

---

##### `basic` <a name="basic" id="ecr-scan-verifier.ScanConfig.basic"></a>

```typescript
import { ScanConfig } from 'ecr-scan-verifier'

ScanConfig.basic(options?: BasicScanConfigOptions)
```

Basic scanning using Amazon ECR native scanning.

Basic scanning scans for known CVEs in the OS packages of your container image.

###### `options`<sup>Optional</sup> <a name="options" id="ecr-scan-verifier.ScanConfig.basic.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.BasicScanConfigOptions">BasicScanConfigOptions</a>

---

##### `enhanced` <a name="enhanced" id="ecr-scan-verifier.ScanConfig.enhanced"></a>

```typescript
import { ScanConfig } from 'ecr-scan-verifier'

ScanConfig.enhanced(options?: EnhancedScanConfigOptions)
```

Enhanced scanning using Amazon Inspector.

Enhanced scanning provides more detailed findings including
programming language package vulnerabilities.
Ensure Amazon Inspector is enabled for your registry.

###### `options`<sup>Optional</sup> <a name="options" id="ecr-scan-verifier.ScanConfig.enhanced.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.EnhancedScanConfigOptions">EnhancedScanConfigOptions</a>

---

##### `signatureOnly` <a name="signatureOnly" id="ecr-scan-verifier.ScanConfig.signatureOnly"></a>

```typescript
import { ScanConfig } from 'ecr-scan-verifier'

ScanConfig.signatureOnly(options?: SignatureOnlyConfigOptions)
```

Signature verification only (no vulnerability scanning).

Verifies the image signature without performing vulnerability scanning.
This mode skips ECR/Inspector scanning entirely and only validates the image signature.

**Requirements**:
- `signatureVerification` must be specified in EcrScanVerifierProps

###### `options`<sup>Optional</sup> <a name="options" id="ecr-scan-verifier.ScanConfig.signatureOnly.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.SignatureOnlyConfigOptions">SignatureOnlyConfigOptions</a>

---



### ScanLogsOutput <a name="ScanLogsOutput" id="ecr-scan-verifier.ScanLogsOutput"></a>

Represents the output of the scan logs.

#### Initializers <a name="Initializers" id="ecr-scan-verifier.ScanLogsOutput.Initializer"></a>

```typescript
import { ScanLogsOutput } from 'ecr-scan-verifier'

new ScanLogsOutput()
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.ScanLogsOutput.bind">bind</a></code> | Returns the output configuration for scan logs. |

---

##### `bind` <a name="bind" id="ecr-scan-verifier.ScanLogsOutput.bind"></a>

```typescript
public bind(grantee: IGrantable): ScanLogsOutputOptions
```

Returns the output configuration for scan logs.

###### `grantee`<sup>Required</sup> <a name="grantee" id="ecr-scan-verifier.ScanLogsOutput.bind.parameter.grantee"></a>

- *Type:* aws-cdk-lib.aws_iam.IGrantable

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.ScanLogsOutput.cloudWatchLogs">cloudWatchLogs</a></code> | Scan logs output to CloudWatch Logs log group. |
| <code><a href="#ecr-scan-verifier.ScanLogsOutput.s3">s3</a></code> | Scan logs output to S3 bucket. |

---

##### `cloudWatchLogs` <a name="cloudWatchLogs" id="ecr-scan-verifier.ScanLogsOutput.cloudWatchLogs"></a>

```typescript
import { ScanLogsOutput } from 'ecr-scan-verifier'

ScanLogsOutput.cloudWatchLogs(options: CloudWatchLogsOutputProps)
```

Scan logs output to CloudWatch Logs log group.

**Note on Large Scan Results**: CloudWatch Logs has a limit of 1 MB per log event.
If scan results exceed this limit, they will be automatically
split into multiple log events. Each chunk will be prefixed with `[part X/Y]` to
indicate the sequence, ensuring no data loss while staying within CloudWatch Logs quotas.
**For large scan results, we recommend using S3 output instead** to avoid fragmentation
and make it easier to view complete results.

###### `options`<sup>Required</sup> <a name="options" id="ecr-scan-verifier.ScanLogsOutput.cloudWatchLogs.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.CloudWatchLogsOutputProps">CloudWatchLogsOutputProps</a>

---

##### `s3` <a name="s3" id="ecr-scan-verifier.ScanLogsOutput.s3"></a>

```typescript
import { ScanLogsOutput } from 'ecr-scan-verifier'

ScanLogsOutput.s3(options: S3OutputProps)
```

Scan logs output to S3 bucket.

###### `options`<sup>Required</sup> <a name="options" id="ecr-scan-verifier.ScanLogsOutput.s3.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.S3OutputProps">S3OutputProps</a>

---



### SignatureVerification <a name="SignatureVerification" id="ecr-scan-verifier.SignatureVerification"></a>

Signature verification configuration for container images.

Supports Notation (AWS Signer) and Cosign (Sigstore) verification methods.
Signature verification is performed before the vulnerability scan during deployment.

#### Initializers <a name="Initializers" id="ecr-scan-verifier.SignatureVerification.Initializer"></a>

```typescript
import { SignatureVerification } from 'ecr-scan-verifier'

new SignatureVerification()
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.SignatureVerification.bind">bind</a></code> | Returns the signature verification configuration. |

---

##### `bind` <a name="bind" id="ecr-scan-verifier.SignatureVerification.bind"></a>

```typescript
public bind(grantee: IGrantable): SignatureVerificationBindOutput
```

Returns the signature verification configuration.

###### `grantee`<sup>Required</sup> <a name="grantee" id="ecr-scan-verifier.SignatureVerification.bind.parameter.grantee"></a>

- *Type:* aws-cdk-lib.aws_iam.IGrantable

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.SignatureVerification.cosignKms">cosignKms</a></code> | Verify image signature using Cosign with an AWS KMS key. |
| <code><a href="#ecr-scan-verifier.SignatureVerification.cosignPublicKey">cosignPublicKey</a></code> | Verify image signature using Cosign with a public key. |
| <code><a href="#ecr-scan-verifier.SignatureVerification.notation">notation</a></code> | Verify image signature using Notation (AWS Signer). |

---

##### `cosignKms` <a name="cosignKms" id="ecr-scan-verifier.SignatureVerification.cosignKms"></a>

```typescript
import { SignatureVerification } from 'ecr-scan-verifier'

SignatureVerification.cosignKms(options: CosignKmsVerificationOptions)
```

Verify image signature using Cosign with an AWS KMS key.

**Important:** Cosign verification skips Rekor transparency log verification.

Sign your images with:
```bash
cosign sign --tlog-upload=false --key awskms:///KMS_KEY_ARN IMAGE
```

###### `options`<sup>Required</sup> <a name="options" id="ecr-scan-verifier.SignatureVerification.cosignKms.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.CosignKmsVerificationOptions">CosignKmsVerificationOptions</a>

---

##### `cosignPublicKey` <a name="cosignPublicKey" id="ecr-scan-verifier.SignatureVerification.cosignPublicKey"></a>

```typescript
import { SignatureVerification } from 'ecr-scan-verifier'

SignatureVerification.cosignPublicKey(options: CosignPublicKeyVerificationOptions)
```

Verify image signature using Cosign with a public key.

**Important:** Cosign verification skips Rekor transparency log verification.

Sign your images with:
```bash
cosign sign --tlog-upload=false --key cosign.pub IMAGE
```

###### `options`<sup>Required</sup> <a name="options" id="ecr-scan-verifier.SignatureVerification.cosignPublicKey.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.CosignPublicKeyVerificationOptions">CosignPublicKeyVerificationOptions</a>

---

##### `notation` <a name="notation" id="ecr-scan-verifier.SignatureVerification.notation"></a>

```typescript
import { SignatureVerification } from 'ecr-scan-verifier'

SignatureVerification.notation(options: NotationVerificationOptions)
```

Verify image signature using Notation (AWS Signer).

Requires the image to be signed with AWS Signer.

###### `options`<sup>Required</sup> <a name="options" id="ecr-scan-verifier.SignatureVerification.notation.parameter.options"></a>

- *Type:* <a href="#ecr-scan-verifier.NotationVerificationOptions">NotationVerificationOptions</a>

---




## Enums <a name="Enums" id="Enums"></a>

### SbomFormat <a name="SbomFormat" id="ecr-scan-verifier.SbomFormat"></a>

SBOM (Software Bill of Materials) output format.

Only available with Enhanced scanning (Amazon Inspector).
Uses the Inspector CreateSbomExport API to generate SBOM.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.SbomFormat.CYCLONEDX_1_4">CYCLONEDX_1_4</a></code> | CycloneDX 1.4 JSON format. |
| <code><a href="#ecr-scan-verifier.SbomFormat.SPDX_2_3">SPDX_2_3</a></code> | SPDX 2.3 JSON format. |

---

##### `CYCLONEDX_1_4` <a name="CYCLONEDX_1_4" id="ecr-scan-verifier.SbomFormat.CYCLONEDX_1_4"></a>

CycloneDX 1.4 JSON format.

---


##### `SPDX_2_3` <a name="SPDX_2_3" id="ecr-scan-verifier.SbomFormat.SPDX_2_3"></a>

SPDX 2.3 JSON format.

---


### ScanLogsOutputType <a name="ScanLogsOutputType" id="ecr-scan-verifier.ScanLogsOutputType"></a>

Enum for ScanLogsOutputType.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.ScanLogsOutputType.CLOUDWATCH_LOGS">CLOUDWATCH_LOGS</a></code> | Output scan logs to CloudWatch Logs. |
| <code><a href="#ecr-scan-verifier.ScanLogsOutputType.S3">S3</a></code> | Output scan logs to S3 bucket. |

---

##### `CLOUDWATCH_LOGS` <a name="CLOUDWATCH_LOGS" id="ecr-scan-verifier.ScanLogsOutputType.CLOUDWATCH_LOGS"></a>

Output scan logs to CloudWatch Logs.

---


##### `S3` <a name="S3" id="ecr-scan-verifier.ScanLogsOutputType.S3"></a>

Output scan logs to S3 bucket.

---


### Severity <a name="Severity" id="ecr-scan-verifier.Severity"></a>

ECR severity levels for vulnerability findings.

> [https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-basic.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-basic.html)

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#ecr-scan-verifier.Severity.INFORMATIONAL">INFORMATIONAL</a></code> | *No description.* |
| <code><a href="#ecr-scan-verifier.Severity.LOW">LOW</a></code> | *No description.* |
| <code><a href="#ecr-scan-verifier.Severity.MEDIUM">MEDIUM</a></code> | *No description.* |
| <code><a href="#ecr-scan-verifier.Severity.HIGH">HIGH</a></code> | *No description.* |
| <code><a href="#ecr-scan-verifier.Severity.CRITICAL">CRITICAL</a></code> | *No description.* |
| <code><a href="#ecr-scan-verifier.Severity.UNDEFINED">UNDEFINED</a></code> | *No description.* |

---

##### `INFORMATIONAL` <a name="INFORMATIONAL" id="ecr-scan-verifier.Severity.INFORMATIONAL"></a>

---


##### `LOW` <a name="LOW" id="ecr-scan-verifier.Severity.LOW"></a>

---


##### `MEDIUM` <a name="MEDIUM" id="ecr-scan-verifier.Severity.MEDIUM"></a>

---


##### `HIGH` <a name="HIGH" id="ecr-scan-verifier.Severity.HIGH"></a>

---


##### `CRITICAL` <a name="CRITICAL" id="ecr-scan-verifier.Severity.CRITICAL"></a>

---


##### `UNDEFINED` <a name="UNDEFINED" id="ecr-scan-verifier.Severity.UNDEFINED"></a>

---

