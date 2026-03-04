# 署名検証のみモード追加 + SBOM 設計変更 - 実装計画

## 概要

1. **`ScanConfig.signatureOnly()` 追加**: 署名検証だけを行いスキャンをスキップできるようにする
2. **破壊的変更: `sbomOutput` の移動**: `EcrScanVerifierProps.sbomOutput` を `EnhancedScanConfigOptions.sbomOutput` に移動し、型レベルで Enhanced 専用であることを保証

## 変更の動機

### 現状の問題

```typescript
// ❌ Basic scanning + sbomOutput は型レベルで禁止されていない
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(), // Basic では SBOM 使えない
  sbomOutput: SbomOutput.cycloneDx14({...}), // でも指定できてしまう（実行時エラー）
});
```

### 改善後

```typescript
// ✅ Enhanced のみで sbomOutput が指定可能（型安全）
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({...}), // Enhanced 専用
  }),
});

// ✅ 署名検証のみ（スキャンなし）
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
  }),
});
```

---

## API デザイン

### 新しい API

```typescript
// 1. Enhanced scanning + SBOM
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({
      bucket: sbomBucket,
      encryptionKey: sbomKey,
    }),
  }),
});

// 2. 署名検証のみ（スキャンなし）
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
  }),
});

// 3. Basic scanning（変更なし）
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(),
});
```

### 移行ガイド（破壊的変更）

**Before (v1.x):**

```typescript
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced(),
  sbomOutput: SbomOutput.cycloneDx14({...}), // props 直下
});
```

**After (v2.x):**

```typescript
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({...}), // scanConfig 内
  }),
});
```

---

## バリデーションルール

### 型レベル（コンパイル時）

- `ScanConfig.enhanced()` のみ `sbomOutput` を受け入れ
- `ScanConfig.basic()` / `ScanConfig.signatureOnly()` では `sbomOutput` を指定不可

### 実行時（CDK construct）

- `ScanConfig.signatureOnly()` 使用時:
  - `signatureVerification` が **未指定** → **エラー**
  - `signatureVerification` が **指定済み** → OK

---

## 実装変更一覧

### 1. `src/scan-config.ts` — API 変更

**変更内容:**

- `EnhancedScanConfigOptions` に `sbomOutput` プロパティ追加
- `SignatureOnlyConfigOptions` インターフェース追加
- `ScanConfigBindOutput.scanType` の JSDoc を更新（`'SIGNATURE_ONLY'` を追加）
- `ScanConfig.signatureOnly()` メソッド追加
- `SignatureOnlyScanConfig` クラス実装
- `EnhancedScanConfig.bind()` で `sbomOutput` を返すように変更

**コード:**

```typescript
/**
 * Options for basic ECR image scanning.
 */
export interface BasicScanConfigOptions {
  readonly startScan?: boolean;
}

/**
 * Options for enhanced ECR image scanning (Amazon Inspector).
 */
export interface EnhancedScanConfigOptions {
  /**
   * SBOM (Software Bill of Materials) output configuration.
   *
   * SBOM export uses Amazon Inspector's CreateSbomExport API to generate SBOM
   * and uploads it to S3.
   *
   * @default - no SBOM output
   */
  readonly sbomOutput?: SbomOutput;
}

/**
 * Options for signature-only verification (no scanning).
 */
export interface SignatureOnlyConfigOptions {
  // 将来的なオプション用に予約
}

/**
 * Output of ScanConfig.bind().
 */
export interface ScanConfigBindOutput {
  /**
   * The scan type ('BASIC', 'ENHANCED', or 'SIGNATURE_ONLY').
   */
  readonly scanType: string;

  /**
   * Whether to start an image scan via StartImageScan API.
   */
  readonly startScan: boolean;

  /**
   * SBOM output configuration (Enhanced scanning only).
   */
  readonly sbomOutput?: SbomOutput;
}

/**
 * Configuration for ECR image scan type.
 *
 * Use `ScanConfig.basic()` for ECR native basic scanning,
 * `ScanConfig.enhanced()` for Amazon Inspector enhanced scanning,
 * or `ScanConfig.signatureOnly()` for signature verification without scanning.
 */
export abstract class ScanConfig {
  public static basic(options?: BasicScanConfigOptions): ScanConfig {
    return new BasicScanConfig(options);
  }

  public static enhanced(options?: EnhancedScanConfigOptions): ScanConfig {
    return new EnhancedScanConfig(options);
  }

  /**
   * Signature verification only (no vulnerability scanning).
   *
   * Verifies the image signature without performing vulnerability scanning.
   * This mode skips ECR/Inspector scanning entirely and only validates the image signature.
   *
   * **Requirements**:
   * - `signatureVerification` must be specified in EcrScanVerifierProps
   */
  public static signatureOnly(options?: SignatureOnlyConfigOptions): ScanConfig {
    return new SignatureOnlyScanConfig(options);
  }

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
  private readonly sbomOutput?: SbomOutput;

  constructor(options?: EnhancedScanConfigOptions) {
    super();
    this.sbomOutput = options?.sbomOutput;
  }

  public bind(): ScanConfigBindOutput {
    return {
      scanType: 'ENHANCED',
      startScan: false,
      sbomOutput: this.sbomOutput,
    };
  }
}

class SignatureOnlyScanConfig extends ScanConfig {
  constructor(_options?: SignatureOnlyConfigOptions) {
    super();
  }

  public bind(): ScanConfigBindOutput {
    return {
      scanType: 'SIGNATURE_ONLY',
      startScan: false,
    };
  }
}
```

---

### 2. `src/ecr-scan-verifier.ts` — バリデーション + IAM 権限調整

**変更内容:**

- `EcrScanVerifierProps` から `sbomOutput` プロパティを削除
- `scanConfigOutput.sbomOutput` から SBOM 設定を取得
- `signatureOnly` + `signatureVerification` 必須のバリデーション追加
- Basic + SBOM のバリデーションを削除（型レベルで保証されるため不要）
- `scanType !== 'SIGNATURE_ONLY'` の場合のみスキャン関連 IAM 権限を付与

**変更箇所:**

```typescript
export interface EcrScanVerifierProps {
  readonly repository: IRepository;
  readonly imageTag?: string;
  readonly scanConfig: ScanConfig;
  readonly severity?: Severity[];
  readonly failOnVulnerability?: boolean;
  readonly ignoreFindings?: string[];
  readonly scanLogsOutput?: ScanLogsOutput;
  // readonly sbomOutput?: SbomOutput; // ← 削除
  readonly signatureVerification?: SignatureVerification;
  readonly defaultLogGroup?: ILogGroup;
  readonly suppressErrorOnRollback?: boolean;
  readonly vulnsNotificationTopic?: ITopic;
  readonly blockConstructs?: IConstruct[];
}

// constructor 内
const scanConfigOutput = props.scanConfig.bind();

// Validate: signatureOnly requires signatureVerification
if (scanConfigOutput.scanType === 'SIGNATURE_ONLY' && !props.signatureVerification) {
  throw new Error(
    'ScanConfig.signatureOnly() requires signatureVerification to be specified. ' +
    'Use SignatureVerification.notation(), SignatureVerification.cosignPublicKey(), or SignatureVerification.cosignKms().',
  );
}

// Validate: SBOM output requires Enhanced scanning (削除: 型レベルで保証)
// if (props.sbomOutput && scanConfigOutput.scanType === 'BASIC') { ... }

const outputOptions = props.scanLogsOutput?.bind(customResourceLambda);

// SBOM output (scanConfigOutput から取得)
const sbomConfig = scanConfigOutput.sbomOutput?.bind(customResourceLambda);

// Signature verification
const signatureVerificationConfig = props.signatureVerification?.bind(customResourceLambda);

// ECR scan permissions (SIGNATURE_ONLY の場合は不要)
if (scanConfigOutput.scanType !== 'SIGNATURE_ONLY') {
  customResourceLambda.addToRolePolicy(
    new PolicyStatement({
      actions: ['ecr:DescribeImageScanFindings', 'ecr:DescribeImages'],
      resources: [props.repository.repositoryArn],
    }),
  );
}

// Inspector permissions (Enhanced のみ)
if (scanConfigOutput.scanType === 'ENHANCED') {
  customResourceLambda.addToRolePolicy(
    new PolicyStatement({
      actions: ['inspector2:ListCoverage', 'inspector2:ListFindings'],
      resources: ['*'],
    }),
  );
}

// StartImageScan permission
if (scanConfigOutput.startScan) {
  customResourceLambda.addToRolePolicy(
    new PolicyStatement({
      actions: ['ecr:StartImageScan'],
      resources: [props.repository.repositoryArn],
    }),
  );
}

// Signature verification permissions (変更なし)
if (signatureVerificationConfig) {
  // ... 既存コード
}

// SBOM export permissions (変更なし)
if (sbomConfig) {
  customResourceLambda.addToRolePolicy(
    new PolicyStatement({
      actions: ['inspector2:CreateSbomExport', 'inspector2:GetSbomExport'],
      resources: ['*'],
    }),
  );
}
```

---

### 3. `src/index.ts` — export 変更なし

`SbomOutput` は既に export されているため変更不要。

---

### 4. `src/custom-resource-props.ts` — 型定義更新

```typescript
export interface ScannerCustomResourceProps {
  readonly addr: string;
  readonly repositoryName: string;
  readonly imageTag: string;
  readonly scanType: string; // 'BASIC' | 'ENHANCED' | 'SIGNATURE_ONLY' を受け入れる
  readonly startScan: string;
  readonly severity: string[];
  readonly failOnVulnerability: string;
  readonly ignoreFindings: string[];
  readonly output?: OutputDetails;
  readonly sbom?: SbomConfig; // 変更なし
  readonly signatureVerification?: SignatureVerificationConfig;
  readonly suppressErrorOnRollback: string;
  readonly vulnsTopicArn?: string;
  readonly defaultLogGroupName: string;
}
```

---

### 5. `assets/lambda/lib/handler.ts` — Lambda ロジック修正

```typescript
export const handler = async (event: CloudFormationCustomResourceEvent) => {
  // ... 既存の初期化処理

  // 1. 署名検証（既存コード、変更なし）
  if (props.signatureVerification) {
    const verificationResult = await verifySignature(
      ecrClient,
      registryId,
      repositoryName,
      imageIdentifier,
      props.signatureVerification,
    );

    await outputSignatureVerificationLogs(
      verificationResult,
      repositoryName,
      imageTag,
      props.output,
      props.defaultLogGroupName,
    );
  }

  // 2. スキャン処理（新規: SIGNATURE_ONLY の場合は早期リターン）
  if (props.scanType === 'SIGNATURE_ONLY') {
    console.log('Vulnerability scanning skipped (ScanConfig.signatureOnly() mode).');
    return { PhysicalResourceId: physicalId };
  }

  // 3-5. 既存のスキャンフロー（BASIC / ENHANCED）
  console.log(`Starting scan verification (scanType: ${props.scanType})...`);

  // ... 既存コード
};
```

---

### 6. `test/scan-config.test.ts` — テスト追加

```typescript
import { ScanConfig } from '../src/scan-config';
import { SbomOutput } from '../src/sbom-output';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Stack } from 'aws-cdk-lib';

describe('ScanConfig', () => {
  // 既存テスト...

  describe('enhanced()', () => {
    test('accepts sbomOutput option', () => {
      const stack = new Stack();
      const bucket = new Bucket(stack, 'Bucket');
      const key = new Key(stack, 'Key');

      const config = ScanConfig.enhanced({
        sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
      });

      const output = config.bind();
      expect(output.scanType).toBe('ENHANCED');
      expect(output.sbomOutput).toBeDefined();
    });

    test('sbomOutput is optional', () => {
      const config = ScanConfig.enhanced();
      const output = config.bind();
      expect(output.scanType).toBe('ENHANCED');
      expect(output.sbomOutput).toBeUndefined();
    });
  });

  describe('signatureOnly()', () => {
    test('returns SIGNATURE_ONLY scan type', () => {
      const config = ScanConfig.signatureOnly();
      expect(config.bind()).toEqual({
        scanType: 'SIGNATURE_ONLY',
        startScan: false,
      });
    });

    test('accepts options parameter', () => {
      const config = ScanConfig.signatureOnly({});
      expect(config.bind().scanType).toBe('SIGNATURE_ONLY');
    });

    test('does not accept sbomOutput', () => {
      // TypeScript コンパイルエラーになるため、この test は不要
      // signatureOnly() に sbomOutput オプションは存在しない
    });
  });
});
```

---

### 7. `test/ecr-scan-verifier.test.ts` — テスト更新

**変更内容:**

- `sbomOutput` を `props` 直下から `ScanConfig.enhanced()` 内に移動
- Basic + SBOM のバリデーションテストを削除（型レベルで保証）
- `signatureOnly` + `signatureVerification` 必須テスト追加
- IAM 権限テスト追加

```typescript
describe('EcrScanVerifier', () => {
  test('enhanced scanning with SBOM output', () => {
    const stack = new Stack();
    const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');
    const bucket = new Bucket(stack, 'Bucket');
    const key = new Key(stack, 'Key');

    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.enhanced({
        sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
      }),
    });

    const template = Template.fromStack(stack);

    // SBOM 関連の IAM 権限が付与されている
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith(['inspector2:CreateSbomExport']),
          }),
        ]),
      },
    });
  });

  describe('ScanConfig.signatureOnly() validation', () => {
    test('throws error when signatureOnly without signatureVerification', () => {
      const stack = new Stack();
      const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');

      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          // signatureVerification: 未指定
        });
      }).toThrow(/signatureOnly.*requires signatureVerification/);
    });

    test('allows signatureOnly with notation verification', () => {
      const stack = new Stack();
      const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');

      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.notation({
            trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/test'],
          }),
        });
      }).not.toThrow();
    });

    test('allows signatureOnly with cosign public key verification', () => {
      const stack = new Stack();
      const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');

      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.cosignPublicKey({
            publicKey: 'test-key',
          }),
        });
      }).not.toThrow();
    });

    test('allows signatureOnly with cosign KMS verification', () => {
      const stack = new Stack();
      const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');
      const key = new Key(stack, 'Key');

      expect(() => {
        new EcrScanVerifier(stack, 'Verifier', {
          repository,
          scanConfig: ScanConfig.signatureOnly(),
          signatureVerification: SignatureVerification.cosignKms({ key }),
        });
      }).not.toThrow();
    });
  });

  describe('IAM permissions', () => {
    test('signatureOnly does not grant scan-related permissions', () => {
      const stack = new Stack();
      const repository = Repository.fromRepositoryName(stack, 'Repo', 'test-repo');

      new EcrScanVerifier(stack, 'Verifier', {
        repository,
        scanConfig: ScanConfig.signatureOnly(),
        signatureVerification: SignatureVerification.notation({
          trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/test'],
        }),
      });

      const template = Template.fromStack(stack);

      // ECR DescribeImageScanFindings が付与されていないことを確認
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.not(
            Match.arrayWith([
              Match.objectLike({
                Action: Match.arrayWith(['ecr:DescribeImageScanFindings']),
              }),
            ]),
          ),
        },
      });

      // 署名検証用の権限は付与されていることを確認
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith(['ecr:GetAuthorizationToken']),
            }),
            Match.objectLike({
              Action: Match.arrayWith(['signer:GetRevocationStatus']),
            }),
          ]),
        },
      });
    });
  });
});
```

**削除するテスト:**

```typescript
// このテストは不要（型レベルで保証されるため）
test('throws error when basic scanning with sbomOutput', () => {
  expect(() => {
    new EcrScanVerifier(stack, 'Scanner', {
      repository,
      scanConfig: ScanConfig.basic(),
      sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
    });
  }).toThrow(/SBOM output is only available with Enhanced scanning/);
});
```

---

### 8. `assets/lambda/test/handler.test.ts` — Lambda テスト追加

```typescript
describe('handler with scanType=SIGNATURE_ONLY', () => {
  test('skips scan when signatureOnly mode with notation', async () => {
    mockGetAuthorizationToken();
    mockBatchGetImage();
    const execMock = mockExecFile(); // notation mock

    const event = createEvent({
      scanType: 'SIGNATURE_ONLY',
      signatureVerification: {
        type: 'NOTATION',
        trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/test'],
        failOnUnsigned: 'true',
      },
    });

    const result = await handler(event);

    expect(result).toBeDefined();
    expect(result.PhysicalResourceId).toContain('ecr-scan-verifier');

    // 署名検証は実行される
    expect(execMock).toHaveBeenCalledWith(
      '/var/task/notation',
      expect.arrayContaining(['verify']),
      expect.any(Object),
    );

    // スキャン API は呼ばれない
    expect(mockClient(ECRClient)).not.toHaveReceivedCommand(StartImageScanCommand);
    expect(mockClient(ECRClient)).not.toHaveReceivedCommand(DescribeImageScanFindingsCommand);
    expect(mockClient(Inspector2Client)).not.toHaveReceivedCommand(ListFindingsCommand);
  });

  test('skips scan when signatureOnly mode with cosign', async () => {
    mockGetAuthorizationToken();
    mockBatchGetImage();
    const execMock = mockExecFile(); // cosign mock

    const event = createEvent({
      scanType: 'SIGNATURE_ONLY',
      signatureVerification: {
        type: 'COSIGN',
        publicKey: 'test-public-key',
        failOnUnsigned: 'true',
      },
    });

    const result = await handler(event);

    expect(result).toBeDefined();

    // cosign verify が実行される
    expect(execMock).toHaveBeenCalledWith(
      '/var/task/cosign',
      expect.arrayContaining(['verify']),
      expect.any(Object),
    );

    // スキャン API は呼ばれない
    expect(mockClient(ECRClient)).not.toHaveReceivedCommand(StartImageScanCommand);
    expect(mockClient(ECRClient)).not.toHaveReceivedCommand(DescribeImageScanFindingsCommand);
  });
});
```

---

### 9. `README.md` — ドキュメント更新

**変更箇所:**

#### SBOM Output セクション（破壊的変更）

```markdown
### SBOM Output

You can generate SBOM (Software Bill of Materials) using Amazon Inspector's CreateSbomExport API.

**Note**: SBOM export is only available with Enhanced scanning.

```ts
import { SbomOutput, ScanConfig } from 'ecr-scan-verifier';

const sbomBucket = new Bucket(this, 'SbomBucket');
const sbomEncryptionKey = new Key(this, 'SbomEncryptionKey');

new EcrScanVerifier(this, 'Scanner', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({
      bucket: sbomBucket,
      prefix: 'sbom/', // Optional
      encryptionKey: sbomEncryptionKey,
    }),
  }),
});
```

Available SBOM formats:

- `SbomOutput.cycloneDx14()` — CycloneDX 1.4 JSON format
- `SbomOutput.spdx23()` — SPDX 2.3 JSON format
```

#### 署名検証セクションに追加

```markdown
### Signature Verification Only (No Scanning)

If you only want to verify the image signature without performing vulnerability scanning,
use `ScanConfig.signatureOnly()`:

```typescript
import { EcrScanVerifier, ScanConfig, SignatureVerification } from 'ecr-scan-verifier';

new EcrScanVerifier(this, 'SignatureOnlyVerifier', {
  repository,
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: [
      'arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile',
    ],
  }),
});
```

**Note**:
- `ScanConfig.signatureOnly()` requires `signatureVerification` to be specified.
- This mode skips vulnerability scanning entirely, reducing Lambda execution time and IAM permissions.

#### Use Cases

- **Fast deployments**: When you only need to verify image authenticity without waiting for scan results.
- **Pre-production environments**: Verify signatures in dev/staging before running full scans in production.
- **Minimal IAM permissions**: No `ecr:DescribeImageScanFindings` or `inspector2:*` permissions required.
```

---

### 10. `test/integ/enhanced/integ.sbom-output.ts` — テスト更新

```typescript
// Before
new EcrScanVerifier(stack, 'Scanner', {
  repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.enhanced(),
  ignoreFindings: IGNORE_FOR_PASSING_TESTS,
  sbomOutput: SbomOutput.cycloneDx14({ bucket: sbomBucket, encryptionKey: sbomKey }),
});

// After
new EcrScanVerifier(stack, 'Scanner', {
  repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({ bucket: sbomBucket, encryptionKey: sbomKey }),
  }),
  ignoreFindings: IGNORE_FOR_PASSING_TESTS,
});
```

---

### 11. `test/integ/signature/integ.notation-only.ts` — インテグレーションテスト（新規）

```typescript
import { App, Stack } from 'aws-cdk-lib';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { Construct } from 'constructs';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

class TestStack extends Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const repository = Repository.fromRepositoryName(
      this,
      'Repository',
      'ecr-scan-verifier-integ-notation',
    );

    // 署名検証のみ（スキャンなし）
    new EcrScanVerifier(this, 'SignatureOnlyVerifier', {
      repository,
      imageTag: 'latest',
      scanConfig: ScanConfig.signatureOnly(),
      signatureVerification: SignatureVerification.notation({
        trustedIdentities: [
          `arn:aws:signer:${this.region}:${this.account}:/signing-profiles/ecr-scan-verifier-integ`,
        ],
      }),
    });
  }
}

const app = new App();
new TestStack(app, 'integ-signature-only-notation');
```

---

### 12. `test/integ/signature/integ.cosign-kms-only.ts` — インテグレーションテスト（新規）

```typescript
import { App, Stack } from 'aws-cdk-lib';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

class TestStack extends Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const repository = Repository.fromRepositoryName(
      this,
      'Repository',
      'ecr-scan-verifier-integ-cosign-kms',
    );

    const kmsKeyArn = process.env.COSIGN_KMS_KEY_ARN;
    if (!kmsKeyArn) {
      throw new Error('COSIGN_KMS_KEY_ARN environment variable is required');
    }

    const key = Key.fromKeyArn(this, 'CosignKey', kmsKeyArn);

    // 署名検証のみ（スキャンなし）
    new EcrScanVerifier(this, 'SignatureOnlyVerifier', {
      repository,
      imageTag: 'latest',
      scanConfig: ScanConfig.signatureOnly(),
      signatureVerification: SignatureVerification.cosignKms({ key }),
    });
  }
}

const app = new App();
new TestStack(app, 'integ-signature-only-cosign-kms');
```

---

### 13. `test/integ/README.md` — 実行手順追加

```markdown
### Signature Verification Only (No Scanning)

署名検証のみを行い、スキャンをスキップするモードのテスト。

#### Notation (signatureOnly)

```bash
# 準備（integ.notation.ts と同じ）
# ...

# integ test 実行
pnpm integ:signature:update --language javascript --test-regex integ.notation-only.js
```

#### Cosign KMS (signatureOnly)

```bash
# 準備（integ.cosign-kms.ts と同じ）
# ...

# integ test 実行
COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" pnpm integ:signature:update \
  --language javascript --test-regex integ.cosign-kms-only.js
```

**注意**: `signatureOnly` モードでは脆弱性スキャンが実行されないため、Lambda 実行時間が短縮されます。
```

---

### 14. `docs/plans/signature-verification.md` — 既存計画ドキュメント更新

SBOM の API デザイン例を更新:

```typescript
// Enhanced scanning + SBOM（更新）
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({
      bucket: sbomBucket,
      encryptionKey: sbomKey,
    }),
  }),
});
```

---

## 変更ファイル一覧

| # | ファイル | 変更内容 |
|---|---------|---------|
| 1 | `src/scan-config.ts` | `EnhancedScanConfigOptions.sbomOutput` 追加、`signatureOnly()` メソッド追加、`ScanConfigBindOutput` に `sbomOutput` と `'SIGNATURE_ONLY'` 追加 |
| 2 | `src/ecr-scan-verifier.ts` | `EcrScanVerifierProps.sbomOutput` 削除、`scanConfigOutput.sbomOutput` 使用、バリデーション追加、IAM 権限条件分岐 |
| 3 | `src/custom-resource-props.ts` | 変更不要（`scanType: string` で既に対応済み） |
| 4 | `assets/lambda/lib/handler.ts` | `scanType === 'SIGNATURE_ONLY'` 時の早期リターン |
| 5 | `test/scan-config.test.ts` | `enhanced()` + `sbomOutput` テスト、`signatureOnly()` テスト追加 |
| 6 | `test/ecr-scan-verifier.test.ts` | `sbomOutput` を `scanConfig` 内に移動、`signatureOnly` テスト追加、Basic+SBOM テスト削除 |
| 7 | `assets/lambda/test/handler.test.ts` | `scanType=SIGNATURE_ONLY` テスト×2追加 |
| 8 | `README.md` | SBOM セクション更新（破壊的変更）、署名検証のみモード追加 |
| 9 | `test/integ/enhanced/integ.sbom-output.ts` | `sbomOutput` を `scanConfig.enhanced()` 内に移動 |
| 10 | `test/integ/signature/integ.notation-only.ts` | Notation 署名検証のみ integ テスト（新規） |
| 11 | `test/integ/signature/integ.cosign-kms-only.ts` | Cosign KMS 署名検証のみ integ テスト（新規） |
| 12 | `test/integ/README.md` | signatureOnly integ テスト実行手順追加 |
| 13 | `docs/plans/signature-verification.md` | SBOM API 例を更新 |

---

## メリット

1. **型安全性**: `sbomOutput` が Enhanced 専用であることが型レベルで保証される
2. **実行時バリデーション削減**: Basic + SBOM のエラーチェックが不要になる
3. **命名の一貫性**: `ScanConfig.signatureOnly()` ↔ `scanType: 'SIGNATURE_ONLY'`
4. **明確な意図表現**: 各スキャンモードの機能が API レベルで明確
5. **パフォーマンス**: `signatureOnly` でスキャンをスキップし Lambda 実行時間短縮
6. **IAM 最小権限**: スキャン不要な場合は `DescribeImageScanFindings`、`inspector2:*` 権限が不要
7. **設計の一貫性**: `SbomOutput` が Enhanced の責務として明確化

---

## 破壊的変更の影響範囲

### ユーザーコードの修正

**v1.x → v2.x 移行:**

```typescript
// Before
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced(),
  sbomOutput: SbomOutput.cycloneDx14({...}),
});

// After
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.enhanced({
    sbomOutput: SbomOutput.cycloneDx14({...}),
  }),
});
```

### 影響を受けるユーザー

- Enhanced scanning + SBOM 出力を使用しているユーザーのみ
- Basic scanning や署名検証のみのユーザーは影響なし

---

## 検証手順

1. **ユニットテスト**:
   ```bash
   cd assets/lambda && pnpm test
   pnpm test
   ```

2. **スナップショット更新**:
   ```bash
   npx jest --updateSnapshot
   ```

3. **ビルド**:
   ```bash
   pnpm build
   ```

4. **インテグレーションテスト** (Docker 起動状態で):
   ```bash
   # SBOM output
   pnpm integ:enhanced:update --language javascript --test-regex integ.sbom-output.js

   # Signature only - Notation
   pnpm integ:signature:update --language javascript --test-regex integ.notation-only.js

   # Signature only - Cosign KMS
   COSIGN_KMS_KEY_ARN="arn:aws:kms:..." pnpm integ:signature:update \
     --language javascript --test-regex integ.cosign-kms-only.js
   ```
