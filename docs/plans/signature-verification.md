# 署名検証機能の追加 - 実装計画

## Context

ecr-scan-verifier に署名検証機能を追加する。Notation (AWS Signer) と Cosign (Sigstore) の両方をサポートする。

署名の検証には CLI ツールが必要（ECR の `DescribeImageSigningStatus` はステータス確認であり暗号的検証ではない）。`AssetCode.fromAssetImage()` でコンテナイメージ Lambda として Notation CLI + Cosign バイナリをバンドルする。

## CDK API

```typescript
// Notation (AWS Signer / ECR Managed Signing)
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
  }),
});

// Cosign (公開鍵ファイルパス - Construct 内部で読み込み)
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignPublicKey({
    publicKeyPath: 'path/to/cosign.pub',
  }),
});

// Cosign (KMS - IKey を渡す、bind() で IAM 権限付与)
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignKms({
    key: myKmsKey, // IKey
  }),
});
```

## Lambda 処理フロー

```text
0. 署名検証 (新規、スキャンの前に実行)
   ├─ イメージ digest を取得
   ├─ ECR 認証トークン取得 → login
   │
   ├─ type=NOTATION の場合:
   │  ├─ trust policy を /tmp/ に生成
   │  ├─ trust store を /var/task/ → /tmp/ にコピー
   │  └─ notation verify <registry>/<repo>@<digest>
   │
   ├─ type=COSIGN の場合:
   │  ├─ publicKey → /tmp/cosign.pub に書き出し → cosign verify --key /tmp/cosign.pub
   │  └─ kmsKeyArn → cosign verify --key awskms:///<arn>
   │
   └─ 失敗時: failOnUnsigned=true → throw (デプロイ失敗)

1-4. 既存のスキャン検証フロー（変更なし）
```

---

## ファイル変更一覧

### 新規作成

#### 1. `src/signature-verification.ts`

```typescript
// --- Notation ---
export interface NotationVerificationOptions {
  readonly trustedIdentities: string[];  // Signing profile ARNs
  readonly failOnUnsigned?: boolean;     // default: true
}

// --- Cosign (公開鍵) ---
export interface CosignPublicKeyVerificationOptions {
  readonly publicKeyPath: string;      // 公開鍵ファイルパス (bind()時に読み込み)
  readonly failOnUnsigned?: boolean;   // default: true
}

// --- Cosign (KMS) ---
export interface CosignKmsVerificationOptions {
  readonly key: IKey;                  // AWS KMS key (IKey)
  readonly failOnUnsigned?: boolean;   // default: true
}

// --- 共通出力 ---
export interface SignatureVerificationBindOutput {
  readonly type: string;               // 'NOTATION' | 'COSIGN'
  readonly trustedIdentities?: string[];
  readonly publicKey?: string;
  readonly kmsKeyArn?: string;
  readonly failOnUnsigned: boolean;
}

// --- 抽象クラス ---
// bind(grantee) で IAM 権限を付与（ScanLogsOutput, SbomOutput と同じパターン）
export abstract class SignatureVerification {
  public static notation(options: NotationVerificationOptions): SignatureVerification;
  public static cosignPublicKey(options: CosignPublicKeyVerificationOptions): SignatureVerification;
  public static cosignKms(options: CosignKmsVerificationOptions): SignatureVerification;
  public abstract bind(grantee: IGrantable): SignatureVerificationBindOutput;
}

// private class NotationSignatureVerification { ... }
// private class CosignPublicKeySignatureVerification { bind() → readFileSync(publicKeyPath) }
// private class CosignKmsSignatureVerification { bind(grantee) → key.grant(grantee, ...) }
```

バリデーション:

- Notation: `trustedIdentities` が空 → エラー
- CosignPublicKey: `publicKeyPath` のファイルが読めない → エラー（bind() 時）
- CosignKms: `key` 必須（型レベルで保証）

#### 2. `assets/lambda/Dockerfile`

```dockerfile
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS builder

RUN dnf install -y cpio curl unzip && dnf clean all

# Notation CLI + AWS Signer plugin (rpm2cpio で展開、x86_64/ARM64 どちらでもビルド可能)
RUN curl -sLo /tmp/signer.rpm \
    "https://d2hvyiie56hcat.cloudfront.net/linux/arm64/installer/latest/aws-signer-notation-cli_arm64.rpm" \
    && cd / && rpm2cpio /tmp/signer.rpm | cpio -idm

# Cosign for ARM64 (Sigstore)
ARG COSIGN_VERSION=2.4.1
RUN curl -sLo /tmp/cosign \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64" \
    && chmod +x /tmp/cosign

FROM public.ecr.aws/lambda/nodejs:22-arm64

# Notation
COPY --from=builder /usr/bin/notation /var/task/bin/notation
COPY --from=builder /root/.config/notation/plugins /var/task/notation-config/plugins
COPY --from=builder /root/.config/notation/truststore /var/task/notation-config/truststore

# Cosign
COPY --from=builder /tmp/cosign /var/task/bin/cosign

# Lambda handler
COPY dist/index.js ${LAMBDA_TASK_ROOT}/index.js

CMD ["index.handler"]
```

注: コンテナイメージ Lambda として動作する。`public.ecr.aws/lambda/nodejs:22-arm64` ベースイメージを使用。
`rpm2cpio | cpio` により rpm パッケージ内のファイルを展開するため、ホストの
アーキテクチャ (x86_64/ARM64) に関係なく ARM64 用バイナリを取得できる。

#### 3. `assets/lambda/.dockerignore`

```text
node_modules
test
lib
src
*.ts
tsconfig.json
pnpm-lock.yaml
```

#### 4. `assets/lambda/lib/signature-verification.ts`

Lambda 側の署名検証ロジック:

```typescript
export async function verifySignature(
  repositoryName: string,
  imageTag: string,
  config: SignatureVerificationConfig,
): Promise<SignatureVerificationResult>
```

共通処理:

- `getImageDigest()`: imageTag → digest 解決
- `getEcrAuthInfo()`: `GetAuthorizationToken` で認証情報取得
- `execFileSync` でシェルインジェクション防止、パスワードは stdin

Notation 固有:

- `setupNotationConfig()`: trust policy + trust store を /tmp/ にセットアップ
- `notation login` → `notation verify`
- 環境変数: `NOTATION_CONFIG`, `NOTATION_LIBEXEC`

Cosign 固有:

- publicKey（bind()でファイルから読み込み済み）→ `/tmp/cosign.pub` に書き出し → `cosign verify --key /tmp/cosign.pub`
- kmsKeyArn → `cosign verify --key awskms:///<arn>`
- `cosign login` で ECR 認証

#### 5. `test/signature-verification.test.ts`

CDK Construct テスト:

- Notation: スナップショット、props検証、IAMパーミッション、trustedIdentities空配列エラー
- CosignPublicKey: スナップショット、props検証、IAMパーミッション、ファイル読み込み
- CosignKms: スナップショット、KMS パーミッション検証（IKey 経由）
- failOnUnsigned デフォルト値テスト
- signatureVerification 未設定時は props に含まれないこと

#### 6. `assets/lambda/test/signature-verification.test.ts`

Lambda テスト (child_process + ECR client mock):

- Notation: 検証成功/失敗、login失敗
- Cosign (publicKey): 検証成功/失敗
- Cosign (kmsKeyArn): 検証成功/失敗
- failOnUnsigned true/false 動作
- digest 直接使用 (sha256:...)

### 修正

#### 7. `src/custom-resource-props.ts`

```typescript
export interface SignatureVerificationConfig {
  readonly type: string;               // 'NOTATION' | 'COSIGN'
  readonly trustedIdentities?: string[];
  readonly publicKey?: string;         // bind()時にファイルから読み込み済みの内容
  readonly kmsKeyArn?: string;
  readonly failOnUnsigned: string;     // 'true'/'false'
}
```

`ScannerCustomResourceProps` に `signatureVerification?: SignatureVerificationConfig` 追加

#### 8. `src/ecr-scan-verifier.ts`

- `EcrScanVerifierProps` に `signatureVerification?: SignatureVerification` 追加
- **`Code.fromAsset()` → `AssetCode.fromAssetImage()` に変更（コンテナイメージ Lambda）**:

  ```typescript
  runtime: Runtime.FROM_IMAGE,
  handler: Handler.FROM_IMAGE,
  code: AssetCode.fromAssetImage(join(__dirname, '../assets/lambda'), {
    platform: Platform.LINUX_ARM64,
    ignoreMode: IgnoreMode.DOCKER,
  }),
  ```

- signatureVerification.bind() → Custom Resource props に渡す
- IAM パーミッション（signatureVerification 有効時のみ）:

  共通:

  ```text
  ecr:GetAuthorizationToken    (*)
  ecr:BatchGetImage            (repository ARN)
  ecr:GetDownloadUrlForLayer   (repository ARN)
  ```

  Notation 追加:

  ```text
  signer:GetRevocationStatus   (*)
  ```

  Cosign + KMS 追加（bind() 内で `key.grant()` により付与）:

  ```text
  kms:GetPublicKey             (key.keyArn)
  kms:Verify                   (key.keyArn)
  ```

#### 9. `src/index.ts`

`export * from './signature-verification'` 追加

#### 10. `assets/lambda/lib/handler.ts`

- import `verifySignature`
- スキャン実行の前に署名検証呼び出し
- 失敗時: SNS 通知 + ロールバック抑制（既存パターン踏襲）

#### 11. `assets/lambda/test/handler.test.ts`

- `jest.mock('../lib/signature-verification')` 追加
- 署名検証あり/なしのテストケース
- 実行順序テスト（署名検証 → スキャン検証）

#### 12. スナップショット更新

`AssetCode.fromAssetImage` + `Runtime.FROM_IMAGE` 変更により全スナップショット更新

#### 13. `test/integ/signature/integ.notation.ts`

Notation (AWS Signer) の integ テスト:

- 事前準備: AWS Signer signing profile 作成 + ECR Managed Signing 有効化
- CDK context で signing profile ARN を渡す
- `DockerImageAsset` でイメージ push → 自動署名 → 検証

#### 14. `test/integ/signature/integ.cosign-kms.ts`

Cosign (KMS) の integ テスト:

- 事前準備: KMS key 作成 + cosign CLI で事前署名
- CDK context で KMS key ARN を渡す
- `Key.fromKeyArn()` で既存キー参照

#### 15. `.projenrc.ts` / `package.json`

`integ:signature` / `integ:signature:update` スクリプト追加

#### 16. `test/integ/README.md`

署名検証 integ テストの事前準備・実行手順を追記

#### 17. `README.md`

署名検証機能の紹介セクションを追加:
- Notation (AWS Signer) と Cosign (Sigstore) 対応
- 使用例コードスニペット
- Docker 必須の注意事項

---

## 検証手順

1. `cd assets/lambda && pnpm install && pnpm build` — Lambda ビルド
2. `npx jest --updateSnapshot` — テスト + スナップショット更新
3. `pnpm build` — 全体ビルド（jsii + eslint + jest + integ）
4. Docker 起動状態で `cdk deploy` — Docker ビルド動作確認
5. `pnpm integ:signature:update` — integ テスト（事前準備必要）
