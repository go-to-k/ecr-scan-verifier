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

// Cosign (公開鍵文字列 - PEM コンテンツを直接渡す)
new EcrScanVerifier(this, 'Verifier', {
  repository,
  scanConfig: ScanConfig.basic(),
  signatureVerification: SignatureVerification.cosignPublicKey({
    publicKey: readFileSync('path/to/cosign.pub', 'utf-8'),
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
   │  ├─ trust store を /var/task/ → /tmp/ にコピー
   │  ├─ trust policy を /tmp/ に生成
   │  ├─ HOME=/tmp (Lambda コンテナは HOME 未定義)
   │  ├─ NOTATION_CONFIG=/tmp/notation-config (trust policy + trust store)
   │  ├─ NOTATION_LIBEXEC=/var/task/notation-config (plugins はここから直接参照)
   │  └─ notation verify <registry>/<repo>@<digest>
   │
   ├─ type=COSIGN の場合:
   │  ├─ DOCKER_CONFIG=/tmp/.docker
   │  ├─ publicKey → /tmp/cosign.pub に書き出し → cosign verify --key /tmp/cosign.pub
   │  └─ kmsKeyArn → cosign verify --key awskms:///<arn>
   │
   └─ 失敗時: failOnUnsigned=true → throw (デプロイ失敗)

1-4. 既存のスキャン検証フロー（変更なし）
```

---

## ファイル変更一覧

### 新規作成

#### 1. `src/signature-verification.ts` ✅

```typescript
// bind(grantee) で IAM 権限を付与（ScanLogsOutput, SbomOutput と同じパターン）
export abstract class SignatureVerification {
  public static notation(options: NotationVerificationOptions): SignatureVerification;
  public static cosignPublicKey(options: CosignPublicKeyVerificationOptions): SignatureVerification;
  public static cosignKms(options: CosignKmsVerificationOptions): SignatureVerification;
  public abstract bind(grantee: IGrantable): SignatureVerificationBindOutput;
}
```

バリデーション:

- Notation: `trustedIdentities` が空 → エラー
- CosignPublicKey: `publicKey` 必須（型レベルで保証）
- CosignKms: `key` 必須（型レベルで保証）

#### 2. `assets/lambda/Dockerfile` ✅

コンテナイメージ Lambda (Notation CLI + Cosign バイナリ同梱)

**RPM のファイル配置 (実測):**

- `/usr/local/bin/notation` — notation バイナリ
- `/opt/.../notation_libexec/notation-com.amazonaws.signer.notation.plugin` — プラグインバイナリ (flat)
- `/opt/.../notation_config/aws-signer-notation-root.crt` — ルート CA 証明書 (flat)
- `/opt/.../notation_config/aws-us-gov-signer-notation-root.crt` — GovCloud ルート CA

**Dockerfile で notation の期待するディレクトリ構造に変換:**

- プラグイン: `plugins/<plugin-name>/<binary>` 構造に配置
- trust store: `truststore/signingAuthority/aws-signer-ts/<certs>` 構造に配置
- `chmod -R 755` でパーミッション修正 (RPM は 700/600 で Lambda 非 root ユーザーが読めない)

#### 3. `assets/lambda/.dockerignore` ✅

#### 4. `assets/lambda/lib/signature-verification.ts` ✅

Lambda 側の署名検証ロジック。

**デバッグで発見・修正した問題:**

1. **EACCES エラー**: `cpSync` で plugins を `/tmp` にコピーする際 Permission denied
   - 原因: RPM が 700/600 パーミッションでインストール + Lambda は非 root ユーザーで実行
   - 修正: Dockerfile で `chmod -R 755` + plugins の `/tmp` コピー削除 (`NOTATION_LIBEXEC` で直接参照)

2. **`$HOME is not defined` エラー**: notation login が Docker credential store 初期化に `$HOME` を参照
   - 原因: Lambda コンテナイメージは `HOME` 環境変数が未定義
   - 修正: Notation env に `HOME: '/tmp'` を追加

3. **credential store required エラー**: `notation login` が credential helper を要求
   - 原因: Lambda コンテナに Docker credential helper がインストールされていない
   - 修正: `notation login` / `cosign login` を廃止し、Docker `config.json` にクレデンシャルを直接書き込む方式に変更 (`writeDockerConfig()`)

4. **ディレクトリ構造の不一致**: RPM は flat にインストールするが notation は nested 構造を期待
   - プラグイン: `plugins/com.amazonaws.signer.notation.plugin/notation-com.amazonaws.signer.notation.plugin`
   - trust store: `truststore/signingAuthority/aws-signer-ts/<certs>`
   - 修正: Dockerfile の COPY で正しい構造に配置

#### 5. `test/signature-verification.test.ts` ✅

CDK Construct テスト

#### 6. `assets/lambda/test/signature-verification.test.ts` ✅

Lambda テスト (child_process + ECR client mock)

### 修正

#### 7. `src/custom-resource-props.ts` ✅

`SignatureVerificationConfig` インターフェース追加

#### 8. `src/ecr-scan-verifier.ts` ✅

- `Code.fromAsset()` → `AssetCode.fromAssetImage()` に変更 (コンテナイメージ Lambda)
- `signatureVerification` プロパティ追加
- IAM パーミッション追加

  共通: `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`
  Notation: `signer:GetRevocationStatus`
  CosignKms: `key.grant()` で `kms:GetPublicKey`, `kms:Verify`

#### 9. `src/index.ts` ✅

export 追加

#### 10. `assets/lambda/lib/handler.ts` ✅

スキャン前に署名検証実行。失敗時: SNS 通知 + ロールバック抑制（既存パターン踏襲）

#### 11. `assets/lambda/test/handler.test.ts` ✅

署名検証 mock + テストケース追加

#### 12. スナップショット更新 ✅

Docker イメージハッシュ変更により全スナップショット更新

#### 13-14. integ テスト ✅

- `test/integ/signature/integ.notation.ts` — Notation (AWS Signer)
- `test/integ/signature/integ.cosign-kms.ts` — Cosign (KMS)

#### 15. `.projenrc.ts` / `package.json` ✅

`integ:signature` / `integ:signature:update` スクリプト追加

#### 16. `test/integ/README.md` ✅

署名検証 integ テストの事前準備・実行手順

#### 17. `README.md` ✅

署名検証機能の紹介セクション

---

## インテグレーションテスト

### Notation (`test/integ/signature/integ.notation.ts`)

```bash
# 環境変数で signing profile ARN を渡す
SIGNER_PROFILE_ARN="${PROFILE_ARN}" pnpm integ:signature:update \
  --language javascript --test-regex integ.notation.js
```

前提: ECR Managed Signing を有効化 (`aws ecr put-signing-configuration`)

### Cosign KMS (`test/integ/signature/integ.cosign-kms.ts`)

```bash
# cdk synth + cdk-assets でイメージ push → cosign sign → integ test
COSIGN_KMS_KEY_ARN="${KMS_KEY_ARN}" pnpm integ:signature:update \
  --language javascript --test-regex integ.cosign-kms.js
```

### 共通注意事項

- Basic / Enhanced scanning どちらでも動作する
- integ-runner は `-c` (CDK context) を渡せないため環境変数を使用
- `--test-regex` は `.js` サフィックスを付けて `.ts` / `.d.ts` を除外

---

## 検証手順

1. `cd assets/lambda && pnpm install && pnpm build` — Lambda ビルド
2. `npx jest --updateSnapshot` — テスト + スナップショット更新
3. `pnpm build` — 全体ビルド（jsii + eslint + jest + integ）
4. Docker 起動状態で integ test — 実際の署名検証動作確認
