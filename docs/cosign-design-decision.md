# Cosign Rekor検証をスキップする設計決定

## 概要

このライブラリのCosign実装は、常にRekor透明性ログ検証をスキップし、KMSキーまたは公開鍵を使用した暗号署名検証のみを実行します。このドキュメントでは、この設計決定の理由と背景を説明します。

## 設計決定

### 実装方針

**常に`--insecure-ignore-tlog`を使用してRekor検証をスキップ**

- ユーザーにはRekor検証を有効/無効にする選択肢は提供しない
- Lambda関数は常に`cosign verify --insecure-ignore-tlog`を実行
- 暗号署名検証は引き続き実行される（セキュリティは維持）

### 理由

#### 1. AWS Lambda環境での信頼性の問題

**TUFメタデータ同期の問題:**

Rekor検証には、ローカル署名環境とLambda検証環境間でTUF (The Update Framework) メタデータを同期する必要があります。

```
[ローカル環境]
cosign initialize  # TUFメタデータ バージョンAを取得
cosign sign ...    # バージョンAの公開鍵で署名

[Lambda環境 - 数分後]
cosign verify ...  # TUFメタデータ バージョンBを取得しようとする
                   # バージョンが異なると検証失敗
```

**失敗の例:**

```
Error: verifying transparency log entry: unable to verify signature on artifact:
transparency log certificate does not match
```

**根本原因:**

- TUFメタデータ（Rekor公開鍵）は時間とともに変更される
- Lambda環境に静的なTUFメタデータをバンドルする方法がない
- 動的に取得されるメタデータのバージョンを保証できない
- 結果として、`ignoreTlog: false`（Rekor検証有効）はAWS Lambdaで信頼性が低い

#### 2. ユーザーエクスペリエンスの向上

**複雑さの削減:**

- ユーザーは`ignoreTlog`オプションの意味を理解する必要がない
- 署名時にRekor設定を考慮する必要がない
- 「どちらを選べばいいか分からない」という混乱を回避

**一貫した動作:**

- 常に同じ動作（Rekorスキップ）
- 断続的な失敗なし
- トラブルシューティングが容易

#### 3. パフォーマンスと環境適応性

**利点:**

- ✅ より高速な検証（Rekorへのネットワーク呼び出しなし）
- ✅ VPCやエアギャップ環境で動作
- ✅ インターネットアクセス不要
- ✅ プライベートコンテナイメージに適している

#### 4. セキュリティは維持される

**重要なポイント:**

暗号署名検証は引き続き実行されます。

```bash
# 署名時
cosign sign --tlog-upload=false --key "awskms:///${KMS_KEY_ARN}" IMAGE

# 検証時（Lambda内）
cosign verify --insecure-ignore-tlog --key "awskms:///${KMS_KEY_ARN}" IMAGE
```

**検証される内容:**

- ✅ イメージが指定されたKMSキーで署名されている
- ✅ 署名が有効で改ざんされていない
- ✅ イメージコンテンツが署名後に変更されていない

**検証されない内容:**

- ❌ 署名が特定の時刻に作成されたこと（タイムスタンプなし）
- ❌ Rekor透明性ログへの記録（公開監査証跡なし）

## トレードオフ

### 失うもの

**透明性と監査可能性:**

- 署名が公開Rekor透明性ログに記録されない
- 署名作成のタイムスタンプ証明がない
- 外部監査者による検証が困難

### 得るもの

**信頼性とシンプルさ:**

- 常に動作する（TUF同期の問題なし）
- より高速な検証
- シンプルなAPI（オプション不要）
- VPC/エアギャップ環境のサポート

## 業界の視点

Sigstoreコミュニティの議論（GitHub Issue #2808）より:

> "以前に透明性ログに依存していなかった組織にとって、この慣行は必ずしも'insecure'とは見なされないが、透明性ログに裏付けられたチェックはセキュリティを向上させる。"

**`--insecure-ignore-tlog`の適切なユースケース:**

- プライベートリポジトリとイメージ
- カスタム/プライベートPKIインフラストラクチャ
- エアギャップまたは制限されたネットワーク環境
- Rekorの公開透明性が望ましくない場合

**このライブラリは上記のユースケースに該当します** - ほとんどのユーザーはプライベートECRイメージを使用しており、公開透明性ログへの記録を必要としません。

## Rekor検証が必要な場合

Rekor透明性ログ検証がコンプライアンス要件の場合、**Notation with AWS Signerの使用を推奨します**。

```typescript
signatureVerification: SignatureVerification.notation({
  trustedIdentities: [
    'arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'
  ],
})
```

**Notationの利点:**

- ✅ AWS Signerとのネイティブ統合
- ✅ TUF同期の問題なし
- ✅ タイムスタンプと失効チェックのサポート
- ✅ エンタープライズ向けに設計

## 使用方法

### 署名

```bash
# Rekorアップロードなしで署名
cosign sign --tlog-upload=false --key "awskms:///${KMS_KEY_ARN}" IMAGE
```

### 検証（CDK）

```typescript
import { SignatureVerification } from 'ecr-scan-verifier';

// Cosign with KMS
signatureVerification: SignatureVerification.cosignKms({
  key: kmsKey,
  // Rekor検証は常にスキップされます（オプションなし）
})

// Cosign with public key
signatureVerification: SignatureVerification.cosignPublicKey({
  publicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  // Rekor検証は常にスキップされます（オプションなし）
})
```

## 参考文献

- [Sigstoreドキュメント: Cosignキー管理](https://docs.sigstore.dev/cosign/key_management/overview/)
- [GitHub Issue #2808: 新しいtlogとsct insecure CLIオプション - 本当にinsecureなのか？](https://github.com/sigstore/cosign/issues/2808)
- [統合テストREADME](../test/integ/README.md)
