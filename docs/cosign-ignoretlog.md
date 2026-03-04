# Cosign `ignoreTlog` オプション - 設計と現状の問題

## 概要

`ignoreTlog`オプションは、CosignがRekor透明性ログに対してイメージ署名を検証するかどうかを制御します。このドキュメントでは、設計上の決定、現在の実装、および既知の問題について説明します。

## 設計目標

### 主な目標

ユーザーに以下の選択肢の柔軟性を提供する：

1. **完全な透明性ログ検証** (`ignoreTlog: false`) - 監査可能性を備えた最大限のセキュリティ
2. **署名のみの検証** (`ignoreTlog: true`) - より高速で、オフライン/エアギャップ環境で動作

### API設計の決定

**デフォルト: `ignoreTlog: false` (Rekor検証有効)**

根拠：

- Sigstoreが推奨するセキュリティベストプラクティスに従う
- 署名が特定の時刻に作成されたことのタイムスタンプ付き証明を提供
- 本番環境デプロイメントに監査可能性と透明性を提供
- Cosign 2.0+のデフォルトに合わせる

## 実装

### CDK API ([src/signature-verification.ts](../src/signature-verification.ts))

```typescript
export interface CosignKmsVerificationOptions {
  readonly key: IKey;
  readonly failOnUnsigned?: boolean;

  /**
   * Whether to skip Rekor transparency log verification.
   * @default false - Rekor verification is enabled by default for better security
   */
  readonly ignoreTlog?: boolean;
}

// Usage
signatureVerification: SignatureVerification.cosignKms({
  key: kmsKey,
  // ignoreTlog: false (default) - Full Rekor verification
  // ignoreTlog: true          - Signature-only verification
})
```

### Lambda実装 ([assets/lambda/lib/signature-verification.ts](../assets/lambda/lib/signature-verification.ts))

```typescript
const cosignVerify = (imageRef: string, keyArgs: string[], cosignBin: string,
                     env: Record<string, string>, ignoreTlog: boolean): void => {
  if (ignoreTlog) {
    // Skip Rekor transparency log verification
    execFileSync(cosignBin, ['verify', '--insecure-ignore-tlog', ...keyArgs, imageRef], {
      env: { ...process.env, ...env },
      encoding: 'utf8',
      timeout: 120_000,
    });
    return;
  }

  // Verify with Rekor transparency log
  execFileSync(cosignBin, ['verify', ...keyArgs, imageRef], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 120_000,
  });
};
```

## 署名と検証のワークフロー

### モード1: `ignoreTlog: false` (デフォルト)

**ローカルでの署名:**

```bash
# 1. Initialize TUF metadata (downloads Rekor v2 public keys)
cosign initialize

# 2. Sign WITH Rekor transparency log upload
cosign sign --key "awskms:///${KMS_KEY_ARN}" "${IMAGE}"
```

**Lambdaでの検証:**

```bash
# 以下の両方を検証:
# 1. KMSキーを使用した暗号署名
# 2. Rekor透明性ログエントリ
cosign verify --key "awskms:///${KMS_KEY_ARN}" "${IMAGE}"
```

**要件:**

- ローカル: 署名前に`cosign initialize`を実行する必要がある
- ローカル: Rekorサービスへのインターネットアクセス
- Lambda: `rekor.sigstore.dev`へのインターネットアクセス
- Cosignバージョン: 3.0.1以上（Rekor v2サポート用）

### モード2: `ignoreTlog: true`

**ローカルでの署名:**

```bash
# Sign WITHOUT Rekor transparency log upload
cosign sign --tlog-upload=false --key "awskms:///${KMS_KEY_ARN}" "${IMAGE}"
```

**Lambdaでの検証:**

```bash
# 暗号署名のみを検証
cosign verify --insecure-ignore-tlog --key "awskms:///${KMS_KEY_ARN}" "${IMAGE}"
```

**要件:**

- Rekorアクセス不要
- エアギャップ環境で動作
- より高速な検証（Rekorへのネットワーク呼び出しなし）

## 現在の問題

### 問題1: TUFメタデータの同期（クリティカル）

**問題:**
`ignoreTlog: false`（デフォルト）の場合、ローカル署名環境とLambda実行環境間のTUFメタデータバージョンの不一致により検証が失敗する可能性があります。

**技術的詳細:**

- ローカル署名環境: `cosign initialize`を実行 → TUFメタデータバージョンAを取得
- Lambda環境: `cosign verify`を実行 → TUFメタデータバージョンBの取得を試みる
- バージョンが異なる場合（Rekor v2証明書の変更）、以下のエラーで検証が失敗:

  ```
  transparency log certificate does not match
  ```

**根本原因:**

- TUFメタデータ（Rekor公開鍵）は時間とともに変化する
- 静的なTUFメタデータをバンドルする方法がない（動的に取得されることを前提としている）
- Lambda内の`cosign initialize`は、ローカル署名時と同じメタデータバージョンを保証しない

**影響:**

- `ignoreTlog: false`（デフォルト）はAWS Lambda環境で信頼性が低い
- ユーザーは断続的な検証失敗を経験する可能性がある
- デフォルトの動作が意図したとおりに機能しない

**回避策:**

1. `ignoreTlog: true`を設定してRekor検証をスキップ（監査可能性を失う）
2. 署名と検証を短い時間枠内で実行する（実用的ではない）
3. 断続的な失敗を受け入れて再試行する

### 問題2: 統合テストの制限

**問題:**
問題1により、統合テストで`ignoreTlog: false`を信頼性を持ってテストできません。

**現状:**

- 統合テスト（[test/integ/signature/integ.cosign-kms.ts](../test/integ/signature/integ.cosign-kms.ts)）はデフォルトとして`ignoreTlog: false`を使用
- TUFメタデータ同期の問題により、テストが断続的に失敗する可能性がある
- デフォルトの動作を信頼性を持ってテストする実用的な方法がない

**影響:**

- デフォルトの動作が正しく機能することを検証できない
- テスト失敗は誤検出の可能性がある
- ドキュメントに従うユーザーは、テストできない問題に遭遇する可能性がある

### 問題3: ドキュメントと現実のギャップ

**問題:**
ドキュメントでは`ignoreTlog: false`がデフォルトで推奨されているが、信頼性が低い。

**現状:**

- APIドキュメント: "本番環境とセキュリティクリティカルなデプロイメントに最適"
- 現実: Lambda環境で断続的に失敗する可能性がある
- ユーザーの期待: デフォルトは「そのまま動作する」べき

**影響:**

- ユーザーエクスペリエンスが低下
- ユーザーは制限を理解するためにトラブルシューティングドキュメントを読む必要がある
- 「デフォルトでセキュア」の原則に矛盾

## トレードオフ分析

| 側面 | `ignoreTlog: false` (デフォルト) | `ignoreTlog: true` |
|--------|------------------------------|-------------------|
| **セキュリティ** | より高い（透明性+監査可能性） | より低い（透明性ログなし） |
| **信頼性** | ❌ 信頼性が低い（TUF同期の問題） | ✅ 信頼性が高い |
| **パフォーマンス** | 遅い（ネットワーク呼び出し） | 速い（ネットワークなし） |
| **ネットワーク** | インターネットアクセス必要 | オフラインで動作 |
| **ユースケース** | 公開、監査可能なデプロイメント | プライベート、エアギャップ環境 |
| **Cosignの推奨** | ✅ Sigstoreが推奨 | ⚠️ "insecure"（議論の余地あり） |

## 業界の視点

Sigstoreコミュニティの議論（GitHub Issue #2808）より:

> "以前に透明性ログに依存していなかった組織にとって、この慣行は必ずしも'insecure'とは見なされないが、透明性ログに裏付けられたチェックはセキュリティを向上させる。"

**本番環境での使用ガイダンス:**
> "本番環境では、プライバシー/コントロールと透明性/監査可能性のトレードオフがセキュリティ要件に合致するかを検討してください。"

**`ignoreTlog: true`の適切なユースケース:**

- プライベートリポジトリとイメージ
- カスタム/プライベートPKIインフラストラクチャ
- エアギャップまたは制限されたネットワーク環境
- 開発およびテスト環境
- Rekorの公開透明性が望ましくない場合

## 推奨事項

### ライブラリメンテナー向け（現状）

1. **`ignoreTlog: false`をデフォルトとして維持** - セキュリティベストプラクティスに従う
2. **制限を明確に文書化** - ユーザーはTUF同期の問題を理解する必要がある
3. **明確なガイダンスを提供** - 各モードをいつ使用すべきか
4. **統合テスト** - 実用的な検証のために`ignoreTlog: true`のテストを検討

### ユーザー向け

**`ignoreTlog: false`（デフォルト）を使用する場合:**

- 最大限の透明性と監査可能性が必要
- LambdaがRekorへの信頼できるインターネットアクセスを持つ
- 時折の検証失敗を許容できる
- 再試行ロジックを実装する意思がある

**`ignoreTlog: true`を使用する場合:**

- 透明性よりも信頼性を優先
- LambdaがRekorアクセスなしのVPC内にある
- プライベート/内部イメージを使用している
- より高速な検証が必要

## 今後の改善

### TUF同期問題の潜在的な解決策

1. **Lambda layerにTUFメタデータをバンドル**
   - 課題: TUFメタデータは頻繁に変更される
   - リスク: 古いメタデータが検証失敗を引き起こす

2. **TUFメタデータキャッシングの実装**
   - 課題: Lambdaの読み取り専用ファイルシステム（/tmp以外）
   - リスク: キャッシュ無効化の複雑さ

3. **指数バックオフによる再試行ロジックの追加**
   - 断続的な失敗を軽減
   - 根本原因は解決しない

4. **`ignoreTlog: true`をデフォルトにし、透明性への明確なオプトインを提供**
   - 論争的: セキュリティベストプラクティスに矛盾
   - 利点: デフォルトの動作が信頼できる

5. **「ベータ」または「実験的」としてドキュメント化**
   - 制限について正直
   - 期待値をガイド

## 参考文献

- [Sigstoreドキュメント: Cosign署名](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [GitHub Issue #2808: 新しいtlogとsct insecure CLIオプション - 本当にinsecureなのか？](https://github.com/sigstore/cosign/issues/2808)
- [Cosign 2.0リリースノート](https://blog.sigstore.dev/cosign-2-0-released/)
- [統合テストREADME](../test/integ/README.md)
- [トラブルシューティングガイド](../test/integ/README.md#troubleshooting)
