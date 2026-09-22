# iff-x402-transparency

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[IFF Monitor](https://ifandonlyif.io/ja/monitor) · [SDK ガイド](https://ifandonlyif.io/ja/sdk) · [API ドキュメント](https://ifandonlyif.io/ja/docs)

IFF の x402 requirement transparency log と Service Receipt v1 において、信頼に関わる公開検証部分です。Protocol specification、JSON Schema、既知の正解を持つテストベクトル、offline verifier、TypeScript と Go の client を提供します。

目的は明確で、検証可能です。公開されていない server logic に依存せず、第三者が公開ログの出力と署名済みサービスレシートを検証できるようにします。

## 用途別の入口

| 目的 | 使用するもの |
|---|---|
| 自分の支払いポリシーを適用する前に x402 payment requirement を比較する | 公開済み TypeScript または Go preflight SDK |
| ログ署名、包含証明、追記のみであることの整合性を独立して確認する | Python reference verifier と保存した checkpoint |
| 署名済み Service Receipt や保存済み API response を検証する | この checkout の Go receipt CLI または browser verifier core |
| Wire protocol を審査・実装する | 仕様、schema、言語間共通のテストベクトル |

公開済み preflight SDK のインストール：

```bash
npm install @ifandonlyif/x402-preflight@0.2.0
go get github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0
```

JavaScript/TypeScript project では npm コマンドを、初期化済み Go module では Go コマンドを使用してください。[TypeScript ガイド](ts/README.md)、[npm package](https://www.npmjs.com/package/@ifandonlyif/x402-preflight/v/0.2.0)、[Go API reference](https://pkg.go.dev/github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0)を参照できます。リリースタグは `ts/v0.2.0` と `go/v0.2.0` です。

Go `v0.2.0` タグには fingerprint/preflight の機能が含まれます。Service Receipt package と CLI は、その後 `main` に追加されたソースです。Receipt 検証には以下の checkout 用コマンドを使用し、旧タグにこれらのツールが含まれるとは想定しないでください。

Preflight は payment requirement と IFF の観測を比較し、支払いは実行しません。呼び出し側が自分の支払いポリシーを保持します。結果は `consistent`、`diverged`、`unobserved`、`stale` のいずれかです。

## 含まれるもの

- [`spec/x402-requirement-transparency-v1.md`](spec/x402-requirement-transparency-v1.md)：requirement fingerprint、signed tree head、Merkle 包含・整合性証明、公開フィールド、判定語彙を定義します。
- [`spec/service-receipt-v1.md`](spec/service-receipt-v1.md)：canonical Service Receipt v1 の envelope、payload、domain、信頼モデル、有効期限の意味、証拠参照、API adapter の動作を定義します。
- [`schemas/`](schemas/)：receipt envelope と receipt-key directory の JSON Schema です。
- [`spec/testdata/`](spec/testdata/)：fingerprint、Merkle proof、完全な receipt 検証について、言語間で共有する既知の正解と拒否ケースを含みます。
- [`spec/verify_example.py`](spec/verify_example.py)：Python 標準ライブラリのみで動く verifier です。本番 log key の fingerprint を固定し、全 leaf と完全な Merkle root を再計算し、包含証明を検証します。Checkpoint を保存して追記のみの整合性を確認することもできます。
- [`ts/`](ts/)：`@ifandonlyif/x402-preflight` です。
- [`go/`](go/)：IFF の非公開 production monitor が import する canonical Go fingerprint/preflight module です。標準ライブラリのみの [`receipt`](go/receipt/) package と、オフラインの [`iff-receipt-verify`](go/cmd/iff-receipt-verify/) コマンドも含みます。
- [`browser/service-receipt.mjs`](browser/service-receipt.mjs)：DOM に依存しない Web Crypto receipt verifier core です。Node での適合性テストを備えます。

## 独立して検証する

オフラインの適合性チェック：

```bash
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

本番を検証し、次回の整合性確認用に checkpoint を保存：

```bash
python3 spec/verify_example.py --checkpoint ~/.iff-production-sth.json
```

Verifier はレビュー済みソースで、次の本番 trust anchor を固定しています。

- log ID：`e33f4a64fe0ef33fca5cbfddce858667`
- Raw Ed25519 公開鍵の SHA-256：`e33f4a64fe0ef33fca5cbfddce858667ee56be6347c6cf7ffcda9d1bceaffe5b`

API 自身の `/log/keys` response は metadata であり、独立した trust anchor ではありません。鍵の rotation には、過去の checkpoint 用の旧鍵を保持し、信頼できる経路で後継鍵を追加する、レビュー済みリリースが必要です。

### Service Receipt を検証する

言語間共通の既知の正解テストを実行：

```bash
(cd go && go test ./receipt ./cmd/iff-receipt-verify)
node --test browser/service-receipt.test.mjs
```

単独の receipt envelope または完全な API response を `response.json` として保存し、検証：

```bash
(cd go && go run ./cmd/iff-receipt-verify -file ../response.json)
```

Canonical encoding、hash、Ed25519 署名、時間状態を確認します。完全な response を渡した場合は、署名済み subject との結び付きも確認します。埋め込み鍵を誰が管理しているかは証明しません。Issuer の身元を確認するには、完全一致の expected issuer と、独立して信頼した完全な `sha256:` key ID を一つ以上指定してください。信頼条件の不一致でコマンドを失敗させるには `-require-trust` を使用します。

完全一致の expected HTTPS issuer から取得した receipt key directory は、出所の metadata として役立ちます。ただし独立して固定された trust anchor ではありません。

2026-09-01 に初公開された、バージョン管理された本番 pin は [`keys/service-receipt-production-2026-09-01.json`](keys/service-receipt-production-2026-09-01.json) に保存されています。

- issuer：`https://ifandonlyif.io`
- 完全な key ID：`sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb`

Issuer と完全な key ID を組み合わせて使用してください。日付付きファイルは、この保護された repository を通じて配布するバージョン付きリリース snapshot です。Live key directory は変更可能な発見用 metadata のままです。Rotation では新しい snapshot を追加し、過去の receipt が元の pin を維持できるよう旧 snapshot を残します。

`current` は、その日付の snapshot 公開時点で current だったという意味です。旧 snapshot は過去の検証に使えますが、新規 receipt を無期限に自動承認してはなりません。後継を先に公開し、receipt の有効期間と directory cache の有効期間を合計した期間だけ旧鍵を併用し、その後のバージョン付き snapshot で旧鍵を historical/inactive にします。

## 公開証拠が示すことと、その限界

| 主張 | 公開証拠 | 限界 |
|---|---|---|
| Requirement fingerprint が v1 に従う | 仕様、vectors、本番で使う canonical Go 実装 | ソース公開だけでは server 上で動く binary を特定できません |
| STH が IFF の固定 log key から来た | Canonical bytes、署名、固定 key fingerprint | Rotation には別途信頼した更新が必要です |
| 観測が snapshot に含まれる | 再計算した root と RFC 6962 包含証明 | 包含は観測の事実上の正しさを証明しません |
| 履歴が追記のみで進んだ | 保存した STH と整合性証明 | 一人の観測者では全 split view を排除できません。独立 witness が改善に役立ちます |
| Service Receipt payload を特定の Ed25519 鍵が署名した | Canonical payload bytes、domain-separated digest、署名、完全な key ID | 埋め込み公開鍵は署名の自己整合性のみを示します。身元には独立して信頼した issuer/key policy が必要です |
| API response が receipt の署名済み subject と一致する | Decode した署名済み subject と domain-separated hash | Evidence と compute-proof descriptor は参照であり、個別検証までは明示的に未検証です |
| SDK package がこのソースから作られた | 公開 CI と npm OIDC provenance | Provenance は source/build を識別し、本番 server binary は識別しません |

支持できる主張は、**monitor の信頼に関わる出力と署名済み receipt bytes は独立して検証でき、canonical 実装は公開監査が可能である**、というものです。観測や receipt が、支払いの安全性、endpoint の誠実さ、remote attestation、TEE 実行、AI 推論の正しさ、総合 trust score を保証するわけではありません。

API server、本番デプロイ設定と secrets、owner/auth state、秘密鍵、hosted UI DOM は、この repository には含めません。Canonical receipt 検証の再現には不要です。Receipt vector の seed は、明示的にラベル付けされた公開テスト用です。その鍵を信頼したり本番で使ったりしないでください。

## 関連する IFF プロジェクト

[iff-apostille](https://github.com/ifandonlyif-io/iff-apostille) は、producer artifact のための issuer 非依存の署名とオフライン検証を提供します。Apostille record は x402 monitor の観測、transparency log、reputation に取り込まれません。Core 0.1 alpha は別のリリースと信頼ポリシーを持ちます。

## 開発

以下はこの repository の checkout で実行してください。現在の CI は Go 1.26.6 と Node.js 24 を使用し、Node.js 22 との互換性も検査します。以下のチェックには Python 3 と npm も必要です。

```bash
(cd go && go test ./...)
(cd go && go vet ./...)
(cd ts && npm ci && npm test && npm run build)
node --test browser/service-receipt.test.mjs
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
python3 -m json.tool schemas/service-receipt-v1.json >/dev/null
python3 -m json.tool schemas/service-receipt-key-directory-v1.json >/dev/null
python3 -m json.tool spec/testdata/service_receipt_v1.json >/dev/null
```

脆弱性の非公開報告は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

MIT。[LICENSE](LICENSE) を参照してください。
