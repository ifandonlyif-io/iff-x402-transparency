# iff-x402-transparency

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[IFF Monitor](https://ifandonlyif.io/zh-hant/monitor) · [SDK 指引](https://ifandonlyif.io/zh-hant/sdk) · [API 文件](https://ifandonlyif.io/zh-hant/docs)

IFF x402 requirement transparency log 與 Service Receipt v1 中，攸關信任的公開查驗部分：協定規格、JSON Schema、已知答案向量、離線查驗器，以及 TypeScript 與 Go client。

目標明確且可測試：讓獨立讀者不依賴未公開的伺服器邏輯，也能查驗已發佈的日誌輸出與簽署服務收據。

## 依用途選擇入口

| 你的需求 | 從這裡開始 |
|---|---|
| 套用自己的付款政策前，比對 x402 付款要求 | 已發佈的 TypeScript 或 Go preflight SDK |
| 獨立查驗日誌簽章、包含證明與僅附加的一致性 | Python 參考查驗器與保留的 checkpoint |
| 查驗已簽署 Service Receipt 或已儲存的 API 回應 | 目前 checkout 的 Go receipt CLI 或瀏覽器查驗核心 |
| 審查或實作傳輸協定 | 規格、schema 與跨語言測試向量 |

安裝已發佈的 preflight SDK：

```bash
npm install @ifandonlyif/x402-preflight@0.2.0
go get github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0
```

在 JavaScript/TypeScript 專案使用 npm 指令，或在已初始化的 Go 模組使用 Go 指令。詳見 [TypeScript 指引](ts/README.md)、[npm 套件](https://www.npmjs.com/package/@ifandonlyif/x402-preflight/v/0.2.0)及 [Go API 參考](https://pkg.go.dev/github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0)。發佈標籤為 `ts/v0.2.0`、`go/v0.2.0`。

Go `v0.2.0` 標籤只包含 fingerprint/preflight 支援；Service Receipt 套件與 CLI 是後來加入 `main` 的原始碼。查驗收據請使用下方 checkout 指令，不能假設舊標籤已包含這些工具。

Preflight 比對付款要求與 IFF 的觀測，不執行付款。呼叫者保留自己的付款政策。結果分為 `consistent`、`diverged`、`unobserved`、`stale`。

## Repo 內容

- [`spec/x402-requirement-transparency-v1.md`](spec/x402-requirement-transparency-v1.md)：定義 requirement fingerprint、signed tree head、Merkle 包含與一致性證明、公開欄位及判定詞彙。
- [`spec/service-receipt-v1.md`](spec/service-receipt-v1.md)：定義 canonical Service Receipt v1 的 envelope、payload、domain、信任模型、有效期限語意、證據參照及 API adapter 行為。
- [`schemas/`](schemas/)：receipt envelope 與 receipt-key directory 的 JSON Schema。
- [`spec/testdata/`](spec/testdata/)：fingerprint、Merkle proof 與完整收據查驗的跨語言已知答案向量，含拒絕案例。
- [`spec/verify_example.py`](spec/verify_example.py)：僅使用 Python 標準函式庫的查驗器。釘選正式環境 log key 指紋、重新計算所有 leaf 與完整 Merkle root、查驗包含證明，並可保留 checkpoint 查驗僅附加的一致性。
- [`ts/`](ts/)：`@ifandonlyif/x402-preflight`。
- [`go/`](go/)：IFF 私有正式監測器匯入的 canonical Go fingerprint/preflight 模組。也包含僅依賴標準函式庫的 [`receipt`](go/receipt/) 套件與離線 [`iff-receipt-verify`](go/cmd/iff-receipt-verify/) 指令。
- [`browser/service-receipt.mjs`](browser/service-receipt.mjs)：不依賴 DOM、使用 Web Crypto 的收據查驗核心，附 Node 相容性測試。

## 獨立查驗

離線相容性檢查：

```bash
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

查驗正式環境，並保留 checkpoint 供後續一致性檢查：

```bash
python3 spec/verify_example.py --checkpoint ~/.iff-production-sth.json
```

查驗器在經審查的原始碼中釘選下列正式環境信任錨：

- log ID：`e33f4a64fe0ef33fca5cbfddce858667`
- 原始 Ed25519 公鑰的 SHA-256：`e33f4a64fe0ef33fca5cbfddce858667ee56be6347c6cf7ffcda9d1bceaffe5b`

API 自己的 `/log/keys` 回應是 metadata，不是獨立信任錨。輪替金鑰需要經審查的發佈，保留舊金鑰以查驗歷史 checkpoint，並經可信管道加入後繼金鑰。

### 查驗服務收據

執行跨語言已知答案測試：

```bash
(cd go && go test ./receipt ./cmd/iff-receipt-verify)
node --test browser/service-receipt.test.mjs
```

將獨立 receipt envelope 或完整 API 回應存為 `response.json`，再查驗：

```bash
(cd go && go run ./cmd/iff-receipt-verify -file ../response.json)
```

這會檢查 canonical 編碼、雜湊、Ed25519 簽章、時間狀態，以及在提供完整回應時檢查已簽署 subject 的綁定。它不證明誰控制嵌入的金鑰。若要查驗 issuer 身分，還需提供完全相符的預期 issuer，以及一個或多個由獨立來源信任的完整 `sha256:` key ID；信任條件不符時必須讓指令失敗，則使用 `-require-trust`。

從完全相符的預期 HTTPS issuer 取得 receipt key directory，可作為來源 metadata；它不是獨立釘選的信任錨。

首次於 2026-09-01 公開、納入版本控制的正式環境 pin 存於 [`keys/service-receipt-production-2026-09-01.json`](keys/service-receipt-production-2026-09-01.json)：

- issuer：`https://ifandonlyif.io`
- 完整 key ID：`sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb`

Issuer 與完整 key ID 必須一起使用。日期檔案是透過此受保護 repo 發佈的版本快照；即時 key directory 仍是可變更的探索 metadata。輪替會新增版本快照，並保留舊檔，讓歷史收據維持原有 pin。

快照中的 `current` 只表示該日期發佈時有效；舊快照可支援歷史查驗，但絕不可自動永久授權新簽發收據。應先發佈後繼金鑰，讓前後金鑰重疊至少「收據生命週期加上 directory 快取生命週期」，再於下一份版本快照將前任標為 historical/inactive。

## 公開證據能支持哪些聲明

| 聲明 | 公開證據 | 限制 |
|---|---|---|
| Requirement fingerprint 遵循 v1 | 規格、向量與正式環境使用的 canonical Go 實作 | 僅公開原始碼無法識別伺服器實際執行的執行檔 |
| STH 來自 IFF 釘選的 log key | Canonical bytes、簽章與釘選的金鑰指紋 | 輪替需要另一份可信更新 |
| 某項觀測包含在快照中 | 重新計算的 root 與 RFC 6962 包含證明 | 被包含不代表觀測符合事實 |
| 歷史以僅附加方式前進 | 保留的 STH 與一致性證明 | 單一觀測者無法排除所有分裂視圖；獨立 witness 可改善此點 |
| Service Receipt payload 由特定 Ed25519 金鑰簽署 | Canonical payload bytes、domain-separated digest、簽章與完整 key ID | 嵌入公鑰僅證明簽章自洽；身分需要獨立信任的 issuer/key 政策 |
| API 回應仍符合收據已簽署的 subject | 解碼後的已簽署 subject 與其 domain-separated hash | Evidence 與 compute-proof 描述只是參照，個別查驗前明確維持未查驗狀態 |
| SDK 套件來自這份原始碼 | 公開 CI 與 npm OIDC provenance | Provenance 識別來源／建置，不代表正式伺服器執行檔 |

可支持的聲明是：**監測器中攸關信任的輸出與已簽署收據位元組可以獨立查驗，canonical 實作可供公開審查。** 這不使觀測或收據成為付款安全、端點誠實、遠端證明、TEE 執行、AI 推理正確或綜合信任分數的保證。

本 repo 不包含 API server、正式部署設定與 secrets、owner/auth 狀態、私鑰及託管 UI DOM；重現 canonical 收據查驗並不需要這些元件。收據向量只包含明確標示的公開測試 seed，不可信任或部署該金鑰。

## 相關 IFF 專案

[iff-apostille](https://github.com/ifandonlyif-io/iff-apostille) 為 producer 產物提供與 issuer 無關的簽章及離線查驗。Apostille 紀錄不會匯入 x402 monitor 觀測、透明日誌或 reputation。其 Core 0.1 alpha 有獨立的發佈與信任政策。

## 開發

在本 repo 的 checkout 執行下列指令。目前 CI 使用 Go 1.26.6 與 Node.js 24，也檢查 Node.js 22 相容性。下列檢查另需 Python 3 與 npm。

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

私下通報弱點請見 [SECURITY.md](SECURITY.md)。

## 授權

MIT。詳見 [LICENSE](LICENSE)。
