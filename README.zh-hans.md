# iff-x402-transparency

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[IFF Monitor](https://ifandonlyif.io/zh-hans/monitor) · [SDK 指南](https://ifandonlyif.io/zh-hans/sdk) · [API 文档](https://ifandonlyif.io/zh-hans/docs)

IFF x402 requirement transparency log 与 Service Receipt v1 中，攸关信任的公开验证部分：协议规范、JSON Schema、已知答案向量、离线验证器，以及 TypeScript 与 Go client。

目标明确且可测试：让独立读者不依赖未公开的服务器逻辑，也能验证已发布的日志输出与签署服务收据。

## 依用途选择入口

| 你的需求 | 从这里开始 |
|---|---|
| 应用自己的付款策略前，比较 x402 付款要求 | 已发布的 TypeScript 或 Go preflight SDK |
| 独立验证日志签名、包含证明与仅附加的一致性 | Python 参考验证器与保留的 checkpoint |
| 验证已签署 Service Receipt 或已保存的 API 响应 | 目前 checkout 的 Go receipt CLI 或浏览器验证核心 |
| 审查或实现传输协议 | 规范、schema 与跨语言测试向量 |

安装已发布的 preflight SDK：

```bash
npm install @ifandonlyif/x402-preflight@0.2.0
go get github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0
```

在 JavaScript/TypeScript 项目使用 npm 命令，或在已初始化的 Go 模块使用 Go 命令。详见 [TypeScript 指南](ts/README.md)、[npm 软件包](https://www.npmjs.com/package/@ifandonlyif/x402-preflight/v/0.2.0)及 [Go API 参考](https://pkg.go.dev/github.com/ifandonlyif-io/iff-x402-transparency/go@v0.2.0)。发布标签为 `ts/v0.2.0`、`go/v0.2.0`。

Go `v0.2.0` 标签只包含 fingerprint/preflight 支持；Service Receipt 软件包与 CLI 是后来加入 `main` 的源代码。验证收据请使用下方 checkout 命令，不能假设旧标签已包含这些工具。

Preflight 比较付款要求与 IFF 的观测，不执行付款。调用者保留自己的付款策略。结果分为 `consistent`、`diverged`、`unobserved`、`stale`。

## 仓库内容

- [`spec/x402-requirement-transparency-v1.md`](spec/x402-requirement-transparency-v1.md)：定义 requirement fingerprint、signed tree head、Merkle 包含与一致性证明、公开字段及判定词汇。
- [`spec/service-receipt-v1.md`](spec/service-receipt-v1.md)：定义 canonical Service Receipt v1 的 envelope、payload、domain、信任模型、有效期限语义、证据引用及 API adapter 行为。
- [`schemas/`](schemas/)：receipt envelope 与 receipt-key directory 的 JSON Schema。
- [`spec/testdata/`](spec/testdata/)：fingerprint、Merkle proof 与完整收据验证的跨语言已知答案向量，含拒绝案例。
- [`spec/verify_example.py`](spec/verify_example.py)：仅使用 Python 标准库的验证器。固定生产环境 log key 指纹、重新计算所有 leaf 与完整 Merkle root、验证包含证明，并可保留 checkpoint 验证仅附加的一致性。
- [`ts/`](ts/)：`@ifandonlyif/x402-preflight`。
- [`go/`](go/)：IFF 私有生产监测器导入的 canonical Go fingerprint/preflight 模块。也包含仅依赖标准库的 [`receipt`](go/receipt/) 软件包与离线 [`iff-receipt-verify`](go/cmd/iff-receipt-verify/) 命令。
- [`browser/service-receipt.mjs`](browser/service-receipt.mjs)：不依赖 DOM、使用 Web Crypto 的收据验证核心，附 Node 兼容性测试。

## 独立验证

离线兼容性检查：

```bash
python3 spec/verify_example.py --self-test
python3 -m unittest discover -s spec -p 'test_*.py' -v
```

验证生产环境，并保留 checkpoint 供后续一致性检查：

```bash
python3 spec/verify_example.py --checkpoint ~/.iff-production-sth.json
```

验证器在经审查的源代码中固定下列生产环境信任锚：

- log ID：`e33f4a64fe0ef33fca5cbfddce858667`
- 原始 Ed25519 公钥的 SHA-256：`e33f4a64fe0ef33fca5cbfddce858667ee56be6347c6cf7ffcda9d1bceaffe5b`

API 自己的 `/log/keys` 响应是 metadata，不是独立信任锚。轮换密钥需要经审查的发布，保留旧密钥以验证历史 checkpoint，并经可信渠道加入后继密钥。

### 验证服务收据

执行跨语言已知答案测试：

```bash
(cd go && go test ./receipt ./cmd/iff-receipt-verify)
node --test browser/service-receipt.test.mjs
```

将独立 receipt envelope 或完整 API 响应存为 `response.json`，再验证：

```bash
(cd go && go run ./cmd/iff-receipt-verify -file ../response.json)
```

这会检查 canonical 编码、哈希、Ed25519 签名、时间状态，以及在提供完整响应时检查已签署 subject 的绑定。它不证明谁控制嵌入的密钥。若要验证 issuer 身份，还需提供完全相符的预期 issuer，以及一个或多个由独立来源信任的完整 `sha256:` key ID；信任条件不符时必须让命令失败，则使用 `-require-trust`。

从完全相符的预期 HTTPS issuer 取得 receipt key directory，可作为来源 metadata；它不是独立固定的信任锚。

首次于 2026-09-01 公开、纳入版本控制的生产环境 pin 存于 [`keys/service-receipt-production-2026-09-01.json`](keys/service-receipt-production-2026-09-01.json)：

- issuer：`https://ifandonlyif.io`
- 完整 key ID：`sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb`

Issuer 与完整 key ID 必须一起使用。日期文件是通过此受保护 repo 发布的版本快照；即时 key directory 仍是可变更的探索 metadata。轮换会新增版本快照，并保留旧档，让历史收据维持原有 pin。

快照中的 `current` 只表示该日期发布时有效；旧快照可支持历史验证，但绝不可自动永久授权新签发收据。应先发布后继密钥，让前后密钥重叠至少「收据生命周期加上 directory 缓存生命周期」，再于下一份版本快照将前任标为 historical/inactive。

## 公开证据能支持哪些声明

| 声明 | 公开证据 | 限制 |
|---|---|---|
| Requirement fingerprint 遵循 v1 | 规范、向量与生产环境使用的 canonical Go 实现 | 仅公开源代码无法识别服务器实际执行的可执行文件 |
| STH 来自 IFF 固定的 log key | Canonical bytes、签名与固定的密钥指纹 | 轮换需要另一份可信更新 |
| 某项观测包含在快照中 | 重新计算的 root 与 RFC 6962 包含证明 | 被包含不代表观测符合事实 |
| 历史以仅附加方式前进 | 保留的 STH 与一致性证明 | 单一观测者无法排除所有分裂视图；独立 witness 可改善此点 |
| Service Receipt payload 由特定 Ed25519 密钥签署 | Canonical payload bytes、domain-separated digest、签名与完整 key ID | 嵌入公钥仅证明签名自洽；身份需要独立信任的 issuer/key 策略 |
| API 响应仍符合收据已签署的 subject | 解码后的已签署 subject 与其 domain-separated hash | Evidence 与 compute-proof 描述只是引用，个别验证前明确维持未验证状态 |
| SDK 软件包来自这份源代码 | 公开 CI 与 npm OIDC provenance | Provenance 识别来源／构建，不代表生产服务器可执行文件 |

可支持的声明是：**监测器中攸关信任的输出与已签署收据字节可以独立验证，canonical 实现可供公开审查。** 这不使观测或收据成为付款安全、端点诚实、远程证明、TEE 执行、AI 推理正确或综合信任分数的保证。

本 repo 不包含 API server、生产部署配置与 secrets、owner/auth 状态、私钥及托管 UI DOM；重现 canonical 收据验证并不需要这些组件。收据向量只包含明确标示的公开测试 seed，不可信任或部署该密钥。

## 相关 IFF 项目

[iff-apostille](https://github.com/ifandonlyif-io/iff-apostille) 为 producer 产物提供与 issuer 无关的签名及离线验证。Apostille 记录不会导入 x402 monitor 观测、透明日志或 reputation。其 Core 0.1 alpha 有独立的发布与信任策略。

## 开发

在本 repo 的 checkout 执行下列命令。目前 CI 使用 Go 1.26.6 与 Node.js 24，也检查 Node.js 22 兼容性。下列检查另需 Python 3 与 npm。

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

私下报告漏洞请见 [SECURITY.md](SECURITY.md)。

## 授权

MIT。详见 [LICENSE](LICENSE)。
