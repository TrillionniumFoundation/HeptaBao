# HeptaBao System Context 与 Crate Graph V1

## 1. 进程边界

| 进程/工具 | 信任级别 | 可接触明文 | 可写 durable state | 可授予 authority |
|---|---|---:|---:|---:|
| `heptabao-server` | authority-critical | 请求 scope 内 | 仅经 domain writer | 否 |
| `heptabao` CLI | untrusted client | 用户输入 scope | 否 | 否 |
| Agent/Proxy | edge client | bounded token/secret | 本地受控 cache | 否 |
| plugin process | isolated external | operation scope 内 | 不直接写核心存储 | 否 |
| Oracle lab | restricted research | 受控 fixture scope | 只写 restricted evidence store | 否 |
| qualification verifier | offline/high integrity | 不需要业务 secret | 只写 evidence index | 否 |
| authority signer | isolated external | 不需要业务 secret | 只写 signed grant/revocation | 是，仅签名策略允许的 scope |

## 2. Crate 分层

```text
heptabao-types / heptabao-secret-types
        ↓
heptabao-protocol / heptabao-operation-registry
        ↓
heptabao-storage-api ─ heptabao-barrier-api ─ heptabao-audit-api
        ↓                    ↓                       ↓
storage backends        barrier provider        audit devices
        ↓                    ↓                       ↓
policy / identity / token / lease / system / namespace / plugin-host
        ↓
heptabao-core-pipeline
        ↓
HTTP listener / CLI / Agent / Proxy adapters
```

### 2.1 允许的依赖方向

- types、protocol 和 provider-neutral API 不依赖 server adapter；
- domain writer 不依赖 HTTP types；
- Raft FSM 只依赖 deterministic domain command/result types；
- audit schema 可被所有 domain 使用，但 audit device 不得反向依赖 domain writer；
- qualification/governance tooling 不进入 runtime authority path；
- Oracle tooling 不得成为 implementation crate 的 build dependency。

### 2.2 禁止边

- barrier → HTTP/CLI；
- policy → storage backend implementation；
- token/lease → plugin concrete transport；
- Raft FSM → clock/random/network/KMS/plugin；
- production crates → Oracle raw material；
- runtime code → qualification grant parsing as an implicit feature switch。

## 3. Secret-bearing 类型

明文 secret、token、key share、private key 和 recovery material 必须使用 non-Clone 或显式复制审计的 wrapper；Debug/Display/Serialize 默认禁止。任何跨进程/持久化边界使用 versioned envelope，并且日志/metric/trace 只携带 opaque ID 或 keyed digest。

## 4. Domain writer

每个 domain 在 `HEPTABAO_AUTHORITATIVE_DATA_OWNERSHIP_AND_TRANSACTION_MAP_V1.md` 中拥有唯一 writer。adapter、cache、projection、standby、migration comparator 和 Oracle observer 永远不是 writer。

## 5. Feature 与 dependency 隔离

- crypto provider、TLS provider、runtime、storage 和 Raft 必须位于 replacement seam 后；
- candidate-specific types 不穿透 public domain API；
- feature组合有 closed-world matrix；unknown feature 或组合拒绝构建；
- unsafe/native/build-script surface 必须在 dependency receipt 中逐项 disposition。
