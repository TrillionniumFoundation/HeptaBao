# HeptaBao Authoritative Data Ownership 与 Transaction Map V1

## 1. 规则

每个 durable domain 只有一个 authoritative writer。读 cache、projection、standby 和 migration tooling 必须携带 source revision/epoch；无法证明新鲜度时 fail closed 或转发 active。

| Domain | Authoritative writer | Transaction boundary | Fence / generation | Snapshot owner |
|---|---|---|---|---|
| operation registry | `heptabao-protocol` | registry revision | schema version | protocol |
| barrier/keyring | `heptabao-barrier` | envelope + keyring commit | key epoch | barrier |
| seal lifecycle | `heptabao-seal` | ceremony step | ceremony ID/epoch | seal |
| mounts/system | `heptabao-system` | mount table revision | mount epoch | system |
| policy | `heptabao-policy` | policy source revision | policy generation | policy |
| identity/MFA | `heptabao-identity` | entity/group/alias tx | identity revision | identity |
| token graph | `heptabao-token` | token + accessor + parent edges | token epoch | token |
| lease/effect intent | `heptabao-lease` | intent/result/lease tx | owner epoch + operation key | lease |
| audit config | `heptabao-audit` | device config revision | audit epoch | audit |
| plugin catalog | `heptabao-plugin-host` | catalog entry revision | process generation | plugin host |
| namespace | `heptabao-namespace` | tree/keyring/seal context tx | namespace epoch | namespace |
| Raft FSM | `heptabao-storage-raft` | deterministic log entry | term/index + cluster ID | Raft storage |
| cluster membership | `heptabao-cluster` | membership command | membership epoch | cluster |
| migration authority | `heptabao-migration` | writer switch receipt | migration epoch/fence | migration |
| qualification graph | `heptabao-qualification` | immutable evidence index | receipt generation | qualification |

## 2. Persist-before-publish

```text
read current generation
→ build candidate state without modifying visible state
→ validate candidate invariants
→ persist candidate bytes
→ fsync file/device as profile requires
→ atomically publish generation/manifest
→ fsync parent metadata as profile requires
→ replace in-memory authoritative state
→ acknowledge/callback/respond
```

任何 persist/publish 失败都不能让读者看到 candidate state。重试必须使用 operation ID 和 expected generation。

## 3. 跨域事务

跨域操作不假设分布式 ACID。使用 durable intent + domain-local commit + observable result + compensation/reconciliation。External effect 永远在 durable fenced intent 之后；未知结果不得重新创建 credential。

## 4. Snapshot

state、snapshot metadata、membership、key/barrier metadata 和 checksum 必须属于同一 generation。多文件实现必须通过原子 manifest 指向完整 generation；任一 component 缺失、摘要不匹配或 generation 混合时拒绝启动。

## 5. Migration

source 与 target writer 不能重叠。cutover 必须以 source freeze receipt、final delta digest、target verification、new authority epoch 和 signed switch object 为一个逻辑事务。发生 target-only irreversible effect 后只允许 forward recovery。
