# HeptaBao Oracle Compatibility Matrix Specification V1

## 1. 条目粒度

每个 API/CLI/config/operator 行为使用独立机器条目，不允许只按“endpoint family”笼统通过。必需字段：

```text
operation_id
oracle_version/commit
method/path or command/config key
request headers/query/body schema
namespace/mount/seal/active-standby context
authentication and policy capability
status/exit/signal
response/output shape
error class
audit side effects
storage/token/lease/plugin/raft/external side effects
normalization rules
raw fixture digest
sanitized fixture digest
review identities
HeptaBao implementation/evidence status
deviation/exclusion
```

## 2. Fixture 生命周期

```text
INVENTORIED
→ CAPTURED_RAW_RESTRICTED
→ SANITIZED
→ PROVENANCE_TRANSFERRED
→ REVIEWED
→ IMPLEMENTED
→ DIFFERENTIAL_PASS
→ QUALIFIED
```

raw fixture 只存在 restricted Oracle lane；implementation lane 只接收经过 source classification、secret scan、normalization review、digest 和签名 transfer 的内容。

## 3. Normalization

只允许预先登记的 nondeterminism：request ID、timestamp、nonce、address、ordering（仅在语义无序时）和 secret placeholder。未知字段、未匹配 secret、额外 side effect、状态码/错误类变化不得被 normalizer 隐藏。

## 4. Side-effect differential

响应相同不等于兼容。每个 operation 比较 mount/policy/identity/token/lease/audit/plugin/Raft/external effect、seal/active transition、ordering 和 failure semantics。动态 secret GET 必须被分类为 lease-issuing mutation。

## 5. Claim 生成

Compatibility Claim 只覆盖满足 `DIFFERENTIAL_PASS + independent review + current evidence` 的 exact entries；其余必须列为 `UNSUPPORTED`、`DEVIATION` 或 `EXPERIMENTAL`。Claim 不授予生产 authority。
