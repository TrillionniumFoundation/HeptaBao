# HeptaBao V1.2 垂直切片执行计划

## 1. 目标

本计划把 301 个 Work Package 的长期范围转换为可运行、可测、可演进的垂直价值流。任何切片通过测试都不自动授予 compatibility 或 production authority。

## 2. Slice 0：治理与可信执行底座

**Exit 条件**

- V1.2 normative manifest、canonical renderer、blocker register 和 validators 在 exact head 运行；
- active workflow 全部 `contents: read`，不存在持久化 Git 凭据或直接 push；
- exact dependency lock 已进入 source truth；
- repository-controlled blocker 均有 owner、evidence 和状态；
- external blocker 均 fail closed，未伪造审批；
- integration 与 authority 分离写入规范。

## 3. Slice 1：`HB-P0-DEV-MEMORY`

### 3.1 可运行路径

```text
server bootstrap
→ parse/bound config
→ TLS or loopback development listener
→ canonicalize request
→ bind namespace/mount context
→ classify operation
→ token authentication
→ ACL decision
→ request audit
→ memory backend dispatch
→ response audit
→ response
```

### 3.2 最小功能

- `/v1/sys/health` 的明确 initialization/seal/active 状态；
- development-only init/seal/unseal；
- minimal service token、accessor、parent graph；
- policy read/evaluate；
- KV v1 put/get/list/delete；
- file audit with fail-closed option；
- graceful shutdown、deadline、cancellation 和 resource bounds；
- secret-free deterministic Oracle fixtures。

### 3.3 非范围

PostgreSQL、Integrated Raft、HA、dynamic credential、plugin、namespace、migration、Agent/Proxy、production seal 和 production key custody 均不在 P0 authority scope。

### 3.4 资格门槛

- every named endpoint has request/response/error/audit side-effect evidence；
- no unaudited secret response；
- sealed bypass、ACL bypass、path ambiguity 和 client-disconnect tests 全 PASS；
- memory/task/fd leak bounded；
- secret canary=0；
- `production_supported=false`。

## 4. Slice 2：`HB-P1-CORE-POSTGRES`

### 4.1 增量能力

- PostgreSQL transaction/CAS/list；
- barrier envelope/keyring；
- production-style init/seal/unseal/rekey state machines（仍无 production authority）；
- KV v2；
- token graph、wrapping、cubbyhole；
- lease/expiration/revoke；
- audit broker + file/http/socket/syslog devices；
- backup/restore、schema migration、reopen；
- kill-point、disk-full、fsync-loss、corruption and rollback evidence。

### 4.2 原子性边界

每次 durable mutation 必须拥有 operation ID、generation/epoch、before digest、candidate digest、commit marker 和 publish point。数据库提交成功前不得更新可读 projection；提交结果不确定时进入 reconciliation。

## 5. Slice 3：Raft/HA

只有 H04 durable storage contract、H03 operation/effect model 和 H02 bounded Raft selection receipt 完整后，H20/H21 才能进入 qualification。必须执行 multi-process nodes、per-node directories、real restart、snapshot install、membership churn、partition、clock skew、filesystem crash 和 external linearizability checker。

## 6. 每个切片的交付节奏

每个迭代只允许小型 PR：一个 contract、一个 implementation seam 或一个 evidence closure。PR 描述必须列明 exact base/head、风险、authority effect、失败证据与下一个 blocker。禁止通过长期 stacked branches 积累未审查代码。
