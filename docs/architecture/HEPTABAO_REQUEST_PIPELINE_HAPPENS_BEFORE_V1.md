# HeptaBao Request Pipeline Happens-Before Specification V1

## 1. Authoritative order

```text
receive + transport bounds
HB canonicalize(path, headers, query, body shape)
HB bind(namespace, mount, request ID, deadline)
HB classify(operation ID and effect class)
HB authenticate or verify declared unauthenticated route
HB identity/MFA
HB policy decision
HB request audit durable acceptance
HB fenced intent commit (when mutation/external effect)
HB backend/plugin/cluster dispatch
HB effect observation and domain commit
HB response audit durable acceptance
HB response write
```

`HB` 表示前一步的成功事实是后一步的必要前提，不只是日志顺序。

## 2. Commit point

- PURE_READ：authoritative snapshot/freshness 被选定时；
- DURABLE_MUTATION：domain commit generation 原子发布时；
- TOKEN/LEASE ISSUE：记录、索引、parent/effect edge 同一事务提交时；
- EXTERNAL_EFFECT：本地 intent 已提交且 provider result 被持久化分类时；
- CLUSTER_OPERATION：Raft entry committed 且 local FSM applied 到要求 index 时。

Client disconnect 不撤销已完成的 commit point，也不授权 blind retry。

## 3. Cancellation

每个 stage 声明 cancellable/uncancellable。进入 irreversible external call 或 durable commit 后，取消只影响等待者，不回滚 authority。超时后结果未知必须写入 `INDETERMINATE`。

## 4. Audit failure

- request audit 失败：不得 dispatch；
- response audit 在无 side effect 时失败：响应失败，操作可安全标记未发送；
- response audit 在已发生 effect 后失败：保留 opaque effect reference，禁止重复创建；仅允许重新审计的 lookup/retrieve/revoke/compensate/manual hold。

## 5. Active/standby

可能写入的 GET、token/lease issue、external effect、seal ceremony、mount mutation 和 security-sensitive read 默认 active-only。Read standby 必须证明 applied index 与 freshness policy；epoch/leader 变化取消 active-only context 并 fence stale owner。

## 6. Retry matrix

| Outcome | Client retry | Server automatic retry |
|---|---|---|
| before dispatch | same idempotency key | allowed if policy says safe |
| durable commit known success | lookup result | no duplicate mutation |
| durable commit known failure | new or same key per API | bounded |
| external effect unknown | reconcile/lookup only | forbidden creation retry |
| audit response failure after effect | retrieval/revoke flow | forbidden creation retry |
| stale owner/epoch | redirect/retry after re-auth | old context fenced |
