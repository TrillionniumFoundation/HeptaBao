# HeptaBao Repository Control Plane Enforcement Specification V1

**状态：** `NORMATIVE_TARGET_STATE / EXTERNAL_ACTION_REQUIRED / AUTHORITY_EFFECT_NONE`  
**关联 blocker：** `HB-BLK-CTRL-001`  
**执行包：** `HB-EAP-CTRL-001`

## 1. 边界

仓库中的 YAML、CODEOWNERS、PR 模板和 workflow 只能描述期望控制；只有 GitHub 控制面实际启用且经过读取和负向验证的配置，才构成 enforcement evidence。

本文不指定某个未保护分支自动成为 canonical integration truth。目标分支必须由 repository-control completion object 显式声明，并绑定 repository ID、branch/ref、ruleset ID 和生效时间。

## 2. Canonical integration branch

被选分支必须满足：

- 存在且非临时 `codex/*`、`exec/*` branch；
- 只接受 pull request 或 merge queue；
- direct push、force push、branch deletion 禁止；
- 管理员和 repository owner 不得默认 bypass；任何 `administrator bypass` 必须为空或受紧急双人控制；
- branch rename/retarget 需要新的 control-plane receipt；
- merge 后代码可以是 `UNQUALIFIED`，不得因进入 integration branch 自动改变 authority；
- release、qualification、claim 和 grant 使用独立对象，不由 branch 名称推导。

## 3. Required ruleset

### 3.1 Pull request

- 必须通过 PR；
- 至少 2 个审批；
- 必须 CODEOWNERS approval；
- 新 commit 后 dismiss stale approvals；
- 必须解决 review conversations；
- 最后一次 push 的作者不能是唯一 approver；
- critical path 必须满足 program + security + domain/specialist 角色；
- merge queue 或 strict up-to-date branch requirement；
- 禁止 self-merge critical PR。

### 3.2 Required checks

至少要求以下逻辑门禁；实际 check-run 名称必须从 exact PR run 枚举并写入 completion object：

- V1.2/V1.2.1 plan and Python semantic validation；
- root Rust fmt/test/clippy；
- OpenRaft exact lock/metadata；
- OpenRaft Rust 1.88/1.98 test/clippy；
- in-memory cluster matrix；
- hostile snapshot + linearizability matrix；
- OS/durable/clock blocker closure matrix；
- candidate adapter/source-integrity/SBOM/MSRV；
- repository identity；
- final authority sentinel。

Ruleset 不得要求一个永远不触发的 check。每个 required check 必须在 representative PR 上证明可执行，并有 fail/pass 两种负向/正向验证。

### 3.3 Commit provenance

至少选择一种可验证方案：

- GitHub verified signatures；
- organization-issued signing identities；
- merge queue produced verified commit；
- Sigstore/GitHub OIDC provenance 与不可变 source binding。

Web commit signoff、DCO 和 cryptographic signature 是不同概念。若未强制 cryptographic provenance，不得把 signoff 描述为 signed commit。

### 3.4 History

推荐 squash-only 或 merge-queue 线性历史。若允许 merge commit，必须明确：

- qualification 绑定 PR head、merge commit 还是 release commit；
- merge tree 与已测试 tree 的等价性证明；
- parent ordering；
- dependency/lock digest；
- base drift disposition。

## 4. CODEOWNERS 与角色

CODEOWNERS 必须使用真实可解析的 user/team，不允许 placeholder。最低角色：

- `program`
- `security`
- `domain`
- `compatibility`
- `legal`
- `crypto`
- `distributed-systems/storage`
- `operations`
- `migration`
- `release`

关键路径最少映射：

| 路径 | 必需角色 |
|---|---|
| `/planning/**` | program + security |
| `/schemas/**` | program/domain + security |
| `/docs/security/**` | security |
| `/docs/storage/**`、Raft probe | storage/distributed-systems |
| `/docs/compatibility/**`、`/oracle/**` | compatibility + security |
| `/qualifications/**` | qualification/program + security |
| `/.github/workflows/**` | platform + security |
| `/SECURITY.md` | security operations |
| `/LICENSE*` | legal |
| authority/grant/revocation objects | release-security + required domain role |

同一自然人可以长期承担多个组织职责，但不能用多个 GitHub alias 满足同一 critical receipt 的独立性要求。

## 5. Workflow permissions

默认：

```yaml
permissions:
  contents: read
```

额外权限必须 job-scoped、最小化并有 threat-model delta。验证 workflow 禁止：

- `contents: write`；
- `persist-credentials: true`；
- `git commit/push/rebase`；
- 修改源码后把修改后的工作树称为 exact-head evidence；
- 使用未固定 commit SHA 的第三方 action；
- 从不可信 PR 执行可访问 secrets 的代码；
- 由同一 workflow 修改 policy、validator 与 final evidence。

生成器输出只能作为 artifact 或由 bot 创建普通 PR；不能直接改变 canonical branch。

## 6. Merge queue 与 concurrency

- required PR checks 应在 exact head 或 queue-generated candidate 上明确运行；
- concurrency key 必须避免不同 PR/branch 相互取消；
- `cancel-in-progress` 只允许取消同一 PR 的旧 SHA，不得删除旧失败证据；
- queue merge 前必须重新验证 source/lock/tree；
- merge 后生成 integration receipt，记录 PR head、queue candidate、final commit/tree 和 check suite；
- 自动 merge 不得签发 qualification 或 authority。

## 7. Negative control tests

配置完成后必须至少执行：

1. direct push 被拒绝；
2. force push 被拒绝；
3. branch delete 被拒绝；
4. 少于审批数无法 merge；
5. stale approval 被新 commit 失效；
6. 缺少 CODEOWNER 无法 merge；
7. failed required check 无法 merge；
8. expected check 未触发时无法 merge；
9. unresolved conversation 无法 merge；
10. repository admin/owner bypass 被拒绝；
11. unsigned/unverified commit 按所选 policy 被拒绝；
12. workflow 尝试写 repository 时被 validator 或 token 权限拒绝。

负向测试必须使用无真实 secret 的专用 branch/PR，并保留 API response、status code、actor、time 和 ruleset ID。

## 8. Required evidence

Completion object 至少包含：

- repository ID/full name；
- canonical branch/ref/commit；
- ruleset ID/version；
-完整 ruleset JSON digest；
- branch protection JSON digest（若并存）；
- required check names；
- approval/CODEOWNERS settings；
- bypass actor list，期望为空或仅明确 emergency role；
- commit provenance policy；
- negative test results；
- representative positive merge evidence；
- operator identity；
- independent reviewer identity；
- issue/expiry/revalidation time；
- revocation lookup key；
- `qualification=false`、`authority_effect=NONE`。

截图只能作为辅助，不能替代 API/配置对象。

## 9. Emergency controls

必须定义：

- emergency lock role；
- lock trigger；
- read-only/freeze procedure；
- bypass 使用条件和双人审批；
- 所有 bypass event 的审计；
- temporary exception expiry；
-恢复 ruleset 的验证；
- credential compromise 时的 revocation；
- branch/tag/release provenance re-evaluation。

Emergency bypass 不得静默；任何使用都会使相关 qualification/claim/grant 进入 review 或 revocation。

## 10. Revalidation

以下事件必须重新执行 control-plane package：

- ruleset/branch protection/CODEOWNERS/workflow permission 改变；
- GitHub plan/feature 或 organization policy 改变；
- canonical branch 改名；
- required check 名称变化；
- reviewer team 或 membership 变化；
- admin/bypass actor 变化；
- signing/provenance policy变化；
-发现未授权 push、merge 或 workflow write。

在 revalidation 完成前，repository-control blocker 回到 `EXTERNAL_ACTION_REQUIRED`，但已合并代码不自动获得或失去 production authority；authority 由独立 revocation/grant graph处理。
