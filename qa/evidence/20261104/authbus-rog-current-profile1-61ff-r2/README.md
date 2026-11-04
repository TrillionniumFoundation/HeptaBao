# ROG 真实受管凭证 1：V6、原 SDK、冷恢复与逻辑回滚

实际作业 `rog/1a1a719db42-fc05-2a20` exit 0，使用正常源码 `33cafa4c6e29f0bde1553e041550d21b4c725d9c` 和 Linux 二进制 `7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`。原始公开归档 SHA-256 为 `9ab2d2822e78cb442496bb50a60c6c3bcb9ca182e51e98ad0a907daa99373eef`，含 10 份回执及清单。

## 实际执行

在内核隔离的网络／PID 命名空间中读取 ROG main 的当前真实 SQLite 凭证，生产目录、SDK、源码和配置均为只读。选定受管凭证 1 的内容摘要为 `bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1`；账号标识与凭证值均不进入公开证据。

新建私有 HeptaBao，正式执行 native V6 激活并确认 KV2 reader format 2。通过真实 TLS、AppRole、Policy 与 KV2 发布该凭证，再让原已安装 SDK 和 AuthBus 插件恢复私有副本中被删除的指定 profile。使用 SDK 的显式 profile resolver 核对选出的 access credential 与源完全一致。

实际 SIGKILL 服务进程后，在同一持久化状态启动，先确认 sealed 503，再解封并重复上述 SDK 导入。两轮均完成越权读 403、renew 200、revoke 204 及撤销后读 403。

随后两份私有逻辑 store 各通过原 SDK 的原子 CAS 恢复完整基线，并额外由独立 SDK 读取核对 profiles、order、usageStats、lastGood。父流程 48 项、两轮 SDK 各 55 项、两轮回滚各 39 项，共 236 个动态断言；额外的 2 次独立读取单独计数。

## 保留的失败和晚到差异

r1 在删除 profile 后发现原 SDK 会清除该 profile 的 usage 状态，原断言因此失败。r2 只使用 SDK 正式支持的 `saveOptions.preserveStateProfileIds` 保留该指定 profile 的状态；没有删除原始 order／usage／默认配置守卫，驱动源码逐字节保持不变。

实际运行期间源 auth 表全行和 34 个冻结输入保持一致。稍后的独立导出发现 state 中原始第 3 条 profile 的 `usageStats.lastUsed` 及行时间变化；store 行及所选凭证代际未变。该晚到差异与第一次导出失败均保留，原因未归属，也没有把变化后的源当作回滚目标。之后独立 SDK 读取证明两份已停止私有副本的完整逻辑回滚仍精确成立。

## 资格范围

本轮只证明 **ROG main、指定受管 profile 1** 的 V6 存储和显式 SDK 恢复路径；不等于六个 agent 全部通过，不证明非 primary SQL 行或整个 SQLite 数据库的备份恢复，也没有重启生产服务管理器。

ROG 默认 native Codex 路径的凭证来源另行核验，不能通过改变默认路由或 profile 顺序来替代这项测试。本轮只关联同代际的历史上游 GET 回执，没有发出新的 provider 请求，没有 OAuth refresh、模型请求或 J3160 访问。最新上游有效性必须看独立的 fresh-provider 回执；这份存储恢复成功不能覆盖后续的上游 401。

生产配置、原默认模型、order、usage、排除策略与网关进程在本轮保持不变；全部所属进程已退出。生产流量切换、默认网关实际选用、native factory 重开、OAuth 轮换归属及全量替代均未获本轮资格。

## 重算公共证据

```sh
python3 qa/evidence/20261104/authbus-rog-current-profile1-61ff-r2/root_review.py
```

复核会完整重算原 reviewer，并核对 11 个归档条目、实际嵌入源码、运行时 pins、12 个作业终态、r1 失败及晚到差异。不会联系主机或读取真实凭证。
