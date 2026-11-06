# 当前 Mac 业务 SQLite 的可逆捕获准备

## 当前结论

这是尚未执行的正式数据准备控制器。它准备从当前 Mac 配置列出的所有 agent 数据库、共享数据库及七个 AuthBus 安全状态文件取得受保护副本，制作独立文件系统上的加密备份，再从备份恢复到全新目录。它不启动 HeptaBao、OpenBao、SDK、provider 或服务管理器，也不写原业务配置、切换流量或删除旧资产。

该工作不能把此前的 34 MiB 合成测试升级为真实业务迁移。实际 Mac 4bde9 的正常构建与 107 项 Rust 执行已另有通过证据；第一次 full34 → DR25 仍失败且未完成原 31 项及 25 项恢复要求。修正后的 DR 必须取得自己的完整实际证据，才能由外层执行控制器准入本任务。这里的 18 项本地控制回归不替代那个门槛。

当前文件是候选 QA，仍需独立复审、固定 Mac 解释器及依赖、实际 Darwin 控制回归和外层输入绑定。不要直接把下面的模板填入真实凭据后执行。

## 真实源与历史副本的区别

四机只读审计已确认，三个名称含 production 的 HeptaBao 根仍是 `native_v6_raft` 的 HA staged 模板，相关数据目录为空，服务/流量资格均为 false。它们不是当前业务 KV2 的来源。Mac 当前主 agent SQLite 的受限 stat 观察为 2,469,126,144 字节；该时刻未见 WAL/SHM/journal，不能由此推断数据库已冻结。

新的 R11 观察看到 Mac 当前 bootstrap 内的 gateway 和四个 AuthBus relay 有 PID。旧 HeptaBao owner label 仍无 PID、tabular status 78。检查只读元数据，没有打开业务库、凭据文件、服务环境或完整进程参数。它既不能证明这些进程都是写者，也不能排除其他写者；因此控制器所有公开结果都保持 `all_known_writers_fenced=false`。

非 J3160 的 Nov 2 加密归档及 X230 Nov 3 恢复副本已经有历史绑定。历史恢复记录的七个非空数据库、六个 auth store 不能充当今天的完整源分母。新计划必须绑定当前配置字节及完整 agent 列表；历史副本仅提供回溯和代码审计依据。

已有 profile1 SDK 迁移脚本只复制、更新和回滚两张认证表，部分 `materialize` 流程新建的数据库也只有这两张表。它们不是整库回滚。本控制器复制完整 SQLite 文件，完整字节校验覆盖其他业务表，并另核认证表及 schema。

## 输入与执行边界

`mac-current-sqlite-workflow.schema.json` 描述唯一的完整工作流输入。`workflow-plan.template.private.json` 含故意无效的占位 pin，不能作为可执行计划。

真正执行前，外层控制器需要固定以下内容：

1. 已完成且独立绑定的正常 107、原 full34 31 和 DR25 证据；对应 source commit/tree、实际二进制和 QA 文件字节。
2. 当前配置 SHA、完整 agent 列表、原 source 根和 capture parent 的实际 dev/inode/uid/mode。这些值留在本机私有输入，不进入公开报告。
3. Mac 解释器、SQLite 与 `cryptography` 的受控来源。当前已检查的 Homebrew Python 和 Xcode Python 在隔离模式下均未找到 `cryptography` distribution；没有安装或修改它们，也没有据此声称全机不存在其他可用环境。
4. 新鲜、绝对且不互含的 capture、archive、key、restore 目标。原 source 根与 capture 根可以在同一内置文件系统；archive 必须与这两者都不同；key 必须与 archive 不同。只需两个文件系统，例如内盘 source/capture/key 与 T5 archive。实际卷身份和持久介质资格需要外层绑定，`st_dev` 不等本身不是物理电源故障试验。
5. 同一原始 Runtime 作业的唯一输入、截止时间和持久终态。控制器内部 `passed` 文件不能代替 Runtime 的 succeeded/0、非 timeout、非 cancelled、完整持久输出确认。

CLI 只提供完整工作流，没有失败后从某个阶段继续的入口：

```text
<fixed-python> -I -B mac_current_sqlite_capture.py --plan <private-plan>
```

`--validate-only` 仅核输入结构和平台范围，不打开源配置或业务库，不证明磁盘、依赖、数据、writer 或产品资格。实际运行会在读取源配置和创建明文副本之前检查加密依赖可导入。依赖缺失立即拒绝。

## 新定义的预算

这是新定义的三阶段工作流，不声称沿用旧 whole-capture 预算。

| 项目 | 上限 | 约束 |
| --- | ---: | --- |
| 同一外层 Runtime | 900 秒 | 从唯一入口开始，不因失败另起计时 |
| 控制器工作 | 840 秒 | 为清理及回执保留原总预算的最后 60 秒 |
| capture | 300 秒 | 截止取阶段原起点与总体工作截止的较早者 |
| backup | 300 秒 | 没有自动重试 |
| restore-verify | 300 秒 | 总体只剩 240 秒时，此阶段至多 240 秒 |

所有边界、计数及总时长仍需真实 Mac 试验；超时不能以扩预算或续跑旧目录改成通过。失败不开始下一阶段，保留本次所有部分输出、私钥及失败回执。不得删除旧失败目录来取得 create-only 成功。

## 捕获如何保持一致性

每个数据库分别以 SQLite `mode=ro`、`query_only`、显式读事务执行 backup。首次 schema 查询建立该库的读快照，backup 及认证表比较都在同一源事务内。它能读取该事务可见的 WAL 内容，不能用直接复制主文件代替，也不会把活库误当 immutable 文件。

每个闭合副本检查 `quick_check`、完整 schema、页数，并独立读回完整文件 SHA。所有 agent 的 `auth_profile_store` 和 `auth_profile_state` 行也在同一事务内逐行比对。完整非认证业务表由全文件复制及字节校验保护。副本归一为 DELETE journal 并关闭后再复制第二份 candidate。恢复时才对闭合副本使用 `immutable=1`。

原主文件及 `-wal`、`-shm`、`-journal` 家族都记录前后身份。主文件缺席却有 sidecar 时拒绝；全部缺席才记录 absence。零字节主文件仅在整个 sidecar 家族缺席、主文件身份与大小未变且最终再次核实后保留为空标记；已有或晚出现的 sidecar 均拒绝，不能跳过其潜在内容。SQLite 即使只读也可能触及原生 sidecar；控制器明确不声称排除了这类原生写入，不声称原物理文件前后逐字相等。

输入分母为当前配置内所有 agent，加共享库、quarantine 库及两个 transport 库。已配置的非默认 agentDir 需要单独审计，当前实现拒绝。两个 transport 库若存在则拒绝，直到其真实 writer/operation fence 另行闭合，不能静默漏掉。七个安全状态文件在前后各做受控读，内容与身份必须严格相同；没有旧脚本允许的 producer 时间戳豁免。

这是分别一致的数据库快照及一个严格观察到未变化的安全文件集合，**不是跨库原子快照**。两次看不到锁文件、相同统计、无 WAL 或服务 PID 空值都不产生全局写者锁。后续要改变正式同步方向，仍须逐个查明 gateway、relay、刷新/续期、denial producer、定时任务、手动 SDK/operator 和其他客户端的真实 writer 归属及停止/恢复协议。

## 独立备份与完整恢复

捕获 private manifest 绑定实际 source/capture 路径及 dev/inode/uid/mode。完整工作流 admission 首先要求 archive 与 source/capture parent 分别位于不同文件系统；backup 再以已绑定的实际 source/capture 根重复验证，并在完成前复核全部目录身份。只把 key 放另一盘而把 archive 留在原数据盘会被拒绝。

备份使用随机 Fernet key，将完整受保护文件分为 4 MiB 块。manifest、原配置、全部数据库及安全文件的来源/内容摘要都在加密内容里。key 目录与 archive 不互含且异文件系统，key 本身只在独立私有文件中读取和写入，不公开摘要。此处证明的是受控文件权限、目录身份、加密认证及文件系统分离；未证明 HSM/TPM/Keychain、内存清零或真实设备掉电恢复。

恢复在创建目标目录之前认证全部块、逐文件完整明文 SHA 和 manifest，核完整文件/absence 集合，再一次读块写入全新目录并独立读回。随后冷开所有非空恢复数据库，核 schema、认证行、sidecar 缺席及零字节/absent 家族。它使用加密包内认证的原 source/capture 身份，不重新打开已经失去的原路径。本地新增回归实际把原 source 与 capture 路径 rename 隔离后完成恢复。

恢复的 baseline 配置保持原捕获副本的路径投影，尚未启动 SDK或替换生产配置。它证明可重建原捕获世代的完整文件，不授予把旧 credential/denial/lease epoch 覆盖回当前业务库的权力。真正回滚安装必须在业务写者已受控、后续世代冲突已核对、原配置与所有数据库/sidecar 家族作为完整操作受保护时单独执行。

## 原生 KV2 的后续映射

OpenBao raw KV2 的 lossless/native-large 导入需要真实 mount UUID、原始版本记录、删除/销毁元数据及完整协议见证。SQLite auth store 不是这些 raw records，不能把 profile 更新次数伪装成旧 KV2 历史。

当前业务映射只能在上述闭合副本上先生成私有 schema/provenance inventory，明确每个 inline credential、受保护外部引用、policy、denial/epoch 约束与 writer。之后在普通 `native_v6_file` 上用真实授权身份、精确 document schema 与 CAS=0 建立新 KV2 文档，并核真实依赖客户端、TLS、读写/续期/撤销、备份和回滚。应用自身 schema/version 应作为数据保留；不能宣称已有 OpenBao 历史。无法解析或尚未验证的保护引用必须保留为未闭合项，不调用 J3160 或 provider 补成虚构资格。

## 证据与仍未通过的门槛

本地 `evidence/local-controls-r1.*` 保留原 13 项通过；root 独审发现备份盘门槛缺口后，`r2` 的 16 项实测新增了故障域和失去原路径的恢复测试；`r3` 的 17 项实测另覆盖缺少加密依赖时不得读取源配置。host 独审又发现空主文件与 sidecar 的遗漏，新增一项覆盖三种已有 sidecar、空家族正例和晚出现 WAL。`r4` 保留了首次运行器错误：Python `-I -m unittest` 未把当前目录加入导入路径，只运行了一个 loader error，没有执行 18 项。仅把入口改为同一绝对测试文件后，`r5` 实际 18/18、0 failure/error/skip、0.186 秒 unittest，外层仍 60 秒，输入字节前后相同。它只使用 owned synthetic SQLite、两个真实本地文件系统与一个短 Python WAL writer。

Linux 测试默认以 `/dev/shm` 放置合成 archive；Darwin 必须通过 `HEPTABAO_CAPTURE_TEST_ARCHIVE_PARENT` 给出预先创建的私有测试父目录，并为 `TMPDIR` 固定另一个文件系统的私有父目录。两者都远离业务源，测试实测 `st_dev` 不同，不使用 skip 代替。archive/key 的原目录身份仍须可用；当前恢复证据仅允许原 source/capture 消失，并未证明 archive/key 的目录迁移、重装卷或整盘丢失后的恢复。

仍未通过：真实 Darwin 同类控制、受控加密依赖、当前业务完整 agent/writer/同步 inventory、原生 KV2 真实业务导入、原正式服务 owner/manager 准入、独立业务备份/恢复/回滚、各客户端切换及所有备份路径迁移。这里没有 HA 或 AuthBus 资格，也没有旧服务清理资格。

公开输出只包含阶段、计数、固定失败码、预算和明确的资格 false。全部 source path、账号/profile、完整数据库/配置、credential-dependent hashes、私钥及原诊断留在 0700/0600 的私有目录。现有固定 `AUDIT.public.json` 的 94,718 字节未被本准备改写；新增 R11/R12 元数据另存 supplemental。
