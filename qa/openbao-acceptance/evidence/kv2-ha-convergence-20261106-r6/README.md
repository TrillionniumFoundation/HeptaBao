# HeptaBao KV2 → HA → AuthBus：r6 原始失败与源码诊断检查点

## 当前结论

**仍不能证明 HeptaBao 已替代 OpenBao 2.7.1 的实际职责。五个生产门均保持 HOLD。**
本检查点记录新的真实准备、失败和后继只读诊断，保留原始分母及失败结果。它没有完成正式业务 KV2、物理多机 HA、可信 AuthBus、逐机切流或旧版清理。

前一检查点为 [r5 / cfb6b816](https://github.com/TrillionniumFoundation/HeptaBao/tree/cfb6b8164aabc86e3f582736bdb72609be6383f6/qa/openbao-acceptance/evidence/kv2-ha-convergence-20261106-r5)。r5 已发布并独立核验全部 338 个文件，包含原完整 CI 日志与 ROG R11 的实际 107 项结果。本 r6 在该提交之上只新增自己的证据目录。

| 必须按顺序通过的门 | 本检查点真实进展 | 尚未获得的证明 |
| --- | --- | --- |
| 正式 KV2 | 当前私有数据保护计划与 19 个输入实际准备成功；首次整库工作流在进入业务阶段前失败；已找到固定 T5 卷根权限与外层通用目录检查不兼容 | 当前业务数据完整捕获、可认证归档、全新恢复、独立回读，之后还需普通持久 KV2 及真实数据来源/历史映射 |
| 物理 HA | 既有回归证据保留；新的诊断源码已发布 | Mac/ROG/Pocket4 真实断主、选主、ReadIndex、持久提交、重新启动与故障恢复 |
| 可信 AuthBus | 当前本地主机数据来源的准备证据保留 | 独立于 J3160 的凭证信任链、AppRole/TLS/Policy/KV、续期、撤销、密钥保护与依赖客户端 |
| 逐机切换 | 本次没有切换真实流量 | 每台机器真实凭证读写、完整备份恢复、回滚、客户端与同步边界全部无回归 |
| 旧版清理 | 本次没有删除旧服务、二进制或失败输出 | 所有客户端和备份路径迁移、逐项独立验收、可恢复性及保留资产闭合 |

## 1. 新产品提交仅修正 lint 并增加诊断

产品候选为 [9c68b95b152a468ab378b68730e9e3f04e6a7100](https://github.com/TrillionniumFoundation/HeptaBao/commit/9c68b95b152a468ab378b68730e9e3f04e6a7100)，tree `7f4b75930e8491a3110d8c7f8f894cfc0cfc1fdb`，父提交 `4bde9aee03fcd27c59e13607e529b1cee594b249`。

四处变更的内容及 SHA 在 `source-candidate-9c68/source-binding.public.json`。一处把等价的线性存在判断改为 `contains`，处理原 Clippy `manual_contains`；三处把既有阶段观察接入原失败用例的同一次 finalization。原 15 秒请求预算、fault、断言、执行次数和正式响应/授权规则均保留。

这个提交**没有证明 publication 协议故障已经修复**。失败观察按 HTTP >= 500 输出；该用例本来就预期 503，所以出现观察日志不等于测试断言失败。新增观察仅输出固定类别、计数和时间，不输出 reason 内容、凭证、密文或源内容摘要。

Mac 实际 rustfmt 任务 `1a1b1dc9905-fc05-7b2f` 成功：原版工具的 version、format、check 三个子进程均退出 0、原 wait 一次、无未回收成员。该证据只证明格式检查。最终源码通过公开 Git fetch 回读，恰好四个文件、tree、父提交和冻结字节一致。对已写入工作区的完全相同源码做过非破坏性的 Git index 对齐，工作文件未改变；没有把本地 checkout 的拒绝误记为产品失败。

保留格式化前的源码审查与 patch，并明确它们是历史版本；最终格式化 patch 和四文件绑定单独保存。

## 2. Mac 当前私有计划与输入准备：实际成功

私有计划任务 `1a1b1dca238-fc05-7b30` 的权威终态为成功/0，非超时、非取消，输出完整持久。它从当前配置重新构造范围，创建四个私有父目录和三个必要中间目录，关闭九个原目录 FD；两个实际卷信息子进程均退出 0、原 wait 一次且无存活成员。

它没有读取缺少独立原始 SHA/version 绑定的旧私有 admission，也没有声称那个旧文件在历史上保持不变。当前计划及 binding 的内容、配置指纹和私有原生 pin 留在主机。公开证据只保留角色、数量及非内容文件身份。

随后输入准备任务 `1a1b1f38125-fc05-7bad` 成功/0，原 52/60 秒、nice 5。19 个输入是 18 个公开固定输入加 1 个私有 pin 文件，全部独占创建、0600、所有者与逐字回读一致；两个目录 FD 全部关闭，零子进程，零业务工作流。其公开 result 为 6,592 B，SHA256 `749955b1e8a7e0895d1f7a0e81fca263844c9b2e5fa0875b48d90e62dad8512c`。

实际输入最终 outer 控制器为 55,776 B / `4ac1110cb3a065f06a1f408b9b5b0b17565a3e0517a322d380307ab11b5ff88d`，固定输入为 5,386 B / `413027c61091eae87f17ab247930a48a0d7a3f20b105432b15d2826c8dbb337b`。原 capture core 仍为 57,280 B / `9e27369657667dc3360ae276bb62e2d1ad0c6f55f07290d91304d7d396d72972`。

`mac/outer900-static-review` 是较早 53,236 B 版本的静态审查。最终窄差异及固定最终源码在输入包中。准备期间的本地 7 pass + 1 error 观察和后续 8/8 结果原样保留；不能把它们描述成最终 55,776 B 版本的重新执行，更不能当作业务数据恢复成功。

## 3. Mac 首次整库执行：实际失败，工作流未调用

唯一实际任务为 `1a1b1f76336-fc05-7bc7`，原 900 秒 Runtime / 840 秒工作 / 每阶段最多 300 秒 / 60 秒收尾，nice 5。它在约 1.116905 秒后退出 1，非超时、非取消，原始输出完整持久。

独立回读确认：

- `workflow_invoked=false`，整库 capture、backup 和 restore 均未调用，没有启动产品、SDK、provider 或 J3160。
- 原公开 result 为 5,109 B / `c57baaa47b723ed073d09f8297b9e058bd45a4dc9e4741a8a436bd598bc15050`。
- 原最终 stdout 为 4,220 B，包含九个目录 FD 全部关闭的记录；stderr 为 0 B。
- 首个 Data 卷信息子进程实际退出 0，原 wait 一次，无存活成员，gap 数为 0。整个 owner block 仍报告失败，不能把单个子进程退出 0 改写成流程通过。
- 通用 finally 把先前错误覆盖成 `final_owned_custody_incomplete`。原私有记录也没有单独保留首次错误。**首次错误的原始 code 无法恢复，本检查点没有回填或伪造它。**

后继只读诊断 `1a1b1fd3eb3-fc05-7be8` 成功/0，约 0.004356 秒，原 52/60 秒，零子进程，四个只读 FD 全部关闭。它验证原 public/private 记录未变，仅输出固定安全投影：

- 原私有记录已经记下 Data 的真实 diskutil 字段比较通过。
- Data 根为 0755；T5 根的原 stage 与本次后继 lstat 身份完全相同：dev 16777244、inode 2、uid 0、gid 0、mode 0775。
- 原 outer 的 `private=False` 通用目录门仍要求没有 022 写权限位，故与已绑定的 T5 卷根模式不兼容。
- 四个预定 capture/archive/key/restore 目录仍全部不存在。
- 原两份私有 stdout/stderr 均为零字节。没有业务数据库或密钥内容读取，没有文件创建、服务改动或网络调用。

这一后继观察和静态控制流足以确认需要修复的兼容性缺陷，与“原 Data 已通过、未启动 T5 子进程、只持有九个目录 FD”一致；它不是原时刻首次异常的直接日志。后继修复与新执行必须另行收证，不能把 r1 失败改判通过。

## 4. ROG R12：资源预检失败，11 项全部未执行

R12 源码准备 `1a1b1eeff11-fc05-7b8f` 成功/0，15 个 Git 步骤均退出 0，约 3.228985 秒。它使用公开候选 9c68 和原 4bde bundle prerequisite，创建独立新 source 与空 target；旧 R11 source、receipt、根目录和 Cargo home 的身份保持。

实际诊断 `1a1b1f14810-fc05-7b9e` 在约 4.9592 秒退出 1，非超时/取消，输出完整持久。失败为 `other_compiler_present`：

- 编译/测试步骤 0，测试组 0，11 个选定用例全部未执行，原目标案例未调用。
- preflight/postflight 均看见 `cargo` PID 1419419；原记录没有该进程的 birth，未读 argv/env，不能凭 PID 推断归属。
- 当时磁盘空闲 113,849,556,992 B、MemAvailable 28,731,700 KiB 满足原门。只有“无其他编译器”门失败。
- 25 项旧资产的完整 before/after 对象完全相同：22 项匹配，原 3 项仍缺失，0 项新增异常。原缺失的原因和操作者仍未知。
- 目录身份前后相同。没有启动自有 Cargo/测试子进程，不存在“失败后未回收编译器”的证据。
- 原失败目录、target 和证据保留，不覆盖、不自动重试。

本诊断计划沿用真实 CI 的 dev/test profile（opt-level 1、debug info 2、debug assertions 与 overflow checks 开启）、Rust 1.98.0、jobs 1 和默认 features。它只计划运行 timing 10 + 原 cipher 案例 1，各一次；build 最多 3,600 秒、两组各 60 秒、Runtime 4,200 秒、原案例内部 15 秒不变。其 schema 和成功状态也明确不是正常 107 项资格。正式恢复消费者仍要求正常 schema、status passed、正常 server/seed 制品与完整 107 项，不可误收 R12 诊断输出。

R12 原 result 为 34,946 B / `2b8d85d39c2759615f40bec8ee5b4cb630a7c257a8b352b776dbbbc0a115b7d7`。完整 prep、冻结输入、失败终态、独立对账均在对应包中。

## 5. CI 原失败没有被顶层 cancelled 抹除

本检查点保存一次当前 GitHub 原生读回，三个 run 的 jobs 均完整分页，数量分别为 2、2、3。queued 项的 runner_id 为 0、steps 为空；API 中的 started_at 字段不据此解释为已经执行测试。

| Run | 本次观察 | 实际意义 |
| --- | --- | --- |
| [42229582001](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42229582001) | 顶层 completed/cancelled；原 merge、head 及后续 verdict 三个 job 均 failure | 原 merge 3751 pass/1 fail/8 ignored 与原 head 3752 pass/0 fail/8 ignored 后 Clippy failure 均继续保留 |
| [42260689756](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42260689756) | 9c68 的 merge/head 两个 job queued | 尚无新全工作区结果 |
| [42260689736](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42260689736) | 9c68 的两个 workflow-trust job queued | 尚无新 trust 结果 |

原 publication 案例不在旧 107 项选择内。旧 Mac/ROG 107 项通过和 head 全测试通过，都不能消除 merge 上实际的 `actual install observer absent`。原日志仍不足以区分 pre-commit/source/witness/quorum/local gate 等具体路径，没有证据证明原 15 秒预算耗尽。没有通过重跑、增加预算或减少分母来改写该故障。

## 6. 原件、独立性与范围

`INPUT_MANIFESTS.public.json` 记录七个不可变 package tree、原 manifest 字节和独立重算的 tree。`FILES.public.json` 覆盖本检查点除自己以外的每一个文件，列出完整 bytes、SHA256 和 Git blob SHA1。

原件保留在各包；`root-review` 的主代理独立 native status/read/stdout 结果与逐项检查不替代原件。大整数身份通过原 UTF-8 文本保留，不能经 JavaScript Number 重写后当成原始 identity。公开包不含凭证值、私有配置/计划内容、密钥、私有混合请求或其内容指纹。

前期 34 MiB、31 baseline + 25 DR、独立 26 项与 700 个子进程、18 个 capture guard、两个主机各 107 项都是各自明确边界内的证据。它们没有证明正式当前业务 KV2、跨设备丢失后的密钥恢复、全部客户端迁移或真实物理 HA。原三个缺失旧二进制仍构成保留资产缺口，不会因新增构建而自行关闭。

后续继续按 **KV2 → HA → AuthBus → 逐台切换 → 旧版清理**。在当前数据保护闭合和正式普通持久 KV2 之前，不进入物理 HA 验收或切流。所有旧 OpenBao 服务、旧 HeptaBao 二进制、回滚依据和失败输出继续保留。
