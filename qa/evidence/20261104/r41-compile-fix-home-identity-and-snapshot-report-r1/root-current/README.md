# HeptaBao R41：编译修复、Mac HOME 身份检查及快照完整报告

更新时点：2026-11-06 11:27:23 UTC。任务继续进行。本检查点汇集 70 个完整证据包、1226 个文件、24,942,324 字节；完整成员及 SHA256 见 [证据索引](EVIDENCE-INDEX.public.json)，当前判断见 [状态](STATE.public.json)。

**尚未证明可以全量替代 OpenBao 2.7.1，尚未执行生产切换，尚未完成所有客户端及备份路径迁移，也没有授权旧版全量清理。** 已通过的旧基线结果不能自动转移给本轮新候选。所有原始失败、未知结果和后续独立观察分别保存。

## 五项门槛的当前位置

| 门槛 | 已有实际证据 | 本检查点新增结果 | 仍须完成 |
|---|---|---|---|
| KV2 正式迁移和恢复 | 既有 4e808 基线：Mac、X230 各 31/31 的正式 34MiB 测试；含官方 TLS 导出/导入、快照恢复、冷启动及 CAS/delete/undelete/destroy | 2379 候选的 49 文件格式化完整报告、工具及输入身份已核验；23 个变更输出开始逐个实际读取 | 冻结格式化后的候选，正常构建，并用新候选重跑相关存储及转发回归 |
| HA 真多机 | 既有 Mac/ROG/Pocket4 LAN 断主进程、重新选主、ReadIndex、持久化及原密钥冷重启证据 | 保留既有合格范围；本轮没有将它升级成新候选的资格 | 新快照转发路径、多机大文件及必要跨平台回归；不把 SIGKILL 写成物理断电测试 |
| AuthBus 无 J3160 | 原来建立的固定工作流及当前 QA label 清理证据保留 | 原 R1 inert 失败已完整取回；只读核查当前残留 HOME，first5 修复及 r2 全22源已核验 | r2 实际准备、独立验收，随后真实 TLS/AppRole、KV/Policy、五 agent 初冷启动、逆向回滚、续期和撤销闭环 |
| 逐台正式切换 | 既有有限客户端清单及早期迁移收据 | 本轮未切生产流量 | 每台真实凭证读写、重启、回滚；补齐 Pocket4/X230 消费者和所有备份路径 |
| 旧版清理 | 清理过明确归属的临时 QA label | 原 R1 残留及历史失败资产保留 | 全部客户端及备份路径迁移证据闭合后，才删除旧服务、二进制及可再生资产 |

## 1. 正常构建的两个真实编译错误已做最小修复

原 `33b814c7034ec853151b1ff13e7529c83f65ea70` 的 Cargo 退出码为 101。完整原 stderr 显示两个 E0061：PKI 和 SSH 的非 JWT 调用遗漏新增的第十四个生命周期输出参数。失败发生在编译阶段，不能记成运行测试失败，也不能记成 149/166 已通过。

新提交 [025b05a340de841b8161c1120344e86eae30eb97](https://github.com/TrillionniumFoundation/HeptaBao/commit/025b05a340de841b8161c1120344e86eae30eb97) 在这两处各增加一个 `None`，合计 52 字节；其余 3,914 个文件完全相同。它以原 33b 为唯一父提交，位于独立分支 `codex/heptabao-jwt-pki-compile-fix-20261106`，树为 `1d8160c9385f8053b9a683cc1834da0f912e2d37`。

ROG 新源码准备作业 `1a1b07b7e0b-fc05-70ca` 已取得 exit0/full/durable/confirmed，原 7 calls、2 observers、2 pages 闭合。新准备报告的实际 metadata 已取得，固定为 28,125 字节；本检查点时正文独立读取仍在进行，尚未证明详细准备报告或正常构建通过。既定分母仍为 **149 个唯一测试、166 次 profile 实例**。

相关证据：[原编译 stderr](../PKI33b-compiler-stderr-minimal2/)、[原 stderr 根资格](../PKI33b-compiler-stderr-root44/)、[最小产品修复证明](../PKI-twoNone-product-freeze-proof/)、[新阶段原始终态](../PKI025b-stage-terminal54/)、[结果 metadata](../PKI025b-stage-INFO-actual25/)。

## 2. Mac 失败被保留，修复针对目录身份判断

原 R1 inert 作业 `1a1b0702e84-fc05-708a` 在 `home_own_create_preserves_root_object` 处失败。它已经创建 HOME 和写入第一个公共副本，但未完成该副本回读及整个准备过程，因此原 effectUnknown 保留。实际失败点的 current/named 两个 tuple 当时没有记录，后续观察不能补造它们。

新的只读作业 `1a1b0889605-fc05-7138` 已完整闭合：10 calls、2 observers、5 pages，exit0/full/durable，stdout 8,624 字节。当前 HOME 的 dev/ino/uid/gid/mode 与原 prewrite 前五字段相同；当前 nlink 为 3，原 prewrite 为 2。四个当前检查点的 held/name full9 一致。固定 server copy 的 14,052 字节及 SHA256 完全匹配；另外 19 个固定名称各两次 ENOENT。5 个打开的 FD 均 once-close，实际 82 次 metadata、2 次 read，没有 T5/private/服务/SDK 操作。

first5 修复只调整本实例独占创建叶文件之后的目录连续性比较，并在判断前记录 before/current/named full9。当前 held/name 仍要求 full9 一致，操作前的 full9 校验及文件 nlink1 校验保留。组件由根 15 项和独立复现的 peer64 检查覆盖。

新的 r2 SOURCE 使用明确的独立 HOME/T5 路径，保留旧 partial 根。22 源中 11 整件不变、10 仅改固定 namespace、1 manager 加入已审组件；全部严格正反差异和派生 pins 已核验。根80、纯作者182通过，只授权一次原预算内公共 inert 准备，尚无 runtime 凭证结论。三目标独立读取与 runtime exact request 仍须依据本次真实结果派生。

相关证据：[原 R1 失败全链](../Auth-HOME-inert-failure-actual63/)、[当前只读原链](../Auth-HOME-partial-probe-actual66/)、[根资格](../Auth-HOME-probe59-and-first5-15-roots/)、[r2 完整源码](../Auth-HOME-T5-R2-source125/)、[r2 精确准备范围](../Auth-HOME-T5-R2-GO-and-root80/)。

## 3. 快照完整报告已经取回，输出身份单独观察

原 formatter 作业 `1a1b02771c2-fc05-6e9f` 的完整报告为 118,925 字节，SHA256 `5755903ce5696b6745d7af2b27a69a30e0d001697eeb85282df75eb25cea40d8`。BODY0 原 timeout 记录仍为 UNKNOWN；另一次受限的原 key 对照只取得已有 binding，返回 reused=true，并独立闭合原范围。BODY1 的新 7 calls、5 pages 已全部闭合，合并后整件长度、SHA 与实际 metadata 一致。

根149检查确认：49 个原输入及工具/配置身份前后未变，49 个格式化 child 都退出0并被回收，原 50 秒共享预算、10 秒 child、60 秒 supervisor 未变。报告中的 49 个 after 记录与原 stdout 完全一致。

23 个文件发生变化，总计 1,346,637 字节；另26个文件共686,814字节与已经完整读取的冻结源码相同。报告不含输出的 full9，因此后续只对23个变更文件做精确 metadata 和36个版本绑定范围读取。所有块先按字节拼接及核整件 SHA，再做 UTF-8 解码。26个未变文件复用其原完整源码，不声称取得了新的输出身份。

本轮还没有新候选的编译或运行测试结果。原 standby SAVE 的 incomplete_snapshot、standby RESTORE 未达到 baseline 的失败仍未由实际新回归解决。

相关证据：[BODY0 独立核查](../Snapshot2379-BODY0-root48/)、[BODY1 原链及完整报告](../Snapshot2379-BODY1-actual52/)、[根报告149与输出读取范围](../Snapshot2379-output23-GO-and-report149-source121/)。

## 4. 官方兼容性边界继续保留

官方 OpenBao 2.7.1 固定源码显示，JWT role 存储处理支持明确提供的空 token_policies，role handler 中没有当前 HeptaBao 的 actor-policy-subset 限制。旧版 ParsePolicies 对 nil 的 default 特例仍存在；不能把 nil 和明确空数组混为一谈。入口 ACL 仍生效，这些源码证据也不等于允许 root token 发放。

既有 JWT ACL successor、23 个 HTTP 对照案例和 PKI HTTP 对照仍未形成新的完整实际 oracle 资格，未借本次两个编译参数修复一并修改权限语义。参见 [官方策略原件与来源](../JWT-policy-official-primary-source/)、[独立 peer 核对](../JWT-policy-delegation-peer4/)。

## 证据解释与下一步

本检查点包含原始 request、armed/intent、原 SDK、immutable payload/pages、原 stdout/stderr、实际文件及独立根校验。SOURCE、纯检查通过、原生实际结果和生产迁移分别记录。构建耗时、文件路径、identity 或出口成功都不会单独升级成“全量替代”。

下一步继续实际执行 r2 AuthBus 准备与闭环；完成新 025b 构建及149/166；收齐23个格式化输出后冻结快照候选并跑存储/转发回归，再把通过的实现整合到最终最新版，做 Mac、X230 和必要 LAN 多机回归。每台真实凭证的读写、重启、回滚及所有备份路径迁移仍是切流与删除旧资产的前置条件。
