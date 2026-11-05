# Linux 控制器第二版：已组装，仍禁用

本版在第一版完整 33 文件输入、19 项隔离清单与阶段约束上，增加了可审阅的 Linux 控制器源代码。第一版 `16d0e8a4f0aa637effecad82fcc2d9e328d33f19` 的原件保留。这里只有离线 AST/compile、字节核对与静态审查；**没有运行控制器、Cargo、组件测试或远端进程，也没有生成可提交的 process request。**

## 关闭原未知作业与取得当前准入是两个条件

`ORIGINAL_UNKNOWN_PREFLIGHT_JOB` 在代码中固定为 `1a1a93e525e-fc05-3335`。新的 `original_unknown_preflight_resolution` 必须明确证明该同一身份已获得权威终态及 owned child 清空，或获得权威“确定没有启动”的证明。目录不存在、超过预期时间、另一个成功作业都不能替代它。

`authoritative_preflight_resolution` 则必须是完整、持久化、未超时且 exit 0 的实际只读预检结果。若这两项最终是同一作业，必须匹配同一成功原始 SDK 回执；若原 3335 确认失败或未启动，必须分别保存它的关闭证据和另一个成功预检证据。任何后续预检都需另行审查，本包不会创建或提交它。资源/归属 review 还必须绑定原关闭记录的规范 JSON SHA256。

当前两个 resolution 都是 `null`，工具链当前 pin、资源/归属结论、模式、实际开始和截止时间也都是 `null`。新输入 `control/candidate-input-r2.draft.public.json` 只比第一版增加上述两个字段。完整控制包 `control/candidate-controller.draft.public.json` 明确保持 `execution_enabled=false`、`process_request=null`、`bootstrap=null`。

## 已机械保留的内容

`OwnedRunner` 完整类从已审 Mac r5 控制器机械提取，逐字 SHA256 为 `2e330d72944e02791b9a15bc91da07c9ca2abac9e9917b4bacf3b502e437f9e8`。它仍以未 reap 的直接子进程作清理身份锚，先收尾进程组再 wait，不在 reap 后发信号。

`read_owned`、`hash_owned`、`retain_artifact` 只把固定 UID 501 改为 ROG 1000，各一处，机械报告记录前后 hash 并检查没有残留 501。其他提取帮助函数保持原字节。Linux 组观察只读取 `/proc/*/stat`，观察错误不会转成“空组”。

原 ROG r6 guard 连续片段保持 SHA256 `b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59`。其 UID、32 GiB 内存/盘门槛、CPU 裕量、外部编译器判断和唯一历史精确编译例外均未改变。原 timed guard 继续拒绝外部编译器和 unit test；新增检查只进一步约束源码/target/cache 的外部占用与普通产品进程。它们仍是当前 UID、当前调用时点的检查，不是全主机预约。

## 控制流程与证据范围

候选固定为 `f80d2d54800ba7e932d91572c084f930af3e5714` / tree `667ae96b264c5e7f4b9290933612125d883b9e69`。实际 source 必须重新证明 clean 7071/ef0 和原 62 pins，然后才可在新的 branch/output 中应用全部 33 文件并核对完整树。原 target 的已有 build-directory 锁只在源码准备期间以只读 FD 持有，Cargo 前释放；不宣称锁住整个 cache 或主机。

新的独立总预算提案为 3600 秒，包含准入、准备、格式化、strict、libtest 编译、命名组件和条件正常链接。3900 秒只供外层监督收尾，不能延长成功资格。旧请求、旧预算、旧结果均不复用。实际开始时间仍不存在。

两种闭合模式分开：`compile_only` 到 strict + server libtest 编译即终止，测试数为零，server/seed 未链接；`components_and_build` 另需当前 ROG fixture 归属证据和 timed 准入，真实 libtest `--list` 确认 19 名各一次，再在各自私有 TMPDIR 中逐项执行一次。任一测试失败阻止正常 server/seed 链接；unknown、超时或清理失败直接停止该 attempt，不重放。

实际 Cargo JSON 的源码路径、目标、特征与 normal profile 用于绑定当前 artifact；独立 retained copy 与原产物逐字 hash 绑定。结束时再次检查实际冻结源码/tree/84 个 pins。这里的代码还没有执行，不能把这些计划字段写成实际通过。

`review/controller-local-syntax.public.json` 是机械提取与本地 AST/compile 回执；`review/controller-static-review-r2.public.json` 是必要窄审记录。两者明确 `driver_executed=false` 与零 product tests。当前仍缺原 3335 关闭证明、实际成功只读预检、当前工具链和资源/归属审查，以及后续独立批准的 enabled revision 和 exact request。

本版不证明 Mac 窗口释放、full workspace、正常 server HTTPS、物理多机 HA、X230 新源迁移、切流或删除旧服务；也不补普通 KV NoForward/TTL 未实现部分和 native-disabled V5 同步错误优先级的覆盖缺口。
