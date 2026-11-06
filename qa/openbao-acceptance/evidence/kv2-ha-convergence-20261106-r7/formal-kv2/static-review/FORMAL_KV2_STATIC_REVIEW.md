# 普通私有 KV2 接入：静态源码审查

## 结论与证据范围

审查对象是 HeptaBao `9c68b95b152a468ab378b68730e9e3f04e6a7100`，tree `7f4b75930e8491a3110d8c7f8f894cfc0cfc1fdb`。普通 `native_v6_file` 的入口已经存在，配置绑定实际 Shamir 文件存储，初始化、解封和 V6 激活仍是显式操作。现有控制器提供普通 TLS、冷重启、完整原生归档和独立目录恢复的可复用组件；尚不能把临时凭证暂存脚本改一个报告字段就称作长期正式服务。

这是只读源码审查。没有读取私有凭证、业务数据库或私有计划，没有执行产品、改变配置或修改仓库。对实际测试的引用仅限本次会话已有回执，不将源码或单元测试定义当作新的实际通过。当前 SQLite 完整恢复代际的成功由父代理报告；本审查没有再次执行或独立重读该业务代际。

## 1. 真实普通 Service 路径

- `crates/heptabao-server/src/main.rs:77–80`：仅 `--config` 时进入普通 `http::serve`。
- `http.rs:357–365,412–430,595–600`：普通入口明确 `native_candidate=false`，运行时配置校验后调用 `configure_native_v6_storage`；已配置存储不能由 fixture 参数替代。
- `server_storage.rs:26–29,59–94,242–254`：`native_v6_file` 选择 root standalone Shamir file owner。配置要求 `storage.path == data_dir`，拒绝混用 HA、PostgreSQL、Wrapper、外部 KMS 和 SDK provider 等不属于此 profile 的来源。
- `service_native_storage.rs:79–127,133–176`：启动捕获真实目录/文件 custody，`sys/storage/native-v6/activate` 单独执行；选择配置不等于迁移、解封或激活。支持的 live-owner 范围仍须实际检查。

这些路径的不可变源码和 Git blob、SHA256、长度列在 `SOURCE_BINDINGS.public.json`。例如普通配置入口：[main.rs](https://github.com/TrillionniumFoundation/HeptaBao/blob/9c68b95b152a468ab378b68730e9e3f04e6a7100/crates/heptabao-server/src/main.rs#L77-L80)。

## 2. 可复用的初始化、冷启与恢复组件

| 组件 | 实际职责 | 不能继承的额外资格 |
| --- | --- | --- |
| `kv2_271_lossless_native_live.py::NativeInstance`，626–682 | 普通 `binary --config`、显式 native_v6_file、真实 TLS health/init/unseal | 其 CA、随机端口和凭证生命周期仍为合成测试 |
| 同文件 711–722 与 `verify_storage_witness`，329–360 | V6/reader2/逻辑容量、API 与原生存储见证、冷启 | 固定 secret/history/19 版本要改为真实业务清单，摘要仅可留私有 |
| `kv2_native_fresh_directory_dr_live.py::capture_seed` | 停原 writer，导出激活前四文件 seed，分离备份与钥匙 | seed 只是引导，不含后续写入，不能称为当前恢复 |
| 同文件 `make_recovery`、`reopen`、`cli`、`inspect_v6_archive` | 全新空目录/新 TLS、seed stage、官方 2.7.1 CLI、完整 HBV6PK01 包、冷重启 | 不是 HA，不是长期 manager，不是跨封印强制恢复 |
| 同文件恢复负例与当前归档恢复流程 | 错误 key、坏 sealed sums、冷启后仍无异常提交，合法恢复只执行一次 | 实际业务数据还需独立运行，不能复用合成 full34 结论 |

**使用修正后的 QA 基底**：产品分支 9c68 继承的旧 DR 主文件仍含已证错误的物理 `state_bytes >= 34 MiB` 条件。正确 QA 在独立提交 `a25772377e9bfad91564cf6702a26e861fded16f`，tree `d34d344e261811c406f63de56b3a7227c0e0ddf3`；其主文件 75012 B，SHA256 `2271a4ca539e1190b03e95e95d4d1c79414bd852c80ac85e205def2adac74263`。它将逻辑历史证据与物理包长度分开。真实业务的新分母应来自实际数据清单，不能照搬 19 版本或 34 MiB。

`native_snapshot_cli_live.py::inspect_archive` 面向 HBB2/KV1 归档，不能拿来解析 V6；可复用其中 CLI 环境与固定安全错误分类。`heptabao-seed recover-ha` 也不是普通文件归档的直接恢复工具，详见本包的桥审查。

这些 QA 的精确原字节已经在本地 `source-references/a25772377e9bfad91564cf6702a26e861fded16f/` 下提取，12 文件共 356870 B，逐 Git blob 校验。它们仅为实现新控制器的源码参考，**不是可执行完整 checkout**，不能直接在这个摘录目录启动产品。

## 3. 当前凭证暂存脚本的具体缺口

`qa/openbao-acceptance/authbus_current_credential_stage.py` 本身是受控暂存工具，不能直接晋级：

1. 第 23 行硬编码五个代理；`capture:56–110` 只读取两张认证表的 `primary` 行，每表至多一行。`materialize:112–128` 只重建这两表，其他表、完整 schema、索引、触发器和非 primary 行不在恢复范围。
2. `run:162` 重新读取 live SQLite，而不是消费已经完成完整恢复的固定代际。若复用此入口，会把不同时间的源状态混在一起。
3. 第 177 行公开 `documentsSha256=digest(captured)`，这是凭据内容派生指纹。新公开证据必须移除，不能仅做明文子串过滤。第 247–248 行的字符串泄漏检查不能替代该要求。
4. 普通 native_v6_file 启动（184–201）确实正确，但继承 `smoke.Instance` 的随机端口和两天合成 CA；root token 与 1-of-1 unseal share 同存一文件（193–196）。它没有长期 TLS/密钥托管和 manager 启动、重启、开机恢复证据。
5. 第 235–241 行仅验证同目录 SIGKILL 冷启与 auth-only 回滚，未验证当前业务原生归档在独立介质、全新目录的完整恢复。
6. 第 252–254 行 `finally` 必须停止该实例。删除 cleanup 或让临时子进程逃离 custody 不能构成长期服务 handoff。
7. 第 206–210 行的策略无 renew-self；AppRole token 120/180 秒、SecretID 600 秒且不限使用次数。它不证明长期消费者续期、撤销、分发和再登录完整生命周期。
8. 第 263–266 行明确 provider validity、正式切流、完整 OpenClaw 数据库恢复和完整替代仍为 false。应保留这些边界。

## 4. 消费完整 SQLite 恢复代际

已只读查看公开控制器核心 `mac_current_sqlite_capture.original.py`，未读其业务输入：

- `capture:424–566` 依据当前配置和计划完整匹配代理集合，以每个数据库事务执行 SQLite backup，核全 schema、页面数、所有认证行及目录/文件身份。
- `capture_inputs:685–701` 验证私有完整 manifest、原配置代理分母、显式不存在项和 capture 完成回执。
- `restore_verify:867–955` 在目标创建前认证全部密文块，再写入全新目录，核完整文件原字节、schema、cold SQLite integrity、全部认证行和缺失文件族。
- `public_result:404–412` 明确只是逐数据库一致的捕获代际；无跨数据库原子快照、无全部 writer fence、无 capture 后源新鲜度和流量切换资格。

新 KV2 ingest 必须消费已经恢复出的固定 `baseline-state`，并绑定实际 outer terminal、完成回执和最终句柄收尾。不能再读取 live 源来替换其中数据。完整加密 SQLite kit 继续保留；KV2 credential projection 与整库恢复是两个不同交付。

## 5. 最少必要的新控制器工作

1. **代际准入与映射**：核完成代际与私有身份，动态枚举所有声明代理/数据库/安全文件，确定实际 KV projection。认证表应覆盖所有行，缺表、空库、缺失文件族均显式记录。其他 SQLite 表继续由完整恢复 kit 保全；若要宣称完整 SQLite bytes 经 KV2 往返，需要另做分块 manifest 与 whole-database roundtrip，当前仓库没有通用转换器。
2. **普通长期实例**：绑定实际已合格的 normal server/seed 源码、产物和 build receipt；固定长期 TLS/监听身份、0700 owner、真实 Shamir 初始化及 root/share 分离策略。新增经过验证的长期 service manager handoff 和实际重启证据；本次在当前 repo 的 QA 与非 evidence 部署文件中未找到可直接授予长期服务资格的安装控制器。
3. **一次当前导入**：新专用 mount 的每条真实记录用 CAS0 写入，逐条 API 与原生存储见证。部分完成的多 key 代际不得发布 ready/current 指针；最终完成后单次 CAS 发布代际清单。未知结果先只读对账，不自动重放。
4. **当前业务备份/恢复**：保存 preactivation 引导 seed 和当前 full native archive，备份文件系统与钥匙路径实际分离；恢复到新空目录，原 closure 停止且句柄退役。用当前真实清单核 API/raw/metadata、冷启、合法回滚以及错误 key/坏归档无持久提交。破坏性语义负例放在单独受控 key，不销毁业务凭据。
5. **持续运行与资格分层**：仅在实际验证后发布持久私有 KV2 baseline 资格，长期实例须有独立 manager/PID/文件 owner/TLS 观察。所有密文之外的业务内容摘要、root/unseal/credential 值留私有；公开只保留精确分母、结果、边界与源代码/二进制 pin。AuthBus、SDK、provider 有效性、同步 fence、逐机切流及删除旧服务仍独立未通过。

普通 KV2 JSON 入站限额为 3 MiB（`http.rs:90–152`），内部单 value 上限 16 MiB（`state_records.rs:25`）。不能把大 SQLite 文件直接装入单请求或通过扩大上限掩盖映射缺口。

## 6. 历史来源与后续 HA

SQLite 当前代际只能建立来源明确的新 KV2 v1 基线。其 `updated_at` 是源行事实，不能伪作旧 OpenBao KV2 `created_time`、旧版本号、软删除或销毁记录。没有真实 OpenBao 原始历史时，不能生成一个假来源的 lossless bundle。未来真实 OpenBao 源应单独使用实际 raw export、原 mount 身份与全部历史见证。

**后续迁移不是死路，但有明确上限**：普通活动 V6 已有完整 KV2 export，新 Raft 有 pristine native-large import，详见 `ACTIVE_FILE_TO_RAFT_BRIDGE.md`。这是当前 KV2 逻辑历史桥，不是整个 Service 身份/lease 的物理迁移；需要在正式存储设计中保留可导出上限、明确最终 writer fence 和后续真实多机验证。

R13 的 9c68 dev libtest 11 项诊断不是 normal server/seed build 资格，也不替代 Mac 4bde 的实际 normal107 或 a257 的实际合成恢复链。新业务实例必须绑定它实际使用的正常二进制，不能把不同来源的资格混用。
