# AuthBus metadata gap v3：四份真实公有回执重新定界

## 版本与证据边界

这是 **新 v3**。本地重置后，v2 扫描器除内嵌 PLAN 之外的主体、原控制器、测试与说明已恢复；原 v2 PLAN 和 289,420 字节 migration manifest 的完整原文仍缺失。本版本不冒用 v2 的源码 SHA、PLAN SHA、冻结日期或旧测试执行记录。

v3 直接以四份从原主机公有文件取回、重新逐字节校验的 inventory 为路径权源。`authbus_migration_gap_source_receipts_v3.json` 记录原文件名称、主机、字节数、SHA 和原观察时间。它不是新的主机执行回执。

| 主机 | 原文件字节数 | 原文件 SHA256 |
|---|---:|---|
| main | 29,580 | `a5083d6c99800054eb50155dafe033fd7429fdec48d8b440569eae5678e62452` |
| macbook-pro | 24,261 | `4445db0b874b12f27a11f2f9dab2d9d261dc6457acf827623f840e1705a560fd` |
| rog | 22,917 | `0a10171367de4b7588177f750e65bddef9219a5769615667b356ad0c1602440a` |
| pocket4 | 17,586 | `7282f921223de2fb7ea32a7c39298322e65d22350f0a8e871ed87e3f3a8da293` |

本地构建和测试阶段的真实主机执行数为 **0**。后续 Runtime 执行必须保存自己的回执，不能将本地冻结等同于生产迁移结果。

## 固定扫描范围

| 主机 | SecretRef 文件 | backup/runtime 引用 | AuthBus binding 文件 | 原缺失 agent | relay 启动项 | relay 依赖 |
|---|---:|---:|---:|---:|---:|---:|
| main | 0 | 17 | 3 | 2 | 0 | 0 |
| macbook-pro | 9 | 10 | 3 | 0 | 4 | 8 |
| rog | 2 | 3 | 3 | 0 | 0 | 0 |
| pocket4 | 8 | 8 | 3 | 0 | 0 | 0 |
| 总计 | **19** | **38** | **12** | **2** | **4** | **8** |

38 个引用由 33 个 backup 引用、4 个 AuthBus runtime 目录和 1 个 Mac relay runtime 目录组成，均直接来自原 `backup_references[].references[]`。原枚举目录自身不因被列为枚举入口而自动加入 allowlist。引用路径去重并排序，原 metadata 作为 baseline 保留。

原回执的 21 个配置 agent scope 仅作为旧观察保留，标记 `freshly_scanned: false` 并保留原时间。fresh missing-agent 检查严格限于 main 已观察缺失的两个目录和每个目录原回执列出的五个文件路径：

- `trillionnium-os-agent`：`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/.openclaw/agents/trillionnium-os-agent/agent`。
- `hepta-luna-teacher`：`/home/qian-qi/.openclaw/agents/hepta-luna-teacher/agent`。

Mac 四个启动项来自 `/Users/qianqi/Library/LaunchAgents/ai.openclaw.authbus-relay.{bridge,egressguard,front,proxy}.plist` 的四条真实原记录。八个依赖取自这四条记录的原 `path_references`：

| 相对 `/Users/qianqi/.openclaw/authbus-relay/` 的路径 | 检查方式 |
|---|---|
| `auth/cliproxy.internal.key`、`auth/nodes.json` | 仅 metadata，禁止内容打开 |
| `bin/authbus-relay-bridge`、`bin/cli-proxy-api`、`bin/egressguard`、`bin/relayfront` | 最多 16 字节判断二进制；仅有 shebang 的脚本可作受限纯代码投影；从不执行 |
| `config/cliproxy.runtime.yaml` | 批准字段的端点和路径投影 |
| `state/bridge.json` | 批准字段的端点和路径投影 |

`x230`、`ai395` 与 private-CI 来源继续列为未检查边界，`paths` 为空；没有推测目录或额外主机执行。main 当前配置中出现的 ai395 provider/model 引用不构成 ai395 主机检查。

## 保留及收紧的读取规则

1. 所有目录路径使用持有的目录 FD 与 `O_NOFOLLOW` 逐级下降；最终 metadata 使用不跟随 symlink 的 stat。SecretRef、CA/role_id/secret_id、Mac auth/key 文件只取 metadata，不打开文件载荷。
2. SQLite 仅检查 16 字节 magic，不使用 SQL，不读取记录。WAL/SHM、凭证文件、私钥、归档只取 metadata；不提取备份，不复制数据库或凭证。
3. 获准的配置文件可能含内联凭证。扫描器在内存中解析并仅输出批准的配置位置、路径、端点主机/端口和非敏感标签，不输出原 JSON、原命令参数、SecretRef selector、任意字符串值或 URL 的 userinfo/path/query/fragment。
4. v3 的所有 plist 环境变量严格 **names-only**，连 `HTTP_PROXY`/`HTTPS_PROXY` 的值也不再投影。v2 曾允许的六个代理环境字段端点例外已经移除。
5. 当前配置或 plist 出现的新路径只报告为未跟随的引用；不会追加到固定读取集合。获准 backup/runtime 根下只做既定深度的受限目录枚举，敏感子树不递归。
6. 读取前后比较持有 FD 和最终名称的 device/inode/size/mtime/ctime，发生替换或变化时拒绝将结果作为稳定投影。
7. v3 修正跨 deadline 的字节计数：`os.read` 已返回的字节先计入 `bytes_read`，再检查原 deadline；超时读取仍失败且不生成成功读取记录。读前剩余额度检查继续约束真实总读取量。

不调用网络、子进程、SDK、provider 或服务管理命令。扫描器 stdout 输出一个 JSON，本身不创建文件。控制器只在全新隔离目录中保存公有源码和执行回执；没有配置、客户端流量、服务、凭证或备份路径修改。

## 源码与绑定

| 对象 | 字节数 | SHA256 |
|---|---:|---|
| `authbus_migration_gap_inventory_v3.py` | 114,576 | `6e36468e50e6f458cd970779c2a1d7dda7aa761547381edacdb5e1d37e34d2ce` |
| `run_authbus_migration_gap_v3_r1.py` | 35,285 | `aec87e40852bf548982c92833eb75ec88ee1ecca108d7c8fe2dc26ee9061354d` |
| `authbus_migration_gap_allowlist_v3.json` | 112,920 | `a9529e978c15c3f6cf578ff55c95ce42174507baaafd9663190af53ecb6476c5` |
| `authbus_migration_gap_schema_v3.json` | 72,022 | `b38acfc637736cb5e0dcf8935882881e3098f0fc4eac630c9ae69423f18e67b4` |

排序、无额外空格的 canonical PLAN SHA：`a37331721a7560b60029c08db9423dd5eda57dc3855c889c492a4a6b79729644`。

canonical source receipt-set SHA：`bf03a5819e325fac277a2de74768c2639dcb9650cf47285d87e77d26a2f1068c`。它绑定四份原回执的名称、字节数、hash、host 与原时间，不是旧 manifest 的 hash。

公有扫描回执 `source_binding` 必须精确为：

```json
{
  "receipt_set_sha256": "bf03a5819e325fac277a2de74768c2639dcb9650cf47285d87e77d26a2f1068c",
  "allowlist_canonical_sha256": "a37331721a7560b60029c08db9423dd5eda57dc3855c889c492a4a6b79729644",
  "original_metadata_receipt": "该主机在 PLAN 中的完整 receipt 对象"
}
```

示例最后一项表示对象位置，实际回执必须是包含 name、bytes、sha256、created_at 的对象。控制器在主机本地验证实际对象相等，验证成功才将公有 payload 返回 main。

## Root 的精确运行方式

root 将上表两个 `.py` 文件按字节上传到 Runtime main 的 `/home/qian-qi/heptabao-next-gates-20261017/`，与冻结 SHA 核对。它们不含凭证。控制器从相邻文件以 AST 提取 PLAN，不为读取计划而 import 或执行 scanner。

只查看计划，不创建目录或调用主机：

```bash
python3 -I -B /home/qian-qi/heptabao-next-gates-20261017/run_authbus_migration_gap_v3_r1.py
```

在已有 Runtime main owner 上实际执行，外层 Runtime timeout 设为 **300 秒**：

```bash
python3 -I -B /home/qian-qi/heptabao-next-gates-20261017/run_authbus_migration_gap_v3_r1.py --execute
```

控制器依次执行 main、`macbook-pro`、`rog`、`pocket4`，后面三台使用固定已有 SSH alias，固定启用 `BatchMode=yes`、`StrictHostKeyChecking=yes`、`ForwardAgent=no`、`PermitLocalCommand=no`、`ProxyCommand=none`、`ProxyJump=none`，禁止 connection sharing 和 forwarding。连接错误不自动更换认证、代理或主机。

| 对象 | 全新执行目录 |
|---|---|
| main controller | `/home/qian-qi/heptabao-next-gates-20261017/authbus-migration-gap-v3-r1-controller` |
| main scanner | `/home/qian-qi/heptabao-next-gates-20261017/authbus-migration-gap-v3-r1-main` |
| Mac scanner | `/Volumes/T5/hepta-vnext-recovery-20261013/authbus-migration-gap-v3-r1` |
| ROG scanner | `/home/qian-qi/heptabao-authbus-migration-gap-v3-r1` |
| Pocket scanner | `/home/alex/heptabao-authbus-migration-gap-v3-r1` |

目录必须全新，mode 0700。现存目录、symlink parent、文件覆盖均拒绝。控制器不删除、不复用旧目录。Mac `/Users/qianqi` UID 501/Darwin，main 和 ROG `/home/qian-qi` UID 1000/Linux，Pocket `/home/alex` UID 1000/Linux。Home/UID 不能区分 main 和 ROG，四机身份仍须与 root 的固定 Runtime/StrictSSH 路径核对。

## 执行上限与退出码

每次 scan 保持原始 20 秒 deadline、24 秒 alarm，单配置最多 2 MiB、代码/投影最多 256 KiB、真实读取总量最多 16 MiB。目录深度最多 2、每目录最多 64 条、目录总数最多 96、条目总数最多 2,048；JSON 结构最多深度 32、20,000 节点。

每台子扫描进程上限 30 秒，transport 45 秒加最多 5 秒清理自己创建的子进程。控制器 210 秒是启动下一台的 admission budget，不是所有序列化/fsync 都包含在内的硬总超时，因此要求外层 300 秒。未知 transport 结果或 wrapper 非零会停止继续启动后续主机，保留现有回执供核对；不自动重试。

| 程序/状态 | 退出码 | 含义 |
|---|---:|---|
| scanner 公有 metadata JSON | 0 | 产出受限观察；可能仍有 missing、error、bounds hit，所有迁移资格仍 false |
| scanner owner/context/顶层错误 | 2 | 不得当作有效完整观察；owner mismatch 在任何 allowlist 路径 I/O 前返回 |
| controller 完成四份有效公有 metadata | 0 | 仅 metadata 执行完成；不代表迁移/恢复/切换完成 |
| controller 保存部分结果 | 3 | 检查 controller 与各 host operation 回执，保留缺失和未知状态 |
| controller 前置条件或未处理验证拒绝 | 2 | 查看公有 error_class/reason；可能需要核对已有新目录中的已执行结果，不复跑同一目录 |

## 公有回执与精确取回

公有 scanner schema 为 `authbus-migration-gap-metadata-v3`。顶层字段包括 source binding、当前配置投影、19 SecretRef 所属主机的 metadata、bindings、missing agents、38 backup/runtime 所属主机引用、Mac relay、显式旧观察、pending boundaries、逐项 gaps、执行计数/读取记录与固定资格字段。完整顶层字段集合受控制器严格校验。

| main controller 中的文件 | 大小上限 | 用途 |
|---|---:|---|
| `public-receipt.json` | 32,768 B | 四机摘要、源 hash、计数、状态、公有文件 hash/bytes |
| `<host>.operation.public.json` | 65,536 B | 该主机执行封套、摘要与分片清单 |
| `<host>.public.json` | 8 MiB | 经主机和 main 两次校验的原始公有 metadata JSON |
| `<host>.public.part-NNN.json` | 65,536 B/片 | 每片最多 36,000 B 解码内容，供受限工具精确取回 |

实际分片文件名以 operation 回执 `receipt_parts` 列表为准，不按示例猜测。每片包含 `offset`、`decoded_bytes`、`decoded_sha256`、`receipt_bytes`、`receipt_sha256`、`data_base64`。按记录顺序解码，先验证每片原公有 JSON 文件自身 hash/bytes，再校验每片 decoded hash/bytes、连续 offset，拼接后校验完整 receipt hash/bytes，再用 `validate_public_receipt` 验证 host、PLAN 和来源。不要对解码后的原公有 JSON 重新格式化后宣称保留原 hash。

stderr 与未通过校验的 scanner stdout 保留在新隔离目录中，公有封套只输出其 bytes/hash/error class；不传输原始错误文本。公有 source code、已验证 metadata 与分片是唯一预期返回对象。

`authbus_migration_gap_schema_v3.json` 是 Draft 2020-12 结构约束。动态 metadata/projection 内部允许生产者字段；它不是通用凭证脱敏器。必须同时绑定冻结的生产者源码和控制器严格的 source/scope/读取验证。当前本地没有 `jsonschema` 包，冻结记录会明确 formal schema-engine validation 未运行；JSON 文件解析、28 项本地测试和控制器严格验证均为实际运行。

所有输出保留：`allClientsAndBackupsMigrated=false`、`backupRestoreQualified=false`、`providerLivenessQualified=false`、`productionCutoverQualified=false`、`legacyCleanupQualified=false`、`metadataOnly=true`。真实凭证读写、AppRole/TLS/KV/Policy/续期/撤销、HA、cold restore、客户端 restart/rollback、逐台切流和旧版删除须由后续独立操作证据完成。

## 本地再生与冻结

`rebuild_authbus_migration_gap_v3.py` 从四份原公有回执和精确恢复的 v2 主体/控制器/测试生成新源码、allowlist、source receipt-set、schema 与两组测试；输入不匹配即拒绝，不尝试恢复旧 hash。独立 `authbus_migration_gap_v3_provenance_tests.py` 对每条固定路径和 baseline 与原回执比对，并验证深度/目录/条目上限。

`freeze_authbus_migration_gap_v3.py` 只运行本地临时测试和 plan-only，把本次真实日志、源码绑定与新冻结回执写到 `local-r8-evidence/`。它不会重造 v2 的执行记录，也不运行任何真实 host scan。
