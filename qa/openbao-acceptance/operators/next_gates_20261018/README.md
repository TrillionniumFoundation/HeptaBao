# 下一阶段冻结 operator 归档（2026-10-18）

本目录保存 24 个按原字节复制的 operator、测试、allowlist/schema 和原说明，供审计及按原前置条件复现。每个文件绑定固定源码、版本、二进制、依赖布局或 owned root；它们不是通用部署器。复制归档不执行测试、不触发远程操作，也不产生新的生产资格。

实际结果以 [公有证据索引](../../evidence/next-gates-20261017/index.json) 和每轮原回执为准。历史失败、原 wrapper false、旧冻结时的未执行说明全部保留；后来的局部通过不覆盖它们。原 secret candidate、凭证载荷、私钥和 token 未纳入本目录。

## 固定版本及已发生的结果

| 范围 | 当前已核验的公有结果 | 限制 |
|---|---|---|
| R8j native physical | 实际尝试两次；第 1 次观察 18 项全通过后终止，第 2 次观察 35 项、34 通过 | 89 项未完成，尚未进入 native leader SIGKILL/重选主/全冷重启；不得盲重跑原 roots |
| R8m Mac | 当前闭包 repair 3 项、archive34 1 项实际通过；2,588 文件运行前后树一致 | 内部 helper/对象包范围，不是 Service/HTTP 恢复或物理 HA 完成 |
| R8n shared-01 Mac | 13 项 shared-object sync 回归实际通过；2,590 文件树 `9277b345ca1f9c1117b03332958b51b7c25ed772` 前后一致，R8m 基础不变 | 仅 shared-object sync 范围；完整 HTTP 性能、34 MiB 链及 HA 未由这 13 项取得资格 |
| AuthBus owned-source R2 | 原 driver exit 0；293 passing events / 292 distinct labels；严格对账支持限定功能证据 | 原 wrapper `ok=false`、唯一标签合同失败保持不变；不证明真实 A→B/provider refresh/全部迁移 |
| migration-gap v3 | 4 份实际 metadata 公有回执有效；源码/PLAN/receipt-set 绑定 | 21 client scope/store 为原 reused 观察；所有迁移、恢复、provider、切流及清理资格 false |

## 相邻文件与原布局

- 保持 `freeze_native_shared_reuse_r8n.py` 与 `freeze_archive_repair_r8m.py` 相邻：前者直接 `import freeze_archive_repair_r8m as helper`。不要为解决导入去修改冻结源码；使用能保留原 sibling import 的调用方式，不盲目加入会移除脚本搜索路径的 isolated-mode 参数。
- 保持 `r8j_native_physical_control.py` 与 `r8j_native_build_freeze.py` 相邻。第二版控制器及其测试也通过文件路径装载原 helpers，保留本目录完整文件名关系。
- 保持 metadata scanner、controller、allowlist 和测试相邻；controller 默认从自身同目录读取 `authbus_migration_gap_inventory_v3.py`，以 AST 验证精确 bytes/SHA/PLAN。
- `freeze_archive_repair_r8m.py` 的默认 repo 是脚本同目录下的 `HeptaBao/`。在本归档布局下不要依赖该默认：使用时必须明确 `--repo <实际仓库绝对路径>` 和新的绝对 `--output-dir`。`freeze_native_shared_reuse_r8n.py` 已将这两个参数设为必需；它只接受冻结的 R8m 基础及三个已审查文件 hash。
- `freeze_authbus_migration_gap_v3.py` 与 `rebuild_authbus_migration_gap_v3.py` 没有 `--repo` 参数；它们保留原 `__file__` 相邻文件、精确 v2 恢复输入以及 `local-r8-evidence/` 布局假设。本归档没有把缺失旧 PLAN 或 private candidate 补造成输入，不应直接将归档目录当作新的执行工作区。
- `authbus_owned_source_r2_reconcile.py` 及两版 physical02 diagnostics 保留各自原输入/输出路径约定。归档的源码可审计，重新调用仍需满足原精确来源及布局；对账脚本不是一次新 credential/HA 执行。

## 已使用的 owned roots 与重跑约束

| operator 范围 | 原固定路径/约束 |
|---|---|
| metadata v3 controller/main | `/home/qian-qi/heptabao-next-gates-20261017/authbus-migration-gap-v3-r1-controller`、`.../authbus-migration-gap-v3-r1-main` |
| metadata v3 Mac / ROG / Pocket4 | `/Volumes/T5/hepta-vnext-recovery-20261013/authbus-migration-gap-v3-r1`；`/home/qian-qi/heptabao-authbus-migration-gap-v3-r1`；`/home/alex/heptabao-authbus-migration-gap-v3-r1` |
| R8j physical02 | Mac `/Volumes/T5/hepta-vnext-recovery-20261013/native-r8j-physical89-02-node1`；ROG `/home/qian-qi/heptabao-native-r8j-physical89-02-node2`；Pocket4 `/home/alex/heptabao-native-r8j-physical89-02-node3` |
| Mac R8m | `/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/source-r8m` 与 `r8m-archive-repair-verify-01`；固定 R8k 基础 |
| Mac R8n shared-01 | 同 Mac 基目录下 `source-r8n-shared-01` 与原 shared-run work root；固定 R8m 基础，精确值见原 summary |
| AuthBus R2 / R2b | `/home/qian-qi/heptabao-next-gates-20261017` 下原 fixture/source packet 和 owner-host private candidate；凭证不从本归档供应 |

这些是已经使用的历史执行位置，不是可复用的空目录。操作前核对对应源码、二进制、完整 manifest、原预算与 owner；未知提交或 transport 结果先按原回执对账。原脚本要求全新目录时不覆盖、删除或绕过该保护；新候选或新执行必须形成自己审查、冻结和回执绑定。

## 精确文件清单

下表 hash 来自本次对归档文件的直接读取；各文件原 bytes 保持不变。README 本身不列入下面的冻结 operator 计数，索引单独记录本说明的 hash。

| 文件 | Bytes | SHA256 | 作用 |
|---|---:|---|---|
| [authbus_migration_gap_allowlist_v3.json](authbus_migration_gap_allowlist_v3.json) | 112920 | `a9529e978c15c3f6cf578ff55c95ce42174507baaafd9663190af53ecb6476c5` | 新 v3 固定四机允许路径；19 SecretRef / 38 backup-runtime / 12 binding |
| [authbus_migration_gap_inventory_v3.py](authbus_migration_gap_inventory_v3.py) | 114576 | `6e36468e50e6f458cd970779c2a1d7dda7aa761547381edacdb5e1d37e34d2ce` | 批准范围 metadata 扫描；凭证载荷不打开、全环境字段 names-only |
| [authbus_migration_gap_inventory_v3_tests.py](authbus_migration_gap_inventory_v3_tests.py) | 14482 | `2457096e0407ca233936dc207cb5611732b317bca3203de6bcf6f84edce00c17` | 原 14 项本地 scanner 验证源码；本次归档不执行 |
| [authbus_migration_gap_schema_v3.json](authbus_migration_gap_schema_v3.json) | 72022 | `b38acfc637736cb5e0dcf8935882881e3098f0fc4eac630c9ae69423f18e67b4` | v3 公有 JSON 结构约束，与源码/控制器验证共同使用 |
| [authbus_migration_gap_source_receipts_v3.json](authbus_migration_gap_source_receipts_v3.json) | 1105 | `9aaae531fa476dd930a5425bd03e3f9cbaaae295008547de154bb590b98f6013` | 四份 2026-10-17 原公有 receipt-set 绑定 |
| [authbus_migration_gap_v3.README.md](authbus_migration_gap_v3.README.md) | 12993 | `0f2ad255d5a80f37c3ff5cc32d30d64a905b78903403bc044b36fde384f4ff71` | 冻结时的原 v3 说明；其中 local freeze/0-host 描述保留历史时点 |
| [authbus_migration_gap_v3_provenance_tests.py](authbus_migration_gap_v3_provenance_tests.py) | 6846 | `bb5554664d8bfecde3675ff17aceea18bfa18c1b4eebf1b0c0edd51df4f0c0b7` | 两项独立来源与目录边界验证源码；本次不执行 |
| [authbus_owned_source_r2_reconcile.py](authbus_owned_source_r2_reconcile.py) | 25882 | `57f5f99ed41708945521480c005ed8438161aeda2c7051515d2ad91245e22642` | 仅公有原件和冻结源码的严格 R2 对账；保留原 wrapper false |
| [freeze_archive_repair_r8m.py](freeze_archive_repair_r8m.py) | 16384 | `463cb139c4e1cd93c37fa42bdafc1814ba57b4334fd4174d8a0ab966bfba8c24` | 从固定 R8k 基础冻结 R8m 精确 overlay/manifest；不是测试回执 |
| [freeze_authbus_migration_gap_v3.py](freeze_authbus_migration_gap_v3.py) | 7705 | `430dbd7528786d50f1989594e7d398e018151774665e573cfcc3160be3bbf5b0` | 原 local-only 冻结器；依赖原相邻源码和 local-r8-evidence 布局 |
| [freeze_native_shared_reuse_r8n.py](freeze_native_shared_reuse_r8n.py) | 5134 | `7ef203b4468186298b008597ca7bb0463c90a4cce0889cdf2764484ec0a641f8` | 固定 R8m 基础的三文件 shared reuse 冻结器；导入相邻 R8m helper |
| [inspect_native_physical02_public.py](inspect_native_physical02_public.py) | 7244 | `27a8ab50dd2b3266ff98f8a3ddc4ed752bf6420b41a7507804994f58b0f656dd` | physical02 第一版固定公有诊断 |
| [inspect_native_physical02_public_r2.py](inspect_native_physical02_public_r2.py) | 7747 | `f00edf4042e763edfc7d0a437e3c30b888fccf33bb1067d632a6b9f59d6c81f2` | physical02 第二版固定公有诊断，版本并存 |
| [r8j_native_build_freeze.py](r8j_native_build_freeze.py) | 14613 | `1f90af9625d8efedf8e15ff42fed599f38b1b068ad968679012dd229b5453e84` | 固定 R8j 完整 manifest 与 ABI 原生构建证据约束 |
| [r8j_native_physical_control.py](r8j_native_physical_control.py) | 10028 | `3cd7c522faf091d7fdbd449641b1c45de4f10b9a07661862a3c6a34eeca9f997` | R8j 第一版固定三机验收控制器；导入相邻 build freezer |
| [r8j_native_physical_control_r2.py](r8j_native_physical_control_r2.py) | 21197 | `28c32d201b656e5bc68f9420bb72b1e9350c4ab408b18485ae0d1037c0501fef` | R8j physical02 query 修订的精确控制器和 owned roots |
| [rebuild_authbus_migration_gap_v3.py](rebuild_authbus_migration_gap_v3.py) | 21214 | `33cd50ea8c59f6d63812ad99dcdc72016af13e6cb3ceae9510a2b828ca03973a` | 从四份原公有 inventory 及精确恢复 v2 主体生成新 v3；不恢复旧 PLAN |
| [run_archive_repair_r8m.py](run_archive_repair_r8m.py) | 32931 | `7b50253a449cf9815cea87236aed00d12e167de02caef6b2abd29bb59487caa4` | 固定 Mac R8m 当前闭包修复 3 项与 archive34 1 项 runner |
| [run_authbus_migration_gap_v3_r1.py](run_authbus_migration_gap_v3_r1.py) | 35285 | `aec87e40852bf548982c92833eb75ec88ee1ecca108d7c8fe2dc26ee9061354d` | 已执行四机 metadata 的固定 StrictSSH controller |
| [run_authbus_migration_gap_v3_r1_tests.py](run_authbus_migration_gap_v3_r1_tests.py) | 10210 | `9bb4dd5758f41a01133d19cadbcae4c8e3dc2e94e02aea42be809ee5b2e6a563` | 原 12 项本地 controller 验证源码；本次不执行 |
| [run_authbus_owned_source_actual_r2.py](run_authbus_owned_source_actual_r2.py) | 9395 | `a5eb681bc5049693207a7583695883e870e1e88ce4acd69b516fd8b706d5995b` | R2 最初版本的 owner fixture operator，独立原版本保留 |
| [run_authbus_owned_source_actual_r2b.py](run_authbus_owned_source_actual_r2b.py) | 10329 | `e499bd67cae460aa1895805043194d22141f8890d6a08806fd3d9c93770d92db` | 实际 R2 执行绑定版本；仅引用 owner-host private candidate |
| [run_native_shared_reuse_r8n_01.py](run_native_shared_reuse_r8n_01.py) | 32770 | `e6bb00b8ce298a273b591e467a7352e10443cf9046f28473a9a61d4cce65a250` | 实际 Mac 13 项 shared-object sync runner；不是性能或 HA 总验收 |
| [test_r8j_native_physical_control_r2.py](test_r8j_native_physical_control_r2.py) | 13429 | `a89d2f878d0f4bedbb355380ea699badf677c6b918b0323d001364cad03b3124` | R8j 第二版 controller 的原本地测试源码；本次不执行 |

旧索引中的 5 份原日志当前未恢复，原名称、bytes 与 SHA 均保留在证据索引的 historical verification 中；不存在的原日志没有被伪造为新文件。生产切流和旧版清理继续未完成。
## 原始组件日志补充回收

[recover_original_component_logs_r1.py](recover_original_component_logs_r1.py)（2,415 bytes，SHA-256 `27f2fd0adca2bcd00765064a72ce49bd755f0ad072ea48a06f58e0ef8332390a`）记录本次实际执行的只读回收操作。它绑定既有日志路径与事先记录的摘要，通过严格 SSH 主机校验取回 R8f、R8k 的原始组件日志；没有重跑测试，也没有读取凭证载荷。对应实际回执为 [r8-original-component-log-recovery-receipt.json](../../evidence/next-gates-20261017/r8-original-component-log-recovery-receipt.json)。原 24 份冻结 operator 的记录保持原样。
