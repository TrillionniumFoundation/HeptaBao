# 21a Linux 可行性：仅 Git 归档核对

## 结论

ROG 的历史独立 normal target 与 X230 的正式 full34 运行包，为追加 Linux 证据提供了基础。**目前没有可原样重放的现成控制器，也没有当前主机空闲或可执行的结论。** 本次只访问固定 GitHub 记录，没有远端 Runtime RPC、进程启动、源码/guard修改、真实凭证或生产动作；没有创建新执行预算或请求。Mac r5 的并发阻断仍保留，Linux 结果也不能替代 Darwin socket 行为验证。

## 已观测路径

| 项目 | 固定归档中的路径或身份 |
|---|---|
| ROG 源码 | /home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/source |
| ROG 独立 normal target | /home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/cargo-target-normal |
| ROG Cargo home | /home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home；这不是独占新目录 |
| ROG 实际 Cargo 路径 | /home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo；所读记录没有 Cargo/rustc 二进制 SHA 的新核验 |
| ROG retained server | /home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1/normal-build-r6/retained-heptabao-server |
| X230 根目录 | /home/qian/heptabao-kv2-formal34-61ff-7071-20261104-r1 |
| X230 源码与 binary | 根下 source/ 与 artifacts/heptabao-server；从 ROG 只读转移的固定源码及正常产物 |
| X230 Python | /usr/bin/python3.12，SHA e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f |

ROG 历史源为 70714605c39014bea93545f7f6aa4217d2a23544 / tree ef0ae63704a06b7dda1038e02abcc3233a2a438f；Git review alias c71b405970544682e7b9b25c91214f66351a767b 同树。r6 严格检查、正常生产链接和 workspace --no-run 均退出 0。正常 server 为 110846072 字节 / SHA 199e2b6a91346db2b61a6066827a0b4ee658991758926ed9c6b50a8f1ea98a71，三个正常 features 为 default/native-v6-ha/native-v6-storage，opt3，debug assertions 与 overflow checks 开启。

X230 历史 full34 记录为 31/31，408 个 owned children 已全部 wait 且组为空，正式 native_v6_file 路径，34 MiB retained payload。这仅属于当时 7071 component。所读 X230 包没有 Rust 编译步骤或独立编译 target 的证据；它可作为后续新 Linux binary 的 synthetic 运行端，不能直接认定为另一个 builder。

## 完整源码差分

候选为 21a521e3e59af291dd2abc6721e8559e06338657 / tree 625b0a5d4e2bce62fe0b014edff9c18f96840a3c。递归比对完整不可变 Git tree，共 26 个不同 leaf：19 个 Rust 文件、2 个 Python 控制文件、5 个证据文件。Cargo.lock、workspace Cargo.toml、rust-toolchain.toml 未变。完整 before/after Git blob、字节数和 tree 遍历记录保存在 source-delta-7071-to-21a.public.json。**7071 不能仅应用最后的 Mac 三文件修复就宣称得到 21a。** 本次没有增加普通 KV clock transport 或任何其他产品源。

## 现成控制器的复用边界

ROG r6 请求位于 c1b2c50ef32a112149dc61bce1685972f32549b0 的 docs/evidence/20261104-unified-61ff-checkpoint-r1/controls/r6-exact-process-start-request.public.json。它是一次旧 r5→r6 的单文件 lint 修复控制器：绑定旧 439c166 源、原 overall-bound/boot、已使用的 normal-build-r6 输出。它不能原样重放给 21a。其 compiler admission 只声明 operator UID 与特定历史外部 Cargo 身份/锁的范围，不声明整机持续预约，也不能代替当前 HA fixture 的窗口交接。

X230 stage/run 控制器位于 dee59223feea40a0633900fdbd496d66c3ea4194 的 qa/evidence/20261104/x230-formal34-61ff-r1/control/。stage 要求 fresh root，run 要求 fresh full34 output，并精确绑定 7071 的源码、二进制、helper 和构建回执；旧目录已经使用。stage 实际使用 rog: 的 Git fetch 与 scp，因此新 X230 transfer 仍可能竞争 ROG/SSH 资源，不能因换主机就跳过协调。

## 下一步仅需补的只读准入

1. 核实当前各 configured host/UID/架构、实际 Python/Cargo/rustc 文件身份，source HEAD/tree/clean、target/cache owner/device/no-alias 与锁持有者；历史成功不是当前完整性证明。
2. 取得当前 HA/测试/编译任务的真实 ownership 与 authoritative 终态/窗口交接。保留原 guard，不从 PID 间隙或仅无 compiler 推断可并行。
3. 确认 ROG 原资源门槛和新独立 source/target 的隔离方法；历史 guard 要求 available memory 与 disk 各至少 32 GiB，load 不超过 CPU 数一半。CARGO_HOME 是共享旧路径，不是 reservation。
4. 若获准，另审 fresh package/key/output、完整 21a tree、原绝对截止、14 唯一命名测试及 actual Cargo artifact/hash；原 r6 请求与已结束预算不能沿用。未准备或启动此包。
5. X230 需先有新候选的真实 Linux normal binary 与完整 provenance，再核源/binary/oracle pins、fresh private root、原 15/360/5 秒业务预算、一次 export/import 和完整 owned cleanup。旧 stage240/outer1800 是历史记录，本报告未新设预算。

当前结论为 conditional feasibility only，ready_to_execute=false、Mac blocker remains、full_replacement_qualified=false。固定来源、原件 SHA256 与完整判断见 evidence-index.public.json 和 feasibility.public.json。
