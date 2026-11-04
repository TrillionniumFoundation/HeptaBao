# 三节点正式存储的离线准备与修正

本记录证明 Mac 外接 T5、ROG、Pocket4 的独立节点目录、正常构建二进制、TLS 身份、复制密钥与三节点 HA 配置已经实际准备完成。它不代表节点已初始化、服务已启动、生产客户端已切换或 OpenBao 全量替代已获准。

## 实际准备范围

| 节点 | API / Raft 地址 | 节点目录 |
| --- | --- | --- |
| Mac | 192.168.0.8:8200 / 8201 | /Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1 |
| ROG | 192.168.0.10:8200 / 8201 | /home/qian-qi/heptabao-production-20261104-r1 |
| Pocket4 | 192.168.0.9:8200 / 8201 | /home/alex/heptabao-production-20261104-r1 |

源码为 `33cafa4c6e29f0bde1553e041550d21b4c725d9c`，tree 为 `cdc2376e7b39c1d8bbbeb10a813d58bfe923f336`。Mac 正常二进制 SHA256 为 `d8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20`；两台 Linux 为 `7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba`。这些身份与已完成的正常构建三机 128/128 回归一致，没有启用私有诊断 feature。

每台节点在本机生成自己的 RSA 3072 位私钥；Mac 只接收两台 Linux 的公开 CSR，并以本地 CA 签发含实际主机名和 IP SAN 的服务端/客户端证书。私钥未离开所属主机，CA 私钥留在 Mac。安装时验证了严格证书链、SAN 及本地私钥与证书的公钥一致性。

离线配置中的暂定集群 ID 为 `4f2a8929-0136-47fb-80a8-e99075947410`，节点编号依次为 1、2、3。它尚未绑定初始化后的存储身份；正式 Shamir 种子建立后必须使用其真实 `cluster_id`，保留旧配置并重新绑定三台配置与启动记录。所有节点使用同一份 peer registry，并固定各节点证书 DER 哈希。32 字节复制密钥只通过现有 SSH 的标准输入分发；先在同一 SSH 连接上检查真实主机名、UID、准备记录、证书安装记录、配置修正记录及当前二进制哈希，收到准确的确认后才发送密钥。工具参数、公开证据和仓库没有密钥内容。

## 发现并修正的两个阻断点

初版配置使用 `node/data`，与真实 Native Raft 要求的 `data_dir == storage.path/state` 不符。三台节点均已修正为 `node/state`，保留原配置及原空目录；没有触及已初始化的数据。Linux 最初执行的脚本以 `executed_prepare_linux_node_stage_r1.py` 保留，当前工具源已修正，因此两者不可混称为同一版本。

Mac 原先固定的 Homebrew Python 入口在执行修正前已变为 29 字节的 `synthetic installation marker`，实际 SHA256 为 `eb7f64c44303e2912bef17df23c1c11755d74206f476eb02d9ffd3ecd6ebaf3c`，不再匹配原 `cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43`。首次修正任务在进入脚本前以 Exec format error 失败，未重放该任务。

后续独立核验同一套 Python 3.14.3 中完整的 Python.app 入口：SHA256 为 `7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211`，严格代码签名检查通过，运行库 SHA256 为 `e5728c35bdc26dee85e45b3fb94780afc1c9f97ced6b0af64d54e4eab3422e0a`。仅修订 HeptaBao 的绑定和 launchd 模板，固定这个入口，并保留旧绑定、脚本和模板。实际 plist lint 与保护脚本 `check-stage` 均通过。共享 Homebrew 安装没有被修改，也没有将损坏文件的新哈希当作可执行文件放行。

## 可核验结果

`mac-result.public.json` 为总配置收据，SHA256 `f83c915b24bb87792e88ee8a0c2bd6967f750a5057c101f05e2851520a4f1f62`。ROG / Pocket4 的独立收据分别为 `062cdcb29df625a2efb683e9e4223b76de7d1dd3b26e414dba7a27f8f9f357bd` 和 `044d1a15ab74e82a1d6c51514cfe516b1fad39e87d6edc9976ba44ede752a07e`。三份收据均明确未初始化、未启动服务、未切流量。

三台机器的 `state-path-correction.public.json`、两台 Linux 的 `certificates-installed.public.json`、同一 SSH 会话的身份确认和原始诊断输出一并保留。独立读取各主机的完成收据与 Mac 聚合记录一致。

两台 Linux 的启动保护脚本及 systemd 用户服务模板也已实际生成。两台均通过本机 `systemd-analyze --user verify` 和准确启动参数的 `check-stage`；再调用同一入口的 `serve`，均因缺少激活记录返回 `activation_pin_missing`，确认没有启动服务。它们的收据 SHA256 分别为 `2696a660f402b57b7c86c1acb69b6edf8ca4499e140839c1a1b3566d59f11d5d` 和 `e39a3edabdb1bc5612df2e4b88132e971b53f226791a927b181549715566c40e`。模板没有注册到用户或系统服务目录。

`root_review.py` 可离线复核各主机读回文件的原始哈希、聚合记录、密钥分发前的身份握手、源码/启动脚本哈希、模板检查及未切换的范围。它不执行任何网络请求，也不重放已完成操作。

## 尚未完成的后续门槛

需要把快照 HTTP 响应与 standby 读取的兼容修复、AuthBus 未确认连续轮换修复及正常完整 CI 的结果收敛到同一发布候选，再完成正式初始化/密钥保管、服务启动、真实凭证读写、重启、备份恢复和逐台回滚验证。现有 34 MiB、HA 和 SDK 的分项通过，不等同于所有 OpenBao 2.7.1 接口与部署方式均已覆盖。

旧服务、旧二进制和回滚/备份路径仍保留。删除条件尚未满足。
