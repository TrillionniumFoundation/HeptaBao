# R47：最终候选的实际阻塞与已闭合观察

截止 2026-11-06 19:43:45 UTC。本轮工作继续进行。**全量替代、正式流量切换、全部客户端及备份迁移、旧版清理均为 false。**

## 当前结果

- 候选仍为 `02b90762b3d6cc8699cc88bffb6f76cb1f07e270`，源码树 `9781e9615ac5fb068d217241c74bb54bf87942cf`。ROG 上 3,932 个源码文件、62,537,554 字节已完整核验，独立 Git 存储、严格 fsck、无共享对象链接。没有执行格式化。
- 三个构建控制文件已发布；其准确 receipt 字节由原发布 stdout 无损重建。没有把这个派生值伪称为独立 Native 文件读取。原 BUILD 入口仍要求当前 receipt 和三个控制文件的完整哈希及 full9 一致。
- 唯一首轮 BUILD job `rog/1a1b2580881-fc05-7da1` 已完整失败并关闭：入口第 470 行发现旧 target 目录不存在。此处早于 stage/control 准入、ADMISSION 创建、Cargo、runner 和测试。**实际编译与测试数仍为零**；计划是 246 个不同测试、268 次 profile 运行、18 组。原失败不重放，不猜目录消失原因。
- Mac 新公共启动探针 job `mac/1a1b25c3c54-fc05-7db1` 的父进程成功完成观察，但 Node 子进程 51494 以信号 6 退出；启动标记、stdout、stderr 均为空。保留退出身份、reap、进程组清空、79 个 guard FD、5 个输入 FD 和原期限均闭合。**观察完成不等于 Node 执行成功**。这不能回填旧 cycle 的业务进度或证明旧 SIGABRT 根因。
- Mac、ROG、Pocket4 共六条 Native/SSH 身份路线全部闭合，三个 pair 一致，原链 46 calls / 12 observers / 16 pages，根独立复算 1,048 项。精确 OS 型号字符串已按一手资料映射；不是硬件认证。端口只在观测时 bind/close，没有保留。**新版 HA、断主、选主、ReadIndex、持久化与重启尚未通过。**
- X230 当前所见容器名为 `heptabao-openbao271-oracle-r46`，镜像引用为 `ghcr.io/openbao/openbao:2.7.1`，报告 mounts 为空。名字不足证明没有真实客户端，标签不足证明正在运行的二进制版本；未读取 NetworkMode，空 published ports 不代表不存在主机监听。当前客户端及备份覆盖仍不完整。

## 后续执行顺序

核对 ROG 的固定构建前提并建立有效的独立 target；读取这次公共 Node 进程对应的崩溃记录；将精确源码 bundle 与控制文件分开传输，在既定大小上限内推进 Mac 构建；随后在同一最终候选上完成 Mac/X230 正式 34MiB 迁移恢复和三机 HA。逐客户端真实凭证读写、重启、回滚与备份路径仍是正式切换和清理的前置。

## 证据与边界

[STATE.public.json](STATE.public.json) 记录机器可读状态；[MOUNT-INDEX.public.json](MOUNT-INDEX.public.json) 逐叶记录本轮 20 个证据包、1076 文件、8278777 字节。证据位于本目录的同级挂载子树。此前官方 OpenBao 2.7.1 的 23 项 oracle、历史 34MiB 与历史 LAN 结果保留在 R46 及其父提交，未作为最终候选的现时通过结果。Native JWT batch 等既有能力缺口继续保留。

本提交只保存证据，不改变生产服务、客户端、凭证或旧版资产。
