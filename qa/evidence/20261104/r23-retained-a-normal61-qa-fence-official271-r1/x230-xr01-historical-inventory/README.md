# XR01：X230 既有公开 runtime/config 报告的精确读取

结果为 PASS_EXACT_PUBLIC_REPORT_RETRIEVAL_ONLY；只有一项 file_info 和一次同 version 的 binary_read。
完整报告 11,770 B，SHA256 df94b577ce539fa23316d686c287b8aaeb8f6f3ee2561a5d1875368c8420dbff。

实际原报告创建于 2026-11-04T04:56:35.468832+00:00；scope.filesystem_roots 只有 /home/qian/.openclaw/openclaw.json。
该历史路径在 credential_binding_path_preflight 返回 FileNotFoundError / errno2；报告没有解码配置，configured_agents=[]，status=bounded_observation_with_gaps。
它没有逐层 held-parent 或双 ENOENT 证据，不能区分叶与哪个缺失祖先，也不能据此声明当前全机无客户端。
此次读取仅取得这份历史公开报告，未访问上述当前配置或任何第二路径；所有历史 query/process/listener 字段均留在原文，不作为本次新观察。

file_info 成功提供 regular/no-symlink 准入，依据工具明确合同；mode384只作为实际权限值，未用它推断文件类型。
两 operation 均已 completed / stored_observed，原生 SDK 各一页完整 SHA 验证，原内容/metadata/version/EOF全部相符。
未创建 process job，不伪造 process authority exit0 或 API 内部 FD 账本。原 complete/native isError=false 与操作状态保留。

recovered-readset.public.json 保存实际一条名单与原缺席语义。其可选下一 metadata 合同仅为 SOURCE，未提交。
本包不变更原 finite plan，不升级 X230 当前客户端、生产迁移或删除资格。
