# 4a 当前工作的五条主线

候选固定为 `4a49405b93c45ab1c25ecba11cde63a7ede20dce`。本件整理已读源码、原始证据与后续验收次序，不修改正在运行的候选，不增加测试分母，不授予新运行、切换或清理权限。

## 当前实际进度

同一 ROG job `1a1b3978da9-fc05-83bd` 的最新 authority4 仍为 running；streams4 无新增字节。正常 release 阶段已生成 server 和 seed，具体保留路径、长度、SHA 及原 payload 引用在 FINITE-ORDER。实际产物 full9/version、完整 BUILD 报告、252/280 运行结果与最后围栏尚未资格。原 observer 已闭合，原 BUILD 仍占 B 的一条 lane。旧 START timeout 与显式同 key conditional admission 历史保留。

## 按原五项目标推进

| 次序 | 主线 | 下一项实际验收 | 完成条件 |
|---|---|---|---|
| 1 | 正式KV2迁移与恢复 | 完成同一4a BUILD全部结果、末围栏、owned cleanup和retained产物metadata。 | 同一候选的实际原档恢复及数据/权限/owner/fence/audit/冷重启验收完成。 |
| 2 | 当前三机HA | 分别闭合当前Linux与Mac产物资格，Mac normal89 unique/117 profile另列。 | 同一current候选在三机的实际HA验收、原进程和观察闭合；不继承旧binary或仅IP对应。 |
| 3 | 实际AuthBus | 绑定current qualified产物、真实信任源/端点与consumer接口。 | 实际业务和owner关闭同时成立；版本或无凭证probe不替代。 |
| 4 | 逐台切换与回滚 | 固定每台当前依赖/备份/rollback身份，具体未迁移consumer或Native API缺口先独立处理。 | 逐台真实切换及可复核回滚/恢复完成，所有实际依赖覆盖。 |
| 5 | 旧版清理 | 活跃消费者全部迁移且rollback保留要求满足后，固定可处置旧资产身份。 | 逐项处置和剩余消费者/回滚资产验证闭合，历史证据保留。 |

近期共同前提是闭合同一4a构建并取得当前产物资格；源码准备可以并行。正式KV2、三机HA与AuthBus的业务结果不能由源码审查、公开诊断或旧版本实测替代。逐台切换依赖相应业务门与当前依赖/回滚基线；旧版清理在迁移和回滚保留要求满足之后。

## 252 个不同用例，280 次 profile 执行

完整名称来自原 groups blob `0a3d746de42bfc31d3072cee1073f3908fc5811c`，原文随包。按 (crate, exact fullname) 去重为252；file28/default235/HA17共280。首四组164 unique、snapshot五组27、原normal九组61，三集合不相交。每族仍600秒，受原12000秒总截止限制；单一1800秒 release 截止包含最多300秒 type-check，随后 compile 共享3600秒，没有重置或放宽。

| 顺序 | 原组名 | Profile | 次数 |
|---|---|---|---:|
| 1 | native-jwt-pki-file28 | file | 28 |
| 2 | native-jwt-pki-default28 | default | 28 |
| 3 | legacy-jwt-default67 | default | 67 |
| 4 | native-auth-identity-default69 | default | 69 |
| 5 | snapshot-body10 | ha-native-v6-peer-ingress | 10 |
| 6 | snapshot-peer7 | ha-native-v6-peer-ingress | 7 |
| 7 | snapshot-actor2 | default | 2 |
| 8 | snapshot-wire4 | default | 4 |
| 9 | snapshot-service-audit4 | default | 4 |
| 10 | ssh25 | default | 25 |
| 11 | mount1 | default | 1 |
| 12 | redirect5 | default | 5 |
| 13 | actor2 | default | 2 |
| 14 | ordinary5 | default | 5 |
| 15 | no_forward6 | default | 6 |
| 16 | ingress_observer | default | 7 |
| 17 | cold_h2 | default | 9 |
| 18 | same_root_publication | default | 1 |

这里仅复算冻结计划的集合；实际每例仍需原 binary 的 exact list 和一次 one-passed 执行。正常 release 成功不能推出测试完成。Snapshot四个Service审计回归包含在27里，不冒称已实际通过。

## 候选 HTTP 35 的现成官方基线

官方2.7.1 ACL23已有23项真实状态与前后transition，12×403、8×204、2×200、1×405；原owner已关闭。省略role策略的实际readback为present=true/[]。这23项没有显式空策略输入、root策略或role no-default发行场景，不能外推到那些语义。

官方strict PKI12已有12项真实原始数值，expired与revoked lease lookup均为400，没有400/404归一化；原4个child已关闭。完整报告 `0cb0f23e1a4484cca6ac65c5597afe3f2ed502bd` 与ACL摘要 `5ebf2743de2e5e96a68c042d80e37f0921cb021e` 本轮均已whole读。候选23+12的实际结果仍为空；它们与252/280分开记录，无需重跑这两份oracle。

## 当前 Native JWT 和远程信任源

本地 JWT service/batch 已有当前实现，等待本轮实测。六个batch用例各在file/default执行，合计12实例；完整名称在 FINITE-ORDER。早期Native batch501描述已经不适用。

远程JWKS是当前formal Native准入的具体缺口。官方精确2.7.1 primary在 config 路径声明 jwks_url/CA、OIDC discovery/CA、本地public keys和skip_jwks_validation，注册read/update，实际检查信任源与加载错误。当前4a `auth_remote.rs` 已有HTTPS/JWKS/discovery准备、外部执行和完成流程；但 `native_v6_jwt_state_supported` 仍要求root/local且remote=None。因此既不能称整个仓库没有remote实现，也不能因legacy实现存在便宣称formal Native支持。

原remote Service测试模块没有列入252/280；本轮remote负例覆盖的是拒绝边界。未来接线应保留原Auth/Namespace/Identity/Actor、mount/config/role及clock捕获；网络在writer/lock外；bounded重入后核原source；paired publication、batch owner、audit与delivery保留。提交后的veto继续UNKNOWN/no replay。只删除remote guard不成立；完整OIDC授权/回调也不等同discovery取JWT key。任何新实现与oracle/candidate对照需另立候选，不改变正在运行的4a及本轮分母。

其他OIDC/Kubernetes/MFA/SDK等状态域的当前Native空集合限制已按精确源码列出。本窄件没有完成所有官方API的映射，不据该guard断言整个仓库无实现。

官方primary：

- [path_config.go，a5db72…](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/credential/jwt/path_config.go)
- [backend.go，同一commit](https://github.com/openbao/openbao/blob/a5db72cef75c24b920ade02065b18dd8eb666bac/internal/builtin/credential/jwt/backend.go)

## 三机身份与资格边界

当前6路Native/SSH已以OS/model/boot和Linux machine-HMAC交叉；独立exact-model审批接受Mac17,2、ROG Flow Z13 GZ302EA_GZ302EA和G1628-04这些OS上报家族label。原comparison的model_label_verified=false保持原字，审批是另一记录。它不是硬件attestation；声明的IPv4不是新的接口采样，端口当时可用不等于预留。身份结果与C新X230 SOURCE29均不会自动赋予当前4a三机HA/full34资格。

## 保留的纯资料错误

canonical index第一次在whole hash通过后被误作JSON解析；原SyntaxError保留，随后按实际LF行/4个NUL字段解析，3932叶/62553956B吻合。本包首次Markdown拼装又在JavaScript解析阶段遇到未转义反引号；该错误同包保留，随后改用普通字符串数组。两次都没有Native、Git mutation、产品或原state修改，不是构建错误。

同包JSON提供完整事实、范围、原groups及来源pins。fullReplacement、productionCutover、legacyCleanup仍为false。
