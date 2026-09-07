# HeptaBao Threat Model V1

## 1. 资产

root/barrier/recovery/namespace keys、unseal shares、tokens、leases、dynamic credentials、policy/identity、audit records、plugin identity、Raft state、migration authority、qualification/claim/grant/revocation objects、build/signing provenance。

## 2. 对手能力

- 未认证远程客户端；
- 已认证低权限租户；
- 恶意或被攻陷 plugin/provider；
- 可读写 physical storage 的攻击者；
- 网络分区、DNS/TLS/KMS 故障；
- 恶意/错误 operator；
- 被攻陷 CI token、repository admin、dependency maintainer 或 artifact service；
- 可观察日志、core dump、metrics、trace 或 build artifact 的内部人员；
- migration source/target 中任一方被攻陷。

## 3. 信任边界与核心威胁

| 边界 | 主要威胁 | 必要控制 |
|---|---|---|
| network → listener | smuggling、slowloris、oversize、TLS downgrade | strict parser、bounds、deadline、TLS policy |
| listener → core | canonicalization confusion、namespace spoof | typed context、single canonical form |
| auth/policy → dispatch | bypass、TOCTOU、stale cache | revision/epoch binding、deny default |
| core → storage | plaintext leak、rollback、corruption | barrier、authenticated envelope、generation |
| core → provider/plugin | duplicate effect、credential leak、hang | fenced intent、mTLS、sandbox、bounds |
| active ↔ standby | split brain、stale security read | quorum、epoch fence、freshness proof |
| CI → source/evidence | self-modification、token exfiltration、false attestation | read-only exact SHA、OIDC provenance、separate signer |
| Oracle → implementation | source contamination、secret fixture leak | clean-room ACL、sanitization、signed transfer |
| qualification → authority | forged signature、revoked/stale receipt | trust-root verifier、scope/time/revocation closure |

## 4. Abuse cases

必须至少覆盖：sealed bypass、root ceremony replay、token parent cycle、lease resurrection、audit bypass、namespace confusion、plugin fork bomb/output flood、snapshot rollback、stale leader write、migration writer overlap、CI source mutation、signed-object replay、dependency yanked/replaced、debug bundle secret extraction。

## 5. Detection 与 revocation

secret canary、unexpected writer overlap、audit gap、policy bypass、committed-write loss、linearizability violation、invalid provenance/signature、new Critical/High advisory 均触发受影响 scope 的 immediate revocation。Revocation 优先于所有 claim/grant；恢复 authority 需要新 evidence graph，不能简单解除告警。

## 6. Residual risk

风险接受必须签名、限期、scope-bound、可撤销；密码、安全、耐久、分布式和 operator-critical named requirement 不允许 waiver。缺少独立 reviewer 时保持 blocked，而不是由 author/admin 自批。
