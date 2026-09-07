# HeptaBao Evidence Trust Root 与 Verification Protocol V1

## 1. 验证层

`SCHEMA_VALID`、`SEMANTICALLY_CONSISTENT`、`CRYPTOGRAPHICALLY_VERIFIED_AND_CURRENT` 是不同结果。任何 verifier 必须输出达到的最高层和未满足原因。

## 2. Canonical payload

签名 payload 使用明确版本的 canonical JSON：UTF-8、对象 key 排序、无无意义空白、整数禁止浮点替代、时间为 UTC RFC3339、digest 使用 lowercase `sha256:<64hex>`。签名字段本身不进入 payload；schema ID、object type、version 和 domain separator 必须进入。

## 3. Trust root registry

每个 key 记录 key ID、algorithm、公钥、owner identity、role、not-before/not-after、allowed object/scope、rotation predecessor、revocation authority 和 transparency reference。未知 key/algorithm/role/scope 一律拒绝。

## 4. Verification algorithm

1. parse with duplicate-key rejection and resource bounds；
2. schema validation；
3. canonicalize and verify content digest；
4. resolve referenced objects and compare digests；
5. verify cryptographic signature；
6. resolve signer identity and required independent roles；
7. evaluate not-before/expiry and trusted time policy；
8. evaluate global revocation and supersession graph；
9. verify transparency inclusion/checkpoint as required；
10. close dependency receipts recursively；
11. enforce source/profile/scope match；
12. emit immutable verification result with `authority_effect` determined only by object type and policy。

自报 `signature_valid`、`revocation_status`、approval alias 或 CI conclusion 不可替代上述步骤。

## 5. Object separation

- Qualification Receipt：记录证据成熟度，`authority_effect=NONE`；
- Compatibility Claim：只声明 exact profile/version/platform/deviation，`authority_effect=NONE`；
- Authority Grant：唯一可授予 bounded operational action，必须 expiring/revocable；
- Revocation：优先级最高；
- Release Attestation：证明 release artifact graph，不自动产生 runtime authority。

## 6. CI 与独立性

GitHub-hosted Linux/macOS 的两个 job 不自动构成 independently operated reproduction。独立环境必须具有不同 operator、credential root、runner administration、artifact custody 和签名角色，并复现 exact source/tree/lock/profile。

## 7. Offline verification

release bundle 必须包含 schema、trust-root snapshot、referenced receipts、revocations、transparency checkpoint、source/lock/artifact digest 和 verifier version，使隔离环境无需在线查询即可 fail-closed 验证。在线 freshness check 可以收紧结果，不能放宽离线失败。
