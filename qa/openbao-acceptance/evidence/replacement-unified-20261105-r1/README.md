# HeptaBao replacement: frozen Mac R1 regression evidence

本记录固定第一次合并候选的**失败结果**，不代表后续候选，也不授予生产替代、切流或清理资格。原始测试分母、失败、日志、控制器和进程终态均保留。

## 固定源码与真实构建

- Candidate commit: `9208e0765f566f3bd7908e6567d2e39008156b9b`
- Candidate tree: `3a353adca3300eb46dbe8622c36eaa1f6d3fa7ce`
- Merge parents: `df026fe323dd7cf0f0ec57d7d2d9c5a79897053c`, `f80d2d54800ba7e932d91572c084f930af3e5714`.
- Actual producer: Mac, aarch64-apple-darwin, Rust 1.98.0; source and retained artifacts verified before and after execution.
- Normal default features: `default,native-v6-ha,native-v6-storage`; no fixture storage flags.
- Release profile: opt-level 3, codegen-units 16, LTO false, debug 0, debug assertions and overflow checks true, panic unwind.
- Server SHA256: `70b0e8dc6c785c0098ea7980258fcca9e966253b979b0c01c8c2ff27928a333e`.
- Server libtest SHA256: `ba7bf627dfa1406c6b9bf727b4139c2422798c11ab6f392563bc7822e8eee8a8`.
- HA libtest SHA256: `aad04c6fb205be71473779749fff21f5f315edd0f3e7f2681954019c14c07bc5`.
- Build result SHA256: `aad77d0e806fe1718e4e77e8c3c4a701fc7fc83fe3ea59fed6ff500074facf7c`.

The server, seed executable, server libtest and HA libtest were actually built and retained. Build CPU/RSS measurements in the receipts describe compilation, not service runtime performance.

## 完整结果

| Suite | Passed | Required | Authoritative executor result |
|---|---:|---:|---|
| Server exact tests | 160 | 167 | failed / exit 1 |
| Original sixty, included above | 59 | 60 | one original redirect regression |
| HA service exact tests | 9 | 9 | succeeded / exit 0 |
| Aggregate | **169** | **176** | **failed / exit 1** |

Server executed 166 required tests. Six failed with libtest exit 101. The seventh non-pass was absent from the actual Mac libtest inventory and remains in the denominator. No failed test was retried. Test processes were reaped and their owned process groups were observed empty. The original request deadlines and suite budgets were unchanged.

The six actual failures were not executor timeouts:

| Original record | Exact test suffix | Elapsed seconds | Actual failure |
|---|---|---:|---|
| test-0028 | native_http_redirect_has_exact_safe_location_and_no_upload_read_or_response_body | 0.586485 | expected safe bodyless HTTP 307; synchronization logged 503 |
| test-0123 | formal_native_standby_snapshot_read_restore_validation_and_no_forward_use_real_owners | 17.305929 | formal TLS original deadline |
| test-0124 | formal_native_standby_snapshot_finite_tokens_redirect_without_consumption | 17.599026 | formal TLS original deadline |
| test-0126 | formal_native_standby_ttl_snapshot_commits_real_leader_floor_and_survives_cold_restart | 19.259591 | formal TLS original deadline |
| test-0128 | formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor | 24.360480 | formal TLS original deadline |
| test-0132 | formal_native_http_consistency_forward_restricts_local_snapshot_and_no_forward_kv | 17.330724 | formal TLS original deadline |

The missing test was `service::snapshot_transfer::tests::native_seal_reader_rejects_linked_nonprivate_and_oversized_metadata`. This candidate declared it only under `target_os = "linux"`; its absence on Mac was recorded as `not_run_missing_from_libtest`, never counted as a pass or removed from the manifest.

Full names, individual invocation receipts, original stdout/stderr, exact inventory, manifests and cleanup observations are included in the bundle.

## 可独立复核的证据

- [Aggregate result](mac-regression-result.public.json), SHA256 `6932f1089a9e34da164abd315f15a77c0f676a91805b4e255f6b24d17e98948f`.
- [Executor terminal observations](mac-runtime-terminals.public.json), SHA256 `69b233e4e92e706650e6aa276f8b8ecc0d1cb1aa1c885cee06dff0d0dc5d1d4a`.
- [Complete regression evidence archive](r1-regression-evidence.tar.gz), 316257 bytes, SHA256 `6de61dab0f264257aade12b492058caa0b2ef330c84cd02e3a126536d3ed090a`.

The archive contains 724 original synthetic regression logs, public receipts and controller files, plus `MANIFEST.public.json`. The manifest SHA256 is `a0f11db21600647f5c97a2ce43e58cffb08c416c9b9e290f3d4e608f4212d5d8`. Every member was read back and matched to its recorded SHA256. Production credential stores, production snapshots, key material and client configuration payloads are excluded.

The independent executor observations confirm terminal publication, complete durable output and no truncation for:

- Server: `mac / 1a1aa2e11a8-fc05-3ebe`.
- HA: `mac / 1a1aa34ea49-fc05-3f1e`.
- Aggregate: `mac / 1a1aa35e85c-fc05-3f2c`.

Verify the downloaded archive without extracting files:

```python
import hashlib, json, tarfile
from pathlib import Path

path = Path("r1-regression-evidence.tar.gz")
assert hashlib.sha256(path.read_bytes()).hexdigest() == (
    "6de61dab0f264257aade12b492058caa0b2ef330c84cd02e3a126536d3ed090a"
)
with tarfile.open(path, "r:gz") as archive:
    raw = archive.extractfile("MANIFEST.public.json").read()
    assert hashlib.sha256(raw).hexdigest() == (
        "a0f11db21600647f5c97a2ce43e58cffb08c416c9b9e290f3d4e608f4212d5d8"
    )
    manifest = json.loads(raw)
    assert len(manifest["entries"]) == manifest["file_count"] == 724
    assert len(archive.getmembers()) == 725
    for row in manifest["entries"]:
        content = archive.extractfile(row["path"]).read()
        assert len(content) == row["bytes"]
        assert hashlib.sha256(content).hexdigest() == row["sha256"]
print("All 724 original evidence files verified")
```

## 验收边界

This candidate failed the complete regression prerequisite. No full34 migration or physical Mac/ROG/Pocket4 HA qualification was launched from it. The nine HA component tests are not physical-host HA evidence.

The required order remains **KV2 → physical HA → AuthBus independent of J3160 → per-host real credential/client/backup/rollback verification → traffic cutover → cleanup**. Historical isolated 34MiB results and partial SDK tests do not satisfy those gates. All production replacement, traffic cutover, all-clients/all-backups migration and cleanup flags remain false for this record.

Subsequent fixes or test-harness diagnoses must carry their own frozen source identity and new results. They cannot rewrite this failure record.
