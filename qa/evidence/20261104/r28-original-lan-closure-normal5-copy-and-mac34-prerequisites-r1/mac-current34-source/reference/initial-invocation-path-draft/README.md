# Current Mac full34: a separate single-node migration and recovery gate

This packet prepares one new Mac T5 fixture against product commit `4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`, tree `eba5e650bd080b8ad41ea52a2bc68867f541d255`. It contains SOURCE and six proposed public `file_info` operations. No operation in this packet has been submitted. There is no `process_start` request, and `BINDING_READY` remains false with all six current metadata slots unresolved.

The retained product is the actual Mac normal61 server at:

`/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-same-root-publication-normal-r2/normal-release-tests-r1/artifacts/heptabao-server`

Its recorded whole identity is 92,398,928 bytes / SHA256 `c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63`. The fixed source is the `source` directory under that same normal-r2 root. The combined Mac normal61, native-build and normal-release receipts are preserved byte for byte. The wrapper requires their exact digests and the Mac runner `3e013354f125cc4c282905beb6347d19f84448a14c304efd576b4d8705e0c2d8`; it keeps the original 44, ingress 7, cold/H2 9 and independent same-root publication 1 fields separate. A Linux schema, old 60 count, missing/failed ABA group, changed source/runner or surviving normal child is rejected by the selected receipt components.

## Why the official input paths are concrete

The preserved actual Mac wrapper `203e9a3f03a6dd52956026267cd3cec8ddcff019` fixed these two paths:

| Role | Previously observed path | Required official SHA256 |
| --- | --- | --- |
| OpenBao executable | `/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016/bao` | `50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c` |
| Official archive | `/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016/oracle-official.tar.gz` | `15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91` |

The old actual controller `caae6c1da91e959a381b4d57396fdc676f4db8eb` and summary `406b17534dd1e7e7e93aa5678ad0762a0bb85295` bind those whole digests to a completed 31-check Mac run on the older b24 product. The summary also records a unique archive member matching the executable, actual official version 2.7.1, verified TLS and pebbledb. This is evidence for previously observed inputs. It is not current file metadata or current 4e808 qualification. All six current `file_info` results are still required before a binding-ready successor can be reviewed.

The proposed Python path `/opt/homebrew/opt/python@3.14/bin/python3.14` comes from the old actual controller's executable argv. That observation does **not** establish that this pathname is presently a regular file. The fixed metadata API rejects a symlink or special target; such a refusal stops this sequence without following a new link, inventing a Cellar path, or changing a request under the same key. A separately evidenced regular Python path can be introduced only in a reviewed binding successor. `/usr/bin/git` is the exact executable in the old successful Mac wrapper. `/usr/bin/openssl` has an independently preserved public whole-file receipt and an actual `req -help` observation advertising repeatable `-addext`. That help observation is not a certificate-generation result.

## Adapter and preparation boundary

The source adapter uses the already reviewed current 4e808 full34 wrapper as its normal61-admission basis and preserves the earlier Mac invocation pattern. The only product process invocation is still the original `subprocess.run(argv, stdin=DEVNULL, stdout=..., stderr=..., env=...)` expression. The complete canonical driver, official launcher, smoke helper, online evidence helper, process compatibility helper and native-large migration worker are retained unchanged in `canonical/`. The full checkout remains the runtime source; these excerpts are not a substitute partial checkout.

The new control root is:

`/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261105-official271-full34-4e808-r1`

The new work directory is its absent `actual-r1` child. A later separately reviewed inert publisher must create the private control root and publish the exact wrapper. Neither the current source checkout nor any previous full34/Phase B work root is modified. There is no X230 transfer receipt or desktop/LAN admission dependency in this local Mac gate. The ROG entry remains unbound because its official input paths have not been evidenced; this packet proposes no second run.

`--prepare-only` is a new read-only phase with a proposed internal 60-second cap and external 90-second cap. It does not import product modules, create the fixture, generate TLS material or start a product. It binds six fixed file identities, full hashes, single-link regular-file status, EOF and unchanged descriptor/name observations; verifies the exact normal61 receipts; and performs only bounded Git commit/tree/clean checks against the actual independent checkout. It is not a new full fsck or 3,914-blob import verification. Those were performed by the independent source stage. Its stable prepared object has a separate SHA256; elapsed time is outside that object.

The later `--run <actual-prepared-sha256>` repeats the original preparation guards and requires the same stable object. Only after that comparison can it create `actual-r1` and invoke the unchanged full34 driver. The future exact request, wrapper publication, ready transition, current metadata, actual prepare digest and live stable key are not supplied as completed facts here. All require root review and an explicit single-run admission.

## Preserved runtime contract and scope

The canonical driver is `kv2_271_lossless_native_live.py`, 49,393 bytes / SHA256 `383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581`, Git blob `87db25eab1258c8a2d7f9047e2009b62404b6259`. All 31 names and business assertions are unchanged. `full34` means 17 retained live versions of 2 MiB each plus the original deleted/destroyed history slots, with wide-integer/decimal raw-storage comparison. It does not promise an exactly 34 MiB compressed archive.

The actual fixture will start one new official OpenBao 2.7.1 pebbledb source and one new HeptaBao `native_v6_file` target on loopback, formally activate the native target before import, export/import once through native-large, compare history and raw storage, cold restart, save a snapshot, make the original post-snapshot CAS mutation, restore once, cold restart again, and execute the original undelete/destroyed/CAS negative checks. The driver explicitly selects 2.7.1 at its official verification and startup calls; the launcher's historical default 2.6.2 is not used for this invocation.

The original HTTP limit is 15 seconds, the original native-large migration worker limit is 360 seconds, and that worker retains its own original 5-second HTTP calls. The runtime external supervisor remains 1,800 seconds. The new read-only preparation budget does not enlarge any of these budgets. No source or tool is compiled, no dependencies are fetched, no timeout is widened and no operation is retried by this adapter.

The standalone full34 path uses `owned_process` with no active `Owner`. Its existing compatibility branch retains and waits the original Popen handles, including the original TERM/KILL behavior. It expressly does not grant the Linux affine/private-admission/kernel-birth receipt. Its failure fallback includes the pre-existing final unbounded `wait()` after a kill; this packet does not relabel that as a bounded 5+5 affine proof. The migration worker separately retains its original group kill and five-second communicate cleanup. The success gate requires the unchanged driver summary, all 31 checks, `owned_processes_stopped`, original child exit 0 and unchanged source/binary. Any missing terminal evidence, unknown outcome or timeout stays failed/unknown and never permits replay under a new key.

This gate can prove a new single-node migration/restore/cold run if actually completed. It does not prove HA/LAN, negotiated HTTP/2, official CLI Phase B, all OpenBao 2.7.1 routes or production replacement. Both earlier Phase B B01 UNKNOWN attempts and all old failed/unknown fixtures remain unchanged. The separate H2 client instrument and CLI cases retain their own admissions and denominators.

## Offline verification performed

The candidate parsed and compiled without importing/executing its module. The three-hunk unified diff strictly reconstructs the complete candidate from its retained current-wrapper basis. Four unchanged generic functions are byte equal. Six complete canonical sources are whole SHA/Git-blob checked and are exact members of the supplied current tree chain. Only the selected receipt-admission function was executed with in-memory archived JSON and a fake file surface: actual Mac61 accepted; nine targeted corruptions and unresolved binding refused. There were 271 recorded source/diff/membership/component checks, zero host operations and zero product starts.

The initial offline verifier selected the wrong membership directory for `owned_process.py`, then the wrong spelling for `openbao271_kv2_native_large_migrate.py`. Both attempts stopped on their membership assertion before receipt components. The corrections use the already retrieved exact tree entries; candidate source, receipts and canonical bytes did not change. These verifier mistakes are preserved in the review note and must not be represented as product failures or ignored actual tests.
