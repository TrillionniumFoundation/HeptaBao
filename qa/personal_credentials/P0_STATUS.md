# P0 credential service scope and evidence

Updated 2026-11-06. The integration base is PR #160 at
`8f3dd8353aaf9642ad58f7716b0c14813d09983d`.

## Observed ROG result: selected profile passed 57/57

The frozen personal-credentials candidate below completed the selected P0
profile on ROG with **57 passed, 0 failed, 0 missing**. This is a new observation
for this exact combination; it does not inherit or repair the older 176/181-case
results. The profile took 5.095 seconds and inspected 88 audit records. The
original server and the restarted server were both reaped through their original
handles, with no owned process survivors.

| Bound input | Observed identity |
| --- | --- |
| Source commit | `a1b6ff4506f52082a0893b7167fafb4ff95610be` |
| Source tree | `5f685c1aaf647f016afed0555a6710cd4a76c317` |
| Source content SHA-256 | `a0c7c57850d25ae09aacc2d2ab9b951ddd765d438f570b565559c0b250325307` |
| Cargo.lock SHA-256 | `ef3b19cf8b1b360f7888f11e3e5b1523e464762d6c24ce7e92b64d0d7d5c99a9` |
| P0 profile SHA-256 | `87cdc90d32531f1ef85ec74ec572298461170a98cdace50a482ce306d5926b23` |
| Frozen server SHA-256 | `c27a0c223d227d3b2b5292e1e3ab6cf0230562baee36b6465b22a7ddf17be172` |
| Compiler / target | Rust 1.98.0 (`88d9e12ae178fab0fb5cc050a94da85685d449ea`), `x86_64-unknown-linux-gnu` |

The source was clean and unchanged before and after the build and the service
profile. A separate build receipt records the normal Cargo command, exact
compiler, build environment, source identities and frozen artifact hash. A
separate admission and verification controller then binds that receipt to both
actual server exec inputs in the original-process receipt. These are stronger
checks than source/binary co-presence alone; `source_and_binary_unchanged=true`
by itself does not prove which source produced an existing binary.

The normal build command was:

```text
/home/qian-qi/.cargo/bin/cargo build --locked -p heptabao-server --bin heptabao-server
```

It used `RUSTUP_TOOLCHAIN=1.98.0`, `CARGO_BUILD_JOBS=2`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`,
`CARGO_INCREMENTAL=0` and a separate private `CARGO_TARGET_DIR`.
The validated GCC builtin-header path was supplied as
`BINDGEN_EXTRA_CLANG_ARGS=-isystem /usr/lib/gcc/x86_64-linux-gnu/15/include`;
the GSSAPI and Kerberos headers were present and recorded. No additional
experimental or fixture features were requested. The build completed in
439.466 seconds, and each server was launched through the normal
`heptabao-server --config <private synthetic configuration>` entry point.

The authoritative private evidence root on ROG is:

```text
/home/qian-qi/heptabao-personal-build-evidence-20261106-a1b6ff-r1
```

| Evidence relative to that root | SHA-256 |
| --- | --- |
| `server-build-r1/build.public.json` | `96bad2644072717e73e08440afe65470ff542d159a2d85340951581a4c17ead5` |
| `p0-run-r1/admission.public.json` | `96b26d9e222c66f5ddc2f176909b8b675ad383d4501785b517d15e94e774b38b` |
| `p0-run-r1/result.public.json` | `289338861eaea104c296844a6553a5b4e55d3813577dd9a0d81cb8448b16a6f3` |
| `p0-run-r1/qa-owned-diyzriuj/original-process-receipt.json` | `4ca27ef723062e17a2daef15d30d88d107d40cf50b2858a855d6aeddb00b666f` |
| `p0-run-r1/build-bound-result.public.json` | `a2798606458240e23f6fd99b9f1aaa6b41bc33583ccf1e6f44d1d970a6400f30` |
| `build-controller.py` | `24166f5956bc6ba6f7a6035abde449a129464d31587f4e071e397138dd7bd75d` |
| `p0-bound-evidence.py` | `67ce5772bf2ca0dc19aff81b640594c6b8d5501aed20050d9b03ab17ce389394` |

HeptaRuntime original jobs are `1a1af753aa4-fc05-68b5` (normal server build),
`1a1af7d2bc6-fc05-68fd` (admission), `1a1af7e887f-fc05-6908` (57-case profile)
and `1a1af7f5e10-fc05-6917` (binding verification). Each completed with exit
code 0; no retry result replaced an earlier attempt. Byte-identical public
receipt copies are archived under [evidence/20261106](evidence/20261106/),
including `rog-p0-*a1b6ff.public.json` and
`rog-server-build-a1b6ff.public.json`. The directory's manifest pins the bytes.
`source-a1b6ff4.bundle` preserves the original local commit identity and needs
the public PR #160 base `8f3dd8353aaf9642ad58f7716b0c14813d09983d`.

The joined receipt explicitly keeps `ha_qualified`, `production_qualified`,
`full_replacement_qualified` and `independent_security_review` false.
The selected single-node profile is **observed PASS**; broader P0/LAN/HA and
full replacement qualification remain **HOLD**. Changes after this frozen
commit, including this status-document update, do not acquire its observation
merely by being on the same branch.

## Current acceptance boundary

`p0_service.py` observes one explicitly selected combination:

- Normal `heptabao-server --config` entry point and `native_v6_file` storage.
- Single Linux process, loopback HTTPS, generated private CA, Shamir seal.
- Root namespace, KV2 versioned entries, userpass and scoped service tokens.
- Synthetic values generated in controller memory; no real account material.
- One actual SIGKILL and fresh server process, followed by manual unseal.
- Source content, lockfile, script and executable hashes recorded; all original child processes are waited and their sessions checked for survivors.

The fixed denominator is 57 observations. The profile checks normal reads;
path, namespace, unauthenticated and write denials; real clock expiry; explicit
revocation; CAS conflict nonmutation; one-use wrapping; cold recovery of versions,
valid user authorization and prior denials; recovery of a write whose response
body was deliberately discarded; and secret absence in audit, diagnostics and
persisted files. It parses the audit stream and observes audit growth for a deny.

For the discarded-body case the harness has observed successful HTTP status
headers. It does **not** claim an unknown network commit was resolved. CAS prevents
a duplicate version when the recovered write is submitted again.

This profile does not qualify HA/Raft, cross-host failover, AuthBus transport,
OpenBao differential compatibility, full replacement, personal vault recovery,
production operation or adoption of real credentials. A passing report applies
only to its exact recorded source/binary/environment combination.

## Running the finite profile

Build with the repository's declared Rust 1.98 toolchain and lockfile. CMake and
C build tools are required by the existing AWS-LC dependency. Bound compiler
parallelism to the machine's memory budget; the current small executor uses two
jobs.

```sh
CARGO_BUILD_JOBS=2 cargo +1.98.0 build --locked -p heptabao-server --bin heptabao-server
install -d -m 700 /absolute/private-p0-work
python3 -B qa/personal_credentials/p0_service.py \
  --source-root /absolute/HeptaBao \
  --binary /absolute/HeptaBao/target/debug/heptabao-server \
  --work-parent /absolute/private-p0-work \
  --report /absolute/private-p0-work/result.public.json
```

The output report must not exist. Keep the work and report directories outside
the source tree. The harness fails if source or executable bytes change during
the observation. Source changes made in parallel by other work require a new,
explicit run; an old report must never be relabeled as covering the new tree.
The private fixture remains for inspection and is not automatically deleted.
Keep an independently recorded build receipt and verify its artifact hash
against the executable inputs in the original-process receipt before calling
the result build-bound. A path named `target/debug/heptabao-server` or an
unchanged source tree alone is insufficient. Any new run needs a new private
work directory, report path and runtime request identity; the completed ROG
`r1` paths and identities above are retained evidence, not reusable run slots.

## Reconciled older receipts

These are **historical observations**, read from their original ROG paths on
2026-11-06. They are not results for PR #160 or the personal-credentials
integration. Their previous pending/unknown label can now be replaced with the
recorded terminal failure, without rerunning either request.

| Original combination | Terminal result | Remaining failures |
| --- | --- | --- |
| ROG r1 source `9208e0765f566f3bd7908e6567d2e39008156b9b`, tree `3a353adca3300eb46dbe8622c36eaa1f6d3fa7ce` | **174/176 passed, 2 failed, 0 missing**; original 60 denominator: 59 passed | Native snapshot HTTP redirect; non-root snapshot ACL/history-restore actor |
| ROG r3 source `6b16a9292d046bbc42aec65045fa105aaa1ac5de`, tree `0de9c516e94a47cb89e2e0f5ac2146e60913cfef` | **180/181 passed**; original 176: 175; original 60: 60 | Non-root snapshot ACL/history-restore actor |

ROG r1 original report:
`/home/qian-qi/heptabao-replacement-unified-20261105-r1/regression-aggregate-r1/result.public.json`

SHA-256:
`6804101a1d42b186f1a082e2f9f7d12a58b1ca3dddd0019f74926d0e979d2c5e`

ROG r3 original report:
`/home/qian-qi/heptabao-replacement-unified-20261105-r3/regression-r1/result.public.json`

SHA-256:
`64e2b5cc57005ceb8a6c24cd8ca1033b4fc3c3e7a28236804123a39882cd00f5`

Exact failed tests retained:

```text
http::snapshot::redirect_tests::native_http_redirect_has_exact_safe_location_and_no_upload_read_or_response_body
service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor
```

The second name remains failed in r3, in `test-0128.public.json`. The r3 aggregate
reports `source_unchanged=true` and `all_owned_groups_empty=true`; both aggregates
report `full_replacement_qualified=false` and `production_changed=false`.
The r1 aggregate also keeps `full34_allowed=false` and `ha_live_allowed=false`.

x230's
`/home/qian/heptabao-formal-kv2-r3-preflight-20261105-r1/result.public.json`
records an **observed preflight**, not a completed formal-34 migration run.

## Outstanding qualification work

PR #160 addresses three official differential profiles rejected at private
process-root admission. It does not close the full qualification workflow's
other failures. The exact-head full workflow, the non-root historical snapshot
actor regression, native HA shutdown, Unicode decoding and non-root OpenAPI
visibility require their own current-combination evidence.

- [PR #160](https://github.com/TrillionniumFoundation/HeptaBao/pull/160)
- [PR #159](https://github.com/TrillionniumFoundation/HeptaBao/pull/159)
- [Original qualification workflow](https://github.com/TrillionniumFoundation/HeptaBao/actions/runs/42011051329)

All broader P0/LAN/HA and full replacement qualification remains **HOLD** until
its explicit support scope has current, complete receipts.
