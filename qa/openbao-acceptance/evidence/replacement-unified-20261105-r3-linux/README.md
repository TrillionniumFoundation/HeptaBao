# R3 Linux complete regression evidence — failed 180/181

This record preserves the actual ROG/Linux execution of source commit
`6b16a9292d046bbc42aec65045fa105aaa1ac5de`, tree
`0de9c516e94a47cb89e2e0f5ac2146e60913cfef`.
It is a failed candidate record. It does not qualify R3, R5, physical HA,
production storage, AuthBus, traffic migration or OpenBao replacement.

| Cohort | Actual result |
| --- | ---: |
| Server cases | 171/172 |
| HA library cases | 9/9 |
| Combined original plan | 180/181 |
| Retained original 176-case cohort | 175/176 |
| Retained original 60-case subset | 60/60 |

The archive contains all 181 planned per-case records, original stdout/stderr,
process and intent receipts, exact manifests, source acquisition evidence, normal
release and both libtest build evidence, aggregation inputs, and the original
executor terminal records. The failing test was not omitted or relabelled.

## The preserved failure

Case `test-0128.public.json` is:

```text
service::native_v6_ha_pipeline_tests::historical_restore_tests::cold_dr_tests::standby_http_tests::acl_denial_tests::formal_native_nonroot_snapshot_acl_and_historical_restore_use_original_update_actor
```

The Linux case failed in 3.7332072049903218 seconds with the original publication
counter equality assertion. The observed root publication was generation 46 /
index 105 while the asserted earlier root was generation 38 / index 89.
The original case record remains `status: failed` and
`exact_one_test_proved: false`; its subprocess failure is not converted into a
timeout, retry, skipped case or pass.

The matching Mac R3 failure, the later additive R4 diagnostic, and the explicit R5
semantic change are separate evidence sets:

- [R3 Mac failed complete regressions](https://github.com/TrillionniumFoundation/HeptaBao/tree/08d70687490561145c994b62818c2b23d4075b17/qa/openbao-acceptance/evidence/replacement-unified-20261105-r3)
- [R4 original-assertion diagnostic, still failed](https://github.com/TrillionniumFoundation/HeptaBao/tree/7380f9c36ea5a8889fa7df481973b74f3f75419e/qa/openbao-acceptance/evidence/replacement-unified-20261105-r4-diagnostic)
- [R5 Mac complete regressions and semantic-change disclosure](https://github.com/TrillionniumFoundation/HeptaBao/tree/551fe5928705ec30c2db3b08f997834d08f1ae28/qa/openbao-acceptance/evidence/replacement-unified-20261105-r5)

R5 changes the assertion's treatment of legitimate precise-auth-clock
publication while retaining the post-204 baseline and comparing the full
relevant state and lineage. That is a disclosed assertion change. It does not
retroactively make this R3 result successful.

## Exact executable and result bindings

| Object | SHA-256 |
| --- | --- |
| Normal Linux server | `406d6b4a13d788b5d465adc9a0eefae8bc393247e87184297284fba90ed4a2ca` |
| Server libtest | `a96c3acd94206e2777cd83bb21858e4e21c781bc6aed87748bc38dd5b3985efb` |
| HA libtest | `bc928e5c2072bbaed1d17bdd5aa4036f2b2ae084ada028a8c05f62c31b795fb6` |
| Server result | `33a2ee0427b61770c7531d5c3c45973dafa40b8cbb28eee06cb810769ab2c641` |
| HA result | `ac51b0ed2f26ff151507319c45f668b38484c21bba8f68af35ff6511a0c3b828` |
| Aggregate result | `64e2b5cc57005ceb8a6c24cd8ca1033b4fc3c3e7a28236804123a39882cd00f5` |
| Server manifest | `ee44d8dc29f0762b532d13af3ecf2417638855e9464ca0bb052ae3f2dd35ba9e` |
| HA manifest | `132ae0404e4d40ac9adc159533176b0e54d4ab1b32928aabf8b9b977c2e15287` |

The source HTTPS acquisition failure is retained alongside the subsequent
exact-source bundle and Git proof. The archive includes the following original
executor records; the recorded failed states remain failed.

| Stage | Host | Original job | Exit |
| --- | --- | --- | ---: |
| HTTPS source acquisition | rog | `1a1aa685760-fc05-429a` | 1 |
| Git proof | rog | `1a1aa7c0e7b-fc05-4398` | 0 |
| Exact source bundle stage | rog | `1a1aa814acc-fc05-43c4` | 0 |
| Normal release build | rog | `1a1aa82b347-fc05-43d2` | 0 |
| Manifest transfer | mac | `1a1aa8a5ebe-fc05-4427` | 0 |
| Libtest builds | rog | `1a1aa91b49a-fc05-447b` | 0 |
| Server 172-case sequence | rog | `1a1aaa75193-fc05-45ad` | 1 |
| HA 9-case sequence | rog | `1a1aab059ea-fc05-4619` | 0 |
| 181-case aggregate | rog | `1a1aab33244-fc05-4645` | 1 |

Independent root observations of the server, HA and aggregate terminal states
are included beside this README, with the archive packaging and independent
cross-machine readback terminals. Complete/durable output proves that the
recorded result is available; it does not turn a failed exit into success.

## Archive contents and independent verification

- Archive: `r3-linux-regression-evidence.tar.gz`, 458,728 bytes.
- Archive SHA-256:
  `e24608f93b097a0d0e901fd441d559d0cd33328a106ca2b9339f341ffab90364`.
- Embedded manifest SHA-256:
  `d3dd2dfa3ab43be0c6d1b49185b87b3f31d915a7dc5d712c9d60edc0c73fcea9`.
- 827 original evidence entries plus `MANIFEST.public.json`: 828 regular archive
  members, with no duplicate or traversing names.
- Aggregate member: `regression-r1/result.public.json`.
- Suite members: `server-regressions-r1/result.public.json` and
  `ha-regressions-r1/result.public.json`.

The packager used a public-file allowlist, four positive controls for the
sensitive-pattern scan, deterministic reconstruction, per-member readback and
unchanged-input checks. The scanner establishes only its explicit pattern scope;
it is not a proof about every possible secret representation.

The archive was stored as data on the existing TOSHIBA volume. Its no-execute
mount flag was not changed. A bounded read-only SCP transfer copied the exact
archive and manifest to Mac/T5, where a separate process independently verified
all 828 member names, all 827 evidence sizes and SHA-256 values, the embedded
manifest, and the aggregate's exact source/denominator/failure fields. No
regression or product process was rerun by that verification.

The independent readback file has SHA-256
`4ca167dfc11eb5d1f7d2945d27fcc17ce6b07908f25e4c87478acd073be2931b`.
Four output-range reads initially failed to return the expected shape. Those
same byte offsets were reread from the same completed export job; the archive,
tests and export process were not restarted.

## The packager's own failed first attempt

The first new archive attempt, job `rog/1a1aaf735fc-fc05-491b`, failed before
producing an archive because its source-acquisition digest literal was
mistyped as 62 hexadecimal characters. The original evidence file was unchanged.
The corrected, separately retained packager revision validates that every pin is
64 hexadecimal characters before use. Its successful packaging job was
`rog/1a1ab02efb3-fc05-496b`.

Both the first packager and its failed stdout/stderr/terminal record, plus the
explicit correction, are preserved under `revision-history/` in the archive.
The actual source-acquisition digest is
`f46a47be73a5aa92bee9b394242febe6f26dc0dc9ee4c1feca433947d9d9d24f`.

## Qualification boundary

This evidence preserves a real Linux regression failure and its full execution
context. It does not qualify formal production KV2 migration, blank-machine
disaster recovery, real three-host HA, AuthBus credential trust, AppRole/token
renewal or revocation, real client migration, production traffic cutover or old
asset cleanup. Compiler CPU/RSS observations in build logs are not service
resource comparisons. No production credentials, traffic, services, old
OpenBao binaries or old HeptaBao assets were changed by this archive work.
