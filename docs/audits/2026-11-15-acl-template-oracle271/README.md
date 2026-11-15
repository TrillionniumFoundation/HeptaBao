# Actual OpenBao 2.7.1 ACL wildcard observation

## Result and scope

On **2026-11-15, 02:52:00–02:52:04 UTC**, the existing pinned official OpenBao
**2.7.1** binary returned **HTTP 400** for ordinary requests whose Identity ACL
template contained a present, forbidden wildcard binding. Root inspection of
that target through `sys/capabilities` returned **HTTP 403**. All rejected writes
left the original data intact. Service and batch reads returned **200** before
injection and after the metadata was repaired.

This was an actual local TLS oracle run using synthetic data, normal `server`
mode and `pebbledb`. It was not inferred from the upstream source. The exact
sanitized [observation](observation.json) and exact
[observer source](observer-source.py.txt) are retained here. The source is an
archive of the executed probe, including its original local paths, rather than
an installed acceptance runner.

The run exercised the unmodified `policy_templates_live.run_scenarios_270`
against the separately selected and verified **2.7.1** server. All **99 existing
pre-restart checks** passed with their original expectations. The observer then
repeated the three wildcard cases independently on the same original service
and batch credentials. The `270` function name selects its existing expectations;
it does not identify the executable used in this observation.

| Metadata `team` | Service GET | Batch GET | Service POST | Root target capabilities | Original data retained |
| --- | ---: | ---: | ---: | ---: | --- |
| `*` | 400 | 400 | 400 | 403 | yes |
| `+` | 400 | 400 | 400 | 403 | yes |
| `red*` | 400 | 400 | 400 | 403 | yes |

The observer recorded error-envelope presence, statuses and equality predicates;
it did not serialize credentials or response payloads. The exact original oracle
process exited with code **0**, and its private credential/data directory was
removed. The report retains those cleanup results.

## Artifact and source identity

The artifact was prepared using the existing repository helper:

```sh
python -B scripts/prepare_openbao_oracle.py \
  --version 2.7.1 \
  --output /tmp/heptabao-oracle271-audit-20261116-r1
```

The helper verified the independently pinned archive and executable digests and
the unique regular archive member. The launcher checked them again, verified
that the member matched the executed binary, and checked live health version
`2.7.1` with TLS verification enabled. The directory suffix is merely the local
input path; the report timestamps above record when execution occurred.

Actual `bao version` output:

```text
OpenBao v2.7.1 (a5db72cef75c24b920ade02065b18dd8eb666bac), committed 2026-10-01T15:32:54Z
```

| Item | SHA-256 or Git identity |
| --- | --- |
| Official archive, pinned and observed | `0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243` |
| Official binary, pinned and observed | `535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea` |
| Observation JSON | `f9d89820ed1e5e0c53fe8e9f2e3fb9436018b77554a9dbcb948c1433c6883d5c` |
| Executed observer source | `2106277391e13de3048e56756e595e24911b29143f5295dda8acddec4502340d` |
| Existing policy template profile | `f4b439d7d384d17aee4e09e8a91d2f5c4f80d137894dc3d8332fe759ce68d1a7` |
| Existing official launcher | `cafed4b33b071ec72da917fe0150d72a396e4bb8a46b4cc2ed9f7b95cc7619cc` |
| Repository commit used by the observation | `21f9c5fa032fbdba6b7d9289c94b890581fea2fa` |
| Repository tree used by the observation | `bef921020c7ccb4e4f3601132aa4030d18443fef` |

Official release provenance:
<https://github.com/openbao/openbao/releases/tag/v2.7.1>.

## Runtime correction and regressions

The current renderer incorrectly used `empty_is_missing` to choose a 403 error
for a forbidden wildcard in a current policy, while the legacy renderer returned
400. The correction returns the same fixed, redacted 400 for this specific
forbidden-wildcard failure in both paths. It still aborts the entire ACL
evaluation before a rule or write can be admitted.

No general permission-denial mapping changes. Missing/empty substitution
semantics, slash restrictions, explicit wildcard opt-in and normal 403 denials
remain unchanged. Target capability inspection retains its existing independent
403 mapping, preventing partial capability results or Identity data disclosure.

The existing Rust regressions now check:

- The exact redacted 400 for four wildcard values under legacy semantics,
  current defaults and current slash opt-in: twelve combinations.
- Ordinary grant success and normal denial as 200/403, plus the existing
  rejection of missing Identity and non-wildcard malformed paths.
- Service and batch GET/POST rejection at 400 even when an invalid templated
  deny accompanies a broad static grant. The same test retains the full state
  digest and data readback checks, root target capabilities at 403, cold reopen,
  and successful root repair followed by the original 200/403 decisions.
- The existing explicit wildcard opt-in remains effective, while a forbidden
  template cannot disappear and leave a broad grant active.

The actual renderer module's seven unit tests passed in an isolated Rust test
carrier using `AuthError`, `err`, `bad`, `denied`, `valid_name` and `validate_path`
copied byte-for-byte from the production `auth.rs`. A control that restored only
the predecessor wildcard branch failed the new exact regression, as required.
This narrow execution avoids rebuilding the full server; it does not substitute
for execution of the Service integration tests.

`cargo check --locked --offline -p heptabao-server --all-targets` also passed
against this patch, including compilation checking of the updated Service and
AuthState tests. It completed in 2 minutes 58 seconds using the existing target
cache, one build job and the already configured local Clang headers. The changed
Rust sources pass `rustfmt`, and `git diff --check` is clean. The full server was
not rebuilt or executed during this correction.

## Qualification limits

The oracle report remains explicitly `candidate_executed: false`,
`full_acl_qualified: false`, `independent_qualification: false` and
`production_qualified: false`. The probe did not execute the profile's restart
stage, a HeptaBao server binary or a candidate-versus-oracle comparison. Those
limits are not changed by the runtime patch or its local module checks.

The earlier failed candidate-versus-2.7.0 comparison remains a failed historical
observation. This new 2.7.1 evidence resolves the disputed error classification;
it does not retroactively pass that comparison or the integration CI. Full
candidate execution and the normal live compatibility gate must establish
their own results after integration.
