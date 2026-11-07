# AuthBus and fleet continuation — 2026-11-06

This continuation is based on the existing product candidate
`09c14eae7a3b52dee8ce3af3175dad5900ac59ec`. It preserves the ordered formal
KV2 recovery, physical HA, AuthBus, actual-client cutover and legacy-cleanup
gates. **The real OpenBao 2.7.1 replacement is not qualified.**

## Actual new results

| Work | Observed result | Scope |
| --- | --- | --- |
| Final DR process-custody helper on Mac | 18/18 existing tests, no failures or skips; authoritative succeeded/exit 0 | Same final helper hashes; completes the earlier split 15+3 evidence gap |
| Mac launchd parser | The original R2 parser rejects actual `(never exited)`; the candidate retains it as `None` | Read-only actual GUI registration comparison, no service relaunch |
| Parser regressions | Final source 17/17; root rerun 17/17 | Exact-source preparation and refusal behavior, not deployment |
| Mac product `09c14eae` | 103 executed: 102 passed, 1 failed; 4 required TLS-close cases not executed | Actual failed terminal retained; no full 107-case pass |
| X230 deployment scope | Exact old proxy is disabled/inactive; exact retained development oracle is running | Read-only inventory; no cleanup permission inferred from lack of network/mounts |

The sole Mac product failure is
`native_jwt_role_operations_keep_the_existing_legacy_acl_contract`: an expected
204 received 403. Its original logs and authoritative failure are under
`mac-09c14-failed/`. The full result contains a failed group with 14 passing
cases; the group-level accepted count must not erase those actual executions.
The remaining failure still requires diagnosis and current-source execution.

## AuthBus repair and outstanding registration

See the adjacent `../mac-authbus-launchctl-parser-20261106-r1/` evidence for the
actual Mac comparison and exact parser-only patch. Existing R2 already handles
the observed `78: EX_CONFIG` as a nonzero exit. The new fix recognizes only
the exact `(never exited)` value in `last exit code` and preserves a missing
exit observation as `None`. It does not grant an identity, successful exit,
new deadline, replay, or continuation after an unknown effect.

Root independently observed the exact R2 GUI registration with one successful
read-only job, `1a1b0f67109-fc05-7466`: running, runs 1, PID 32527, last exit
`(never exited)`. The raw launchctl arguments and environment were not exported.
This current observation does not reconstruct the missing raw field at the
time of the historical failure.

The old R2 owner-bind record still has zero business checks and zero phases.
Its wrapper and executed-server identities were not recorded before the parser
failure; its cleanup did not prove registration and lineage closure. A parser
repair by itself does not reconcile that prior effect or authorize replay of
bootstrap. The old registration requires its own identity-bound recovery.

## Fixed migration scope

`finite-scope.public.json` retains the previously accepted finite registration
scope. It does not promote arbitrary historical archives into new blockers.
The selected actual consumers are the installed Mac, ROG and Pocket4 gateways,
their declared AuthBus bindings and source-bound held helpers. Mac's four
legacy relay components need separate consumer-retirement evidence.

X230 has no standard OpenClaw configuration in the checked location. It remains
an independent Linux validation/recovery host; this continuation does not invent
a new production consumer to satisfy a cutover checkbox. Its old disabled proxy
and development oracle remain separately enumerated assets.

The retained finite registration scan confirmed no Bao/AuthBus backup producer
or scheduled restore within its selected launchd/systemd/cron scope. That is a
historical bounded observation, not a claim that no backups exist on disk.
Only newly observed active Bao/AuthBus configuration, command or restore
entrypoints reopen the agreed scope.

## Evidence boundaries

- `mac-custody18/verify_evidence.py` checks the original streams, exact 18 names,
  source hashes, independent file reads and authoritative terminal state.
- The helper run started only disposable test processes; it did not run
  full34/DR25, a Bao server, a compiler or the existing 107-test campaign.
- The original failed product runs remain failed. No passing observation is
  transferred to another source, artifact or actual-client profile.
- No production configuration, real credential, previous backup or original
  evidence was changed. No old Bao service or binary was deleted.
- Public records omit credential values, credential digests, production config
  fingerprints and private cache identifiers. Internal source reviews are not
  independent external security review.

The ordered storage, physical HA, trusted credential source, selected installed
client and cleanup gates still need their own complete real execution results.
