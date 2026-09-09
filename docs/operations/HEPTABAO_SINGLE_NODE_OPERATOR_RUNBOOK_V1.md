# HeptaBao Single-Node Operator Runbook V1

Status: repository-owned candidate procedure; not production qualification.

```yaml
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Startup admission

1. Bind the exact build commit, configuration digest and storage generation.
2. Reject startup when storage, journal, barrier or recovery metadata is newer than the binary understands.
3. Complete replay and reconciliation before opening a listener.
4. Keep the service sealed until key custody and unseal policy are satisfied.
5. Confirm that the active namespace, policy, token, mount and plugin generations form one admitted snapshot.

## Request outcome actions

| Classification | Meaning | Operator action |
|---|---|---|
| before entry / not committed | backend effect was not entered | correct the cause and submit a new request identifier |
| committed | authoritative effect completed | do not retry; inspect response/audit delivery separately |
| unknown after entry | effect may have completed | do not retry; query the recovery reference and perform authoritative readback |
| resolved committed | readback found the effect | mark resolved, return committed outcome, never replay |
| resolved not committed | readback proves no effect | mark resolved, then a new request identifier may be used |
| compensated | external effect was deliberately reversed | preserve both original and compensation evidence |

The original request identifier is never reused after backend entry.

## Backup and restore

1. Bind a stable source generation.
2. Begin snapshotting and record the start tick.
3. Seal the archive with a nonzero digest and custody metadata.
4. Verify bytes after transfer.
5. Restore only into an empty admitted target.
6. Read back restored generations and run application-level checks.
7. A backup is not qualified until a separate restore drill succeeds.

## Disk pressure

At warning threshold, stop nonessential compaction and create an operator alert. At critical threshold, reject new writes before entry while continuing bounded reads and reconciliation where safe. Never delete audit, journal, recovery or anchor state merely to clear space.

## Key rotation

Stage a new key generation, validate provider availability, switch writer generation once, verify readback under the new generation, then retire the previous key according to the retention policy. Revocation is terminal and must not occur before all required data is rewrapped or intentionally made unavailable.

## Reconciliation

For every unknown-after-entry record, compare the operation ledger, journal, storage generation, audit outcome and external provider state. Conflicting evidence escalates to an incident; it is not converted to a safe retry.

## Incident triggers

Escalate immediately for credential disclosure, policy bypass, audit bypass, committed-write loss, writer overlap, split brain, invalid provenance, unknown key custody or unexplained generation rollback. Revoke affected authority before restoring service.

## Current limitations

The V2 service composition remains in memory. This runbook defines the required operational semantics but does not claim that production providers, 24x7 staffing, KMS/HSM custody, destructive failure tests or independent review exist.
