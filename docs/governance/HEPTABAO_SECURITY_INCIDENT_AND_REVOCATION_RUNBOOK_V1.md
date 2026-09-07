# HeptaBao Security Incident and Revocation Runbook V1

Status: `H00 IMPLEMENTED / NOT OPERATIONALLY QUALIFIED`  
Plan: `HEPTABAO-PLAN-2026-08-28` revision `1.1`

This runbook defines the minimum fail-closed response for suspected secret exposure, security bypass, data-loss/consistency failure, duplicate external effect, writer overlap, invalid provenance or release compromise. It does not claim that a staffed 24/7 response organization currently exists.

## 1. Severity

| Severity | Examples | Initial response objective |
|---|---|---|
| Sev-0 | active private-key/root/unseal leak; unauthorized active writer; confirmed split brain with writes; malicious release | immediate containment and revocation |
| Sev-1 | policy/audit/namespace/token/plugin bypass; committed data loss; blind retry causing duplicate credential | immediate stop of affected authority and incident command |
| Sev-2 | exploitable high finding without confirmed production impact; migration mismatch before cutover | same-day containment and qualification invalidation |
| Sev-3 | medium/low issue, evidence drift or non-security compatibility deviation | bounded triage and scheduled repair |

## 2. Trigger sources

- private vulnerability report or security advisory;
- secret canary or artifact scan;
- audit, policy, token, lease, seal, plugin, Raft or migration invariant alert;
- upstream OpenBao/Rust/dependency advisory;
- release signature, SBOM or transparency mismatch;
- operator report or automated chaos/qualification failure.

Unknown credibility does not authorize public disclosure, continued promotion or automatic dismissal.

## 3. First actions

1. Create a private incident ID and assign an incident commander.
2. Freeze promotion, release, migration and new authority grants for the affected scope.
3. Preserve immutable evidence: source/tree, artifact/config/toolchain digests, audit IDs, operation keys, epochs/fences, cluster indexes and relevant receipts.
4. Determine whether a secret/key/token may be exposed. If yes, prevent further distribution and start rotation/revocation without waiting for complete root cause.
5. Issue a signed revocation for affected Qualification Receipts, Compatibility Claims, Authority Grants and Release Attestations.
6. Stop or fence affected writers. If writer authority is uncertain, select **no writer** and enter manual hold.
7. Seal an affected cluster/namespace when continued operation could widen impact.
8. Isolate compromised plugin, build, runner, KMS/HSM, signing key, repository credential or dependency.
9. Notify required internal/legal stakeholders through the private channel.

## 4. Revocation ordering

```text
Revocation record signed and published
→ grant/claim/receipt consumers reject affected object
→ traffic/promotion/migration stopped
→ writers fenced
→ secret/key/token rotation or credential revoke
→ forensic capture
→ repair and regression
→ new qualification
→ new claim/grant only after independent approval
```

A branch deletion, issue label, PR closure or release removal is not a cryptographic revocation.

## 5. Incident-specific containment

### Secret, token or key leak

- revoke/rotate affected credential and descendants;
- identify every artifact/log/audit/debug/snapshot/fixture that may contain it;
- invalidate caches and wrapping/cubbyhole references;
- inspect access and provider logs;
- assess whether encrypted historical material requires barrier/key rotation;
- prohibit reuse of leaked values in tests.

### Policy, identity, namespace or token bypass

- disable affected route/mount/profile or seal affected namespace;
- revoke tokens issued or renewed through the bypass;
- invalidate policy/identity/token caches and bump authority epoch;
- add a minimal regression and pattern-wide scan.

### Audit bypass or leak

- stop secret-returning operations when minimum audit success is not met;
- rotate material exposed in audit/debug artifacts;
- preserve device state and determine ordering failure;
- requalify all affected operation classes.

### Duplicate or ambiguous external effect

- stop the affected engine/provider lane;
- never repeat an unknown effect;
- lookup by durable operation key, revoke/compensate or retain manual hold;
- reconcile every in-flight operation before reopening.

### Storage/Raft data loss or split brain

- halt writes and fence every active owner;
- preserve WAL/log/snapshot and node-image digests;
- select a recovery point only through verified committed-index evidence;
- restore or forward recover; do not merge divergent state ad hoc;
- revoke HA/durability claims and grants.

### Migration writer overlap

- revoke both source and target grants;
- stop both writers;
- collect accepted-write counts, operation keys and epochs;
- reconcile divergence and choose signed forward recovery or proven-safe rollback;
- never pick a writer by network reachability alone.

### Build/signing compromise

- revoke signing key and every affected artifact/claim/grant;
- stop distribution and deployment;
- rotate repository/CI credentials;
- rebuild hermetically from verified source on a clean builder;
- publish a replacement transparency entry and incident notice under approved policy.

## 6. Investigation and closure

Every critical/high incident must produce:

- timeline with trustworthy clock/source annotations;
- affected scope and exposure window;
- root-cause class and contributing controls;
- exact receipts, claims, grants and releases revoked;
- credentials/keys rotated or confirmed unaffected;
- invariant and requirement references;
- regression tests and similar-pattern scan;
- recovery/restore evidence;
- residual risk and expiration;
- external disclosure decision and upstream coordination where applicable;
- independent security and domain approval.

An incident is not closed merely because service is restored. Closure requires evidence that the vulnerable class is addressed and affected authority remains revoked or has been reissued from new qualification.

## 7. Current H00 blockers

The following are not yet operational and therefore block H00 qualification:

- named incident commander rotation and 24/7 escalation roster;
- dedicated private disclosure endpoint and service-level commitment;
- signing/revocation keys and offline emergency procedure;
- tested notification, legal, public-advisory and upstream coordination paths;
- at least one tabletop exercise and one technical revocation game day.
