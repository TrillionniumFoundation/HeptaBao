# R990 Shamir pre-B budget fence (isolated candidate)

Status: NOT_ADMITTED. This is not a production rollout.

## Actual evidence
R985 physical LAN: Pocket4 original Shamir request had 229ms before durable B, 108ms after B, 4ms before mandatory recovery index. Existing R910 post-graph deadline refused it, and R985 FAILED at 29 checks.

## Behavior
After original authenticated HA owner admission but BEFORE any durable B staging, an actual Shamir-bound receipt must retain 750ms in the minimum of its captured original request deadline and current nested deadline. The short-budget arm invokes only the existing actual disk/generation/nonce/readback BeforePublicationNoWrite::retain_original_a integrity proof and returns an opaque 503. On failed proof, keep the old permanent recovery fence. No clock extension, result replay, write retry, quorum shortcut or positive authority. Reserve is a conservative early refusal, not a timing guarantee.

## Test and admissions
The real-Raft test uses a 700ms nested budget, proves original A disk bytes and generation unchanged, denies forwarding the old result and requires a new independent sync. Existing negative quorum, deadline, integrity, expiry and index tests remain enabled.
Source derived from R980 diagnostic worktree. V6 production KV2 writer/migration, repeated physical LAN HA, unknown post-compact delivery, full OpenBao 2.7.1 provider parity, rolling upgrade, rollback and supply-chain/11 admission gates remain OPEN. Never mark full replacement by this guard.
