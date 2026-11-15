# Three-host live ACL authority qualification

Status: `IMPLEMENTED_SCOPED_LAB_PROFILE`

`qa/openbao-acceptance/ha_multihost_acl_live.py` composes the existing private
three-host process, Raft, snapshot, failover and quorum-loss lifecycle in
`ha_multihost_live.py`. It does not implement a second supervisor or execution
kernel. The original profile and its fixed 54 checks are unchanged. This separate
profile requires all 54 baseline checks **and** 64 additional ACL checks, exactly
once, for a fixed denominator of **118**. Its report schema is
`heptabao.multihost-acl-ha.v1`; an old 54-check report cannot qualify this scope.

## Scope and evidence boundary

One clean candidate commit/tree and one executable SHA-256 are used on three
separately authorized Linux machines. The common lifecycle creates fresh
owner-only roots, a fixture-only CA, distinct node certificates and a private
replication key. The listener and Raft addresses stay on the explicitly approved
private tailnet. It starts and stops only its own path-verified fixture PIDs and
does not alter system services, firewalls, the user's existing workspaces or a
production OpenBao deployment.

The composed receipt binds the wrapper runner checksum **and** the shared
lifecycle checksum. It checks both again at completion, along with the controller
and all three remote binary copies. Root, unseal, role secret, service, batch and
wrapping tokens remain process-local fixture data; none may enter the report.
Recursive key/value checks run before success and again in final cleanup. A
failed case retains its bounded prefix and cannot borrow another profile's
completion marker. No mutating request is retried after a timeout or ambiguous
acknowledgement.

## Additional lifecycle checks

The setup uses normal HTTP entry points to mount KV2 and AppRole, issue a service
token and a batch token for the same entity, create a member group, and persist
Identity-templated policies with schema-61 wrapping bounds. All data is synthetic.
The original tokens are retained for the entire fault sequence; a restart or
failover is never concealed by issuing a new subject token.

Before any fault, requests through a **standby** must demonstrate all of the
following together:

- A positive minimum rejects both a missing header and explicit zero. A
  maximum-only rule rejects a missing header but permits explicit zero without a
  wrapper, including for the original batch token. The authenticated forwarding
  protocol therefore cannot collapse `Some(0)` into an absent request fact.
- A permitted positive TTL captures a response, releases it only through the
  one-use wrapper, and rejects wrapper replay. Foreign entity paths are denied.
- A denied wrapped write has no KV version; an admitted write is sent once,
  acknowledged once, unwrapped once and reads back at version one.
- Metadata changes immediately revoke the old template path for the same token.
  Removing direct group membership immediately removes the group template grant.

The restarted snapshot follower must preserve the original service and batch
permissions, the metadata and group revocations, and explicit-zero semantics.
After a real remote leader kill, the surviving standby must still accept the
original permitted requests. Disabling the entity through the surviving cluster
must revoke both original tokens on **both** survivors. The old leader's process
restart and catch-up must not resurrect either token. After the original
quorum-loss/recovery sequence, all three nodes must still observe the revocation.

The extension deletes its synthetic group, entity, authentication mount, policy
and KV mount and checks data absence before the shared lifecycle cleans its own
baseline data and stops the fixture processes. Secret fixture roots can be
retained privately for bounded failure diagnosis; they are not repository
artifacts and are never uploaded as a report.

## Invocation and acceptance

Use the prerequisites and exact CLI fields from
[the shared multi-host guide](HEPTABAO_MULTIHOST_HA_QUALIFICATION.md), replacing
only the script name with `qa/openbao-acceptance/ha_multihost_acl_live.py` and
using a new private work root and new remote fixture roots. The inventory profile
is `ha_multihost_acl`. It is intentionally not a default public PR job: untrusted
pull requests must not execute on persistent authorized LAN machines.

A report is successful only when it contains all 118 distinct passing checks,
the expected schema, both runner hashes, the exact source/binary bindings, three
distinct physical host identities and no runtime secrets. Unit tests in
`test_ha_multihost_acl_live.py` exercise verdict/transport/ownership rules but are
**not** physical-host or product qualification. The single-host checksum-pinned
OpenBao 2.6.2 comparisons remain separate evidence in `policy_templates_live.py`
and `policy_wrapping_ttl_live.py`; this composed HA profile is not itself an
OpenBao-versus-HeptaBao HA differential.

Mixed-version readers/forwarders, physical power loss, disk-full recovery, WAN
partitions, long-horizon linearizability, external-provider effects, full Identity
or ACL semantics, independent security admission and production key custody
remain outside this bounded profile. Every full-compatibility, independent-
qualification and production-authority flag remains false.
