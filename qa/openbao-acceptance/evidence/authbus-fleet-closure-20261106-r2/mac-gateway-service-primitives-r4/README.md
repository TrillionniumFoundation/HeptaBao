# Actual Mac launchd maintenance primitives

The final r4 attempt passed all six once-only actions against the new credential-free QA label `org.heptabao.qa.gateway-maintenance-actions-20261106-r4`: bootstrap, disable, bootout, enable, bootstrap of a new generation, and final bootout. Both services ran `/bin/sleep 30` with `KeepAlive: false`. This is a qualification of service-control primitives, not a production gateway restart or a complete production rollback.

The original r4 job is `1a1b2e87896-fc05-802a`. Its authoritative terminal is succeeded, exit 0, complete and durable, with no timeout, cancellation or automatic retry. The original stdout is 117,007 bytes, SHA256 `6e9b34c61d1b90c98b8d279f7066df7420153289c8b7169622738349d88e0f05`, reconstructed and compared byte for byte from eight original pages. Runtime was 2.845 seconds within the unchanged 45-second shared budget and 70-second supervisor bound.

All six mutation intents were persisted before their single dispatch and each returned a known successful result. The 43 original command helpers were reaped with empty related groups and closed streams; no helper outcome was unknown. All 105 launcher-recorded descriptors closed once. The two sleep service identities were PID 6054, birth 1794002942.562423, and PID 6310, birth 1794002944.274470. Each generation received two checks confirming the exact label absent, the original PID absent through libproc, and no related PID, PPID or PGID rows.

The final effective disabled value is false. Launchd retains a newly created false override entry for this new QA label. The qualification does **not** claim that the initial absence of an override entry was restored. No production gateway, credential, provider or J3160 path was involved.

## Earlier failures retained

| Attempt | Original job | Result and boundary |
| --- | --- | --- |
| r1 | `1a1b2d11c20-fc05-7fe1` | Known failure before command helpers or service actions. Its own root creation changed the containing directory's link count. |
| r2 | `1a1b2d75e8e-fc05-7ff9` | Known failure before command helpers or service actions. The writable QA root's link count changed as its five source files were created. |
| r3 | `1a1b2dcbcc3-fc05-800b` | Known failure after two complete read-only helpers, before all mutations. The real `print-disabled` envelope had leading whitespace and `enabled`/`disabled` literals. |

All earlier roots, source versions and original failure receipts are retained. No failed action was replayed. None of these three failures bootstrapped a service or altered an override.

## Specific fixes and actual preconditions

The parent-directory fix is limited to a single relative `mkdir` on the retained immediate-parent FD: device, inode, owner, group and mode must remain exact, and the link count must be unchanged or rise by exactly one. Other read-only ancestor checks remain exact. The writable, owned QA root uses its stable first five identity fields, checked against both the retained FD and the named directory. Public source and plist checks still require full file identity and complete pinned bytes.

The new-root metadata-only Mac observation `1a1b2d9f4b8-fc05-8003` proved that each of five ordinary file creations increased the actual APFS directory link count by one while leaving those first five fields unchanged. All seven descriptors closed; no child or service command was run. The local seven-case regression includes an actual local filesystem `mkdir` and rejection of changed inode, owner, mode or multiple extra links.

The real disabled-map bytes were kept private. Two read-only projections bound them privately to the original successful command receipt and published only syntax classes and known state literals. The final parser accepts the observed leading blank boundary and exact `enabled`/`disabled` values, retains legacy boolean values, and fully rejects duplicate keys, unknown literals, extra records, unobserved separators and trailing nonblank data. It never exports the full map, unrelated labels or that map's digest.

Before r4 service actions, original job `1a1b2e734bf-fc05-8029` executed the exact r4 parser on all 1,435 retained private original bytes and nine related positive/negative cases: 10/10 passed, both FDs closed, zero launchctl calls. The same r4 source also passed 21 local pure cases. The four pure print-parser definitions and the original command, custody and libproc helpers remain source-bound to the earlier actual SDK qualification.

## Remaining production boundary

Actual normal-gateway configuration selection and plugin registration are separate qualifications. A production recovery package must bind the current loaded arguments, environment, full service lineage and all relevant state. After real OAuth refresh, the valid rollback baseline must be captured after all selected owners reach known committed generations; old rotated refresh credentials must never be restored. Unknown provider or CAS outcomes continue to forbid automatic writer restart.
