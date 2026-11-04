# R9 normal release and exact 44-test terminal evidence

Candidate: `1d12abc45a83d4b32e7185d01a876eb93110b1e2`; tree: `e1faeaa3ed49d26fb01a7617a8879cb693a12907`.

ROG's normal default release and normal release libtest builds succeeded. The original six exact groups executed all 44 named tests: **42 passed, 2 failed, 0 ignored**. The durable combined job exited 1, without supervisor timeout. All 14 owned process groups were reaped with no surviving members. Source and retained binaries remained unchanged.

| Group | Passed | Failed | Ignored |
|---|---:|---:|---:|
| SSH ownership | 25 | 0 | 0 |
| Native mount refusal | 1 | 0 | 0 |
| Native redirect transport | 5 | 0 | 0 |
| Parallel export actor and original scope | 2 | 0 | 0 |
| Ordinary HTTP response framing | 5 | 0 | 0 |
| NoForward 2.7.1 | 4 | 2 | 0 |

Both failures occurred in the new normal HA tests' setup. `finite_actor` invokes `unchanged(service)`, whose `serde_json::to_vec(state)` tries to flatten a native KV2 owner. The formal storage implementation rejects it with `native KV2 owner requires separate authenticated records`. Neither failing test reaches its target NoForward request, so their desired HA behavior is unqualified. A test-witness repair is under review; the product's flat-serialization refusal remains required. There was no retry or weakened timeout.

The independent root review checks each group's actual stdout and names against the frozen 44-test denominator, hashes the complete original result and logs, and binds the release, retained libtest, controller and source. See [root review](root-review.public.json), [combined result](rog/result.public.json), [failure stdout](rog/no_forward6.stdout) and [failure stderr](rog/no_forward6.stderr).

Mac's R9 source stage remains a separate failed Git-fetch observation with its original evidence retained. Its offline continuation is source preparation under review; no R9 Mac Cargo build or real Mac/ROG/Pocket4 HA run is admitted by this directory. Official-CLI Phase B and the proposed native snapshot relay are not runtime results here. The earlier successful 31/31, 69/69, 128/128 and 98/98 contracts remain bound to their own recorded candidates.

No production initialization, traffic switch or old-installation deletion is admitted. Full OpenBao 2.7.1 replacement remains unqualified.
