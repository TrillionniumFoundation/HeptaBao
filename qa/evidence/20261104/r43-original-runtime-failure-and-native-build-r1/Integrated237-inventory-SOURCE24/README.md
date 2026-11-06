# Exact combined test inventory — SOURCE only

The required final inventory is **237 unique tests / 254 profile entries**. The original C groups contribute 149 / 166; snapshot contributes 27 / 27; original normal61 contributes 61 / 61. All pairwise intersections are empty by crate plus fully qualified test name. The 17 additional profile entries are exactly the original C file/default duplicate names.

| Required libtest | Profile entries |
|---|---:|
| heptabao-server / default | 220 |
| heptabao-server / file (`native-v6-storage`, no defaults) | 17 |
| heptabao-ha-service / `native-v6-peer-ingress` | 17 |

The HA package needs its own retained libtest artifact; these 17 names cannot be executed by the server libtest. Snapshot27 remains 23 lower-level source tests plus 4 actual-Service regression source tests. The transport7 source contains 6 socket/mTLS scenarios and 1 constructor-only deadline case. None has been newly compiled or run by this inventory work.

Original normal61 is mandatory for the combined candidate. Its old runner is included only as an exact case-name source, with original budgets retained as historical facts; this packet creates no new runtime request or budget. The ordinary no-default Cargo check is a compilation gate, not another test.

The final source candidate still requires all 23 changed output bodies and the 49-output mapping. At this cutoff, 10 changed files are whole. The source plan uses C 025b as the base and overlays the 49 snapshot files while preserving the five disjoint C files, including the two None compile fixes, PKI 400 changes, cold tests and strict HTTP assertions.
