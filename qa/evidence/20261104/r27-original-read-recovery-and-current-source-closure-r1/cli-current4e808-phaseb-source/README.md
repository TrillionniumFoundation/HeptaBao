# Official OpenBao 2.7.1 CLI Phase B — current 4e808 source successor

This packet prepares the existing five-window CLI experiment for product commit
`4e808d0ecb1bcded22870a7ec960dfb2491cf6ec`, tree
`eba5e650bd080b8ad41ea52a2bc68867f541d255`. It is **source-only**. The binding is
unresolved, all four current product size/hash pairs remain null, and neither
dispatch template is executable or authorized. There has been no new local stage,
prepare, CLI request, restore, or restart for this successor.

## Source changes

The base is the archived R18 `official-cli/df026-phaseb-unbound-source` tree
`f3f268581b6efe14d7f8e8e6981ff4e1498802c4`. The 28,134-byte binder changes the exact
product commit/tree, the one changed `service_native_v6_ha_read.rs` source pin,
the current canonical-source namespace, and the combined normal-test receipt
contract. The original 44, 7, and 9 groups keep their exact names and terminal
requirements. One separate A→B→A regression is required, with a total of 61,
its original 600-second group cap clipped to the existing parent deadline, and
the exact current runner SHA `93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be`.

The separate one-test predicate is copied from the already reviewed current H2
binder `9b3a605a2ac2f47729678bdb696d89b0c9b06b9a`. This CLI binding has no H2 QA
binary input. Its client remains the independently pinned official OpenBao 2.7.1
binary. The actual 4e808 normal61 receipt is an offline predicate input in this
packet; it does not supply future desktop file versions or staged product pins.

The following four sources remain byte-for-byte unchanged:

| Source | Git blob | Bytes |
|---|---|---:|
| Main controller | `03497f1ee45be3228de99ab4872ae2f9ca869de0` | 61,210 |
| Evidence parser | `e507fef5b87305f4b8e8a0d729aecec6da284bed` | 15,201 |
| Native fixture reference | `7e465b3ea72814726ed2e01355ab91412190a747` | 68,149 |
| Official CLI reference | `4a4a60d1d52a0fd835b467f1e4687ee95314d1de` | 46,586 |

The old df026 binding and both old templates are included. Strict unified diffs
reconstruct the successor, and the recorded literal transformations reverse to
the complete original bytes. Fifteen unchanged binder definitions also match
exactly. No V5-only/2.6.2 CLI driver is substituted.

## Future fixture and remaining gates

The fixed ancestor stays `/home/qian-qi/heptabao-ha-closure-20261103-r1`.
Only the final fixture suffix advances to `official271-native-cli-phaseb-r3-control-r4`
and `official271-native-cli-phaseb-r3-live-r4`; prepare remains `control-r4/prepare-r1`.
The required private binding basename stays `binding.private.json`.

The required canonical source is
`normal-same-root-publication-validation-source-r1`. Future product input paths
are under `normal-same-root-publication-shared-artifacts-r1/incoming`.
The completed source export alone is insufficient for either input: standalone
import and product transport must independently close, followed by a reviewed
create-only local stage. The stage must capture the actual files and preserve the
official CLI, tools, host identity, and old evidence fences. The source template
contains expected old tool/host values; it does not claim a fresh observation.

Only after exact staged binding bytes exist can a concrete prepare request be
frozen and reviewed. Actual prepare closure then precedes a separate live request
and exclusive fixture window. Both present request objects still contain explicit
unresolved digest strings and `ready=false` / `requests_authorized=false`.

## Five actual CLI windows still required

| Case | Once-only operation | Required result |
|---|---|---|
| B01 | Save archive A against the observed leader | CLI exit 0, terminal server 200, complete canonical native archive |
| B02 | CAS-write version 3, restore the previously verified A against the leader | Exit 0 plus 200/204 and all-node exact two-version baseline; then one eligible cold restart and exact readback |
| B03 | Save independent archive B against the observed leader | A distinct owned file satisfying the same save proof as B01 |
| B04 | Save against an observed standby using the official CLI's default redirect behavior | A complete save proof; a recognized complete business failure remains a failed qualification |
| B05 | CAS-write version 3, restore verified B against a standby using default behavior | Exit 0 plus 200/204 and exact baseline; then one eligible cold restart and exact readback |

The machine-readable case map includes source anchors and prerequisite/failure
branches. All five current-product statuses are `not_run`. A known B04 save
failure does not substitute a new save: B05 uses the separately verified B03 file.
A known restore rejection requires 400/403 and unchanged pre-restore state. It
may allow the original cold-readback branch, but it never qualifies as restoration.
A success status or rejection with unaccounted state is UNKNOWN.

The fixture is one physical desktop with three process nodes. The unchanged
reference setup bootstraps its owned seed and performs formal native activation;
the exercised configuration must subsequently be `native_v6_raft`, with native
record format and both original KV2 versions observed on every node. This is not
a claim that setup has no migration step, nor a multi-host deployment proof.

## Budgets and UNKNOWN fences

HTTP and CLI calls retain 15 seconds. Each existing action retains 300 seconds,
readiness 45, election 60, stable-leader observation 2.2, peer timeout 1,500 ms,
forward timeout 8,000 ms, and owned cleanup TERM 5 plus KILL 5. The prepare outer
cap remains 330 seconds and the live outer supervision cap remains 3,000.
The existing final evidence/cleanup phase retains its own 300-second deadline.

The stop-once ledger shares one original 5+5 budget across explicit seed/cold
stops and finish cleanup. The retained reference deadline paths have their own
pre-existing SIGKILL/wait-5 stage; this packet does not claim that every initial
signal eliminates that separate original stage.

Both old B01 UNKNOWN results remain byte-bound fences:

| Old fixture | Bytes | SHA-256 |
|---|---:|---|
| `official271-native-cli-phaseb-r3-live-r1/result.public.json` | 270,785 | `cd2d1d89271b0342755935f366cf41b25ad49e1cd560a1ab7a1eb7b698e9d184` |
| `official271-native-cli-phaseb-r3-live-r2/result.public.json` | 278,829 | `15a07dca63299bbfb7f871c5d1611a22713382a85cd9f8acc917569d9044600e` |

All six old fences in the source template remain unchanged. Neither old UNKNOWN
is replayed, reclassified as rejection, or assigned the new fixture's identity.
Any new UNKNOWN stops subsequent mutation, CLI, and cold restart; only the
unchanged read-only evidence and owned cleanup paths remain available.

## Offline validation and limits

The packet's verifier reports 143 checks, including strict whole-file diffs,
reverse transformations, seven complete canonical source hashes and their four
Merkle membership links, unchanged helpers/caps, private binding paths, and
future null/ready guards. Fourteen selected receipt-predicate cases accept the
actual current normal61 data and reject historical60 or missing/failed/unknown
ABA, changed budgets/counts/source/runner. It compiles five whole Python sources
without importing them, then separately executes only the actual data-only
receipt statements and ready guard. No whole binding constructor, fixture,
product, subprocess, or network path is executed.

The initial verifier referenced the wrong filename for the already present
historical60 receipt. Its source and failure note are retained; only that checker
reference changed. Candidate and evidence bytes were unchanged.

The evidence parser keeps a 16 MiB compressed archive and 32 MiB expanded bound.
These five windows therefore provide no 34 MiB archive qualification. Server
audit is not TLS framing or ALPN proof. The independent H2 fixture covers its
separate small GET paths; it does not prove official-CLI ALPN, restore, these five
windows, or archive interoperability with OpenBao's own state format. Dynamic
invariants, the normal 61 tests, and the existing bounded69 compatibility cases
are separate denominators; none is the full OpenBao 2.7.1 route × operation ×
configuration × lifecycle surface.
