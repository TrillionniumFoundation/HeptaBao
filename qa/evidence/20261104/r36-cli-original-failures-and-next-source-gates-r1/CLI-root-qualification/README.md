# Official OpenBao 2.7.1 CLI Phase B — original evidence qualified, compatibility gate failed

The 711-file / 8,639,016-byte original aggregate (401 verified Merkle trees) has been independently read. Root reconciled 117 original calls, 17 inactive observers, 82 immutable pages and 13 binary ranges into the exact 848,065-byte report. All 415 root evidence checks pass. The original controller exits 1, with full durable output and all 283 owned children closed. Its 416 dynamic invariants are not a full-replacement compatibility denominator.

B01 leader save, B02 leader restore plus real three-node readback/cold restart, and B03 second leader save qualify. B04 standby save returns CLI 2 / incomplete_snapshot and produces no valid archive. B05 standby restore returns CLI 0 but the leader audits 400; all three nodes retain the mutated state, including after cold restart. B05 used the valid unchanged B03 archive, not the absent B04 output.

The audit status arrays are grouped by node and do not prove temporal order, HTTP framing, ALPN, actual redirected upload bytes or the detailed internal cause of 400. The pinned controller performs actual version/value/metadata API comparisons on all three process nodes, and compares exact state after cold restart. It runs on one physical host with owned synthetic credentials. Native archives are not claimed interoperable with OpenBao's Raft archive state format.

Original report: https://api.github.com/repos/TrillionniumFoundation/HeptaBao/git/blobs/0b2edd60185b80817c3c7f1378b914ae914ab21e

Original aggregate: 871aa23bfee256e91247fbb7e6d42c4cb82d181d. Original Git create 75ff6983c667aa524100e19258693f7e0bf1b982 remains UNKNOWN with its returned error and exact read-only reconciliation preserved. No Native business replay occurred. Full replacement, production cutover, all-client/backup migration and legacy cleanup remain false.
