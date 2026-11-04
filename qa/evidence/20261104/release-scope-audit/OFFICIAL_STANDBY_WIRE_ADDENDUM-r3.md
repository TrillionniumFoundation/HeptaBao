# Official 2.7.1 standby wire observations — later addendum

This addendum records a new actual OpenBao observation after the r2 source correction. It does not overwrite the original audit or its correction, and it does not turn the current HeptaBao source analysis into an executed wire comparison.

## Frozen oracle and boundaries

OpenBao `v2.7.1`, source `a5db72cef75c24b920ade02065b18dd8eb666bac`, normal binary SHA-256 `535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea`. The independent run used three fresh loopback nodes, real TLS and joined Raft state; actual role observations before and after identify node 1 as leader and nodes 2 and 3 as standbys. The two followers remained **non-voters** in the recorded autopilot views. This qualifies the observed standby HTTP behavior, not official three-voter HA or physical-host fault tolerance.

The run recorded 49/49 behavior checks and an independently reconciled 51/51 operation boundary: 48 complete HTTP responses and 3 explicit pre-connect readiness failures, with zero unknown outcomes. Every operation retained the original 15-second request budget; no redirect following was enabled. All three owned processes stopped. No valid restore body or production request was sent.

## Observed responses

| Request | Actual leader 1 | Standby 2, `disable_standby_reads` omitted | Standby 3, `disable_standby_reads=true` |
| --- | --- | --- | --- |
| Snapshot GET with root token | 200; 19,993-byte gzip archive-shaped body | 200; 19,993-byte gzip archive-shaped body | 307 to the exact enrolled leader origin and target |
| Snapshot GET without token or with invalid token | 403 | 307 to leader | 307 to leader |
| Invalid POST to snapshot and snapshot-force | Complete 500 for each | Complete 500 for each | 307 to leader for each |
| Ordinary KV2 256 KiB write with a valid token | Exact persisted value checked on leader | 200; leader value exactly matches | 200; leader value exactly matches |

An explicit no-forward ordinary write to standby 2 returned 307 and left its proposed mutation absent. The snapshot bodies were checked for archive shape only; this is not a successful restoration or decrypted-content proof. The two invalid restore POST statuses do not demonstrate valid restore compatibility.

## Effect on the replacement denominator

Exact normal HeptaBao tree `cdc2376e7b39c1d8bbbeb10a813d58bfe923f336` already has a pre-body snapshot redirect path in `http_snapshot.rs` and `service_snapshot_transfer.rs`, backed by real-Raft admission/parser tests. The earlier r2 correction remains valid: snapshot standby handling is not absent merely because the inner generic dispatcher contains a 503 guard.

The new official observation shows why source-only parity was insufficient: an authorized GET on the **default** official standby returned 200, while the examined HeptaBao front door selects 307 for a configured follower. A real HeptaBao network request and actual client redirect behavior still need to be associated with this oracle before claiming compatibility or documenting an intentional difference. Returning 307 can be compatible for clients that follow it safely, but that inference is not a measured result here.

The dedicated HeptaBao large-KV upload entry still has the separately documented standby 503 guard. Its proprietary request path is not an OpenBao API, and these successful ordinary 256 KiB KV writes must not be described as an oracle for that separate large-upload path.

## Evidence custody

Run root: `/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-standby-oracle-live-r1`.

* `result.public.json`: 6,521 bytes; SHA-256 `d84a783d817ee7827496182b6f750a1cd995424e554b287f602fd9204f289975`.
* `wire-observations.public.json`: 18,036 bytes; SHA-256 `45d2039f2e68e006cb10dc80925f9d6719fa16dfa433bf22bf5b538e9adfae02`.
* Independently read local cache `ha_standby_review/official271_oracle_readback.public.json`: 34,941 bytes; SHA-256 `0cfbd3d9ae36d3533d881cf7e7dadc071ca5f32e40ad0454fbc36aec53254dd0`. It retains the complete parsed objects and the original file hashes, not a byte-identical reserialization of those original files.

The aggregate audit admission remains incomplete. Neither this official observation nor the existing 69/128/98 results is a universal OpenBao API equivalence certificate.
