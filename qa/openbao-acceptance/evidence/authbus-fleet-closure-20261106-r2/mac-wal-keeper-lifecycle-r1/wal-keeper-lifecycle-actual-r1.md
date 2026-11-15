# Actual Mac synthetic WAL lifecycle

The single original job `1a1b2b25216-fc05-7f58` succeeded with exit 0, complete durable output, no timeout, no cancellation, and no automatic retry. Its launcher ran for 1.093749 seconds inside the original 45-second shared budget and 70-second supervisor limit. The complete 26,613-byte stdout has SHA-256 `ac9d311c758f40e4191d9a97c7b8a6c00c56e0429c3d8a5c973859506e9f852c`.

This is a synthetic SQLite and installed-SDK qualification. It read no production credentials or configuration, contacted no provider, acquired no production mutex, and started or changed no service. It does not authorize production refresh, credential migration, or gateway recovery by itself.

## What the actual run established

| Stage | Actual observation |
|---|---|
| Cold database after its final original writer closes | WAL and SHM are absent. Under the kernel policy that denies database writes, the installed SDK's original read-only adapter receives `ERR_SQLITE_ERROR` with SQLite code 14. Both database namespace and absence remain unchanged. This known diagnostic refusal is retained; it is not counted as a successful credential read. |
| Existing WAL with a read-only keeper | The parent opens the existing database read-only, sets `query_only`, starts `BEGIN`, and executes the selected row query. An independent immutable main-file control proves that this row was committed in WAL and had not been checkpointed into the main database. The immutable control is explicitly not a current-source reader. |
| Original writer closes while the keeper transaction remains live | The existing database, WAL, and SHM keep their exact identities. An independent installed-SDK read-only connection reads the committed owner and closes. Its entire full-nine-field namespace remains unchanged. |
| One installed-SDK raw CAS | The unchanged, previously qualified raw adapter writes only the selected synthetic credential, preserves the other profiles, order, usage and state row, commits once, performs an independent readback, and closes both original connections. The synthetic response witness was fsynced before CAS. Only the WAL size, mtime and ctime change in the observed namespace. |
| Independent latest read with the old keeper still open | A new installed-SDK connection reads the newly committed credential. The keeper continues to see its old snapshot and is never used as the latest source. |
| Keeper rollback and close | The original keeper rolls back and closes once. In this run WAL and SHM remain present, and SHM ctime changes. A fresh namespace observation is required. A final independent installed-SDK read succeeds under the write-denying policy and leaves that new full-nine-field generation unchanged. |

The Python runtime used SQLite 3.53.4; the installed Node 25.9.0 runtime used SQLite 3.51.3. The unchanged raw adapter is 19,390 bytes, SHA-256 `73af96757ba8e012c94543eb03f188b75bb3de572061abcd9388f06a1fd21833`.

## Closure and original evidence

All seven original children completed with exit 0 under the already qualified original-process custody helper. Each original child was reaped once with no live member in its anchored group. No signal was needed. All four parent SQLite connections and their 21 query cursors closed once. All 12 returned Node SQLite connections and 1,750 recorded source/response file descriptors closed once. All installed JavaScript guards were restored. The five explicit kernel-denied loopback probes observed original socket closure; no later network or child attempt occurred.

Both raw process-output pages are preserved, with independent byte offsets, matching hexadecimal/UTF-8 bytes, and final EOF. The five original phase stdout files were read back independently; their exact sizes and hashes match the parent's original child ledger and their JSON values match the embedded phase results. The original synthetic plan and both sandbox policies are also preserved.

The preparation includes eight local real-SQLite checks on the exact parent helper functions. Those local controls use a Python writer stand-in and are explicitly not installed-Mac-SDK evidence. They additionally show that merely opening a read-only connection without establishing a transaction does not retain sidecars. The actual Mac run above remains the authority for the keeper path.

## Production design consequences and limits

A keeper, if later used, must establish its read transaction while the original relevant writer and existing WAL/SHM are still available. Every required source database must independently satisfy its admission; this one synthetic owner does not prove that all five current agent databases or the registry have eligible sidecars. A keeper must remain an explicitly owned outer handle, separate from the claim that an individual capture child's handles have closed.

Fresh independent readers remain responsible for current credentials. The keeper's snapshot is deliberately old. Expected changes from the admitted owner's own CAS are recorded as a new generation; other agent databases, registry, configuration and metadata retain their exact fences. Keeper closure can itself change SHM ctime, so old full-nine-field bindings cannot be relabeled or reused after closure. A new capture or independently verified generation is required before subsequent admission or consumer recovery.

No response, provider dispatch, COMMIT, unknown child, or service action may be retried because a later source observation fails. The current production launcher and gateway registration path still require their own concrete qualification. No production keeper or refresh controller is marked qualified by this evidence.
