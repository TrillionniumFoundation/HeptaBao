# Donor-window dispatch-order observation — source proposal

Parent: c133d7e7b8a1df5f0be8f4337893f234c6ccede2. This proposal creates no commit/ref, dispatch, build or runtime request. The running df026 host candidate is unchanged.

## Observed CI boundary

The root reports PR152 merge job 127009390540 failed the existing silent-donor testcase at line 329 with the unresolved-tail assertion. The exact tested merge is ae18cbdd8b29dbf612588ea81aa22cbbf6a33952. Full failure log is retained at blob a02bfea997bb0f4abb7fc3769f2cae6f0b7b9150; this proposal does not rewrite that failure as a pass.

The test and pull implementation have identical Git blob IDs in the exact CI merge, df026 and this c133d7 parent. The independent source read confirms that all preceding real wire population, recovered bytes/root, checked local closure, task cleanup, capacity and 14-second assertions precede the failed ordering assertion. No per-request arrival trace is available from that historical failure, so a unique historical interleaving is not claimed.

## Source-level cause of the ordering gap

fill_object_window first assigns leaves without any pending request, then permits a cross-donor race for remaining unresolved leaves. pending_pull submits separate Tokio tasks. Four real TLS server workers append their observations only after separate authenticated exchanges arrive. A late original healthy-leaf connection can reach its server handler after a subsequently submitted silent-tail fallback request. Assignment priority therefore does not imply the same total order at the remote handlers.

The existing server-side assertions still establish exactly four silent requests, exactly 24 healthy requests, and the complete exact 24-object set. The old final-four assertion additionally imposed a receive-order property for which the actual concurrent transport has no ordering contract.

## Minimal proposal

1. Inside the already cfg(test)-only observation module, retain an ordered vector of (donor, object ID) for actual object task submissions. Manifest submissions still count in spawned but add no object entry.
2. At the existing sole-controller spawned observation, after runtime.spawn and before pending_pull returns, record the same target and validated reference ID. Sequential calls cannot record in another order; the hook grants no authority and changes no transport state, deadline, scheduling decision or persistence call.
3. Preserve all real server arrival collection, first-window disjointness, complete wire population/uniqueness, slow-four, bytes/root, actual ReadIndex, 8-global/4-per-donor capacity, 14-second bound, cancel/join and source-stop assertions. Add exact count and set checks for the healthy dispatch observations. Apply the original final-four silent-tail assertion to that actual dispatch order, still matching the first silent IDs observed on the wire.

The production projection is byte-identical after removing the two cfg(test) observation regions. The server fixture, handler barriers and two existing test entries are byte-identical. No sleep, extra request, wider deadline, retry, lint suppression or test denominator is introduced.

## Validation and remaining gates

A local offline source-mechanics script applied and reversed all four unique changes, generated the 3-hunk implementation and 1-hunk test diffs, and verified the non-test projection plus unchanged fixture and contract statements. It did not import or execute Rust, use a host, start a product, compile or format Rust.

Formatting/compilation and the unchanged two actual donor-window tests require a later explicit build plan. No previous Mac60, df026 selected60, old CI or source review is transferred to this proposal as execution qualification.
