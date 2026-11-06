# Remaining three controls bodies after the qualified body0

SOURCE only. This is a narrow adaptation of the existing 35,548-byte four-file journal, with the independent-context pattern already used by B. It is not a new Runtime service or wrapper.

The original paused 208,774-byte context and the completed body0 reconciliation context are each pinned as a whole. Initialization and every later state access check these entire immutable snapshots. Neither historical context receives a store. The new context starts with zero calls and zero newly completed observers. Its inherited body0 row refers to the actual completed operation, full native payload and 30,397-byte body; the prior real observer is explicitly separate in inheritedClosedObservers.

Only the already frozen body1, body2 and body3 requests may be admitted, in that order. They are three separate files, each with its own closed metadata, path, version, full SHA and EOF. No two-range join is borrowed from B. The existing complete per-file closer and original SDK acceptance functions are byte-identical. No new metadata or body0 request is allowed.

Five strict hunks describe six explicit replacements. Five existing functions change; the remaining definitions are preserved. The initializer handles only inheritance and a separate exact root GO; state access protects the old snapshots; validation limits the three requests and their status/pages; invocation drops process/INFO paths; the public action dispatcher drops old metadata/body-authorize actions.

The new root GO must pin the actual predecessor qualification as well as the exact three requests, the historical state pins and the actual body0 native/release. Its supplied raw qualification is whole-hashed before initialization. The template remains unauthorized and its qualification pin is null; this is not a request to invent that pin.

74 source/private-memory checks passed, including 37 guard cases. No real context was initialized. All private test stores and fake authority values were isolated; no Native, Git, compiler or product test was called by the verifier. Production test denominator remains 149/166. The live root evidence archive for body0 is ef7f4f011eb70b4183c298f3ac6a81a475a2f869.

After a separate GO: whole exact arm, independent invocation boundary, one read, returned-ID closed status and contiguous 16 KiB pages, complete payload/body SHA+EOF, then the next original request. Total remaining decoded bytes are 60,208; together with body0 they make 90,605. BUILD is separate and remains unsubmitted.
