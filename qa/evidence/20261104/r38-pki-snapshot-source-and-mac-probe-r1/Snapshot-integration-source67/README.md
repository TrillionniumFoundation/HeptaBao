# Native snapshot standby forwarding — integrated SOURCE draft 2

This is a reviewable Rust source candidate, not execution evidence. It uses
808e45d690f177ecb922e13d1ed19f7877156094 / 0506d30b02f5a2a2dc7d6364299365ae8d1d7cc7
as its exact base. The JWT formatted service.rs is preserved byte for byte
except for its existing begin_forwarded function. The other ten modified
base files were checked against the exact current source directories.
There is no branch update, build, format, test execution, Runtime operation,
fixture or product publication in this packet.

## Actual problem and boundaries

The preserved 4e808 official 2.7.1 CLI run failed B04 and B05. B04 was an
incomplete standby save. B05 returned CLI exit zero but the actual request
was rejected and all three nodes plus cold recovery retained the mutated
state. The report does not identify the second HTTP upload bytes, actual
ALPN, or the internal reason for HTTP 400. This source changes the default
native HA snapshot forwarding path, not CLI flags or the original test
expectations. Explicit no-forward, query, repair and non-native paths retain
their original local redirect handling.

## Concrete ownership and event order

1. The HTTP admission captures its original request clock, actual spool
   owner and one selected remote leader. The returned affine plan performs
   exactly one peer exchange outside the Service writer.
2. The existing authenticated HA listener uses its original capacity slot
   and worker. Ordinary frames retain the exact original callback and
   diagnostic classifications. The new snapshot branch uses actual mTLS
   peer enrollment, current/next pinned leaf identity and strict ALPN.
3. The leader clamps its accepted connection deadline to the same original
   request timeout before Actor admission. It performs the existing
   snapshot request admission once. The READY MAC binds this actual Actor,
   original Auth projection, physical seal, activation, identity, epoch,
   request nonce and actual completed prefix.
4. The ingress verifies READY, authenticates its catch-up and original
   Auth view, and only then allows the first upload byte to be read.
   Finite-use Actor validation is delivery only; it does not consume a
   second use or validate the original Actor against restored Auth.
5. DATA/END frames require exact length, SHA256, order and actual transport
   EOF. TLS close_notify permits reading the opposite direction. The
   original snapshot parser result must also succeed: BodyComplete alone
   cannot turn an inner Err into success.
6. The original snapshot finalizer, historical restore receipt, token
   clock and mandatory audit run with the real plan retained. The source
   completion MAC binds the actual Verified upload, sealed private file
   descriptor, actual Actor/owner data and authenticated READY.
7. Immediately before MAC publication the retained physical owner and real
   historical/download gate are checked again. Current identity, epoch,
   activation, owner projection, clock precision/floor and audit identity
   must still equal the signed data. Any failure after an actual historical
   publication uses only its private receipt to return outcome_unknown,
   root_attempted, the original recovery_reference, retry_allowed=false,
   and fence the local service. The original failed-finalizer response
   remains unchanged. No wire object can manufacture this authority.
8. The response sink is a private held SnapshotFile, never HTTP. The
   ingress requires its independent actual download witness and whole-file
   digest, then its real native pre-audit and post-audit gates and original
   Actor validation. Only then can HTTP expose the file or terminal JSON.
   Vetoes drop the affine file and do not replay the source operation.

## Surface and bounds

- Existing HTTP 15-second and HA forwarding absolute bounds are reused;
  no clock is refreshed and no budget is raised.
- One selected peer, one connection, one request; no redirect loop,
  fallback, request replay, or hidden retry is added.
- The dedicated native archive stream is bounded by MAX_NATIVE_ARCHIVE,
  uses at most 65536 bytes per DATA frame, and exact END plus actual EOF.
- The existing public H2 32 MiB request limit is unchanged.
- Ordinary JSON completion, retained-KV owner exceptions and ordinary
  forwarding remain separate. No JSON receipt grants binary authority.
- The old incomplete checkpoint cc59c38bb3a0ad42cdb655f33c612397f86cd92a
  remains preserved. This successor adds the missing HA/HTTP wiring,
  source post-publication failure handling and current JWT base integration.

## Source components, not runtime qualification

23 test functions are present as source: ten body/EOF components; seven
peer components (six socket/mTLS scenarios and one constructor-only
expired-deadline rejection); four binary publication/READY binding
components; two actual Auth-state Actor components. The earlier frozen
transport slice had six functions (five socket/mTLS plus one constructor).
Its static peer is not a qualification of this new Service integration.

The new READY component checks that an admission veto reads zero upload
bytes, cannot extend the accepted deadline, never enters the body consumer,
and joins the actual socket worker. Wire components use actual
encode/decode witnesses and reject even a correctly MACed substituted
descriptor. Auth components exercise a real final finite use and separate
the retained original Auth from a freshly restored owner. None has been
compiled or executed. No assertion suppression or lint allow is added.

## Mechanical checks and remaining gates

Each of 23 files has complete after text and a strict unified diff; the
eleven modified files also have complete before text. All 42 hunks were
applied and reversed with exact whole-text equality in pure V8. The two
current directory responses preserve source-membership evidence. The
diff helper and service function excerpts are included. These checks
establish source identity only, not Rust type correctness.

The next gates remain independent source review, exact formatter output,
Rust compilation with the actual features, selected real components,
and fresh official CLI B01–B05 with the original valid archive/baseline,
all-three-node plus cold readback and audit conditions. No prior runtime
qualification is transferred to this draft. PKI's future three-file
successor must be merged without replacing these or the JWT changes.
