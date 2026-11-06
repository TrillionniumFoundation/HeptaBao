# Narrow ingress audit failure correction — SOURCE r3

Root review d873378c48f691f121b82e1a6a5af52c45ca5904 identified two error
exits in integrated SOURCE67 that replaced an already constructed UNKNOWN
with an ordinary503 when a later response/veto audit failed. This exact
successor changes only three of its23 Rust files. The original67 and its
blocking review are preserved.

The plan now records one local transport-attempt marker immediately before
the one endpoint.exchange call. It is false throughout preflight and HTTP
framing rejection. Audit or writer-lock failure after that boundary returns
conservative outcome_unknown=true and retry_allowed=false; no response JSON
is consulted for root_attempted or recovery_reference.

Once the existing CompletionWire.authenticate has checked its dedicated MAC
and independent actual upload/download witnesses, all later failure paths
retain that exact CompletionData. This includes private-file descriptor
comparison, ReplyData conversion and both native delivery gates. An audit
failure reconstructs a fixed UNKNOWN response from that retained data.
A HistoricalRestore terminal supplies its authenticated operation reference;
a Download never fabricates one. Known peer rejection JSON is discarded on
an audit failure and is not promoted into an authenticated publication.

The common veto audit function now accepts a caller-provided failure
constructor. It erases the previous response JSON, fences the service as
before and invokes that constructor. The ingress passes a closure over the
already authenticated completion. The source's only call is after its
actual private historical-receipt veto branch returned None, and continues
to pass its original unavailable constructor. Its actual restored receipt,
original root attempt/reference, Actor, physical owner and final MAC gates
are unchanged.

PLAN.json enumerates every new forwarding audit exit and the source of its
failure authority. Ordinary callback/JSON forwarding, selected peer,
deadline, capacities, private file custody and all23 test sources are
unchanged. No positive response or file is released by these failure paths.
No field of arbitrary response JSON creates authority.

The three diffs (8+1+1 hunks) were applied and reversed exactly against the
whole SOURCE67 members. Eighteen additional pure V8 source/dataflow checks
passed; they are source checks, not Rust execution or regression test
qualification. No format, compilation, candidate function, Runtime or
fixture was run. Future actual audit-failure validation remains necessary
alongside the existing component and fresh official CLI gates.
