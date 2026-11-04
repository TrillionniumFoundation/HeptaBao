# R2 exception and cleanup correction

R1 was staged and its preparation completed, but its preflight and live commands
were never launched. R1 files, receipts and hashes remain unchanged. R2 uses a
new QA directory and new preflight/live directories. It reads the same exact
frozen private inputs and writes a separate `prepare-r2.public.json`; the old
preparation is retained.

The controller now records the safe HTTP operation name, method and route before
entering the original `server.call`. It never logs request bodies, token headers
or returned credential values. Only a clearly returned status/value clears the
in-flight record. A transport/parsing exception retains that record and makes
the result conservatively unknown. A returned HTTP rejection remains a known
response. Neither kind is retried.

Every exception from launching or communicating with an owned Node process now
passes through the same bounded kill/wait cleanup. The original exceptional
cleanup ceiling remains five seconds, shared by wait and any final timeout-pipe
drain. The normal consumer70/rollback35 and outer440 limits are unchanged. An
exception preserves its class and known reap state. Failure before a process
handle is retained is also treated conservatively; absence of a handle is not
proof that no process was created.

No rollback child may start without confirmation that the corresponding Node
and its native children stopped. An unconfirmed Node cleanup blocks all further
rollback children in that run. The rollback-attempt guard is consumed even when
execution must be refused; it is never retried. The outer private PID namespace
is still the final cleanup boundary. Partial or skipped rollback cannot qualify
the fixture.

The original consumer, cache helper, native observer, raw auth-row CAS helper,
trusted-source projection and registry-input helper are unchanged. Only the
controller behavior and the necessary new QA/preparation/run path bindings
change. Core behavior, original first-cycle predicates, real credential
generations, grant scope, original flags/caches/order/exclusions and all original
request budgets remain unchanged.

The focused local component ran three real owned Python children: an injected
non-timeout communication failure after real spawn, an actual timeout, and a
normal completion. All three were stopped and reaped. It also executed the exact
nested HTTP-call AST and actual unknown-classification expression for synthetic
timeout, malformed reply, known rejection and known success, then the exact
early rollback-gate AST for three unconfirmed-stop states. All25 checks passed.
This is a component result, not Pocket runtime or actual HTTP/TLS qualification.
The pre-freeze syntax error and synthetic-holder field error are retained as
separate failed component-attempt records; no product or runtime predicate was
relaxed to correct them.
