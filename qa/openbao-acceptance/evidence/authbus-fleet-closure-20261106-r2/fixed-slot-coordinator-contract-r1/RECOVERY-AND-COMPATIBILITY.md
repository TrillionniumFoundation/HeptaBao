# Fixed-slot coordinator: source recovery and minimum compatible implementation

Status: source inspection and implementation specification only. No coordinator
has been installed or executed by this work. The deployed client contract must
remain `heptabao-authbus-fixed-slots-v1`; the legacy inbox is not its substitute.

## Bounded recovery result

The recorded r11 package was
`/home/qian-qi/heptabao-authbus-chain-tools-20261030-r11/production_authbus_v1`,
with local source commit `6a80b787d006f59376c5bc4ec3f99f240a6b9809` and manifest
SHA-256 `cba57019c7ac852ff33e19c01894eda0a61a54f4ca60f7d2a29b058fbb50c7f5`.
The root agent's read of that exact ROG path returned NotFound. These identifiers
are provenance; the source commit is not a recovered GitHub repository commit.

The local current checkout and the explicitly referenced publication at commit
`06759210bcabcae04b1fa7cb8e6008a60b3ab285` were examined. The latter's
`tools/authbus/production-transport/publication-20261103.json` enumerates four
client modules, their tests, and the lifecycle test driver. It does not enumerate
a fixed-slot coordinator. The lifecycle driver seeds control, manifest and a
profile for authentication/lease tests; it does not consume an outbox or produce
terminal acknowledgements. The publication's phrase “complete AuthBus package”
therefore does not prove that a coordinator was included.

Exact package-name searches in the current local work and the available
TrillionniumFoundation GitHub repositories did not recover that implementation.
The other two agents have no observed copy in their captured X230, ai395,
Pocket4 or Mac evidence. This is a bounded recovery failure, not a statement
that no historical copy exists anywhere. No further broad history search is a
prerequisite for implementing the explicit contract below.

## Sources to reuse and sources to extend

`tools/authbus/production-transport/plugin/bounded-outbox.js` is the authoritative
consumer of the fixed-slot protocol. Reuse its exact canonical JSON digest,
`initialSlot`, `initialAck` and `validatePair` rules as cross-language test
oracles. `production-client.js`, `strict-bao-client.js` and
`private-outbox-store.js` define the client lifecycle and persistent request
barriers. They do not implement the server-side coordinator.

`tools/authbus/authbus_coordinator.py` supplies the existing credential event,
operator grant, immutable profile, manifest CAS and receipt-recovery rules. Its
`once()` enumerates the legacy inbox. That scanner cannot serve fixed slots
unchanged. Reuse or derive the explicit validation and manifest transaction
logic; replace enumeration and add separately journaled acknowledgement and
enrollment operations. Do not call the old inbox scanner behind a new label.

## Enrollment and finite namespace

The owner-controlled topology fixes the enrolled hosts, each UUID epoch, 1–32
slots per host, and 1–128 unique agent names. The client admits only control KV
version 1, schema `heptabao-authbus-fixed-slots-v1.control`, exact private control
digest, `retainedSlotVersions: 2`, positive bootstrap profile count, matching
topology, and a valid coordinator owner UUID. The canonical manifest must be
nonempty, contain at most 64 profiles and bind the same owner UUID.

Preallocate with CAS 0, bind every original dispatch to a durable private
journal, and read back complete exact documents:

| Key under `openclaw-auth` | Initial document / writer |
| --- | --- |
| `transport-v1/control` | Immutable admitted topology; publish only after its referenced enrollment and canonical bootstrap are confirmed |
| `transport-v1/<host>/outbox/slot-000` … | Exact `initialSlot(source, index)`, version 1; subsequently only that host's producer updates |
| `transport-v1/<host>/ack/slot-000` … | Exact `initialAck(source, index)`, version 1; subsequently only the coordinator updates |
| `transport-v1/<host>/reports/<sha256(agent)>` | `{schema: TRANSPORT+'.report', sourceHost, epoch, agentId, sequence:0, event:null}`, version 1; subsequently only that host/agent producer updates |
| `manifest`, `profiles/<content-key>` | Existing operator-authorized canonical publication rules |

Configure and verify the actual two-version retention needed by the slot/ack
protocol. A slot or report must not be deleted/recreated to reset its KV version
or sequence. A failed/unknown enrollment is retained, not repaired with a new
epoch or new operation key. Any known-but-different existing document requires
explicit review.

Client policies may read the admitted canonical manifest/profiles/order policy/
scheduler assignments/control and their exact own slot/ack/report records.
After enrollment, they may update only their own fixed outbox and report keys;
they may not write acknowledgements, canonical profiles/manifest, other hosts,
or a legacy inbox. Coordinator rights are separately scoped. An AppRole login
does not itself authorize a credential transition.

## One fixed-slot transaction

1. Acquire the existing private operation lock and resolve the exact previous
   pending operation before admitting another. Read current immutable control,
   canonical manifest and the exact enrolled slot/ack pair. No unbounded LIST
   or caller-selected path is needed.
2. Validate both exact schemas/field sets, host, epoch, index, safe sequence,
   document digests and KV versions. Both KV versions equal their corresponding
   `sequence + 1`. A pair is either terminal at the same sequence, or has one
   pending event where slot sequence is ack sequence plus one and
   `previousAckDigest` equals the complete current ack's canonical digest.
   Reject any skipped, rewritten, foreign or ambiguous history.
3. For a credential event, apply the existing full event validator and exact
   operator grant: authorization UUID, profile ID, source host, provider,
   identity digest, expected current credential digest and next credential
   digest. Expiry, a producer's login, or a larger timestamp is not a grant.
4. Retain the existing immutable profile CAS-0 and manifest transaction. The
   same manifest CAS replaces the profile reference, increments generation,
   consumes the exact grant and records the canonical receipt provenance.
   The manifest receipt is confirmed or recovered through exact retained
   history, never inferred from a matching new credential alone.
5. After the canonical receipt is confirmed, prepare the exact acknowledgement
   with a separate fsynced intent before its one CAS dispatch. Its fields are:
   `schema`, `sourceHost`, `epoch`, `slot`, `sequence`, `slotVersion`,
   `slotDocumentDigest`, `eventId`, `eventDigest`, `status`, `receiptDigest`,
   `receipt`. It copies the exact consumed slot sequence/version/digests and
   receipt; its CAS preimage is the previously read ack version/document.
6. Require complete response and exact readback. `validatePair` must accept the
   resulting pair before it is reported terminal. Only then may the producer
   reuse the slot. A manifest commit without an ack remains pending transport
   work; it is not a second credential transaction.

For `committed`, the receipt schema is
`heptabao-authbus-coordinator-v1.receipt`; owner, source/event identity,
credential digest, hashed profile ID and content-addressed profile key must
match the exact slot event. For a schema-2 `health-observation`, the compatible
terminal status is `observed_health_no_scheduler_action`; preserve exact
event/owner bindings and do not grant a scheduler or provider action. Unsupported
event kinds remain blocked/pending; do not invent a terminal status that the
client cannot validate.

## Reports and scheduler boundary

Reports are separate overwriteable, fixed per-agent records, with sequence
bound to KV version. Validate enrolled host/epoch/agent, exact report document
and event kind; reject credentials in the report. They do not consume a slot
and do not require a slot acknowledgement. Reading a health/report document is
not proof that a provider is usable and does not authorize a lease or scheduling
change. If the deployment does not implement scheduling, its explicit canonical
empty scheduler document and the existing plugin behavior must be qualified;
never claim that the coordinator supplies a scheduler through report ingestion.

## Unknown outcomes and recovery

The private journal must bind coordinator owner, control digest, host/epoch,
slot index, exact slot document/version, previous ack document/version,
canonical receipt and desired ack. Record dispatch before the mutating request.
On restart, only read to reconcile a previously dispatched request. An exact
expected postimage at the exact next version proves that effect. Equality to
the old preimage does not prove a delayed original request cannot still commit.
Unknown manifest, profile, ack or enrollment effects must retain their original
identity and stop new work; no fresh key, epoch, event UUID, empty local state or
rewound backup may bypass the barrier. Explicit known CAS conflicts and known
non-dispatch can be archived under the existing original-outcome rules.

Ack recovery must additionally distinguish a producer that has advanced after
a confirmed ack from a foreign overwrite. If the current slot is already one
generation newer, bind the recovered ack to its original slot through retained
version history and exact `previousAckDigest`; do not validate it against the
new event. If that original history is unavailable, remain unknown. The client
retains at most one unacknowledged generation, but that does not justify
guessing which event a receipt belongs to.

## Required evidence before production use

Use the unchanged client validators against the new coordinator with a normal
HeptaBao service, strict independent CA/leaf trust, exact AppRoles and bounded
deadlines. Minimum substantive cases are enrollment and actual ACL denial;
authorized credential publication and two rotations through the same slot;
unauthorized/stale/revoked grant refusal; health ack and report handling;
all-slots-full backpressure; server/client/coordinator cold restart; and process
death or dropped response at profile/manifest/ack boundaries with no repeated
unknown mutation. A recovered manifest commit must produce exactly one terminal
ack, and a crash after remote ack before local journal completion must resolve
by exact original readback without replay. Retain original failures and all
process/FD/network closure evidence. Synthetic qualification and source review
are distinct from current provider-valid credential migration and client cutover.

Credential values and credential/config/profile-derived digests remain in the
private journals and private wire documents. Public evidence contains only
fixed schemas, operation ordinals, counts, source pins and outcome booleans.
