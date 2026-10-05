# Native public producer facts (isolated schema 86 source)

This finite source implements producer facts observed in pinned OpenBao 2.7.0,
commit ca305a02daa68b203325daa1b25c18d7a252d4b3. It is not a qualification claim.
No Cargo or candidate HTTPS run has occurred for this source at freeze time.
The combined Root writer, schemas 82–85, Linux, HA/mTLS, and full replacement
remain separate and unqualified. The isolated parent already supports namespace
custody schema 81; this successor explicitly supports 86 and rejects 82–85.

## Actual evidence and input surfaces

The fresh official R43-r02 matrix records 69 real operations, including root and
ordinary namespace Token API service/batch issuance, wrapping, process restart,
and repeat lookup. Every real mint records same-host wall nanosecond bounds.
The complete raw archive remains private; no actual credential, token ID, key,
share, dynamic nonce or namespace UUID is checked into this source.

The original inputs distinguish omitted meta, explicit JSON null, an explicit
empty string map, and a populated public string map. A service token returns
null for the first two and preserves the exact map for the latter two, at mint
and lookup. A native batch token preserves an explicit empty map at mint but
returns null for an empty map at lookup, including after restart. This is the
actual native protobuf round-trip boundary, not a rule for provider batch
metadata or every empty map in an HTTP response. Go weak map/scalar conversion
outside these four input shapes remains open.

The pinned primary Token API producer preserves meta nil-versus-map and its
actual creation path. `internal/vault/expiration.go` RegisterAuth stores actual
service lease time.Time; its batch path uses time.Unix(CreationTime,0). The
observed service issue_time has a real nanosecond fraction and local offset;
native batch issue_time has integer seconds and local offset. The service
observation survives lookup and restart unchanged. Both manual and Token API
wrap creation_path values are relative to the actual owner namespace.
`internal/vault/wrapping.go` captures time.Now once, stores the full time.Time
in cubbyhole creation_info, and HTTP uses time.RFC3339Nano.

## Complete private owner

TokenApiOrigin owns the admitted metadata input variant and immutable relative
creation path. CreationStamp owns the observed epoch seconds, nanoseconds and
actual local UTC offset, with closed serde grammar. It uses the existing trusted
listener wall observation plus the original monotonic anchor. No client input
selects that clock; no new deadline or retry budget is introduced. Historical
missing fields and direct explicit-clock Service calls retain None. No old
integer timestamp receives fabricated nanoseconds or a later producer sample.
The independent wrapping producer stores its single immutable stamp in the
wrapped owner. The same fact is used by wrapping mint and lookup after reopen.
Native batch claims own metadata once within the unchanged 8 KiB AEAD claims and
16 KiB bearer bounds; their input variant does not duplicate the metadata map.

AuthState retains a root-owned sticky public origin floor. All real service
issue/store paths pin it when they contain new facts; native batch pins it only
after genuine sealing in the candidate. Credential delivery still depends on
the existing atomic publication and late admission guards. Origin facts confer
no principal, key, parent, alias, policy, namespace or lease authority.

The complete typed Token moves with NamespaceAssets. Detach leaves the global
floor in root Auth; restore requires the retained floor before any attach, with
all existing collision checks. Strong and inherited owner encryption, actual
Binding/incarnation/AAD, cells, manual frontiers and nearest-parent key custody
are unchanged. Closed Auth authenticates against the full private parcel and
never registers a transient child key. Its atomic finite/wrapping consumption
serializes the complete updated Auth owner, including origin facts and floor.
Canonical record publication serializes protected Auth, not the loaded logical
projection. Owner digests and authenticated received graph validation therefore
include the same complete facts. Future precision82 integration must continue
to use this complete protected owner; it is not included here.

Writer promotion, publication, format admission, received materialization and
snapshot restore reject a hidden/missing/downgraded origin floor. Retirement,
revoke or wrapper consumption cannot authorize an old reader or old snapshot.
The high maximum does not admit unknown schemas 82–85. Existing old fixture
labels may need new successors when native Token API issuance now genuinely
raises their reader requirement; old failed originals must be preserved.

## Proposed verification, not results

Meaningful new tests cover real producer wall bounds; sixteen input/type/owner
samples and durable reopen; four real wrappers and repeat lookup; explicit-clock
absence; retirement and old snapshot refusal without artifact changes; complete
Auth digest and genuine-key authenticated malformed received owner rejection;
full NamespaceAssets round-trip and no-partial-attach floor failure; actual
closed finite admission without key registration; and strong share restore of
unchanged stamp and empty metadata map. They have not run at source freeze.

Remaining scope includes weak map conversion, historical missing origin facts,
lease expiry fractional precision, root-init lease issue_time, full namespace
HCL/PGP/remote effects, closed batch/cross-owner mutation, schemas 82–85 combined
admission, native HA inherited adoption, and final Linux/mTLS whole-system proof.


R38 static review successor additionally requires the typed retired Auth floor
for exact schema 86 even when no token facts remain and there is no prior live
state. A genuine mint/revoke plus real-key authenticated received-graph negative
covers this source invariant; R37 was not compiled or launched and stays an
unqualified predecessor. This remains proposed test code until actual execution.
