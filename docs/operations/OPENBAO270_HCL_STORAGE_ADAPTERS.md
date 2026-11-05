# HCL storage adapters

The static parser now selects the existing durable consumer from one storage
stanza. This is source-only implementation; it has not been compiled or run.
OpenBao 2.7.0 non-Go documentation is pinned in the author contract receipt.

- PebbleDB durable path selects the native single-node file-backed durable
  owner at that path. It conflicts with HA and PostgreSQL. This adapter retains
  durable single-node semantics, not the physical PebbleDB file format.
- Raft path selects native application state under path/state and native Raft
  under path/raft. An explicit --ha-config remains required. Before
  HaProcess::start, the directory, optional node_id, required cluster_addr and
  optional api_addr must match the enrolled local peer. Direct library serve
  also rechecks the actual running consumer. Three-voter admission, TLS peer
  pins, replication key and bootstrap guards remain unchanged.
- PostgreSQL connection_url accepts a bounded URI subset with a username and
  password, standard postgres/postgresql schemes, default port 5432 and
  optional sslmode=verify-full. The native canonical Target parser validates
  the destination. Exactly one existing outbound_endpoints enrollment must
  match that origin. The parser does no DNS, environment reads or networking,
  and never changes enrolled addresses/CA roots or disables TLS. Credentials
  are transferred into the existing zeroizing PostgreSQL durable config.
  Default table, ha_enabled=false and skip_create_table=false are recognized.
  Native PostgreSQL manifest/chunk SQL and scope openbao270 are selected;
  existing OpenBao SQL rows are not reinterpreted as native state.

JSON without the new selector preserves its existing deployment schema and
consumer behavior. Conflicting aliases and unsupported options are rejected
before provider effects. There is no silent Raft-to-local or PostgreSQL-to-local
fallback.

Remaining replacement blockers are explicit: PebbleDB :memory: and read_only,
OpenBao physical database migration, automatic Raft identity/enrollment and
retry_join/discovery/timing options, PostgreSQL custom tables/HA read standby,
general pgx URI/keyword/environment configuration and unenrolled DNS endpoints.
The mandatory native audit file, TLS and deployment-owned SDK/provider fences
remain part of this adapter contract.

Three new controls check selection, path/identity/address drift, HA conflicts,
enrolled PostgreSQL credentials, TLS downgrade refusal and unsupported modes.
All prior 274 functions and the six inherited HCL functions remain literal.
No registration, Cargo, server or full-replacement qualification is claimed.
