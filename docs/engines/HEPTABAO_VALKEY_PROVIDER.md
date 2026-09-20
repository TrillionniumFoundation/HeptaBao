# HeptaBao Valkey database provider

HeptaBao now has a bounded Valkey ACL provider profile behind the database
service. The profile is intentionally deployment-enrolled: configuration uses
`valkeys://host:port/<database>` and the matching `valkeys://` endpoint must be
present in `outbound_endpoints` with a pinned address, server name and CA. The
client performs RESP2 over verified TLS, authenticates the configured manager,
selects a database in the range `0..15`, and fails closed on a protocol error,
timeout or ambiguous write.

`plugin_name` is `valkey-database-plugin`. Dynamic roles currently accept only
the bounded `readonly` and `readwrite` profiles. Each issued lease creates a
deterministic ACL user with a generated password, `on`, no channel patterns,
one generated key pattern bound to the provider identity, and the selected
command category. The provider state is read back with `ACL GETUSER` before the
durable lease is marked active. Revoke issues `ACL DELUSER` and requires a null
`ACL GETUSER` readback. A lost response remains a durable pending intent and
the normal database reconciliation worker can retry it after reopen.

The manager connection is verified with `PING` and `ACL WHOAMI` before the
configuration is committed. Manager credentials remain private state and are
never included in configuration readback. Existing PostgreSQL database state
continues to deserialize because the provider field defaults to PostgreSQL.

This is a scoped adapter, not a claim of OpenBao provider parity. Static-role
rotation, root credential rotation, cluster/sentinel discovery, ACL selector
expressions, RESP3, transactions, and independent real-Valkey qualification
remain open. The implementation also does not modify the compatibility corpus
until a real Valkey TLS fixture and restart/revocation evidence are available.
