# HeptaBao durable backend profile marker

`durable-backend.json` is a local, private marker published beside `seal.json`.
It is metadata only: encrypted snapshot, replay ledger, and journal bytes stay
in the selected durable backend. The marker prevents a restarted process from
silently reopening a PostgreSQL deployment against the local filesystem.

Schema `2` contains `backend`, `scope`, and a 64-character lowercase SHA-256
`binding`. The binding is domain separated with
`heptabao.durable-profile.v2` and covers the enrolled PostgreSQL endpoint
origin, pinned address, TLS server name, path prefix and CA bundle, database
connection URL, username, and scope. It never stores or hashes the database
password into the marker. The marker therefore rejects a restart that changes
the database target or trust profile while retaining the same scope.

Schema `1` markers are rejected as an explicit offline migration condition.
They contain only a scope and cannot prove which database target was used; the
server never upgrades them in place and never falls back to file storage.
Operators must complete an explicit migration or reinitialization that writes
a schema `2` marker before unseal.
