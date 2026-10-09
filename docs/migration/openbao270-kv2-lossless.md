# OpenBao 2.7 KV2 lossless migration

This tool exports the raw KV2 records and imports one validated bundle through
HeptaBao's `POST /v1/sys/migration/openbao/kv2` transaction. Public KV reads cannot
recover retained soft-deleted values or original version deletion timestamps.

Stop writes to the source mount for the duration of export. Export is read-only;
it enumerates the complete raw mount twice and refuses to produce a bundle if
the mount UUID or any record changes. Two equal reads are a consistency check,
not a transactional snapshot of a source that remains writable.

Use a source root token with the raw storage endpoint enabled. The destination
token needs update and sudo on `sys/migration/openbao/kv2`. Create an empty KV2
destination mount first. Import rejects a non-pristine mount and any replay.
The bundle contains secrets; keep its directory private and its mode 0600.

```sh
python3 tools/migration/openbao270_kv2_migrate.py export \
  --address https://source.example:8200 --ca-file source-ca.pem \
  --token-file source.token --mount secret --output kv2.bundle.json
python3 tools/migration/openbao270_kv2_migrate.py import \
  --address https://destination.example:8200 --ca-file destination-ca.pem \
  --token-file destination.token --mount secret --input kv2.bundle.json
```

Use `--namespace child` when the source or destination mount belongs to that
namespace. Token files and import files must be private regular files owned by
the invoking user. Export never overwrites an existing file. HTTPS verifies the
certificate and hostname; cleartext HTTP is accepted only at a literal loopback
IP for a local process or SSH tunnel. Redirects and environment proxies are
disabled. Requests have a five-second timeout and a 360-second overall deadline.

The decoder preserves exact JSON numbers, Unicode, all retained versions,
metadata CAS counters, nanosecond timestamps, destroy/delete markers, key and
engine configuration, custom metadata, and original scheduled-deletion timestamps.
Every raw version must authenticate its locator against the actual raw salt and
match its metadata creation timestamp. Unknown fields, duplicate maps or JSON
keys, missing versions, orphan payloads and unsupported records fail closed.

Current finite bounds match the import implementation: 10,000 raw records,
1 MiB per raw record, 64 MiB aggregate acquisition, 16 MiB import request,
10,000 entries, JSON nesting 128, canonical logical names up to 1,024 UTF8
bytes and deletion durations up to ten years. These limits are explicit
qualification limits, not a claim to accept every possible OpenBao installation.

An import makes one HTTP write and does not retry. If the connection fails after
submission, inspect the destination before any further action. Successful import
returns HTTP 204. Verify reads, history and metadata, then perform a durable
restart before switching application traffic. Source records are left intact.

The command's printed receipt contains sizes and hashes, never secret values.
Native HTTP, encrypted restart and live source collector qualification are
tracked separately from the strict decoder's recorded baseline.

## Absolute deadlines and owned execution

The default CLI entry supervises one isolated worker in its own POSIX session.
The original 360-second monotonic deadline starts before argument parsing,
credential reads, capture, decode, staging, publication and receipt generation.
Each HTTP operation runs in one short-lived isolated Python process. Token,
headers and request body pass through anonymous stdin only. The original
Popen.communicate deadline is the smaller of five seconds and the remaining
overall budget, covering connection, headers and the complete response body.
A timed-out operation receives SIGTERM, then the original process is waited
for; the write is never retried. Termination waits are cleanup and do not
extend business deadlines. Overall timeout terminates only the worker's
owned session group. This strict CLI currently requires Linux/macOS POSIX
process groups; unsupported platforms fail before any input or HTTP action.

Export stages a private file in the destination directory, checks the original
deadline after writing and fsync, then publishes exclusively. Existing output
is never replaced. POSIX link/unlink publication leaves one final link.
A timeout or uncertain import outcome is a failure even if the destination
might have committed: inspect the destination before choosing any later action.

The recorded seven local controls exercise a real slow-drip HTTP response,
refused redirect, private file and symlink guards, blocked credential input
under the original overall supervisor, output deadline checks, exclusive
publication and successful private output. They do not qualify a real
OpenBao export, HeptaBao import, or the decoder's independent prior oracle.
