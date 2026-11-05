# OpenBao SDK Backend companion

This companion uses `github.com/openbao/openbao/sdk/v2@v2.7.0` and its official
go-plugin client to launch application protocol v5 logical backends with
AutoMTLS. It performs Backend Setup, Initialize, HandleRequest and Cleanup.
The external plugin receives the official Backend and Storage gRPC protocols.
The version 1 newline JSON channel is private IPC with the Rust host only.

Build with Go 1.27 or later, with module checksums enabled:

```sh
go build -mod=readonly -trimpath -o heptabao-openbao-sdk-companion .
```

`heptabao_plugin_host::sdk_backend::SdkBackendHost` retains digest-verified,
sealed executable images for both binaries. The caller supplies an owned
private socket directory, a fresh private log, TTL defaults and a mount-scoped
`SdkStorage` view. Requests have one deadline; storage callbacks do not extend
it. Callback sequence assignment and output are serialized even when the
actual plugin performs concurrent Storage RPCs. Protocol uncertainty fences
the host; it never restarts the plugin or retries a business operation.

The caller must enforce namespace and mount incarnation, authorization, seal
and HA fences, and the durable commit policy in its storage view. The trait's
deadline covers each operation. A plugin's storage write can have committed
before a later plugin error, so callers must not treat an error as a rollback.

The first adapter supports secret backend CRUD, List and ListPage. It rejects
auth and lease-bearing responses because their issuance and revocation must be
integrated with the server's durable lifecycle. SystemView currently supplies
static lease defaults. Transactions, provider capabilities, catalog mutation,
HTTP mounting and server barrier storage integration remain separate work.
The test example does not qualify those capabilities or full replacement.

The genuine fixture under `crates/heptabao-plugin-host/fixtures/sdk_v270` also
builds with its own pinned Go module. `sdk_backend_real` accepts the companion,
fixture binary and a fresh output directory. It calls the HeptaBao Rust host,
persists a test file storage view, starts a fresh host to read it, propagates a
real storage rejection, and exercises 16 parallel SDK Storage workers and
paginated listing. Its report explicitly retains server plugin ABI as false.

Committed StorageKey invalidation uses a separate `storage_key_v1` control.
`SdkBackendHost::invalidate` accepts 1–256 sorted, unique mount-relative keys,
each at most 4096 bytes and at most 64 KiB in total, under the original owner
deadline. Setup must advertise this control; an old companion is fenced if
asked to invalidate. The typed acknowledgement contains only version, kind,
call, control and count. Duplicate fields, logical responses, Auth, Secret,
Storage messages, stale calls and incorrect counts cannot acknowledge it.
The same-host control carries an absolute `CLOCK_MONOTONIC` deadline. The
companion subtracts IPC time and maps the remaining interval conservatively
to its Go monotonic context; wall-clock adjustments cannot renew the window.
The Rust owner checks its original `Instant` again before accepting the ack.

The companion reuses its admitted AutoMTLS `go-plugin.GRPCClient.Conn` and the
official `plugin/pb.BackendClient.InvalidateKey`. The SDK v2.7.0 server calls the
real backend's `InvalidateKey` hook before returning `pb.Empty`. Its public
logical backend client discards the RPC error, so this control deliberately
uses the typed client and requires a successful nonnil reply for every key.
Timeout, owner closure and transport failure produce no acknowledgement and
fence the Rust host. The control leaves the active Storage call at zero and
does not authorize a hook to mutate host storage.

`go test` includes a genuine SDK process with AutoMTLS and a cache that remains
stale after a host storage change until the real hook runs. The Rust
`sdk_backend_invalidation_real` example additionally tests actual private
stdio control, exact hook counts, Storage mutation denial, original-deadline
timeout, fencing and a genuinely old companion lacking the control. Both are
bridge evidence only. Committed Service state, namespace/mount custody, HA
installation, other SDK manager capabilities and full OpenBao replacement
require their own qualification.
