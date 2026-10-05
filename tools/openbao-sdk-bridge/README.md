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
