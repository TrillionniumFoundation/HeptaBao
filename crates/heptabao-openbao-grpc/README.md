# OpenBao Wrapper gRPC bridge

This crate is an isolated transport increment. The existing `heptabao-plugin-host`
HBP1/HBR1 implementation and its tests are unchanged. No server configuration,
seal provider, plugin catalog or OCI installer selects this crate yet.

`protocol.rs` uses maintained Prost 0.14.4 message derives with explicit field
numbers from the two unmodified public `.proto` files in `proto/`. The seven RPC
paths are `/pb.Wrapper/{SetConfig,Type,KeyId,Encrypt,Decrypt,Init,Finalize}`.
Tonic 0.14.6 supplies gRPC/HTTP2 framing and Rustls with Ring supplies mutual TLS.
`OpaqueBlobInfo` retains complete wire bytes, including unknown nested fields,
for subsequent Decrypt. Secret messages, session configuration and transport
errors have redacted Debug or fixed error text. Owned message buffers are cleared
on Drop; this does not prove zeroization of all allocator/Tonic/Rustls internals.

The trusted platform adapter must supply fresh executable SHA/device/inode,
UID/PID/SID/start ticks and immutable private-config SHA/device/inode/mode observations.
The concrete TLS transport binds its captured owner and configuration generation;
a different owner or generation cannot reuse the connection. Admission and
SetConfig/Init/Finalize require a sealed host. Existing initialized cryptographic
calls may run unsealed within the same authoritative configuration generation.
This library does not collect OS process metadata, spawn, kill or reattach.
Installing it in a product requires an actual immutable-executable adapter,
authoritative lifecycle hook and endpoint/certificate provenance verification.

The full awaited call has one caller-supplied deadline, a bounded gRPC timeout
and pre/post owner checks. Before its first await the session is fenced. A
canceled waiter, timeout, RPC error, malformed/oversized response or post-call
owner change leaves the outcome unknown; there is no application retry or
reconciliation API. The fence makes no claim that the peer did or did not commit.

The official public SDK documentation establishes the KMS application cookie,
versioned plugin set 1 and `wrapper` name. The cookie is an intent check, not
authentication. The go-plugin public API describes per-launch client/server
X.509 exchange and prohibits AutoMTLS reattachment and a second TLS config.
The pinned public non-Go guide documents five startup fields. It does not
specify the AutoMTLS extension serialization or environment encoding.
`PublicHandshake::automatic_launch_admission` therefore rejects every launch.
Additional startup fields are rejected, rather than guessed or used to dial.
The explicit mutually authenticated Tonic constructor is not a completed
AutoMTLS launcher; the caller must supply correctly captured per-launch material.
Unix handshake endpoints can be parsed, but this first concrete TLS client
supports loopback TCP only. Ambient environment configuration is disabled by
requiring `with_disallow_env_vars` in RPC options.

Public sources:

- [Exact Wrapper proto](https://github.com/openbao/go-kms-wrapping/blob/9184e29ddec41fb6dae447b6292264a65b512f84/plugin/pb/plugin.proto)
- [Exact wrapping types](https://github.com/openbao/go-kms-wrapping/blob/9184e29ddec41fb6dae447b6292264a65b512f84/types.proto)
- [Plugin SDK v2.4.0 exported interface](https://pkg.go.dev/github.com/openbao/go-kms-wrapping/plugin/v2@v2.4.0)
- [go-plugin v1.8.0 exported interface](https://pkg.go.dev/github.com/hashicorp/go-plugin@v1.8.0)
- [Pinned non-Go startup guide](https://github.com/hashicorp/go-plugin/blob/v1.8.0/docs/guide-plugin-write-non-go.md)
- [Prost 0.14.4](https://docs.rs/prost/0.14.4/prost/)
- [Tonic 0.14.6](https://docs.rs/tonic/0.14.6/tonic/)

Only in-memory contract tests have been run. External plugin interoperability,
PKCS11/SoftHSM execution, Linux process admission, seal lifecycle integration,
full OpenBao replacement and independent security qualification remain false.

The Linux identity adapter reads only the captured process's `stat`, `status`,
`exe` and the exact private config file. It holds the original file descriptors,
reopens both identities, hashes each file twice with stable metadata brackets,
and rejects unknown grammar, changed UID/PID/SID/start ticks, file replacement,
config mode/link changes or lifecycle-generation races. A trusted authoritative
sealed/generation hook is still required; `/proc` does not supply that authority.
Mac tests use an isolated fake `/proc` tree; the Linux `/proc/self` test is present
but has not been executed in this increment. No process is launched or signaled.

In-process loopback tests exercise Tonic's actual mutual TLS, HTTP/2 and all seven
RPC paths with fresh synthetic certificates. They preserve unknown nested
BlobInfo wire bytes and prove refusal for wrong peer/DNS and missing client
identity, plus session fencing after timeout, waiter cancellation and oversized
responses without request replay. Every fixture owns its listener/shutdown task,
awaits its terminal and checks the listener was released. These tests are not
qualification against the official OpenBao plugin, SDK AutoMTLS launcher wire,
PKCS11, SoftHSM or a production server. Rcgen is a test-only maintained dependency;
no custom TLS, ASN.1, HTTP/2 or gRPC framing is added. Provider-internal temporary
allocation cleanup has not been independently proven.

The network fixture uses a controlled identity/lifecycle probe; it does not
pretend that Mac provides the Linux collector. A real network response followed
by a changed controlled owner is fenced without replay. Linux-only `/proc/self`
and replaced-FIFO tests remain pending a separately granted Linux execution.
