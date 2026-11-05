# Bounded AutoMTLS contract for the independent HashiCorp SDK

This is isolated interoperability research explicitly authorized by ROOT. No OpenBao implementation source was read. It is a protocol contract, not a translation of SDK implementation. The existing owner candidate and its refusal behavior remain frozen. Neither compilation nor a plugin process was executed.

The approved inert PKCS11 release v0.2.1 binary has SHA-256 `e88632ee52600513bd0e77242823ef57641f1eaac019d8c66515c8bca81e007d`. Its actual Go build metadata identifies `github.com/hashicorp/go-plugin v1.8.0`, module checksum `h1:ie8S6RRY8RvB2usYZv+AAZ/wBvx2AU5p5QeP5j/FORs=`. Tag v1.8.0 resolves to commit `155dcddc94873a285e14b7fa24b2f6ab6139668e`, whose tree is `c47012873e2f71bb8e1c01b4ea5f1f5ac4615549`. The earlier provenance field named `tag_tree_sha1` contains the resolved commit returned by the tree endpoint; it must not be cited as the actual tree ID. The independently retrieved commit object establishes the tree above.

## Launch and certificate exchange

The launcher sets the product's public magic cookie, an explicit supported application version list in `PLUGIN_PROTOCOL_VERSIONS`, and `PLUGIN_CLIENT_CERT`. The certificate environment value is a PEM certificate with literal newlines. The client private key stays in the host; it is not an environment value or startup argument. The cookie indicates launch intent and does not authenticate a peer.

With AutoMTLS enabled, one host certificate/key pair is generated per launch. The SDK requires at least TLS 1.2 and the DNS name `localhost`. The SDK certificate profile uses P-521, a self-signed CA certificate, a `localhost` DNS SAN, and both client and server authentication EKUs. Its serial is random within 128 bits; the validity starts approximately 30 seconds before generation and ends approximately 30 years later. Those long certificate dates are SDK facts, not a proposed host runtime authority lifetime. Revocation of the Service generation remains authoritative.

The server parses the public client PEM into its trust store and requires and verifies a client certificate. It generates a new server certificate for this launch. The server's startup certificate field is the full X.509 DER certificate encoded using unpadded standard Base64, rather than PEM, URL-safe Base64, an SPKI hash, or a certificate chain.

Without broker multiplexing enabled, stdout has exactly six pipe-separated fields followed by LF:

`core-version | application-version | network | address | protocol | server-certificate`

The minimal supported contract is core `1`, application `1`, protocol `grpc`, exactly one server certificate, and no seventh field. `PLUGIN_MULTIPLEX_GRPC` remains unset. An empty sixth field or a five-field line cannot admit AutoMTLS. No caller-provided endpoint or certificate can replace this owned stdout exchange.

On Linux the SDK chooses a Unix socket by default. `PLUGIN_UNIX_SOCKET_DIR` specifies the directory used to create the socket. The host must use a new private directory, bind the returned socket path to that directory, reject symbolic links and substituted inode/owner metadata, and retain the exact child identity. Socket pathname possession alone is not TLS authentication. TCP loopback support is separate and cannot replace Linux Unix behavior by guessing.

## Authenticated HTTP/2 and RPC boundaries

The TLS trust set consists only of this launch's server certificate. Standard chain, server-purpose, time, DNS-name, and signature verification must succeed; an additional peer DER equality check binds the actual TLS peer to the startup certificate. The fact that the SDK certificate is a CA does not authorize a verification callback that returns true on a failed verification. Both the host and plugin certificates must be proved usable under the maintained TLS backend before compatibility can be claimed.

TLS must negotiate `h2`. The SDK gRPC server exposes the standard health service with service name `plugin` and the broker/controller/stdio services. Wrapper calls belong to the separate public `pb.Wrapper` protobuf contract. These SDK facts do not establish a particular OpenBao application's full call order. Wrapper, SDK KMS/metadata, and HBP1 remain separate.

One owned connection is eligible for admission. A disconnected channel cannot reconnect using a remembered endpoint or launch identity. No configuration, initialization, encryption, decryption, or other provider mutation is replayed after timeout, cancellation, invalid response, or lost identity. A failed or cancelled dispatched RPC leaves the session outcome unknown and invalidates further calls.

## Source provenance and license scope

Only the necessary HashiCorp v1.8.0 SDK files were retained under `sdk-v1.8.0`, with their MPL-2.0 notices and pinned LICENSE. `sdk-source-provenance.json`, `sdk-protocol-provenance.json`, and `sdk-constants-provenance.json` bind their bytes. The raw SDK source remains in this research directory. Any new compatibility module must identify this reviewed contract and its provenance rather than copying or mechanically rewriting SDK functions. ROOT is the independent reviewer; this note does not invent a legal approval.

Primary sources: [client](https://github.com/hashicorp/go-plugin/blob/v1.8.0/client.go), [server](https://github.com/hashicorp/go-plugin/blob/v1.8.0/server.go), [certificate profile](https://github.com/hashicorp/go-plugin/blob/v1.8.0/mtls.go), [constants](https://github.com/hashicorp/go-plugin/blob/v1.8.0/constants.go), [gRPC client](https://github.com/hashicorp/go-plugin/blob/v1.8.0/grpc_client.go), [gRPC server](https://github.com/hashicorp/go-plugin/blob/v1.8.0/grpc_server.go).
