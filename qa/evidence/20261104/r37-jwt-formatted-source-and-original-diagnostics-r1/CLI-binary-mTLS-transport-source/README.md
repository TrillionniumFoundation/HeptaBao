# Native snapshot peer transport: concrete SOURCE slice

This is executable Rust source, not a runtime qualification. The original JSON/ordinary frame API and all original source bytes in authenticated_peer_frame.rs remain unchanged; the new function is not wired into ha.rs yet.

## Wire and closure order

The initiating node selects one configured cluster endpoint and independently enrolled server leaf pin (primary or rotation pin). It makes exactly one TCP/TLS connection. CA/name/strict Raft ALPN/actual leaf checks finish before request metadata or token bytes are sent.

The new prefix HBSF0001 carries the remaining original deadline and bounded metadata (at most the original 1 MiB). The receiver clamps it from the actual TCP acceptance origin to its existing configured bound. A native Service callback must still authenticate the original Actor and validate source/target/cluster/nonce/hop before issuing READY.

After READY the client emits the bounded binary body plus its END count/length/SHA, sends rustls close_notify, flushes, then keeps reading the opposite TLS direction. The receiver's accept_body returns its data-only witness only after actual TLS EOF. Raw TCP FIN without close_notify is an error. A pending native restore must not finalize inside the parsing callback; it is retained until this witness exists.

COMPLETED status and application completion metadata precede the response body. The metadata must already bind a sealed/held download file's actual descriptor. No completion trailer follows END. The response decoder verifies END and actual TLS EOF; an external HTTP success cannot be released until the separate native publication/Actor/audit gates also pass.

REJECTED consumes the connection and sends only error status plus metadata and close_notify. There is no retry, alternate leader, HTTP proxy, redirection chase or ordinary-frame fallback for a failed snapshot request.

## Actual component sources

Six selected tests use existing disposable OpenSSL certificate fixture style and original eight-second TLS test timeout. They exercise actual rustls/TCP upload close-notify followed by opposite application response, unauthenticated TCP EOF rejection before finalization, wrong selected pin before body admission, rejection without upload consumption, unchanged old ordinary frame callback, and expired deadline before connect. No test in this packet has executed. Test metadata and archive data are public synthetic bytes.

The raw TCP EOF test explicitly omits close_notify after a valid binary END. A Cursor-based test is not substituted for this real transport check.

## Exact dependency source basis

Canonical Cargo.lock and HA-service Cargo.toml pin rustls 0.23.44. The official annotated tag resolves to commit 64ad386785c718c74262b79e6893813db381adfe. Three whole files were fetched by immutable commit and compared with the tag bytes. In that code, received close_notify enables Reader EOF after buffered plaintext, whereas unnotified socket EOF produces UnexpectedEof. Sending close_notify affects the local write direction; reading the opposite direction remains available. This is static source evidence, not proof that the proposed actual mTLS tests pass.

## Deliberate incomplete integration

The callback type cannot construct native storage authority. HA registration, existing forward-slot ownership, original native Actor admission, historical original-auth proof, audit/publication gates and held-file delivery still require concrete server integration. No route is changed by this slice alone, and the original B04/B05 compatibility failures remain unchanged. The public H2 request-body limit remains 32 MiB. The body's native archive cap remains 2,488,803,400 bytes, with fixed 65,536-byte DATA frames and one original deadline.

All changes are SOURCE only: no format, Cargo, test execution, Runtime call, product ref update or business replay.
