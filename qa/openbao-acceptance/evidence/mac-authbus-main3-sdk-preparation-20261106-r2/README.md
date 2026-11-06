# Mac main3 installed-SDK cycle preparation r2

This package freezes the Node workers for a future two-process Mac run. **No actual Mac SDK cycle, production gateway restart, provider refresh, production rollback or traffic switch is qualified by this package.**

The actual local Linux qualification passed **22/22** cases on Node v24.22.1, using 15 real synthetic TLS connections and 15 HTTP requests. The original stdout and command completion envelope are retained. Every owned peer and replaced hook closed or was restored. This is transport-fence qualification only; it does not substitute for the Mac kernel sandbox or installed SDK.

The canonical normal server can return JSON larger than 2048 bytes using HTTP/1.1 chunked transfer encoding. The r2 fence accepts complete, bounded, unambiguous chunked responses in addition to bounded Content-Length and empty 204 responses. It rejects truncated or oversized decoded bodies, invalid chunks, duplicate transfer coding, conflicting framing and content encoding. TLS CA and leaf admission occur before HTTP. Wrong leaf, timeout and failed framing prohibit further dispatch; no retry was added.

The real plugin listens for response data/end and request errors. An observed response failure that arrives after the request has closed can otherwise leave that promise unsettled. The fence forwards that observed failure once to the original request error path. It does not fabricate a response or retry a request. Local synthetic peers cover this event order.

The planned initial process imports three freshly captured main-owned OAuth objects into five private fixture agent stores through the actual installed plugin. The second process checks cold persistence, runs the cached plugin cycle, and performs a private exact inverse of five auth stores, the two auth tables including timestamps, and six AuthBus cache files. These are empty fixture stores, not a production database snapshot. The original 15-second per-request ceiling and 120-second phase ceiling remain unchanged. The Python service owner and actual Mac execution are separate gates.

All source files below are public QA code. No credential value, credential digest, profile identifier or raw client configuration hash is present. The exact source hashes and Git blob identities are in the manifest.
