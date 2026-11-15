# SDK r2 network diagnosis and scope qualification

The original SDK r2 campaign remains failed. The owned SDK child exited 65 before returning a qualified worker result. Independent safe projection located the sandbox compiler error at the one outbound network rule. It did not publish the private worker stderr or a digest of it.

## Original synthetic probe r1 — failed

Job `1a1b271da51-fc05-7e0a` has an authoritative failed / exit 1 terminal. Both numeric-address forms, `remote ip "127.0.0.1:port"` and `remote tcp "127.0.0.1:port"`, returned the fixed sandbox compiler host refusal with known exit 65. The `remote tcp "localhost:port"` variant compiled and executed Node. Its exact TLS GET and certificate checks succeeded, and protected file access plus another real loopback listener port plus a nonlocal documentation address returned EPERM. The attempt still failed because its required local-LAN denial was only ECONNREFUSED without a listener. Its IPv6 loopback connection succeeded. All four original children, parent descriptors, listeners, accepted TLS connection, and peer thread closed. These originals are unchanged.

## Separate scope qualification r2 — passed

Job `1a1b27ad919-fc05-7e36` has an authoritative succeeded / exit 0 terminal, complete durable stdout of 15,768 bytes, and no stderr. The original 60-second diagnostic outer limit and 10-second child limits remained unchanged. The actual diagnostic took 0.3901583328843117 seconds and used two owned children.

Its new definition qualified the available combination of kernel policy and the unchanged request adapter. The parent successfully established simultaneous owned listeners on 127.0.0.1, 192.168.0.8, and ::1 at one port. Under `remote tcp "localhost:port"`, the Node process reached all three local addresses: the LAN and IPv6 listeners each accepted exactly one connection from their expected local source, and all those sockets closed. The kernel therefore does not restrict this rule to IPv4 loopback. The report explicitly sets both `kernelIpv4OnlyDestinationClaimed` and `kernelLocalLanDeniedClaimed` to false.

The separate real loopback listener on another port and the nonlocal 192.0.2.1 address were denied with EPERM, as were reads and writes to protected synthetic files. The single allowed TLS request to 127.0.0.1 verified the certificate authority, exact certificate leaf, exact destination, one GET, exact response, and socket closure.

The original request adapter `main3_sdk_wire_r2.mjs` remained byte-identical, SHA-256 `2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2`. Twelve actual calls exercised its guards: four non-127 configuration addresses; five wrong request hosts or ports; and https.get, http.request, and fetch bypass paths. Every call was refused before dispatch; there were zero request rows and zero HTTP sends. Every created HTTPS agent closed with zero remaining requests or sockets, and all hooks were restored.

All public code pins matched before and after; the two original children were reaped with empty related groups and closed streams; all parent descriptors, listeners, accepted sockets, and the TLS peer thread closed. No actual SDK, plugin, provider, product server, credential file, or production state was accessed.

The new SDK r3 candidate can use this explicitly qualified combination: one local-machine TCP port at the kernel boundary and the original exact-127.0.0.1 endpoint/CA/leaf fence at the business request boundary. That is a distinct claim from kernel-only loopback isolation. The earlier failed probe and SDK campaign are not relabeled as successes.
