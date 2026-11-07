# Wire r3: bounded TLS response admission qualification

The fixed candidate source is SHA-256 `e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c`, 13,346 bytes. It removes the assumption that a callback associated with the current request must have set a request-local flag. The original stateless handshake host/leaf checks remain. Each response independently requires an authorized actual socket at the exact IPv4 address and port, a complete current peer certificate, a successful standard hostname check, and the pinned leaf hash. Five public booleans describe those conditions without publishing certificates, bodies or identifiers.

The original Agent settings, 15-second request ceiling, phase deadline, 1 MiB decoded-response bound, Content-Length/chunked rules, unknown-outcome stop, no retry and owned connection closure are unchanged. The sandbox still admits one local-machine port; the wire separately restricts the endpoint to exact IPv4. The prior SDK r3 business attempt remains failed with one original response unknown.

## Actual evidence

| Qualification | Result |
| --- | --- |
| Local Linux Node v24.22.1, real TLS peers | 29/29, including the retained 22 tests and seven new response-admission fault cases |
| Mac Node v25.9.0, job `1a1b2afdd12-fc05-7f4e` | Succeeded, exit 0; 40,735 original stdout bytes, empty stderr |
| Mac positive sequences | Two independent peers, close and keep-alive control; two once-only requests each, all four complete |
| Mac response-fault cases | Seven independent new fences/Agents; each deliberate fault refused, no later dispatch, all connections closed |

Both positive Mac manifest responses were 3,146-byte valid chunked JSON with TLS 1.3, exact endpoint, CA/host/leaf checks true, complete framing and unknown count zero. The seven negative cases inject a false response-time JavaScript observation after an actual valid synthetic handshake: unauthorized socket, wrong IP, wrong port, missing peer, hostname mismatch, leaf mismatch and a throwing peer getter. They prove the candidate's response gates and stop/closure behavior; they are not claims that a kernel connection to a wrong peer occurred.

The Mac job used new create-only fixture roots and fresh synthetic TLS material, imported no SDK or plugin, and read no production credential source. Its three original child processes exited zero without cleanup signals. All 38 parent descriptors, eleven accepted sockets, two peer threads and listeners closed. Every observed input source remained unchanged. The original 10-second child and 60-second diagnostic outer ceilings were retained, with the same 70-second runtime supervisor ceiling.

See [the complete actual stdout](execution/stdout.original.json), [authority](execution/terminal.original.json), [final reviewed loader](qualify_wire_r3_mac.py), and [the minimal source diff](wire-r2-to-r3.diff). The reviewed draft loader is retained separately; the final loader changed only its explanatory first docstring. This result qualifies the isolated candidate wire and does not by itself qualify a complete actual AuthBus SDK cycle, provider use, production restart or cutover.
