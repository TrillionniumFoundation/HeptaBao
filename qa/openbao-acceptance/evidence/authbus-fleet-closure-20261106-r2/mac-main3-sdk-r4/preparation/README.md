# Mac main3 SDK r4: frozen preparation and local qualification

This directory preserves the exact r4 source bundle, its predecessor derivation, launchers, and local preparation checks. Actual Mac preparation, source readback, guard qualification, two-generation SDK execution and independent absence are preserved in the parent runtime directory. Frozen source manifests retain their original prepared-only flags; no executed source or earlier failed attempt was rewritten.

## Exact source binding

- Canonical product commit: 4bde9aee03fcd27c59e13607e529b1cee594b249. Normal Mac server SHA256: 5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c.
- Staging bundle: 746592 bytes, SHA256 5a7e243d9b76ed9e0972e4f430b6f643581647324012b9a903bb46fc1cb510d3.
- Manifest: 11054 bytes, SHA256 482950e0a59c33435f6d74982324c679359de9e8c94e2b07b14290746564e61d.
- 27 Python sources, 13 assets (5 QA Node files and 8 current installed-plugin files), and the bound preparer are archived separately, with exact contents also retained in the staging bundle.
- Wire r3: 13346 bytes, SHA256 e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c. Its independent real-TLS qualification is in ../../mac-main3-sdk-wire-r3/ from this preparation directory.
- Root's independent byte-for-byte rebuild and review is preserved in qualification/root-derivation-review.public.json.

## Narrow change from r3

The fixed sandbox profile, normal product, eight installed-plugin files, request limits, no-retry policy, and cleanup rules remain unchanged after the necessary new-root bindings. The wire no longer treats a request-local handshake callback side effect as proof for a later response. It retains the original handshake hostname and leaf rejection, and independently requires the response's actual authorized TLS socket, exact IPv4 address/port, current peer certificate, hostname verification, and exact leaf pin. A missing or failed observation rejects that response and prevents later business dispatch.

Each new root, label, operation key and corresponding source pin is explicit. No original failed r1/r2/r3 source or result was replaced. The kernel rule permits the observed local-machine single-port scope; the unchanged narrower application wire fixes the actual target to HTTPS 127.0.0.1 and the owned port. This evidence does not claim kernel IPv4-only isolation.

## Local checks and original budgets

Local 8/8 derivation checks, 173/173 inherited guards and 7/7 plugin-pure-function seed checks passed once. Their original stdout/stderr are included. They are preparation checks, not product, Mac SDK, provider or production-client qualification.

The existing limits remain: 600 seconds outer controller, 120 seconds per business phase, 45 seconds inline source capture, 30/10 seconds wrapper ready/exec, 15 seconds health/SDK HTTP, 10 seconds outer API HTTP and 60 seconds cleanup. The normal release uses native_v6_file and sys/storage/native-v6/activate, without fixture features.

Actual Mac qualification and business outcomes must be established from the parent runtime receipts and exact job identities. No credential values, profile IDs, private capsule digests or production configuration digests are archived here.
