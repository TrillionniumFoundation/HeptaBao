# B R2 node2: bounded existing-log observation

Status: SOURCE-ONLY. The remote request is proposed, not submitted. The actual B R2 run remains failed; no mutation, unseal retry, startup, kill, permission change or fixture edit is authorized by this packet.

## Fixed evidence and target

Only the already stopped node2 root from final summary dc954e44 is selected. The executed QA process action appends stdout/stderr to that root's process.log. That combined file is not assumed public or secret-free. The observer reads it locally and returns only two exact source-derived marker grammars, whole-input SHA, byte/line counts, and held/named metadata. Unknown lines are never returned. The source-derived fixed 503 message is cryptographically consistent with the stored canonical response hash but does not identify its many inner refusal sites.

## Read and output bounds

NEW shared observer deadline: 15 seconds from entry. NEW supervisor: 45 seconds for termination/report transport, not a successful work extension. Input ≤2 MiB, 64 KiB reads and exact EOF; selected markers ≤128, each ≤512 B; final JSON ≤64 KiB. All path components are opened O_DIRECTORY/O_NOFOLLOW and held, with named/held identities checked before and after. The fixture root must be UID1000/mode0700; process.log must be a regular no-symlink file, UID1000/mode0600/nlink1. Exact file metadata including ns is stable before/open/named/after. All owned descriptors close once; any close error forbids success. No child, network, shell, product request or file write.

The two formatter grammars have fixed labels, exact lowercase booleans, canonical unsigned decimal range, reason digest, exact spaces/order/LF, and no duplicate/extra tokens. u128 time quantities are published as decimal strings to preserve precision. A malformed recognized marker fails the read. Valid but unselected lines are counted, never emitted. The complete input hash is retained without transmitting input bytes. Other logs and credentials remain untouched.

## Evidence interpretation

Accept a completed observation only with authoritative exit0, full durable terminal, complete=true, within-original-deadline publication=true, and every owned FD closed. Final flush is followed by the original deadline check, so an early JSON flag cannot override a nonzero authoritative exit. Line order alone is not a request-ID correlation; cross_request_correlation_proven remains false. No marker or generic unavailable body establishes deadline/cipher/authority failure by itself. This packet makes no product qualification claim.

## Offline validation

Exact full source AST/compile plus only seven selected pure AST definitions/constants were evaluated. Twenty-four parser controls/negative cases passed, including unknown/private field values, duplicate/extra fields, malformed bool/integer, u128 overflow/leading zeros, missing LF/CRLF and excessive length. Whole module, filesystem, children, sockets and host APIs were not executed. Existing B results remain unchanged.

## Exact proposed dispatch

See exact-request.proposed.json. Configured host rog, /usr/bin/python3 -I -S -B -c exact-source exact-source-sha; fixed cwd; one stable key. Await root source review and explicit one-run GO. Unknown admission or terminal will be reconciled under the same key and never replayed.
