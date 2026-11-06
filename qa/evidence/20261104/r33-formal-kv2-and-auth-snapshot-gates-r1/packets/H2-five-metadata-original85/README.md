# QA12 remaining five destination file_info observations

Five exact requests from SOURCE29 were admitted once under root GO 8c5542d05ace15c6d1405852ff69b091fa6c88ce. Every admission, same-ID completed/stored/inactive status, immutable original page, original native file_info, and separate external intent is retained. All five versions, whole content hashes, paths, modes, owners, link counts and derived full9 tuples equal the historical receiver records. Five payloads total 3,091 B; five native file_info results total 2,506 B.

These are new observations for indices 7–11. The accepted independent 0–6 metadata remains separately referenced. Prior direct/MCP and lost-ACK UNKNOWNs are unchanged. `file_info` supplied whole hashes; there were no binary_read RPCs and no process_start calls. No H2 target was created or observed, no source was changed, and no product/stage/prepare/live qualification is asserted.

The full9 decimal projection combines exact version components with uid/gid/mode/link_count; the regular-file bit follows the file_info regular-file contract. The raw native values remain authoritative and are retained unchanged. The local verifier executed only JSON/base64/hash/identity checks against these saved records (278 PASS); it did not execute any candidate or product module.

Lane A is released to root. Any next Runtime action requires root scheduling.
