# Fixed 23 formatter output observations — SOURCE only

The actual 49-file formatter report binds output sizes and SHA256 but does not contain formatted output identities. This proposal observes exactly the 23 changed output files at their original `formatted/<name>` paths, then retrieves their 36 fixed ranges using each file's newly observed immutable version. It performs no subprocess or file mutation. Existing source-input identities cannot substitute for output metadata.

The other 26 outputs match already whole canonical source bytes and the original formatter after hashes. Their evidence remains reuse of those whole source blobs; no newly observed output full9 is claimed.

The journal derives from the already reviewed four-INFO/four-BODY Git-first source, with the old publication and process execution branches removed. Each file is completed before the next metadata call. Raw chunk bytes remain binary until whole-file length/SHA passes, then UTF-8 is decoded and roundtripped. Every output is Git archived and whole read back before advancing.

No new context has been initialized, no Native request has been submitted, and no previous UNKNOWN or paused context is cleared. Root must issue an exact GO and lane before any action.
