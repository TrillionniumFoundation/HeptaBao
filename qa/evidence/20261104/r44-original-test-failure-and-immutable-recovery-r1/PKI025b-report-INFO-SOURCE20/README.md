# One metadata observation of the original 025b build report

The existing BUILD ended with exit 1 after the normal-production-release-built row. Its two original stream observers cover stdout 0..1809 and 1809..2216, stderr 0. The final row supplies the fixed report path and SHA-256; it supplies no size or version.

This SOURCE-only successor attaches the existing closed slot and permits one separately approved file_info. It does not initialize a slot, start a process, read a body, change a test, or authorize target reuse. The original report size cap is 1 MiB, permission 0600, Linux full mode 33152, uid/gid 1000:1000, nlink 1. Exact original native metadata must determine size, five-field version and full9 before a later body proposal.

The only structural change is a guard for the actual two reads/three stdout rows, with exact original pins and 31-call/10-closed-observer frontier. The existing archive, native invocation, lossless metadata and once-only logic remain byte-exact after fixed binding changes. The 39 checks execute selected pure guards in an isolated V8 map with no tool calls. They are not product tests or host observations.
