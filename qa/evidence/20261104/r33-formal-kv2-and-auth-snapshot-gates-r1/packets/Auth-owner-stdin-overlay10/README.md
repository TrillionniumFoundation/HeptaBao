# Exact request stdin-key correction

The original SOURCE88 and request 850fdaf3c82e5067605494f5a8e8d8af3a1ab899 remain immutable. The request was never submitted and is not directly admissible: the current process_start schema accepts `stdin`, whereas that proposal used `stdin_text`.

This overlay changes only that request key, removing five ASCII bytes. The original 801,859-byte stdin value, publisher, executable, argv, cwd, timeout, root and idempotency key are exact. The generator changes its corresponding single key literal and is parsed only, not executed. The compact key-patch record gives the byte offset, exact removed/inserted strings, unchanged prefix/suffix hashes and complete before/after pins; this avoids duplicating the entire 801 KB escaped JSON value in a textual diff.

Only the corrected request 521c4700c9896ef48c8b710f7b787b5cfb5d1504 can be considered for a future exact GO. This packet grants no dispatch permission. There are zero Runtime calls and neither the old nor corrected request has been submitted. The original future runtime request and all 22 source files remain unchanged.

The 31 post-inert targets in SOURCE88 are an unsubmitted path inventory, with no bound read requests. The prior exact GO 952f0725a4c36766b85f95720eafa3636d4566ab required independent file_info plus version-pinned whole reads for those 31 targets in its old root; this is the historical basis for preserving the inventory, not an automatic authorization or a new API requirement for the fresh root. The new exact GO must state the applicable acceptance/readback scope. The publisher's own 30 held readbacks and runtime's 22 source-pin gates remain byte-identical.
