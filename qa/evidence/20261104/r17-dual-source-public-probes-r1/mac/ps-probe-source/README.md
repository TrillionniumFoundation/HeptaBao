# Fresh public ps sandbox diagnostic, revision 1

This immutable package is a source candidate. No Mac dispatch has been submitted for it. The exact proposed request is `dispatch/start.public.json`; only root may authorize that one request.

The earlier devnull probe remains failed with a nested custody/exit unknown. Its complete evidence is tree `767a66d03d2f96a14d016baaaa10e86665bd0ccd`. Later read-only absence of PID/PGID 11754 does not establish the earlier child exit or reap.

## What this candidate does

The unchanged retained owner runs the original T5 diskutil guard outside the sandbox and creates one fresh owned root. It copies the already fixed public `/bin/ps` into a new mode-0500 inode using create-only publication, exact original bytes, same-FD readback, whole SHA, and fsync. The original system binary, its mode, and its signature are never changed.

Two sandbox parents then use the same patched policy. Each makes exactly one numeric-only ps observation of its own PID: first the fixed system binary, then the fresh owned copy. The inner Popen retains `close_fds=True`, `start_new_session=False`, DEVNULL and PIPE collection. It stays within the outer owner's retained sandbox PGID. No diskutil or other independent session is started inside the sandbox. The inner observer sends no signal and adds no retry or cleanup allowance. Unknown execution or stream closure stops the sequence and delegates group cleanup to the existing outer retained owner.

The only policy permission difference from the relocated original capture policy is the existing 41-byte literal read rule for `/dev/null`. Both variants receive that same policy. The original four fixed owned-write, sidecar-create and loopback refusals run only after the copied binary actually executes successfully. A known system launch refusal is a diagnostic observation, not execution success. Overall exit zero additionally requires actual copied-binary success, all four refusals, unchanged inputs, complete descriptors/process closure, and the original shared deadline.

## Scope of conclusions

A successful comparison does not prove a unique setuid cause, an observed CPython spawn branch, successful code-signature validation in other paths, or successful execution of the complete production `capture_child` ownership path. A system variant may also succeed; that remains an observed comparison result. Copy or signature refusal remains an explicit failed observation. No no-sandbox path, private read, SQLite connection, current capture, consumer, provider, J3160 request, service operation, or business replay is included.

The stdout contains fixed stage/class and bounded numeric errno, public whole pins, numeric process identity and hashed child stderr. It does not publish exception messages or dynamic exception filenames. Source, read-only input, output and aggregate hash-read caps remain explicit.

## Review evidence

`diffs/devnull-to-ps.review.diff` strictly reconstructs all 39810 candidate bytes from the included historical source in 12 hunks. Sixteen original functions, including the policy generation and four-refusal body, remain byte-identical. The actual selected-AST fake component run passed 13 checks with zero real descriptors, subprocesses or network calls. The profile-only verifier generated the exact two policy files and verified their sole 41-byte permission delta. The candidate module's main was not executed.

The local executor response files are original tool-return objects encoded as JSON snapshots, not claimed raw transport wire bytes. The included component and invariance scripts are the exact files executed, including their actual terminal newlines. All source/output strings and immutable Git blobs are whole-hash bound by the manifest. These local checks are source evidence and do not substitute for the eventual Mac authority, exact stdout, EOF, or closure.
