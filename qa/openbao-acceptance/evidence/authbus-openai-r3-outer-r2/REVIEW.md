# OpenAI R3 outer controller R2: scoped SDK input custody

## Actual failure retained

The first main invocation stopped in preflight after 0.030054224 seconds with `owned_directory_custody_required`. Node submission count was zero. The original controller and SDK custody diagnostic are preserved byte for byte with this revision. All 38 fixed SDK hashes matched the diagnostic, but the SDK root used mode 0775, its source files 0664 and its entrypoint 0775. Their canonical task ancestor is owned by the same UID and has mode 0700. No SDK file or mode has been changed. This preflight observation is not execution of the 32 OpenAI R3 cases.

## Narrow correction

Only `verify_sdk` changes, and it calls one new SDK-specific reader. `safe_directory` and `read_regular` are unchanged. The new reader accepts only paths in the fixed SDK_ROOT. It opens the canonical owner-only 0700 HOST_ROOT, retains its directory descriptor, traverses each component with relative `open` plus O_DIRECTORY/O_NOFOLLOW, and retains those descriptors through the read. Every directory must retain the same UID and must reject world-write; a missing, shared or changed private ancestor rejects before qualification. Group-write bits are accepted only behind this complete private path.

Each of the 35 JS modules, activation JSON, package.json and bin file still requires the bound SHA256, fixed size limit, exact UID, regular type, one hardlink and stable file identity before/after read. The reader also rejects world-write, final symlinks, alias directories, path escape, directory replacement or permissions changing during the read. It closes every descriptor on rejection. The receipt records the original modes and the private directory identities; before/after comparisons now include this custody evidence. Directory inode/UID/mode stay fixed, while unrelated creation in the shared private task root can update its timestamps/link count without invalidating the SDK input.

All other controller functions and all top-level constants are AST-identical to R1: original 180 seconds, fixed 16-member tar, 35+1+2 SDK pins, 32 scenario inventory, exact Node binary, one Popen submission, UNKNOWN no-retry behavior, owned-session TERM/KILL/pidfd cleanup, source verification and actual result gate. The frozen R3 runtime packet and original native-four-case controller remain unchanged. The only existing unit-test adjustment binds its synthetic SDK and private ancestor explicitly; all eight test names and original process assertions remain.

## Local validation and actual main command

Ten new local filesystem checks passed, including actual 0775/0664 inputs under 0700, four nonprivate ancestor modes, sibling escape, symlinks/hardlinks, wrong file UID, world-write, wrong hash, expired deadline, private ancestor mutation and descriptor cleanup. The original eight controller checks also passed, including three real owned Python process custody cases. The tests executed no installed SDK, provider, native backend, production service or remote command.

Stage only this new outer Python file at a fresh owned path. Reuse the unchanged, previously transferred R3 tar only after its exact hash check. The next invocation uses a new claimed run directory:

```sh
python3 -B /home/qian-qi/heptabao-next-gates-20261017/authbus-openai-r3-once-r2-20261019.py --packet /home/qian-qi/heptabao-next-gates-20261017/authbus-openai-r3-20261019.tar.gz --run-root /home/qian-qi/heptabao-next-gates-20261017/authbus-r5-openai-r3-actual-20261019-02
```

The outer file SHA256 is `ab57d4826c6d7b66b2c28f061df766d39bc21a7f2df1df9f90e3b0b8f81342d5`. The source tar remains SHA256 `29ff0adcfffe64632d683482c34a10696329796b7a56f3d656502b546c881fb7` (66,245 bytes). The exact inner manifest remains `e47f38e9b04d68d9570b1432c71f3fb42764d79309c80f4de5eb4bfc84cc0d5b`. A lost response must be reconciled using the claimed directory and its journal; this command is never automatically retried. The 32-scenario actual SDK/OpenAI/Undici result remains pending.
