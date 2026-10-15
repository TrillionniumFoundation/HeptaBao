# V6 target-import syscall attribution (diagnostic only)

This folder contains a read-only parser for already captured Linux `strace -f/-ff -ttt -T` output and the existing redacted `HBV6-SNAPSHOT-PHASE` / `HBV6-RESTORE-STAGE` fixture log markers. It never launches a server, attaches to a PID, changes OpenBao, reads credentials, or authorizes HA.

## Scope and capture precautions

The unresolved gate is a fresh independent-target import of a 66-version, approximately 133 MiB HBV6PK01 archive under the original 15-second request deadline. The two-version smoke test and the source rollback have passed; prior target imports timed out. Never retransmit an unacknowledged original request. Cold-boot a *copy* to reconcile its committed state.

Capture a new **disposable fixture target only** under a private directory (umask 077). Do not trace production, nor a server containing real credentials. The command below is illustrative; the exact server executable, configuration and activation must come from the authorized frozen fixture harness:

    umask 077
    mkdir -m 700 -p /private/v6-io-profile
    strace -ff -ttt -T -s 0 \
      -e trace=fsync,fdatasync,syncfs,openat,openat2,close,linkat,unlinkat,renameat,renameat2,newfstatat,statx \
      -o /private/v6-io-profile/syscall \
      -- /path/to/frozen-fixture-server --config /path/to/private-fixture-config.json --fixture-native-v6-service

Raw traces can contain sensitive paths, metadata and timing even with -s 0. **Never upload raw traces to public GitHub, CI artifacts, chat, or PRs.** Parse them only inside the isolated host. The parser deliberately retains only syscall names, counts, error classes, duration buckets, file SHA256 digests, and redacted phase/checkpoint times.

    python3 tools/v6-io/strace_summary.py \
      --trace /private/v6-io-profile/syscall.1234 \
      --trace /private/v6-io-profile/syscall.1235 \
      --server-log /private/v6-io-profile/fixture-server.log \
      --output /private/v6-io-profile/redacted-summary.json

`--output` creates a new private JSON file; it never replaces an existing one. A valid trace must include `-T` syscall durations. The summarizer does not serialize syscall arguments, filenames, request contents, actor identities or vault secrets.

**Interpreting results:** summed syscall duration across concurrent threads is NOT wall time. Percentiles are histogram upper bounds, and the parser measures only completed traced syscalls. `strace` itself perturbs timing, so a traced run is for bottleneck *attribution*, never the original-15-second qualification decision.

Qualification must still use a separate **untraced** complete run of the **same frozen binary**: HTTP 200 on fresh-target import under the original 15-second deadline, target cold restart after SIGKILL, all 66 versions bit-exact on readback, subsequent next-version write/read, authoritative audit receipts and independent uncertain-command terminal-state reconciliation. Until every check passes, do not promote to Mac/ROG/Pocket4 V6 HA or retire OpenBao.

Tests (no external dependencies):

    python3 -m unittest discover -s tools/v6-io -p 'test_*.py' -v
