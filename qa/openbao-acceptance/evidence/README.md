# Historical acceptance evidence

This directory retains the original results, logs, manifests and archive
containers of recorded acceptance campaigns. Current acceptance programs and
their tests live in the parent directory and `../tests/`.

The 2026-11-15 repository cleanup retired 1,301 inactive executable source
snapshots from this directory. The results and their original source bindings
remain unchanged. A relative source path in an older receipt names its original
checkout; it does not assert that the source is still present in the current
tree.

Each retired path, file mode, Git blob, byte count and SHA-256 is indexed in the
[retirement manifest](../../../docs/audits/2026-11-15-repository-cleanup/retired-sources.json).
The original complete tree is available at commit
[`6faf7957bb0b9390141a9f3680567ef96295eba6`](https://github.com/TrillionniumFoundation/HeptaBao/tree/6faf7957bb0b9390141a9f3680567ef96295eba6).

See the [repository layout guide](../../../docs/REPOSITORY_LAYOUT.md) for
verification, isolated recovery and complete historical replay commands.
The restoration tool does not execute archived programs. Use the original
complete tree when replaying a campaign with relative imports and dependencies.

The [follow-up cleanup](../../../docs/audits/2026-11-15-repository-cleanup-round2/README.md)
also retires 125 inactive historical `.diff` and `.patch` source captures. Its
separate [manifest](../../../docs/audits/2026-11-15-repository-cleanup-round2/retired-sources.json)
binds the original files to commit `dd38ea55476813fb4b5d6d9a9e73211249536a73`.
Use the restoration tool's `--manifest` option for that set. Receipt JSON, logs
and archive containers retain their original bytes.
