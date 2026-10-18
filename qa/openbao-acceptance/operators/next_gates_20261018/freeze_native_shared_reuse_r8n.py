#!/usr/bin/env python3
"""Freeze the three shared-ciphertext reuse files over exact tested R8m.

Only an alternate Git index is written. Ordinary HEAD/index and all unrelated
worktree files remain intact. This creates source artifacts, not a test result.
"""
import argparse
import gzip
from pathlib import Path
import tempfile

import freeze_archive_repair_r8m as helper

BASE = "090da802ce1d26c890f7c4100623f05bf488002f"
BASE_TREE = "f8413d46654dde2425260d044f0000ad3a2fda87"
FILES = {
    "crates/heptabao-raft-runtime/src/v6_replica_blobs_checked.rs":
        "1f59352b187f37f8fd40de0d897ca791726333d9df4989be660bc996daf8d644",
    "crates/heptabao-raft-runtime/src/v6_replica_blobs_existing.rs":
        "bb2066810579acc397ce7ba2ea5358bcab6218d6a83aa11d2f7194222f4253e7",
    "crates/heptabao-raft-runtime/src/v6_replica_blobs_existing_tests.rs":
        "2a698f68e432f5f8d8387f0d429f8d5c3ca695245f19610310e25ee31a823b8d",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    output = args.output_dir
    h = helper
    h.require(h.git(repo, "rev-parse", BASE + "^{tree}").decode().strip() == BASE_TREE,
              "base_tree_mismatch")
    before = h.tree_entries(repo, BASE)
    h.require(len(before) == 2588, "base_file_count_mismatch")
    captured = {name: h.capture_file(repo / name) for name in FILES}
    h.require(all(h.sha256(captured[name][0]) == digest for name, digest in FILES.items()),
              "candidate_not_exact_reviewed_bytes")
    h.require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
              and not output.exists() and not output.is_symlink()
              and output != repo and repo not in output.parents, "output_not_new")
    index = Path(h.git(repo, "rev-parse", "--git-path", "index").decode().strip())
    if not index.is_absolute():
        index = repo / index
    index_before = h.index_fingerprint(index)
    head_before = h.git(repo, "rev-parse", "HEAD")
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(dir=output, prefix="alternate-") as temporary:
        alternate = Path(temporary) / "index"
        h.git(repo, "read-tree", BASE, index=alternate)
        updates = bytearray()
        for name, (raw, _) in captured.items():
            oid = h.git(repo, "hash-object", "-w", "--stdin", data=raw).decode().strip()
            updates.extend(("100644 " + oid + "\t" + name).encode() + b"\0")
        h.git(repo, "update-index", "-z", "--index-info", data=bytes(updates), index=alternate)
        tree = h.git(repo, "write-tree", index=alternate).decode().strip()
        entries = h.tree_entries(repo, tree)
        h.require(len(entries) == 2590 and h.changed_paths(before, entries) == set(FILES),
                  "unexpected_source_delta")
        commit = h.git(repo, "commit-tree", tree, "-p", BASE,
                       data=b"storage: reuse exact shared ciphertext with real held-file fsync\n").decode().strip()
    h.require(h.index_fingerprint(index) == index_before
              and h.git(repo, "rev-parse", "HEAD") == head_before,
              "ordinary_index_or_head_changed")
    h.require(all(h.capture_file(repo / name) == value for name, value in captured.items()),
              "candidate_changed_during_freeze")
    blobs = h.blob_bytes(repo, [oid for source in (before, entries)
                              for _, oid in source.values()])
    base_manifest = h.manifest_for(BASE, BASE_TREE, helper.PARENT, before, blobs)
    manifest = h.manifest_for(commit, tree, BASE, entries, blobs)
    overlay = {"schema": "heptabao.source-overlay.v1", "base_commit": BASE,
               "base_tree": BASE_TREE, "base_manifest": base_manifest,
               "before": {name: h.sha256(blobs[before[name][1]]) if name in before else None
                          for name in FILES}, "after": dict(FILES),
               "files": h.encoded_files(entries, blobs, FILES), "manifest": manifest}
    artifacts = {
        "manifest": h.write_new(output / "r8n-shared-source-manifest.json", h.json_bytes(manifest)),
        "base_manifest": h.write_new(output / "r8m-base-manifest.json", h.json_bytes(base_manifest)),
        "overlay": h.write_new(output / "r8n-shared-source-overlay.json.gz",
                               gzip.compress(h.json_bytes(overlay), compresslevel=9, mtime=0)),
    }
    receipt = {"schema": "heptabao.shared-reuse-source-freeze.v1", "source_commit": commit,
               "source_tree": tree, "source_file_count": len(entries),
               "base_commit": BASE, "base_tree": BASE_TREE, "included_paths": FILES,
               "ordinary_index_unchanged": True, "head_unchanged": True,
               "tests_executed": False, "production_cutover": False, "artifacts": artifacts}
    h.write_new(output / "r8n-shared-source-freeze-receipt.json", h.json_bytes(receipt))
    print(h.json_bytes(receipt).decode(), end="")


if __name__ == "__main__":
    main()
