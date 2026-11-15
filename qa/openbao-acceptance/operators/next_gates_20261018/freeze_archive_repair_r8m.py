#!/usr/bin/env python3
"""Freeze only the R8m archive repair slice, without changing the normal index.

The root owner runs this script after the five allowlisted source files are
ready. Git writes use an alternate index rooted at the exact recovered R8l
commit. HEAD, refs, the ordinary index and every other worktree file are left
alone. No Cargo, Runtime, network, installation or test execution occurs here.

Outputs include a complete binary-safe source bundle, an eight-file overlay
from the exact R8k tree, and SHA-256 manifests for all source files and modes.
An existing output directory is rejected, including one from a failed attempt.
"""

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile


PARENT = "4eea1bf4f5ac16d1bf14a53c5e34addb38ff79ce"
PARENT_TREE = "182642fba4ccd1058cf3f3295a79d751f82ec4f2"
OVERLAY_BASE = "f78a5ab8c8ef32b1a9aff2346c0f6f953bc9e526"
OVERLAY_BASE_TREE = "74f48aff203336f3f56e0a943f97904220343190"
EXPECTED_FILE_COUNT = 2588
INCLUDE = (
    "crates/heptabao-server/src/ha_native_v6_archive_repair.rs",
    "crates/heptabao-server/src/service_native_v6_ha_archive_repair_tests.rs",
    "docs/storage/HEPTABAO_NATIVE_V6_HA_ARCHIVE_REPAIR_CANDIDATE_20261017.md",
    "crates/heptabao-server/src/ha_native_v6_runtime.rs",
    "crates/heptabao-server/src/service_native_v6_ha_install_tests.rs",
)
HOOKS = {
    INCLUDE[3]: (
        b'use std::sync::OnceLock;\n\n',
        b'#[path = "ha_native_v6_archive_repair.rs"]\nmod archive_repair;\n\n',
    ),
    INCLUDE[4]: (
        b'use std::time::Instant;\n\n',
        b'#[path = "service_native_v6_ha_archive_repair_tests.rs"]\n'
        b'mod archive_repair_tests;\n\n',
    ),
}
PROTECTED_R8L = {
    "crates/heptabao-raft-runtime/src/v6_replica_blobs.rs":
        "130f2c42acadcf2f932b053bbc0becf48c4beb250f0b03a6a04c16f871b3895e",
    "crates/heptabao-raft-runtime/src/v6_closure_manifest.rs":
        "bd7d5e29be01702131e0f395cc47f392067192dc5d8602aaa78129fa953caa40",
    "crates/heptabao-server/src/ha_native_v6_backup.rs":
        "c1ee4f697b084e1c808903bdd416cd8de31c7bb92901f35e56dfca16119b88b0",
}


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def safe_name(name):
    path = PurePosixPath(name)
    require(name and path.as_posix() == name and not path.is_absolute()
            and ".." not in path.parts and ".git" not in path.parts
            and "\\" not in name and "\0" not in name, "unsafe_source_path")
    return name


def git_environment(index=None):
    environment = dict(os.environ)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                 "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    if index is not None:
        environment["GIT_INDEX_FILE"] = str(index)
    return environment


def git(repo, *arguments, data=None, index=None):
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=git_environment(index), check=False,
    )
    require(result.returncode == 0,
            "git_command_failed:" + arguments[0] + ":"
            + result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def tree_entries(repo, revision):
    entries = {}
    for entry in git(repo, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        name = safe_name(raw_name.decode("utf-8"))
        require(kind == "blob" and mode in ("100644", "100755")
                and len(object_id) == 40 and name not in entries,
                "unsupported_or_duplicate_source_entry")
        entries[name] = (mode, object_id)
    return entries


def blob_bytes(repo, object_ids):
    """Read exact binary object sizes; never decode a source blob as text."""
    blobs = {}
    with subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=git_environment(),
    ) as process:
        for object_id in sorted(set(object_ids)):
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii").split()
            require(len(header) == 3 and header[:2] == [object_id, "blob"],
                    "git_blob_header_mismatch")
            size = int(header[2])
            require(size >= 0, "negative_blob_size")
            data = process.stdout.read(size)
            require(len(data) == size and process.stdout.read(1) == b"\n",
                    "git_blob_truncated")
            canonical = b"blob " + str(size).encode("ascii") + b"\0" + data
            require(hashlib.sha1(canonical).hexdigest() == object_id,
                    "git_blob_object_digest_mismatch")
            blobs[object_id] = data
        process.stdin.close()
        require(process.wait() == 0, "git_blob_batch_failed")
    return blobs


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def capture_file(path):
    require(path.resolve(strict=True) == path, "source_symlink_or_alias")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode), "source_not_regular")
        data = source.read()
        require(file_identity(before) == file_identity(os.fstat(source.fileno()))
                == file_identity(path.lstat()) and len(data) == before.st_size,
                "source_changed_during_read")
    return data, file_identity(before)


def index_fingerprint(path):
    if not path.exists() and not path.is_symlink():
        return None
    data, identity = capture_file(path)
    return sha256(data), identity


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), 0o600)
        os.fsync(output.fileno())
    sync_directory(path.parent)
    require(path.read_bytes() == data, "freeze_artifact_readback_mismatch")
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data)}


def manifest_for(commit, tree, base, entries, blobs):
    return {
        "schema": "heptabao.source-freeze.v1",
        "base_commit": base,
        "source_commit": commit,
        "source_tree": tree,
        "files": {name: sha256(blobs[object_id])
                  for name, (_, object_id) in sorted(entries.items())},
        "modes": {name: mode for name, (mode, _) in sorted(entries.items())},
    }


def encoded_files(entries, blobs, names):
    files = {}
    for name in sorted(names):
        data = blobs[entries[name][1]]
        encoded = base64.b64encode(data).decode("ascii")
        require(base64.b64decode(encoded, validate=True) == data,
                "source_base64_roundtrip_failed")
        files[name] = encoded
    return files


def changed_paths(before, after):
    return {name for name in set(before) | set(after)
            if before.get(name) != after.get(name)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path,
                        default=Path(__file__).resolve().parent / "HeptaBao")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    repo = args.repo.resolve(strict=True)
    require(git(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo),
            "repo_is_not_git_toplevel")
    require(git(repo, "rev-parse", PARENT + "^{commit}").decode().strip() == PARENT
            and git(repo, "rev-parse", PARENT + "^{tree}").decode().strip() == PARENT_TREE
            and git(repo, "rev-parse", OVERLAY_BASE + "^{commit}").decode().strip() == OVERLAY_BASE
            and git(repo, "rev-parse", OVERLAY_BASE + "^{tree}").decode().strip() == OVERLAY_BASE_TREE,
            "pinned_base_identity_mismatch")
    # Check existing identity configuration before creating any output or Git object.
    git(repo, "var", "GIT_AUTHOR_IDENT")
    git(repo, "var", "GIT_COMMITTER_IDENT")
    parent_entries = tree_entries(repo, PARENT)
    base_entries = tree_entries(repo, OVERLAY_BASE)
    require(len(parent_entries) == 2585 and len(base_entries) == 2585
            and changed_paths(base_entries, parent_entries) == set(PROTECTED_R8L),
            "r8l_delta_is_not_exactly_the_three_checked_io_files")
    initial_blobs = blob_bytes(repo, [oid for entries in (parent_entries, base_entries)
                                    for _, oid in entries.values()])
    for name, expected in PROTECTED_R8L.items():
        require(sha256(initial_blobs[parent_entries[name][1]]) == expected,
                "r8l_protected_blob_mismatch:" + name)
    captured = {name: capture_file(repo / name) for name in INCLUDE}
    for name, (anchor, addition) in HOOKS.items():
        original = initial_blobs[parent_entries[name][1]]
        require(original.count(anchor) == 1
                and captured[name][0] == original.replace(anchor, anchor + addition, 1),
                "hook_contains_changes_other_than_the_one_module_declaration:" + name)
    require(all(name not in parent_entries for name in INCLUDE[:3]),
            "new_candidate_path_already_present_in_r8l")
    output = args.output_dir
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
            and not output.exists() and not output.is_symlink()
            and output != repo and repo not in output.parents,
            "output_must_be_new_and_outside_repo")
    normal_index = Path(git(repo, "rev-parse", "--git-path", "index").decode().strip())
    if not normal_index.is_absolute():
        normal_index = repo / normal_index
    normal_index = normal_index.absolute()
    before_index = index_fingerprint(normal_index)
    head_before = git(repo, "rev-parse", "HEAD")
    output.mkdir(mode=0o700)
    sync_directory(output.parent)
    with tempfile.TemporaryDirectory(prefix="alternate-index-", dir=output) as temporary:
        alternate = Path(temporary) / "index"
        require(alternate != normal_index, "alternate_index_is_normal_index")
        git(repo, "read-tree", PARENT, index=alternate)
        index_updates = bytearray()
        for name in INCLUDE:
            object_id = git(repo, "hash-object", "-w", "--stdin",
                            data=captured[name][0], index=alternate).decode().strip()
            mode = parent_entries[name][0] if name in parent_entries else "100644"
            index_updates.extend((mode + " " + object_id + "\t" + name).encode("utf-8") + b"\0")
        git(repo, "update-index", "-z", "--index-info", data=bytes(index_updates), index=alternate)
        tree = git(repo, "write-tree", index=alternate).decode().strip()
        entries = tree_entries(repo, tree)
        require(len(entries) == EXPECTED_FILE_COUNT
                and changed_paths(parent_entries, entries) == set(INCLUDE)
                and changed_paths(base_entries, entries) == set(INCLUDE) | set(PROTECTED_R8L),
                "frozen_tree_contains_unallowlisted_changes")
        for name in PROTECTED_R8L:
            require(entries[name] == parent_entries[name], "protected_r8l_tree_entry_changed")
        commit = git(
            repo, "commit-tree", tree, "-p", PARENT, index=alternate,
            data=("storage: wire internal native HA archive repair and real Raft regressions\n\n"
                  "Freeze only the five archive repair source files over recovered R8l.\n"
                  "Service/HTTP recovery admission remains closed; test execution is separate.\n").encode(),
        ).decode().strip()
    require(index_fingerprint(normal_index) == before_index
            and git(repo, "rev-parse", "HEAD") == head_before,
            "ordinary_index_or_head_changed_during_freeze")
    require(git(repo, "rev-parse", commit + "^{tree}").decode().strip() == tree
            and git(repo, "rev-parse", commit + "^").decode().strip() == PARENT,
            "new_commit_does_not_name_exact_tree_and_parent")
    for name in INCLUDE:
        require(capture_file(repo / name) == captured[name], "source_changed_during_freeze:" + name)
    blobs = blob_bytes(repo, [oid for _, oid in entries.values()])
    manifest = manifest_for(commit, tree, PARENT, entries, blobs)
    # The recovered object may be a shallow boundary. Read its immutable
    # commit header instead of asking Git to walk across that boundary.
    base_headers = git(repo, "cat-file", "commit", OVERLAY_BASE).split(b"\n\n", 1)[0]
    base_parents = [line.removeprefix(b"parent ").decode("ascii")
                    for line in base_headers.splitlines() if line.startswith(b"parent ")]
    require(base_parents == ["675d842e3f086b84512e398368d9ffd38071c636"],
            "overlay_base_commit_header_parent_mismatch")
    base_parent = base_parents[0]
    base_manifest = manifest_for(OVERLAY_BASE, OVERLAY_BASE_TREE, base_parent,
                                 base_entries, initial_blobs)
    manifest_data = json_bytes(manifest)
    overlay_names = set(INCLUDE) | set(PROTECTED_R8L)
    overlay = {
        "schema": "heptabao.source-overlay.v1",
        "base_commit": OVERLAY_BASE,
        "base_tree": OVERLAY_BASE_TREE,
        "base_manifest": base_manifest,
        "before": {name: sha256(initial_blobs[base_entries[name][1]])
                   if name in base_entries else None for name in sorted(overlay_names)},
        "after": {name: manifest["files"][name] for name in sorted(overlay_names)},
        "files": encoded_files(entries, blobs, overlay_names),
        "manifest": manifest,
    }
    full = {
        "schema": "heptabao.source-bundle.v1",
        "encoding": "base64",
        "manifest": manifest,
        "files": encoded_files(entries, blobs, entries),
    }
    artifacts = {
        "manifest": write_new(output / "r8m-source-manifest.json", manifest_data),
        "base_manifest": write_new(output / "r8k-recovered-base-manifest.json", json_bytes(base_manifest)),
        "overlay": write_new(output / "r8m-source-overlay.json.gz",
                             gzip.compress(json_bytes(overlay), compresslevel=9, mtime=0)),
        "full_source": write_new(output / "r8m-source-full.json.gz",
                                 gzip.compress(json_bytes(full), compresslevel=9, mtime=0)),
    }
    require(index_fingerprint(normal_index) == before_index
            and git(repo, "rev-parse", "HEAD") == head_before,
            "ordinary_index_or_head_changed_before_receipt")
    receipt = {
        "schema": "heptabao.archive-repair-source-freeze.v1",
        "source_commit": commit, "source_tree": tree,
        "parent_commit": PARENT, "parent_tree": PARENT_TREE,
        "overlay_base_commit": OVERLAY_BASE, "overlay_base_tree": OVERLAY_BASE_TREE,
        "source_file_count": len(entries), "overlay_file_count": len(overlay_names),
        "included_worktree_paths": sorted(INCLUDE),
        "preserved_r8l_sha256": PROTECTED_R8L,
        "ordinary_index_unchanged": True, "head_unchanged": True,
        "service_http_recovery_enabled": False, "tests_executed": False,
        "artifacts": artifacts,
    }
    write_new(output / "r8m-source-freeze-receipt.json", json_bytes(receipt))
    print(json.dumps(receipt, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
