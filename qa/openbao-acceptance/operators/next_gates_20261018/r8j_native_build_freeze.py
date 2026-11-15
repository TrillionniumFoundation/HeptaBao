#!/usr/bin/env python3
"""R8j native build -> private, copied binary and hash-bound build receipt.

Run locally ON each build host, after its source installation is verified and
while the owner schedules no other Cargo job against the same target directory.
This script has no SSH, service, fault-injection, cleanup or deployment action.
An existing output directory is always rejected; partial evidence is retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import struct
import subprocess
import sys
import time

COMMIT = "4f0bacd59be21d204783d69b500d2a19ef6af55a"
TREE = "9514b66b8cda559938e135d6c7c5b9606296fd4a"
MANIFEST_SHA = "676ca7874714d3113b45a880fea4e898f9d8d42aefb16e3d733e7e7fc0efda8f"
GITHUB_COMMIT = "675d842e3f086b84512e398368d9ffd38071c636"
FEATURE = "experimental-native-v6-ha"
ABIS = {("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu"}


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def sync_dir(path):
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(str(path), flags, mode), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    sync_dir(path.parent)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def canonical_directory(path):
    require(path.is_absolute() and path.resolve(strict=True) == path
            and path.is_dir() and not path.is_symlink(), "directory_not_canonical")
    return path


def load_manifest(path):
    require(path.is_absolute() and not path.is_symlink()
            and digest(path) == MANIFEST_SHA, "r8j_manifest_sha256_mismatch")
    value = json.loads(path.read_bytes())
    require(value.get("schema") == "heptabao.source-freeze.v1"
            and value.get("source_commit") == COMMIT
            and value.get("source_tree") == TREE
            and len(value.get("files", {})) == 2582
            and set(value["files"]) == set(value.get("modes", {})),
            "r8j_manifest_identity_mismatch")
    return value


def verify_source(root, manifest):
    seen = set()
    for parent, directories, names in os.walk(str(root), followlinks=False):
        directories[:] = [name for name in directories if name != "__pycache__"]
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), "source_symlink_directory")
        for name in names:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            seen.add(relative)
            require(relative in manifest["files"], "unexpected_source_file")
            mode = path.lstat().st_mode
            require(stat.S_ISREG(mode) and not path.is_symlink(), "source_not_regular")
            require(digest(path) == manifest["files"][relative], "source_content_mismatch")
            expected = 0o755 if manifest["modes"][relative] == "100755" else 0o644
            require(stat.S_IMODE(mode) == expected, "source_mode_mismatch")
    require(seen == set(manifest["files"]), "source_file_set_mismatch")
    for name in manifest["files"]:
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and ".git" not in relative.parts, "unsafe_manifest_path")


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def copy_binary(source, destination):
    require(source.resolve(strict=True) == source, "artifact_path_not_canonical")
    descriptor = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    value = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and before.st_size > 1024,
                "artifact_owner_or_shape")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(str(destination), flags, 0o500), "wb") as output:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                value.update(chunk)
                output.write(chunk)
            output.flush()
            os.fchmod(output.fileno(), 0o500)
            os.fsync(output.fileno())
            copied = os.fstat(output.fileno())
            require((copied.st_dev, copied.st_ino) != (before.st_dev, before.st_ino)
                    and copied.st_nlink == 1 and copied.st_size == before.st_size,
                    "binary_copy_must_have_independent_inode")
        require(file_identity(before) == file_identity(os.fstat(descriptor))
                == file_identity(source.lstat()), "artifact_changed_during_freeze")
    finally:
        os.close(descriptor)
    sync_dir(destination.parent)
    require(digest(destination) == value.hexdigest(), "binary_copy_readback_mismatch")
    return value.hexdigest()


def verify_binary_abi(path, abi):
    with path.open("rb") as stream:
        header = stream.read(64)
        if abi == "aarch64-apple-darwin":
            require(header[:4] == b"\xcf\xfa\xed\xfe"
                    and struct.unpack_from("<I", header, 4)[0] == 0x0100000c
                    and struct.unpack_from("<I", header, 12)[0] == 2,
                    "binary_is_not_native_arm64_macho_executable")
            return {"format": "Mach-O64", "cpu": "arm64", "filetype": "MH_EXECUTE"}
        require(header[:6] == b"\x7fELF\x02\x01"
                and struct.unpack_from("<H", header, 18)[0] == 62,
                "binary_is_not_native_x86_64_elf")
        offset = struct.unpack_from("<Q", header, 32)[0]
        width, count = struct.unpack_from("<HH", header, 54)
        require(width == 56 and 0 < count <= 1024, "elf_program_header_shape")
        interpreter = None
        for index in range(count):
            stream.seek(offset + index * width)
            item = stream.read(width)
            require(len(item) == width, "elf_program_header_truncated")
            if struct.unpack_from("<I", item, 0)[0] == 3:
                position = struct.unpack_from("<Q", item, 8)[0]
                size = struct.unpack_from("<Q", item, 32)[0]
                require(0 < size <= 512 and interpreter is None, "elf_interpreter_shape")
                stream.seek(position)
                interpreter = stream.read(size).rstrip(b"\0").decode("ascii")
        require(interpreter in ("/lib64/ld-linux-x86-64.so.2",
                                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                                "/usr/lib64/ld-linux-x86-64.so.2"),
                "gnu_dynamic_abi_not_proven")
        return {"format": "ELF64", "cpu": "x86_64", "interpreter": interpreter}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "manifest", "cargo", "rustc", "cargo-home", "target-dir", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-abi", choices=sorted(set(ABIS.values())), required=True)
    parser.add_argument("--cmake", type=Path)
    parser.add_argument("--path-prefix", action="append", default=[], type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    source = canonical_directory(args.source_root)
    cargo_home = canonical_directory(args.cargo_home)
    target = canonical_directory(args.target_dir)
    output = args.output_dir
    parent = canonical_directory(output.parent)
    require(output.is_absolute() and output.name not in ("", ".", "..")
            and not output.exists() and not output.is_symlink()
            and parent.stat().st_uid == os.getuid() and not parent.stat().st_mode & 0o022,
            "output_must_be_new_below_owned_parent")
    require(source != target and source not in target.parents
            and source != output and source not in output.parents,
            "build_outputs_cannot_change_source_freeze")
    manifest = load_manifest(args.manifest)
    verify_source(source, manifest)
    require(ABIS.get((platform.system(), platform.machine())) == args.native_abi,
            "build_host_native_abi_mismatch")
    for executable in (args.cargo, args.rustc):
        require(executable.is_absolute() and executable.is_file()
                and os.access(str(executable), os.X_OK), "explicit_toolchain_unavailable")
    environment = dict(os.environ)
    for key in ("CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        environment.pop(key, None)
    paths = [str(args.cargo.parent), str(args.rustc.parent)]
    paths.extend(str(canonical_directory(path)) for path in args.path_prefix)
    environment.update(PATH=os.pathsep.join(paths + [environment.get("PATH", "/usr/bin:/bin")]),
                       CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target), RUSTC=str(args.rustc))
    if args.cmake is not None:
        require(args.cmake.is_absolute() and args.cmake.is_file(), "explicit_cmake_unavailable")
        environment["CMAKE"] = str(args.cmake)
    rustc = subprocess.check_output([str(args.rustc), "-vV"], env=environment, timeout=10).decode()
    cargo = subprocess.check_output([str(args.cargo), "-V"], env=environment, timeout=10).decode().strip()
    require("release: 1.98.0\n" in rustc and "host: " + args.native_abi + "\n" in rustc
            and cargo.startswith("cargo 1.98.0 "), "toolchain_198_native_host_not_verified")
    output.mkdir(mode=0o700)
    sync_dir(parent)
    command = [str(args.cargo), "build", "--locked", "--offline", "-p", "heptabao-server",
               "--bin", "heptabao-server", "--features", FEATURE, "--message-format=json"]
    started = time.monotonic()
    write_new(output / "build-start.json", json_bytes({
        "schema": "heptabao.r8j-native-build-start.v1", "source_commit": COMMIT,
        "source_tree": TREE, "source_manifest_sha256": MANIFEST_SHA,
        "command": command, "source_root": str(source), "native_abi": args.native_abi,
        "cargo_home": str(cargo_home), "target_dir": str(target),
        "production_cutover": False}))
    messages = output / "cargo-artifacts.jsonl"
    log = output / "cargo-build.log"
    with messages.open("xb") as stdout, log.open("xb") as stderr:
        result = subprocess.run(command, cwd=str(source), env=environment,
                                stdout=stdout, stderr=stderr, check=False)
        for stream in (stdout, stderr):
            stream.flush()
            os.fsync(stream.fileno())
    require(result.returncode == 0, "cargo_build_failed_private_log_retained")
    artifacts, finished = [], []
    with messages.open("r") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("reason") == "build-finished":
                finished.append(event.get("success"))
            if event.get("reason") != "compiler-artifact":
                continue
            value = event.get("target", {})
            if value.get("name") != "heptabao-server" or value.get("kind") != ["bin"]:
                continue
            require(Path(value["src_path"]) == source / "crates/heptabao-server/src/main.rs"
                    and event.get("profile", {}).get("test") is False
                    and {FEATURE, "fixture-native-v6-service"} <= set(event.get("features", []))
                    and isinstance(event.get("executable"), str),
                    "cargo_binary_event_not_bound_to_native_source")
            artifacts.append(Path(event["executable"]))
    require(finished == [True] and len(artifacts) == 1, "cargo_binary_event_missing_or_ambiguous")
    artifact = artifacts[0]
    require(target in artifact.parents, "cargo_artifact_not_in_explicit_target")
    binary = output / "heptabao-server"
    binary_sha = copy_binary(artifact, binary)
    abi_evidence = verify_binary_abi(binary, args.native_abi)
    verify_source(source, manifest)
    receipt = {
        "schema": "heptabao.native-build.v1", "source_commit": COMMIT, "source_tree": TREE,
        "github_saved_commit_same_tree": GITHUB_COMMIT, "binary_sha256": binary_sha,
        "build_exit_code": result.returncode, "source_freeze_verified": True,
        "native_abi": args.native_abi, "source_manifest_sha256": MANIFEST_SHA,
        "source_files": len(manifest["files"]), "source_root": str(source),
        "source_verified_before_and_after": True, "binary_path": str(binary),
        "cargo_artifact_path": str(artifact), "binary_has_independent_inode": True,
        "copied_binary_readback_verified": True, "binary_abi_evidence": abi_evidence,
        "command": command, "cargo_version": cargo, "rustc_verbose_version": rustc,
        "cargo_home": str(cargo_home), "target_dir": str(target), "features": [FEATURE],
        "cargo_artifact_log_sha256": digest(messages), "build_log_sha256": digest(log),
        "freezer_sha256": digest(Path(__file__).resolve()),
        "elapsed_seconds": round(time.monotonic() - started, 3), "production_cutover": False,
    }
    receipt_path = output / "native-build-r8j.json"
    write_new(receipt_path, json_bytes(receipt), 0o400)
    print(json.dumps({"status": "frozen", "source_commit": COMMIT, "source_tree": TREE,
                      "native_abi": args.native_abi, "binary_path": str(binary),
                      "binary_sha256": binary_sha, "receipt_path": str(receipt_path),
                      "receipt_sha256": digest(receipt_path)}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(json.dumps({"status": "failed", "error": code,
                          "native_build_receipt_issued": False}), file=sys.stderr)
        raise SystemExit(1)
