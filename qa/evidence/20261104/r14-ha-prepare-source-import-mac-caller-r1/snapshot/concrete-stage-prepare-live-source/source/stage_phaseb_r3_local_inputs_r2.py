#!/usr/bin/env python3
"""Create-only local Phase B source/artifact carrier; no product execution.

This new script does not invoke either target module or a subprocess. It is
not a prepare result. Root must separately qualify the actual canonical source
stage and shared artifact transport, review this source, and authorize one run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
BASE = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1")
CONTROL = BASE / "official271-native-cli-phaseb-r3-control-r2"
WORK = BASE / "official271-native-cli-phaseb-r3-live-r2"
SOURCE = BASE / "normal-phaseb-ingress-observer-source-r1"
INCOMING = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-shared-artifacts-r1/incoming")
OFFICIAL = BASE / "official271-standby-oracle-control-r1/artifacts/bao"
MACHINE_SHA = "d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3"
HEAD = "3cb873919170cc77101b27f6a3ab9e98f41f8d93"
TREE = "7f4d48a647a81ca96e8a24a0a057c2c829459060"
PAYLOAD_SHA = "2f9f8acb45e66f49b42739e64eac6bf289f06a7d5bc840eab3b2c8ce87ce0fcd"
PAYLOAD_BYTES = 273490
FILES = json.loads(r'''{
  "phaseb_controller_r3.py": {
    "bytes": 61210,
    "sha256": "10816d06fd5ad59175872ccb7db1337d7677e92405a26a7ab1cae2796ee0a86c"
  },
  "phaseb_binding_r3.py": {
    "bytes": 23664,
    "sha256": "73736dbcfe951cf666f8413190958aff38d68e95457f1f969b0e47f8c0266c25"
  },
  "phaseb_evidence_r3.py": {
    "bytes": 15201,
    "sha256": "4fb452f9eabbbc9f66913e0b824f7f3db5b2a75848b2adf4186e76078f2c9024"
  },
  "native_fixture_reference_r8.py": {
    "bytes": 68149,
    "sha256": "a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416"
  },
  "official_cli_reference_r4.py": {
    "bytes": 46586,
    "sha256": "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"
  },
  "normal-release-tests-result.public.json": {
    "bytes": 35178,
    "sha256": "8899a7acc647505c230430b35771ae1eccaf48cc5aea27a034906d513fd0b0f7"
  },
  "groups.json": {
    "bytes": 6249,
    "sha256": "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"
  },
  "binding.partially-resolved.json": {
    "bytes": 6656,
    "sha256": "26ffaf3fd669fcf83bf78af275fc38512b1f8b6b467693b371b8c61a0f53f69c"
  }
}''')
QA_NAMES = (
    "phaseb_controller_r3.py", "phaseb_binding_r3.py", "phaseb_evidence_r3.py",
    "native_fixture_reference_r8.py", "official_cli_reference_r4.py",
)
COPY = (
    ("heptabao-server", 109074848, "437723d26976b23628a5b5058b4b89e00923b8e0f1b9604045a47e8e34459da0", 0o500, 0o500),
    ("native-build.public.json", 794, "51d0d83956a82e532b1f576a904bd1d5708ccc8991eaa6572b7435d8e57aebce", 0o400, 0o600),
    ("normal-release-result.public.json", 3200, "6313b4eaad68ac882d0891e14bd9d1632e138e635e3626b1b2b774e6be8f243f", 0o400, 0o600),
)
SOURCE_PINS = {
    "crates/heptabao-server/src/ha_native_v6_runtime.rs": (61623, "5291c584d8c91d6517cf4282fbbb66424dbdb184e070b9b23d11a4cbc564074a"),
    "crates/heptabao-server/src/snapshot_archive.rs": (14013, "77c9565ac4efcfe8d387ae7955c4c977bdd4913bcf770981a9b28facdeb2313d"),
    "crates/heptabao-server/src/service.rs": (518245, "2545e0951051b76b6278c2678c893b98756d3164855939a811db6b22dfc31cf2"),
    "crates/heptabao-server/src/service_snapshot_transfer.rs": (50683, "022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9"),
    "crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs": (43899, "3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff"),
    "crates/heptabao-server/src/service_no_forwarding_ha_tests.rs": (16529, "3c5e9b2e8f306786e1c5ce1ef1a02b5442bb1dc12e9de08bfed78e0dfcec808f"),
}
OLD_FENCES = {
    "official271-native-cli-phaseb-r3-live-r1/result.public.json": "cd2d1d89271b0342755935f366cf41b25ad49e1cd560a1ab7a1eb7b698e9d184",
    "official271-cli-transport-live-r3/result.public.json": "03ab9457519569ac87a8d1738bbb1be0f108d8d9ca87d0c567f8301ec26dcd68",
    "normal33-standby-oracle-live-r3/result.public.json": "f5a44d25e6f33e562b492e050242f36cc2744417a13a01db4beab1c0422ae590",
    "formal-33cafa-normal-full128-r2/summary.json": "8f7285ffad498ec0b6eeaca48e255790776a15ec62c218e195cf5e7ce0f2e8f1",
    "formal-33cafa-pocket3-mac1-direct98-r1/summary.json": "b02a111b487e33065117fc88596113c7e8a7695feb283331165381fafd3c167f",
}
UNTIL = 0
schema = "heptabao.official271-native-cli-phaseb-r3.local-stage.v1"
result = {"schema": schema, "status": "not_started", "product_started": False,
          "readonly_prepare_started": False, "network_calls": 0,
          "children_spawned": 0, "source_tree_modified": False,
          "runtime_qualification": False, "production_changed": False}


class StageError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise StageError(code)


def remaining():
    need(time.monotonic_ns() < UNTIL, "local_stage_original_300_seconds")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def identity(s):
    return {"device": s.st_dev, "inode": s.st_ino, "uid": s.st_uid, "gid": s.st_gid,
            "mode": stat.S_IMODE(s.st_mode), "links": s.st_nlink,
            "bytes": s.st_size, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}


def directory_identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise StageError("fresh_owned_namespace_required")


def open_source(path, maximum, expected_size=None, expected_mode=None, expected_uid=None):
    remaining()
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         "source_parent_not_canonical")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_source")
    need(0 <= before.st_size <= maximum, "source_size_bound")
    need(expected_size is None or before.st_size == expected_size, "source_exact_size")
    need(expected_mode is None or stat.S_IMODE(before.st_mode) == expected_mode, "source_exact_mode")
    need(expected_uid is None or before.st_uid == expected_uid, "source_exact_owner")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(before), "source_fd_custody")
    except BaseException:
        os.close(fd)
        raise
    return fd, before


def finish_source(path, fd, before):
    need(identity(os.fstat(fd)) == identity(before)
         and identity(path.lstat()) == identity(before), "source_changed_during_read")
    remaining()


def capture(path, maximum, expected_sha=None, expected_size=None):
    fd, before = open_source(path, maximum, expected_size)
    try:
        digest = hashlib.sha256()
        count = 0
        while True:
            remaining()
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            need(count <= maximum and count <= before.st_size, "source_grew")
            digest.update(block)
        need(count == before.st_size, "source_truncated")
        need(expected_sha is None or digest.hexdigest() == expected_sha, "source_sha_mismatch")
        finish_source(path, fd, before)
        return {"path": str(path), **identity(before), "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


class NewDirectories:
    def __init__(self):
        self.fds = []
        self.created = False
        self.basefd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.fds.append(self.basefd)
        try:
            self.base_identity = directory_identity(os.fstat(self.basefd))
            need(BASE.resolve(strict=True) == BASE and BASE.lstat().st_uid == 1000
                 and not stat.S_IMODE(BASE.lstat().st_mode) & 0o022, "base_directory_owner")
        except BaseException:
            os.close(self.basefd)
            self.fds = []
            raise
        self.rootfd = self.qafd = self.artfd = None
        self.written = []

    def check(self):
        need(directory_identity(BASE.lstat()) == self.base_identity
             == directory_identity(os.fstat(self.basefd)), "base_directory_custody")
        if self.created:
            need(directory_identity(os.stat(CONTROL.name, dir_fd=self.basefd, follow_symlinks=False))
                 == self.root_identity == directory_identity(os.fstat(self.rootfd)), "new_root_custody")
            for name, fd, expected in self.children:
                need(directory_identity(os.stat(name, dir_fd=self.rootfd, follow_symlinks=False))
                     == expected == directory_identity(os.fstat(fd)), "new_child_directory_custody")

    def create(self):
        self.check()
        absent(CONTROL)
        os.mkdir(CONTROL.name, 0o700, dir_fd=self.basefd)
        self.created = True
        self.children = []
        self.rootfd = os.open(CONTROL.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self.basefd)
        self.fds.append(self.rootfd)
        self.root_identity = directory_identity(os.fstat(self.rootfd))
        need(stat.S_IMODE(os.fstat(self.rootfd).st_mode) == 0o700
             and os.fstat(self.rootfd).st_uid == 1000, "new_root_permissions")
        os.fsync(self.basefd)
        for name in ("qa", "artifacts"):
            os.mkdir(name, 0o700, dir_fd=self.rootfd)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.rootfd)
            self.fds.append(fd)
            self.children.append((name, fd, directory_identity(os.fstat(fd))))
            if name == "qa":
                self.qafd = fd
            else:
                self.artfd = fd
        os.fsync(self.rootfd)
        self.check()

    def write(self, fd, name, raw, mode=0o600):
        need(fd in (self.rootfd, self.qafd, self.artfd), "owned_destination_fd")
        need(name in set(QA_NAMES) | {"groups.json", "normal-release-tests-result.public.json",
                                    "binding.private.json", "stage.result.public.json",
                                    "stage.failure.public.json"}, "closed_destination_filename")
        self.check()
        remaining()
        child = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            view = memoryview(raw)
            while view:
                remaining()
                n = os.write(child, view)
                need(n > 0, "write_progress")
                view = view[n:]
            os.fchmod(child, mode)
            os.fsync(child)
            st = os.fstat(child)
            os.lseek(child, 0, os.SEEK_SET)
            observed = bytearray()
            while True:
                remaining()
                block = os.read(child, 65536)
                if not block:
                    break
                observed.extend(block)
                need(len(observed) <= len(raw), "destination_growth")
            need(bytes(observed) == raw, "destination_byte_readback")
            need(identity(st) == identity(os.fstat(child))
                 == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), "destination_name_identity")
            need(st.st_uid == 1000 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode,
                 "destination_permissions")
        finally:
            os.close(child)
        os.fsync(fd)
        self.check()
        self.written.append(name)
        return {"name": name, **identity(st), "sha256": sha(raw), "create_only": True}

    def copy(self, name, size, expected_sha, source_mode, target_mode):
        self.check()
        path = INCOMING / name
        sourcefd, before = open_source(path, size, size, source_mode, 1000)
        targetfd = None
        try:
            targetfd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                               dir_fd=self.artfd)
            digest = hashlib.sha256()
            count = 0
            while True:
                remaining()
                block = os.read(sourcefd, 65536)
                if not block:
                    break
                count += len(block)
                need(count <= size, "copy_source_growth")
                digest.update(block)
                view = memoryview(block)
                while view:
                    remaining()
                    n = os.write(targetfd, view)
                    need(n > 0, "copy_write_progress")
                    view = view[n:]
            need(count == size and digest.hexdigest() == expected_sha, "copy_source_exact")
            finish_source(path, sourcefd, before)
            os.fchmod(targetfd, target_mode)
            os.fsync(targetfd)
            st = os.fstat(targetfd)
            need(st.st_uid == 1000 and st.st_nlink == 1 and st.st_size == size
                 and stat.S_IMODE(st.st_mode) == target_mode, "copy_target_custody")
            os.lseek(targetfd, 0, os.SEEK_SET)
            back = hashlib.sha256()
            read_size = 0
            while True:
                remaining()
                block = os.read(targetfd, 65536)
                if not block:
                    break
                read_size += len(block)
                need(read_size <= size, "copy_target_growth")
                back.update(block)
            need(read_size == size and back.hexdigest() == expected_sha, "copy_target_sha")
            need(identity(st) == identity(os.fstat(targetfd))
                 == identity(os.stat(name, dir_fd=self.artfd, follow_symlinks=False)),
                 "copy_target_name_identity")
            finish_source(path, sourcefd, before)
            source = {"path": str(path), **identity(before), "sha256": expected_sha}
            target = {"path": str(CONTROL / "artifacts" / name), **identity(st), "sha256": expected_sha}
        finally:
            try:
                if targetfd is not None:
                    os.close(targetfd)
            finally:
                os.close(sourcefd)
        os.fsync(self.artfd)
        self.check()
        self.written.append(name)
        return {"source": source, "target": target, "create_only": True, "same_fd_readback": True}

    def close(self):
        errors = []
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError as error:
                errors.append(type(error).__name__)
        self.fds = []
        return errors


def main():
    global UNTIL
    started = time.monotonic_ns()
    UNTIL = started + 300_000_000_000
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-controller-sha256", required=True)
    args = parser.parse_args()
    need(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
         "python_I_S_B_required")
    need(re.fullmatch(r"[0-9a-f]{64}", args.external_controller_sha256), "external_controller_pin")
    need((platform.system(), platform.machine(), os.getuid()) == ("Linux", "x86_64", 1000),
         "exact_operator_host")
    os.umask(0o077)
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    need(len(raw) == PAYLOAD_BYTES and sha(raw) == PAYLOAD_SHA, "exact_source_carrier")
    payload = json.loads(raw, object_pairs_hook=unique)
    need(set(payload) == {"schema", "files"}
         and payload["schema"] == "heptabao.official271-native-cli-phaseb-r3.local-source-carrier.v1",
         "source_carrier_shape")
    need(type(payload["files"]) is dict and set(payload["files"]) == set(FILES), "source_carrier_members")
    files = {}
    for name, pin in FILES.items():
        value = payload["files"][name]
        need(type(value) is str, "source_carrier_text")
        value = value.encode("utf-8")
        need(len(value) == pin["bytes"] and sha(value) == pin["sha256"], "source_carrier_file_pin")
        files[name] = value
    spec = json.loads(files["binding.partially-resolved.json"], object_pairs_hook=unique)
    need(spec["candidate_commit"] == HEAD and spec["candidate_tree"] == TREE
         and spec["ready_for_readonly_prepare"] is False, "original_partial_binding")
    need(spec["layout"] == {"control": str(CONTROL), "source": str(SOURCE),
                            "work": str(WORK), "prepare": str(CONTROL / "prepare-r1")},
         "original_binding_layout")
    absent(CONTROL)
    absent(WORK)
    machine = capture(Path("/etc/machine-id"), 256, MACHINE_SHA)
    need(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir()
         and SOURCE.lstat().st_uid == 1000, "source_root_custody")
    need(INCOMING.resolve(strict=True) == INCOMING and INCOMING.is_dir()
         and INCOMING.lstat().st_uid == 1000
         and stat.S_IMODE(INCOMING.lstat().st_mode) == 0o500, "shared_incoming_custody")
    directory_fences = {str(path): directory_identity(path.lstat()) for path in (SOURCE, INCOMING)}
    source_pins = [capture(SOURCE / p, 2 * 1024 * 1024, digest, size)
                   for p, (size, digest) in SOURCE_PINS.items()]
    old_fences = [capture(BASE / p, 16 * 1024 * 1024, digest) for p, digest in OLD_FENCES.items()]
    official = capture(OFFICIAL, 181760103, "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea", 181760103)
    python = Path(sys.executable).resolve(strict=True)
    need(python.parent == Path("/usr/bin")
         and re.fullmatch(r"python3(?:\.[0-9]+)?", python.name), "fixed_python_family")
    utilities = {"python": capture(python, 64 * 1024 * 1024),
                 "git": capture(Path("/usr/bin/git"), 64 * 1024 * 1024),
                 "openssl": capture(Path("/usr/bin/openssl"), 64 * 1024 * 1024)}
    captured = [machine, *source_pins, *old_fences, official, *utilities.values()]
    owned = None
    try:
        owned = NewDirectories()
        owned.create()
        copied = [owned.copy(*item) for item in COPY]
        qarecords = [owned.write(owned.qafd, name, files[name]) for name in QA_NAMES]
        extra = [owned.write(owned.artfd, name, files[name])
                 for name in ("groups.json", "normal-release-tests-result.public.json")]
        for category in ("qa_files", "artifacts"):
            for pin in spec[category].values():
                pin["uid"] = 1000
        def bind(observed):
            return {key: observed[key] for key in ("path", "sha256", "bytes", "uid", "mode")}
        spec["host"]["uid"] = 1000
        spec["host"]["machine_id_sha256"] = MACHINE_SHA
        spec["utilities"] = {name: bind(value) for name, value in utilities.items()}
        spec["official_cli"] = bind(official)
        spec["old_fences"] = [bind(value) for value in old_fences]
        spec["ready_for_readonly_prepare"] = True
        binding_raw = (json.dumps(spec, sort_keys=True, indent=2) + "\n").encode()
        binding_record = owned.write(owned.rootfd, "binding.private.json", binding_raw)
        for item in [*captured, *[entry["source"] for entry in copied]]:
            now = identity(Path(item["path"]).lstat())
            need(now == {key: item[key] for key in now}, "protected_source_metadata_changed")
        for name, captured_directory in directory_fences.items():
            need(directory_identity(Path(name).lstat()) == captured_directory,
                 "protected_source_directory_custody_changed")
        owned.check()
        need(set(os.listdir(owned.qafd)) == set(QA_NAMES), "exact_created_qa_members")
        need(set(os.listdir(owned.artfd)) == {x[0] for x in COPY}
             | {"groups.json", "normal-release-tests-result.public.json"}, "exact_created_artifact_members")
        result.update(status="passed", source_commit=HEAD, source_tree=TREE,
                      source_full_git_verification_performed_by_stage=False,
                      source_full_git_verification_required_in_readonly_prepare=True,
                      machine_id_sha256=MACHINE_SHA, copied=copied, qa_files=qarecords,
                      extra_artifacts=extra, captured_readonly_inputs=captured,
                      source_directory_fences=directory_fences,
                      binding={"path": str(CONTROL / "binding.private.json"), **binding_record},
                      source_metadata_unchanged=True, original_existing_assets_replaced=False,
                      source_carrier_sha256=PAYLOAD_SHA,
                      external_controller_sha256=args.external_controller_sha256,
                      external_controller_self_attestation_claimed=False,
                      next_step="root reviews stage and canonical/transport receipts before separate prepare")
        remaining()
        result["elapsed_ms"] = (time.monotonic_ns() - started) / 1e6
        # The durable file records the fsynced state before closing its own
        # directory FDs. Only stdout plus authoritative exit confirms closure.
        result["fd_close_pending"] = True
        result["closure_evidence"] = "complete_runtime_stdout_and_authoritative_exit_required"
        owned.write(owned.rootfd, "stage.result.public.json",
                    (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    except BaseException as error:
        result.update(status="failed", error_type=type(error).__name__,
                      new_root_created=bool(owned and owned.created),
                      known_written_names=[] if owned is None else list(owned.written),
                      partial_owned_assets_retained=True, automatic_replay=False)
        if isinstance(error, StageError):
            result["failure_code"] = str(error)
        if owned is not None and owned.created and owned.rootfd is not None:
            try:
                owned.write(owned.rootfd, "stage.failure.public.json",
                            (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
            except BaseException as log_error:
                result["failure_receipt_error_type"] = type(log_error).__name__
    finally:
        result["fd_close_errors"] = [] if owned is None else owned.close()
        result["fd_close_pending"] = False
        result["all_stage_fds_closed"] = (result["status"] == "passed"
                                          and not result["fd_close_errors"])
        result["elapsed_after_closure_ms"] = (time.monotonic_ns() - started) / 1e6
        result["within_stage_deadline"] = time.monotonic_ns() < UNTIL
        if result["fd_close_errors"] or not result["within_stage_deadline"]:
            result["status"] = "failed"
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["status"] == "passed" and time.monotonic_ns() < UNTIL else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        result.update(status="failed_before_new_owned_root", error_type=type(error).__name__)
        if isinstance(error, StageError):
            result["failure_code"] = str(error)
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(1) from None
