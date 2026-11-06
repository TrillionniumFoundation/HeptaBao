#!/usr/bin/env python3
"""Create-only local H2 source/artifact carrier; no product execution.

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
CONTROL = BASE / "normal-native-h2-gate-control-r2"
WORK = BASE / "normal-native-h2-gate-live-r2"
SOURCE = BASE / "normal-same-root-publication-validation-source-r1"
INCOMING = BASE / "normal-same-root-publication-shared-artifacts-r1/incoming"
H2_INCOMING = BASE / "normal-native-h2-qa-shared-artifacts-r1/incoming"
MACHINE_SHA = "d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3"
HEAD = "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
TREE = "eba5e650bd080b8ad41ea52a2bc68867f541d255"
PAYLOAD_SHA = '6700283209e4de4433d0ef562c696c9d95ea6a12a2f0c3926701e4cc11674883'
PAYLOAD_BYTES = 321152
FILES = json.loads(r'''{
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
  "native_h2_gate_r1.py": {
    "bytes": 62344,
    "sha256": "703e5ecfc9b88ce4d8cdaf81342597a12a7b42c92af583b54d87f4f8a37bcf13"
  },
  "native_h2_binding_r1.py": {
    "bytes": 41350,
    "sha256": "6bbaa72dcb899d359f14c6e442c824c46a8c52aa74aa0d6be8b1820596c34cf4"
  },
  "normal-release-tests-result.public.json": {
    "bytes": 57532,
    "sha256": "7830845172732432895c246d77c47266432a03c0788e15689ea74d15dff14475"
  },
  "groups.json": {
    "bytes": 6249,
    "sha256": "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"
  },
  "binding.partially-resolved.json": {
    "bytes": 10231,
    "sha256": "f8eaa547f0cf3d2536c55652293b3c8e9572126b537ee34014495ed222d20bcf"
  }
}''')
QA_NAMES = (
    'phaseb_evidence_r3.py',
    'native_fixture_reference_r8.py',
    'official_cli_reference_r4.py',
    'native_h2_gate_r1.py',
    'native_h2_binding_r1.py',
)
COPY = (
    ("heptabao-server", 110219600, "cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0", 0o500, 0o500),
    ("native-build.public.json", 786, "3bfc21f48ce6dd831c8bde094b2f24f53ed0266e57e5fd55839b0a5977f5db5a", 0o400, 0o600),
    ("normal-release-result.public.json", 3192, "78d5eeb0235f62896ec57ca4d0243e31c56e861a4dde438ccd23eac3edafdd22", 0o400, 0o600),
)
H2_COPY = {
    'executable': ('heptabao-native-h2-qa', 4616576, '1f1c6eccf1ac9652a69572cb270b1d3d99a3402eaabf6d7feed6e4b2c4d55b13', 0o500, 0o500),
    'rust_source': ('native_h2_client.rs', 19382, '41347a71055e5c7086a256549f25f20d52ba8361e16926b4470f3448425f90dd', 0o400, 0o600),
    'test_source': ('native_h2_client_tests.rs', 8942, '7f23470287fe953f0271e974d6eda759b7daf9f15bc363d522a02d3633e012c2', 0o400, 0o600),
    'cargo_manifest': ('Cargo.toml', 957, '960de7b19776cda4bd8a00561a417f72b08ca320efb93ec05028a3be0e7315e5', 0o400, 0o600),
    'cargo_lock': ('Cargo.lock', 17409, 'f1882bc0bb81e5f74da28502e8cbd718e87fcda0100bf85ad118b007a8faf9bf', 0o400, 0o600),
    'canonical_lock': ('canonical.Cargo.lock', 101193, 'd2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5', 0o400, 0o600),
    'build_receipt': ('build-result.public.json', 62314, 'b8a2e83ea012f11cef7dc83bc79758d2b624df7eac2265efddbd32e2880db95e', 0o400, 0o600),
    'build_controller': ('build_native_h2_client_r1.py', 59791, '7ea25347f71764f1ed3d459d24b92750ef82c361878e9c856c7a7e8fe699bc15', 0o400, 0o600),
    'build_binding': ('build-binding.private.json', 4039, 'ac127d3e67971ad6b9ae987c0fc6437f8882ff00d9480acbc12ed149796dd12a', 0o400, 0o600),
    'component_stdout': ('components.stdout', 633, '9c8b4f62679c5771d7a0b575674f9961e64afaefe46eb30b1825c2f696ed3274', 0o400, 0o600),
    'component_record': ('components.public.json', 804, '41a0386206a00967a450df01dab89d008d8fc543c4e84702f80aaa1fcbe1f829', 0o400, 0o600),
    'component_list_stdout': ('components-list.stdout', 507, 'cebfab7307ba716aeebf08514df4cc6cf9a638009579168ced3b621cf8c10d5d', 0o400, 0o600),
}
SOURCE_PINS = {
    'Cargo.lock': (101193, 'd2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5'),
    'crates/heptabao-server/src/ha_native_v6_runtime.rs': (61623, '5291c584d8c91d6517cf4282fbbb66424dbdb184e070b9b23d11a4cbc564074a'),
    'crates/heptabao-server/src/http_h2.rs': (14691, '4db2b72314f7f8c0fd7b271d57d359156bc6add9fdd25e8206d44eee45d20ed1'),
    'crates/heptabao-server/src/http_snapshot.rs': (35170, '1cc98a78d6a037a47456b7c6b93dc13647a261e8217f12a6a4edff3d91fe41e2'),
    'crates/heptabao-server/src/service.rs': (518245, '2545e0951051b76b6278c2678c893b98756d3164855939a811db6b22dfc31cf2'),
    'crates/heptabao-server/src/service_snapshot_transfer.rs': (50683, '022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9'),
    'crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs': (43899, '3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff'),
    'crates/heptabao-server/src/snapshot_archive.rs': (14013, '77c9565ac4efcfe8d387ae7955c4c977bdd4913bcf770981a9b28facdeb2313d'),
}
OLD_FENCES = {
    "official271-native-cli-phaseb-r3-live-r1/result.public.json": "cd2d1d89271b0342755935f366cf41b25ad49e1cd560a1ab7a1eb7b698e9d184",
    "official271-cli-transport-live-r3/result.public.json": "03ab9457519569ac87a8d1738bbb1be0f108d8d9ca87d0c567f8301ec26dcd68",
    "normal33-standby-oracle-live-r3/result.public.json": "f5a44d25e6f33e562b492e050242f36cc2744417a13a01db4beab1c0422ae590",
    "formal-33cafa-normal-full128-r2/summary.json": "8f7285ffad498ec0b6eeaca48e255790776a15ec62c218e195cf5e7ce0f2e8f1",
    "formal-33cafa-pocket3-mac1-direct98-r1/summary.json": "b02a111b487e33065117fc88596113c7e8a7695feb283331165381fafd3c167f",
    "official271-native-cli-phaseb-r3-live-r2/result.public.json": "15a07dca63299bbfb7f871c5d1611a22713382a85cd9f8acc917569d9044600e",
}
UNTIL = 0
schema = "heptabao.normal-native-h2-gate.local-stage.v1"
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
        self.rootfd = self.qafd = self.artfd = self.h2fd = None
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
        for name in ("qa", "artifacts", "h2qa"):
            os.mkdir(name, 0o700, dir_fd=self.rootfd)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.rootfd)
            self.fds.append(fd)
            self.children.append((name, fd, directory_identity(os.fstat(fd))))
            if name == "qa":
                self.qafd = fd
            elif name == "artifacts":
                self.artfd = fd
            else:
                self.h2fd = fd
        os.fsync(self.rootfd)
        self.check()

    def write(self, fd, name, raw, mode=0o600):
        need(fd in (self.rootfd, self.qafd, self.artfd), "owned_destination_fd")
        need((fd == self.qafd and name in QA_NAMES)
             or (fd == self.artfd and name in {"groups.json", "normal-release-tests-result.public.json"})
             or (fd == self.rootfd and name in {"binding.private.json", "stage.result.public.json",
                                               "stage.failure.public.json"}), "closed_destination_filename")
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

    def copy(self, name, size, expected_sha, source_mode, target_mode, *, h2=False):
        self.check()
        need(type(h2) is bool, "fixed_copy_route")
        member = (name, size, expected_sha, source_mode, target_mode)
        need(member in (H2_COPY.values() if h2 else COPY), "fixed_copy_member")
        incoming, directory, destination = ((H2_INCOMING, "h2qa", self.h2fd) if h2
                                            else (INCOMING, "artifacts", self.artfd))
        need(destination is not None, "owned_copy_destination_fd")
        path = incoming / name
        sourcefd, before = open_source(path, size, size, source_mode, 1000)
        targetfd = None
        try:
            targetfd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                               dir_fd=destination)
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
                 == identity(os.stat(name, dir_fd=destination, follow_symlinks=False)),
                 "copy_target_name_identity")
            finish_source(path, sourcefd, before)
            source = {"path": str(path), **identity(before), "sha256": expected_sha}
            target = {"path": str(CONTROL / directory / name), **identity(st), "sha256": expected_sha}
        finally:
            try:
                if targetfd is not None:
                    os.close(targetfd)
            finally:
                os.close(sourcefd)
        os.fsync(destination)
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
         and payload["schema"] == "heptabao.normal-native-h2-gate.local-source-carrier.v1",
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
    need(spec["schema"] == "heptabao.normal-native-h2-gate.binding.v2"
         and spec["candidate_commit"] == HEAD and spec["candidate_tree"] == TREE
         and spec["instrument_build_commit"] == "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
         and spec["instrument_build_tree"] == "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"
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
    need(H2_INCOMING.resolve(strict=True) == H2_INCOMING and H2_INCOMING.is_dir()
         and H2_INCOMING.lstat().st_uid == 1000
         and stat.S_IMODE(H2_INCOMING.lstat().st_mode) == 0o500, "instrument_incoming_custody")
    directory_fences = {str(path): directory_identity(path.lstat())
                        for path in (SOURCE, INCOMING, H2_INCOMING)}
    source_pins = [capture(SOURCE / p, 2 * 1024 * 1024, digest, size)
                   for p, (size, digest) in SOURCE_PINS.items()]
    old_fences = [capture(BASE / p, 16 * 1024 * 1024, digest) for p, digest in OLD_FENCES.items()]
    python = Path(sys.executable).resolve(strict=True)
    need(python.parent == Path("/usr/bin")
         and re.fullmatch(r"python3(?:\.[0-9]+)?", python.name), "fixed_python_family")
    utilities = {"python": capture(python, 64 * 1024 * 1024),
                 "git": capture(Path("/usr/bin/git"), 64 * 1024 * 1024),
                 "openssl": capture(Path("/usr/bin/openssl"), 64 * 1024 * 1024)}
    captured = [machine, *source_pins, *old_fences, *utilities.values()]
    owned = None
    try:
        owned = NewDirectories()
        owned.create()
        copied = [owned.copy(*item) for item in COPY]
        h2_copied = {role: owned.copy(*item, h2=True) for role, item in H2_COPY.items()}
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
        actual_h2 = {role: bind(entry["target"]) for role, entry in h2_copied.items()}
        need(actual_h2 == spec["h2_client"], "actual_h2_targets_match_frozen_binding")
        spec["h2_client"] = actual_h2
        spec["old_fences"] = [bind(value) for value in old_fences]
        spec["ready_for_readonly_prepare"] = True
        binding_raw = (json.dumps(spec, sort_keys=True, indent=2) + "\n").encode()
        binding_record = owned.write(owned.rootfd, "binding.private.json", binding_raw)
        for item in [*captured, *[entry["source"] for entry in copied],
                     *[entry["source"] for entry in h2_copied.values()]]:
            now = identity(Path(item["path"]).lstat())
            need(now == {key: item[key] for key in now}, "protected_source_metadata_changed")
        for name, captured_directory in directory_fences.items():
            need(directory_identity(Path(name).lstat()) == captured_directory,
                 "protected_source_directory_custody_changed")
        owned.check()
        need(set(os.listdir(owned.qafd)) == set(QA_NAMES), "exact_created_qa_members")
        need(set(os.listdir(owned.artfd)) == {x[0] for x in COPY}
             | {"groups.json", "normal-release-tests-result.public.json"}, "exact_created_artifact_members")
        need(set(os.listdir(owned.h2fd)) == {item[0] for item in H2_COPY.values()},
             "exact_created_h2_members")
        need(set(os.listdir(owned.rootfd)) == {"qa", "artifacts", "h2qa", "binding.private.json"},
             "exact_created_control_members")
        result.update(status="passed", source_commit=HEAD, source_tree=TREE,
                      source_full_git_verification_performed_by_stage=False,
                      source_full_git_verification_required_in_readonly_prepare=True,
                      machine_id_sha256=MACHINE_SHA, copied=copied, h2_copied=h2_copied, qa_files=qarecords,
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
