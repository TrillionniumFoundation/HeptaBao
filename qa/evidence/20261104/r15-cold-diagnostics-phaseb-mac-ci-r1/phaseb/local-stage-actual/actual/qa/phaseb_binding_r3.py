#!/usr/bin/env python3
"""Explicit NEW R3 binding. No artifact placeholder authorizes prepare or runtime."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import sys
import time

SCHEMA = "heptabao.official271-native-cli-phaseb-r3.binding.v1"
COMMIT = "3cb873919170cc77101b27f6a3ab9e98f41f8d93"
TREE = "7f4d48a647a81ca96e8a24a0a057c2c829459060"
OBSERVER_PATH = "crates/heptabao-server/src/ha_native_v6_runtime.rs"
INGRESS_OBSERVER_TESTS = (
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_is_affine_and_resumed_binding_never_arms",
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root",
    "service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_actual_failed_repair_closes_reselection_before_any_result",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_failure_has_only_bounded_static_metadata",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_sixty_four_buckets_preserve_existing_aggregates",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_observes_deadlines_but_preserves_once_only_results",
    "ha::native_v6_runtime::request_timing_tests::native_request_timing_phase_advance_is_distinct_from_operation_success",
)
BASE = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1")
OFFICIAL_SHA = "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea"
OFFICIAL_BYTES = 181760103
OFFICIAL_SOURCE_COMMIT = "a5db72cef75c24b920ade02065b18dd8eb666bac"
GROUPS_SHA = "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"
FEATURES = ["default", "native-v6-ha", "native-v6-storage"]
PROFILE = {"debug_assertions": True, "debuginfo": 0, "opt_level": "3",
           "overflow_checks": True, "test": False}
QA_NAMES = (
    "phaseb_controller_r3.py", "phaseb_binding_r3.py", "phaseb_evidence_r3.py",
    "native_fixture_reference_r8.py", "official_cli_reference_r4.py",
)
REFERENCE_PINS = {
    "native_fixture_reference_r8.py": (
        68149, "a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416"),
    "official_cli_reference_r4.py": (
        46586, "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"),
}
PRODUCT_PINS = {
    OBSERVER_PATH: ("3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3",
                    "5291c584d8c91d6517cf4282fbbb66424dbdb184e070b9b23d11a4cbc564074a"),
    "crates/heptabao-server/src/snapshot_archive.rs": (
        "6828ae88590184830da949001b13abd82a4f9b10",
        "77c9565ac4efcfe8d387ae7955c4c977bdd4913bcf770981a9b28facdeb2313d"),
    "crates/heptabao-server/src/service.rs": (
        "baf0a89b7ed2a2dec6c89d2464ef6605faaffa08",
        "2545e0951051b76b6278c2678c893b98756d3164855939a811db6b22dfc31cf2"),
    "crates/heptabao-server/src/service_snapshot_transfer.rs": (
        "6b94e34c223fac25858c1e7f82fb18c07abf0ef3",
        "022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9"),
    "crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs": (
        "0a94044292493853c7770cb36aa69544c1488aca",
        "3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff"),
}
BUDGETS = {
    "http_seconds": 15, "cli_seconds": 15, "action_seconds": 300,
    "readiness_seconds": 45, "election_seconds": 60,
    "stable_leader_seconds": 2.2, "peer_timeout_ms": 1500,
    "forward_timeout_ms": 8000, "cleanup_term_seconds": 5, "cleanup_kill_seconds": 5,
}
API_PORTS = {1: 48630, 2: 48632, 3: 48634}
RAFT_PORTS = {node: port + 1 for node, port in API_PORTS.items()}


class BindingError(RuntimeError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise BindingError(code)


def remaining(until: int) -> float:
    value = (until - time.monotonic_ns()) / 1e9
    need(value > 0, "original_action_deadline")
    return value


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def identity(st: os.stat_result) -> dict:
    return {"device": st.st_dev, "inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
            "links": st.st_nlink, "mode": stat.S_IMODE(st.st_mode),
            "bytes": st.st_size, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}


def exact_path(value: str) -> Path:
    need(type(value) is str and value.startswith("/") and "\0" not in value, "absolute_path_required")
    path = Path(value)
    need(str(path) == value and ".." not in path.parts, "canonical_path_spelling")
    return path


def no_symlink_ancestors(path: Path) -> None:
    for parent in reversed(path.parents):
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "symlink_or_nondirectory_ancestor")
    need(path.parent.resolve(strict=True) == path.parent, "resolved_parent_changed")


def duplicate_free(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def parse(raw: bytes) -> object:
    return json.loads(raw.decode(), object_pairs_hook=duplicate_free)


def read_file(path: Path, maximum: int, until: int, *, retain: bool = True) -> tuple[bytes | None, dict]:
    remaining(until)
    no_symlink_ancestors(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_file_required")
    need(0 <= before.st_size <= maximum, "file_size_bound")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    data = bytearray() if retain else None
    try:
        need(identity(os.fstat(fd)) == identity(before), "file_identity_before_read")
        count = 0
        while True:
            remaining(until)
            block = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            need(count <= maximum, "file_size_bound")
            digest.update(block)
            if data is not None:
                data.extend(block)
        need(identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before), "file_identity_after_read")
        remaining(until)
        return (bytes(data) if data is not None else None), {
            **identity(before), "path": str(path), "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def pin_file(pin: dict, until: int, *, retain: bool = False) -> tuple[bytes | None, dict]:
    need(type(pin) is dict and set(pin) == {"path", "sha256", "bytes", "uid", "mode"}, "exact_file_pin_fields")
    need(type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None
         and pin["sha256"] != "0" * 64, "real_file_sha_required")
    need(type(pin["bytes"]) is int and 0 < pin["bytes"] <= 512 * 1024 * 1024, "real_file_size_required")
    need(type(pin["uid"]) is int and pin["uid"] in (0, os.getuid()), "allowed_file_owner")
    need(type(pin["mode"]) is int and 0 <= pin["mode"] <= 0o777
         and not pin["mode"] & 0o022, "pinned_nonwritable_by_others_mode")
    raw, observation = read_file(exact_path(pin["path"]), pin["bytes"], until, retain=retain)
    need(all(observation[key] == pin[key] for key in ("sha256", "bytes", "uid", "mode")), "file_pin_mismatch")
    return raw, observation


def load_verified_module(name: str, path: Path, expected_sha: str, expected_bytes: int, until: int):
    raw, observation = read_file(path, expected_bytes, until)
    need(observation["sha256"] == expected_sha and len(raw) == expected_bytes, "module_pin_mismatch")
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "module_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # Execute the exact already-hashed source bytes, rather than reopen the path.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    remaining(until)
    return module


class Binding:
    def __init__(self, path: Path, expected_sha: str, until: int):
        need(type(COMMIT) is str and re.fullmatch(r"[0-9a-f]{40}", COMMIT) is not None
             and type(TREE) is str and re.fullmatch(r"[0-9a-f]{40}", TREE) is not None
             and type(PRODUCT_PINS[OBSERVER_PATH][0]) is str
             and re.fullmatch(r"[0-9a-f]{40}", PRODUCT_PINS[OBSERVER_PATH][0]) is not None
             and type(PRODUCT_PINS[OBSERVER_PATH][1]) is str
             and re.fullmatch(r"[0-9a-f]{64}", PRODUCT_PINS[OBSERVER_PATH][1]) is not None,
             "diagnostic_candidate_source_not_frozen")
        raw, observed = read_file(path, 2 * 1024 * 1024, until)
        need(observed["sha256"] == expected_sha, "binding_sha_mismatch")
        need(observed["uid"] == os.getuid() and observed["mode"] == 0o600, "private_binding_custody")
        spec = parse(raw)
        need(type(spec) is dict and set(spec) == {
            "schema", "candidate_commit", "candidate_tree", "host", "layout",
            "qa_files", "artifacts", "official_cli", "utilities", "old_fences",
            "budgets", "ready_for_readonly_prepare",
        }, "exact_binding_fields")
        need(spec["schema"] == SCHEMA and spec["candidate_commit"] == COMMIT
             and spec["candidate_tree"] == TREE, "exact_diagnostic_candidate_binding")
        need(spec["ready_for_readonly_prepare"] is True, "unresolved_binding_is_not_admission")
        need(spec["budgets"] == BUDGETS, "original_budgets_unchanged")
        self.spec, self.path, self.sha256, self.initial_file = spec, path, expected_sha, observed
        layout = spec["layout"]
        need(type(layout) is dict and set(layout) == {"control", "source", "work", "prepare"}, "layout_fields")
        self.control, self.source, self.work, self.prepare = [exact_path(layout[key])
                                                           for key in ("control", "source", "work", "prepare")]
        need(self.control.parent == BASE
             and re.fullmatch(r"official271-native-cli-phaseb-r3-control-r[0-9]+", self.control.name) is not None,
             "owned_control_namespace")
        need(self.work.parent == BASE
             and re.fullmatch(r"official271-native-cli-phaseb-r3-live-r[0-9]+", self.work.name) is not None,
             "owned_work_namespace")
        need(self.source.parent == BASE
             and re.fullmatch(r"normal-phaseb-ingress-observer-source-r[0-9]+", self.source.name) is not None,
             "canonical_source_namespace")
        need(self.prepare.parent == self.control
             and re.fullmatch(r"prepare-r[0-9]+", self.prepare.name) is not None, "prepare_namespace")
        need(path.parent == self.control and path.name == "binding.private.json", "exact_binding_location")
        no_symlink_ancestors(self.control)
        st = self.control.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
             and stat.S_IMODE(st.st_mode) == 0o700, "owned_control_custody")
        self.qa = spec["qa_files"]
        need(type(self.qa) is dict and set(self.qa) == set(QA_NAMES), "exact_five_qa_members")
        for name, pin in self.qa.items():
            need(pin["path"] == str(self.control / "qa" / name)
                 and pin["uid"] == os.getuid() and pin["mode"] == 0o600, "qa_owned_layout")
        for name, (size, digest) in REFERENCE_PINS.items():
            need(self.qa[name]["bytes"] == size and self.qa[name]["sha256"] == digest, "exact_reference_source")
        self.artifacts = spec["artifacts"]
        need(type(self.artifacts) is dict and set(self.artifacts) == {
            "server", "native_receipt", "release_receipt", "combined_tests", "test_groups"
        }, "artifact_members")
        artifact_names = {
            "server": "heptabao-server", "native_receipt": "native-build.public.json",
            "release_receipt": "normal-release-result.public.json",
            "combined_tests": "normal-release-tests-result.public.json", "test_groups": "groups.json",
        }
        for role, pin in self.artifacts.items():
            need(pin["path"] == str(self.control / "artifacts" / artifact_names[role])
                 and pin["uid"] == os.getuid()
                 and pin["mode"] == (0o500 if role == "server" else 0o600), "owned_artifact_layout")
        self.server = exact_path(self.artifacts["server"]["path"])
        self.cli = exact_path(spec["official_cli"]["path"])
        need(spec["official_cli"]["sha256"] == OFFICIAL_SHA
             and spec["official_cli"]["bytes"] == OFFICIAL_BYTES, "official271_exact_artifact")
        need(type(spec["utilities"]) is dict and set(spec["utilities"]) == {"python", "git", "openssl"},
             "utility_members")
        need(exact_path(spec["utilities"]["python"]["path"]) == Path(sys.executable).resolve(strict=True),
             "actual_python_binding")
        need(spec["utilities"]["git"]["path"] == "/usr/bin/git"
             and spec["utilities"]["openssl"]["path"] == "/usr/bin/openssl", "fixed_utilities")
        need(type(spec["old_fences"]) is list and 1 <= len(spec["old_fences"]) <= 32, "finite_existing_fences")
        paths = [item["path"] for item in spec["old_fences"]]
        need(len(paths) == len(set(paths)), "unique_existing_fences")
        for value in paths:
            p = exact_path(value)
            need(p.is_relative_to(BASE) and p != BASE
                 and not p.is_relative_to(self.work), "old_fence_scope")

    def check_host(self, until: int) -> dict:
        host = self.spec["host"]
        need(type(host) is dict and set(host) == {"uid", "machine_id_sha256", "system", "machine"}, "host_fields")
        need(host["uid"] == os.getuid() and host["system"] == platform.system() == "Linux"
             and host["machine"] == platform.machine() == "x86_64", "physical_native_host")
        raw, _ = read_file(Path("/etc/machine-id"), 256, until)
        need(re.fullmatch(r"[0-9a-f]{64}", host["machine_id_sha256"]) is not None
             and sha(raw) == host["machine_id_sha256"], "exact_desktop_identity")
        return dict(host)

    def verify(self, run_readonly, until: int) -> dict:
        remaining(until)
        host = self.check_host(until)
        observations = {}
        for category, pins in (("qa", self.qa), ("artifacts", self.artifacts),
                               ("utilities", self.spec["utilities"])):
            observations[category] = {}
            for key, pin in pins.items():
                _, observations[category][key] = pin_file(pin, until)
        _, observations["official_cli"] = pin_file(self.spec["official_cli"], until)
        observations["old_fences"] = [pin_file(pin, until)[1] for pin in self.spec["old_fences"]]
        _, binding_now = read_file(self.path, 2 * 1024 * 1024, until)
        need(binding_now == self.initial_file, "binding_file_identity_changed")
        receipt = {}
        for name in ("native_receipt", "release_receipt", "combined_tests", "test_groups"):
            raw, _ = pin_file(self.artifacts[name], until, retain=True)
            receipt[name] = parse(raw)
        native, release, combined, groups = [receipt[key] for key in
                                            ("native_receipt", "release_receipt", "combined_tests", "test_groups")]
        for item in (native, release):
            need(item.get("source_commit") == COMMIT and item.get("source_tree") == TREE
                 and item.get("source_freeze_verified") is True and item.get("build_exit_code") == 0
                 and item.get("native_abi") == "x86_64-unknown-linux-gnu", "normal_build_source_identity")
        artifact = release["artifacts"]["heptabao-server"]
        need(native.get("schema") == "heptabao.native-build.v1"
             and release.get("schema") == "heptabao.native-default-build-result.v1"
             and native.get("binary_sha256") == self.artifacts["server"]["sha256"]
             and native.get("features") == FEATURES and artifact.get("features") == FEATURES
             and artifact.get("profile") == PROFILE
             and artifact.get("sha256") == self.artifacts["server"]["sha256"]
             and artifact.get("bytes") == self.artifacts["server"]["bytes"],
             "normal_default_abi_profile_artifact")
        need(release.get("normal_default_candidate") is True
             and release.get("timed_out") is False
             and release.get("owned_group_survivors_after_wait") is False
             and release.get("build_finished_success") is True
             and native["provenance"]["result_sha256"] == self.artifacts["release_receipt"]["sha256"]
             and native["provenance"]["cargo_events_sha256"] == release["cargo_events_sha256"],
             "normal_release_provenance")
        command = release["command"]
        need(type(command) is list and command[1:] == [
            "build", "--release", "--locked", "--offline", "-p", "heptabao-server",
            "--bin", "heptabao-server", "--bin", "heptabao-seed",
            "--message-format=json-render-diagnostics"
        ] and str(command[0]).endswith("/bin/cargo"), "normal_release_exact_command")
        need(self.artifacts["test_groups"]["sha256"] == GROUPS_SHA, "original_44_group_file")
        need(combined.get("schema") == "heptabao.linux-normal-release-and-exact-libtest-phaseb-observer.v1"
             and combined.get("source_commit") == COMMIT and combined.get("source_tree") == TREE
             and combined.get("status") == "passed"
             and combined.get("normal_default_features") is True
             and combined.get("fixture_features") == []
             and combined.get("test_count") == 44 and combined.get("groups_sha256") == GROUPS_SHA
             and combined.get("groups") == groups and combined.get("runtime_tests_started") is True
             and combined.get("binary_unchanged") is True
             and combined.get("release_artifacts_unchanged") is True
             and combined.get("source_unchanged") is True
             and combined.get("native_build_receipt_sha256") == self.artifacts["native_receipt"]["sha256"],
             "diagnostic_original44_terminal_pass_required")
        shapes = [("ssh25", 25), ("mount1", 1), ("redirect5", 5), ("actor2", 2),
                  ("ordinary5", 5), ("no_forward6", 6)]
        need(type(groups) is list and [(g["label"], len(g["tests"])) for g in groups] == shapes,
             "original_group_denominator")
        actual = combined.get("group_results")
        need(type(actual) is list and len(actual) == len(groups), "complete_44_group_results")
        for group, observed in zip(groups, actual):
            test = observed["tests"]
            need(observed["label"] == group["label"]
                 and len(observed["actual_test_names"]) == len(group["tests"])
                 and set(observed["actual_test_names"]) == set(group["tests"])
                 and test.get("exit_code") == 0 and test.get("timed_out") is False
                 and test.get("direct_child_reaped") is True and test.get("remaining") == [],
                 "original_group_terminal_and_ownership")
        extra = combined.get("ingress_observer_regression")
        need(type(extra) is dict
             and extra.get("schema") == "heptabao.normal-ingress-observer-regression.v1"
             and extra.get("status") == "passed" and extra.get("test_count") == 7
             and extra.get("original_44_denominator_unchanged") is True
             and extra.get("new_total_group_cap_seconds") == 600
             and extra.get("actual_test_names") == list(INGRESS_OBSERVER_TESTS)
             and type(extra.get("tests")) is list and len(extra["tests"]) == 7
             and combined.get("original_44_status") == "passed",
             "exact_ingress_observer_negative_regression")
        for name, observed in zip(INGRESS_OBSERVER_TESTS, extra["tests"]):
            test = observed["tests"]
            need(observed.get("name") == name and test.get("exit_code") == 0
                 and test.get("timed_out") is False
                 and test.get("direct_child_reaped") is True and test.get("remaining") == [],
                 "ingress_observer_regression_terminal")
        cleanup = combined.get("cleanup")
        need(type(cleanup) is list and bool(cleanup)
             and all(item.get("direct_child_reaped") is True and item.get("remaining") == []
                     and not item.get("cleanup_error_type") for item in cleanup), "build_all_owned_stopped")
        source_observation = {}
        commands = {
            "commit": ["rev-parse", "HEAD"], "tree": ["rev-parse", "HEAD^{tree}"],
            "status": ["status", "--porcelain", "--untracked-files=all"],
        }
        for key, suffix in commands.items():
            remaining(until)
            argv = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                    "-C", str(self.source), *suffix]
            source_observation[key] = run_readonly(argv, "source-" + key, min(until, time.monotonic_ns() + 15_000_000_000)).decode().strip()
        need(source_observation == {"commit": COMMIT, "tree": TREE, "status": ""}, "canonical_clean_source")
        product = {}
        for relative, (blob, expected) in PRODUCT_PINS.items():
            raw, observed = read_file(self.source / relative, 2 * 1024 * 1024, until)
            actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            need(observed["sha256"] == expected and actual_blob == blob, "exact_product_archive_audit_source")
            product[relative] = {"sha256": expected, "git_blob": blob, "bytes": len(raw)}
        remaining(until)
        return {
            "schema": "heptabao.official271-native-cli-phaseb-r3.inputs.v1",
            "binding_sha256": self.sha256, "host": host, "files": observations,
            "source": source_observation, "archive_and_audit_product_sources": product,
            "budgets": BUDGETS,
            "api_ports": {str(node): port for node, port in API_PORTS.items()},
            "raft_ports": {str(node): port for node, port in RAFT_PORTS.items()},
            "official_source_commit": OFFICIAL_SOURCE_COMMIT,
            "whole_replacement_qualification": False,
        }

    def quick_fence(self, verified: dict) -> None:
        files = verified["files"]
        pins = []
        for category in ("qa", "artifacts", "utilities"):
            pins.extend(files[category].values())
        pins.append(files["official_cli"])
        pins.extend(files["old_fences"])
        for item in pins:
            now = exact_path(item["path"]).lstat()
            need(identity(now) == {key: item[key] for key in identity(now)}, "pinned_input_metadata_changed")
        need(identity(self.path.lstat()) == {key: self.initial_file[key] for key in identity(self.path.lstat())},
             "binding_metadata_changed")

    def fresh_path(self, path: Path) -> None:
        need(path in (self.work, self.prepare), "fresh_path_scope")
        no_symlink_ancestors(path)
        try:
            path.lstat()
        except FileNotFoundError:
            return
        raise BindingError("fresh_owned_path_required")

    def check_ports(self) -> None:
        for port in [*API_PORTS.values(), *RAFT_PORTS.values()]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", port))
        # This is an availability observation only, not a persistent reservation.
