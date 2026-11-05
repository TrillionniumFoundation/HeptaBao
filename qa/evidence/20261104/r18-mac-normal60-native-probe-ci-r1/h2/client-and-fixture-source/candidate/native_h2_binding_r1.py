#!/usr/bin/env python3
"""NEW normal-native H2 gate binding. Actual product and QA build receipts are required."""
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
import tomllib

SCHEMA = "heptabao.normal-native-h2-gate.binding.v1"
COMMIT = "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
TREE = "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"
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
COLD_H2_TESTS = (
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity",
    "service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results",
    "service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context",
    "http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity",
)
H2_COMPONENT_TESTS = [
    "component_tests::native_h2_client_accepts_complete_data_eos",
    "component_tests::native_h2_client_accepts_complete_empty_trailers_eos",
    "component_tests::native_h2_client_rejects_rst_no_error_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_eof_after_exact_body_before_eos",
    "component_tests::native_h2_client_rejects_short_eos_and_duplicate_content_length",
    "component_tests::native_h2_client_refuses_expired_or_extended_original_deadline"
]
H2_BUILD_CONTROLLER_SHA = "2e2ea6edd029b3d7164fbe6a85826ef3523a0ec60586d330b539761d870c0a35"
H2_BUILD_CAPS = {
    "total_seconds": 600,
    "git_seconds": 15,
    "tool_seconds": 15,
    "lock_seconds": 20,
    "build_seconds": 180,
    "components_build_seconds": 180,
    "list_seconds": 15,
    "components_seconds": 30,
    "cleanup_term_seconds": 5,
    "cleanup_kill_seconds": 5
}
H2_SOURCE_PINS = {
    "rust_source": [
        19382,
        "41347a71055e5c7086a256549f25f20d52ba8361e16926b4470f3448425f90dd"
    ],
    "test_source": [
        8942,
        "7f23470287fe953f0271e974d6eda759b7daf9f15bc363d522a02d3633e012c2"
    ],
    "cargo_manifest": [
        957,
        "960de7b19776cda4bd8a00561a417f72b08ca320efb93ec05028a3be0e7315e5"
    ]
}
BASE = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1")
CANONICAL_LOCK_SHA = "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
GROUPS_SHA = "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1"
FEATURES = ["default", "native-v6-ha", "native-v6-storage"]
PROFILE = {"debug_assertions": True, "debuginfo": 0, "opt_level": "3",
           "overflow_checks": True, "test": False}
QA_NAMES = (
    "native_h2_gate_r1.py", "native_h2_binding_r1.py", "phaseb_evidence_r3.py",
    "native_fixture_reference_r8.py", "official_cli_reference_r4.py",
)
REFERENCE_PINS = {
    "native_fixture_reference_r8.py": (
        68149, "a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416"),
    "official_cli_reference_r4.py": (
        46586, "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"),
}
PRODUCT_PINS = {
    "Cargo.lock": [
        "f3b5394e274d5da977e7e1ec89940b0d0e9f55ff",
        "d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5"
    ],
    "crates/heptabao-server/src/ha_native_v6_runtime.rs": [
        "3289da21ebb25a1efd04ae0d0fd1013ac7ac8fb3",
        "5291c584d8c91d6517cf4282fbbb66424dbdb184e070b9b23d11a4cbc564074a"
    ],
    "crates/heptabao-server/src/http_h2.rs": [
        "70db7e9c37f057ddb7a1a146e57d1697928d33ce",
        "4db2b72314f7f8c0fd7b271d57d359156bc6add9fdd25e8206d44eee45d20ed1"
    ],
    "crates/heptabao-server/src/http_snapshot.rs": [
        "4a5743d757b79493400b712bf57a5fa552b50bda",
        "1cc98a78d6a037a47456b7c6b93dc13647a261e8217f12a6a4edff3d91fe41e2"
    ],
    "crates/heptabao-server/src/service.rs": [
        "baf0a89b7ed2a2dec6c89d2464ef6605faaffa08",
        "2545e0951051b76b6278c2678c893b98756d3164855939a811db6b22dfc31cf2"
    ],
    "crates/heptabao-server/src/service_snapshot_transfer.rs": [
        "6b94e34c223fac25858c1e7f82fb18c07abf0ef3",
        "022be62ccaf26a335103dc106be432d7b8896768cace056e649b65ca920e97b9"
    ],
    "crates/heptabao-server/src/service_snapshot_v6_ha_restore.rs": [
        "0a94044292493853c7770cb36aa69544c1488aca",
        "3802288e0f2e3f58b94df509c928467fa2d3d11ee47bb9c68128c6143b9138ff"
    ],
    "crates/heptabao-server/src/snapshot_archive.rs": [
        "6828ae88590184830da949001b13abd82a4f9b10",
        "77c9565ac4efcfe8d387ae7955c4c977bdd4913bcf770981a9b28facdeb2313d"
    ]
}
BUDGETS = {
    "http_seconds": 15, "h2_client_seconds": 15, "action_seconds": 300,
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


def lock_subset(actual_raw: bytes, canonical_raw: bytes) -> dict:
    actual = tomllib.loads(actual_raw.decode("utf-8"))
    canonical = tomllib.loads(canonical_raw.decode("utf-8"))
    need(type(actual) is dict and set(actual) == {"version", "package"}
         and type(actual["version"]) is int
         and actual["version"] == canonical.get("version"), "qa_lock_top_level")
    package_list = canonical.get("package")
    need(type(package_list) is list and type(actual["package"]) is list
         and 1 < len(actual["package"]) <= len(package_list), "qa_lock_package_bound")
    allowed = {}
    for item in package_list:
        key = (item["name"], item["version"], item.get("source"))
        need(key not in allowed, "canonical_lock_duplicate_package")
        allowed[key] = item.get("checksum")
    seen, members, own = set(), [], 0
    for item in actual["package"]:
        need(type(item) is dict and set(item) <=
             {"name", "version", "source", "checksum", "dependencies"}, "qa_lock_package_fields")
        need(type(item.get("name")) is str and type(item.get("version")) is str
             and type(item.get("dependencies", [])) is list
             and all(type(value) is str for value in item.get("dependencies", [])),
             "qa_lock_package_types")
        key = (item["name"], item["version"], item.get("source"))
        need(key not in seen, "qa_lock_duplicate_package")
        seen.add(key)
        if item["name"] == "heptabao-native-h2-qa":
            need(item["version"] == "0.1.0" and "source" not in item
                 and "checksum" not in item, "only_owned_qa_root_package")
            own += 1
            continue
        need(item.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
             and type(item.get("checksum")) is str
             and re.fullmatch(r"[0-9a-f]{64}", item["checksum"]) is not None
             and key in allowed and item["checksum"] == allowed[key],
             "qa_dependency_not_exact_canonical_lock_member")
        members.append({"name": item["name"], "version": item["version"],
                        "source": item["source"], "checksum": item["checksum"]})
    need(own == 1, "one_owned_qa_root_package")
    members.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    return {"schema": "heptabao.native-h2-qa.lock-subset.v1",
            "canonical_sha256": sha(canonical_raw), "qa_lock_sha256": sha(actual_raw),
            "registry_package_count": len(members), "owned_qa_package_count": own,
            "packages": members, "exact_version_source_checksum_subset": True}


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
            "qa_files", "artifacts", "h2_client", "utilities", "old_fences",
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
             and re.fullmatch(r"normal-native-h2-gate-control-r[0-9]+", self.control.name) is not None,
             "owned_control_namespace")
        need(self.work.parent == BASE
             and re.fullmatch(r"normal-native-h2-gate-live-r[0-9]+", self.work.name) is not None,
             "owned_work_namespace")
        need(self.source.parent == BASE
             and re.fullmatch(r"normal-cold-h2-validation-source-r[0-9]+", self.source.name) is not None,
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
        self.h2_client = spec["h2_client"]
        names = {
            "executable": "heptabao-native-h2-qa", "rust_source": "native_h2_client.rs",
            "test_source": "native_h2_client_tests.rs", "cargo_manifest": "Cargo.toml",
            "cargo_lock": "Cargo.lock", "canonical_lock": "canonical.Cargo.lock",
            "build_receipt": "build-result.public.json", "build_controller": "build_native_h2_client_r1.py",
            "build_binding": "build-binding.private.json",
            "component_stdout": "components.stdout", "component_record": "components.public.json",
            "component_list_stdout": "components-list.stdout",
        }
        need(type(self.h2_client) is dict and set(self.h2_client) == set(names),
             "exact_independent_h2_qa_members")
        for role, pin in self.h2_client.items():
            need(pin["path"] == str(self.control / "h2qa" / names[role])
                 and pin["uid"] == os.getuid()
                 and pin["mode"] == (0o500 if role == "executable" else 0o600),
                 "owned_h2_qa_layout")
        self.h2_executable = exact_path(self.h2_client["executable"]["path"])
        need(self.h2_client["canonical_lock"]["sha256"] == CANONICAL_LOCK_SHA,
             "exact_canonical_lock_copy")
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

    def verify_h2_qa(self, until: int) -> dict:
        for role, (size, digest) in H2_SOURCE_PINS.items():
            need(self.h2_client[role]["bytes"] == size
                 and self.h2_client[role]["sha256"] == digest, "exact_reviewed_h2_qa_source")
        need(type(H2_BUILD_CONTROLLER_SHA) is str
             and re.fullmatch(r"[0-9a-f]{64}", H2_BUILD_CONTROLLER_SHA) is not None
             and self.h2_client["build_controller"]["sha256"] == H2_BUILD_CONTROLLER_SHA,
             "exact_reviewed_h2_qa_builder")
        raw = {}
        for role in ("cargo_lock", "canonical_lock", "build_receipt", "build_binding",
                     "component_stdout", "component_record", "component_list_stdout"):
            raw[role], _ = pin_file(self.h2_client[role], until, retain=True)
        subset = lock_subset(raw["cargo_lock"], raw["canonical_lock"])
        need(subset["canonical_sha256"] == CANONICAL_LOCK_SHA, "canonical_dependency_source")
        build = parse(raw["build_receipt"])
        original_binding = parse(raw["build_binding"])
        component = parse(raw["component_record"])
        need(type(build) is dict and build.get("schema") == "heptabao.native-h2-qa.build.v1"
             and build.get("status") == "passed"
             and build.get("candidate_commit") == COMMIT and build.get("candidate_tree") == TREE
             and build.get("controller_sha256") == H2_BUILD_CONTROLLER_SHA
             and build.get("binding_sha256") == self.h2_client["build_binding"]["sha256"]
             and build.get("normal_product_result_sha256") == self.artifacts["combined_tests"]["sha256"]
             and build.get("normal_product_runner_sha256")
             == "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40"
             and build.get("caps") == H2_BUILD_CAPS
             and build.get("all_owned_stopped") is True
             and build.get("all_input_fds_closed") is True
             and build.get("command_outcome_unknown") is False
             and build.get("incomplete_command_labels") == []
             and build.get("completed_within_original_build_deadline") is True
             and build.get("source_before") == build.get("source_after")
             == {"commit": COMMIT, "tree": TREE, "status": ""}
             and build.get("lock_subset") == subset
             and build.get("offline_only") is True
             and build.get("product_modified") is False
             and build.get("product_or_http_requests") == 0, "actual_qa_build_provenance")
        need(type(original_binding) is dict
             and original_binding.get("schema") == "heptabao.native-h2-qa.build-binding.v1"
             and original_binding.get("candidate_commit") == COMMIT
             and original_binding.get("candidate_tree") == TREE
             and original_binding.get("ready") is True
             and original_binding.get("caps") == H2_BUILD_CAPS,
             "original_actual_qa_build_binding")
        expected_sources = {role: {"bytes": size, "sha256": digest}
                            for role, (size, digest) in H2_SOURCE_PINS.items()}
        need(build.get("reviewed_sources") == expected_sources, "qa_compiled_source_identity")
        executable = build.get("executable")
        need(type(executable) is dict
             and executable.get("sha256") == self.h2_client["executable"]["sha256"]
             and executable.get("bytes") == self.h2_client["executable"]["bytes"]
             and executable.get("features") == []
             and executable.get("profile") == PROFILE,
             "qa_actual_binary_from_release_event")
        need(build.get("component_names") == H2_COMPONENT_TESTS
             and build.get("component_record_sha256") == self.h2_client["component_record"]["sha256"]
             and component.get("stdout_sha256") == self.h2_client["component_stdout"]["sha256"]
             and component.get("exit_code") == 0 and component.get("timed_out") is False
             and component.get("direct_child_reaped") is True and component.get("remaining") == []
             and component.get("completed_within_deadline") is True,
             "six_actual_qa_components_and_owned_terminal")
        listed = [line[:-6] for line in raw["component_list_stdout"].decode("utf-8").splitlines()
                  if line.endswith(": test")]
        need(len(listed) == 6 and set(listed) == set(H2_COMPONENT_TESTS),
             "exact_qa_component_listing")
        output = raw["component_stdout"].decode("utf-8")
        executed = [line[5:-7] for line in output.splitlines()
                    if line.startswith("test ") and line.endswith(" ... ok")]
        need(len(executed) == 6 and set(executed) == set(H2_COMPONENT_TESTS)
             and output.count("test result: ok. 6 passed; 0 failed; 0 ignored;") == 1,
             "six_actual_qa_component_results")
        commands = build.get("commands")
        cleanup = build.get("owned_cleanup")
        need(type(commands) is list and 5 <= len(commands) <= 24
             and all(item.get("exit_code") == 0 and item.get("timed_out") is False
                     and item.get("direct_child_reaped") is True and item.get("remaining") == []
                     and item.get("completed_within_deadline") is True for item in commands)
             and type(cleanup) is list and len(cleanup) == len(commands)
             and all(item.get("direct_child_reaped") is True and item.get("remaining") == []
                     and item.get("owned_stopped") is True for item in cleanup),
             "all_actual_qa_commands_and_cleanup")
        remaining(until)
        return {"candidate_commit": COMMIT, "candidate_tree": TREE,
                "executable_sha256": executable["sha256"],
                "actual_build_receipt_sha256": self.h2_client["build_receipt"]["sha256"],
                "reviewed_sources": expected_sources,
                "component_names": H2_COMPONENT_TESTS,
                "component_count": 6, "component_status": "passed",
                "lock_subset": subset, "offline_only": True,
                "http_or_product_qualification": False,
                "new_qa_components_not_added_to_product_44_7_9": True}

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
                               ("utilities", self.spec["utilities"]), ("h2_client", self.h2_client)):
            observations[category] = {}
            for key, pin in pins.items():
                _, observations[category][key] = pin_file(pin, until)
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
        need(combined.get("schema") == "heptabao.linux-normal-cold-h2-exact-tests.v1"
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
        increment = combined.get("cold_h2_regression")
        need(type(increment) is dict
             and increment.get("schema") == "heptabao.normal-cold-h2-regression.v1"
             and increment.get("status") == "passed" and increment.get("test_count") == 9
             and increment.get("original_44_denominator_unchanged") is True
             and increment.get("existing_ingress_7_denominator_unchanged") is True
             and increment.get("new_total_group_cap_seconds") == 600
             and increment.get("clamped_to_original_outer_deadline") is True
             and increment.get("actual_test_names") == list(COLD_H2_TESTS)
             and type(increment.get("tests")) is list and len(increment["tests"]) == 9
             and combined.get("original_44_and_ingress_7_status") == "passed"
             and combined.get("selected_test_total") == 60
             and combined.get("additional_test_counts") == {"ingress_observer": 7, "cold_h2": 9},
             "exact_new_cold_h2_nine_regression")
        for name, observed in zip(COLD_H2_TESTS, increment["tests"]):
            test = observed["tests"]
            need(observed.get("name") == name and test.get("exit_code") == 0
                 and test.get("timed_out") is False
                 and test.get("direct_child_reaped") is True and test.get("remaining") == [],
                 "new_cold_h2_regression_terminal")
        need(combined.get("controller_sha256")
             == "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40",
             "exact_actual_df026_normal_runner")
        cleanup = combined.get("cleanup")
        need(type(cleanup) is list and bool(cleanup)
             and all(item.get("direct_child_reaped") is True and item.get("remaining") == []
                     and not item.get("cleanup_error_type") for item in cleanup), "build_all_owned_stopped")
        h2_proof = self.verify_h2_qa(until)
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
            "schema": "heptabao.normal-native-h2-gate.inputs.v1",
            "binding_sha256": self.sha256, "host": host, "files": observations,
            "source": source_observation, "archive_and_audit_product_sources": product,
            "budgets": BUDGETS,
            "api_ports": {str(node): port for node, port in API_PORTS.items()},
            "raft_ports": {str(node): port for node, port in RAFT_PORTS.items()},
            "independent_h2_qa": h2_proof,
            "official_cli_qualification": False,
            "whole_replacement_qualification": False,
        }

    def quick_fence(self, verified: dict) -> None:
        files = verified["files"]
        pins = []
        for category in ("qa", "artifacts", "utilities", "h2_client"):
            pins.extend(files[category].values())
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
