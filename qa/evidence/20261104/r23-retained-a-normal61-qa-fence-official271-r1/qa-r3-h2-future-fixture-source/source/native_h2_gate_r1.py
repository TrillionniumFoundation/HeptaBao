#!/usr/bin/env python3
"""NEW independent normal-native HTTP/2 gate for exact df026.

Reuse the recovered normal setup and owned lifecycle. Two explicit H2 GETs
and one independent H1 archive control are new operations in a fresh fixture.
No official CLI command, restore, replay, provider or production cutover runs.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import ssl
import struct
import subprocess
import sys
import time
from types import FunctionType

sys.dont_write_bytecode = True
SCHEMA = "heptabao.normal-native-h2-gate.controller.v1"
BASE = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1")
SNAPSHOT_ROUTE = "/v1/sys/storage/raft/snapshot"
H2_BODY_LIMIT = 8 * 1024 * 1024
CLIENT_REPORT_FIELDS = frozenset(["schema","candidate_commit","candidate_tree","stage","error_code","deadline_monotonic_ns","operation","connections_started","tls_chain_and_hostname_verified","selected_alpn_h2","tls_version","peer_leaf_sha256","request_dispatched","send_request_calls","stream_id","response_status","header_count","header_bytes","header_sha256","content_length","content_type","data_frames","data_none_observed","trailers_completed","trailers_empty","recv_end_stream","response_complete","body_bytes","body_sha256","connection_task_joined","connection_task_cancelled_after_observation","completed_before_original_deadline","outcome_unknown","client_reconnects","client_request_retries","redirects_followed","trace_enabled","raw_error_messages_emitted","product_or_official_cli_qualification"])



class Failure(RuntimeError):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Failure(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fixed_error(error: BaseException) -> str:
    value = str(error)
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,159}", value or ""):
        return value
    return type(error).__name__


def stable_identity(st) -> tuple:
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def write_json(path: Path, value: object) -> None:
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def bootstrap_modules(binding_path: Path, expected_sha: str):
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
            "explicit_python_I_S_B_required")
    require(binding_path.is_absolute() and binding_path.parent.parent == BASE
            and re.fullmatch(r"normal-native-h2-gate-control-r[0-9]+",
                             binding_path.parent.name) is not None
            and binding_path.name == "binding.private.json", "bootstrap_binding_path")
    st = binding_path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid()
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 2 * 1024 * 1024,
            "bootstrap_binding_custody")
    require(binding_path.parent.resolve(strict=True) == binding_path.parent, "bootstrap_parent_custody")
    fd = os.open(binding_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stable_identity(os.fstat(fd)) == stable_identity(st), "bootstrap_binding_fd_identity")
        raw = b""
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            raw += block
            require(len(raw) <= 2 * 1024 * 1024, "bootstrap_binding_bound")
        require(stable_identity(os.fstat(fd)) == stable_identity(st) and stable_identity(binding_path.lstat()) == stable_identity(st), "bootstrap_binding_stable")
    finally:
        os.close(fd)
    require(sha(raw) == expected_sha, "bootstrap_binding_digest")
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "bootstrap_duplicate_json_key")
            result[key] = value
        return result
    spec = json.loads(raw, object_pairs_hook=no_duplicates)
    require(spec.get("ready_for_readonly_prepare") is True, "binding_still_unresolved")
    expected = {
        "native_h2_gate_r1.py", "native_h2_binding_r1.py", "phaseb_evidence_r3.py",
        "native_fixture_reference_r8.py", "official_cli_reference_r4.py",
    }
    require(set(spec["qa_files"]) == expected, "bootstrap_exact_qa_set")
    recovered = {
        "native_fixture_reference_r8.py": (68149, "a0bac9972fbb9d65ed3edf537f732a08b5177864516b33ada0a6e98c4c6a0416"),
        "official_cli_reference_r4.py": (46586, "18318841d3538e60fddf951708055a206402f5bf1ecdacc2bfceabec4f998dd9"),
    }
    loaded = {}
    for name in sorted(expected):
        pin = spec["qa_files"][name]
        path = binding_path.parent / "qa" / name
        require(pin["path"] == str(path), "bootstrap_qa_location")
        require(path.parent.resolve(strict=True) == path.parent, "bootstrap_qa_parent")
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size == pin["bytes"] <= 512 * 1024, "bootstrap_qa_custody")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(stable_identity(os.fstat(fd)) == stable_identity(before), "bootstrap_qa_fd")
            content = b""
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                content += block
                require(len(content) <= 512 * 1024, "bootstrap_qa_bound")
            require(stable_identity(os.fstat(fd)) == stable_identity(before) and stable_identity(path.lstat()) == stable_identity(before), "bootstrap_qa_stable")
        finally:
            os.close(fd)
        require(sha(content) == pin["sha256"] and len(content) == pin["bytes"], "bootstrap_qa_digest")
        if name in recovered:
            require((len(content), sha(content)) == recovered[name], "exact_recovered_reference_before_exec")
        if name == "native_h2_gate_r1.py":
            require(path == Path(__file__).absolute(), "executed_controller_exact_location")
            continue
        module_spec = importlib.util.spec_from_file_location("phaseb_r3_" + name[:-3], path)
        require(module_spec is not None and module_spec.loader is not None, "bootstrap_module_spec")
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[module_spec.name] = module
        exec(compile(content, str(path), "exec"), module.__dict__)
        loaded[name] = module
    return (loaded["native_h2_binding_r1.py"], loaded["phaseb_evidence_r3.py"],
            loaded["native_fixture_reference_r8.py"], loaded["official_cli_reference_r4.py"])


def owner_class(cli):
    class Owned(cli.Owner):
        def __init__(self, root: Path):
            # Do not call Phase A Owner.__init__: no synthetic archive, token,
            # peer socket or Phase A case is created.
            self.private = root / "private"
            self.children = []
            self.child_provenance = []
            self.child_exec_visibility = []
            self.creating_child = False
            self.pending_signal = None
            self.counter = 0
            self.cleanup_records = []
            self.cleanup_attempted = set()
            self.cleanup_by_child = {}
            self.operation = None

        def invoke(self, argv: list[str], label: str, until: int, env: dict) -> dict:
            self.counter += 1
            unique = "%04d-%s" % (self.counter, label)
            record = None
            try:
                record = self.run_private(argv, unique, until, env)
                record["private_capture_label"] = unique
                return record
            finally:
                # Any exception after Popen still leaves the original Popen in
                # self.children. The outer owner cleanup runs for every child.
                pass

        def stop_once(self, process, captured, *, stopper=None, propagate=False) -> dict:
            require(any(child is process and saved == captured for child, saved in self.children),
                    "stop_requires_actual_owned_popen_and_capture")
            key = id(process)
            if key in self.cleanup_attempted:
                result = {**self.cleanup_by_child[key], "prior_cleanup_result_retained": True}
                if propagate:
                    require(result.get("owned_stopped") and result.get("direct_child_reaped"),
                            "original_owned_stop_unknown_not_retried")
                return result
            # Reserve the single original 5+5 s stop budget before dispatch.
            # A signal/error before completion retains a failed placeholder.
            self.cleanup_by_child[key] = {
                "pid": process.pid, "owned_stopped": False,
                "direct_child_reaped": process.returncode is not None,
                "stop_attempt_started": True, "stop_terminal_captured": False,
            }
            self.cleanup_attempted.add(key)
            try:
                if stopper is not None:
                    result = stopper(process, captured)
                elif captured is not None:
                    result = cli.stop_owned(process, captured)
                else:
                    result = cli.stop_provisional(process)
                result["direct_child_reaped"] = process.returncode is not None
                result["stop_terminal_captured"] = True
                self.cleanup_by_child[key] = result
            except BaseException as error:
                result = {
                    "pid": process.pid, "owned_stopped": False,
                    "direct_child_reaped": process.returncode is not None,
                    "error_type": type(error).__name__, "stop_terminal_captured": False,
                }
                self.cleanup_by_child[key] = result
                if propagate:
                    raise
            if propagate:
                require(result.get("owned_stopped") and result.get("direct_child_reaped"),
                        "original_owned_stop_not_confirmed")
            return result

        def cleanup(self) -> list[dict]:
            records = []
            seen = set()
            for process, captured in reversed(self.children):
                if id(process) in seen:
                    continue
                seen.add(id(process))
                try:
                    records.append(self.stop_once(process, captured))
                except BaseException as error:
                    # A collection/identity error must not skip other children.
                    records.append({"pid": process.pid, "owned_stopped": False,
                                    "direct_child_reaped": process.returncode is not None,
                                    "error_type": type(error).__name__})
            self.cleanup_records = records
            return records
    return Owned


def neutral_environment(home: Path) -> dict:
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "PYTHONDONTWRITEBYTECODE": "1"}


def readonly_runner(owner, root: Path, evidence):
    def run(argv: list[str], label: str, until: int) -> bytes:
        result = owner.invoke(argv, label, until, neutral_environment(root))
        require(result["returncode"] == 0 and not result["timed_out"]
                and result["direct_child_reaped"] and not result["remaining"],
                "readonly_command_not_complete")
        raw, _ = evidence.checked_bytes(owner.private / (result["private_capture_label"] + ".stdout"),
                                         64 * 1024, until, owner=os.getuid())
        return raw
    return run


def make_fixture(native, cli, bm, evidence, binding, verified, prepared):
    Owned = owner_class(cli)

    class PhaseB(native.Fixture):
        def __init__(self):
            super().__init__(binding.server, binding.work, prepared)
            self.binding = binding
            self.verified = verified
            self.owner = Owned(self.root)
            self.action_until = 0
            self.action_name = None
            self.actions = []
            self.cli_cases = []
            self.cli_intents = []
            self.cli_inflight = None
            self.operation_inflight = None
            self.last_exchange = None
            self.nodes = {}
            self.seed_owned = None
            self.spawn_counts = {}
            self.cold_results = []
            self.h2_results = []
            self.h2_intents = []
            self.h2_state_unchanged = False
            self.secret_values = []
            self.checks = []
            self.failures = []
            self.generation = 0
            self.setup_complete = False
            self.generated_fences = {}
            self.boundary_known = True
            self.audit_postmortem = None
            self.reference_startup_scope = "normal_v5_seed_then_normal_native_v6_raft_and_formal_activate"

        def interrupted(self, signum, frame):
            if self.owner.creating_child:
                return self.owner.interrupted(signum, frame)
            return super().interrupted(signum, frame)

        def deadline(self) -> int:
            bm.remaining(self.action_until)
            return self.action_until

        @contextmanager
        def action(self, name: str):
            require(self.action_name is None, "nested_action_not_allowed")
            self.action_name = name
            self.action_until = time.monotonic_ns() + 300_000_000_000
            started = time.monotonic_ns()
            record = {"action": name, "original_action_seconds": 300,
                      "deadline_monotonic_ns": self.action_until, "started_unix_ns": time.time_ns()}
            try:
                self.binding.quick_fence(self.verified)
                yield
                self.deadline()
                record["completed"] = True
            except BaseException as error:
                # Reference setup parses mutation replies outside request().
                # A malformed successful init/unseal/KV reply can raise before
                # check() sees a boolean. Keep that mutation boundary unknown.
                exchange = self.last_exchange
                if (exchange and exchange["method"] not in ("GET", "HEAD")
                        and self.seq > exchange["sequence_before"]
                        and exchange.get("status") not in (400, 403)):
                    self.outcome_unknown = True
                    self.boundary_known = False
                record["completed"] = False
                record["failure_code"] = fixed_error(error)
                record["outcome_unknown"] = self.outcome_unknown
                raise
            finally:
                record["elapsed_ms"] = (time.monotonic_ns() - started) / 1e6
                self.actions.append(record)
                self.action_name = None

        def check(self, name: str, ok: bool) -> None:
            self.checks.append({"name": name, "passed": bool(ok)})
            if not ok:
                if self.operation_inflight is not None:
                    self.outcome_unknown = True
                    self.boundary_known = False
                elif self.last_exchange and self.last_exchange["method"] not in ("GET", "HEAD"):
                    if self.last_exchange.get("status") not in (400, 403):
                        self.outcome_unknown = True
                        self.boundary_known = False
                raise Failure(name)

        def mutation_allowed(self) -> None:
            self.deadline()
            require(not self.outcome_unknown and self.boundary_known
                    and self.cli_inflight is None and self.operation_inflight is None,
                    "unknown_boundary_forbids_new_mutation_or_restart")

        def request(self, node, method, path, label, **options):
            self.deadline()
            if method not in ("GET", "HEAD"):
                require(not self.outcome_unknown and self.boundary_known
                        and self.cli_inflight is None, "unknown_boundary_forbids_http_mutation")
            requested_parent = options.pop("parent_deadline_ns", None)
            until = self.action_until if requested_parent is None else min(self.action_until, requested_parent)
            self.last_exchange = {"node": node, "method": method, "label": label,
                                  "status": None, "sequence_before": self.seq}
            before = self.seq
            try:
                observation, body = super().request(node, method, path, label,
                                                     parent_deadline_ns=until, **options)
                self.last_exchange["status"] = observation.get("status")
                self.deadline()
                return observation, body
            except BaseException:
                terminal = next((item for item in reversed(self.observations)
                                 if item.get("sequence") == self.seq), None)
                if self.seq > before and (terminal is None or terminal.get("outcome_unknown")):
                    self.outcome_unknown = True
                    self.boundary_known = False
                raise

        def start_owned_child(self, collection: list, *args, **options):
            self.deadline()
            require(len(args) == 1 and type(args[0]) is list, "exact_http_child_argv")
            argv = args[0]
            require(len(argv) == 4 and argv[:3] == [
                sys.executable, str(Path(native.__file__).resolve()), "--child-request"
            ], "only_original_http_child_entry")
            spec_path = Path(argv[3])
            require(spec_path.parent == self.private and spec_path.name.endswith(".spec.json"),
                    "owned_http_child_spec_path")
            raw, _ = evidence.checked_bytes(spec_path, 64 * 1024, self.action_until, owner=os.getuid())
            spec = evidence.decode_json(raw)
            until = spec["deadline_monotonic_ns"]
            require(type(until) is int and until <= self.action_until, "http_original_parent_deadline")
            process = self.owner.start_child(argv, until=until, **options)
            captured = self.owner.children[-1][1]
            collection.append((process, captured))
            return process

        def openssl(self, args: list[str], label: str) -> None:
            self.mutation_allowed()
            until = min(self.deadline(), time.monotonic_ns() + 15_000_000_000)
            result = self.owner.invoke(["/usr/bin/openssl", *args], "tls-" + label, until,
                                       neutral_environment(self.root))
            require(result["returncode"] == 0 and not result["timed_out"]
                    and result["direct_child_reaped"] and not result["remaining"],
                    "owned_tls_generation_failed")

        def spawn(self, node: int, *, native: bool):
            self.mutation_allowed()
            directory = self.root / ("node%d" % node)
            kind = "native" if native else "seed"
            key = (node, kind)
            attempt = self.spawn_counts.get(key, 0)
            self.spawn_counts[key] = attempt + 1
            argv = [str(self.binary), "--config", str(directory / ("server-%s.json" % kind))]
            if native:
                argv.extend(["--ha-config", str(directory / "ha.json")])
            require("--native-v6-isolated-fixture" not in argv, "fixture_entry_forbidden")
            until = min(self.deadline(), time.monotonic_ns() + 15_000_000_000)
            out_path = directory / ("%s-start%d.stdout.private.log" % (kind, attempt))
            err_path = directory / ("%s-start%d.stderr.private.log" % (kind, attempt))
            with out_path.open("xb") as out, err_path.open("xb") as err:
                process = self.owner.start_child(
                    argv, until=until, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    start_new_session=True, cwd=self.root,
                    env={"PATH": "/usr/bin:/bin", "HOME": str(directory), "LANG": "C", "LC_ALL": "C"})
                captured = self.owner.children[-1][1]
                self.procs.append((process, captured))
            require(captured is not None, "server_identity_missing")
            if native:
                self.nodes[node] = (process, captured)
            else:
                require(self.seed_owned is None and node == 1, "single_fresh_seed_process")
                self.seed_owned = (process, captured)
            write_json(directory / ("%s-start%d.identity.public.json" % (kind, attempt)), captured)
            return process, captured

        def generated_fence(self) -> None:
            self.deadline()
            for value, original in self.generated_fences.items():
                _, current = evidence.checked_bytes(Path(value), 128 * 1024,
                                                      self.deadline(), owner=os.getuid())
                require(current == original, "owned_config_or_credential_source_changed")

        def node_fence(self) -> list[dict]:
            self.deadline()
            self.generated_fence()
            results = []
            for node in (1, 2, 3):
                process, captured = self.nodes[node]
                current = cli.process_identity(process.pid)
                require(process.poll() is None and current is not None
                        and current["start_ticks"] == captured["start_ticks"]
                        and current["pgid"] == process.pid and current["ppid"] == os.getpid()
                        and current["exe"] == str(self.binary), "live_owned_node_identity")
                results.append({"node": node, "pid": process.pid, "start_ticks": current["start_ticks"],
                                "pgid": current["pgid"], "same_executable": True})
            return results

        def collect_secrets(self) -> None:
            self.deadline()
            if not self.created_root:
                return
            values = []
            bootstrap_path = self.private / "bootstrap.json"
            if bootstrap_path.exists():
                raw, _ = evidence.checked_bytes(bootstrap_path, 64 * 1024, self.action_until, owner=os.getuid())
                bootstrap = evidence.decode_json(raw)
                token = bootstrap.get("root_token")
                if isinstance(token, str) and token:
                    values.append(token.encode())
                for name in ("keys", "keys_base64", "recovery_keys", "recovery_keys_base64"):
                    for value in bootstrap.get(name, []):
                        if isinstance(value, str) and value:
                            values.append(value.encode())
                            if name.endswith("base64"):
                                try:
                                    import base64
                                    decoded = base64.b64decode(value, validate=True)
                                    if decoded:
                                        values.append(decoded)
                                except ValueError:
                                    pass
                            elif re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
                                values.append(bytes.fromhex(value))
            fixed = [self.root / "ca.key"]
            for node in (1, 2, 3):
                fixed.extend([self.root / ("node%d" % node) / "tls.key",
                              self.root / ("node%d" % node) / "replication.key"])
            for path in fixed:
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                raw, _ = evidence.checked_bytes(path, 64 * 1024, self.action_until, owner=os.getuid())
                values.append(raw)
            self.secret_values = list(dict.fromkeys(values))

        def stop_fixture_owned_once(self, process, captured, *, stopper=None) -> dict:
            try:
                return self.owner.stop_once(process, captured, stopper=stopper, propagate=True)
            except BaseException:
                self.outcome_unknown = True
                self.boundary_known = False
                raise

        def setup_phase(self) -> None:
            with self.action("normal_native_setup"):
                original_setup = native.Fixture.setup
                original_stop = native.stop_owned
                def stop_seed_once(process, captured):
                    require(self.seed_owned is not None and process is self.seed_owned[0]
                            and captured == self.seed_owned[1], "reference_stop_is_exact_owned_seed")
                    return self.stop_fixture_owned_once(process, captured, stopper=original_stop)
                # Preserve the exact recovered setup bytecode/defaults/closure.
                # Only its one stop symbol is routed into the shared budget.
                # The reference module itself and every other global are untouched.
                setup_globals = dict(original_setup.__globals__)
                require(setup_globals.get("stop_owned") is original_stop,
                        "reference_original_stop_callable")
                setup_globals["stop_owned"] = stop_seed_once
                require(all(setup_globals[key] is value for key, value in original_setup.__globals__.items()
                            if key != "stop_owned"), "reference_setup_other_globals_unchanged")
                setup = FunctionType(original_setup.__code__, setup_globals, original_setup.__name__,
                                     original_setup.__defaults__, original_setup.__closure__)
                setup.__kwdefaults__ = original_setup.__kwdefaults__
                setup(self)
                self.collect_secrets()
                self.node_fence()
                self.setup_complete = True
                configs = {}
                for node in (1, 2, 3):
                    directory = self.root / ("node%d" % node)
                    raw, fence = evidence.checked_bytes(directory / "server-native.json", 128 * 1024,
                                                          self.deadline(), owner=os.getuid())
                    server = evidence.decode_json(raw)
                    require(set(server["storage"]) == {"native_v6_raft"}
                            and "native_v6_file" not in server["storage"], "actual_formal_native_raft_config")
                    ha_raw, ha_fence = evidence.checked_bytes(directory / "ha.json", 128 * 1024,
                                                               self.deadline(), owner=os.getuid())
                    ha = evidence.decode_json(ha_raw)
                    require(ha["peer_timeout_ms"] == 1500 and ha["forward_timeout_ms"] == 8000
                            and ha["max_inflight"] == 32
                            and ha["node_id"] == node, "original_ha_budgets")
                    configs[str(node)] = {"server_sha256": fence["sha256"], "ha_sha256": ha_fence["sha256"]}
                self.config_pins = configs
                generated = [self.root / "ca.crt", self.root / "ca.key", self.private / "bootstrap.json"]
                for node in (1, 2, 3):
                    directory = self.root / ("node%d" % node)
                    generated.extend(directory / name for name in
                                     ("server-native.json", "ha.json", "ca.crt",
                                      "tls.crt", "tls.key", "replication.key"))
                for path in generated:
                    _, fence = evidence.checked_bytes(path, 128 * 1024,
                                                        self.deadline(), owner=os.getuid())
                    self.generated_fences[str(path)] = fence
                self.initial_state = self.state_view("initial-two-version-state")
                for node in (1, 2, 3):
                    values = self.initial_state["nodes"][str(node)]
                    for version in (1, 2):
                        self.check("initial_node%d_version%d_value" % (node, version),
                                   values["versions"][str(version)]["data"] ==
                                   {"marker": "normal33-wire-seed-%d" % version})
                    self.check("initial_node%d_current_version2" % node,
                               values["metadata"]["current_version"] == 2)
                    self.check("initial_node%d_version3_absent" % node, values["version3_status"] == 404)

        def read_json(self, node: int, route: str, label: str, expected: int = 200) -> dict:
            observation, raw = self.request(node, "GET", route, label)
            self.check(label + "_status", observation["status"] == expected)
            value = evidence.decode_json(raw)
            self.check(label + "_object", type(value) is dict)
            return value

        def state_view(self, label: str) -> dict:
            self.deadline()
            nodes = {}
            for node in (1, 2, 3):
                versions = {}
                for version in (1, 2):
                    body = self.read_json(node, "/v1/wire/data/seed?version=%d" % version,
                                          "%s-node%d-version%d" % (label, node, version))
                    value = body.get("data")
                    self.check(label + "_version_data_shape", type(value) is dict
                               and value.get("metadata", {}).get("version") == version)
                    versions[str(version)] = value
                metadata = self.read_json(node, "/v1/wire/metadata/seed",
                                          "%s-node%d-metadata" % (label, node)).get("data")
                self.check(label + "_metadata_shape", type(metadata) is dict)
                observation, raw = self.request(node, "GET", "/v1/wire/data/seed?version=3",
                                                "%s-node%d-version3" % (label, node))
                self.check(label + "_version3_bounded_status", observation["status"] in (200, 404))
                third = None
                if observation["status"] == 200:
                    third = evidence.decode_json(raw).get("data")
                    self.check(label + "_version3_shape", type(third) is dict
                               and third.get("metadata", {}).get("version") == 3)
                capacity = self.read_json(node, "/v1/sys/internal/capacity",
                                          "%s-node%d-capacity" % (label, node)).get("data", {})
                self.check(label + "_actual_native_v6", capacity.get("state_storage_format") == "heptabao-state-records-v6"
                           and capacity.get("native_kv2_reader_format") == 2)
                nodes[str(node)] = {"versions": versions, "metadata": metadata,
                                    "version3_status": observation["status"], "version3": third}
            canonical = nodes["1"]
            self.check(label + "_three_actual_nodes_same_data", all(value == canonical for value in nodes.values()))
            value = {"nodes": nodes}
            write_json(self.private / (label + ".state.private.json"), value)
            write_json(self.root / (label + ".state.public.json"), {
                "label": label, "all_nodes_equal": True,
                "state_sha256": sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()),
                "versions": [1, 2], "current_version": canonical["metadata"]["current_version"],
                "version3_status": canonical["version3_status"], "actual_api_readback": True,
            })
            self.deadline()
            return value

        def audit_window(self, before: dict) -> dict:
            after = evidence.capture_audits(self.root, self.deadline())
            return evidence.audit_delta(before, after, self.deadline())

        def one_audit_pair(self, before: dict, target: int, label: str) -> dict:
            audit = self.audit_window(before)
            # Keep the recovered audit parser byte-identical; describe this
            # new request window explicitly instead of adopting its old label.
            audit["reference_association_scope"] = audit.pop("association_scope")
            audit["association_scope"] = "single_owned_" + label + "_window_without_other_controller_http"
            pairs = audit["pairs"]
            self.check(label + "_one_actual_server_pair",
                       audit["complete_known_request_response_pairs"]
                       and not audit["unexpected_event_kind"]
                       and not audit["historical_delivery_veto_observed"]
                       and audit["request_count"] == len(pairs) == 1
                       and pairs[0]["node"] == target and pairs[0]["kind"] == "request"
                       and pairs[0]["status"] == 200)
            return audit

        def h1_control(self) -> None:
            self.mutation_allowed()
            roles = self.roles("H01-before")
            target = roles["actual_leader"]
            before = evidence.capture_audits(self.root, self.deadline())
            self.operation_inflight = {"kind": "H1_archive_control", "case": "H01"}
            self.boundary_known = False
            record = {"case": "H01", "target_node": target, "outcome_unknown": True}
            try:
                observation, raw = self.request(target, "GET", SNAPSHOT_ROUTE,
                                                "H01-leader-normal-h1-snapshot")
                self.check("H01_actual_complete_200", observation["status"] == 200
                           and observation["response_complete"]
                           and not observation["outcome_unknown"])
                self.check("H01_selected_small_body_bound", len(raw) <= H2_BODY_LIMIT)
                path = self.private / "H01-h1.snapshot"
                write_new(path, raw)
                archive, _ = evidence.archive_observation(path, self.deadline())
                self.check("H01_real_native_archive", archive["archive_valid"])
                record.update(http_observation=observation, archive=archive,
                              audit=self.one_audit_pair(before, target, "H01_h1"))
                record["after_nodes"] = self.node_fence()
                record["qualified"] = True
                record["outcome_unknown"] = False
                self.operation_inflight = None
                self.boundary_known = True
            except BaseException as error:
                self.outcome_unknown = True
                self.boundary_known = False
                record["failure_code"] = fixed_error(error)
                raise
            finally:
                self.h2_results.append(record)
                write_json(self.root / "cases" / "H01.outcome.public.json", record)

        def h2_private_spec(self, target: int, operation: int, until: int) -> tuple[bytes, str]:
            self.deadline()
            raw, _ = evidence.checked_bytes(self.private / "bootstrap.json", 64 * 1024,
                                             self.deadline(), owner=os.getuid())
            bootstrap = evidence.decode_json(raw)
            token = bootstrap["root_token"].encode("ascii")
            require(16 <= len(token) <= 16 * 1024 and all(33 <= byte <= 126 for byte in token),
                    "h2_private_token_shape")
            ca_raw, _ = evidence.checked_bytes(self.root / "ca.crt", 16 * 1024,
                                                self.deadline(), owner=os.getuid())
            leaf_raw, _ = evidence.checked_bytes(self.root / ("node%d" % target) / "tls.crt",
                                                  16 * 1024, self.deadline(), owner=os.getuid())
            def der(value: bytes) -> bytes:
                text = value.decode("ascii")
                require(text.count("-----BEGIN CERTIFICATE-----") == 1
                        and text.count("-----END CERTIFICATE-----") == 1, "one_owned_tls_certificate")
                return ssl.PEM_cert_to_DER_cert(text)
            ca, leaf = der(ca_raw), der(leaf_raw)
            require(128 <= len(ca) <= 16 * 1024 and 0 < until < 2 ** 64
                    and target in (1, 2, 3) and operation in (1, 2), "h2_closed_spec_values")
            expected_leaf = sha(leaf)
            spec = (b"HBH2QA01" + struct.pack(">QHBI", until, bm.API_PORTS[target],
                                            operation, len(ca)) + ca
                    + bytes.fromhex(expected_leaf) + struct.pack(">H", len(token)) + token)
            require(len(spec) <= 64 * 1024, "h2_private_spec_bound")
            return spec, expected_leaf

        def run_h2_once(self, label: str, spec: bytes, until: int) -> tuple[dict, bytes, dict]:
            require(self.operation_inflight is not None, "h2_pending_before_dispatch")
            input_path = self.private / (label + ".stdin.private")
            body_path = self.private / (label + ".body.private")
            meta_path = self.private / (label + ".report.private.json")
            write_new(input_path, spec)
            before = input_path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                    "h2_input_custody")
            input_fd = os.open(input_path, os.O_RDONLY | os.O_NOFOLLOW)
            process = None
            timed_out = False
            started = time.monotonic_ns()
            try:
                require(stable_identity(os.fstat(input_fd)) == stable_identity(before),
                        "h2_input_same_fd")
                with body_path.open("xb") as output, meta_path.open("xb") as error:
                    cli.remaining(until)
                    argv = [str(self.binding.h2_executable), "--spec-sha256", sha(spec)]
                    process = self.owner.start_child(
                        argv, until=until, cwd=self.root, stdin=input_fd, stdout=output,
                        stderr=error, start_new_session=True, env=neutral_environment(self.root))
                    try:
                        process.wait(timeout=cli.remaining(until))
                    except (subprocess.TimeoutExpired, cli.Refused):
                        timed_out = True
                        captured = self.owner.children[-1][1]
                        current = cli.process_identity(process.pid)
                        require(captured is not None and (current is None
                                or current["start_ticks"] == captured["start_ticks"]),
                                "h2_child_identity_before_timeout_kill")
                        if process.poll() is None:
                            require(current is not None and current["pgid"] == process.pid
                                    and current["ppid"] == os.getpid(), "h2_live_owned_group_before_kill")
                            os.killpg(process.pid, signal.SIGKILL)
                        # Preserve the reference's independent timeout-stage wait;
                        # final explicit stop uses the single original 5+5 ledger.
                        process.wait(timeout=5)
                    output.flush()
                    error.flush()
                    os.fsync(output.fileno())
                    os.fsync(error.fileno())
                require(stable_identity(os.fstat(input_fd)) == stable_identity(before)
                        and stable_identity(input_path.lstat()) == stable_identity(before),
                        "h2_private_input_unchanged")
            finally:
                os.close(input_fd)
            completed = time.monotonic_ns()
            remaining = cli.group_members(process.pid)
            process_record = {
                "pid": process.pid, "returncode": process.returncode,
                "direct_child_reaped": process.returncode is not None, "remaining": remaining,
                "timed_out": timed_out, "request_deadline_monotonic_ns": until,
                "completed_monotonic_ns": completed, "elapsed_ns": completed - started,
                "completed_before_original_deadline": completed < until,
                "private_input_fd_closed": True, "private_input_unchanged": True,
            }
            require(process.returncode == 0 and not timed_out
                    and process.returncode is not None and not remaining and completed < until,
                    "h2_child_terminal_not_qualified")
            raw, meta_fence = evidence.checked_bytes(meta_path, 64 * 1024,
                                                       self.deadline(), owner=os.getuid())
            body, body_fence = evidence.checked_bytes(body_path, H2_BODY_LIMIT,
                                                       self.deadline(), owner=os.getuid())
            require(not any(value in raw for value in evidence.secret_variants(self.secret_values)),
                    "h2_report_contains_fixture_secret_variant")
            result = evidence.decode_json(raw)
            require(type(result) is dict and set(result) == CLIENT_REPORT_FIELDS,
                    "h2_exact_client_report")
            process_record["private_report"] = meta_fence
            process_record["private_body"] = body_fence
            return process_record, body, result

        def h2_case(self, case: str, operation: int) -> None:
            self.mutation_allowed()
            self.binding.quick_fence(self.verified)
            before_nodes = self.node_fence()
            roles = self.roles(case + "-before")
            target = roles["actual_leader"]
            before_audit = evidence.capture_audits(self.root, self.deadline())
            until = min(self.deadline(), time.monotonic_ns() + 15_000_000_000)
            spec, expected_leaf = self.h2_private_spec(target, operation, until)
            path = "/v1/wire/data/seed?version=2" if operation == 1 else SNAPSHOT_ROUTE
            intent = {
                "case": case, "target_node": target, "actual_leader_before": target,
                "method": "GET", "path": path, "loopback_port": bm.API_PORTS[target],
                "server_name": "localhost", "offered_alpn": ["h2"],
                "expected_peer_leaf_sha256": expected_leaf,
                "private_spec_sha256": sha(spec), "private_spec_bytes": len(spec),
                "client_seconds": 15, "deadline_monotonic_ns": until,
                "action_deadline_monotonic_ns": self.action_until,
                "client_sha256": self.binding.h2_client["executable"]["sha256"],
                "client_connections_allowed": 1, "client_requests_allowed": 1,
                "client_reconnects_allowed": 0, "client_retries_allowed": 0,
                "redirects_allowed": 0, "before_nodes": before_nodes,
            }
            write_json(self.root / "cases" / (case + ".intent.public.json"), intent)
            self.h2_intents.append(case)
            self.operation_inflight = {"kind": "h2_native_request", "case": case}
            self.boundary_known = False
            record = {"case": case, "intent": intent, "outcome_unknown": True}
            try:
                process, body, client = self.run_h2_once(case, spec, until)
                record["process"] = process
                require(client["schema"] == "heptabao.h2-single-request-client.v1"
                        and client["candidate_commit"] == bm.COMMIT
                        and client["candidate_tree"] == bm.TREE
                        and client["operation"] == operation
                        and client["deadline_monotonic_ns"] == str(until)
                        and client["stage"] == "complete" and client["error_code"] is None,
                        "h2_exact_bound_client_terminal")
                require(client["tls_chain_and_hostname_verified"] is True
                        and client["selected_alpn_h2"] is True
                        and client["tls_version"] in ("TLS1.2", "TLS1.3")
                        and client["peer_leaf_sha256"] == expected_leaf,
                        "h2_actual_tls_identity_and_alpn")
                require(client["connections_started"] == client["send_request_calls"] == 1
                        and client["request_dispatched"] is True and client["stream_id"] == 1
                        and client["client_reconnects"] == client["client_request_retries"]
                        == client["redirects_followed"] == 0, "h2_single_actual_request")
                require(client["response_status"] == 200
                        and client["response_complete"] is True
                        and client["data_none_observed"] is True
                        and client["trailers_completed"] is True
                        and client["trailers_empty"] is True and client["recv_end_stream"] is True
                        and client["content_length"] == client["body_bytes"] == len(body)
                        and client["body_sha256"] == sha(body),
                        "h2_actual_complete_200_eos_and_exact_content_length")
                require(client["connection_task_joined"] is True
                        and client["completed_before_original_deadline"] is True
                        and client["outcome_unknown"] is False
                        and client["trace_enabled"] is False
                        and client["raw_error_messages_emitted"] is False
                        and client["product_or_official_cli_qualification"] is False,
                        "h2_owned_connection_completed")
                record["client"] = client
                record["audit"] = self.one_audit_pair(before_audit, target, case + "_h2")
                if operation == 1:
                    require(client["content_type"] == "application/json", "h2_kv2_media_type")
                    data = evidence.decode_json(body).get("data")
                    require(data == self.initial_state["nodes"][str(target)]["versions"]["2"]
                            and data["metadata"]["version"] == 2
                            and data["data"] == {"marker": "normal33-wire-seed-2"},
                            "h2_actual_kv2_value_and_version")
                    record["actual_kv2_exact_version_and_value"] = True
                else:
                    require(client["content_type"] == "application/gzip", "h2_native_archive_media_type")
                    archive, _ = evidence.archive_observation(
                        self.private / (case + ".body.private"), self.deadline())
                    require(archive["archive_valid"], "h2_real_native_archive_complete")
                    record["archive"] = archive
                record["after_nodes"] = self.node_fence()
                record["qualified"] = True
                record["outcome_unknown"] = False
                self.operation_inflight = None
                self.boundary_known = True
            except BaseException as error:
                self.outcome_unknown = True
                self.boundary_known = False
                record["failure_code"] = fixed_error(error)
                raise
            finally:
                record["terminal_unix_ns"] = time.time_ns()
                self.h2_results.append(record)
                write_json(self.root / "cases" / (case + ".outcome.public.json"), record)

        def execute(self) -> None:
            self.setup_phase()
            (self.root / "cases").mkdir(mode=0o700)
            with self.action("H01_normal_h1_leader_archive_control"):
                self.h1_control()
            with self.action("H02_actual_h2_native_kv2_version2"):
                self.h2_case("H02", 1)
            with self.action("H03_actual_h2_leader_native_archive"):
                self.h2_case("H03", 2)
                after = self.state_view("h2-gate-all-node-after")
                self.check("h2_gate_two_versions_all_nodes_unchanged", after == self.initial_state)
                self.h2_state_unchanged = True

        def finish(self, failure: str | None) -> int:
            # Once a signal/failure ends the action, only read-only observations
            # and cleanup are permitted. No service respawn or upload occurs here.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            final_until = time.monotonic_ns() + 300_000_000_000
            final_errors = []
            self.action_until = final_until
            if self.created_root:
                try:
                    self.collect_secrets()
                    if self.setup_complete:
                        capture = evidence.capture_audits(self.root, final_until)
                        self.audit_postmortem = {
                            str(node): {"file": item["file"], "records": len(item["records"])}
                            for node, item in capture.items()
                        }
                except BaseException as error:
                    final_errors.append({"stage": "readonly_final_evidence", "code": fixed_error(error)})
                    self.outcome_unknown = True
            cleanup = self.owner.cleanup()
            clean = all(item.get("owned_stopped")
                                         and item.get("direct_child_reaped") for item in cleanup)
            after = None
            try:
                after = binding.verify(readonly_runner(self.owner, self.root, evidence), final_until)
                require(after == self.verified, "input_fence_changed_after_run")
            except BaseException as error:
                final_errors.append({"stage": "input_after", "code": fixed_error(error)})
            # Include the read-only after-fence Git children in final cleanup too.
            cleanup = self.owner.cleanup()
            clean = all(item.get("owned_stopped")
                                         and item.get("direct_child_reaped") for item in cleanup)
            incomplete_http = sorted(set(range(1, self.seq + 1)) -
                                     {item["sequence"] for item in self.observations})
            incomplete_h2 = sorted(set(self.h2_intents) -
                                   {item["case"] for item in self.h2_results})
            unknown = (self.outcome_unknown or bool(incomplete_http) or bool(incomplete_h2)
                       or self.operation_inflight is not None
                       or any(item.get("outcome_unknown") for item in self.h2_results)
                       or any(item.get("outcome_unknown") for item in self.observations)
                       or not clean)
            final_observations_completed = time.monotonic_ns()
            if final_observations_completed >= final_until:
                final_errors.append({"stage": "final_deadline", "code": "original_final_deadline"})
            case_map = {item["case"]: item for item in self.h2_results}
            qualifications = {case: bool(case_map.get(case, {}).get("qualified"))
                              for case in ("H01", "H02", "H03")}
            complete = (list(case_map) == ["H01", "H02", "H03"]
                        and self.h2_intents == ["H02", "H03"]
                        and self.h2_state_unchanged and not unknown
                        and not final_errors and failure is None)
            passed = complete and all(qualifications.values()) and all(item["passed"] for item in self.checks)
            status = "passed" if passed else "failed"
            report = {
                "schema": SCHEMA, "status": status, "failure_code": failure,
                "final_errors": final_errors, "candidate_commit": bm.COMMIT, "candidate_tree": bm.TREE,
                "input_binding_sha256": binding.sha256, "prepared": prepared,
                "verified_inputs_before": self.verified, "verified_inputs_after": after,
                "actions": self.actions, "h2_gate_cases": self.h2_results,
                "case_qualifications": qualifications, "all_node_state_unchanged": self.h2_state_unchanged,
                "checks": self.checks, "checks_total": len(self.checks),
                "checks_passed": sum(item["passed"] for item in self.checks),
                "checks_are_dynamic_invariants_not_full_replacement_denominator": True,
                "http_intents": self.seq, "http_outcomes": len(self.observations),
                "incomplete_http_intents": incomplete_http, "incomplete_h2_intents": incomplete_h2,
                "h2_client_requests": len(self.h2_intents),
                "outcome_unknown": bool(unknown), "all_owned_stopped": bool(clean),
                "owned_cleanup": cleanup, "child_provenance": self.owner.child_provenance,
                "child_exec_visibility": self.owner.child_exec_visibility,
                "final_all_node_audit_observation": self.audit_postmortem,
                "reference_startup_scope": self.reference_startup_scope,
                "normal_default_features": True, "fixture_feature_startup": False,
                "production_changed": False, "provider_requests": 0, "j3160_requests": 0,
                "physical_hosts": 1, "process_nodes": 3,
                "actual_negotiated_h2_native_path_only": True, "h2_body_limit_bytes": H2_BODY_LIMIT,
                "official_cli_commands": 0, "restore_uploads": 0, "post_restore_cold_starts": 0,
                "official271_cli_or_archive_interoperability_qualified": False,
                "large_34MiB_transport_qualified": False,
                "audit_is_not_client_response_framing_proof": True,
                "client_exit_zero_is_not_product_success": True,
                "no_late_reset_or_whole_bidirectional_session_claim": True,
                "controller_request_or_restore_replays": 0, "full_replacement_qualification": False,
                "original_44_existing_7_new_9_denominators_unchanged": True,
                "final_deadline_monotonic_ns": final_until,
                "final_observations_completed_monotonic_ns": final_observations_completed,
                "terminal_unix_ns": time.time_ns(),
            }
            try:
                encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
                variants = evidence.secret_variants(self.secret_values)
                require(not any(value in encoded for value in variants), "fixture_secret_in_final_report")
                write_new(self.root / "result.public.json", encoded)
                public_files = sorted(self.root.rglob("*.public.json"))
                # Enumeration is confined to this newly created owned fixture.
                scan = evidence.public_literal_scan(public_files, self.secret_values, final_until)
                write_json(self.root / "public-literal-scan.public.json", scan)
                print(json.dumps({
                    "status": status, "result": str(self.root / "result.public.json"),
                    "result_sha256": sha(encoded), "case_qualifications": qualifications,
                    "outcome_unknown": bool(unknown), "all_owned_stopped": bool(clean),
                    "literal_scan_hits": 0, "full_replacement_qualification": False,
                }, sort_keys=True), flush=True)
            except BaseException as error:
                # Do not print the rejected public bytes or any raw exception.
                print(json.dumps({"status": "public_evidence_withheld", "error_type": type(error).__name__,
                                  "outcome_unknown": bool(unknown), "all_owned_stopped": bool(clean)},
                                 sort_keys=True), flush=True)
                return 1
            return 0 if passed and time.monotonic_ns() < final_until else 1
    return PhaseB()


def prepare(binding, bm, evidence, cli) -> int:
    binding.fresh_path(binding.prepare)
    binding.fresh_path(binding.work)
    binding.prepare.mkdir(mode=0o700)
    (binding.prepare / "private").mkdir(mode=0o700)
    cli.ROOT = binding.prepare
    owner = owner_class(cli)(binding.prepare)
    signal.signal(signal.SIGTERM, owner.interrupted)
    signal.signal(signal.SIGINT, owner.interrupted)
    until = time.monotonic_ns() + 300_000_000_000
    inputs = None
    failure = None
    try:
        inputs = binding.verify(readonly_runner(owner, binding.prepare, evidence), until)
        binding.check_ports()
        binding.fresh_path(binding.work)
        bm.remaining(until)
    except BaseException as error:
        failure = fixed_error(error)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup = owner.cleanup()
    clean = all(item.get("owned_stopped") and item.get("direct_child_reaped")
                                  for item in cleanup)
    completed_after_cleanup = time.monotonic_ns()
    if completed_after_cleanup >= until and failure is None:
        failure = "original_prepare_deadline"
    report = {
        "schema": "heptabao.normal-native-h2-gate.prepare.v1",
        "status": "passed" if failure is None and clean else "failed",
        "binding_sha256": binding.sha256, "inputs": inputs, "failure_code": failure,
        "owned_cleanup": cleanup, "all_owned_stopped": clean,
        "child_provenance": owner.child_provenance, "child_exec_visibility": owner.child_exec_visibility,
        "runtime_started": False, "server_processes": 0, "cli_snapshot_commands": 0,
        "production_changed": False, "readiness_is_not_runtime_qualification": True,
        "deadline_monotonic_ns": until,
        "completed_after_cleanup_monotonic_ns": completed_after_cleanup,
        "terminal_unix_ns": time.time_ns(),
    }
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    write_new(binding.prepare / "result.public.json", raw)
    print(json.dumps({"status": report["status"], "result": str(binding.prepare / "result.public.json"),
                      "result_sha256": sha(raw), "runtime_started": False,
                      "all_owned_stopped": clean}, sort_keys=True), flush=True)
    return 0 if report["status"] == "passed" and time.monotonic_ns() < until else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--binding-sha256", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare-only", action="store_true")
    modes.add_argument("--run", action="store_true")
    parser.add_argument("--prepare-result-sha256")
    args = parser.parse_args()
    os.umask(0o077)
    bm, evidence, native, cli = bootstrap_modules(args.binding, args.binding_sha256)
    binding = bm.Binding(args.binding, args.binding_sha256, time.monotonic_ns() + 300_000_000_000)
    if args.prepare_only:
        require(args.prepare_result_sha256 is None, "prepare_has_no_prior_result")
        return prepare(binding, bm, evidence, cli)
    require(args.prepare_result_sha256 is not None, "reviewed_prepare_result_required")
    until = time.monotonic_ns() + 300_000_000_000
    raw, _ = bm.read_file(binding.prepare / "result.public.json", 4 * 1024 * 1024, until)
    require(sha(raw) == args.prepare_result_sha256, "exact_prior_prepare_result")
    prepared = bm.parse(raw)
    require(prepared["schema"] == "heptabao.normal-native-h2-gate.prepare.v1"
            and prepared["status"] == "passed" and prepared["all_owned_stopped"] is True
            and prepared["binding_sha256"] == binding.sha256
            and prepared["runtime_started"] is False, "prior_prepare_admission")
    binding.fresh_path(binding.work)
    binding.quick_fence(prepared["inputs"])
    binding.check_ports()
    cli.ROOT = binding.work
    # The imported native HTTP child keeps its original fixed loopback ports,
    # 15 s framing checks and no-redirect transport. Old artifact globals are
    # never invoked; only the exact source methods named in the scope are used.
    require(native.API_PORTS == bm.API_PORTS and native.CLUSTER_PORTS == bm.RAFT_PORTS
            and native.HTTP_SECONDS == 15 and native.READINESS_SECONDS == 45
            and native.ELECTION_SECONDS == 60 and native.STABLE_LEADER_SECONDS == 2.2,
            "reference_original_time_and_port_contract")
    fixture = make_fixture(native, cli, bm, evidence, binding, prepared["inputs"], prepared)
    signal.signal(signal.SIGTERM, fixture.interrupted)
    signal.signal(signal.SIGINT, fixture.interrupted)
    failure = None
    try:
        fixture.execute()
    except BaseException as error:
        failure = fixed_error(error)
    finally:
        if fixture.created_root:
            return fixture.finish(failure)
    require(False, failure or "failed_before_owned_root")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed_before_live", "error_code": fixed_error(error),
                          "runtime_qualification": False}, sort_keys=True), flush=True)
        raise SystemExit(2) from None
