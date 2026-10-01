#!/usr/bin/env python3
"""Fixed 64 metadata PATCH CLI observations over two fresh owned TLS servers.

Requested command output and HTTP bodies stay in memory. Build source, QA
source, and executable Python CLI source have separate immutable identities.
The bounded operator supplies the original 120-second outer process limit.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error

from bao_http import BaoError, Client as TransportClient, SafeArgumentParser, private_read, private_write, private_write_text
from core_isolation import ScenarioFailure, file_hash
import official_openbao_launcher as launcher
from online_evidence import admit_output

ROOT = Path(__file__).resolve().parents[2]
VERSION = "2.7.0"
HTTP_SECONDS = 2
COMMAND_SECONDS = 10
OUTER_SECONDS = 120
CHECKSET_PATH = Path(__file__).with_name("kv_metadata_patch_cli_cases.json")
CHECKSET = json.loads(CHECKSET_PATH.read_text())
INTERFACES = tuple(CHECKSET["interfaces"])
REQUIRED_INTERFACE_CASES = tuple(CHECKSET["cases"])
if len(INTERFACES) != 4 or len(REQUIRED_INTERFACE_CASES) != 16 or len(set(REQUIRED_INTERFACE_CASES)) != 16:
    raise ValueError("fixed_checkset_invalid")
CLIENT_BUDGET_OBSERVATIONS = []


class Client(TransportClient):
    def __init__(self, address, ca_file, token, namespace="", timeout=HTTP_SECONDS, **options):
        if type(timeout) is not int or timeout != HTTP_SECONDS:
            raise ValueError("fixture_http_budget_changed")
        CLIENT_BUDGET_OBSERVATIONS.append(timeout)
        super().__init__(address, ca_file, token, namespace, timeout=timeout, **options)

    def request(self, *args, **kwargs):
        try:
            return super().request(*args, **kwargs)
        except BaoError as error:
            cause = error.__context__
            if str(error) == "transport_read_failed" and (
                    isinstance(cause, ssl.SSLCertVerificationError) or
                    isinstance(cause, urllib.error.URLError) and isinstance(cause.reason, ssl.SSLCertVerificationError)):
                # The official startup read poll catches BaoError; TLS rejection
                # must retain its exception category and fail immediately.
                raise cause
            raise


def bounded_native_instance(smoke, binary, root):
    class Instance(smoke.Instance):
        def stop(self):
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if getattr(self, "log", None) is not None:
                self.log.close()

        def call(self, method, path, body=None, *, token=None, namespace="", extra_headers=None):
            if namespace or extra_headers:
                raise ValueError("unexpected_fixture_option")
            try:
                response = Client(self.address, str(self.root / "ca.crt"),
                                  self.token or "synthetic-uninitialized-client").request(method, "/v1/" + path, body, token=token)
            except BaoError as error:
                cause = error.__context__
                if (method == "GET" and path == "sys/health" and str(error) == "transport_read_failed"
                        and isinstance(cause, (OSError, urllib.error.URLError))):
                    # Only the original startup readiness loop handles a
                    # temporarily unavailable read. Business calls never retry.
                    raise cause
                raise
            return response.status, response.body
    return Instance(binary, root)


def git_identity(root: Path) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
    return {"source_commit": git("rev-parse", "HEAD"), "source_tree": git("rev-parse", "HEAD^{tree}"),
            "source_dirty": bool(git("status", "--porcelain=v1", "--untracked-files=all"))}


def cli_identity(root: Path) -> dict:
    return {**git_identity(root), "files_sha256": {name: file_hash(root / name) for name in (
        "clients/python/heptabao/cli.py", "clients/python/heptabao/kv_cli.py", "clients/python/heptabao/transport.py")}}


def build_custody(binary: Path, receipt: Path, source: Path) -> dict:
    value = json.loads(private_read(receipt, 2 * 1024 * 1024))
    actual = git_identity(source)
    if (actual["source_dirty"] or value.get("schema") != "heptabao.immutable-runtime-build-custody.v1"
            or value.get("source_identity_before") != actual or value.get("source_identity_after") != actual
            or value.get("source_unchanged") is not True or value.get("exit") != 0
            or value.get("binary_sha256") != file_hash(binary)):
        raise ValueError("candidate_build_custody_mismatch")
    return {"source_identity": actual, "binary_sha256": file_hash(binary), "receipt_sha256": file_hash(receipt)}


def interface_complete(rows) -> bool:
    return (isinstance(rows, list) and tuple(row.get("case") for row in rows if isinstance(row, dict)) == REQUIRED_INTERFACE_CASES
            and len(rows) == 16 and all(isinstance(row, dict) and set(row) == {"case", "passed"}
                                       and row["passed"] is True for row in rows))


def all_interfaces_complete(interfaces) -> bool:
    return isinstance(interfaces, dict) and set(interfaces) == set(INTERFACES) and all(interface_complete(interfaces[name]) for name in INTERFACES)


def safe_errors(completed, protected) -> bool:
    return all(value not in completed.stderr and value not in completed.stdout for value in protected)


def invoke_patch(kind, instance, cli_root, binary, token_path, flags, path):
    if kind not in ("python", "bao"):
        raise ValueError("unexpected_cli_kind")
    token = private_read(token_path).decode("ascii").strip()
    environment = launcher.oracle_cli_environment(instance, token)
    environment.update({"PYTHONPATH": str(cli_root / "clients/python"), "PYTHONDONTWRITEBYTECODE": "1",
                        "BAO_CLIENT_TIMEOUT": "2s", "VAULT_CLIENT_TIMEOUT": "2s",
                        "BAO_DISABLE_REDIRECTS": "true", "VAULT_DISABLE_REDIRECTS": "true"})
    executable = [sys.executable, "-B", "-m", "heptabao", "kv"] if kind == "python" else [str(binary), "kv"]
    # Token files remain private inputs. Values, argv, environment and command
    # output are never placed in a report or reconstructed on an exception.
    return subprocess.run(executable + ["metadata", "patch", "-format=json", "-mount=cli-metadata"] + flags + [path],
                          cwd=cli_root, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=COMMAND_SECONDS, check=False)


def metadata_shape(value) -> bool:
    return (isinstance(value, dict) and type(value.get("current_version")) is int and value["current_version"] == 1
            and type(value.get("oldest_version")) is int and isinstance(value.get("versions"), dict)
            and set(value["versions"]) == {"1"} and isinstance(value["versions"]["1"], dict)
            and isinstance(value.get("custom_metadata"), dict)
            and all(isinstance(key, str) and isinstance(item, str) for key, item in value["custom_metadata"].items()))


def frontier_unchanged(before, after, data, expected_data) -> bool:
    return (metadata_shape(before) and metadata_shape(after) and isinstance(data, dict)
            and before["current_version"] == after["current_version"]
            and before["oldest_version"] == after["oldest_version"] and before["versions"] == after["versions"]
            and data.get("data") == expected_data and isinstance(data.get("metadata"), dict)
            and type(data["metadata"].get("version")) is int and data["metadata"]["version"] == 1)


def run_interface(kind, instance, cli_root, official_binary, rows):
    client = Client(instance["address"], instance["ca_file"], instance["token"])
    key = kind + "-item"
    metadata_path = "/v1/cli-metadata/metadata/" + key
    data_path = "/v1/cli-metadata/data/" + key
    expected_data = {"value": "synthetic-metadata-data-value"}
    custom = {"owner": "synthetic-before", "keep": "synthetic-preserved"}

    def call(method, path, payload=None, expected=200):
        response = client.request(method, path, payload)
        if response.status != expected:
            raise ScenarioFailure("metadata_patch_interface_setup_or_read_status")
        return response.body

    def check(case, condition):
        if case != REQUIRED_INTERFACE_CASES[len(rows)]:
            raise ScenarioFailure("metadata_patch_case_order_changed")
        rows.append({"case": case, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)

    def read_metadata():
        value = call("GET", metadata_path).get("data")
        if not metadata_shape(value):
            raise ScenarioFailure("metadata_patch_typed_read_required")
        return value

    call("POST", data_path, {"data": expected_data})
    call("POST", metadata_path, {"custom_metadata": custom}, expected=204)
    before = read_metadata()
    tokens = {"root": instance["token"]}
    for mode, capability in (("patch", "patch"), ("update", "update")):
        policy = "cli-metadata-" + kind + "-" + mode
        call("PUT", "/v1/sys/policies/acl/" + policy,
             {"policy": 'path "cli-metadata/metadata/' + key + '" { capabilities = ["' + capability + '"] }'}, expected=204)
        response = call("POST", "/v1/auth/token/create", {"policies": [policy], "no_default_policy": True, "ttl": "1h"})
        tokens[mode] = response.get("auth", {}).get("client_token")
        if not isinstance(tokens[mode], str) or not tokens[mode]:
            raise ScenarioFailure("metadata_patch_scoped_token_required")
    token_paths = {}
    for mode, token in tokens.items():
        path = Path(instance["root"]) / (kind + "-metadata-" + mode + ".token")
        private_write_text(path, token, replace=False)
        token_paths[mode] = path
    protected = tuple(value.encode() for value in (*tokens.values(), *expected_data.values(), *custom.values(),
                                                  "synthetic-next", "synthetic-added", "synthetic-acl", "synthetic-refused"))

    def command(mode, flags, item=key):
        return invoke_patch(kind, instance, cli_root, official_binary, token_paths[mode], flags, item)

    result = command("root", ["-custom-metadata=owner=synthetic-next"])
    check("merge_exit", result.returncode == 0)
    check("merge_safe_errors", safe_errors(result, protected))
    merged = read_metadata()
    check("merge_delta_applied_and_unmentioned_custom_key_preserved",
          merged["custom_metadata"] == {"owner": "synthetic-next", "keep": custom["keep"]})
    check("merge_data_version_and_history_unchanged", frontier_unchanged(before, merged, call("GET", data_path).get("data"), expected_data))

    result = command("root", ["-custom-metadata=added=synthetic-added", "-remove-custom-metadata=owner"])
    check("remove_exit", result.returncode == 0)
    check("remove_safe_errors", safe_errors(result, protected))
    removed = read_metadata()
    check("remove_key_absent_and_other_custom_keys_preserved",
          removed["custom_metadata"] == {"keep": custom["keep"], "added": "synthetic-added"})
    check("remove_data_version_and_history_unchanged", frontier_unchanged(before, removed, call("GET", data_path).get("data"), expected_data))

    result = command("patch", ["-custom-metadata=keep=synthetic-acl"])
    check("patch_only_acl_exit", result.returncode == 0)
    check("patch_only_acl_safe_errors", safe_errors(result, protected))
    patched = read_metadata()
    check("patch_only_acl_delta_applied", patched["custom_metadata"] == {"keep": "synthetic-acl", "added": "synthetic-added"})

    result = command("update", ["-custom-metadata=keep=synthetic-refused"])
    check("update_only_acl_refusal_exit", result.returncode == 2)
    check("update_only_acl_safe_errors", safe_errors(result, protected))
    denied = read_metadata()
    check("update_only_acl_refusal_has_no_effect", denied == patched and frontier_unchanged(
        before, denied, call("GET", data_path).get("data"), expected_data))

    result = command("root", ["-custom-metadata=owner=synthetic-next"], kind + "-missing")
    check("missing_entry_refusal_exit_and_safe_errors", result.returncode == 2 and safe_errors(result, protected))
    response = client.request("GET", "/v1/cli-metadata/metadata/" + kind + "-missing")
    check("missing_entry_remains_absent", response.status == 404)
    if not interface_complete(rows):
        raise ScenarioFailure("metadata_patch_interface_incomplete")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    for name in ("binary", "build-receipt", "candidate-source", "cli-source", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    binary, candidate_source, cli_root = (Path(value).resolve(strict=True) for value in
        (args.binary, args.candidate_source, args.cli_source))
    receipt = Path(args.build_receipt).absolute()
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before, cli_before = git_identity(ROOT), cli_identity(cli_root)
    if before["source_dirty"] or cli_before["source_dirty"]:
        raise ValueError("qa_or_cli_source_dirty")
    bound = build_custody(binary, receipt, candidate_source)
    official = Path(launcher.verify_inputs(version=VERSION))
    root = Path(tempfile.mkdtemp(prefix="kv-metadata-cli-", dir=output.parent)); root.chmod(0o700)
    report = {"schema": "heptabao.kv-metadata-patch-cli-live.v1", "profile": "kv-metadata-patch-cli270",
              "synthetic_only": True, "expected_checks": 64, "interfaces": {}, "status": "failed",
              "qa_source_before": before, "cli_source_before": cli_before, "candidate_build_custody": bound,
              "oracle_version": VERSION, "oracle_cli_sha256": file_hash(official), "runner_sha256": file_hash(Path(__file__)),
              "checkset_sha256": file_hash(CHECKSET_PATH), "http_seconds": HTTP_SECONDS,
              "command_seconds": COMMAND_SECONDS, "outer_seconds": OUTER_SECONDS, "started_at_unix": time.time(),
              "production_authority": False, "independent_qualification": False, "full_cli_compatibility": False,
              "requested_stdout_saved": False, "credentials_saved_in_report": False}
    oracle, native = None, None
    original_client = launcher.Client
    CLIENT_BUDGET_OBSERVATIONS.clear()
    launcher.Client = Client
    try:
        spec = importlib.util.spec_from_file_location("metadata_cli_smoke", ROOT / "qa/single-node/smoke.py")
        smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        native = bounded_native_instance(smoke, binary, root / "native")
        native.start()
        client = Client(native.address, str(native.root / "ca.crt"), "synthetic-uninitialized-client")
        response = client.request("POST", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if response.status != 200:
            raise ScenarioFailure("native_init")
        native.token = response.body["root_token"]
        if client.request("POST", "/v1/sys/unseal", {"key": response.body["keys_base64"][0]}).status != 200:
            raise ScenarioFailure("native_unseal")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        oracle = launcher.start_oracle(port, version=VERSION)
        oracle["token"] = private_read(oracle["token_file"]).decode("ascii").strip()
        report["oracle_identity"] = json.loads(private_read(oracle["identity_file"]))
        candidate = {"root": str(native.root), "address": native.address, "ca_file": str(native.root / "ca.crt"), "token": native.token}
        for side, instance in (("candidate", candidate), ("oracle", oracle)):
            client = Client(instance["address"], instance["ca_file"], instance["token"])
            if client.request("POST", "/v1/sys/mounts/cli-metadata", {"type": "kv", "options": {"version": "2"}}).status != 204:
                raise ScenarioFailure("metadata_patch_mount")
            for kind in ("python", "bao"):
                rows = []; report["interfaces"][side + "_" + kind] = rows
                run_interface(kind, instance, cli_root, official, rows)
        report["status"] = "passed"
    except Exception as error:
        report["failure"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        for instance, stop in ((oracle, launcher.stop_oracle), (native, lambda item: item.stop())):
            if instance is not None:
                try:
                    stop(instance)
                except Exception:
                    report["status"], report["failure"] = "failed", "owned_fixture_cleanup_failed"
        launcher.Client = original_client
        owned = ([oracle["process"]] if oracle else []) + ([native.process] if native and native.process else [])
        report["all_owned_stopped"] = all(process.poll() is not None for process in owned)
        report["forced_cleanup_exit_signals"] = [process.returncode for process in owned if process.returncode == -9]
        report["qa_source_after"], report["cli_source_after"] = git_identity(ROOT), cli_identity(cli_root)
        try:
            report["candidate_build_custody_after"] = build_custody(binary, receipt, candidate_source)
        except Exception as error:
            report["candidate_build_custody_after"] = None
            report["candidate_custody_after_error"] = type(error).__name__
        report["source_and_binary_unchanged"] = (before == report["qa_source_after"] and cli_before == report["cli_source_after"]
                                                  and bound == report["candidate_build_custody_after"])
        report["client_budget_seconds_observed"] = list(CLIENT_BUDGET_OBSERVATIONS)
        report["all_http_clients_exact_budget"] = len(CLIENT_BUDGET_OBSERVATIONS) >= 4 and all(value == HTTP_SECONDS for value in CLIENT_BUDGET_OBSERVATIONS)
        report["all_fixed_interfaces_complete"] = all_interfaces_complete(report["interfaces"])
        if not (report["all_owned_stopped"] and not report["forced_cleanup_exit_signals"] and report["source_and_binary_unchanged"]
                and report["all_http_clients_exact_budget"] and report["all_fixed_interfaces_complete"]):
            report["status"] = "failed"; report.setdefault("failure", "incomplete_or_changed_bound_trace")
        report["finished_at_unix"] = time.time()
        if report["status"] == "passed":
            shutil.rmtree(root)
            if oracle:
                shutil.rmtree(oracle["root"])
        else:
            report["private_fixture_retained"] = True
        if admit_output(output) != parent:
            raise ValueError("output_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "failure": report.get("failure"),
                      "interfaces": {name: len(rows) for name, rows in report["interfaces"].items()},
                      "all_owned_stopped": report["all_owned_stopped"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
