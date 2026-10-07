#!/usr/bin/env python3
"""Bounded product Python KV and pinned bao CLI over fresh synthetic TLS only.

Positive stdout is consumed in memory to verify requested values. Neither stdout,
stderr, argv data nor credentials are stored in reports. This is not full CLI
compatibility or independent replacement/production qualification.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import (SUPPORTED_VERSIONS, VERSION, oracle_cli_environment,
                                      start_oracle, stop_oracle, verify_inputs)
from online_evidence import admit_output, source_identity


# Fixed ordered operations, independent of either trace's observed length.
OPERATIONS = ("v1_put", "v1_get", "v1_list", "v1_delete", "v1_missing",
              "v2_create", "v2_field", "v2_stale_cas", "v2_replace", "v2_history",
              "v2_patch", "v2_remove", "v2_read", "v2_rw_patch", "v2_rollback",
              "metadata_put", "metadata_get", "v2_delete", "v2_deleted", "v2_undelete",
              "v2_restored", "v2_destroy", "v2_destroyed", "v2_list", "metadata_delete", "metadata_missing")
VALUE_OPERATIONS = frozenset(("v1_get", "v1_list", "v2_create", "v2_field", "v2_replace", "v2_history",
                             "v2_patch", "v2_remove", "v2_read", "v2_rw_patch", "v2_rollback", "metadata_get",
                             "v2_restored", "v2_list", "v2_deleted", "v2_destroyed"))
REQUIRED_INTERFACE_CASES = tuple(case for operation in OPERATIONS for case in
                                (operation + "_exit", operation + "_safe_errors") +
                                ((operation + "_value",) if operation in VALUE_OPERATIONS else ()))


def _git_identity() -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
            "cli_sha256": file_hash(ROOT / "clients/python/heptabao/cli.py"),
            "kv_cli_sha256": file_hash(ROOT / "clients/python/heptabao/kv_cli.py"),
            "transport_sha256": file_hash(ROOT / "clients/python/heptabao/transport.py")}


def custody(binary: Path, receipt_path: Path) -> dict:
    value = json.loads(private_read(receipt_path))
    before, after = value.get("source_identity_before"), value.get("source_identity_after")
    if (value.get("schema") != "heptabao.immutable-runtime-build-custody.v1" or value.get("exit") != 0
            or not isinstance(before, dict) or before != after or before.get("source_dirty") is not False
            or value.get("source_unchanged") is not True or value.get("binary_sha256") != file_hash(binary)):
        raise ValueError("candidate_build_custody_mismatch")
    return {"source": before, "binary_sha256": value["binary_sha256"], "receipt_sha256": file_hash(receipt_path)}


def run_interface(kind: str, instance: dict, root: Path, official_binary: Path, rows: list[dict]):
    def check(case, passed):
        rows.append({"case": case, "passed": bool(passed)})
        if not passed:
            raise ScenarioFailure(case)

    environment = oracle_cli_environment(instance, instance["token"])
    environment.update({"PYTHONPATH": str(ROOT / "clients/python"), "BAO_CLIENT_TIMEOUT": "2s",
                        "VAULT_CLIENT_TIMEOUT": "2s", "BAO_DISABLE_REDIRECTS": "true", "VAULT_DISABLE_REDIRECTS": "true"})
    for name in ("BAO_NAMESPACE", "VAULT_NAMESPACE", "BAO_TOKEN_FILE", "VAULT_TOKEN_FILE", "BAO_TOKEN_PATH", "VAULT_TOKEN_PATH",
                 "BAO_FORMAT", "VAULT_FORMAT"):
        environment.pop(name, None)
    executable = [sys.executable, "-m", "heptabao", "kv"] if kind == "python" else [str(official_binary), "kv"]
    value = "synthetic-cli-requested-value"
    protected = (instance["token"].encode(), value.encode())
    prefix = kind + "/"
    data_file = Path(instance["root"]) / (kind + "-input.json")
    private_write(data_file, {"value": value, "keep": "yes"}, replace=False)

    def command(case, command, flags, path, data=(), expected=0):
        # Do not print/reconstruct this command or completed output in an error.
        arguments = executable + command + ([] if command == ["metadata", "delete"] else ["-format=json"]) + flags + [path] + list(data)
        completed = subprocess.run(arguments, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
        check(case + "_exit", completed.returncode == expected)
        check(case + "_safe_errors", all(secret not in completed.stderr for secret in protected)
              and protected[0] not in completed.stdout
              and (expected == 0 or protected[1] not in completed.stdout))
        if expected or case not in VALUE_OPERATIONS:
            return None
        try:
            return json.loads(completed.stdout)
        except (ValueError, UnicodeError):
            raise ScenarioFailure(case + "_output_encoding") from None

    def version(case, body, expected):
        check(case + "_value", isinstance(body, dict) and body.get("data", {}).get("version") == expected)

    key1, key2 = prefix + "key", prefix + "key"
    command("v1_put", ["put"], ["-mount=cli-v1"], key1, ["@" + str(data_file)])
    check("v1_get_value", command("v1_get", ["get"], ["-mount=cli-v1", "-field=value"], key1) == value)
    check("v1_list_value", command("v1_list", ["list"], ["-mount=cli-v1"], prefix) == ["key"])
    command("v1_delete", ["delete"], ["-mount=cli-v1"], key1)
    command("v1_missing", ["get"], ["-mount=cli-v1"], key1, expected=2)

    version("v2_create", command("v2_create", ["put"], ["-mount=cli-v2", "-cas=0"], key2, ["@" + str(data_file)]), 1)
    check("v2_field_value", command("v2_field", ["get"], ["-mount=cli-v2", "-field=value"], key2) == value)
    command("v2_stale_cas", ["put"], ["-mount=cli-v2", "-cas=0"], key2, ["@" + str(data_file)], expected=2)
    version("v2_replace", command("v2_replace", ["put"], ["-cas=1"], "cli-v2/" + key2, ["value=second", "keep=yes"]), 2)
    check("v2_history_value", command("v2_history", ["get"], ["-mount=cli-v2", "-version=1", "-field=value"], key2) == value)
    version("v2_patch", command("v2_patch", ["patch"], ["-mount=cli-v2", "-method=patch", "-cas=2"], key2, ["added=yes"]), 3)
    # The pinned CLI ignores PATCH CAS 0. The preceding PATCH keeps exact
    # positive CAS coverage; this removal must still publish exactly version 4.
    version("v2_remove", command("v2_remove", ["patch"], ["-mount=cli-v2", "-method=patch", "-remove-data=added", "-cas=0"], key2), 4)
    read = command("v2_read", ["get"], ["-mount=cli-v2"], key2)
    check("v2_read_value", read.get("data", {}).get("data") == {"value": "second", "keep": "yes"})
    version("v2_rw_patch", command("v2_rw_patch", ["patch"], ["-mount=cli-v2", "-method=rw", "-cas=999"], key2, ["rw=yes"]), 5)
    version("v2_rollback", command("v2_rollback", ["rollback"], ["-mount=cli-v2", "-version=1"], key2), 6)
    command("metadata_put", ["metadata", "put"], ["-mount=cli-v2", "-max-versions=9", "-cas-required=false", "-custom-metadata=team=test"], key2)
    metadata = command("metadata_get", ["metadata", "get"], ["-mount=cli-v2"], key2)
    check("metadata_get_value", metadata.get("data", {}).get("current_version") == 6
          and metadata.get("data", {}).get("max_versions") == 9 and metadata.get("data", {}).get("custom_metadata") == {"team": "test"})
    command("v2_delete", ["delete"], ["-mount=cli-v2", "-versions=6"], key2)
    deleted = command("v2_deleted", ["get"], ["-mount=cli-v2"], key2)
    check("v2_deleted_value", deleted.get("data", {}).get("data") is None
          and deleted.get("data", {}).get("metadata", {}).get("destroyed") is False)
    command("v2_undelete", ["undelete"], ["-mount=cli-v2", "-versions=6"], key2)
    check("v2_restored_value", command("v2_restored", ["get"], ["-mount=cli-v2", "-version=6", "-field=value"], key2) == value)
    command("v2_destroy", ["destroy"], ["-mount=cli-v2", "-versions=6"], key2)
    destroyed = command("v2_destroyed", ["get"], ["-mount=cli-v2", "-version=6"], key2)
    check("v2_destroyed_value", destroyed.get("data", {}).get("data") is None
          and destroyed.get("data", {}).get("metadata", {}).get("destroyed") is True)
    check("v2_list_value", command("v2_list", ["list"], ["-mount=cli-v2"], prefix) == ["key"])
    command("metadata_delete", ["metadata", "delete"], ["-mount=cli-v2"], key2)
    command("metadata_missing", ["metadata", "get"], ["-mount=cli-v2"], key2, expected=2)
    names = [row["case"] for row in rows]
    if set(names) != set(REQUIRED_INTERFACE_CASES) or len(names) != len(REQUIRED_INTERFACE_CASES):
        raise ScenarioFailure("interface_incomplete_or_duplicate_cases")


def main(argv=None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--build-receipt")
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--oracle-version", choices=SUPPORTED_VERSIONS, default=VERSION)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.oracle_only == bool(args.binary) or bool(args.binary) != bool(args.build_receipt):
        parser.error("select oracle-only or binary with immutable build receipt")
    output = Path(args.output).absolute()
    parent = admit_output(output)
    official_binary = Path(verify_inputs(version=args.oracle_version))
    binary = Path(args.binary).resolve(strict=True) if args.binary else None
    bound = custody(binary, Path(args.build_receipt)) if binary else None
    before = _git_identity()
    candidate_before = source_identity(ROOT, binary) if binary else None
    root = Path(tempfile.mkdtemp(prefix="python-kv-cli-", dir=output.parent))
    root.chmod(0o700)
    report = {"schema": "heptabao.python-kv-cli-live.v1", "synthetic_only": True,
              "oracle_version": args.oracle_version, "oracle_cli_sha256": file_hash(official_binary),
              "runner_sha256": file_hash(Path(__file__)), "launcher_sha256": file_hash(ROOT / "qa/openbao-acceptance/official_openbao_launcher.py"),
              "client_source_before": before, "candidate_build_custody": bound,
              "interfaces": {}, "started_at_unix": time.time(), "full_cli_compatibility": False,
              "production_authority": False, "independent_qualification": False,
              "requested_stdout_saved": False, "credentials_saved_in_report": False}
    oracle, native = None, None
    owned = []
    try:
        if binary:
            spec = importlib.util.spec_from_file_location("python_kv_cli_smoke", ROOT / "qa/single-node/smoke.py")
            smoke = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(smoke)
            native = smoke.Instance(binary, root / "native")
            native.start()
            owned.append(native.process)
            unauthenticated = Client(native.address, str(native.root / "ca.crt"), "synthetic-not-initialized", timeout=5)
            response = unauthenticated.request("POST", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if response.status != 200:
                raise ScenarioFailure("native_init")
            native.token = response.body["root_token"]
            if unauthenticated.request("POST", "/v1/sys/unseal", {"key": response.body["keys_base64"][0]}).status != 200:
                raise ScenarioFailure("native_unseal")
            fixtures = [("candidate", {"root": str(native.root), "address": native.address, "ca_file": str(native.root / "ca.crt"), "token": native.token})]
        else:
            fixtures = []
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        oracle = start_oracle(port, version=args.oracle_version)
        owned.append(oracle["process"])
        token = private_read(oracle["token_file"]).decode().strip()
        oracle["token"] = token
        fixtures.append(("oracle", oracle))
        report["oracle_identity"] = json.loads(private_read(oracle["identity_file"]))
        for side, instance in fixtures:
            client = Client(instance["address"], instance["ca_file"], instance["token"], timeout=5)
            for version in ("1", "2"):
                response = client.request("POST", "/v1/sys/mounts/cli-v" + version, {"type": "kv", "options": {"version": version}})
                if response.status != 204:
                    raise ScenarioFailure(side + "_mount_v" + version)
            for kind in ("python", "bao"):
                rows = []
                report["interfaces"][side + "_" + kind] = rows
                run_interface(kind, instance, root, official_binary, rows)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = str(error) if isinstance(error, ScenarioFailure) else type(error).__name__
    finally:
        if oracle:
            try:
                stop_oracle(oracle)
            except Exception:
                report["status"], report["failure"] = "failed", "oracle_cleanup_failed"
        if native:
            try:
                native.stop()
            except Exception:
                report["status"], report["failure"] = "failed", "candidate_cleanup_failed"
        report["all_owned_stopped"] = all(process.poll() is not None for process in owned)
        if not report["all_owned_stopped"]:
            report["status"], report["failure"] = "failed", "owned_process_still_running"
        after = _git_identity()
        candidate_after = source_identity(ROOT, binary) if binary else None
        report["client_source_after"] = after
        report["source_and_binary_unchanged"] = before == after and candidate_before == candidate_after
        report["candidate_binary_sha256_after"] = None if binary is None else file_hash(binary)
        if not report["source_and_binary_unchanged"]:
            report["status"], report["failure"] = "failed", "source_or_binary_changed"
        expected = {side + "_" + kind for side in (("oracle",) if args.oracle_only else ("candidate", "oracle")) for kind in ("python", "bao")}
        report["all_fixed_interfaces_complete"] = set(report["interfaces"]) == expected and all(
            len(rows) == len(REQUIRED_INTERFACE_CASES) and len({row["case"] for row in rows}) == len(REQUIRED_INTERFACE_CASES)
            and {row["case"] for row in rows} == set(REQUIRED_INTERFACE_CASES) and all(row["passed"] is True for row in rows)
            for rows in report["interfaces"].values())
        if not report["all_fixed_interfaces_complete"]:
            report["status"] = "failed"
            report.setdefault("failure", "incomplete_fixed_interfaces")
        report["finished_at_unix"] = time.time()
        # Preserve native private diagnostics on failure. Positive output remains
        # memory-only regardless; no stdout file or value digest is ever written.
        if report["status"] == "passed":
            shutil.rmtree(root)
            if oracle:
                shutil.rmtree(oracle["root"])
        else:
            report["private_fixture_retained"] = True
        if admit_output(output) != parent:
            raise ValueError("output_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "interfaces": {name: len(rows) for name, rows in report["interfaces"].items()},
                      "failure": report.get("failure"), "all_owned_stopped": report["all_owned_stopped"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
