#!/usr/bin/env python3
"""Pinned 2.7 preflight, data permission, finite token and real CLI checks.

This profile covers discovery needed by the KV CLI. Full metadata fields,
listing_visibility tuning and browser UI behavior are separate requirements.
Public contract: https://openbao.org/docs/api/system/internal-ui-mounts/
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from bao_http import BaoError, Client, private_read, private_write
from core_isolation import ScenarioFailure
from official_openbao_launcher import (
    oracle_cli_environment, pinned_artifact, start_oracle, stop_oracle,
    verify_selected_oracle,
)

ROOT = Path(__file__).resolve().parents[2]
MARKER = "synthetic-mount-discovery270"
CASE_COUNT = 169
POLICIES = {
    "exact": 'path "discovery-v2/data/item" { capabilities = ["read"] }',
    "sibling": 'path "discovery-v2/data/other" { capabilities = ["read"] }',
    "mount": 'path "discovery-v2" { capabilities = ["read"] }',
    "ui": 'path "sys/internal/ui/mounts/*" { capabilities = ["read"] }',
    "deny": 'path "discovery-v2/*" { capabilities = ["deny"] }',
    "glob": 'path "discovery-v2/*" { capabilities = ["read", "list", "create", "update"] }',
    "plus": 'path "+/data/item" { capabilities = ["read"] }',
}
SECRETS = {"cubbyhole/", "identity/", "sys/", "discovery-v1/", "discovery-v2/"}
VISIBLE = {"root": SECRETS, "plus": SECRETS, "ui": {"sys/"},
           **{name: {"discovery-v2/"} for name in ("exact", "sibling", "mount", "deny", "glob")},
           "anonymous": set(), "invalid": set()}


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, name, condition, **public):
        row = {"case": "mount-discovery270." + name, "passed": bool(condition), **public}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, status, body=None, *, token=None, wrap_ttl=None):
        response = self.client.request(method, "/v1/" + path, body, token=token, wrap_ttl=wrap_ttl)
        self.check(name, response.status == status, status=response.status)
        return response.body


def normalize_fixture(client):
    original = {}
    for route, keep in (("mounts", {"cubbyhole/", "sys/", "identity/"}), ("auth", {"token/"})):
        response = client.request("GET", "/v1/sys/" + route)
        if response.status != 200 or not isinstance(response.body.get("data"), dict):
            raise ScenarioFailure("mount-discovery270.fixture_catalog")
        original[route] = sorted(response.body["data"])
        for name in response.body["data"]:
            if name not in keep:
                deleted = client.request("DELETE", "/v1/sys/" + route + "/" + name.rstrip("/"))
                if deleted.status != 204:
                    raise ScenarioFailure("mount-discovery270.fixture_unmount")
    return original


def run_scenarios(client, rows, cli_env, cli_binary):
    original = normalize_fixture(client)
    t = Trace(client, rows)
    for name, version in (("discovery-v1", "1"), ("discovery-v2", "2")):
        t.call("mount." + name, "POST", "sys/mounts/" + name, 204,
               {"type": "kv", "options": {"version": version}})
    t.call("fixture.data.v2", "POST", "discovery-v2/data/item", 200, {"data": {"value": MARKER}})
    t.call("fixture.data.v1", "POST", "discovery-v1/item", 204, {"value": MARKER})
    tokens = {"root": client._token, "anonymous": "", "invalid": "synthetic-invalid-token"}
    for name, policy in POLICIES.items():
        t.call("policy." + name, "PUT", "sys/policies/acl/discovery-" + name, 204, {"policy": policy})
        issued = t.call("token." + name, "POST", "auth/token/create", 200,
                        {"policies": ["discovery-" + name], "no_default_policy": True})
        tokens[name] = issued["auth"]["client_token"]
    for name, token in tokens.items():
        for suffix in ("", "/discovery-v2", "/discovery-v2/", "/discovery-v2/item",
                       "/discovery-v2/data/item", "/discovery-v2/other", "/discovery-v1",
                       "/missing", "/sys", "/cubbyhole"):
            response = client.request("GET", "/v1/sys/internal/ui/mounts" + suffix, token=token)
            data = response.body.get("data")
            visible = VISIBLE[name]
            if not suffix:
                expected_status = 403 if name == "invalid" else 200
                good = response.status == expected_status
                if expected_status == 200:
                    good = (good and isinstance(data, dict) and set(data) == {"auth", "secret"}
                            and set(data["secret"]) == visible
                            and set(data["auth"]) == ({"token/"} if name == "root" else set()))
            else:
                mount = suffix.strip("/").split("/", 1)[0] + "/"
                expected_status = 200 if mount in visible else 403
                good = response.status == expected_status
                if expected_status == 200:
                    kind = {"sys/": "system", "cubbyhole/": "cubbyhole"}.get(mount, "kv")
                    options = {"version": mount[-2]} if mount.startswith("discovery-v") else None
                    good = (good and isinstance(data, dict) and data.get("path") == mount
                            and data.get("type") == kind and data.get("options") == options)
                else:
                    good = good and data is None
            t.check(name + suffix, good, status=response.status)

    finite = t.call("finite.create", "POST", "auth/token/create", 200,
                    {"policies": ["discovery-exact"], "no_default_policy": True, "num_uses": 2})["auth"]["client_token"]
    t.call("finite.preflight", "GET", "sys/internal/ui/mounts/discovery-v2/other", 200, token=finite)
    lookup = t.call("finite.lookup.before", "POST", "auth/token/lookup", 200, {"token": finite})
    t.check("finite.remaining.before", lookup["data"]["num_uses"] == 2)
    t.call("finite.data.first", "GET", "discovery-v2/data/item", 200, token=finite)
    t.call("finite.preflight.again", "GET", "sys/internal/ui/mounts/discovery-v2", 200, token=finite)
    lookup = t.call("finite.lookup.after", "POST", "auth/token/lookup", 200, {"token": finite})
    t.check("finite.remaining.after", lookup["data"]["num_uses"] == 1)
    t.call("finite.data.last", "GET", "discovery-v2/data/item", 200, token=finite)
    t.call("finite.spent", "GET", "sys/internal/ui/mounts/discovery-v2", 403, token=finite)

    wrapped = t.call("wrapper.create", "POST", "sys/wrapping/wrap", 200,
                     {"value": MARKER}, wrap_ttl="60s")["wrap_info"]["token"]
    data = t.call("wrapper.collection", "GET", "sys/internal/ui/mounts", 200, token=wrapped)
    t.check("wrapper.only_control_metadata", set(data["data"]["auth"]) == {"token/"}
            and set(data["data"]["secret"]) == {"cubbyhole/", "sys/"})
    for suffix, path, kind in (("sys", "sys/", "system"), ("cubbyhole", "cubbyhole/", "cubbyhole"),
                               ("auth/token", "token/", "token")):
        data = t.call("wrapper.control." + suffix, "GET", "sys/internal/ui/mounts/" + suffix, 200, token=wrapped)
        t.check("wrapper.control.shape." + suffix, data["data"]["path"] == path and data["data"]["type"] == kind)
    t.call("wrapper.single", "GET", "sys/internal/ui/mounts/discovery-v2", 403, token=wrapped)
    unwrapped = t.call("wrapper.unwrap", "POST", "sys/wrapping/unwrap", 200, token=wrapped)
    t.check("wrapper.not_consumed", unwrapped["data"] == {"value": MARKER})
    for method in ("POST", "PUT", "PATCH", "DELETE", "LIST", "HEAD"):
        t.call("method." + method, method, "sys/internal/ui/mounts/discovery-v2", 400 if method == "PATCH" else 405)
    for label, content_type, payload, expected in (
        ("json_body", "application/json", {}, 415),
        ("merge_body", "application/merge-patch+json", {}, 405),
        ("merge_empty", "application/merge-patch+json", None, 400),
    ):
        response = client.request("PATCH", "/v1/sys/internal/ui/mounts/discovery-v2", payload, content_type=content_type)
        t.check("method.PATCH." + label, response.status == expected, status=response.status)
    for name in ("deny", "ui", "sibling"):
        t.call("data.denied." + name, "GET", "discovery-v2/data/item", 403, token=tokens[name])
    for method in ("POST", "DELETE"):
        t.call("data.denied." + method, method, "discovery-v2/data/item", 403,
               {"data": {"value": "synthetic-forbidden"}}, token=tokens["deny"])
    value = t.call("data.unchanged", "GET", "discovery-v2/data/item", 200)
    t.check("data.original", value["data"]["data"] == {"value": MARKER})

    commands = (("get", ["kv", "get", "-format=json", "-mount=discovery-v2", "item"], None, True),
                ("put", ["kv", "put", "-format=json", "-mount=discovery-v2", "created", "-"], {"value": MARKER}, False),
                ("list", ["kv", "list", "-format=json", "-mount=discovery-v2", ""], None, False))
    for name in ("root", "exact", "glob"):
        for label, arguments, payload, readback in commands:
            environment = dict(cli_env)
            for prefix in ("BAO", "VAULT"):
                environment[prefix + "_TOKEN"] = tokens[name]
            result = subprocess.run([str(cli_binary), *arguments], env=environment, capture_output=True,
                                    input=None if payload is None else json.dumps(payload).encode(), timeout=15)
            expected = 2 if name == "exact" and label != "get" else 0
            found = MARKER.encode() in result.stdout
            t.check("cli." + name + "." + label, result.returncode == expected
                    and found == readback and b"preflight" not in result.stderr.lower(),
                    exit=result.returncode, marker_readback=found)
    for label, arguments in (
        ("v1", ["kv", "get", "-format=json", "-mount=discovery-v1", "item"]),
        ("implicit_mount", ["kv", "get", "-format=json", "discovery-v2/item"]),
        ("field", ["kv", "get", "-field=value", "-mount=discovery-v2", "item"]),
        ("version", ["kv", "get", "-format=json", "-version=1", "-mount=discovery-v2", "item"]),
    ):
        result = subprocess.run([str(cli_binary), *arguments], env=cli_env, capture_output=True, timeout=15)
        found = MARKER.encode() in result.stdout
        t.check("cli.root." + label, result.returncode == 0 and found
                and b"preflight" not in result.stderr.lower(), exit=result.returncode, marker_readback=found)
    return original


def file_hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity():
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "dirty": bool(git("status", "--porcelain"))}


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--oracle-version", choices=("2.7.0",), default="2.7.0")
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    parent = output.parent.stat()
    if output.exists() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        parser.error("output must be new in a caller-owned 0700 directory")
    pinned = pinned_artifact("2.7.0")
    private = Path(tempfile.mkdtemp(prefix="heptabao-mount-discovery270-"))
    private.chmod(0o700)
    spec = importlib.util.spec_from_file_location("mount_smoke", ROOT / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    native = smoke.Instance(binary, private / "candidate")
    oracle = None
    result = {"schema": "heptabao.mount-discovery270-comparison.v1", "target_version": "2.7.0",
              "synthetic_only": True, "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "scope": "kv_cli_mount_preflight_and_finite_token_data_permissions_only",
              "remaining_requirements": ["complete_mount_metadata_fields", "listing_visibility_tuning", "browser_ui"],
              "source_before": source_identity(), "binary_sha256": file_hash(binary),
              "cargo_lock_sha256": file_hash(ROOT / "Cargo.lock"), "runner_sha256": file_hash(__file__),
              "oracle_launcher_sha256": file_hash(ROOT / "qa/openbao-acceptance/official_openbao_launcher.py"),
              "oracle_binary_sha256": pinned["binary_sha256"], "oracle_artifact_sha256": pinned["artifact_sha256"],
              "started_at_unix": time.time(), "cases": {}, "side_failures": {}, "original_bootstrap_catalogs": {}}
    try:
        native.start()
        status, initialized = native.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("candidate.init")
        native.token = initialized["root_token"]
        if native.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] != 200:
            raise ScenarioFailure("candidate.unseal")
        oracle = start_oracle(free_port(), version="2.7.0")
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())
        verify_selected_oracle(oracle, reference.health(), version="2.7.0")
        candidate = Client(native.address, str(native.root / "ca.crt"), native.token)
        candidate_fixture = {"root": native.root, "address": native.address, "ca_file": str(native.root / "ca.crt")}
        for name, client, fixture in (("candidate", candidate, candidate_fixture), ("oracle", reference, oracle)):
            result["cases"][name] = []
            try:
                result["original_bootstrap_catalogs"][name] = run_scenarios(
                    client, result["cases"][name], oracle_cli_environment(fixture, client._token),
                    Path(os.environ["HB_ORACLE_BINARY"]))
            except (ScenarioFailure, BaoError) as error:
                result["side_failures"][name] = str(error)
            except Exception as error:
                result["side_failures"][name] = "unexpected_" + type(error).__name__
        candidate_rows, oracle_rows = result["cases"]["candidate"], result["cases"]["oracle"]
        result["cases_match"] = candidate_rows == oracle_rows
        result["expected_checks_per_side"] = CASE_COUNT
        result["ordered_case_set_sha256"] = hashlib.sha256(json.dumps(
            [row["case"] for row in candidate_rows], separators=(",", ":")).encode()).hexdigest()
        result["status"] = "passed" if (len(candidate_rows) == len(oracle_rows) == CASE_COUNT and result["cases_match"]
                                             and not result["side_failures"] and all(row["passed"] for row in candidate_rows)) else "mismatch"
    except (ScenarioFailure, BaoError) as error:
        result["status"], result["safe_failure_code"] = "failed", str(error)
    except Exception as error:
        result["status"], result["safe_failure_code"] = "failed", "unexpected_" + type(error).__name__
    finally:
        native.stop()
        if oracle is not None:
            stop_oracle(oracle)
        result["owned_processes_stopped"] = native.process is None and (oracle is None or oracle["process"].poll() is not None)
        result["source_after"] = source_identity()
        result["binary_unchanged"] = file_hash(binary) == result["binary_sha256"]
        result["finished_at_unix"] = time.time()
        result["private_fixture_retained_on_failure"] = result.get("status") != "passed"
        if not result["private_fixture_retained_on_failure"]:
            shutil.rmtree(private)
            if oracle is not None:
                shutil.rmtree(oracle["root"])
        private_write(output, result)
    admitted = (result.get("status") == "passed" and result["owned_processes_stopped"]
                and result["binary_unchanged"] and result["source_before"] == result["source_after"]
                and not result["source_after"]["dirty"])
    print(json.dumps({"status": result.get("status"), "checks_per_side": len(result["cases"].get("candidate", [])),
                      "side_failures": result["side_failures"], "admitted": admitted, "full_openbao_compatibility": False}))
    return 0 if admitted else 1


if __name__ == "__main__":
    raise SystemExit(main())
