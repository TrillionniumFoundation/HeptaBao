#!/usr/bin/env python3
"""Observe seven numeric JSON lexemes on an owned official OpenBao clone.

The operator starts/stops the new private clone. This script owns only one
POST per new key, subsequent GETs, and read-only raw acquisition. It never
retries a write. The original fixture must remain stopped and untouched.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


CASES = ("1.0", "-0", "1e-6", "1e-7", "1e20", "1e21", "1e400")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class NumberLexeme(str):
    pass


def lexemes(raw):
    def unique(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate_json_key")
            out[key] = value
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_int=NumberLexeme, parse_float=NumberLexeme,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_constant")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--new-key-prefix", required=True)
    parser.add_argument("--private-work-root", type=Path, required=True)
    args = parser.parse_args()
    if not all(p.is_absolute() for p in (args.source_root, args.fixture_root, args.private_work_root)):
        raise ValueError("absolute_paths_required")
    source = args.source_root.resolve(strict=True)
    fixture = args.fixture_root.resolve(strict=True)
    root = args.private_work_root
    if not re.fullmatch(r"numeric-boundary-[a-z0-9-]{1,48}", args.new_key_prefix):
        raise ValueError("new_owned_numeric_prefix_required")
    if root.exists() or root.parent.resolve(strict=True) != root.parent:
        raise ValueError("new_private_output_root_required")
    parent = root.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError("output_parent_custody")
    controller_file = source / "qa/openbao-acceptance/kv2_271_lossless_native_live.py"
    controller = load("numeric_boundary_controller", controller_file)
    token = controller.private_read(fixture / "root.token", 65536).decode().strip()
    configuration = json.loads(controller.private_read(fixture / "server.json"))
    identity = json.loads(controller.private_read(fixture / "oracle-identity.json"))
    controller.need(identity.get("product") == "OpenBao" and identity.get("version") == "2.7.1"
                    and identity.get("synthetic_only") is True, "owned_official_fixture_required")
    root.mkdir(mode=0o700)
    (root / "private").mkdir(mode=0o700)
    report = {"schema": "heptabao.openbao271-numeric-boundary-observation.v1", "diagnostic_complete": False,
              "controller_sha256": hashlib.sha256(controller_file.read_bytes()).hexdigest(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "prefix": args.new_key_prefix, "cases": [], "requests": [], "original_budget_seconds": 120,
              "server_started": False, "original_fixture_unchanged_qualified": False,
              "synthetic_only": True, "migration_qualified": False, "writes_retried": False}
    started = time.monotonic(); end = started + 120
    previous = signal.signal(signal.SIGALRM,
        lambda *_: (_ for _ in ()).throw(controller.Failure("numeric_diagnostic_absolute_deadline")))
    signal.alarm(120)

    def once(method, path, body=None):
        deadline = min(end, time.monotonic() + controller.HTTP_SECONDS)
        controller.need(time.monotonic() < deadline, "numeric_http_deadline_before_dispatch")
        packet = {"address": configuration["api_addr"], "ca_file": str(fixture / "ca.crt"), "token": token,
                  "method": method, "path": path,
                  "body": None if body is None else base64.b64encode(body).decode("ascii"),
                  "archive_in": None, "archive_out": None}
        row = {"method": method, "path": path, "status": None, "outcome": "unknown", "retried": False}
        report["requests"].append(row)
        number = len(report["requests"])
        response_path = root / "private" / (str(number).zfill(3) + "-response.json")
        row["private_response_path"] = str(response_path)
        if body is not None:
            request_path = root / "private" / (str(number).zfill(3) + "-request.json")
            controller.private_write(request_path, body)
            row.update(request_bytes=len(body), request_sha256=hashlib.sha256(body).hexdigest(),
                       private_request_path=str(request_path))
        controller.private_write(root / (str(number).zfill(3) + "-pending.json"), json.dumps(row))
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(controller_file), "--_http_leaf"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            row["pid"] = process.pid
            try:
                stdout, errors = process.communicate(json.dumps(packet).encode(),
                                                    timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                process.kill(); process.communicate(timeout=5)
                raise controller.Failure("numeric_http_unknown_outcome_no_retry" if method == "POST"
                                         else "numeric_http_read_deadline") from error
            controller.need(process.returncode == 0 and not errors and len(stdout) <= 6 * controller.MIB,
                            "numeric_http_unknown_outcome_no_retry" if method == "POST" else "numeric_http_leaf_failed")
            result = json.loads(stdout)
            raw = base64.b64decode(result["body"], validate=True)
            status = result["status"]
            controller.need(type(status) is int and 100 <= status <= 599 and len(raw) <= controller.JSON_BYTES,
                            "numeric_response_frame")
            controller.private_write(response_path, raw)
            row.update(status=status, outcome="response_received", response_bytes=len(raw),
                       response_sha256=hashlib.sha256(raw).hexdigest())
            controller.need(time.monotonic() < deadline, "numeric_http_original_deadline")
            return status, raw
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.communicate(timeout=5)
            row["owned_wait_completed"] = process is None or process.poll() is not None
            controller.private_write(root / (str(number).zfill(3) + "-result.json"), json.dumps(row))

    try:
        status, raw = once("GET", "sys/health")
        health = controller.decode(raw)
        controller.need(status == 200 and health.get("version") == "2.7.1"
                        and health.get("cluster_id") == identity.get("cluster_id"), "actual_official_clone_identity")
        report["actual_official_version"] = health["version"]
        report["actual_cluster_matches_fixture"] = True
        status, raw = once("GET", "secret/config")
        controller.need(status == 200 and controller.decode(raw).get("data", {}).get("cas_required") is True,
                        "owned_source_mount_cas_required")
        status, _ = once("LIST", "secret/metadata/" + args.new_key_prefix)
        controller.need(status == 404, "numeric_prefix_must_be_absent_before_any_write")
        for index, number in enumerate(CASES, 1):
            case = "case-" + str(index).zfill(2)
            key = args.new_key_prefix + "/" + case
            body = ('{"data":{"case":' + json.dumps(case) + ',"number":' + number + '},"options":{"cas":0}}').encode()
            row = {"case": case, "key": key, "request_number_lexeme": number}
            report["cases"].append(row)
            row["write_status"], _ = once("POST", "secret/data/" + key, body)
            row["get_status"], raw = once("GET", "secret/data/" + key + "?version=1")
            row["get_body_sha256"] = hashlib.sha256(raw).hexdigest()
            parsed = lexemes(raw) if raw else {}
            envelope = parsed.get("data") if isinstance(parsed, dict) else None
            value = envelope.get("data") if isinstance(envelope, dict) else None
            number_value = value.get("number") if isinstance(value, dict) else None
            row["api_number_lexeme"] = str(number_value) if isinstance(number_value, NumberLexeme) else None
            row["api_case_matches"] = isinstance(value, dict) and value.get("case") == case
        migration_file = source / "tools/migration/openbao270_kv2_migrate.py"
        migration = load("numeric_boundary_raw_migration", migration_file)
        client = migration.Client(configuration["api_addr"], token, ca_file=str(fixture / "ca.crt"), end=end)
        mount_id = client.mount("secret")
        first = migration.acquire(client, mount_id)
        second = migration.acquire(client, mount_id)
        controller.need(client.mount("secret") == mount_id and first == second, "numeric_raw_source_changed")
        decoded = migration.decode_records(sorted(first.items()))
        storage_root = "logical/" + mount_id + "/"
        salt = first[storage_root + "salt"]
        report["raw_records"] = len(first)
        report["raw_acquisitions_identical"] = True
        report["raw_decoder_sha256"] = hashlib.sha256(migration._decoder_path.read_bytes()).hexdigest()
        for row in report["cases"]:
            digest = hashlib.sha256(salt + (row["key"] + "|1").encode()).hexdigest()
            storage_path = storage_root + "versions/" + digest[:3] + "/" + digest[3:]
            raw_record = first.get(storage_path)
            row["raw_record_present"] = raw_record is not None
            if raw_record is None:
                continue
            fields = migration._decoder_module.message(raw_record, {1: 2, 2: 2, 3: 2})
            raw_payload = fields[1]
            value = lexemes(raw_payload)
            number_value = value.get("number")
            controller.need(isinstance(number_value, NumberLexeme) and value.get("case") == row["case"],
                            "numeric_raw_payload_shape")
            item = decoded["entries"][row["key"]]["versions"]["1"]
            row.update(raw_number_lexeme=str(number_value), raw_payload_bytes=len(raw_payload),
                       raw_payload_sha256=hashlib.sha256(raw_payload).hexdigest(),
                       raw_number_same_lexeme=str(number_value) == row["request_number_lexeme"],
                       decoder_number_text=str(item["data"]["number"]))
            controller.private_write(root / "private" / (row["case"] + "-raw-payload.json"), raw_payload)
        report["diagnostic_complete"] = True
    except Exception as error:
        report["error"] = str(error) if isinstance(error, controller.Failure) else type(error).__name__
        report["mutation_outcome_unknown"] = any(row["method"] == "POST" and row["outcome"] == "unknown"
                                                for row in report["requests"])
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)
        report["elapsed_seconds"] = round(time.monotonic() - started, 6)
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        controller.need(not token or token not in encoded, "numeric_diagnostic_secret_projection")
        controller.private_write(root / "summary.json", encoded + "\n")
        print(json.dumps({"diagnostic_complete": report["diagnostic_complete"],
                          "summary": str(root / "summary.json"), "writes_retried": False}))
    return 0 if report["diagnostic_complete"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("numeric boundary diagnosis failed before publication", file=sys.stderr)
        raise SystemExit(1) from None
