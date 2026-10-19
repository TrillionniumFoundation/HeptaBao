#!/usr/bin/env python3
"""Read-only raw follow-up of a completed seven-key OpenBao 2.7.1 diagnostic.

The operator clones the stopped numeric fixture, rebinds its configuration,
starts and stops that new clone, and retains both original receipts. This
program can issue only GET/LIST, never the seven original POSTs.
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
PRIOR_SCRIPT_SHA256 = "cf1f7a475801b9d39072e8ba9878c912bf86f77d276395a43b8dc0c86e143305"


class Failure(Exception):
    pass


def need(ok, label):
    if not ok:
        raise Failure(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


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
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_int=NumberLexeme, parse_float=NumberLexeme,
                      parse_constant=lambda _: need(False, "invalid_json_constant"))


def validate_prior(prior):
    need(isinstance(prior, dict)
         and prior.get("schema") == "heptabao.openbao271-numeric-boundary-observation.v1"
         and prior.get("script_sha256") == PRIOR_SCRIPT_SHA256
         and prior.get("diagnostic_complete") is False
         and prior.get("error") == "KeyError"
         and prior.get("synthetic_only") is True
         and prior.get("migration_qualified") is False
         and prior.get("writes_retried") is False
         and prior.get("mutation_outcome_unknown") is False
         and prior.get("actual_official_version") == "2.7.1"
         and prior.get("actual_cluster_matches_fixture") is True,
         "prior_failed_diagnostic_identity")
    prefix = prior.get("prefix")
    need(isinstance(prefix, str) and re.fullmatch(r"numeric-boundary-[a-z0-9-]{1,48}", prefix),
         "prior_numeric_prefix")
    cases = prior.get("cases")
    requests = prior.get("requests")
    need(isinstance(cases, list) and len(cases) == 7
         and isinstance(requests, list) and len(requests) == 17,
         "prior_complete_seven_request_pairs")
    need(all(isinstance(row, dict) and row.get("outcome") == "response_received"
             and row.get("retried") is False and row.get("owned_wait_completed") is True
             and type(row.get("status")) is int for row in requests),
         "prior_all_request_outcomes_known")
    for index, (number, row) in enumerate(zip(CASES, cases), 1):
        case = "case-" + str(index).zfill(2)
        need(isinstance(row, dict) and row.get("case") == case
             and row.get("key") == prefix + "/" + case
             and row.get("request_number_lexeme") == number,
             "prior_case_identity")
        write, read = requests[3 + (index - 1) * 2:5 + (index - 1) * 2]
        need(write.get("method") == "POST" and write.get("path") == "secret/data/" + row["key"]
             and read.get("method") == "GET" and read.get("path") == write["path"] + "?version=1"
             and write["status"] == row.get("write_status")
             and read["status"] == row.get("get_status")
             and read.get("response_sha256") == row.get("get_body_sha256"),
             "prior_case_request_binding")
    need(sum(row.get("method") == "POST" for row in requests) == 7,
         "prior_exactly_seven_post_outcomes")
    return prefix, cases


def discover_storage_root(records, mount_id):
    outer = "logical/" + mount_id + "/"
    roots = [name[:-6] for name in records if name.endswith("/config")]
    need(len(roots) == 1, "raw_unique_config_root_required")
    root = roots[0]
    need(root.startswith(outer) and root.endswith("/")
         and all(name.startswith(root) for name in records), "raw_actual_mount_boundary")
    salt = records.get(root + "salt")
    need(isinstance(salt, bytes) and 0 < len(salt) <= 1024, "raw_actual_config_root_salt_required")
    return root, salt, {
        "config_root_sha256": digest(root.encode()),
        "config_root_relative_depth": len([part for part in root[len(outer):].split("/") if part]),
        "legacy_assumed_root_equal": root == outer,
        "legacy_assumed_salt_present": outer + "salt" in records,
        "actual_config_root_salt_present": True,
        "salt_bytes": len(salt),
    }


def allow_read(method, path, body=None):
    need(method in ("GET", "LIST") and body is None, "read_only_request_required")
    need(isinstance(path, str) and path and not path.startswith("/"), "relative_read_path_required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--prior-summary", type=Path, required=True)
    parser.add_argument("--prior-summary-sha256", required=True)
    parser.add_argument("--private-work-root", type=Path, required=True)
    args = parser.parse_args()
    need(all(p.is_absolute() for p in (args.source_root, args.fixture_root,
                                      args.prior_summary, args.private_work_root)), "absolute_paths_required")
    need(re.fullmatch(r"[0-9a-f]{64}", args.prior_summary_sha256), "prior_sha256_required")
    source = args.source_root.resolve(strict=True)
    fixture = args.fixture_root.resolve(strict=True)
    root = args.private_work_root
    need(not root.exists() and root.parent.resolve(strict=True) == root.parent, "new_private_output_root_required")
    parent = root.parent.stat()
    need(parent.st_uid == os.geteuid() and parent.st_mode & 0o022 == 0, "output_parent_custody")
    controller_file = source / "qa/openbao-acceptance/kv2_271_lossless_native_live.py"
    migration_file = source / "tools/migration/openbao270_kv2_migrate.py"
    controller = load("numeric_raw_followup_controller", controller_file)
    prior_raw = controller.private_read(args.prior_summary)
    need(digest(prior_raw) == args.prior_summary_sha256, "prior_summary_exact_hash")
    prior = json.loads(prior_raw)
    prefix, prior_cases = validate_prior(prior)
    health_request = prior["requests"][0]
    need(health_request.get("method") == "GET" and health_request.get("path") == "sys/health"
         and health_request.get("status") == 200, "prior_health_request_binding")
    prior_health_path = args.prior_summary.parent / "private/001-response.json"
    need(health_request.get("private_response_path") == str(prior_health_path), "prior_private_health_path_binding")
    prior_health_raw = controller.private_read(prior_health_path)
    need(digest(prior_health_raw) == health_request.get("response_sha256"), "prior_health_exact_hash")
    prior_health = json.loads(prior_health_raw)
    token = controller.private_read(fixture / "root.token", 65536).decode().strip()
    configuration = json.loads(controller.private_read(fixture / "server.json"))
    identity = json.loads(controller.private_read(fixture / "oracle-identity.json"))
    need(identity.get("product") == "OpenBao" and identity.get("version") == "2.7.1"
         and identity.get("synthetic_only") is True
         and prior_health.get("version") == "2.7.1"
         and isinstance(prior_health.get("cluster_id"), str) and prior_health["cluster_id"]
         and identity.get("cluster_id") == prior_health["cluster_id"], "same_owned_official_cluster_required")
    root.mkdir(mode=0o700)
    (root / "private").mkdir(mode=0o700)
    report = {"schema": "heptabao.openbao271-numeric-raw-followup.v1", "diagnostic_complete": False,
              "script_sha256": digest(Path(__file__).read_bytes()),
              "controller_sha256": digest(controller_file.read_bytes()),
              "prior_summary_sha256": digest(prior_raw), "prior_diagnostic_complete": False,
              "prior_script_sha256": prior["script_sha256"], "prefix": prefix,
              "prior_health_sha256": digest(prior_health_raw), "cases": [], "requests": [],
              "phase": "actual_health", "original_budget_seconds": 120, "source_writes": 0,
              "writes_retried": False, "server_started": False, "synthetic_only": True,
              "original_fixture_unchanged_qualified": False, "migration_qualified": False}
    started = time.monotonic(); end = started + 120
    previous = signal.signal(signal.SIGALRM,
        lambda *_: need(False, "numeric_raw_followup_absolute_deadline"))
    signal.alarm(120)

    def once(method, path, body=None, *, seconds=None):
        allow_read(method, path, body)
        deadline = min(end, time.monotonic() + (controller.HTTP_SECONDS if seconds is None else seconds))
        need(time.monotonic() < deadline, "read_deadline_before_dispatch")
        packet = {"address": configuration["api_addr"], "ca_file": str(fixture / "ca.crt"),
                  "token": token, "method": method, "path": path, "body": None,
                  "archive_in": None, "archive_out": None}
        row = {"method": method, "path": path, "status": None, "outcome": "unknown", "retried": False}
        report["requests"].append(row)
        number = len(report["requests"])
        response_path = root / "private" / (str(number).zfill(3) + "-response.json")
        row["private_response_path"] = str(response_path)
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
                raise Failure("read_deadline_no_retry") from error
            need(process.returncode == 0 and not errors and len(stdout) <= 6 * controller.MIB,
                 "read_http_leaf_failed")
            result = json.loads(stdout)
            raw = base64.b64decode(result["body"], validate=True)
            status = result["status"]
            need(type(status) is int and 100 <= status <= 599 and len(raw) <= controller.JSON_BYTES,
                 "read_response_frame")
            controller.private_write(response_path, raw)
            row.update(status=status, outcome="response_received", response_bytes=len(raw),
                       response_sha256=digest(raw))
            need(time.monotonic() < deadline, "read_original_deadline")
            return status, raw
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.communicate(timeout=5)
            row["owned_wait_completed"] = process is None or process.poll() is not None
            controller.private_write(root / (str(number).zfill(3) + "-result.json"), json.dumps(row))

    try:
        status, raw = once("GET", "sys/health")
        health = json.loads(raw)
        need(status == 200 and health.get("version") == "2.7.1"
             and health.get("cluster_id") == prior_health["cluster_id"], "actual_same_official_cluster")
        report["actual_official_version"] = "2.7.1"
        report["actual_cluster_matches_prior"] = True
        report["phase"] = "repeat_existing_api_gets"
        for old in prior_cases:
            row = {name: old[name] for name in ("case", "key", "request_number_lexeme", "write_status")}
            row["prior_api_status"] = old["get_status"]
            row["prior_api_number_lexeme"] = old["api_number_lexeme"]
            report["cases"].append(row)
            status, raw = once("GET", "secret/data/" + old["key"] + "?version=1")
            value = lexemes(raw).get("data")
            value = value.get("data") if isinstance(value, dict) else None
            number = value.get("number") if isinstance(value, dict) else None
            row.update(get_status=status, get_body_sha256=digest(raw),
                       api_number_lexeme=str(number) if isinstance(number, NumberLexeme) else None,
                       api_case_matches=isinstance(value, dict) and value.get("case") == old["case"])
            row["api_matches_prior"] = (status == old["get_status"]
                and row["api_number_lexeme"] == old["api_number_lexeme"]
                and row["api_case_matches"] == old["api_case_matches"])
            need(row["api_matches_prior"], "existing_numeric_api_changed")
        report["phase"] = "load_legacy_raw_reader"
        migration = load("numeric_raw_followup_migration", migration_file)
        report["migration_sha256"] = digest(migration_file.read_bytes())
        report["raw_decoder_sha256"] = digest(migration._decoder_path.read_bytes())

        class ReadOnlyClient(migration.Client):
            def request(self, method, path, body=None):
                allow_read(method, path, body)
                status, raw = once(method, path, seconds=migration.TIMEOUT)
                need(status in (200, 204), "raw_reader_http_status_" + str(status))
                if status == 204:
                    need(not raw, "raw_reader_unexpected_204_body")
                    return None
                return migration.parse_json(raw, migration.MAX_RESPONSE)

        client = ReadOnlyClient(configuration["api_addr"], token, ca_file=str(fixture / "ca.crt"), end=end)
        report["phase"] = "mount_before_first_acquisition"
        mount_id = client.mount("secret")
        report["mount_id_sha256"] = digest(mount_id.encode())
        report["phase"] = "first_raw_acquisition"
        first = migration.acquire(client, mount_id)
        report["raw_records"] = len(first)
        report["phase"] = "mount_between_acquisitions"
        need(client.mount("secret") == mount_id, "raw_mount_changed_after_first_acquisition")
        report["phase"] = "second_raw_acquisition"
        second = migration.acquire(client, mount_id)
        report["phase"] = "mount_after_second_acquisition"
        need(client.mount("secret") == mount_id and first == second, "raw_records_changed")
        report["raw_acquisitions_identical"] = True
        report["phase"] = "discover_actual_config_root"
        storage_root, salt, projection = discover_storage_root(first, mount_id)
        report["raw_root_projection"] = projection
        report["phase"] = "decode_closed_raw_history"
        decoded = migration.decode_records(sorted(first.items()))
        report["raw_decoder_completed"] = True
        private_manifest = [{"path": path, "bytes": len(record), "sha256": digest(record)}
                            for path, record in sorted(first.items())]
        controller.private_write(root / "private/raw-record-manifest.json", json.dumps(private_manifest))
        report["phase"] = "project_exact_numeric_raw_versions"
        for row in report["cases"]:
            locator = digest(salt + (row["key"] + "|1").encode())
            storage_path = storage_root + "versions/" + locator[:3] + "/" + locator[3:]
            raw_record = first.get(storage_path)
            entry = decoded["entries"].get(row["key"])
            row.update(raw_record_present=raw_record is not None, raw_metadata_present=entry is not None)
            if row["write_status"] == 400:
                row["rejected_write_has_no_raw_state"] = raw_record is None and entry is None
                need(row["rejected_write_has_no_raw_state"], "rejected_numeric_write_retains_raw_state")
                continue
            need(row["write_status"] == 200 and raw_record is not None and isinstance(entry, dict),
                 "accepted_numeric_raw_history_missing")
            versions = entry.get("versions")
            need(entry.get("current_version") == 1 and isinstance(versions, dict) and set(versions) == {"1"},
                 "numeric_raw_requires_exactly_version_one")
            fields = migration._decoder_module.message(raw_record, {1: 2, 2: 2, 3: 2})
            need(1 in fields, "numeric_raw_payload_field_missing")
            payload = fields[1]
            value = lexemes(payload)
            need(isinstance(value, dict) and set(value) == {"case", "number"}
                 and value["case"] == row["case"] and isinstance(value["number"], NumberLexeme),
                 "numeric_raw_payload_shape")
            item = versions["1"]
            need(item.get("destroyed") is False and item.get("deletion_time") == ""
                 and isinstance(item.get("data"), dict), "numeric_raw_version_state")
            decoded_number = item["data"].get("number")
            row.update(raw_number_lexeme=str(value["number"]), raw_payload_bytes=len(payload),
                       raw_payload_sha256=digest(payload), raw_record_sha256=digest(raw_record),
                       raw_number_same_lexeme=str(value["number"]) == row["request_number_lexeme"],
                       decoder_number_text=str(decoded_number),
                       decoder_number_type=type(decoded_number).__name__)
            controller.private_write(root / "private" / (row["case"] + "-raw-payload.json"), payload)
        report["phase"] = "complete"
        report["diagnostic_complete"] = True
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = str(error) if isinstance(error, Failure) else "unexpected_exception_redacted"
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)
        report["elapsed_seconds"] = round(time.monotonic() - started, 6)
        report["all_dispatched_requests_read_only"] = all(
            row["method"] in ("GET", "LIST") for row in report["requests"])
        report["all_owned_http_leaves_waited"] = all(
            row.get("owned_wait_completed") is True for row in report["requests"])
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        need(not token or token not in encoded, "diagnostic_secret_projection")
        controller.private_write(root / "summary.json", encoded + "\n")
        print(json.dumps({"diagnostic_complete": report["diagnostic_complete"],
                          "summary": str(root / "summary.json"), "source_writes": 0}))
    return 0 if report["diagnostic_complete"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("read-only numeric follow-up failed before publication", file=sys.stderr)
        raise SystemExit(1) from None
