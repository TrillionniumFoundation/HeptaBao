#!/usr/bin/env python3
"""Preserve real R5 receipts without turning a failed protocol run into admission."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result, ("duplicate JSON key", key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def read(path):
    return decode((ROOT / path).read_bytes())


def original_api(value):
    while isinstance(value, dict):
        if "status" in value and "value" in value:
            assert value["status"] == "fulfilled"
            value = value["value"]
            continue
        if "request" in value and "result" in value:
            value = value["result"]
            continue
        if isinstance(value.get("content"), list):
            assert value.get("isError") is not True
            texts = [item["text"] for item in value["content"] if item.get("type") == "text"]
            assert len(texts) == 1
            value = decode(texts[0])
            continue
        break
    assert isinstance(value, dict)
    return value


def verified_terminal(status_api, read_api, *, job, state, exit_code, stdout_bytes, stderr_bytes):
    status, output = original_api(status_api), original_api(read_api)
    assert status["job_id"] == output["job_id"] == job
    assert status["state"] == state and status["exit_code"] == exit_code
    assert status["output_complete"] is status["output_durable"] is True
    assert status["terminal_publication_confirmed"] is True
    assert status["cancelled"] is status["timed_out"] is status["automatic_retry"] is False
    for key, expected in (("stdout", stdout_bytes), ("stderr", stderr_bytes)):
        row = output[key]
        raw = bytes.fromhex(row["bytes_hex"])
        assert row["offset"] == 0 and row["eof"] is True
        assert row["next_offset"] == row["size"] == len(raw) == expected
        assert raw.decode() == row["text"]
        assert status["log_bytes"][key] == {"seen": expected, "stored": expected}
        assert status["log_errors"][key] is None and status["log_truncated"][key] is False
        assert status["log_synced"][key] is True
    return status


def verified_remote_files(api):
    value = original_api(api)
    assert value["truncated"] is False
    result = {}
    for entry in value["files"]:
        raw = entry["text"].encode()
        assert entry["eof"] is True and len(raw) == entry["size"]
        assert sha(raw) == entry["sha256"]
        assert entry["path"] not in result
        result[entry["path"]] = raw
    return result


full = read("r5_formal31_evidence/original-readback.json")
full_result = read("r5_formal31_evidence/result.public.json")
full_summary = read("r5_formal31_evidence/summary.public.json")
full_job = "1a1ab90bddc-fc05-4ead"
full_read = original_api(full["read"])
full_terminal = verified_terminal(full["terminal"], full["read"], job=full_job,
    state="succeeded", exit_code=0, stdout_bytes=full_read["stdout"]["size"], stderr_bytes=0)
start = original_api(full["api_start"])
assert start["job"]["id"] == full_job and start["reused"] is False
workers = verified_remote_files(full["worker_response"])
request = decode(next(raw for path, raw in workers.items() if path.endswith("/request.json")))
started = decode(next(raw for path, raw in workers.items() if path.endswith("/started.json")))
assert request["job_id"] == started["job_id"] == full_terminal["job_id"]
assert request["launch_nonce"] == started["launch_nonce"] == full_terminal["launch_nonce"]
assert request["request_digest"] == start["job"]["request_digest"] == "76e0e3372a146a23f20be9f05478dd94b85999e45c3198b237d1c5f461aeb6dc"
for key in ("executable", "args", "cwd", "timeout_seconds", "nice"):
    assert request[key] == full["api_submission"][key]
chunks, offset, original_version = [], 0, None
for index, item in enumerate(full["summary_chunks"]):
    chunk = original_api(item)
    raw = base64.b64decode(chunk["data_base64"], validate=True)
    assert chunk["offset"] == offset and chunk["next_offset"] == offset + len(raw)
    assert sha(raw) == chunk["chunk_sha256"]
    assert chunk["eof"] is (index == len(full["summary_chunks"]) - 1)
    if original_version is None:
        original_version = chunk["version"]
    assert chunk["version"] == original_version
    offset += len(raw)
    chunks.append(raw)
summary_raw = b"".join(chunks)
assert summary_raw == (ROOT / "r5_formal31_evidence/summary.public.json").read_bytes()
assert sha(summary_raw) == "aeecd65ae734182531930c797371693c699197062477d1ccb307cf5eebf9f095"
result_files = verified_remote_files(full["result_response"])
assert any(raw == (ROOT / "r5_formal31_evidence/result.public.json").read_bytes()
           for raw in result_files.values())
assert full_result["passed_count"] == full_result["required_count"] == 31
assert len(full_result["required_checks"]) == len(set(full_result["required_checks"])) == 31
assert {row["case"] for row in full_summary["checks"] if row["passed"] is True} == set(full_result["required_checks"])
assert full_result["missing_checks"] == [] and full_result["full34_qualified"] is True
assert full_result["scope"] == "normal native_v6_file backend with fresh synthetic OpenBao 2.7.1 source"
assert full_result["replacement_qualified"] is full_result["production_changed"] is full_result["production_credentials_tested"] is full_result["traffic_cutover"] is False
assert full_result["all_owned_processes_reconciled"] is True

matched_capture = read("r5_matched27_evidence/original-root-tool-records.json")
matched = {entry["key"]: entry["value"] for entry in matched_capture["entries"]}
matched_job = "1a1abaa7b24-fc05-4f84"
matched_terminal = verified_terminal(matched["r5_matched27_observation_1_0"], matched["r5_matched27_observation_1_1"],
    job=matched_job, state="failed", exit_code=1, stdout_bytes=282, stderr_bytes=0)
matched_start = original_api(matched["r5_matched27_actual_product_start"])
assert matched_start["job"]["id"] == matched_job
assert matched_start["job"]["request_digest"] == "4155b54367229454fa4c9caa527a643275ce716a590967d2287d627d38e562f1"
matched_result = read("r5_matched27_evidence/result.public.json")
comparison = read("r5_matched27_evidence/comparison.public.json")
assert comparison["status"] == matched_result["status"] == "failed"
assert comparison["failure"] == "http_failed_or_unknown_no_retry"
assert len(comparison["checks"]) == 6 and len(comparison["missing_checks"]) == 21
assert [row["engine"] for row in comparison["operations"]] == ["openbao271", "heptabao"]
assert comparison["operations"][0]["status"] == 204 and comparison["operations"][0]["outcome"] == "response_received"
assert comparison["operations"][1]["status"] is None and comparison["operations"][1]["outcome"] == "unknown"
assert all(row["retried"] is False for row in comparison["operations"])
assert comparison["replacement_qualified"] is comparison["matched_kv2_observation_passed"] is False
for engine in ("openbao271", "heptabao"):
    stops = [row for row in comparison["process_stops"] if row["engine"] == engine]
    assert len(stops) == 1 and stops[0]["same_original_waited"] is True and stops[0]["exit_code"] == -9

diag_root = "r5_tls_generic_eof_diagnostic_prepare/evidence/"
diag = read(diag_root + "result.public.json")
observation = read(diag_root + "observation.public.json")
diag_job = "1a1abc19672-fc05-504e"
diag_terminal = verified_terminal(read(diag_root + "terminal-status.api.json"), read(diag_root + "complete-read.api.json"),
    job=diag_job, state="succeeded", exit_code=0, stdout_bytes=320, stderr_bytes=0)
diag_start = original_api(read(diag_root + "reconciled-start.api.json"))
assert diag_start["reused"] is True and diag_start["job"]["id"] == diag_job
diag_request = read(diag_root + "request.json")
diag_started = read(diag_root + "started.json")
assert diag_request["job_id"] == diag_started["job_id"] == diag_job
assert diag_request["launch_nonce"] == diag_started["launch_nonce"] == diag_terminal["launch_nonce"]
assert diag_request["request_digest"] == diag_start["job"]["request_digest"] == "5fe2ab513360003ce2d2ebe44d0c7dcbd3574ef928a6bcfc4e51b19d013a5f7f"
diag_http = observation["observation"]
raw_http = (ROOT / diag_root / "response.raw-http").read_bytes()
assert len(raw_http) == diag_http["response_bytes"] == 204
assert sha(raw_http) == diag_http["response_sha256"] == "1670003b763b9252f9f5692d4dc7f2abeb093122f84daf8e82222a45683c0419"
assert raw_http.startswith(b"HTTP/1.1 204 No Content\r\n") and raw_http.endswith(b"\r\n\r\n")
assert diag_http["request_count"] == 1 and diag_http["method"] == "GET"
assert diag_http["path"] == "/v1/sys/health?uninitcode=204"
assert diag_http["http_204_framing_complete"] is True and diag_http["body_bytes"] == 0
assert diag_http["error"]["type"] == "SSLEOFError" and diag_http["error"]["reason"] == "UNEXPECTED_EOF_WHILE_READING"
assert diag_http["authenticated_tls_eof"] is diag_http["transport_accepted"] is False
assert diag_http["tls"]["ignore_unexpected_eof"] is diag_http["tls"]["suppress_ragged_eofs"] is False
assert diag_http["tls"]["verified_ca_and_san"] is True
assert diag_http["finished_ns"] < diag_http["original_deadline_ns"] == diag_http["started_ns"] + 15_000_000_000
assert diag["same_original_worker_reaped"] is observation["target_stop"]["same_original_waited"] is True
assert observation["original_mount_outcome"] == "unknown_not_retried"
assert diag["finding"] == "complete_204_then_ragged_TLS_EOF"

files = {}
for local, archive in (("r5_formal31_evidence", "kv2-full31"),
                       ("r5_matched27_evidence", "matched27-failure"),
                       ("r5_tls_generic_eof_diagnostic_prepare/evidence", "tls-readonly-diagnostic")):
    for path in sorted((ROOT / local).rglob("*")):
        if path.is_file():
            assert not path.is_symlink()
            files[archive + "/" + path.relative_to(ROOT / local).as_posix()] = path.read_bytes()
files["diagnose_generic_tls_eof.py"] = (ROOT / "r5_tls_generic_eof_diagnostic_prepare/diagnose_generic_tls_eof.py").read_bytes()
files["validate_and_package.py"] = Path(__file__).read_bytes()
files["archive-validation-attempt1.public.json"] = (HERE / "archive-validation-attempt1.public.json").read_bytes()

review = {
    "schema": "heptabao.r5-kv2-protocol-independent-archive-review.v1",
    "source_commit": "1f188df0f2affebb92702222e9fe5dfb4712194c",
    "source_tree": "74bcb2b2af2fc9d349f007cd847fc2f16c08c01a",
    "binary_sha256": "8b42f0a6bc2de0647e558c065f517b52736c208b619902943663fe4a768f44d0",
    "scope": "actual synthetic normal-file KV2 pass and actual protocol failures; not production migration admission",
    "full31": {"job_id": full_job, "launch_nonce": full_terminal["launch_nonce"], "passed": 31,
               "required": 31, "actual_original_worker_and_full_terminal_output_checked": True,
               "summary_exact_original_binary_chunks_checked": True,
               "result_sha256": sha((ROOT / "r5_formal31_evidence/result.public.json").read_bytes())},
    "matched27": {"job_id": matched_job, "launch_nonce": matched_terminal["launch_nonce"], "passed_guards": 6,
                  "missing": 21, "status": "failed", "original_mount_outcome": "unknown_not_retried",
                  "actual_terminal_and_full_output_checked": True,
                  "worker_request_and_started_local_readback_complete": False,
                  "positive_stage_admission_granted": False,
                  "resource_or_performance_winner_established": False},
    "tls_diagnostic": {"job_id": diag_job, "launch_nonce": diag_terminal["launch_nonce"],
                       "same_key_reconciled_after_original_start_timeout": True,
                       "actual_original_worker_and_full_terminal_output_checked": True,
                       "new_readonly_health_request_count": 1, "raw_http_bytes": len(raw_http),
                       "http_status": 204, "transport_accepted": False,
                       "finding": "complete_204_then_ragged_TLS_EOF",
                       "earlier_mount_effect_inferred": False},
    "formal_recovery25_executed": False,
    "physical_ha_qualified": False, "authbus_qualified": False,
    "production_credentials_tested": False, "production_changed": False,
    "traffic_cutover": False, "old_service_cleanup": False, "replacement_qualified": False,
}
review_raw = (json.dumps(review, sort_keys=True, indent=2) + "\n").encode()
files["independent-readback.public.json"] = review_raw
(HERE / "independent-readback.public.json").write_bytes(review_raw)
manifest = {"schema": "heptabao.immutable-evidence-file-manifest.v1",
            "files": [{"path": path, "bytes": len(raw), "sha256": sha(raw)} for path, raw in sorted(files.items())]}
manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
files["manifest.public.json"] = manifest_raw
(HERE / "manifest.public.json").write_bytes(manifest_raw)
archive_path = HERE / "r5-kv2-and-protocol-evidence.tar.gz"
with archive_path.open("wb") as out:
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, raw in sorted(files.items()):
                info = tarfile.TarInfo(path)
                info.size, info.mode, info.mtime = len(raw), 0o600, 0
                info.uid = info.gid = 0
                archive.addfile(info, io.BytesIO(raw))
with tarfile.open(archive_path, "r:gz") as archive:
    assert archive.getnames() == sorted(files)
    for path, raw in files.items():
        assert archive.extractfile(path).read() == raw
print(json.dumps({"status": "archived_and_independently_reopened", "file_count": len(files),
                  "archive_bytes": archive_path.stat().st_size, "archive_sha256": sha(archive_path.read_bytes()),
                  "review_sha256": sha(review_raw), "manifest_sha256": sha(manifest_raw),
                  "replacement_qualified": False}, sort_keys=True))
