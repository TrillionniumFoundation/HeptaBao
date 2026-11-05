"""Lossless verification of already collected public R3 inert evidence only."""
import base64
import hashlib
import json
from pathlib import Path

v = json.loads(Path(__file__).with_name("verification-input.json").read_text())
checks = []
def checked(name, condition):
    assert condition, name
    checks.append({"name": name, "passed": True})
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def parsed(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result, "duplicate JSON key"
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

request = parsed(v["request_raw"])
go = parsed(v["go_raw"])
intent = parsed(v["external_intent_raw"])
ack = parsed(v["ack_raw"])
authority = parsed(v["authority_raw"])
streams = parsed(v["streams_raw"])
receipt = parsed(v["receipt_raw"])
infos = [parsed(x) for x in v["infos_raw"]]
base = "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3"
job_id = "1a1ab50b1b9-fc05-4c6e"
checked("exact-approved-request", len(v["request_raw"].encode()) == 409810 and sha(v["request_raw"].encode()) == "428533673ecff4a142ab0e728b64b365c8ec4a7f65919261b636fcb7e6b33804")
checked("go-request-and-source-tree", go["request"]["sha256"] == sha(v["request_raw"].encode()) and go["source_packet"] == "c39a25545380825bbe5d56949563bb08095f9730" and go["build_go"] is False)
checked("external-intent-exact-key-and-request", intent["request_sha256"] == sha(v["request_raw"].encode()) and intent["idempotency_key"] == request["idempotency_key"] and intent["cargo_or_product_authorized"] is False)
checked("fixed-host-cwd-executable-outer", (request["host"], request["cwd"], request["executable"], request["timeout_seconds"]) == ("rog", "/home/qian-qi", "/usr/bin/python3", 60))
checked("ack-unique-launched", ack["reused"] is False and ack["launch"]["ok"] is True and ack["job"]["id"] == job_id)
for name in ("host", "cwd", "executable", "args", "idempotency_key"):
    checked("ack-exact-" + name, ack["job"][name] == request[name])
checked("authority-job-and-known-success", authority["job_id"] == job_id and authority["state"] == "succeeded" and authority["exit_code"] == 0)
for name in ("output_complete", "output_durable", "terminal_publication_confirmed"):
    checked("authority-" + name, authority[name] is True)
for name in ("automatic_retry", "cancelled", "timed_out"):
    checked("authority-no-" + name, authority[name] is False)
checked("streams-same-job", streams["job_id"] == job_id)
raw_streams = {}
for name in ("stdout", "stderr"):
    row = streams[name]
    raw = bytes.fromhex(row["bytes_hex"])
    checked(name + "-whole-hex-utf8", raw == row["text"].encode())
    checked(name + "-full-boundary", row["offset"] == 0 and row["next_offset"] == row["size"] == len(raw) and row["eof"] is True)
    checked(name + "-authority-byte-counts", authority["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)})
    checked(name + "-synced-no-truncation-or-error", authority["log_synced"][name] is True and authority["log_truncated"][name] is False and authority["log_errors"][name] is None)
    raw_streams[name] = raw
checked("actual-receipt-equals-complete-stdout-value", parsed(raw_streams["stdout"]) == receipt)
checked("actual-receipt-original-format", v["receipt_raw"] == json.dumps(receipt, indent=2, sort_keys=True) + "\n")
checked("complete-stdout-original-format", raw_streams["stdout"] == (json.dumps(receipt, sort_keys=True) + "\n").encode())
expected_stderr = ("inputs/owned_reference_phaseb_r3.py:1088: SyntaxWarning: 'return' in a 'finally' block\n"
                   "inputs/official_cli_reference_r4.py:915: SyntaxWarning: 'return' in a 'finally' block\n")
checked("two-original-compile-warnings-preserved", raw_streams["stderr"] == expected_stderr.encode())
checked("receipt-schema-prepared-compile-only", receipt["schema"] == "heptabao.native-h2-qa-build-inert.v1" and receipt["status"] == "prepared" and receipt["python_compile_only"] is True)
for name in ("artifact_transfer_started", "compiler_started", "git_started", "service_started", "source_executed"):
    checked("no-" + name, receipt[name] is False)
elapsed = receipt["terminal_ns"] - receipt["started_ns"]
checked("observed-publication-under-original-outer", type(elapsed) is int and 0 <= elapsed < 60_000_000_000)
checked("exact-stdin-whole", receipt["stdin_bytes"] == len(request["stdin"].encode()) == 403207 and receipt["stdin_sha256"] == sha(request["stdin"].encode()) == "eb776f6c6224825da1460f87b37cb0f6db58f49d66e511195e3379f7a6e3cbc0")
carrier = parsed(request["stdin"])
expected = {base + "/" + name: base64.b64decode(body, validate=True) for name, body in carrier["files"].items()}
checked("eight-fixed-payloads", len(expected) == 8 and len(receipt["files"]) == 8 and len({x["path"] for x in receipt["files"]}) == 8)
checked("all-independent-metadata-present", len(infos) == 9 and len({x["path"] for x in infos}) == 9)
info_map = {x["path"]: x for x in infos}
checked("metadata-exact-path-set", set(info_map) == set(expected) | {base + "/inert-stage.result.public.json"})
for number, info in enumerate(infos):
    checked("metadata-custody-" + str(number), info["mode"] == 0o600 and info["metadata"]["mode"] == 0o600 and info["metadata"]["uid"] == 1000 and info["metadata"]["gid"] == 1000 and info["metadata"]["link_count"] == 1)
for number, row in enumerate(receipt["files"]):
    path = row["path"]
    raw = expected[path]
    info = info_map[path]
    identity = row["identity"]
    checked("publication-created-" + str(number), row["publication"] == "created" and row["mode"] == "0600")
    checked("publication-full9-shape-" + str(number), len(identity) == 9 and all(type(x) is int for x in identity) and identity[2:6] == [1000, 1000, 0o100600, 1])
    checked("publication-current-body-pin-" + str(number), row["bytes"] == info["size"] == identity[6] == len(raw) and row["sha256"] == info["sha256"] == sha(raw))
    version = ":".join(str(identity[index]) for index in (0, 1, 6, 7, 8))
    checked("publication-lossless-version-" + str(number), info["version"] == version)
bodies = {}
for batch_number, raw in enumerate(v["batches_raw"]):
    batch = parsed(raw)
    checked("independent-batch-not-truncated-" + str(batch_number), batch["truncated"] is False and batch["atomic_snapshot"] is False)
    for row in batch["files"]:
        path = row["path"]
        checked("unique-body-" + str(len(bodies)), path not in bodies)
        body = row["text"].encode()
        info = info_map[path]
        checked("whole-read-body-" + str(len(bodies)), row["eof"] is True and row["size"] == len(body) == info["size"] and row["sha256"] == sha(body) == info["sha256"] and row["version"] == info["version"])
        bodies[path] = body
lock_path = base + "/inputs/canonical.Cargo.lock"
lock_info = info_map[lock_path]
parts = []
offset = 0
for number, raw in enumerate(v["chunks_raw"]):
    row = parsed(raw)
    part = base64.b64decode(row["data_base64"], validate=True)
    checked("lock-chunk-metadata-" + str(number), row["path"] == lock_path and row["version"] == lock_info["version"] and row["size"] == lock_info["size"] and row["offset"] == offset)
    checked("lock-chunk-sha-boundary-" + str(number), sha(part) == row["chunk_sha256"] and row["next_offset"] == offset + len(part) and row["eof"] is (number == 1))
    parts.append(part)
    offset = row["next_offset"]
lock_body = b"".join(parts)
checked("lock-two-chunks-whole", offset == len(lock_body) == lock_info["size"] == 101193 and sha(lock_body) == lock_info["sha256"])
bodies[lock_path] = lock_body
checked("nine-whole-readback-bodies", len(bodies) == 9 and set(bodies) == set(info_map))
for number, (path, body) in enumerate(expected.items()):
    checked("actual-body-exact-carrier-" + str(number), bodies[path] == body)
checked("actual-disk-receipt-full-body-and-pin", bodies[base + "/inert-stage.result.public.json"] == v["receipt_raw"].encode() and sha(v["receipt_raw"].encode()) == info_map[base + "/inert-stage.result.public.json"]["sha256"])
checked("fifteen-unique-closed-read-labels", len(v["read_operation_labels"]) == len(set(v["read_operation_labels"])) == 15)
checked("fifteen-read-statuses-present", len(v["read_statuses"]) == 15 and {x["label"] for x in v["read_statuses"]} == set(v["read_operation_labels"]))
for record in v["read_statuses"]:
    status = parsed(record["status_raw"])
    checked("closed-stored-read-" + record["label"], status["operation_id"] == record["operation_id"] and status["async_state"] == "completed" and status["payload_available"] is True and status["owned_future_active"] is False and status["automatic_retry"] is False)
print(json.dumps({
    "schema": "heptabao.qa-r3-draft2.inert-actual-lossless-verification.v1",
    "status": "passed-inert-only",
    "job_id": job_id,
    "check_count": len(checks), "checks": checks,
    "observed_publication_elapsed_ns": str(elapsed),
    "unsafe_ns_values_preserved_as_python_integers": True,
    "actual_whole_input_bodies": 8,
    "actual_disk_receipt_bytes": len(v["receipt_raw"].encode()),
    "independent_file_info_count": 9,
    "read_operations_closed": 15,
    "original_warnings_retained": 2,
    "verification_host_calls": 0, "builder_main_or_cargo_calls": 0,
    "qa_component_runtime_qualified": False,
    "actual_build_go": False
}, indent=2, sort_keys=True))
