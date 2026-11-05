import base64
import hashlib
import json
import pathlib
import stat

ROOT = pathlib.Path("/workspace/scratch/f86faac821c4/source4e808_inert_actual_r1")
data = json.loads((ROOT / "input.json").read_text())
checks = []
def check(name, value):
    if not isinstance(value, bool):
        raise TypeError(name)
    checks.append({"name": name, "passed": value})
    if not value:
        raise AssertionError(name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def text_from_sdk(sdk):
    check("original complete SDK result", sdk.get("resultType") == "complete" and sdk.get("isError") is False)
    text_items = [entry["text"] for entry in sdk["content"] if entry["type"] == "text"]
    check("one original native text", len(text_items) == 1)
    return text_items[0]

go_raw, request_raw = data["go_raw"], data["request_raw"]
go, request = json.loads(go_raw), json.loads(request_raw)
source_raw, inert_raw = data["source_raw"], data["inert_raw"]
check("exact approved request bytes and blob",
      len(request_raw.encode()) == 25931
      and sha(request_raw.encode()) == "0e6e356403b756d599d2a90e5792e147f2df2f1b59323f7057a169ebc68fabe8"
      and blob(request_raw.encode()) == "6b00d3d5d8f1fb95e3aa7b302c966180396ae61b")
check("exact root GO blob",
      blob(go_raw.encode()) == "81c17a0f21d42211229f8b14ba9d4105a152c02b"
      and go["maximum_submissions"] == 1
      and go["exact_request"]["sha256"] == sha(request_raw.encode()))
check("one explicit external intent and submission",
      data["submit_count"] == 1
      and json.loads(data["external_intent_raw"])["exact_request"]["blob"] == go["exact_request"]["blob"])
ack_raw = data["ack_raw"]
ack = json.loads(ack_raw)
job = ack["job"]
check("actual unique ACK not reused",
      ack["reused"] is False and job["id"] == "1a1abb9785a-fc05-5029"
      and job["launch_state"] == "launched" and job["launch_error"] is None)
check("actual ACK exact source argv and host",
      job["host"] == request["host"] == "rog"
      and job["executable"] == request["executable"] == "/usr/bin/python3"
      and job["args"] == request["args"] == ["-I", "-S", "-B", "-c", inert_raw]
      and job["cwd"] == request["cwd"] == "/home/qian-qi"
      and job["idempotency_key"] == request["idempotency_key"]
      and job["env_keys"] == [])
payload = json.loads(request["stdin"])
source_name = "source_export_same_root_publication_4e808_r1.py"
check("source in exact carrier",
      base64.b64decode(payload["files"][source_name], validate=True) == source_raw.encode())
check("actual source source-only packet pin",
      len(source_raw.encode()) == 15364
      and sha(source_raw.encode()) == "9af6738da8526ad5a0dcd6402bf4693f652a4f428eb4b22d0914761292f66d20")

natives = {}
operation_summaries = []
for label, row in data["operations"].items():
    operation_request = json.loads(row["request_raw"])
    admission = json.loads(row["admission_raw"])
    status = json.loads(row["status_raw"])
    op_id = admission["operation_id"]
    check(label + " admission and status original same operation",
          op_id == status["operation_id"]
          and admission["tool_name"] == operation_request["operation"]["tool"])
    check(label + " observation closed with retained original payload",
          status["async_state"] == "completed"
          and status["result_state"] == "stored_observed"
          and status["owned_future_active"] is False
          and status["payload_available"] is True)
    pieces = []
    expected_offset = 0
    snapshot = None
    for page_raw in row["pages_raw"]:
        page = json.loads(page_raw)
        raw = base64.b64decode(page["data_base64"], validate=True)
        if snapshot is None:
            snapshot = (page["total_bytes"], page["result_sha256"])
        check(label + " exact immutable page continuity at " + str(expected_offset),
              page["operation_id"] == op_id
              and page["immutable_snapshot"] is True
              and page["offset"] == expected_offset
              and page["next_offset"] == expected_offset + len(raw)
              and (page["total_bytes"], page["result_sha256"]) == snapshot
              and 0 < len(raw) <= 8192
              and page["payload_kind"] == "native_result")
        expected_offset = page["next_offset"]
        pieces.append(raw)
    combined = b"".join(pieces)
    check(label + " complete page EOF and whole original SHA",
          page["eof"] is True and expected_offset == snapshot[0]
          and len(combined) == snapshot[0] and sha(combined) == snapshot[1])
    check(label + " raw reconstructed original SDK exact",
          combined == row["payload_raw"].encode())
    native_raw = text_from_sdk(json.loads(combined))
    check(label + " original native exact", native_raw == row["native_raw"])
    natives[label] = json.loads(native_raw)
    operation_summaries.append({"label": label, "operation_id": op_id,
                                "payload_bytes": len(combined), "payload_sha256": sha(combined),
                                "pages": len(pieces)})
check("exact six read operations only",
      set(natives) == {"authority", "streams", "source-info", "receipt-info", "source-body", "receipt-body"})
authority = natives["authority"]
check("authoritative job terminal successful and durable",
      authority["job_id"] == job["id"]
      and authority["state"] == "succeeded" and authority["exit_code"] == 0
      and authority["timed_out"] is False and authority["cancelled"] is False
      and authority["output_complete"] is True and authority["output_durable"] is True
      and authority["terminal_publication_confirmed"] is True)
streams = natives["streams"]
check("streams same one job", streams["job_id"] == job["id"])
for stream_name in ("stdout", "stderr"):
    row = streams[stream_name]
    raw = bytes.fromhex(row["bytes_hex"])
    check(stream_name + " complete byte offsets and EOF",
          row["offset"] == 0 and row["eof"] is True
          and row["next_offset"] == row["size"] == len(raw))
    check(stream_name + " text and hex and saved body exact",
          raw == row["text"].encode() == data[stream_name + "_raw"].encode())
    check(stream_name + " authority full synced not truncated",
          authority["log_bytes"][stream_name] == {"seen": len(raw), "stored": len(raw)}
          and authority["log_errors"][stream_name] is None
          and authority["log_synced"][stream_name] is True
          and authority["log_truncated"][stream_name] is False)
check("complete original stderr empty", data["stderr_raw"] == "")
check("complete stdout 837 bytes", len(data["stdout_raw"].encode()) == 837)
terminal = json.loads(data["stdout_raw"])

base = "/home/qian-qi/heptabao-same-root-publication-source-export-controls-20261105-r1"
for label, expected_path in (
    ("source", base + "/" + source_name),
    ("receipt", base + "/inert-stage.result.public.json"),
):
    info = natives[label + "-info"]
    content = natives[label + "-body"]
    raw = base64.b64decode(content["data_base64"], validate=True)
    check(label + " independent exact path mode uid gid nlink",
          info["path"] == expected_path and info["metadata"]["mode"] == 0o600
          and info["metadata"]["uid"] == 1000 and info["metadata"]["gid"] == 1000
          and info["metadata"]["link_count"] == 1)
    check(label + " expected_version request exact actual info",
          json.loads(data["operations"][label + "-body"]["request_raw"])["operation"]["arguments"]
          == {"host": "rog", "path": expected_path, "expected_version": info["version"],
              "offset": 0, "limit": 16384})
    check(label + " full pinned binary read exact",
          content["path"] == expected_path and content["version"] == info["version"]
          and content["offset"] == 0 and content["next_offset"] == info["size"]
          and content["eof"] is True and len(raw) == info["size"]
          and sha(raw) == info["sha256"])
    check(label + " saved body exact native binary", raw == data[label + "_body_raw"].encode())
    if label == "source":
        check("actual source whole body equals reviewed exporter", raw == source_raw.encode())
    else:
        receipt = json.loads(raw)
        check("actual receipt whole JSON equals original stdout",
              receipt == terminal)
        check("receipt exact original publisher formatting",
              raw == (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())

check("inert actual status and schema",
      terminal["status"] == "prepared"
      and terminal["schema"] == "heptabao.same-root-publication-4e808-source-export-inert-carrier.v1")
check("one exact published source", len(terminal["files"]) == 1)
published = terminal["files"][0]
check("published source expected mode byte hash path",
      published["path"] == base + "/" + source_name
      and published["publication"] == "created" and published["mode"] == "0600"
      and published["bytes"] == len(source_raw.encode()) and published["sha256"] == sha(source_raw.encode()))
ident = published["identity"]
info = natives["source-info"]
check("exact nine source identity and native version without JS rounding",
      len(ident) == 9 and all(type(value) is int for value in ident)
      and ident[2:4] == [1000, 1000] and stat.S_ISREG(ident[4])
      and stat.S_IMODE(ident[4]) == 0o600 and ident[5] == 1 and ident[6] == info["size"]
      and ":".join(str(ident[index]) for index in (0, 1, 6, 7, 8)) == info["version"])
check("exact original stdin payload binding",
      terminal["stdin_bytes"] == len(request["stdin"].encode())
      and terminal["stdin_sha256"] == sha(request["stdin"].encode()))
check("Python compile only no child product source execution",
      terminal["python_compile_only"] is True
      and all(terminal[key] is False for key in (
          "source_executed", "git_started", "compiler_started", "service_started",
          "artifact_transfer_started")))
check("original external 60s and lossless actual interval",
      request["timeout_seconds"] == 60
      and type(terminal["started_ns"]) is int and type(terminal["terminal_ns"]) is int
      and 0 <= terminal["terminal_ns"] - terminal["started_ns"] < 60_000_000_000)
result = {
    "schema": "heptabao.current4e808-exporter-inert-actual-verification.v1",
    "status": "passed_inert_only", "job_id": job["id"], "checks_count": len(checks),
    "checks": checks, "operations": operation_summaries,
    "elapsed_ns": str(terminal["terminal_ns"] - terminal["started_ns"]),
    "inputs_source_body_matches": True, "receipt_body_matches": True,
    "source_execute_export_transport_import_or_product": False,
    "old_unknown_or_failures_replayed": False,
    "unsafe_integer_comparison": "Python exact int from original native bytes; no JS numeric reserialization",
}
raw = json.dumps(result, indent=2) + "\n"
(ROOT / "result.public.json").write_text(raw)
print(raw, end="")
