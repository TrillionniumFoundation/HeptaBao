#!/usr/bin/env python3
"""Offline verification of the exact X230 inert originals. No candidate execution."""
from pathlib import Path
import argparse, base64, hashlib, json, stat, sys, traceback

ROOT = Path(__file__).resolve().parents[1]
checks = []

def check(ok, name):
    checks.append({"name": name, "passed": bool(ok)})
    if not ok:
        raise AssertionError(name)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)

def read(path):
    return (ROOT / path).read_bytes()

def obj(path):
    return parse(read(path))

def sdk_text(path):
    value = obj(path + ".sdk.json")
    check(value.get("isError", False) is False, path + " SDK success")
    text = [row["text"] for row in value["content"] if row["type"] == "text"]
    check(len(text) == 1 and text[0].encode() == read(path + ".json"), path + " exact SDK/native")
    return parse(text[0])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap")
    args = parser.parse_args()
    if args.bootstrap:
        bootstrap = parse(Path(args.bootstrap).read_bytes())
        check(bootstrap["root"] == str(ROOT), "bootstrap root is owned scratch")
        for path, raw in bootstrap["files"].items():
            check(not Path(path).is_absolute() and ".." not in Path(path).parts, "safe relative artifact " + path)
            target = ROOT / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw.encode())
        inventory = {"schema": "heptabao.x230-inert.original-input-pins.v1",
                     "files": bootstrap["pins"]}
        (ROOT / "verification/original-input-pins.public.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    inventory = obj("verification/original-input-pins.public.json")
    for row in inventory["files"]:
        raw = read(row["path"])
        check(len(raw) == row["bytes"] and sha(raw) == row["sha256"] and blob(raw) == row["blob"],
              "whole bytes/SHA/Git " + row["path"])

    request = obj("reference/request.original.json")
    go = obj("reference/go.original.json")
    check(request["host"] == "desktop" and request["executable"] == "/usr/bin/python3"
          and request["cwd"] == "/home/qian-qi/heptabao-ha-closure-20261103-r1"
          and request["timeout_seconds"] == 60, "exact process host/executable/cwd/outer")
    check(request["args"] == ["-I", "-S", "-B", "-c", read("reference/publisher.py").decode()],
          "exact inline publisher, no added argv")
    check(request["stdin"].encode() == read("reference/stdin.original.json")
          and len(request["stdin"].encode()) == 87425
          and sha(request["stdin"].encode()) == go["stdin"]["sha256"], "exact carried stdin")
    binding = {
        "args": request.get("args", []), "cpu_quota_percent": request.get("cpu_quota_percent"),
        "cwd": request.get("cwd"), "env": request.get("env", {}),
        "executable": request["executable"], "host": request["host"],
        "memory_max_bytes": request.get("memory_max_bytes"), "nice": request.get("nice"),
        "stdin": request.get("stdin"), "timeout_seconds": request.get("timeout_seconds"),
    }
    canonical = json.dumps(binding, ensure_ascii=False, separators=(",", ":")).encode()
    check(canonical == read("verification/typed-request-canonical.json"), "typed request canonical exact")
    digest = sha(canonical)
    check(digest == go["exact_process_start"]["request_digest_sha256"], "typed request digest")
    check(str(int(digest[:16], 16)) == go["exact_process_start"]["request_fingerprint_decimal"], "lossless fingerprint")

    start = sdk_text("execution/start.original")
    job = start["job"]
    check(job["args"] == request["args"] and job["cwd"] == request["cwd"]
          and job["executable"] == request["executable"] and job["host"] == request["host"]
          and job["idempotency_key"] == request["idempotency_key"], "ACK exact request binding")
    check(job["request_digest"] == digest and str(job["request_fingerprint"]) == "8732753680660856899",
          "ACK exact digest and original u64 fingerprint")
    check(start["reused"] is False and job["launch_state"] == "launched"
          and job["launch_error"] is None and start["launch"]["ok"] is True
          and start["local_record_pending"] is False, "unique launch known accepted")
    job_id = job["id"]
    check(job_id == "1a1ace08ffa-fc05-576b", "original job identity")

    index = obj("observations/index.public.json")
    expected_labels = ["authority", "streams"] + ["info-" + r for r in ("sender", "receiver", "relay", "receipt")] + ["body-" + r for r in ("sender", "receiver", "relay", "receipt")]
    check([r["label"] for r in index["observers"]] == expected_labels, "exact ten read observers")
    check(index["observer_count"] == 10 and index["immutable_page_count"] == 14
          and index["current_tool_calls_in_flight"] == 0
          and index["current_known_owned_futures_active"] == 0, "declared finite closed read set")
    operations = {}
    read_keys = []
    for row in index["observers"]:
        label, operation_id = row["label"], row["operation_id"]
        req = obj(row["request"])
        read_keys.append(req["idempotency_key"])
        admission = sdk_text(row["admission"])
        status = sdk_text(row["status"])
        check(admission["operation_id"] == operation_id and admission["tool_name"] == req["operation"]["tool"]
              and admission["reused"] is False, label + " native admission exact")
        check(status["operation_id"] == operation_id and status["tool_name"] == req["operation"]["tool"]
              and status["async_state"] == "completed" and status["result_state"] == "stored_observed"
              and status["owned_future_active"] is False and status["payload_available"] is True,
              label + " original observer closed")
        check(obj("observations/" + label + "/status.exact-request.json") == {"operation_id": operation_id},
              label + " status same ID")
        pieces, offset, digest_seen, total_seen = [], 0, None, None
        for number, page_path in enumerate(row["pages"]):
            page = sdk_text(page_path)
            check(obj(page_path + ".request.json") == {"operation_id": operation_id, "offset": offset, "limit": 16384},
                  label + " immutable page request " + str(number))
            data = base64.b64decode(page["data_base64"], validate=True)
            if number == 0:
                digest_seen, total_seen = page["result_sha256"], page["total_bytes"]
            check(page["operation_id"] == operation_id and page["offset"] == offset
                  and page["next_offset"] == offset + len(data) and len(data) <= 16384
                  and page["immutable_snapshot"] is True and page["payload_kind"] == "native_result"
                  and page["result_sha256"] == digest_seen and page["total_bytes"] == total_seen
                  and page["eof"] is (number == len(row["pages"]) - 1), label + " immutable page contract " + str(number))
            pieces.append(data)
            offset = page["next_offset"]
        payload = b"".join(pieces)
        check(offset == total_seen == len(payload) and sha(payload) == digest_seen
              and payload == read(row["original_payload"]), label + " whole original native SDK payload")
        sdk = parse(payload)
        check(sdk.get("isError", False) is False and sdk["resultType"] == "complete", label + " original handler success")
        contents = [r["text"] for r in sdk["content"] if r["type"] == "text"]
        check(len(contents) == 1 and contents[0].encode() == read(row["native"]), label + " original content exact")
        operations[label] = {"request": req, "native": parse(contents[0])}
    check(len(set(read_keys)) == 10 and len(set(r["operation_id"] for r in index["observers"])) == 10,
          "unique ten native observations, no business retry")
    check(operations["authority"]["request"]["operation"] == {"tool": "process_status", "arguments": {"host": "desktop", "job_id": job_id}},
          "authority exact original job")
    check(operations["streams"]["request"]["operation"] == {"tool": "process_read", "arguments": {"host": "desktop", "job_id": job_id, "limit": 16384, "stdout_offset": 0, "stderr_offset": 0}},
          "streams exact original job and ranges")

    old_error = obj("observations/streams/status.original.sdk.json")
    check(old_error.get("isError") is True and len(old_error["content"]) == 1
          and old_error["content"][0]["text"].encode() == read("observations/streams/status.error.original.txt")
          and "MCP request timed out" in old_error["content"][0]["text"], "original status transport error preserved")
    recovery = obj("reference/recovery-go.original.json")
    check(recovery["exact_status_request"] == obj("observations/streams/status.exact-request.json")
          and recovery["exact_status_request"]["operation_id"] == operations["streams"]["request"]["operation"]["arguments"]["job_id"].replace(job_id, index["observers"][1]["operation_id"]),
          "recovery only same operation identity")
    check(obj("historical/PARTIAL_AFTER_STREAM_STATUS_ERROR.public.json")["stream_future_state"] == "UNKNOWN_after_status_RPC_error",
          "earlier partial UNKNOWN retained without rewrite")

    authority = operations["authority"]["native"]
    check(authority["job_id"] == job_id and authority["exit_code"] == 0 and authority["state"] == "succeeded"
          and authority["output_complete"] is True and authority["output_durable"] is True
          and authority["terminal_publication_confirmed"] is True
          and authority["cancelled"] is False and authority["timed_out"] is False, "original process success terminal")
    streams = operations["streams"]["native"]
    check(streams["job_id"] == job_id, "streams original job")
    for role, size in (("stdout", 1514), ("stderr", 0)):
        row = streams[role]
        raw = read("actual/" + role + ".original.txt")
        check(raw == bytes.fromhex(row["bytes_hex"]) == row["text"].encode()
              and row["eof"] is True and row["offset"] == 0
              and row["next_offset"] == row["size"] == size == len(raw),
              role + " complete bytes/hex/text/EOF")
        check(authority["log_bytes"][role] == {"seen": size, "stored": size}
              and authority["log_errors"][role] is None
              and authority["log_synced"][role] is True and authority["log_truncated"][role] is False,
              role + " authority complete durable log")
    stdout = parse(read("actual/stdout.original.txt"))
    receipt = obj("actual/inert-stage.result.public.json")
    check(stdout == receipt, "lossless stdout and independent disk receipt equal")
    check((json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode() == read("actual/inert-stage.result.public.json"),
          "original publisher exact disk JSON serialization")
    check((json.dumps(receipt, sort_keys=True) + "\n").encode() == read("actual/stdout.original.txt"),
          "original publisher exact stdout serialization")
    check(set(receipt) == {"artifact_transfer_started", "compiler_started", "files", "git_started", "python_compile_only", "schema", "service_started", "source_executed", "started_ns", "status", "stdin_bytes", "stdin_sha256", "terminal_ns"},
          "closed receipt fields")
    check(receipt["schema"] == "heptabao.4e808-x230-normal7-inert-carrier.v1"
          and receipt["status"] == "prepared" and receipt["python_compile_only"] is True
          and all(receipt[k] is False for k in ("artifact_transfer_started", "compiler_started", "git_started", "service_started", "source_executed")),
          "only inert publication and Python compile")
    elapsed = receipt["terminal_ns"] - receipt["started_ns"]
    check(elapsed == 156215242 and 0 < elapsed < 60 * 1000000000, "original integer clock interval within outer60")
    check(receipt["stdin_bytes"] == 87425 and receipt["stdin_sha256"] == sha(request["stdin"].encode()),
          "actual exact stdin proof")

    carried = parse(request["stdin"])
    check(carried["schema"] == "heptabao.4e808-x230-normal7-inputs.v1"
          and set(carried["files"]) == {"sender.py", "receiver.py", "relay.py"}, "exact carried source names")
    expected = [
        ("sender", "sender.py", 8960, "aac98a6512ccdfc525de9dd5cf544f474220d3415631ea39537672b21ca4b663"),
        ("receiver", "receiver.py", 30791, "8aa027334ad2a99603b0c54bcbe80ff67c194104aea0b5cbf44b68eb82447471"),
        ("relay", "relay.py", 25713, "cc5a9ed329bda9d1b51cf42343b3a9898516c1136b035fc63abb688982a9612f"),
        ("receipt", "inert-stage.result.public.json", 1924, "22bb50e3e627fe07f5b344711790802f45ccb079115c1bcbff70d1bdc889b0ca"),
    ]
    identity_table = obj("actual/identity-table.public.json")["files"]
    base = go["scope"]["create_only_root"]
    check(len(receipt["files"]) == 3 and len(identity_table) == 4, "exact three source and four identity records")
    total_body = 0
    for i, (role, name, size, digest) in enumerate(expected):
        info = operations["info-" + role]["native"]
        body = operations["body-" + role]["native"]
        raw = read("actual/" + name)
        path = base + "/" + name
        check(operations["info-" + role]["request"]["operation"] == {"tool": "file_info", "arguments": {"host": "desktop", "path": path}},
              role + " exact authorized independent info")
        check(info["path"] == path and info["size"] == size and info["sha256"] == digest
              and info["mode"] == 0o600 and info["metadata"]["mode"] == 0o600
              and info["metadata"]["uid"] == 1000 and info["metadata"]["gid"] == 1000
              and info["metadata"]["link_count"] == 1 and info["metadata"]["metadata_platform"] == "linux",
              role + " independent file pin and ownership")
        dev, ino, vsize, mtime, ctime = map(int, info["version"].split(":"))
        full9 = [dev, ino, 1000, 1000, stat.S_IFREG | 0o600, 1, vsize, mtime, ctime]
        check(vsize == size and identity_table[i]["full9_decimal"] == list(map(str, full9))
              and identity_table[i]["version"] == info["version"], role + " lossless original full9/version")
        check(operations["body-" + role]["request"]["operation"] == {"tool": "binary_read", "arguments": {"host": "desktop", "path": path, "expected_version": info["version"], "offset": 0, "limit": 65536}},
              role + " exact version-bound body request")
        decoded = base64.b64decode(body["data_base64"], validate=True)
        check(body["path"] == path and body["version"] == info["version"]
              and body["offset"] == 0 and body["next_offset"] == body["size"] == size
              and body["eof"] is True and body["chunk_sha256"] == digest
              and decoded == raw and len(raw) == size and sha(raw) == digest,
              role + " whole body bound to independent metadata")
        total_body += len(raw)
        if role != "receipt":
            check(raw == read("reference/" + role + ".candidate.py")
                  == base64.b64decode(carried["files"][name], validate=True), role + " actual/candidate/carrier whole equality")
            published = receipt["files"][i]
            check(set(published) == {"bytes", "identity", "mode", "path", "publication", "sha256"}
                  and published["path"] == path and published["bytes"] == size
                  and published["sha256"] == digest and published["mode"] == "0600"
                  and published["publication"] == "created" and published["identity"] == full9,
                  role + " lossless publisher identity exact")
    check(total_body == 67388 and total_body <= 131072 and all(size <= 65536 for _, _, size, _ in expected),
          "fixed four-body byte ceilings")
    result = {
        "schema": "heptabao.current4e808.x230-inert-offline-actual-verification.v1",
        "status": "PASS_INERT_ONLY",
        "checks": checks,
        "check_count": len(checks),
        "job_id": job_id,
        "process_start_count": 1,
        "native_read_operation_count": 10,
        "immutable_page_count": 14,
        "original_status_RPC_error_count": 1,
        "original_status_same_ID_recovery_count": 1,
        "all_original_observers_closed": True,
        "current_tool_calls_in_flight": 0,
        "publisher_elapsed_ns_decimal": str(elapsed),
        "actual_files": identity_table,
        "relay_executed": False,
        "old_relay_state": "UNKNOWN preserved",
        "effect_fence_scope": "Retained future relay precondition. Inert did not execute relay or newly observe the fence.",
        "qualification": "Only exact create-only publication and Python compilation of three public control sources. No seven-file transfer, X230 source import, service, full34, comparison69, or production qualification.",
        "verification_execution": "Offline Python only; no candidate source/functions, network, subprocess, or host operations.",
    }
    (ROOT / "verification/verification-result.public.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "check_count": len(checks),
                      "original_files": len(inventory["files"]), "observers": 10, "pages": 14,
                      "elapsed_ns": str(elapsed)}, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        failure = {"schema": "heptabao.x230-inert.offline-verification-failure.v1",
                   "status": "VERIFIER_FAILED", "error_type": type(error).__name__,
                   "error": str(error), "checks": checks}
        (ROOT / "verification").mkdir(parents=True, exist_ok=True)
        (ROOT / "verification/verification-failure.public.json").write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n")
        traceback.print_exc()
        sys.exit(1)

