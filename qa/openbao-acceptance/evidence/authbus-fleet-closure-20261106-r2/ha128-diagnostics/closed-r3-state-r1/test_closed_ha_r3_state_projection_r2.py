"""Local synthetic checks of the cold projection; never invokes main/hosts."""
import base64
import importlib.util
import json
from pathlib import Path
import struct
import zlib

path = Path(__file__).with_name("observe_closed_ha_r3_state_r2.py")
spec = importlib.util.spec_from_file_location("cold", path)
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)


def frame(magic, value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return magic + struct.pack("<Q", len(raw)) + raw + struct.pack("<I", zlib.crc32(raw))


def entry(index, payload="Blank"):
    return json.dumps({"log_id": {"leader_id": {"term": 1, "node_id": 1}, "index": index},
                       "payload": payload})


def main():
    passed = []
    log = {"journal_format": 1, "journal_epoch": 1, "committed": {"index": 1},
           "log": {"1": entry(1)}}
    state = {"journal_format": 1, "generation": 2,
             "state": {"last_applied_log": {"index": 1}}}
    journal = (b"HBRLJ001" + struct.pack("<Q", 1)
               + frame(b"HBRLE001", {"Append": [[2, entry(2)]]})
               + frame(b"HBRLE001", {"Committed": {"index": 2}}))
    apply = b"HBRSJ001" + frame(b"HBRSE001", {"Apply": {"generation": 3, "entry": entry(2)}})
    inputs = (frame(b"HBRLOG01", log), journal, frame(b"HBRSB001", state), apply)
    result = cold.raft(*inputs)
    assert result["observedCommittedIndex"] == result["observedLastAppliedIndex"] == 2
    assert not result["applicationCommandsReexecuted"]
    passed.append("complete_metadata_indices")
    for position in (0, 1, 3):
        changed = list(inputs)
        changed[position] = changed[position][:-1]
        try:
            cold.raft(*changed)
        except cold.Refusal:
            passed.append("truncated_input_" + str(position))
        else:
            raise AssertionError("truncation accepted")
    changed = list(inputs)
    changed[3] = b"HBRSJ001" + frame(b"HBRSE001", {"Apply": {"generation": 4, "entry": entry(2)}})
    try:
        cold.raft(*changed)
    except cold.Refusal:
        passed.append("generation_gap_refused")
    else:
        raise AssertionError("generation gap accepted")
    try:
        cold.decode('{"x":1,"x":2}')
    except cold.Refusal:
        passed.append("duplicate_json_key_refused")
    else:
        raise AssertionError("duplicate key accepted")
    hidden = "SYNTHETIC_PRIVATE_PAYLOAD_DO_NOT_OUTPUT"
    projected = cold.entry(entry(3, {"Normal": {"serial": 7,
        "records_v5": {"Stage": {"object": {"sealed": hidden}}}}}))
    assert hidden not in json.dumps(projected) and projected["command"] == "Stage"
    passed.append("entry_payload_not_output")
    fingerprint = base64.b64encode(bytes(range(32))).decode()
    record = {"event": {"schema": 2, "sequence": 1, "previous": fingerprint,
        "time": 123, "kind": "request", "path_digest": fingerprint, "status": None},
        "mac": fingerprint}
    observed = cold.audit((json.dumps(record) + "\n").encode())
    assert fingerprint not in json.dumps(observed) and not observed["macAuthenticated"]
    assert observed["timeIsRequestClockNotResponseCompletion"]
    passed.append("audit_digest_not_output_no_auth_claim")
    print(json.dumps({"schema": "heptabao.cold-ha-r3-projection.synthetic-tests.v1",
        "passed": len(passed), "required": 8, "cases": passed,
        "actualHostReads": 0, "productExecutions": 0, "networkCalls": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
