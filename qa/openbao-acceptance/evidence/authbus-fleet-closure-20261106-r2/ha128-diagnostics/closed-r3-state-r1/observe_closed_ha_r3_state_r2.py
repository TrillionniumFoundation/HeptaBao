"""Read five fixed files in one already-closed synthetic HA-r3 fixture.

No product execution, key access, data decryption, request replay, file write,
child or network. Public output contains only audit kinds/status/time and Raft
indices/counters. It is a structural cold observation, not a recovery validator
or an authenticated audit/committed-root/readability certificate.
"""
import base64
import collections
import json
import os
import platform
import signal
import stat
import struct
import sys
import time
import zlib

ROOTS = {
    "x230": ("Linux", "qian-ThinkPad-X230", 1000,
             "/home/qian/heptabao-native-ha-4bde9-authbus-20261106-r3"),
    "ai395": ("Linux", "ai395", 1000,
              "/home/qq/heptabao-native-ha-4bde9-authbus-20261106-r3"),
    "mac": ("Darwin", None, 501,
            "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/native-ha-4bde9-authbus-node-r3"),
}
FILES = ("audit.jsonl", "raft/log/raft-log.bin", "raft/log/raft-log.journal",
         "raft/state-machine/state-bundle.bin", "raft/state-machine/state-machine.journal")
KINDS = {"request", "response", "wire-rejection", "wire-response",
         "initialization-response-prepared"}
COMMANDS = {"EnrollNativeV6", "PublishNativeV6", "BeginNativeV6EpochRestore",
            "CancelNativeV6EpochRestore", "PublishNativeV6EpochRestore",
            "RetireNativeV6Intents", "ActivateNativeV6RetainedRoots",
            "RetainLegacyChunks", "Stage", "Publish", "Prune"}
CAP = 8 * 1024 * 1024
TOTAL_CAP = 32 * 1024 * 1024


class Refusal(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def uint(value):
    need(type(value) is int and 0 <= value < 2**64, "unsigned_integer")
    return value


def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, "duplicate_json_key")
        out[key] = value
    return out


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def index(value):
    if value is None:
        return None
    need(type(value) is dict and "index" in value, "log_id_shape")
    return uint(value["index"])


def intent_counters(command):
    need(type(command) is dict and type(command.get("intent")) is dict, "intent_shape")
    value = command["intent"]
    names = ("epoch", "object_count", "ciphertext_bytes", "prior_generation",
             "proposed_generation", "expected_previous_commit_index")
    result = {name: uint(value[name]) for name in names}
    need(result["proposed_generation"] == result["prior_generation"] + 1,
         "intent_generation")
    return result


def entry(text):
    need(type(text) is str, "entry_string")
    value = decode(text)
    need(type(value) is dict and set(value) == {"log_id", "payload"}, "entry_shape")
    result = {"index": index(value["log_id"])}
    payload = value["payload"]
    if payload == "Blank":
        result["kind"] = "Blank"
    else:
        need(type(payload) is dict and len(payload) == 1, "payload_shape")
        kind, body = next(iter(payload.items()))
        need(kind in {"Normal", "Membership"}, "payload_kind")
        result["kind"] = kind
        if kind == "Normal":
            need(type(body) is dict, "application_shape")
            if "records_v5" in body:
                command = body["records_v5"]
                need(type(command) is dict and len(command) == 1, "command_shape")
                name, args = next(iter(command.items()))
                need(name in COMMANDS, "command_kind")
                result["command"] = name
                if name == "PublishNativeV6":
                    result["publicationIntentCounters"] = intent_counters(args["root"])
            else:
                need(set(body) == {"client", "serial", "status"}, "legacy_shape")
                result["command"] = "Legacy"
    return result


def envelope(raw, magic, offset=0):
    need(len(raw) - offset >= 20 and raw[offset:offset + 8] == magic, "frame_header")
    size = struct.unpack_from("<Q", raw, offset + 8)[0]
    end = offset + 20 + size
    need(size <= CAP and end <= len(raw), "frame_size")
    body = raw[offset + 16:end - 4]
    need(zlib.crc32(body) == struct.unpack_from("<I", raw, end - 4)[0], "frame_crc")
    return decode(body), end


def checkpoint(raw, magic):
    value, end = envelope(raw, magic)
    need(end == len(raw) and type(value) is dict, "checkpoint_eof")
    return value


def frames(raw, magic, offset):
    result = []
    while offset < len(raw):
        need(len(result) < 4096, "frame_count")
        value, offset = envelope(raw, magic, offset)
        need(type(value) is dict and len(value) == 1, "journal_event_shape")
        result.append(value)
    need(offset == len(raw), "journal_eof")
    return result


def audit(raw):
    need(raw.endswith(b"\n") and not raw.startswith(b"\n") and b"\n\n" not in raw,
         "audit_framing")
    rows = raw.splitlines()
    need(0 < len(rows) <= 4096, "audit_count")
    previous = None
    sequence = None
    tail = []
    counts = collections.Counter()
    for line in rows:
        value = decode(line)
        need(type(value) is dict and set(value) == {"event", "mac"}, "audit_record")
        event = value["event"]
        need(type(event) is dict and set(event) == {
            "schema", "sequence", "previous", "time", "kind", "path_digest", "status"
        } and event["schema"] == 2, "audit_event")
        current = uint(event["sequence"])
        need(sequence is None or current == sequence + 1, "audit_sequence")
        need(previous is None or event["previous"] == previous, "audit_chain_links")
        for item in (value["mac"], event["previous"], event["path_digest"]):
            need(type(item) is str and len(base64.b64decode(item, validate=True)) == 32,
                 "audit_digest_shape")
        need(event["kind"] in KINDS, "audit_kind")
        status = event["status"]
        need(status is None or type(status) is int and 100 <= status <= 599, "audit_status")
        counts[event["kind"]] += 1
        tail.append({"sequence": current, "requestClockSeconds": uint(event["time"]),
                     "kind": event["kind"], "status": status})
        previous, sequence = value["mac"], current
    return {"records": len(rows), "kinds": dict(counts), "last64": tail[-64:],
            "macAuthenticated": False, "keysRead": False,
            "timeIsRequestClockNotResponseCompletion": True,
            "routeOrActorAssociationProven": False}


def raft(log_raw, log_journal, state_raw, state_journal):
    log = checkpoint(log_raw, b"HBRLOG01")
    state = checkpoint(state_raw, b"HBRSB001")
    need(log.get("journal_format") == state.get("journal_format") == 1, "journal_format")
    need(log_journal[:8] == b"HBRLJ001" and len(log_journal) >= 16, "log_journal_header")
    epoch = struct.unpack_from("<Q", log_journal, 8)[0]
    need(epoch == uint(log["journal_epoch"]) and epoch > 0, "log_journal_epoch")
    need(state_journal[:8] == b"HBRSJ001", "state_journal_header")
    need(type(log["log"]) is dict, "checkpoint_log")
    serialized = {uint(int(k)): value for k, value in log["log"].items()}
    need(len(serialized) == len(log["log"]), "numeric_log_key_alias")
    committed = index(log["committed"])
    events = frames(log_journal, b"HBRLE001", 16)
    for event in events:
        kind, value = next(iter(event.items()))
        if kind == "Vote":
            need(type(value) is dict, "vote_shape")
        elif kind == "Committed":
            committed = index(value)
        elif kind == "Append":
            need(type(value) is list, "append_shape")
            for pair in value:
                need(type(pair) is list and len(pair) == 2, "append_pair")
                key, text = uint(pair[0]), pair[1]
                need(key not in serialized or serialized[key] == text, "log_conflict")
                need(entry(text)["index"] == key, "entry_index")
                serialized[key] = text
        elif kind == "Truncate":
            start = uint(value["start"])
            serialized = {k: v for k, v in serialized.items() if k < start}
        elif kind == "Purge":
            stop = index(value["log_id"])
            need(stop is not None, "purge_index")
            serialized = {k: v for k, v in serialized.items() if k > stop}
        else:
            raise Refusal("log_event_kind")
    entries = [entry(serialized[k]) for k in sorted(serialized)]
    base_index = index(state["state"]["last_applied_log"])
    generation = uint(state["generation"])
    applied = base_index
    state_events = frames(state_journal, b"HBRSE001", 8)
    applied_entries = []
    for event in state_events:
        need(set(event) == {"Apply"} and type(event["Apply"]) is dict, "state_event_kind")
        value = event["Apply"]
        next_generation = uint(value["generation"])
        observed = entry(value["entry"])
        if next_generation <= generation:
            need(applied is not None and observed["index"] <= applied, "checkpoint_coverage")
            continue
        need(next_generation == generation + 1, "state_generation_gap")
        need(applied is None or observed["index"] == applied + 1, "state_index_gap")
        generation, applied = next_generation, observed["index"]
        applied_entries.append(observed)
    checkpoint_root = state["state"].get("v6_root")
    result = {
        "checkpointLastAppliedIndex": base_index, "observedLastAppliedIndex": applied,
        "observedStateGeneration": generation, "observedCommittedIndex": committed,
        "remainingLogEntries": len(entries), "last24LogEntries": entries[-24:],
        "logJournalEvents": len(events), "stateJournalEvents": len(state_events),
        "last24AppliedEntries": applied_entries[-24:],
        "frameCrcAndEofChecked": True, "journalRepairedOrTruncated": False,
        "applicationCommandsReexecuted": False, "applicationRejectionStateReconstructed": False,
        "ciphertextClosureValidated": False, "kvVersionReadabilityProven": False,
    }
    if checkpoint_root is not None:
        result["checkpointNativePublicationIndex"] = index(checkpoint_root["publication_log"])
        result["checkpointNativeIntentCounters"] = intent_counters(checkpoint_root["command"])
    return result


def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def main():
    began = time.monotonic()
    output = {"schema": "heptabao.closed-ha-r3-cold-observation.v1", "ok": False,
              "originalJob": "1a1b357f5e0-fc05-8241", "productExecutions": 0,
              "children": 0, "networkCalls": 0, "filesWritten": 0,
              "keyFilesRead": 0, "valueOrDigestOutput": False}
    held, directory_checks, file_checks = [], [], []
    opened, closed, close_errors = 0, 0, 0
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in ROOTS, "host_selection")
        role = sys.argv[1]
        system, hostname, uid, root = ROOTS[role]
        need(platform.system() == system and os.geteuid() == uid, "host_identity")
        need(hostname is None or platform.node() == hostname, "host_name")
        output["node"] = role
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refusal("deadline")))
        signal.setitimer(signal.ITIMER_REAL, 12)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        held.append(fd)
        opened += 1
        for component in root.split("/")[1:]:
            parent = fd
            fd = os.open(component, flags, dir_fd=parent)
            held.append(fd)
            opened += 1
            st = os.fstat(fd)
            need(stat.S_ISDIR(st.st_mode), "ancestor_directory")
            directory_checks.append((parent, component, fd, identity(st)[:5]))
        root_fd = fd
        root_st = os.fstat(root_fd)
        need(root_st.st_uid == uid and stat.S_IMODE(root_st.st_mode) == 0o700,
             "private_fixture_root")
        inputs = []
        total = 0
        metadata = []
        for ordinal, relative in enumerate(FILES, 1):
            parent = root_fd
            parts = relative.split("/")
            for component in parts[:-1]:
                child = os.open(component, flags, dir_fd=parent)
                held.append(child)
                opened += 1
                st = os.fstat(child)
                # These exact Rust-created directories remain below the held
                # original 0700 fixture root (and original 0700 raft parent).
                # The observed 0775 does not grant traversal through that root.
                enclosed_mode = (component in ("log", "state-machine")
                                 and stat.S_IMODE(st.st_mode) == 0o775
                                 and stat.S_IMODE(os.fstat(parent).st_mode) == 0o700)
                need(stat.S_ISDIR(st.st_mode) and st.st_uid == uid
                     and (st.st_mode & 0o022 == 0 or enclosed_mode),
                     "owned_inner_directory")
                directory_checks.append((parent, component, child, identity(st)[:5]))
                parent = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                           os.O_NONBLOCK, dir_fd=parent)
            held.append(leaf)
            opened += 1
            st = os.fstat(leaf)
            original = identity(st)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == uid and st.st_nlink == 1
                 and (st.st_mode & 0o022 == 0 or
                      relative in FILES[1:] and stat.S_IMODE(st.st_mode) == 0o664)
                 and st.st_size <= CAP, "bounded_owned_file")
            need(identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) == original,
                 "file_path_binding")
            raw = bytearray()
            while True:
                chunk = os.read(leaf, 65536)
                if not chunk:
                    break
                raw.extend(chunk)
                total += len(chunk)
                need(len(raw) <= st.st_size and len(raw) <= CAP and total <= TOTAL_CAP,
                     "read_cap")
            need(len(raw) == st.st_size and identity(os.fstat(leaf)) == original, "file_changed")
            file_checks.append((parent, parts[-1], leaf, original))
            inputs.append(bytes(raw))
            metadata.append({"ordinal": ordinal, "bytes": len(raw),
                             "mtimeNs": st.st_mtime_ns, "stableFullIdentity": True})
        output["audit"] = audit(inputs[0])
        output["raft"] = raft(*inputs[1:])
        for parent, name, child, original in file_checks:
            need(identity(os.fstat(child)) == original and
                 identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original,
                 "final_file_binding")
        for parent, name, child, original in directory_checks:
            need(identity(os.fstat(child))[:5] == original and
                 identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == original,
                 "final_directory_binding")
        need(identity(os.fstat(root_fd)) == identity(root_st), "fixture_root_changed")
        output.update({"files": metadata, "observedBytes": total, "ok": True})
    except Exception as error:
        output["failureClass"] = type(error).__name__
        output["failureCode"] = str(error) if isinstance(error, Refusal) else "closed_observation_failed"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for fd in reversed(held):
            try:
                os.close(fd)
                closed += 1
            except Exception:
                close_errors += 1
        output["fdCloseFacts"] = {"opened": opened, "closeAttempts": len(held),
                                   "closed": closed, "closeErrors": close_errors}
        if opened != closed or close_errors:
            output["ok"] = False
        output["elapsedSeconds"] = time.monotonic() - began
        print(json.dumps(output, sort_keys=True))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
