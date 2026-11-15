#!/usr/bin/env python3
"""Parse only explicit numeric lsof -F fields; never request names or arguments."""
import re


class FieldRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise FieldRefused(code)


def decimal(raw, *, positive=False):
    need(type(raw) is bytes and re.fullmatch(rb"[0-9]{1,20}", raw) is not None,
         "finite_lsof_decimal_field")
    value = int(raw)
    need(value <= 18446744073709551615 and (not positive or value > 0),
         "finite_lsof_decimal_bound")
    return value


def parse_fields(raw, expected_pids):
    need(type(raw) is bytes and 0 < len(raw) <= 1048576
         and raw.endswith(b"\x00\n"), "finite_lsof_complete_bounded_stream")
    need(type(expected_pids) is set and 0 < len(expected_pids) <= 9
         and all(type(pid) is int and pid > 1 for pid in expected_pids),
         "finite_lsof_exact_pid_set")
    processes = {}
    current = None
    total_files = 0
    for record in raw.split(b"\n")[:-1]:
        need(record and record.endswith(b"\x00"), "finite_lsof_record_terminator")
        tokens = record[:-1].split(b"\x00")
        need(tokens and all(token and len(token) <= 128 for token in tokens),
             "finite_lsof_field_size")
        values = {}
        for token in tokens:
            tag, value = token[:1], token[1:]
            need(tag in (b"p", b"u", b"f", b"a", b"t", b"D", b"i")
                 and tag not in values, "finite_lsof_only_requested_unique_fields")
            values[tag] = value
        if tokens[0].startswith(b"p"):
            need(set(values) == {b"p", b"u"}, "finite_lsof_process_record_shape")
            pid = decimal(values[b"p"], positive=True)
            uid = decimal(values[b"u"])
            need(pid in expected_pids and pid not in processes and uid == 501,
                 "finite_lsof_current_selected_process_owner")
            current = {"pid": pid, "uid": uid, "files": []}
            processes[pid] = current
            continue
        need(tokens[0].startswith(b"f") and current is not None
             and b"f" in values and b"t" in values,
             "finite_lsof_file_record_shape")
        descriptor = values[b"f"]
        need(re.fullmatch(rb"(?:[0-9]{1,7}|cwd|rtd|txt|mem|mmap|DEL|NOFD)", descriptor) is not None,
             "finite_lsof_bounded_descriptor_kind")
        file_type = values[b"t"]
        need(re.fullmatch(rb"[A-Za-z0-9_? -]{1,24}", file_type) is not None,
             "finite_lsof_file_type_scalar")
        access = values.get(b"a", b"")
        need(access in (b"", b" ", b"r", b"w", b"u"), "finite_lsof_known_access_mode")
        regular = file_type in (b"REG", b"VREG")
        device = inode = None
        if regular:
            need(b"D" in values and b"i" in values
                 and re.fullmatch(rb"0x[0-9a-fA-F]{1,16}", values[b"D"]) is not None,
                 "finite_lsof_hex_device")
            device = int(values[b"D"], 16)
            inode = decimal(values[b"i"], positive=True)
        need(not regular or device is not None and inode is not None,
             "finite_lsof_regular_inode_complete")
        current["files"].append({"descriptor": descriptor.decode("ascii"),
            "type": file_type.decode("ascii"), "access": "unspecified" if access in (b"", b" ") else access.decode("ascii"),
            "device": device, "inode": inode, "regularFileIdentityComplete": regular,
            "nonRegularMetadataNotUsedAsFileIdentity": not regular})
        total_files += 1
        need(total_files <= 16384, "finite_lsof_total_descriptor_bound")
    need(set(processes) == expected_pids, "finite_lsof_every_selected_pid_reported")
    return {"processes": list(processes.values()), "fileRecords": total_files,
            "requestedPathOrCommandNameFields": False,
            "kernelWideVisibilityClaimed": False}


def match_files(parsed, targets):
    need(type(targets) is list and len(targets) <= 45, "finite_inode_target_bound")
    by_inode = {}
    for target in targets:
        need(set(target) == {"ordinal", "kind", "member", "device", "inode"}
             and type(target["ordinal"]) is int and 0 <= target["ordinal"] < 45
             and target["kind"] in ("database", "cache", "legacy")
             and target["member"] in ("base", "wal", "shm", "journal", "file")
             and type(target["device"]) is type(target["inode"]) is int,
             "finite_current_target_identity_shape")
        key = (target["device"], target["inode"])
        need(key not in by_inode, "finite_current_target_inodes_unique")
        by_inode[key] = target
    matches = []
    for process in parsed["processes"]:
        for item in process["files"]:
            target = by_inode.get((item["device"], item["inode"]))
            if target is not None:
                need(item["regularFileIdentityComplete"], "matched_inode_is_complete_regular_file")
                matches.append({"pid": process["pid"], "uid": process["uid"],
                    "targetOrdinal": target["ordinal"], "targetKind": target["kind"],
                    "member": target["member"], "descriptor": item["descriptor"],
                    "access": item["access"], "type": item["type"],
                    "deviceAndInodeExact": True})
    return matches
