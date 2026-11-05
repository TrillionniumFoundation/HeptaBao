#!/usr/bin/env python3
"""Offline archive checker: public original files only; no host or product access."""
import argparse
import hashlib
import json
from pathlib import Path

def digest(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--input-json")
    choice.add_argument("--packet-dir")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.input_json:
        payload = json.loads(Path(args.input_json).read_text(encoding="utf-8"))
        files = payload["files"]
        read = lambda name: files[name].encode("utf-8")
        metas = payload["command_file_metas"]
        chunks = payload["chunk_proofs"]
    else:
        root = Path(args.packet_dir)
        read = lambda name: (root / name).read_bytes()
        metas = json.loads(read("analysis/command-log-index.public.json"))["files"]
        chunks = json.loads(read("analysis/binary-assembly.public.json"))["chunks"]
    checks = []
    def require(condition, name):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    core_raw = read("actual/result.public.json")
    core = json.loads(core_raw)
    require(len(core_raw) == 35428 and digest(core_raw) == "afdfccd3a380b1fdc56dd4a1833f073c8d69add409ea0a46604eb54bfaa6226e", "exact original core")
    require(core["status"] == "complete" and core["source_imported"] is True, "actual source import passed")
    require(core["within_original_deadline"] is True and 0 <= core["elapsed_seconds"] < core["overall_seconds"] == 300, "original total deadline")
    require(core["compiler_started"] is False and core["server_started"] is False and type(core["product_tests_executed"]) is int and core["product_tests_executed"] == 0, "source only")
    require(core["input_sources_unchanged"] is True and core["raw_input_receipts_unchanged"] is True, "source and raw receipt fences")
    require(core["input_files_before"] == core["input_files_after"], "lossless full input identity equality")
    require(len(core["commands"]) == len(core["cleanup"]) == 21, "twenty-one commands")
    command_names = set()
    expected_logs = set()
    for command, cleanup in zip(core["commands"], core["cleanup"], strict=True):
        label = command["label"]
        require(label not in command_names, label + " unique")
        command_names.add(label)
        prefix = "commands/" + label
        record_raw = read(prefix + ".public.json")
        require(json.loads(record_raw) == command, label + " original standalone record exactly equals core")
        require(command["argv"][0] == "/usr/bin/git", label + " git program")
        require(command["direct_child_reaped"] is True and command["remaining"] == [] and command["timed_out"] is False, label + " owned child complete")
        require(0 <= command["elapsed_seconds"] <= command["limit_seconds"], label + " original child deadline")
        require(cleanup == {key: command[key] for key in cleanup}, label + " exact cleanup")
        expected_exit = 1 if label in {"013-no-sparse-config", "020-source-after-partial-config"} else 0
        require(command["exit_code"] == expected_exit, label + " expected exit")
        for stream in ("stdout", "stderr"):
            name = prefix + "." + stream
            body = read(name)
            require(len(body) == command[stream + "_bytes"], name + " bytes")
            require(digest(body) == command[stream + "_sha256"], name + " sha256")
            expected_logs.add(name)
        expected_logs.add(prefix + ".public.json")
    require(len(expected_logs) == 63, "sixty-three exact log names")
    require({row["path"] for row in metas} == expected_logs and len(metas) == 63, "standalone file index exact")
    for row in metas:
        body = read(row["path"])
        require(len(body) == row["bytes"] and digest(body) == row["sha256"] and git_blob(body) == row["blob"], row["path"] + " independently recomputed Git blob")
    closure = core["input_fd_closure"]
    require(closure == {"closed_directories": 4, "closed_files": 3, "complete": True, "created_source_directory_closed": True, "created_source_directory_opened": True, "errors": [], "opened_directories": 4, "opened_files": 3}, "all eight owned FDs closed")
    require(core["all_owned_stopped"] is True, "all owned processes stopped")
    require(core["expected_prerequisites"] == [], "zero bundle prerequisites")
    proof = core["canonical_proof"]
    require(proof == {"commit": "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c", "commit_count": 3757, "full_fsck_passed": True, "parents": ["6304a898192bfdf7eabec3c4ea40f7166e59a137"], "root": "67d79b3b5442ed033d38929eab2010403463e56d", "tree": "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"}, "complete actual canonical proof")
    require(core["source_after"]["clean"] is True and core["source_after"]["no_alternates"] is True and core["source_after"]["independent_git_directory"] is True, "independent clean source")
    def parse_tree(body, index):
        require(body.endswith(b"\0"), "index" if index else "tree" + " NUL terminated")
        records = body.split(b"\0")[:-1]
        require(len(records) == 3913, ("index" if index else "tree") + " 3913 records")
        entries = {}
        for record in records:
            head, path = record.split(b"\t", 1)
            columns = head.split(b" ")
            if index:
                mode, sha, stage = columns
                require(stage == b"0", "index stage zero " + path.decode("utf-8"))
            else:
                mode, kind, sha = columns
                require(kind == b"blob", "tree blob " + path.decode("utf-8"))
            require(mode in {b"100644", b"100755"}, "regular supported mode " + path.decode("utf-8"))
            require(len(sha) == 40 and all(ch in b"0123456789abcdef" for ch in sha), "exact leaf SHA " + path.decode("utf-8"))
            decoded = path.decode("utf-8")
            require(decoded and not decoded.startswith("/") and all(part not in {"", ".", "..", ".git"} for part in decoded.split("/")), "safe named path " + decoded)
            require(decoded not in entries, "unique path " + decoded)
            entries[decoded] = (mode.decode("ascii"), sha.decode("ascii"))
        return entries
    tree_raw = read("commands/011-materialized-tree.stdout")
    index_raw = read("commands/012-materialized-index.stdout")
    tree_entries = parse_tree(tree_raw, False)
    index_entries = parse_tree(index_raw, True)
    require(tree_entries == index_entries, "complete named tree and index equality")
    directories = {}
    for name, leaf in tree_entries.items():
        at = directories
        parts = name.split("/")
        for part in parts[:-1]:
            at = at.setdefault(part, {})
        require(parts[-1] not in at, "Merkle distinct leaf " + name)
        at[parts[-1]] = leaf
    merkle_rows = []
    def tree_hash(node, prefix):
        body = bytearray()
        names = sorted(node, key=lambda name: name.encode("utf-8") + (b"/" if isinstance(node[name], dict) else b""))
        for name in names:
            value = node[name]
            if isinstance(value, dict):
                mode, sha = "40000", tree_hash(value, prefix + name + "/")
            else:
                mode, sha = value
            body.extend(mode.encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(sha))
        sha = hashlib.sha1(b"tree " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
        merkle_rows.append({"path": prefix, "sha": sha, "entries": len(names)})
        return sha
    actual_tree = tree_hash(directories, "")
    require(actual_tree == proof["tree"], "3913 original named leaves reconstruct exact df026 canonical Merkle root")
    require(len(merkle_rows) == 358, "358 canonical tree objects independently reconstructed")
    require(len(chunks) == 14 and len({row["operation"] for row in chunks}) == 14, "fourteen distinct immutable binary operations")
    for which, original in (("tree", tree_raw), ("index", index_raw)):
        selected = sorted((row for row in chunks if row["label"].startswith(which + "-")), key=lambda row: row["offset"])
        require(len(selected) == 7 and len({row["version"] for row in selected}) == 1, which + " exact seven chunks and one original version")
        offset = 0
        for row in selected:
            chunk = original[offset:offset + row["bytes"]]
            require(row["offset"] == offset and len(chunk) == row["bytes"] and digest(chunk) == row["sha256"] and row["size"] == len(original), row["label"] + " exact full-file chunk inclusion")
            offset += len(chunk)
            require(row["eof"] == (offset == len(original)), row["label"] + " exact EOF")
        require(offset == len(original), which + " gapless complete file")
    report = {
        "schema": "heptabao.df026-import-r2-offline-archive-review.v1",
        "status": "passed", "scope": "original public archive only; no host process or product action",
        "checks": len(checks), "commands": 21, "individual_original_logs": 63,
        "original_log_bytes": sum(row["bytes"] for row in metas),
        "command_exit_codes": {"zero": 19, "expected_one": 2},
        "canonical_commit": proof["commit"], "canonical_tree_recomputed": actual_tree,
        "tracked_leaves": len(tree_entries), "canonical_trees_recomputed": len(merkle_rows),
        "nul_files": [{"path": name, "bytes": len(read(name)), "sha256": digest(read(name)), "git_blob": git_blob(read(name))} for name in ("commands/011-materialized-tree.stdout", "commands/012-materialized-index.stdout")],
        "binary_chunks": len(chunks), "immutable_binary_pages": sum(row["pages"] for row in chunks),
        "same_file_version_per_complete_file": True,
        "lossless_input_fences_equal": True, "all_owned_processes_stopped": True,
        "all_eight_owned_fds_closed": True, "source_only": True,
        "runtime_qualification_added": False,
        "core_original_sha256": digest(core_raw), "merkle": merkle_rows
    }
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "merkle"}, ensure_ascii=False))

if __name__ == "__main__":
    main()
