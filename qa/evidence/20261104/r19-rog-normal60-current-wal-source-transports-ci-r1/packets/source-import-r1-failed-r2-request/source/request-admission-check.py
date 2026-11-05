#!/usr/bin/env python3
"""Offline exact-request admission check; no target importer execution or host access."""
import ast, hashlib, json, re, types
from pathlib import Path
HERE = Path(__file__).parent
data = json.loads((HERE / "importer_request_r2_check_input.json").read_text())
source = data["source"]
old = data["old_request"]
new = data["new_request"]
checks = []
def need(value, name):
    assert value, name
    checks.append(name)
need(hashlib.sha256(source.encode()).hexdigest() == data["source_sha256"], "exact_reviewed_source")
need(old["args"] == ["-I", "-S", "-B", "-c", source], "old_request_missing_self_sha")
need(new["args"] == [*old["args"], data["source_sha256"]], "new_request_adds_only_self_sha_argument")
inverse = dict(new)
inverse["args"] = new["args"][:-1]
inverse["idempotency_key"] = old["idempotency_key"]
need(inverse == old, "all_other_request_fields_exact")
need(new["idempotency_key"] == "heptabao-df026-standalone-import-fbbb2f85-20261105-r2", "new_distinct_reviewable_request_key")
module = ast.parse(source)
body = next(n for n in module.body if isinstance(n, ast.Try) and n.lineno == 518)
selected = body.body[:5]
need([type(n).__name__ for n in selected] == ["Assert", "Assert", "Assert", "Assign", "Assert"], "actual_first_five_source_nodes")
need([n.lineno for n in selected] == [519, 520, 521, 522, 523], "actual_guard_source_locations")
digest_fn = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "digest")
guard = compile(ast.fix_missing_locations(ast.Module(body=[digest_fn, *selected], type_ignores=[])), "reviewed-importer-admission", "exec")
def actual_guard(request):
    fake = types.SimpleNamespace(argv=["-c", *request["args"][5:]], orig_argv=[request["executable"], *request["args"]])
    scope = {"sys": fake, "re": re, "hashlib": hashlib}
    try:
        exec(guard, scope)
        return {"passed": True}
    except AssertionError as error:
        frame = error.__traceback__
        while frame.tb_next:
            frame = frame.tb_next
        return {"passed": False, "line": frame.tb_lineno}
before = actual_guard(old)
after = actual_guard(new)
need(before == {"passed": False, "line": 519}, "old_actual_guard_known_failure")
need(after == {"passed": True}, "new_actual_guard_accepts_exact_self_sha")
authority = json.loads(data["authority_raw"])
streams = json.loads(data["streams_raw"])
for name in ("stdout", "stderr"):
    row = streams[name]
    raw = bytes.fromhex(row["bytes_hex"])
    need(raw == row["text"].encode() and row["offset"] == 0 and row["eof"] is True and row["next_offset"] == row["size"] == len(raw), name + "_whole_original_hex_text_eof")
    need(authority["log_bytes"][name]["seen"] == authority["log_bytes"][name]["stored"] == len(raw), name + "_authority_exact_bytes")
need(streams["stdout"]["size"] == 0 and streams["stderr"]["size"] == 1336, "original_stream_counts")
core = json.loads(streams["stderr"]["text"])
need(authority["exit_code"] == 1 and authority["output_complete"] is True and authority["output_durable"] is True and not authority["timed_out"] and not authority["cancelled"] and authority["state"] == "failed", "actual_authoritative_known_terminal_failure")
need(core["failure_frames"] == [{"function": "<module>", "line": 519}] and core["error_type"] == "AssertionError", "actual_failure_matches_first_guard")
need(core["commands"] == core["cleanup"] == [] and core["all_owned_stopped"] is True, "no_git_children_and_no_outstanding_owned_process")
closure = core["input_fd_closure"]
need(closure["complete"] is True and closure["errors"] == [] and all(closure[k] == 0 for k in ("opened_files", "closed_files", "opened_directories", "closed_directories")) and not closure["created_source_directory_opened"], "no_input_fd_or_created_source_directory")
need(core["source_imported"] is False and core["server_started"] is False and core["compiler_started"] is False and core["product_tests_executed"] == 0 and core["production_changed"] is False, "no_product_or_import_effects")
report = {"schema": "heptabao.df026.import-request-self-sha-correction.r2", "status": "passed_offline_guard_check_only", "old_request_guard": before, "new_request_guard": after, "source_sha256": data["source_sha256"], "source_unchanged": True, "scope": "exact AST-selected admission guard only; importer main, Git, host filesystem and new request were not executed", "checks": checks, "check_count": len(checks), "product_or_host_execution": False, "runtime_source_import_qualification": False}
(HERE / "importer_request_r2_check.public.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"status": report["status"], "checks": len(checks), "before": before, "after": after}))
