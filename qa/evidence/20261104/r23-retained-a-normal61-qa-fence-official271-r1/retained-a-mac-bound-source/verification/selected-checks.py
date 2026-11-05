import argparse
import ast
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path

data = json.loads(Path("/tmp/heptabao_retained_a_mac_binding_r1/input.json").read_text())
checks = []
def check(name, value):
    checks.append({"name": name, "passed": bool(value)})
    if not value:
        raise AssertionError(name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()

before, after = data["before"], data["after"]
tree_before, tree_after = ast.parse(before), ast.parse(after)
compile(tree_before, "unbound-stager", "exec")
compile(tree_after, "bound-stager", "exec")
check("both_stagers_ast_and_compile_only", True)
check("only_two_actual_bundle_constants", before.replace("CANONICAL_BUNDLE_BYTES = None\n", "CANONICAL_BUNDLE_BYTES = 29953\n").replace("CANONICAL_BUNDLE_SHA256 = None\n", "CANONICAL_BUNDLE_SHA256 = '" + data["bundle_info"]["sha256"] + "'\n") == after)
definitions = lambda source, tree: [(node.name, ast.get_source_segment(source, node)) for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
check("all_ordered_definitions_including_duplicate_owned_unchanged", definitions(before, tree_before) == definitions(after, tree_after))
check("ordered_definition_count_21", len(definitions(after, tree_after)) == 21)

old_payload = json.loads(data["payload_before"])
payload = json.loads(data["payload"])
check("exact_payload_keys", set(payload) == {"schema", "controls", "canonical_bundle_base64"})
check("three_controls_unchanged", payload["controls"] == old_payload["controls"] and len(payload["controls"]) == 3)
check("exact_payload_schema", payload["schema"] == old_payload["schema"] == "heptabao.same-root-publication-mac-inert-controls.v1")
for name, text in payload["controls"].items():
    if name.endswith(".py"):
        compile(text, name, "exec")
check("two_control_modules_compile_only", True)
raw = base64.b64decode(payload["canonical_bundle_base64"], validate=True)
read = data["original_bundle_read"]
info = data["bundle_info"]
check("base64_is_original_native_field", payload["canonical_bundle_base64"] == read["data_base64"])
check("actual_bundle_whole_sha_bytes", len(raw) == info["size"] == 29953 and sha(raw) == info["sha256"] == read["chunk_sha256"])
check("actual_bundle_same_version_whole_eof", read["version"] == info["version"] and read["offset"] == 0 and read["next_offset"] == len(raw) and read["eof"])
check("exact_header_and_pack", raw.startswith(data["bundle_header"].encode()) and raw[len(data["bundle_header"]):len(data["bundle_header"])+4] == b"PACK")
check("stdin_original_262144_limit", len(data["payload"].encode()) <= 262144)

request, template = data["request"], data["template"]
check("request_exact_key_set", set(request) == set(template))
check("host_executable_cwd_outer_unchanged", all(request[k] == template[k] for k in ("host", "executable", "cwd", "timeout_seconds")) and request["timeout_seconds"] == 360)
check("exact_source_argument", request["args"][4] == after)
check("exact_self_and_carrier_pins", request["args"][6] == sha(after.encode()) and request["args"][8] == sha(data["payload"].encode()))
check("exact_bundle_arguments", request["args"][10] == str(len(raw)) and request["args"][12] == sha(raw))
check("request_stdin_is_payload", request["stdin"] == data["payload"])
check("argument_contract_other_fields_unchanged", len(request["args"]) == len(template["args"]) and all(a == b for i, (a, b) in enumerate(zip(request["args"], template["args"])) if i not in (4, 6, 8, 10, 12)))
check("key_only_source_sha_suffix", request["idempotency_key"] == template["idempotency_key"].rsplit("-", 1)[0] + "-" + sha(after.encode())[:8])

selected = []
for node in tree_after.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "parser":
        selected.append(node)
    elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "parser" and node.value.func.attr == "add_argument":
        selected.append(node)
namespace = {"argparse": argparse}
exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), "selected-original-argparse-only", "exec"), namespace)
parsed = namespace["parser"].parse_args(request["args"][5:])
check("actual_selected_parser_accepts_exact_invocation", parsed.self_sha256 == sha(after.encode()) and parsed.carrier_sha256 == sha(data["payload"].encode()) and parsed.canonical_bundle_bytes == 29953 and parsed.canonical_bundle_sha256 == sha(raw))
for name, argv in (("missing_bundle_sha_rejected", request["args"][5:-2]), ("extra_arg_rejected", request["args"][5:] + ["unexpected"]), ("noninteger_bundle_size_rejected", request["args"][5:10] + ["not-an-int"] + request["args"][11:])):
    rejected = False
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            namespace["parser"].parse_args(argv)
    except SystemExit as error:
        rejected = error.code == 2
    check(name, rejected)
print(json.dumps({"schema": "heptabao.mac-source-actual-bundle-binding-checks.v1", "all_passed": all(x["passed"] for x in checks), "checks": checks, "definitions_unchanged": len(definitions(after, tree_after)), "source_module_executed": False, "selected_argparse_only": True, "remote_calls": 0, "rust_or_cargo": 0, "filesystem_scope": "read one local public input file; no application module import or execution"}, sort_keys=True))
