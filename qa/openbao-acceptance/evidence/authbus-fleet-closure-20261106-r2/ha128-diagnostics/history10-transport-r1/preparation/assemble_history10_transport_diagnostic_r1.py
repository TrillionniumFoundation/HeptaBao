"""Derive a separate finite diagnostic launcher from the exact HA-r3 input."""
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "launch_ha128_current_r3.py"
ORIGINAL_SHA = "9d703c0b213e5fe9f4e5cd67f6127ca16dd303f870df85526b86e63893b27fd1"
BODY = ROOT / "launch_ha128_current_r3.body.py"
BODY_SHA = "a13b6afa5596efbd28c1ba8233c6e45919684a118b46204a7c5f698351a59014"


def replace_once(source, old, new):
    assert source.count(old) == 1, old[:100]
    return source.replace(old, new)


def main():
    original = ORIGINAL.read_bytes()
    before = BODY.read_bytes()
    assert hashlib.sha256(original).hexdigest() == ORIGINAL_SHA
    assert hashlib.sha256(before).hexdigest() == BODY_SHA
    parsed = ast.parse(original)
    pins = next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "PINS")
    assert len(pins) == 613
    source = before.decode()
    for old, new in (
        ("ha128-current-launch-20261106-r3", "ha-history10-transport-launch-20261107-r1"),
        ("native-ha-official-history-4bde9-authbus-r3", "ha-history10-transport-work-20261107-r1"),
        ("/home/qian/heptabao-native-ha-4bde9-authbus-20261106-r3", "/home/qian/heptabao-ha-history10-transport-20261107-r1"),
        ("/home/qq/heptabao-native-ha-4bde9-authbus-20261106-r3", "/home/qq/heptabao-ha-history10-transport-20261107-r1"),
        ("native-ha-4bde9-authbus-node-r3", "ha-history10-transport-node-20261107-r1"),
        ("import hashlib\n", "import base64\nimport hashlib\n"),
        ("from the immutable af91 QA tree by assemble_ha128_launcher.py.",
         "from the immutable af91 QA tree. This separate diagnostic stops at the\noriginal tenth exact history read and never qualifies the full HA profile."),
        ("heptabao.current-ha128-launch.r1", "heptabao.history10-transport-launch.v1"),
        ("'outerSupervisorSeconds': 1800", "'outerSupervisorSeconds': 600, 'diagnosticOnly': True"),
        ("report['harnessExitCode'] = official.main(ARGUMENTS)",
         "report['harnessExitCode'] = diagnostic.main(ARGUMENTS)"),
        ("'heptabao.native-v6-direct-lan-official271-history.v1', 'original_summary_schema'",
         "'heptabao.history10-transport-diagnostic.v1', 'diagnostic_summary_schema'"),
    ):
        source = replace_once(source, old, new)
    source = replace_once(source, "PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS", """PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS
PAYLOADS = {}  # ASSEMBLED_DIAGNOSTIC_PAYLOADS
STDLIB_PINS = {
    '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/lib/python3.14/urllib/request.py':
        (77037, '7465dbf037295f8f04774c453ab84c31879999c507fa16a82627ce9bd9615992'),
    '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/lib/python3.14/http/client.py':
        (58043, 'a5cd9edd48e0bc67c2ea0b13ea45749d28cd8d6313bb103b17c13509f60a3e33'),
}
PAYLOAD_NAMES = {
    'ha_history10_transport_diagnostic_r1.py', 'ha_http_transport_observer_r1.py',
    'observe_history10_owned_x230_pid_r1.py',
}
""")
    source = replace_once(source, "def main():\n", """def runtime_snapshot():
    result = {}
    for path, (size, pin) in STDLIB_PINS.items():
        raw, identity = read(path, size)
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == pin, 'actual_stdlib_exact')
        result[path] = identity
    return result

def diagnostic_snapshot():
    need(set(PAYLOADS) == PAYLOAD_NAMES, 'exact_three_new_diagnostic_sources')
    result = {}
    for name, entry in PAYLOADS.items():
        raw, identity = read(CONTROL / name, entry['bytes'], private=True)
        need(len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'diagnostic_source_exact')
        result[name] = identity
    return result

def main():
""")
    source = replace_once(source, "        before = snapshot()\n", """        before = snapshot()
        runtime_before = runtime_snapshot()
""")
    source = replace_once(source, "        created = True\n", """        created = True
        need(set(PAYLOADS) == PAYLOAD_NAMES, 'exact_three_new_diagnostic_sources')
        for name, entry in PAYLOADS.items():
            raw = base64.b64decode(entry['base64'], validate=True)
            need(len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'embedded_diagnostic_source_exact')
            create(CONTROL / name, raw)
        diagnostic_before = diagnostic_snapshot()
        report['diagnosticSourcePins'] = {name: {'bytes': entry['bytes'], 'sha256': entry['sha256']} for name, entry in PAYLOADS.items()}
""")
    source = replace_once(source, "        import native_v6_ha_official_history_live as official\n", """        import native_v6_ha_official_history_live as official
        sys.path.insert(0, str(CONTROL))
        import ha_history10_transport_diagnostic_r1 as diagnostic
        need(Path(diagnostic.__file__).resolve() == CONTROL / 'ha_history10_transport_diagnostic_r1.py'
             and Path(diagnostic.observer.__file__).resolve() == CONTROL / 'ha_http_transport_observer_r1.py'
             and diagnostic.official is official and diagnostic.custody is custody, 'fixed_diagnostic_import_origins')
        import urllib.request, http.client
        need(set((str(Path(urllib.request.__file__).resolve()), str(Path(http.client.__file__).resolve())))
             == set(STDLIB_PINS), 'fixed_actual_stdlib_import_origins')
""")
    source = replace_once(source, "        need(snapshot() == before, 'source_stable_before_entry')", """        need(snapshot() == before and runtime_snapshot() == runtime_before
             and diagnostic_snapshot() == diagnostic_before, 'source_stable_before_entry')""")
    source = replace_once(source, "        need(snapshot() == before, 'all_source_dependencies_unchanged')", """        need(snapshot() == before and runtime_snapshot() == runtime_before
             and diagnostic_snapshot() == diagnostic_before, 'all_source_dependencies_unchanged')""")
    old = """        required = official.OfficialHistoryRun.required_checks
        checks = summary.get('checks', [])
        need(report['harnessExitCode'] == 0 and summary.get('status') == 'passed'
             and len(checks) == len(required) == 128 and {r.get('case') for r in checks} == required
             and all(r.get('passed') is True for r in checks)
             and summary.get('official_history_chain_qualified') is True
             and summary.get('native_ha_backup_verified') is True
             and not summary.get('cleanup_failure') and not summary.get('failure_code'), 'original_ha128_result_qualified')"""
    new = """        required = diagnostic.PREFIX_CHECKS
        checks = summary.get('checks', [])
        need(report['harnessExitCode'] == 0 and summary.get('status') == 'diagnostic-prefix-complete'
             and len(checks) == len(required) == 51 and {r.get('case') for r in checks} == required
             and all(r.get('passed') is True for r in checks)
             and summary.get('required_check_count') == len(official.OfficialHistoryRun.required_checks) == 128
             and summary.get('missing_checks') == sorted(official.OfficialHistoryRun.required_checks - required)
             and summary.get('diagnosticPrefixCompleted') is True and summary.get('tenthExactReadReturned') is True
             and summary.get('diagnosticInputsAfterCleanupExact') is True and summary.get('diagnosticMutationLedgerExact') is True
             and summary.get('eleventhHistoryMutationDispatched') is False
             and all(summary.get(flag) is False for flag in diagnostic.FALSE_FLAGS)
             and not summary.get('cleanup_failure') and not summary.get('failure_code'), 'diagnostic_prefix_result_complete')"""
    source = replace_once(source, old, new)
    ast.parse(source)
    body_path = ROOT / "launch_history10_transport_diagnostic_r1.body.py"
    body_path.write_text(source)
    payloads = {}
    for name in ("ha_history10_transport_diagnostic_r1.py", "ha_http_transport_observer_r1.py", "observe_history10_owned_x230_pid_r1.py"):
        raw = (ROOT / name).read_bytes()
        ast.parse(raw)
        payloads[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                          "base64": base64.b64encode(raw).decode()}
    assembled = replace_once(source, "PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS", "PINS = " + repr(pins))
    assembled = replace_once(assembled, "PAYLOADS = {}  # ASSEMBLED_DIAGNOSTIC_PAYLOADS", "PAYLOADS = " + repr(payloads))
    ast.parse(assembled)
    output = ROOT / "launch_history10_transport_diagnostic_r1.py"
    output.write_text(assembled)
    (ROOT / "history10-launcher-vs-formal-r3.diff").write_text("".join(difflib.unified_diff(
        before.decode().splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile="original-formal-ha128-r3.body.py", tofile=body_path.name)))
    integrity = {
        "schema": "heptabao.history10-source-integrity.v1", "state": "prepared-not-dispatched",
        "originalLauncherSha256": ORIGINAL_SHA, "originalBodySha256": BODY_SHA,
        "sameOriginal613Pins": True, "originalFormal128Unchanged": True,
        "originalMutatingMethodsUnchanged": True, "newProductCode": False,
        "payloads": {k: {x: v[x] for x in ("bytes", "sha256")} for k, v in payloads.items()},
        "body": {"bytes": len(source.encode()), "sha256": hashlib.sha256(source.encode()).hexdigest()},
        "launcher": {"bytes": len(assembled.encode()), "sha256": hashlib.sha256(assembled.encode()).hexdigest()},
        "runtimeExecution": False,
    }
    (ROOT / "history10-source-integrity.public.json").write_text(json.dumps(integrity, indent=2, sort_keys=True) + "\n")
    print(json.dumps(integrity, sort_keys=True))


if __name__ == "__main__":
    main()
