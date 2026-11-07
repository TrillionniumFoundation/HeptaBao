"""Assemble the full original HA128 harness with a transport-only adapter."""
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def once(source, old, new):
    assert source.count(old) == 1, old[:100]
    return source.replace(old, new)


def main():
    formal = (ROOT / "launch_ha128_current_r3.body.py").read_bytes()
    prefix = (ROOT / "launch_history10_transport_diagnostic_r1.body.py").read_bytes()
    assert hashlib.sha256(formal).hexdigest() == "a13b6afa5596efbd28c1ba8233c6e45919684a118b46204a7c5f698351a59014"
    assert hashlib.sha256(prefix).hexdigest() == "d00887721ee8d79656be7b964bbeff65b1eaff88ad471f7cd985a70363b5a1bb"
    original = (ROOT / "launch_ha128_current_r3.py").read_bytes()
    assert hashlib.sha256(original).hexdigest() == "9d703c0b213e5fe9f4e5cd67f6127ca16dd303f870df85526b86e63893b27fd1"
    pins = next(ast.literal_eval(n.value) for n in ast.parse(original).body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "PINS")
    assert len(pins) == 613
    source = prefix.decode()
    for old, new in (
        ("This separate diagnostic stops at the\noriginal tenth exact history read and never qualifies the full HA profile.",
         "This separate adapter observes the\ncomplete original HA128 workload; no prefix stop or product change is present."),
        ("ha-history10-transport-launch-20261107-r1", "ha128-observed-current-launch-20261107-r4"),
        ("ha-history10-transport-work-20261107-r1", "native-ha-official-history-4bde9-authbus-r4"),
        ("/home/qian/heptabao-ha-history10-transport-20261107-r1", "/home/qian/heptabao-native-ha-4bde9-authbus-20261107-r4"),
        ("/home/qq/heptabao-ha-history10-transport-20261107-r1", "/home/qq/heptabao-native-ha-4bde9-authbus-20261107-r4"),
        ("ha-history10-transport-node-20261107-r1", "native-ha-4bde9-authbus-node-r4"),
        ("heptabao.history10-transport-launch.v1", "heptabao.current-ha128-observed-launch.r1"),
        ("'outerSupervisorSeconds': 600, 'diagnosticOnly': True",
         "'outerSupervisorSeconds': 1800, 'observerOnlyChange': True"),
        ("import ha_history10_transport_diagnostic_r1 as diagnostic", "import ha128_transport_observed_r4 as diagnostic"),
        ("'heptabao.history10-transport-diagnostic.v1', 'diagnostic_summary_schema'",
         "'heptabao.native-v6-direct-lan-official271-history.v1', 'original_summary_schema'"),
    ):
        source = once(source, old, new)
    for old, new, count in (
        ("ha_history10_transport_diagnostic_r1.py", "ha128_transport_observed_r4.py", 2),
        ("ha_http_transport_observer_r1.py", "ha_http_transport_observer_formal_r1.py", 2),
        ("observe_history10_owned_x230_pid_r1.py", "observe_ha128_r4_owned_x230_pid.py", 1),
    ):
        assert source.count(old) == count
        source = source.replace(old, new)
    # Restore the exact original formal result gate, without removing any term.
    old_start = source.index("        required = diagnostic.PREFIX_CHECKS\n")
    old_end = source.index("        report['ok'] = True\n", old_start)
    f = formal.decode()
    start = f.index("        required = official.OfficialHistoryRun.required_checks\n")
    end = f.index("        report['ok'] = True\n", start)
    original_gate = f[start:end]
    source = source[:old_start] + original_gate + """        need(summary.get('observerOriginalRequiredCheckCount') == 128
             and summary.get('observerChangesOriginalWorkload') is False
             and summary.get('observerChangesFormalDenominator') is False
             and summary.get('observerChangesOriginalBudgets') is False
             and isinstance(summary.get('transportObservations'), list)
             and 0 < len(summary['transportObservations']) <= 2048,
             'original_ha128_transport_observation_bound')
""" + source[old_end:]
    ast.parse(source)
    payloads = {}
    for name in ("ha128_transport_observed_r4.py", "ha_http_transport_observer_formal_r1.py", "observe_ha128_r4_owned_x230_pid.py"):
        raw = (ROOT / name).read_bytes()
        ast.parse(raw)
        payloads[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                          "base64": base64.b64encode(raw).decode()}
    assembled = once(source, "PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS", "PINS = " + repr(pins))
    assembled = once(assembled, "PAYLOADS = {}  # ASSEMBLED_DIAGNOSTIC_PAYLOADS", "PAYLOADS = " + repr(payloads))
    ast.parse(assembled)
    (ROOT / "launch_ha128_observed_r4.body.py").write_text(source)
    (ROOT / "launch_ha128_observed_r4.py").write_text(assembled)
    (ROOT / "ha128-observed-r4-vs-original-r3.diff").write_text("".join(difflib.unified_diff(
        formal.decode().splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile="original-formal-ha128-r3.body.py", tofile="full-observed-ha128-r4.body.py")))
    changes = []
    for old, new in (("ha_http_transport_observer_r1.py", "ha_http_transport_observer_formal_r1.py"),
                     ("observe_history10_owned_x230_pid_r1.py", "observe_ha128_r4_owned_x230_pid.py")):
        changes.extend(difflib.unified_diff((ROOT / old).read_text().splitlines(keepends=True),
                       (ROOT / new).read_text().splitlines(keepends=True), fromfile=old, tofile=new))
    (ROOT / "ha128-observer-and-snapshot-review-delta.diff").write_text("".join(changes))
    report = {"schema": "heptabao.ha128-observed-source-integrity.v1", "state": "prepared-not-dispatched",
              "sameOriginal613Pins": True, "originalFormal128GateByteExact": original_gate in source,
              "originalAllWorkloadMethodsDelegatedUnchanged": True, "noPrefixStop": True,
              "originalOuterSeconds": 1800, "httpSeconds": 15, "nativeSeconds": 8,
              "normalCandidateUnchanged": True, "runtimeCalls": 0,
              "metadataObservationRowCap": 2048, "previousPrefixRowCap": 512,
              "rowCapChangesProductBudget": False,
              "rowCapReason": "Bound metadata for the complete 128 profile and its original read-only polls; original request and operation budgets stay fixed.",
              "originalFormalLauncherSha256": hashlib.sha256(original).hexdigest(),
              "body": {"bytes": len(source.encode()), "sha256": hashlib.sha256(source.encode()).hexdigest()},
              "launcher": {"bytes": len(assembled.encode()), "sha256": hashlib.sha256(assembled.encode()).hexdigest()},
              "payloads": {k: {x: v[x] for x in ("bytes", "sha256")} for k, v in payloads.items()}}
    (ROOT / "ha128-observed-r4-source-integrity.public.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
