"""Observe the complete original 128-case HA run without changing its workload.

The original OfficialHistoryRun, parser and execute_fixture retain every test,
mutation, lifecycle, denominator, budget and final qualification decision. This
adapter delegates the entire original execute once; it has no ten-write stop.
Only the existing base.api transport is observed. Original CLI/wire helpers
are not instrumented or represented as covered by these observations.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import urllib.error

import kv2_dr_process_custody as custody
import native_v6_ha_official_history_live as official
import ha_http_transport_observer_formal_r1 as observer

native, base = official.native, official.base
X230_ROOT = "/home/qian/heptabao-native-ha-4bde9-authbus-20261107-r4"
SNAPSHOT = Path(__file__).with_name("observe_ha128_r4_owned_x230_pid.py")


class ObservedOfficialHistoryRun(official.OfficialHistoryRun):
    def __init__(self, *args):
        super().__init__(*args)
        if len(self.required_checks) != 128 or self.required_checks is not official.OfficialHistoryRun.required_checks:
            raise base.FixtureError("observer_original_128_definition_changed")
        self.native_x230_pid = None
        self.snapshot_attempted = False
        self.transport_rows = []
        for path in (Path(__file__).resolve(), Path(observer.__file__).resolve(), SNAPSHOT.resolve()):
            self.source_files[str(path)] = base.sha256_file(path)
        bound = observer.bind_original_api(base.api, self.transport_rows)
        self.report.update({
            "transportObservationScope": "original-base-api-only; no CLI-or-wire-helper-coverage",
            "transportObservations": self.transport_rows,
            "transportObservationRowCap": 2048,
            "observerBinding": {**bound.binding_changes,
                                "originalApiSourceSha256": bound.original_source_sha256},
            "observerChangesOriginalWorkload": False,
            "observerChangesFormalDenominator": False,
            "observerChangesOriginalBudgets": False,
            "observerOriginalRequiredCheckCount": 128,
            "optionalOwnedSnapshot": {"attempted": False},
        })
        base.api = bound

    def start(self, node, *, native=True):
        if native and node.node_id == 1:
            # A later original cold-restart is still the original workload.
            # Never reuse the previous PID if this new startup is unresolved.
            self.native_x230_pid = None
        pid = super().start(node, native=native)
        if native and node.node_id == 1:
            self.native_x230_pid = pid
        return pid

    def execute(self):
        try:
            return super().execute()
        except BaseException as error:
            # One bounded read-only snapshot only for the current X230 original
            # process and the same failed API call. No new product/request,
            # foreign PID, repeated operation or different host is introduced.
            try:
                tail = self.transport_rows[-1] if self.transport_rows else None
                if (isinstance(error, (OSError, urllib.error.URLError))
                        and isinstance(tail, dict) and tail.get("node") == 1
                        and tail.get("error") == observer.safe_error(error)
                        and self.nodes[0] in self.started):
                    self.observe_owned_failure()
            except BaseException:
                self.report["optionalSnapshotReportingFailed"] = True
            raise

    def observe_owned_failure(self):
        if self.snapshot_attempted:
            raise base.FixtureError("diagnostic_snapshot_must_not_repeat")
        if (self.native_x230_pid is None or not self.transport_rows
                or "error" not in self.transport_rows[-1]):
            return
        self.snapshot_attempted = True
        result = self.report["optionalOwnedSnapshot"] = {
            "attempted": True, "ok": False, "originalFailureUnchanged": True,
            "helperSeconds": 5, "sshSeconds": 15, "childScope": "one-readonly-SSH",
            "remoteClosureUnknown": True,
        }
        owner = None
        raw = b""
        try:
            source = SNAPSHOT.read_bytes()
            if hashlib.sha256(source).hexdigest() != self.source_files[str(SNAPSHOT.resolve())]:
                raise base.FixtureError("diagnostic_snapshot_source_changed")
            node = self.nodes[0]
            if node.node_id != 1 or node.alias != "x230" or node.root != X230_ROOT:
                raise base.FixtureError("diagnostic_snapshot_target_changed")
            script = ("/usr/bin/python3 -I -S -B - " + shlex.quote(self.run_id)
                      + " " + str(self.native_x230_pid) + " <<'HB_HISTORY10_OWNED_PID'\n"
                      + source.decode("utf-8") + "\nHB_HISTORY10_OWNED_PID\n")
            # Publish intent before the single extra read-only remote action.
            self.checkpoint()
            with custody.activated() as owner:
                try:
                    value = base.ssh(node, script, timeout=15)
                    raw, exit_code = value.encode("utf-8"), 0
                except subprocess.CalledProcessError as error:
                    raw = error.stdout or b""
                    exit_code = error.returncode
                    result["stderrBytes"] = len(error.stderr or b"")
                owner.assert_retired()
            result["exitCode"] = exit_code
            if not isinstance(raw, bytes) or len(raw) > 65536:
                raise base.FixtureError("diagnostic_snapshot_output_bound")
            native.write_private(self.work / "owned-x230-snapshot.original.json", raw)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.get("schema") != "heptabao.history10-owned-x230-pid-observation.v1":
                raise base.FixtureError("diagnostic_snapshot_schema")
            result["observation"] = parsed
            facts = parsed.get("fdCloseFacts", {})
            result["remoteFinalObserved"] = True
            result["remoteClosureUnknown"] = not (
                type(facts.get("opened")) is int and type(facts.get("closed")) is int
                and facts["opened"] == facts["closed"] and facts["opened"] >= 0
            )
            result["ok"] = exit_code == 0 and parsed.get("ok") is True
        except BaseException as error:
            result["failure"] = observer.safe_error(error)
        finally:
            if owner is not None:
                result["processCustody"] = owner.receipt()
                if owner.receipt().get("passed_process_custody") is not True:
                    result["ok"] = False
                    result["remoteClosureUnknown"] = True


def main(argv=None):
    original_api = base.api
    try:
        return native.execute_fixture(*official.parsed_arguments(argv),
                                      run_type=ObservedOfficialHistoryRun)
    finally:
        base.api = original_api
