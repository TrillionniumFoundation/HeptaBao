"""Run only the unchanged original HA prefix through history write ten.

The formal class and its required 128 checks remain unchanged. This separate
diagnostic stops after the original exact GET for version 12 succeeds, before
an eleventh history mutation. It can never set any HA qualification flag.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
import subprocess

import kv2_dr_process_custody as custody
import native_v6_ha_official_history_live as official
import ha_http_transport_observer_r1 as observer

native, base = official.native, official.base
SCHEMA = "heptabao.history10-transport-diagnostic.v1"
X230_ROOT = "/home/qian/heptabao-ha-history10-transport-20261107-r1"
SNAPSHOT = Path(__file__).with_name("observe_history10_owned_x230_pid_r1.py")
PREFIX_CHECKS = frozenset({
    "official271_source_evidence_bound", "node_1_build_receipt", "node_2_build_receipt",
    "node_3_build_receipt", "candidate_binary_digest", "node_1_new_private_root",
    "node_1_binary_digest", "node_2_new_private_root", "node_2_binary_digest",
    "node_3_new_private_root", "node_3_binary_digest", "three_distinct_physical_hosts",
    "same_source_native_abis", "direct_lan_endpoints_configured", "seed_fresh_uninitialized",
    "seed_initialized_once", "seed_unsealed", "official271_mount_created_before_activation",
    "seed_v5_and_kv2_history", "seed_stopped_cold_archive", "node_2_cold_clone",
    "node_3_cold_clone", "three_raft_elected_before_unseal", "node_1_initial_unseal",
    "node_2_initial_unseal", "node_3_initial_unseal", "direct_lan_mtls_1_to_2",
    "direct_lan_mtls_1_to_3", "direct_lan_mtls_2_to_1", "direct_lan_mtls_2_to_3",
    "direct_lan_mtls_3_to_1", "direct_lan_mtls_3_to_2", "direct_lan_api_leaf_1",
    "direct_lan_api_leaf_2", "direct_lan_api_leaf_3", "native_activate_once",
    "native_v5_history_preserved", "native_noop_config_accepted",
    "native_delete_missing_accepted", "owned_processes_stopped", "owned_mesh_stopped",
} | {f"native_history_write_{ordinal:02d}" for ordinal in range(1, 11)})
FALSE_FLAGS = (
    "qualification", "independent_qualification", "production_authority",
    "direct_lan_qualification", "full_openbao_compatibility",
    "official_history_chain_qualified", "native_ha_backup_verified",
    "ha_raw_storage_precision_qualified", "fullReplacementQualified",
)


class PrefixComplete(Exception):
    """Private control flow after the original tenth exact read has returned."""


class History10Run(official.OfficialHistoryRun):
    # Inherit the original 128 required checks. No formal denominator changes.
    def __init__(self, *args):
        super().__init__(*args)
        if len(self.required_checks) != 128 or len(PREFIX_CHECKS) != 51:
            raise base.FixtureError("original_and_diagnostic_denominators_changed")
        if not PREFIX_CHECKS < self.required_checks:
            raise base.FixtureError("diagnostic_prefix_not_original_subset")
        self.prefix_completed = False
        self.snapshot_attempted = False
        self.native_x230_pid = None
        self.transport_rows = []
        for path in (Path(__file__).resolve(), Path(observer.__file__).resolve(), SNAPSHOT.resolve()):
            self.source_files[str(path)] = base.sha256_file(path)
        self.report.update({
            "schema": SCHEMA, "status": "diagnostic-failed", "diagnosticOnly": True,
            "scope": "original-HA-prefix-through-ten-writes-and-exact-GET-version12",
            "originalFormalRequiredChecks": 128, "diagnosticOriginalPrefixChecks": 51,
            "diagnosticPrefixCompleted": False, "tenthExactReadReturned": False,
            "eleventhHistoryMutationDispatched": False,
            "transportObservations": self.transport_rows,
            "observerAddsRequests": False, "observerChangesTimeouts": False,
            "observerChangesTlsContext": False, "automaticRetry": False,
            "optionalOwnedSnapshot": {"attempted": False},
            "history_payload_target_bytes": 10 * native.PAYLOAD_BYTES,
            "formalHistoryPayloadTargetBytes": native.TARGET_BYTES,
            "uncovered": ["full-128-case-HA-profile", "history-writes-11-through-17",
                          "official-history-import-and-snapshot-and-cold-recovery",
                          "production-traffic-switch", "old-production-asset-cleanup"],
            **{flag: False for flag in FALSE_FLAGS},
        })

    def start(self, node, *, native=True):
        pid = super().start(node, native=native)
        if native and node.node_id == 1:
            if self.native_x230_pid is not None:
                raise base.FixtureError("diagnostic_native_restart_forbidden")
            self.native_x230_pid = pid
        return pid

    def exact_read(self, node, path, expected, *, version=None):
        result = super().exact_read(node, path, expected, version=version)
        if (self.stage == "seventeen_actual_native_history_writes"
                and path == self.path and version == 12):
            if (node.node_id != 1 or len(self.history) != 12
                    or self.prefix_completed or self.history.get(12) != expected):
                raise base.FixtureError("diagnostic_tenth_exact_read_binding")
            self.prefix_completed = True
            self.report["tenthExactReadReturned"] = True
            raise PrefixComplete()
        return result

    def execute(self):
        self.prepare()
        leader = self.bootstrap_v5()
        # Observe the same target as the original failure; do not force an
        # election or mutate a different target and call it this reproduction.
        if leader.node_id != 1 or leader.alias != "x230" or leader.root != X230_ROOT:
            raise base.FixtureError("diagnostic_original_target_not_elected")
        self.report["diagnosticOriginalTargetObserved"] = True
        try:
            # This is the unchanged original 17-iteration method. The only exit
            # hook is above, after its tenth original exact read has succeeded.
            self.activate_and_grow(leader)
        except PrefixComplete:
            if not self.prefix_completed:
                raise base.FixtureError("diagnostic_prefix_completion_unbound")
            return
        raise base.FixtureError("diagnostic_prefix_stop_not_reached")

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
    args, nodes, mesh, sources, receipts, expected = official.parsed_arguments(argv)
    args.work_root.mkdir(mode=0o700)
    run = History10Run(args, nodes, mesh, sources, receipts, expected)
    original_api = base.api
    bound = observer.bind_original_api(original_api, run.transport_rows)
    run.report["observerBinding"] = {**bound.binding_changes,
                                     "originalApiSourceSha256": bound.original_source_sha256}
    completed = cleanup = inputs_exact = False
    handlers = base.install_signal_handlers()
    try:
        base.api = bound
        with native.strict_shared_transport():
            try:
                run.checkpoint()
                run.execute()
                completed = run.prefix_completed
            except BaseException as error:
                run.report["failure_code"] = native.failure_code(error)
                run.report["failure_stage"] = run.stage
                run.report["failure_type"] = type(error).__name__
                run.report["firstFailure"] = observer.safe_error(error)
                try:
                    run.observe_owned_failure()
                except BaseException:
                    run.report["optionalSnapshotReportingFailed"] = True
            finally:
                try:
                    cleanup = run.cleanup()
                except BaseException as error:
                    run.report.setdefault("failure_code", native.failure_code(error))
                    run.report["cleanup_reporting_failure"] = True
            # This is read-only verification of the already-stopped owned roots.
            # Reuse the original source/input/binary/CA comparisons, without
            # claiming any later application, import or cold-recovery check.
            try:
                inputs_exact = (
                    run.verify_inputs()
                    and all(base.sha256_file(Path(path)) == pin for path, pin in run.source_files.items())
                    and all(base.remote_binary_digest(node) == run.expected[str(node.node_id)] for node in run.nodes)
                    and base.sha256_file(run.work / "ca.crt") == run.ca_sha256
                )
            except BaseException as error:
                run.report["diagnosticInputRecheckError"] = observer.safe_error(error)
    finally:
        base.api = original_api
        base.restore_signal_handlers(handlers)
    found = [row["case"] for row in run.checks]
    prefix_exact = (len(found) == len(PREFIX_CHECKS) and set(found) == PREFIX_CHECKS
                    and all(row.get("passed") is True for row in run.checks))
    mutations = run.recovery.public_receipt
    run.report["diagnosticInputsAfterCleanupExact"] = inputs_exact
    run.report["diagnosticOriginalPrefixChecksExact"] = prefix_exact
    run.report["diagnosticMutationLedgerExact"] = (
        mutations.get("mutation_intents") == mutations.get("mutation_responses") == 23
        and mutations.get("unknown_transport_outcomes") == 0
        and mutations.get("automatic_resume_or_retry") is False
    )
    run.report["observed_check_count"] = len(run.checks)
    run.report["passed_check_count"] = sum(row.get("passed") is True for row in run.checks)
    run.report["missing_checks"] = sorted(run.required_checks - set(found))
    run.report["diagnosticPrefixCompleted"] = (
        completed and cleanup and inputs_exact and prefix_exact
        and not run.report.get("failure_code")
        and run.report["diagnosticMutationLedgerExact"] is True
        and base.report_is_secret_safe(run.report, run.secrets())
    )
    for flag in FALSE_FLAGS:
        run.report[flag] = False
    if run.report["diagnosticPrefixCompleted"]:
        run.report["status"] = "diagnostic-prefix-complete"
    final = base.secret_safe_report(run.report, run.secrets())
    run.root_token = run.unseal_key = ""
    run.confidential.clear()
    native.write_private(args.work_root / "summary.json", native.canonical(final) + b"\n")
    ok = final.get("status") == "diagnostic-prefix-complete" and final.get("diagnosticPrefixCompleted") is True
    print(json.dumps({"schema": SCHEMA, "status": final.get("status"),
                      "originalPrefixChecks": len(run.checks), "formalRequiredChecks": 128,
                      "fullHaQualified": False}, sort_keys=True))
    return 0 if ok else 1
