#!/usr/bin/env python3
"""The complete original DirectLanRun98 with one explicit synced data source.

All three stores complete the original real cold unseals before choosing
Pocket4 as the sole intact ciphertext source. The original three stop calls
are ordered2, then1/3 after a real two-voter committed-frontier observation.
Both missing stores still form
the actual Raft election. If their actual leader is not Mac, this direction
is uncovered and this fresh fixture stops before the target unseal.
No leader result, request, deadline, retry, ReadIndex, fsync or cleanup is faked.
The separate unchanged canonical128 already covers the official30 sequence.
"""
from __future__ import annotations

import argparse
import inspect
import textwrap
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import shlex
import ssl
import urllib.error

sys.dont_write_bytecode = True
pre = argparse.ArgumentParser(add_help=False)
pre.add_argument('--candidate-source', type=Path, required=True)
pre.add_argument('--describe-contract', action='store_true')
options, remaining = pre.parse_known_args()
SOURCE = options.candidate_source.resolve(strict=True)
NUMERIC_HELPER = Path(__file__).resolve().with_name('read_stopped_direction_frontier_r3.py')
NUMERIC_HELPER_SHA256 = 'e5dbccfdcb4881dfd2ce9bdfea5bf7bdfbbca6b5ce0684c412f67e5d32ea12e0'
COMMIT = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE = '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
PINS = {
    'ha_multihost_live.py': '0e7362d3e579f8a13d63ad1573745fb8cda71aeba75f40288db3927204e408de',
    'native_v6_ha_multihost_live.py': '330cc6fe8eccb02711e897753ef70d9f3f46717f581f6e80a7b814f7603c638c',
    'native_v6_ha_direct_lan_live.py': '8b82b66555f0190eeb0eaf40ad2a19006de932297fa01b512b22b73675995197',
    'native_v6_ha_official_history_live.py': '758e5d6cc93900fd6c5de328446fce069f167fe1eb7c63fc1f2a8310231e04d5',
    'native_fixture_recovery.py': '4c71ef73947ba30a1f4f24344a9840f38f78350c223a4cc80c2b3cb53d777af3',
}


def source_binding():
    def git(*argv):
        return subprocess.check_output(
            ['git', '-C', str(SOURCE), *argv], text=True, timeout=30).strip()
    assert git('rev-parse', 'HEAD') == COMMIT
    assert git('rev-parse', 'HEAD^{tree}') == TREE
    assert git('status', '--porcelain') == ''
    for name, digest in PINS.items():
        assert hashlib.sha256((SOURCE / 'qa/openbao-acceptance' / name).read_bytes()).hexdigest() == digest


source_binding()
assert NUMERIC_HELPER.is_file() and not NUMERIC_HELPER.is_symlink()
assert hashlib.sha256(NUMERIC_HELPER.read_bytes()).hexdigest() == NUMERIC_HELPER_SHA256
sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
import native_v6_ha_official_history_live as original

direct, native, base = original.direct, original.native, original.base
assert len(direct.DIRECT_CHECKS) == 98 and len(original.EXTRA_CHECKS) == 30
assert len(original.OfficialHistoryRun.required_checks) == 128
assert native.REQUEST_SECONDS == 15 and native.NATIVE_ADMISSION_SECONDS == 8
assert native.TARGET_BYTES == 34 * 1024 * 1024

assert len(direct.DirectLanRun.required_checks) == 98
cipher_inventory = native.cipher_inventory
TARGET_BYTES = native.TARGET_BYTES
REQUEST_SECONDS = native.REQUEST_SECONDS
original_method = textwrap.dedent(inspect.getsource(direct.DirectLanRun.missing_cipher_leader)).strip()
assert hashlib.sha256(original_method.encode()).hexdigest() == 'cae208acf0482cfddb43f55722aa98a47eafbcac16aba6b26d52c61381835298'


class PocketSourceDirect98Run(direct.DirectLanRun):
    def __init__(self, *args):
        super().__init__(*args)
        own = Path(__file__).resolve()
        self.source_files[str(own)] = base.sha256_file(own)
        self.source_files[str(NUMERIC_HELPER)] = NUMERIC_HELPER_SHA256
        self.direction_numeric_dispatched = set()
        self.report.update({
            'schema': 'heptabao.normal-r10-explicit-pocket-source-direct98.v2',
            'scope': 'normal-r10-complete-direct98-plus-pocket3-to-mac1-direction',
            'runner_sha256': base.sha256_file(own),
            'source_selection_controlled': True,
            'requested_cipher_source_node': 3,
            'requested_actual_empty_leader_node': 1,
            'leader_selection_forced': False,
            'directional_numeric_reads': [],
            'numeric_helper_sha256': NUMERIC_HELPER_SHA256,
            'new_readonly_preparation_seconds': 60,
            'new_numeric_read_seconds': 15,
            'new_numeric_ssh_seconds': 45,
            'canonical_original_workflow_unchanged': False,
            'original98_assertions_and_denominator_preserved': True,
            'required_original_checks': 98,
            'official30_repeated_in_this_scope': False,
            'canonical128_summary_sha256': '9a23e1b4cce8638f7b5c8ea37d41929864c8b4ef35e0bef47292695d4703405e',
            'ordinary_http_budget_seconds': 15,
            'native_admission_budget_seconds': 8,
            'private_diagnostic_feature_enabled': False,
            'normal_default_candidate': True,
            'production_authority': False,
        })

    def _direction_read_numeric(self, node, *, until=None):
        if node in self.started or node.node_id not in (1, 2):
            raise base.FixtureError("direction_numeric_requires_owned_stopped_node")
        if node.node_id in self.direction_numeric_dispatched:
            raise base.FixtureError("direction_numeric_read_would_be_repeated")
        code = NUMERIC_HELPER.read_bytes()
        if hashlib.sha256(code).hexdigest() != NUMERIC_HELPER_SHA256:
            raise base.FixtureError("direction_numeric_helper_changed")
        script = code.decode("utf-8")
        delimiter = "HB_DIRECTION_R3_NUMERIC"
        if delimiter in script.splitlines():
            raise base.FixtureError("direction_numeric_source_delimiter")
        self.direction_numeric_dispatched.add(node.node_id)
        row = {"node": node.node_id, "remote_completion_unknown": False,
               "dispatch_attempted": False, "source_sha256": NUMERIC_HELPER_SHA256, "repeated": False}
        self.report["directional_numeric_reads"].append(row)
        self.event("direction_numeric_read_intent", node=node.node_id,
                   source_sha256=NUMERIC_HELPER_SHA256)
        remaining = 45.0 if until is None else min(45.0, until - time.monotonic())
        if remaining <= 0:
            row["remote_completion_unknown"] = False
            row["not_dispatched"] = True
            raise base.FixtureError("direction_preparation_deadline_expired")
        seconds = min(15.0, remaining)
        python = (self.args.darwin_watchdog_python
                  if self.hosts[node.alias]["system"] == "Darwin" else "/usr/bin/python3")
        command = ("exec " + shlex.quote(python) + " -B - --node " + str(node.node_id)
                   + " --run-id " + shlex.quote(self.run_id)
                   + " --max-seconds " + repr(seconds) + " <<'" + delimiter + "'\n"
                   + script + "\n" + delimiter + "\n")
        started = time.monotonic()
        # Reuses the original strict host-key/BatchMode SSH transport. No child
        # is started by the remote reader; unknown completion aborts this run.
        row["dispatch_attempted"] = True
        row["remote_completion_unknown"] = True
        output = base.ssh(node, command, timeout=remaining)
        row["remote_completion_unknown"] = False
        row["ssh_elapsed_seconds"] = time.monotonic() - started
        if row["ssh_elapsed_seconds"] > remaining or (until is not None and time.monotonic() >= until):
            raise base.FixtureError("direction_numeric_reply_after_parent_deadline")
        if len(output.encode("utf-8")) > 65536:
            raise base.FixtureError("direction_numeric_public_output_bound")
        value = json.loads(output)
        observed = value.get("observation", {})
        if (value.get("schema") != "heptabao.direction-r3-stopped-node-numeric-observer.v1"
                or value.get("status") != "completed"
                or value.get("fixture_run_id") != self.run_id
                or value.get("publication_within_original_observer_deadline") is not True
                or value.get("new_observer_deadline_seconds") != seconds
                or value.get("child_processes") != 0 or value.get("file_writes") != 0
                or value.get("product_requests") != 0
                or observed.get("node_id") != node.node_id or observed.get("fixed_root") != node.root):
            raise base.FixtureError("direction_numeric_terminal_binding")
        projection = observed.get("numeric_projection", {})
        if (projection.get("complete_current_epoch_journal") is not True
                or projection.get("retained_log_contiguous") is not True
                or projection.get("committed_not_beyond_last_log") is not True
                or projection.get("projection_is_read_authority") is not False):
            raise base.FixtureError("direction_numeric_projection_incomplete")
        row["public_result_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
        row["result"] = value
        self.event("direction_numeric_read_complete", node=node.node_id,
                   public_result_sha256=row["public_result_sha256"])
        return projection

    def _direction_quorum_frontier(self, nodes, stopped_rog, until):
        baseline = stopped_rog.get("last_log_id")
        if not isinstance(baseline, dict) or type(baseline.get("index")) is not int:
            raise base.FixtureError("direction_stopped_baseline_missing")
        rows = self.report["directional_role_preparation"]["observations"]
        candidate, since = None, 0.0

        def get(node, path):
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise base.FixtureError("direction_preparation_deadline_expired")
            status, body = self.request(node, "GET", path, authenticate=False,
                                        timeout=min(2.0, remaining))
            if time.monotonic() >= until:
                raise base.FixtureError("direction_preparation_reply_after_deadline")
            return status, body

        while time.monotonic() < until:
            if len(rows) >= 512:
                raise base.FixtureError("direction_preparation_observation_bound")
            row = {"elapsed_seconds": 60.0 - (until - time.monotonic()), "health": []}
            rows.append(row)
            active = []
            for node in nodes:
                try:
                    status, body = get(node, "sys/health")
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    row["health"].append({"node": node.node_id, "response_observed": False})
                    continue
                row["health"].append({
                    "node": node.node_id, "status": status,
                    "sealed": body.get("sealed") if type(body.get("sealed")) is bool else None,
                    "ha_active": body.get("ha_active") if type(body.get("ha_active")) is bool else None,
                    "ha_application_ready": body.get("ha_application_ready")
                        if type(body.get("ha_application_ready")) is bool else None,
                    "standby": body.get("standby") if type(body.get("standby")) is bool else None})
                if status == 200:
                    if (body.get("ha_active") is not True
                            or body.get("ha_application_ready") is not True
                            or body.get("standby") is not False or body.get("sealed") is not False):
                        raise base.FixtureError("direction_health_without_actual_ready_leader")
                    active.append(node)
            if len(active) > 1:
                raise base.FixtureError("direction_preparation_multiple_actual_leaders")
            eligible = False
            if len(active) == 1:
                leader = active[0]
                try:
                    status, local = get(leader, "sys/leader")
                    mac = next(node for node in nodes if node.node_id == 1)
                    if leader == mac:
                        mac_status, mac_local = status, local
                    else:
                        mac_status, mac_local = get(mac, "sys/leader")
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    status, local, mac_status, mac_local = None, {}, None, {}
                leader_frontier = base.parsed_local_frontier(local) if status == 200 else None
                mac_frontier = base.parsed_local_frontier(mac_local) if mac_status == 200 else None
                row["leader_node"] = leader.node_id
                row["leader_frontier"] = list(leader_frontier) if leader_frontier else None
                row["mac_frontier"] = list(mac_frontier) if mac_frontier else None
                eligible = (local.get("is_self") is True and leader_frontier is not None
                            and mac_frontier is not None and mac_frontier[0] == mac_frontier[1]
                            and mac_frontier[1] >= leader_frontier[0] > baseline["index"])
                now = time.monotonic()
                if eligible and now < until:
                    if candidate == leader and now - since >= 2.2:
                        result = {"leader_node": leader.node_id,
                                  "leader_committed_index": leader_frontier[0],
                                  "mac_committed_index": mac_frontier[0],
                                  "mac_applied_index": mac_frontier[1],
                                  "stable_seconds": now - since,
                                  "within_new_preparation_deadline": True}
                        self.report["directional_role_preparation"]["quorum_frontier"] = result
                        self.event("direction_real_quorum_frontier_observed", **result)
                        if time.monotonic() >= until:
                            raise base.FixtureError("direction_preparation_publication_after_deadline")
                        return result
                    if candidate != leader:
                        candidate, since = leader, now
            if not eligible:
                candidate, since = None, 0.0
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.1, remaining))
        raise base.FixtureError("direction_new_committed_frontier_not_observed")

    def _direction_verify_prepared_frontier(self, rog, mac, frontier, pre_stop_rog, until):
        old_last, old_committed, old_vote = rog.get("last_log_id"), rog.get("committed_log_id"), rog.get("final_vote")
        new_last, new_committed, new_vote = mac.get("last_log_id"), mac.get("committed_log_id"), mac.get("final_vote")
        if not all(isinstance(item, dict) for item in
                   (old_last, old_committed, old_vote, new_last, new_committed, new_vote)):
            raise base.FixtureError("direction_numeric_frontier_shape")
        if (old_committed["index"] < pre_stop_rog["applied_index"]
                or new_committed["index"] != frontier["mac_applied_index"]
                or new_committed["index"] <= old_last["index"]
                or new_committed["leader_id"]["term"] <= max(old_last["leader_id"]["term"],
                                                             old_vote["leader_id"]["term"])
                or old_vote["committed"] is not True or new_vote["committed"] is not True
                or new_vote["leader_id"] != new_committed["leader_id"]
                or new_committed["leader_id"]["node_id"] != frontier["leader_node"]
                or new_committed["leader_id"]["node_id"] not in (1, 3)
                or new_last["index"] < new_committed["index"]):
            raise base.FixtureError("direction_new_persisted_frontier_not_proven")
        proof = {"stopped_rog_last": old_last, "stopped_rog_committed": old_committed,
                 "stopped_rog_vote": old_vote, "stopped_mac_last": new_last,
                 "stopped_mac_committed": new_committed, "stopped_mac_vote": new_vote,
                 "mac_passive_applied_index": frontier["mac_applied_index"],
                 "numeric_preparation_proven": True,
                 "this_does_not_assert_next_actual_leader": True}
        self.report["directional_role_preparation"]["persisted_frontier_proof"] = proof
        self.event("direction_preparation_complete", **proof)
        if time.monotonic() >= until:
            raise base.FixtureError("direction_preparation_completion_after_deadline")
        proof["within_new_total_prepare_deadline"] = True
        proof["new_total_prepare_elapsed_seconds"] = 60.0 - (until - time.monotonic())

    def missing_cipher_leader(self, healthy):
        self.stage = "owned_missing_cipher_leader_recovery"
        # Bring each actual local native store to the current selected closure
        # through an ordinary cold unseal before choosing a healthy source.
        # This is necessary because a prior quorum ACK required only two stores.
        for node in self.nodes:
            self.stop(node)
            self.start(node)
            self.unseal(node)
        original_leader = self.leader(self.nodes)
        healthy = next(node for node in self.nodes if node.node_id == 3)
        self.report["directional_source_selection"] = {
            "requested_source_node": 3, "selected_source_node": healthy.node_id,
            "actual_pre_quarantine_leader_node": original_leader.node_id,
            "all_three_original_cold_unseals_completed": True,
            "data_source_selection_does_not_claim_leader_authority": True,
        }
        rog = next(node for node in self.nodes if node.node_id == 2)
        mac = next(node for node in self.nodes if node.node_id == 1)
        status, before = self.request(rog, "GET", "sys/leader", authenticate=False, timeout=2)
        old_frontier = base.parsed_local_frontier(before) if status == 200 else None
        if old_frontier is None or type(before.get("is_self")) is not bool:
            raise base.FixtureError("direction_rog_pre_stop_frontier_unavailable")
        pre_stop_rog = {"is_self": before["is_self"], "committed_index": old_frontier[0],
                        "applied_index": old_frontier[1]}
        self.report["directional_role_preparation"] = {
            "original_three_stop_calls_preserved": True, "stop_order": [2, 1, 3],
            "new_total_prepare_seconds": 60, "pre_stop_rog": pre_stop_rog,
            "observations": [], "leader_selection_forced": False}
        self.stop(rog)
        prepare_until = time.monotonic() + 60.0
        stopped_rog = self._direction_read_numeric(rog, until=prepare_until)
        frontier = self._direction_quorum_frontier([mac, healthy], stopped_rog, prepare_until)
        self.stop(mac)
        if time.monotonic() >= prepare_until:
            raise base.FixtureError("direction_preparation_deadline_expired")
        self.stop(healthy)
        if time.monotonic() >= prepare_until:
            raise base.FixtureError("direction_preparation_deadline_expired")
        self.check("missing_cipher_targets_stopped", not self.started)
        stopped_mac = self._direction_read_numeric(mac, until=prepare_until)
        self._direction_verify_prepared_frontier(stopped_rog, stopped_mac, frontier,
                                                 pre_stop_rog, prepare_until)
        missing = [node for node in self.nodes if node != healthy]
        inventories = {node: cipher_inventory(node, self.run_id, "quarantine") for node in missing}
        self.check("missing_cipher_two_targets_quarantined", all(
            receipt.get("remaining_count") == 0
            and receipt.get("quarantined_count", 0) > 0
            and receipt.get("quarantined_bytes", 0) >= TARGET_BYTES
            for receipt in inventories.values()),
            nodes={str(node.node_id): receipt for node, receipt in inventories.items()})
        for node in missing:
            self.start(node)
            base.wait_listener(self.context, node)
        elected = self.wait_sealed_leader(missing)
        self.check("missing_cipher_sealed_pair_elected", elected in missing,
                   leader=elected.node_id, both_voters_have_no_native_ciphertext=True)
        self.start(healthy)
        base.wait_listener(self.context, healthy)
        still_elected = self.wait_sealed_leader(self.nodes, expected=elected)
        self.check("missing_cipher_source_rejoined", still_elected == elected,
                   source=healthy.node_id, selected_missing_leader_is_current=elected.node_id)
        self.report["directional_observed_pair"] = {
            "source_node": healthy.node_id, "actual_empty_leader_node": elected.node_id,
            "requested_pair_observed": healthy.node_id == 3 and elected.node_id == 1,
            "leader_selection_forced": False,
        }
        if healthy.node_id != 3 or elected.node_id != 1:
            raise base.FixtureError("directional_pocket_to_mac_pair_not_observed")
        empty = cipher_inventory(elected, self.run_id, "empty")
        self.check("missing_cipher_leader_empty_before_unseal", empty.get("remaining_count") == 0
                   and empty.get("inventory_sha256") == inventories[elected]["inventory_sha256"],
                   leader=elected.node_id)
        self.unseal(elected)
        self.check("missing_cipher_leader_unsealed", True, original_http_budget_seconds=REQUEST_SECONDS)
        status, local = self.request(elected, "GET", "sys/leader", authenticate=False)
        if status != 200 or local.get("is_self") is not True:
            raise base.FixtureError("missing_cipher_reader_was_not_actual_leader")
        self.history_reads(elected)
        self.check("missing_cipher_leader_exact_history", True,
                   leader=elected.node_id, retained_large_payload_bytes=TARGET_BYTES)
        recovered = cipher_inventory(elected, self.run_id, "recovered")
        self.check("missing_cipher_actual_leaves_rebuilt",
                   recovered.get("restored_count", 0) > 0
                   and recovered.get("restored_bytes", 0) >= TARGET_BYTES
                   and recovered.get("every_restored_sha_and_size_match") is True
                   and recovered.get("inventory_sha256") == inventories[elected]["inventory_sha256"],
                   **recovered)
        # Old, unreachable ciphertext remains quarantined; recovery is required
        # to rebuild the committed closure, not resurrect every prior orphan.
        for node in self.nodes:
            if node != elected:
                self.unseal(node)
        self.check("missing_cipher_remaining_nodes_unsealed", True)
        self.small_reads(self.nodes)
        self.check("missing_cipher_all_hosts_readindex", True)
        return self.leader(self.nodes)


for method_name in ('execute', 'request', 'cleanup', 'check', 'start', 'stop',
                    'unseal', 'leader', 'wait_sealed_leader',
                    'full_cold_restart', 'failover_and_quorum', 'finish_application'):
    assert getattr(PocketSourceDirect98Run, method_name) is getattr(direct.DirectLanRun, method_name)

if options.describe_contract:
    print(json.dumps({
        'schema': 'heptabao.normal-r10-explicit-pocket-source-direct98-contract.v1',
        'source_commit': COMMIT, 'source_tree': TREE, 'qa_pins': PINS,
        'required_checks': sorted(direct.DirectLanRun.required_checks),
        'required_check_count': 98, 'original_direct_count': 98,
        'official_history_count_in_this_scope': 0,
        'original_http_seconds': native.REQUEST_SECONDS,
        'original_admission_seconds': native.NATIVE_ADMISSION_SECONDS,
        'original_history_payload_bytes': native.TARGET_BYTES,
        'requested_cipher_source_node': 3, 'requested_actual_empty_leader_node': 1,
        'all_three_original_cold_unseals_preserved': True,
        'numeric_helper_sha256': NUMERIC_HELPER_SHA256,
        'controlled_stop_order': [2, 1, 3],
        'original_stop_count_preserved': 3,
        'new_role_prepare_seconds': 60,
        'new_numeric_read_seconds': 15, 'new_numeric_ssh_seconds': 45,
        'original_sealed_election_seconds': 60,
        'real_new_committed_frontier_required_before_quarantine': True,
        'actual_election_required': True, 'leader_selection_forced': False,
        'wrong_actual_direction_stops_before_target_unseal': True,
        'only_runtime_method_override': 'missing_cipher_leader',
        'original_method_normalized_sha256': hashlib.sha256(original_method.encode()).hexdigest(),
        'direction_method_normalized_sha256': hashlib.sha256(textwrap.dedent(inspect.getsource(PocketSourceDirect98Run.missing_cipher_leader)).strip().encode()).hexdigest(),
        'inherited_execute_request_check_cleanup_identities_verified': True,
        'canonical128_summary_sha256': '9a23e1b4cce8638f7b5c8ea37d41929864c8b4ef35e0bef47292695d4703405e',
        'fixture_started': False,
    }, sort_keys=True))
    raise SystemExit(0)

parsed = direct.parsed_arguments(remaining)
args = parsed[0]
if args.source_commit != COMMIT or args.source_tree != TREE:
    raise SystemExit('directional_source_binding_mismatch')
raise SystemExit(native.execute_fixture(*parsed, run_type=PocketSourceDirect98Run))
