#!/usr/bin/env python3
"""The complete original DirectLanRun98 with one explicit synced data source.

All three stores complete the original real cold unseals before choosing
Pocket4 as the sole intact ciphertext source. Both missing stores still form
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

sys.dont_write_bytecode = True
pre = argparse.ArgumentParser(add_help=False)
pre.add_argument('--candidate-source', type=Path, required=True)
pre.add_argument('--describe-contract', action='store_true')
options, remaining = pre.parse_known_args()
SOURCE = options.candidate_source.resolve(strict=True)
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
        self.report.update({
            'schema': 'heptabao.normal-r10-explicit-pocket-source-direct98.v1',
            'scope': 'normal-r10-complete-direct98-plus-pocket3-to-mac1-direction',
            'runner_sha256': base.sha256_file(own),
            'source_selection_controlled': True,
            'requested_cipher_source_node': 3,
            'requested_actual_empty_leader_node': 1,
            'leader_selection_forced': False,
            'canonical_original_workflow_unchanged': False,
            'original98_assertions_and_denominator_preserved': True,
            'required_original_checks': 98,
            'official30_repeated_in_this_scope': False,
            'canonical128_summary_sha256': 'PENDING_ACTUAL_R10_FULL128_SUMMARY_SHA256',
            'ordinary_http_budget_seconds': 15,
            'native_admission_budget_seconds': 8,
            'private_diagnostic_feature_enabled': False,
            'normal_default_candidate': True,
            'production_authority': False,
        })

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
        for node in self.nodes:
            self.stop(node)
        self.check("missing_cipher_targets_stopped", not self.started)
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
        'actual_election_required': True, 'leader_selection_forced': False,
        'wrong_actual_direction_stops_before_target_unseal': True,
        'only_runtime_method_override': 'missing_cipher_leader',
        'original_method_normalized_sha256': hashlib.sha256(original_method.encode()).hexdigest(),
        'direction_method_normalized_sha256': hashlib.sha256(textwrap.dedent(inspect.getsource(PocketSourceDirect98Run.missing_cipher_leader)).strip().encode()).hexdigest(),
        'inherited_execute_request_check_cleanup_identities_verified': True,
        'canonical128_summary_sha256': 'PENDING_ACTUAL_R10_FULL128_SUMMARY_SHA256',
        'fixture_started': False,
    }, sort_keys=True))
    raise SystemExit(0)

parsed = direct.parsed_arguments(remaining)
args = parsed[0]
if args.source_commit != COMMIT or args.source_tree != TREE:
    raise SystemExit('directional_source_binding_mismatch')
raise SystemExit(native.execute_fixture(*parsed, run_type=PocketSourceDirect98Run))
