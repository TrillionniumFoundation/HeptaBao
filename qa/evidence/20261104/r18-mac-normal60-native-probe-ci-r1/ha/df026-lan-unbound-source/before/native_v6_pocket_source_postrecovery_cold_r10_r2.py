#!/usr/bin/env python3
"""Fresh direct98 plus twelve independent post-recovery cold observations.

All three stores complete the original real cold unseals before choosing
Pocket4 as the sole intact ciphertext source. The original three stop calls
are ordered2, then1/3 after one owned CAS0 witness and its metadata deletion
produce a real two-voter committed-frontier observation.
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
import os
import stat
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
NUMERIC_HELPER = Path(__file__).resolve().with_name('read_stopped_postrecovery_frontier_r2.py')
NUMERIC_HELPER_SHA256 = '5515c6319ab577bed00260caa3bdec9ec730a0c057fb2fdfbfe9debd0afa8d77'
CIPHER_HELPER = Path(__file__).resolve().with_name('read_stopped_recovered_cipher_r2.py')
CIPHER_HELPER_SHA256 = 'a0b9685bd28512cefc62e09d2d61717b4a11229ab2e1e1ddc1d9cf7be3a87d64'
DEADLINE_QA = Path(__file__).resolve().with_name('deadline_qa')
DEADLINE_QA_PINS = {
    "ha_multihost_live.py": "e37e39459f290c8b9121039196038c9021607e86ed4112def8060d20b1233460",
    "native_v6_ha_multihost_live.py": "6fb8f2dbac97730bea706503fb07e9fd5de60e794475d52f32290e374f86d429",
    "native_v6_ha_direct_lan_live.py": "bc99f154d89dfbe8a82babb8c50bcda3accaf8c486c51750db48bfc4003932ea",
    "native_ha_foreground_watchdog.py": "04189572097f5f7ac1f4ea3eaf53afaa3bf9854043cec9e190b9fd96d628ef89"
}
POSTCOLD_SECONDS = 300.0
POSTCOLD_CHECKS = [
    "postcold.inputs_and_history_bound",
    "postcold.all_three_owned_processes_stopped",
    "postcold.mac_persisted_frontier_retained",
    "postcold.same_recovered_cipher_reference_retained",
    "postcold.new_processes_sealed",
    "postcold.real_sealed_leader_elected",
    "postcold.all_three_unsealed_once",
    "postcold.all_local_frontiers_retained",
    "postcold.leader_retained_history_exact",
    "postcold.all_metadata_and_retired_states_exact",
    "postcold.all_hosts_small_readindex",
    "postcold.shared_deadline_completed"
]
CONTROLLER_UNTIL = None
R3_SUCCESS_SUMMARY_SHA256 = 'db362c9c2041636912ccfc95076c6ec7948ec7918efc17032af856875e61cd41'
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
    assert DEADLINE_QA.resolve(strict=True) == DEADLINE_QA and not DEADLINE_QA.is_symlink()
    assert DEADLINE_QA.stat().st_uid == os.getuid() and stat.S_IMODE(DEADLINE_QA.stat().st_mode) == 0o700
    for name, digest in DEADLINE_QA_PINS.items():
        path = DEADLINE_QA / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size < 128 * 1024
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


source_binding()
assert NUMERIC_HELPER.is_file() and not NUMERIC_HELPER.is_symlink()
assert hashlib.sha256(NUMERIC_HELPER.read_bytes()).hexdigest() == NUMERIC_HELPER_SHA256
assert CIPHER_HELPER.is_file() and not CIPHER_HELPER.is_symlink()
assert hashlib.sha256(CIPHER_HELPER.read_bytes()).hexdigest() == CIPHER_HELPER_SHA256
sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
sys.path.insert(0, str(DEADLINE_QA))
import native_v6_ha_official_history_live as original

direct, native, base = original.direct, original.native, original.base
for module in (direct, native, base, direct.foreground):
    assert Path(module.__file__).resolve().parent == DEADLINE_QA
    assert hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() == DEADLINE_QA_PINS[Path(module.__file__).name]
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


class PocketSourcePostRecoveryColdRun(direct.DirectLanRun):
    def __init__(self, *args):
        super().__init__(*args)
        own = Path(__file__).resolve()
        self.source_files[str(own)] = base.sha256_file(own)
        self.source_files[str(NUMERIC_HELPER)] = NUMERIC_HELPER_SHA256
        self.direction_numeric_dispatched = set()
        self.direction_witness_attempted = False
        if CONTROLLER_UNTIL is None:
            raise base.FixtureError('postcold_original_controller_deadline_missing')
        self.controller_until = CONTROLLER_UNTIL
        base.parent_remaining(self.controller_until, 2400)
        self.postcold_reference = None
        self.postcold_reference_raw = None
        self.postcold_reference_sha256 = None
        self.postcold_until = None
        self.postcold_remote_dispatched = set()
        self.postcold_checks = []
        self.source_files[str(CIPHER_HELPER)] = CIPHER_HELPER_SHA256
        self.report.update({
            'schema': 'heptabao.normal-r10-pocket-source-postrecovery-cold.v1',
            'scope': 'new-fresh-direct98-and-independent-postrecovery-cold12',
            'previous_r3_summary_sha256': R3_SUCCESS_SUMMARY_SHA256,
            'new_qa_scope_does_not_rewrite_previous_r3_qualification': True,
            'deadline_qa_pins': DEADLINE_QA_PINS,
            'canonical_qa_files_unchanged': True,
            'post_recovery_cold': {
                'required_extra_checks': list(POSTCOLD_CHECKS), 'required_extra_check_count': 12,
                'checks': self.postcold_checks, 'readonly_observations': [],
                'new_shared_phase_seconds': POSTCOLD_SECONDS, 'completed': False,
                'publication_within_shared_deadline': None,
                'original98_denominator_does_not_include_these_checks': True,
                'only_actual_leader_reads_all_large_retained_versions': True,
            },
            'runner_sha256': base.sha256_file(own),
            'source_selection_controlled': True,
            'requested_cipher_source_node': 3,
            'requested_actual_empty_leader_node': 1,
            'leader_selection_forced': False,
            'directional_numeric_reads': [],
            'numeric_helper_sha256': NUMERIC_HELPER_SHA256,
            'new_role_preparation_seconds': 60,
            'role_preparation_additional_mutations': 2,
            'witness_is_separate_from_original98_and_extra12': True,
            'prior_postcold_failure_summary_sha256': 'ab2819fdcf4deed633fa2b2413a0de0990fa258ef2f1fffcdd8de0f4dc38fc5a',
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
        # base.ssh retains BatchMode/ConnectTimeout; the unchanged outer
        # native.execute_fixture strict_shared_transport adds strict host keys.
        # The remote reader starts no child; unknown completion aborts this run.
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

    @staticmethod
    def _direction_log_id_key(value):
        if type(value) is not dict or set(value) != {"leader_id", "index"}:
            raise base.FixtureError("direction_full_log_id_shape")
        leader = value["leader_id"]
        if type(leader) is not dict or set(leader) != {"term", "node_id"}:
            raise base.FixtureError("direction_full_leader_id_shape")
        numbers = (leader["term"], leader["node_id"], value["index"])
        if any(type(number) is not int or not 0 <= number <= (1 << 64) - 1
               for number in numbers):
            raise base.FixtureError("direction_full_log_id_u64")
        # Exact pinned OpenRaft advanced LeaderId and LogId derived Ord order.
        return numbers

    @classmethod
    def _direction_committed_vote_key(cls, value):
        if (type(value) is not dict or set(value) != {"leader_id", "committed"}
                or value["committed"] is not True):
            raise base.FixtureError("direction_committed_vote_shape")
        return cls._direction_log_id_key({"leader_id": value["leader_id"], "index": 0})[:2]

    def _direction_ledger_counts(self):
        receipt = self.recovery.public_receipt
        names = ("mutation_intents", "mutation_responses", "unknown_transport_outcomes")
        if (any(type(receipt.get(name)) is not int or receipt[name] < 0 for name in names)
                or type(self.recovery.sequence) is not int
                or self.recovery.sequence != receipt["mutation_intents"]
                or receipt["mutation_intents"] != receipt["mutation_responses"]
                or receipt["unknown_transport_outcomes"] != 0):
            raise base.FixtureError("direction_witness_requires_all_known_mutations")
        return {"sequence": self.recovery.sequence, **{name: receipt[name] for name in names}}

    def _direction_witness_mutations_known(self, before, count):
        after = self._direction_ledger_counts()
        if (after["sequence"] != before["sequence"] + count
                or after["mutation_intents"] != before["mutation_intents"] + count
                or after["mutation_responses"] != before["mutation_responses"] + count):
            raise base.FixtureError("direction_witness_mutation_count_changed")
        return after

    def _direction_witness_get(self, node, path, until):
        remaining = base.parent_remaining(until, 2.0)
        status, body = self.request(node, "GET", path, authenticate=False,
                                    timeout=remaining, parent_deadline=until)
        base.parent_remaining(until, 2.0)
        return status, body

    def _direction_witness_actual_leader(self, nodes, until, report):
        while True:
            base.parent_remaining(until, 2.0)
            rows = report["leader_observations"]
            if len(rows) >= 512:
                raise base.FixtureError("direction_witness_leader_observation_bound")
            row = {"health": []}
            rows.append(row)
            active = []
            for node in nodes:
                # A transport exception propagates. There is no new read retry
                # after an unobserved response, and never a mutation retry.
                status, body = self._direction_witness_get(node, "sys/health", until)
                row["health"].append({"node": node.node_id, "status": status})
                if status == 200:
                    if (body.get("ha_active") is not True
                            or body.get("ha_application_ready") is not True
                            or body.get("standby") is not False or body.get("sealed") is not False):
                        raise base.FixtureError("direction_witness_health_not_ready_leader")
                    active.append(node)
            if len(active) > 1:
                raise base.FixtureError("direction_witness_multiple_actual_leaders")
            if len(active) == 1:
                leader = active[0]
                status, body = self._direction_witness_get(leader, "sys/leader", until)
                frontier = base.parsed_local_frontier(body) if status == 200 else None
                if body.get("is_self") is not True or frontier is None:
                    raise base.FixtureError("direction_witness_actual_leader_not_confirmed")
                row.update(leader_node=leader.node_id, frontier=list(frontier))
                return leader, frontier
            time.sleep(base.parent_remaining(until, 0.1))

    def _direction_commit_witness(self, mac, healthy, stopped_rog, until):
        if self.direction_witness_attempted:
            raise base.FixtureError("direction_witness_would_be_repeated")
        self.direction_witness_attempted = True
        base.parent_remaining(until, 15.0)
        if (mac.node_id != 1 or healthy.node_id != 3 or mac not in self.started
                or healthy not in self.started or any(node.node_id == 2 for node in self.started)):
            raise base.FixtureError("direction_witness_requires_live_one_three_quorum")
        old_last = self._direction_log_id_key(stopped_rog.get("last_log_id"))
        old_committed = self._direction_log_id_key(stopped_rog.get("committed_log_id"))
        old_vote = self._direction_committed_vote_key(stopped_rog.get("final_vote"))
        if old_committed > old_last or old_vote < old_last[:2]:
            raise base.FixtureError("direction_witness_stopped_baseline_order")
        if (not isinstance(self.run_id, str) or len(self.run_id) != 32
                or any(char not in "0123456789abcdef" for char in self.run_id)):
            raise base.FixtureError("direction_witness_fresh_run_id_shape")
        prefix = "native-ha-" + self.run_id + "/"
        path = prefix + "direction-prepare-witness"
        if self.path != prefix + "history" or path in self.acknowledged:
            raise base.FixtureError("direction_witness_must_not_alias_original_keys")
        before_state = native.canonical({"path": self.path, "history": self.history,
                                         "retired": self.retired, "acknowledged": self.acknowledged})
        before = self._direction_ledger_counts()
        row = {"schema": "heptabao.direction-owned-commit-witness.v1",
               "fixture_run_id": self.run_id, "path": path, "once_attempt": True,
               "synthetic_only": True, "production_authority": False,
               "expected_cas": 0, "expected_version": 1, "body_bound_bytes": 1024,
               "ledger_before": before, "leader_observations": [],
               "write_request_called": False, "delete_request_called": False,
               "write_returned": False, "delete_returned": False,
               "mac_exact_read_confirmed": False, "mac_absence_confirmed": False,
               "mac_metadata_absence_confirmed": False,
               "same_scope_cleanup_confirmed": False, "completed": False,
               "original_key_lists_sha256": hashlib.sha256(before_state).hexdigest(),
               "witness_added_to_history_or_acknowledged": False,
               "http_outcomes_alone_do_not_prove_durable_commit": True}
        self.report["directional_role_preparation"]["committed_witness"] = row
        self.event("direction_committed_witness_scope_intent", witness=row)
        leader, before_frontier = self._direction_witness_actual_leader([mac, healthy], until, row)
        row.update(actual_leader_node=leader.node_id, leader_frontier_before=list(before_frontier))
        value = {"value": native.secrets.token_hex(24)}
        body = {"options": {"cas": 0}, "data": value}
        if len(native.canonical(body)) > 1024:
            raise base.FixtureError("direction_witness_body_bound")
        expected = native.data_digest(value)
        row["data_sha256"] = expected
        base.parent_remaining(until, 15.0)
        row["write_request_called"] = True
        status, response = self.request(leader, "POST", "secret/data/" + path, body,
                                        timeout=15, parent_deadline=until)
        row.update(write_returned=True, write_status=status,
                   write_sequence=self.recovery.sequence)
        self._direction_witness_mutations_known(before, 1)
        data = response.get("data") if isinstance(response, dict) else None
        if (status != 200 or not isinstance(data, dict)
                or type(data.get("version")) is not int or data["version"] != 1):
            raise base.FixtureError("direction_witness_cas0_not_acknowledged_once")
        base.parent_remaining(until, 15.0)
        self.exact_read(mac, path, expected, parent_deadline=until)
        base.parent_remaining(until, 15.0)
        row["mac_exact_read_confirmed"] = True
        if native.canonical({"path": self.path, "history": self.history,
                             "retired": self.retired, "acknowledged": self.acknowledged}) != before_state:
            raise base.FixtureError("direction_witness_changed_original_key_lists")
        # This is the only cleanup mutation; never call it in an exception or
        # finally path and never delete the original history/acknowledged keys.
        row["delete_request_called"] = True
        status, _ = self.request(leader, "DELETE", "secret/metadata/" + path,
                                 timeout=15, parent_deadline=until)
        row.update(delete_returned=True, delete_status=status,
                   delete_sequence=self.recovery.sequence)
        self._direction_witness_mutations_known(before, 2)
        if status != 204:
            raise base.FixtureError("direction_witness_metadata_delete_not_acknowledged_once")
        base.parent_remaining(until, 15.0)
        self.absent(mac, path, parent_deadline=until)
        base.parent_remaining(until, 15.0)
        row["mac_absence_confirmed"] = True
        metadata_status, metadata = self.request(mac, "GET", "secret/metadata/" + path,
                                                  timeout=15, parent_deadline=until)
        base.parent_remaining(until, 15.0)
        if metadata_status != 404 or metadata.get("data") not in (None, {}):
            raise base.FixtureError("direction_witness_mac_metadata_still_present")
        row["mac_metadata_absence_confirmed"] = True
        if leader != mac:
            self.absent(leader, path, parent_deadline=until)
            base.parent_remaining(until, 15.0)
        row["same_scope_cleanup_confirmed"] = True
        status, local = self._direction_witness_get(leader, "sys/leader", until)
        leader_frontier = base.parsed_local_frontier(local) if status == 200 else None
        if leader == mac:
            mac_frontier = leader_frontier
        else:
            mac_status, mac_local = self._direction_witness_get(mac, "sys/leader", until)
            mac_frontier = base.parsed_local_frontier(mac_local) if mac_status == 200 else None
        if (local.get("is_self") is not True or leader_frontier is None or mac_frontier is None
                or leader_frontier[0] != leader_frontier[1]
                or leader_frontier[0] <= max(old_last[2], before_frontier[0])
                or mac_frontier[0] != mac_frontier[1] or mac_frontier[1] < leader_frontier[0]):
            raise base.FixtureError("direction_witness_postdelete_frontier_not_observed")
        if native.canonical({"path": self.path, "history": self.history,
                             "retired": self.retired, "acknowledged": self.acknowledged}) != before_state:
            raise base.FixtureError("direction_witness_changed_original_key_lists")
        after = self._direction_witness_mutations_known(before, 2)
        row.update(ledger_after=after, known_mutations=2,
                   leader_frontier_after_delete=list(leader_frontier),
                   mac_frontier_after_delete=list(mac_frontier),
                   original_key_lists_unchanged=True)
        self.event("direction_committed_witness_known_and_deleted", witness=row)
        completed = time.monotonic()
        if completed >= until:
            raise base.FixtureError("direction_witness_publication_after_prepare_deadline")
        row.update(completed=True, within_shared_prepare_deadline=True)
        return row

    def _direction_verify_witness_frontier(self, rog, mac, frontier, pre_stop_rog, until):
        base.parent_remaining(until, 15.0)
        witness = self.report["directional_role_preparation"].get("committed_witness", {})
        if (witness.get("completed") is not True or witness.get("known_mutations") != 2
                or witness.get("mac_exact_read_confirmed") is not True
                or witness.get("mac_absence_confirmed") is not True
                or witness.get("mac_metadata_absence_confirmed") is not True
                or witness.get("same_scope_cleanup_confirmed") is not True
                or witness.get("original_key_lists_unchanged") is not True
                or self._direction_witness_mutations_known(witness["ledger_before"], 2)
                    != witness.get("ledger_after")):
            raise base.FixtureError("direction_witness_terminal_not_proven")
        old_last = self._direction_log_id_key(rog.get("last_log_id"))
        old_committed = self._direction_log_id_key(rog.get("committed_log_id"))
        new_last = self._direction_log_id_key(mac.get("last_log_id"))
        new_committed = self._direction_log_id_key(mac.get("committed_log_id"))
        old_vote = self._direction_committed_vote_key(rog.get("final_vote"))
        new_vote = self._direction_committed_vote_key(mac.get("final_vote"))
        if (not old_committed <= old_last < new_committed <= new_last
                or old_vote < old_last[:2] or new_vote < old_vote
                or new_vote != new_committed[:2] or new_last[:2] > new_vote
                or new_committed[2] <= old_last[2]
                or old_committed[2] < pre_stop_rog["committed_index"]
                or old_committed[2] < pre_stop_rog["applied_index"]
                or new_committed[2] != frontier["mac_applied_index"]
                or new_committed[2] < witness["leader_frontier_after_delete"][0]
                or frontier["leader_node"] != witness["actual_leader_node"]):
            raise base.FixtureError("direction_full_log_or_committed_vote_regressed")
        self.report["directional_role_preparation"]["full_order_proof"] = {
            "exact_order": ["term", "node_id", "index"],
            "old_committed": list(old_committed), "old_last": list(old_last),
            "new_committed": list(new_committed), "new_last": list(new_last),
            "old_committed_vote": list(old_vote), "new_committed_vote": list(new_vote),
            "old_committed_le_old_last_lt_new_committed_le_new_last": True,
            "committed_vote_nondecreasing": True,
            "witness_postdelete_frontier_retained": True,
            "stopped_rog_did_not_generate_the_new_log": True,
            "does_not_predict_actual_election_result": True}
        if new_committed[0] > max(old_last[0], old_vote[0]):
            self.report["directional_role_preparation"]["frontier_branch"] = "original-higher-term"
            return self._direction_verify_prepared_frontier(rog, mac, frontier, pre_stop_rog, until)
        if not old_last[:2] == old_committed[:2] == old_vote == new_committed[:2] == new_vote:
            raise base.FixtureError("direction_same_leader_branch_not_exact")
        if (new_committed[1] != frontier["leader_node"] or new_committed[1] not in (1, 3)
                or new_last[2] < new_committed[2]):
            raise base.FixtureError("direction_same_leader_frontier_not_proven")
        self.report["directional_role_preparation"]["frontier_branch"] = "same-committed-leader-witness"
        proof = {"stopped_rog_last": rog["last_log_id"], "stopped_rog_committed": rog["committed_log_id"],
                 "stopped_rog_vote": rog["final_vote"], "stopped_mac_last": mac["last_log_id"],
                 "stopped_mac_committed": mac["committed_log_id"], "stopped_mac_vote": mac["final_vote"],
                 "mac_passive_applied_index": frontier["mac_applied_index"],
                 "numeric_preparation_proven": True,
                 "same_committed_leader_exact": True,
                 "this_does_not_assert_next_actual_leader": True}
        self.report["directional_role_preparation"]["persisted_frontier_proof"] = proof
        self.event("direction_preparation_complete", **proof)
        completed = time.monotonic()
        if completed >= until:
            raise base.FixtureError("direction_preparation_completion_after_deadline")
        proof["within_new_total_prepare_deadline"] = True
        proof["new_total_prepare_elapsed_seconds"] = 60.0 - (until - completed)

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
                                        timeout=min(2.0, remaining), parent_deadline=until)
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
                            and mac_frontier[1] >= leader_frontier[0] > baseline["index"]
                            and leader.node_id == self.report["directional_role_preparation"]["committed_witness"]["actual_leader_node"]
                            and leader_frontier[0] >= self.report["directional_role_preparation"]["committed_witness"]["leader_frontier_after_delete"][0])
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
        completed = time.monotonic()
        if completed >= until:
            raise base.FixtureError("direction_preparation_completion_after_deadline")
        proof["within_new_total_prepare_deadline"] = True
        proof["new_total_prepare_elapsed_seconds"] = 60.0 - (until - completed)

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
        prepare_until = min(time.monotonic() + 60.0, self.controller_until)
        stopped_rog = self._direction_read_numeric(rog, until=prepare_until)
        self._direction_commit_witness(mac, healthy, stopped_rog, prepare_until)
        frontier = self._direction_quorum_frontier([mac, healthy], stopped_rog, prepare_until)
        self.stop(mac, parent_deadline=prepare_until)
        if time.monotonic() >= prepare_until:
            raise base.FixtureError("direction_preparation_deadline_expired")
        self.stop(healthy, parent_deadline=prepare_until)
        if time.monotonic() >= prepare_until:
            raise base.FixtureError("direction_preparation_deadline_expired")
        self.check("missing_cipher_targets_stopped", not self.started)
        stopped_mac = self._direction_read_numeric(mac, until=prepare_until)
        self._direction_verify_witness_frontier(stopped_rog, stopped_mac, frontier,
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
        recovered = cipher_inventory(elected, self.run_id, "recovered", capture_reference=True,
                                     parent_deadline=self.controller_until)
        self._capture_postcold_reference(elected, recovered)
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


    def _capture_postcold_reference(self, node, recovered):
        if node.node_id != 1 or self.postcold_reference is not None:
            raise base.FixtureError("postcold_reference_must_be_same_scan_once")
        leaves = recovered.pop("restored_reference", None)
        directories = recovered.pop("restored_directory_reference", None)
        if (not isinstance(leaves, dict) or not 0 < len(leaves) <= 4096
                or len(leaves) != recovered.get("restored_count")
                or sum(row["bytes"] for row in leaves.values()) != recovered.get("restored_bytes")
                or not isinstance(directories, list) or len(directories) != 3):
            raise base.FixtureError("postcold_captured_reference_incomplete")
        value = {
            "schema": "heptabao.postrecovery-captured-cipher-reference.v1",
            "fixture_run_id": self.run_id, "source_commit": COMMIT, "source_tree": TREE,
            "node_id": node.node_id, "root": node.root,
            "captured_from_same_recovered_scan": True,
            "inventory_sha256": recovered["inventory_sha256"],
            "restored_count": recovered["restored_count"], "restored_bytes": recovered["restored_bytes"],
            "directories": directories, "leaves": leaves,
        }
        raw = native.canonical(value) + b"\n"
        if len(raw) > 1024 * 1024:
            raise base.FixtureError("postcold_captured_reference_bound")
        self.postcold_reference = value
        self.postcold_reference_raw = raw
        self.postcold_reference_sha256 = hashlib.sha256(raw).hexdigest()
        reference_path = self.work / "post-recovery-captured-reference.public.json"
        native.write_private(reference_path, raw)
        base.parent_remaining(self.controller_until, 60)
        self.report["post_recovery_reference"] = {
            "relative_file": reference_path.name, "bytes": len(raw),
            "sha256": self.postcold_reference_sha256, "captured_from_same_recovered_scan": True,
            "actual_recovered_leaves": len(leaves), "actual_recovered_bytes": value["restored_bytes"],
            "not_a_hardcoded_previous_run_count": True,
        }

    def _postcold_remaining(self, cap, *, until=None):
        return base.parent_remaining(self.postcold_until if until is None else until, cap)

    def _postcold_check(self, name, condition, **details):
        self._postcold_remaining(POSTCOLD_SECONDS)
        if name not in POSTCOLD_CHECKS or any(row["case"] == name for row in self.postcold_checks):
            raise base.FixtureError("postcold_extra_denominator_or_duplicate")
        row = {"case": name, "passed": condition is True, **details}
        self.postcold_checks.append(row)
        try:
            self.checkpoint()
            self._postcold_remaining(POSTCOLD_SECONDS)
        except BaseException:
            row["passed"] = False
            row["publication_within_shared_deadline"] = False
            raise
        row["publication_within_shared_deadline"] = True
        if condition is not True:
            raise base.FixtureError(name)

    def _postcold_remote_observation(self, node, kind):
        if node.node_id != 1 or node in self.started or kind not in ("numeric", "cipher"):
            raise base.FixtureError("postcold_reader_requires_stopped_mac")
        if kind in self.postcold_remote_dispatched:
            raise base.FixtureError("postcold_reader_would_be_repeated")
        helper, digest = ((NUMERIC_HELPER, NUMERIC_HELPER_SHA256) if kind == "numeric"
                          else (CIPHER_HELPER, CIPHER_HELPER_SHA256))
        code = helper.read_bytes()
        if hashlib.sha256(code).hexdigest() != digest:
            raise base.FixtureError("postcold_reader_source_changed")
        text = code.decode("utf-8")
        delimiter = "HB_POSTCOLD_FIXED_READ_R1"
        if delimiter in text.splitlines():
            raise base.FixtureError("postcold_reader_source_delimiter")
        row = {"kind": kind, "node": 1, "helper_sha256": digest, "dispatch_attempted": False,
               "remote_completion_unknown": False, "repeated": False}
        self.report["post_recovery_cold"]["readonly_observations"].append(row)
        self.postcold_remote_dispatched.add(kind)
        self.event("postcold_readonly_intent", node=1, kind=kind, helper_sha256=digest)
        remaining = self._postcold_remaining(45)
        seconds = min(15.0, remaining)
        args = ["--run-id", self.run_id, "--max-seconds", repr(seconds)]
        if kind == "numeric":
            args += ["--node", "1"]
        else:
            args += ["--reference-sha256", self.postcold_reference_sha256]
            text = "REFERENCE_JSON = " + repr(self.postcold_reference_raw.decode("utf-8")) + "\n" + text
        if len(text.encode("utf-8")) > 2 * 1024 * 1024:
            raise base.FixtureError("postcold_reader_input_bound")
        command = ("exec " + shlex.quote(self.args.darwin_watchdog_python) + " -B - "
                   + shlex.join(args) + " <<'" + delimiter + "'\n" + text + "\n" + delimiter + "\n")
        self._postcold_remaining(45)
        row.update(dispatch_attempted=True, remote_completion_unknown=True,
                   allocated_read_seconds=seconds, allocated_ssh_seconds=remaining)
        began = time.monotonic()
        output = base.ssh(node, command, timeout=remaining, parent_deadline=self.postcold_until)
        row["remote_completion_unknown"] = False
        row["ssh_elapsed_seconds"] = time.monotonic() - began
        self._postcold_remaining(45)
        limit = 65536 if kind == "numeric" else 1024 * 1024
        if row["ssh_elapsed_seconds"] > remaining or len(output.encode("utf-8")) > limit:
            raise base.FixtureError("postcold_reader_output_or_deadline_bound")
        result = json.loads(output)
        if (result.get("status") != "completed" or result.get("fixture_run_id") != self.run_id
                or result.get("child_processes") != 0 or result.get("file_writes") != 0
                or result.get("product_requests") != 0):
            raise base.FixtureError("postcold_reader_terminal_unqualified")
        if kind == "numeric":
            if (result.get("schema") != "heptabao.direction-r3-stopped-node-numeric-observer.v1"
                    or result.get("publication_within_original_observer_deadline") is not True
                    or result.get("new_observer_deadline_seconds") != seconds):
                raise base.FixtureError("postcold_numeric_reader_binding")
        elif (result.get("schema") != "heptabao.postrecovery-stopped-cipher-reference.v1"
              or result.get("publication_within_original_read_deadline") is not True
              or result.get("new_read_seconds") != seconds
              or result.get("reference_sha256") != self.postcold_reference_sha256):
            raise base.FixtureError("postcold_cipher_reader_binding")
        observed = result.get("observation", {})
        if observed.get("node_id") != 1 or observed.get("fixed_root") != node.root:
            raise base.FixtureError("postcold_reader_fixed_root_binding")
        row["public_result_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
        row["result"] = result
        self.event("postcold_readonly_complete", node=1, kind=kind,
                   public_result_sha256=row["public_result_sha256"])
        self._postcold_remaining(45)
        return observed

    def _postcold_wait_leader(self, *, sealed):
        until = min(self.postcold_until, time.monotonic() + 60.0)
        candidate, since = None, 0.0
        while time.monotonic() < until:
            active = []
            for node in self.nodes:
                try:
                    status, body = self.request(node, "GET", "sys/health", authenticate=False,
                                                timeout=2, parent_deadline=until)
                except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                    continue
                if sealed:
                    if body.get("sealed") is not True:
                        raise base.FixtureError("postcold_sealed_election_observed_unsealed")
                    if body.get("ha_active") is True and body.get("standby") is False:
                        active.append(node)
                elif status == 200:
                    if (body.get("ha_active") is not True or body.get("ha_application_ready") is not True
                            or body.get("standby") is not False or body.get("sealed") is not False):
                        raise base.FixtureError("postcold_health_without_actual_ready_authority")
                    active.append(node)
            if len(active) > 1:
                raise base.FixtureError("postcold_multiple_actual_leaders")
            observed = active[0] if active else None
            if observed is not None and not sealed:
                status, body = self.request(observed, "GET", "sys/leader",
                                            timeout=8, parent_deadline=until)
                if status != 200 or body.get("is_self") is not True:
                    observed = None
            now = time.monotonic()
            if now >= until:
                break
            if observed is not None:
                if candidate == observed and now - since >= 2.2:
                    self._postcold_remaining(60, until=until)
                    return observed
                if candidate != observed:
                    candidate, since = observed, now
            else:
                candidate, since = None, 0.0
            time.sleep(min(0.1, max(0.0, until - time.monotonic())))
        raise base.FixtureError("postcold_actual_election_not_observed_in_original_60s")

    def _postcold_frontier(self, node, required):
        if type(required) is not int or not 0 < required <= (1 << 64) - 1:
            raise base.FixtureError("postcold_invalid_frontier")
        until = min(self.postcold_until, time.monotonic() + 60.0)
        while time.monotonic() < until:
            try:
                status, body = self.request(node, "GET", "sys/leader", authenticate=False,
                                            timeout=4, parent_deadline=until)
                observed = base.parsed_local_frontier(body) if status == 200 else None
                if observed is not None and observed[1] >= required:
                    self._postcold_remaining(60, until=until)
                    return {"committed_index": observed[0], "applied_index": observed[1]}
            except (OSError, ssl.SSLError, urllib.error.URLError, TimeoutError):
                pass
            time.sleep(min(0.1, max(0.0, until - time.monotonic())))
        raise base.FixtureError("postcold_local_frontier_not_observed")

    def _postcold_retired_states(self, node):
        for version, state in sorted(self.retired.items()):
            status, body = self.read_data(node, self.path, version=version,
                                          parent_deadline=self.postcold_until)
            data = body.get("data")
            metadata = data.get("metadata") if isinstance(data, dict) else None
            if (status != 404 or not isinstance(data, dict) or data.get("data") is not None
                    or not isinstance(metadata, dict) or metadata.get("version") != version
                    or metadata.get("destroyed") is not (state == "destroyed")
                    or (state == "deleted" and not metadata.get("deletion_time"))):
                raise base.FixtureError("postcold_retired_version_disclosed_payload")

    def post_recovery_cold(self, leader, denied_path):
        self.stage = "post_recovery_extra_cold_scope"
        started = time.monotonic()
        self.postcold_until = min(started + POSTCOLD_SECONDS, self.controller_until)
        self._postcold_remaining(POSTCOLD_SECONDS)
        scope = self.report["post_recovery_cold"]
        scope.update(started_monotonic=started, shared_absolute_deadline=self.postcold_until,
                     controller_absolute_deadline=self.controller_until, completed=False)
        mac = next(node for node in self.nodes if node.node_id == 1)
        try:
            if (self.postcold_reference is None
                    or set(self.history) != set(range(1, 20)) or self.retired != {1: "deleted", 2: "destroyed"}
                    or len(self.history.keys() - self.retired.keys()) != 17
                    or self.report.get("directional_observed_pair", {}).get("requested_pair_observed") is not True):
                raise base.FixtureError("postcold_requires_this_fresh_successful_recovery")
            reference_path = self.work / "post-recovery-captured-reference.public.json"
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            before = reference_path.lstat()
            fd = os.open(reference_path, flags)
            try:
                opened = os.fstat(fd)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                         item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                        or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                        or not 0 < opened.st_size <= 1024 * 1024 or identity(before) != identity(opened)):
                    raise base.FixtureError("postcold_captured_reference_file_identity")
                pieces, size = [], 0
                while True:
                    self._postcold_remaining(POSTCOLD_SECONDS)
                    part = os.read(fd, 65536)
                    if not part:
                        break
                    size += len(part)
                    if size > 1024 * 1024:
                        raise base.FixtureError("postcold_captured_reference_file_bound")
                    pieces.append(part)
                after, named = os.fstat(fd), reference_path.lstat()
                if (identity(before) != identity(after) or identity(after) != identity(named)
                        or size != before.st_size or b"".join(pieces) != self.postcold_reference_raw):
                    raise base.FixtureError("postcold_captured_reference_file_changed")
            finally:
                os.close(fd)
            status, body = self.request(leader, "GET", "sys/leader", authenticate=False,
                                        timeout=4, parent_deadline=self.postcold_until)
            anchor = base.parsed_local_frontier(body) if status == 200 else None
            if anchor is None or body.get("is_self") is not True:
                raise base.FixtureError("postcold_original_actual_leader_frontier_missing")
            frontier = anchor[0]
            before_frontiers = {str(node.node_id): self._postcold_frontier(node, frontier)
                                for node in self.nodes}
            metadata = {str(node.node_id): native.canonical(self.metadata(node,
                        parent_deadline=self.postcold_until)) for node in self.nodes}
            if len(set(metadata.values())) != 1:
                raise base.FixtureError("postcold_original_metadata_not_identical")
            expected_metadata = metadata["1"]
            before_mutations = dict(self.recovery.public_receipt)
            scope["before"] = {"actual_leader_node": leader.node_id, "committed_index": frontier,
                               "node_frontiers": before_frontiers,
                               "version_metadata_sha256": hashlib.sha256(expected_metadata).hexdigest(),
                               "history_digest_map": {str(k): v for k, v in self.history.items()},
                               "retired_states": {str(k): v for k, v in self.retired.items()},
                               "small_acknowledged_path_digests": dict(self.acknowledged)}
            self._postcold_check(POSTCOLD_CHECKS[0], True, lifecycle_versions=19, readable_large_versions=17,
                                 captured_recovered_leaves=self.postcold_reference["restored_count"],
                                 captured_recovered_bytes=self.postcold_reference["restored_bytes"])
            stopped = {}
            for node in self.nodes:
                stopped[str(node.node_id)] = self.stop(node, parent_deadline=self.postcold_until)
            self._postcold_check(POSTCOLD_CHECKS[1],
                                 not self.started and all(type(v) is int and v > 0 for v in stopped.values()),
                                 original_owned_pids=stopped)
            numeric = self._postcold_remote_observation(mac, "numeric")
            projection = numeric.get("numeric_projection", {})
            committed = projection.get("committed_log_id")
            self._postcold_check(POSTCOLD_CHECKS[2],
                projection.get("complete_current_epoch_journal") is True
                and projection.get("retained_log_contiguous") is True
                and projection.get("committed_not_beyond_last_log") is True
                and projection.get("projection_is_read_authority") is False
                and isinstance(committed, dict) and committed.get("index", -1) >= before_frontiers["1"]["applied_index"],
                required_pre_stop_applied_index=before_frontiers["1"]["applied_index"],
                stopped_committed_log_id=committed, passive_metadata_is_not_read_authority=True)
            cipher = self._postcold_remote_observation(mac, "cipher")
            actual_files = {row["name"]: row for row in cipher.get("files", [])}
            expected_files = self.postcold_reference["leaves"]
            self._postcold_check(POSTCOLD_CHECKS[3],
                cipher.get("all_captured_leaves_match") is True
                and cipher.get("unreferenced_leaves_enumerated_or_read") is False
                and cipher.get("actual_reference_count") == len(expected_files)
                and cipher.get("actual_reference_bytes") == self.postcold_reference["restored_bytes"]
                and len(actual_files) == len(cipher.get("files", []))
                and set(actual_files) == set(expected_files)
                and all(actual_files[name]["bytes"] == row["bytes"]
                        and actual_files[name]["sha256"] == row["sha256"]
                        and actual_files[name]["before"] == row["identity"]
                        and actual_files[name]["after"] == row["identity"]
                        and actual_files[name]["named_after"] == row["identity"]
                        for name, row in expected_files.items()),
                reference_sha256=self.postcold_reference_sha256, actual_reference_count=len(expected_files),
                actual_reference_bytes=self.postcold_reference["restored_bytes"])
            new_pids = {}
            for node in self.nodes[1:] + self.nodes[:1]:
                new_pids[str(node.node_id)] = self.start(node, parent_deadline=self.postcold_until)
            for node in self.nodes:
                _, health = base.wait_listener(self.context, node, parent_deadline=self.postcold_until)
                if health.get("sealed") is not True:
                    raise base.FixtureError("postcold_new_process_not_sealed")
            self._postcold_check(POSTCOLD_CHECKS[4],
                set(self.started) == set(self.nodes)
                and all(type(pid) is int and pid > 0 and pid != stopped[node] for node, pid in new_pids.items()),
                new_owned_pids=new_pids, original_ownership_guards_retained=True)
            elected = self._postcold_wait_leader(sealed=True)
            self._postcold_check(POSTCOLD_CHECKS[5], elected in self.nodes,
                                 actual_sealed_leader_node=elected.node_id, forced_leader=False)
            for node in self.nodes:
                self.unseal(node, parent_deadline=self.postcold_until)
            after_mutations = self.recovery.public_receipt
            self._postcold_check(POSTCOLD_CHECKS[6],
                after_mutations["mutation_intents"] - before_mutations["mutation_intents"] == 3
                and after_mutations["mutation_responses"] - before_mutations["mutation_responses"] == 3
                and after_mutations["unknown_transport_outcomes"] == before_mutations["unknown_transport_outcomes"] == 0,
                original_keys=True, original_inputs_reseeded=False, unseal_attempts=3, automatic_retry=False)
            leader = self._postcold_wait_leader(sealed=False)
            after_frontiers = {str(node.node_id): self._postcold_frontier(node, frontier)
                               for node in self.nodes}
            scope["after"] = {"actual_leader_node": leader.node_id, "node_frontiers": after_frontiers}
            self._postcold_check(POSTCOLD_CHECKS[7],
                                 all(row["applied_index"] >= frontier for row in after_frontiers.values()),
                                 required_original_committed_index=frontier, observed_nodes=3)
            self.history_reads(leader, parent_deadline=self.postcold_until)
            self._postcold_check(POSTCOLD_CHECKS[8], True, actual_leader_node=leader.node_id,
                                 readable_large_versions=17, lifecycle_versions=19,
                                 retained_large_payload_bytes=TARGET_BYTES,
                                 every_standby_large_body_direct_read_claimed=False)
            for node in self.nodes:
                if native.canonical(self.metadata(node, parent_deadline=self.postcold_until)) != expected_metadata:
                    raise base.FixtureError("postcold_exact_version_metadata_changed")
                self._postcold_retired_states(node)
                self.absent(node, denied_path, parent_deadline=self.postcold_until)
            self._postcold_check(POSTCOLD_CHECKS[9], True, observed_nodes=3,
                                 deleted_version=1, destroyed_version=2,
                                 denied_quorum_write_still_absent=True,
                                 exact_version_metadata_sha256=hashlib.sha256(expected_metadata).hexdigest())
            self.small_reads(self.nodes, parent_deadline=self.postcold_until)
            self._postcold_check(POSTCOLD_CHECKS[10], True, observed_nodes=3,
                                 acknowledged_keys=len(self.acknowledged), actual_normal_readindex=True)
            self._postcold_check(POSTCOLD_CHECKS[11],
                                 len(self.postcold_checks) == 11
                                 and all(row["passed"] is True for row in self.postcold_checks),
                                 requested_shared_seconds=POSTCOLD_SECONDS,
                                 original_controller_seconds=2400, original_http_seconds=15,
                                 original_admission_seconds=8)
            self.event("post_recovery_cold_scope_complete", actual_leader_node=leader.node_id,
                       extra_checks=len(self.postcold_checks))
            completed = time.monotonic()
            if completed >= self.postcold_until:
                raise base.FixtureError("postcold_final_publication_after_shared_deadline")
            scope.update(completed=True, elapsed_seconds=completed - started,
                         publication_within_shared_deadline=True,
                         phase_observations_only_until_original98_and_cleanup_complete=True)
            return leader
        except BaseException:
            failed_at = time.monotonic()
            scope.update(completed=False, failure_within_shared_deadline=failed_at < self.postcold_until,
                         failed_at_monotonic=failed_at)
            if self.postcold_checks and self.postcold_checks[-1]["case"] == POSTCOLD_CHECKS[-1]:
                self.postcold_checks[-1]["passed"] = False
            raise

    def execute(self):
        self.prepare()
        leader = self.bootstrap_v5()
        self.activate_and_grow(leader)
        leader, denied = self.failover_and_quorum(leader)
        leader = self.full_cold_restart(leader, denied)
        leader = self.missing_cipher_leader(leader)
        leader = self.post_recovery_cold(leader, denied)
        self.finish_application(leader)


for method_name in ('request', 'cleanup', 'check', 'start', 'stop',
                    'unseal', 'leader', 'wait_sealed_leader',
                    'full_cold_restart', 'failover_and_quorum', 'finish_application'):
    assert getattr(PocketSourcePostRecoveryColdRun, method_name) is getattr(direct.DirectLanRun, method_name)

if options.describe_contract:
    print(json.dumps({
        'schema': 'heptabao.normal-r10-postrecovery-cold-contract.v1',
        'deadline_qa_pins': DEADLINE_QA_PINS,
        'required_extra_checks': list(POSTCOLD_CHECKS), 'required_extra_check_count': 12,
        'new_shared_postrecovery_seconds': POSTCOLD_SECONDS, 'original_controller_seconds': 2400,
        'extra_phase_before_original_finish_application': True,
        'canonical_qa_unchanged': True, 'none_optional_deadline_preserves_old_defaults': True,
        'reference_captured_in_original_recovered_scan': True,
        'cipher_helper_sha256': CIPHER_HELPER_SHA256,
        'prior_r3_success_summary_sha256': R3_SUCCESS_SUMMARY_SHA256,
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
        'role_prepare_clipped_to_original_controller': True,
        'witness_additional_mutation_limit': 2,
        'witness_write_cas': 0, 'witness_cleanup': 'same-key-metadata-delete',
        'witness_requires_mac_exact_read_and_absence': True,
        'witness_excluded_from_history_acknowledged_and_check_denominators': True,
        'original_higher_term_guard_unchanged': True,
        'same_leader_requires_old_last_committed_vote_exact': True,
        'full_log_id_order': ['term', 'node_id', 'index'],
        'new_numeric_read_seconds': 15, 'new_numeric_ssh_seconds': 45,
        'original_sealed_election_seconds': 60,
        'real_new_committed_frontier_required_before_quarantine': True,
        'actual_election_required': True, 'leader_selection_forced': False,
        'wrong_actual_direction_stops_before_target_unseal': True,
        'runtime_method_overrides': ['missing_cipher_leader', 'execute'],
        'original98_checks_and_finish_deletion_order_preserved': True,
        'readable_large_versions': 17, 'lifecycle_versions': 19,
        'large_body_all_standbys_read_claimed': False,
        'original_method_normalized_sha256': hashlib.sha256(original_method.encode()).hexdigest(),
        'direction_method_normalized_sha256': hashlib.sha256(textwrap.dedent(inspect.getsource(PocketSourcePostRecoveryColdRun.missing_cipher_leader)).strip().encode()).hexdigest(),
        'inherited_request_check_cleanup_identities_verified': True,
        'canonical128_summary_sha256': '9a23e1b4cce8638f7b5c8ea37d41929864c8b4ef35e0bef47292695d4703405e',
        'fixture_started': False,
    }, sort_keys=True))
    raise SystemExit(0)

parsed = direct.parsed_arguments(remaining)
args = parsed[0]
if args.source_commit != COMMIT or args.source_tree != TREE:
    raise SystemExit('directional_source_binding_mismatch')
CONTROLLER_UNTIL = float(os.environ['HEPTABAO_SYNTHETIC_CONTROLLER_DEADLINE'])
remaining_controller = CONTROLLER_UNTIL - time.monotonic()
if not 0 < remaining_controller <= 2400:
    raise SystemExit('postcold_original_controller_deadline_invalid')
raise SystemExit(native.execute_fixture(*parsed, run_type=PocketSourcePostRecoveryColdRun))
