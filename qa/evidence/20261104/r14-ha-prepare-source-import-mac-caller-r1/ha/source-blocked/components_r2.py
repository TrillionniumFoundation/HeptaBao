"""Offline exact-method components. No network, product, SSH, or child process."""
from pathlib import Path
import ast
import base64
import copy
from dataclasses import dataclass
import hashlib
import json
import ssl
import sys
import types
import urllib.error

ROOT = Path(__file__).resolve().parent
BEFORE = ROOT / 'before'
AFTER = ROOT / 'candidate'
OLD = (BEFORE / 'native_v6_pocket_source_postrecovery_cold_r10_r1.py').read_text()
NEW = (AFTER / 'native_v6_pocket_source_postrecovery_cold_r10_r2.py').read_text()
NATIVE = (BEFORE / 'deadline_qa/native_v6_ha_multihost_live.py').read_text()
BASE = (BEFORE / 'deadline_qa/ha_multihost_live.py').read_text()
RECOVERY = (BEFORE / 'native_fixture_recovery.py').read_text()
ROWS = []


def check(name, condition, **details):
    ROWS.append({'case': name, 'passed': condition is True, **details})
    if condition is not True:
        raise AssertionError(name)


def definition(source, name):
    return next(item for item in ast.parse(source).body
                if isinstance(item, (ast.FunctionDef, ast.ClassDef)) and item.name == name)


def methods(source, name):
    return {item.name: item for item in definition(source, name).body
            if isinstance(item, ast.FunctionDef)}


def exact(source, node):
    return ''.join(source.splitlines(True)[node.lineno - 1:node.end_lineno])


class Clock:
    def __init__(self):
        self.now = 100.0
    def monotonic(self):
        return self.now
    def time(self):
        return 1_800_000_000.0 + self.now
    def sleep(self, seconds):
        if seconds < 0:
            raise AssertionError('negative_sleep')
        self.now += seconds


class FixtureError(Exception):
    pass


CLOCK = Clock()
GLOBALS = {'time': CLOCK, 'json': json, 'hashlib': hashlib, 'ssl': ssl,
           'urllib': urllib, 'REQUEST_SECONDS': 15, 'FixtureError': FixtureError}
base_nodes = [definition(BASE, name) for name in ('parent_remaining', 'parsed_local_frontier')]
exec(compile(ast.fix_missing_locations(ast.Module(body=base_nodes, type_ignores=[])),
             '<exact-base-functions>', 'exec'), GLOBALS)
BASE_NS = types.SimpleNamespace(FixtureError=FixtureError,
                                parent_remaining=GLOBALS['parent_remaining'],
                                parsed_local_frontier=GLOBALS['parsed_local_frontier'])
GLOBALS['base'] = BASE_NS
native_nodes = [definition(NATIVE, name) for name in ('canonical', 'data_digest')]
exec(compile(ast.fix_missing_locations(ast.Module(body=native_nodes, type_ignores=[])),
             '<exact-native-functions>', 'exec'), GLOBALS)
GLOBALS['native'] = types.SimpleNamespace(canonical=GLOBALS['canonical'],
    data_digest=GLOBALS['data_digest'], secrets=types.SimpleNamespace(token_hex=lambda n: 'cd' * n))

native_methods = methods(NATIVE, 'NativeRun')
native_class = ast.ClassDef(name='ExactNative', bases=[], keywords=[], decorator_list=[],
    body=[native_methods[name] for name in ('request', 'read_data', 'exact_read', 'absent')])
old_methods = methods(OLD, 'PocketSourcePostRecoveryColdRun')
new_methods = methods(NEW, 'PocketSourcePostRecoveryColdRun')
selected = [node for name, node in new_methods.items()
            if name.startswith('_direction_') and name != '_direction_read_numeric']
candidate_class = ast.ClassDef(name='ExactCandidate',
    bases=[ast.Name(id='ExactNative', ctx=ast.Load())], keywords=[], decorator_list=[], body=selected)
exec(compile(ast.fix_missing_locations(ast.Module(body=[native_class, candidate_class], type_ignores=[])),
             '<exact-new-methods-and-original-request>', 'exec'), GLOBALS)

recovery_nodes = [definition(RECOVERY, 'canonical')]
recovery_methods = methods(RECOVERY, 'FixtureRecoveryLedger')
recovery_class = ast.ClassDef(name='ExactRecovery', bases=[], keywords=[], decorator_list=[],
    body=[recovery_methods[name] for name in ('_require', 'begin', 'outcome')])
RECOVERY_GLOBALS = {'time': CLOCK, 'hashlib': hashlib, 'json': json}
exec(compile(ast.fix_missing_locations(ast.Module(body=recovery_nodes + [recovery_class], type_ignores=[])),
             '<exact-ledger-with-memory-storage-adapter>', 'exec'), RECOVERY_GLOBALS)


@dataclass(frozen=True)
class Node:
    node_id: int


MAC, ROG, POCKET = Node(1), Node(2), Node(3)


class Ledger(RECOVERY_GLOBALS['ExactRecovery']):
    def __init__(self):
        self.error_type = FixtureError
        self.nodes = {node.node_id: node for node in (MAC, ROG, POCKET)}
        self.sequence = 45
        self.run_id = 'ab' * 16
        self.initialization_attempted = False
        self.public_receipt = {'mutation_intents': 45, 'mutation_responses': 45,
                               'unknown_transport_outcomes': 0}
        self.records = {}
    def _verify_custody(self):
        pass
    def _write(self, name, value):
        if name in self.records:
            raise FixtureError('memory_adapter_record_not_create_only')
        self.records[name] = copy.deepcopy(value)
        return hashlib.sha256(RECOVERY_GLOBALS['canonical'](value)).hexdigest()


def log(term=2, node=3, index=61):
    return {'leader_id': {'term': term, 'node_id': node}, 'index': index}


def numeric(term=2, node=3, index=61):
    return {'last_log_id': log(term, node, index), 'committed_log_id': log(term, node, index),
            'final_vote': {'leader_id': {'term': term, 'node_id': node}, 'committed': True}}


class ApiAdapter:
    def __init__(self, fixture, fault=None):
        self.fixture = fixture
        self.fault = fault
        self.calls = []
        self.value = None
        self.deleted = False
    def __call__(self, context, node, method, path, body, token, *, timeout, parent_deadline):
        self.calls.append({'node': node.node_id, 'method': method, 'path': path,
                           'body': copy.deepcopy(body), 'timeout': timeout,
                           'parent_deadline': parent_deadline})
        if parent_deadline is not None:
            BASE_NS.parent_remaining(parent_deadline, timeout)
        CLOCK.now += 0.01
        if self.fault == 'unknown_first_read' and len(self.calls) == 1:
            raise TimeoutError('synthetic-read-no-response')
        if path == 'sys/health':
            is_self = node == POCKET
            return (200 if is_self else 429), {'ha_active': True, 'ha_application_ready': True,
                'standby': not is_self, 'sealed': False}
        if path == 'sys/leader':
            index = 63 if self.deleted else (62 if self.value else 61)
            if self.fault == 'no_new_frontier':
                index = 61
            if self.fault == 'mac_not_applied' and node == MAC and self.deleted:
                applied = 61
            else:
                applied = index
            return 200, {'is_self': node == POCKET and not (
                self.fault == 'leader_changed' and self.deleted), 'ha_enabled': True,
                'raft_committed_index': index, 'raft_applied_index': applied}
        expected = 'native-ha-' + self.fixture.run_id + '/direction-prepare-witness'
        if method == 'POST':
            if path != 'secret/data/' + expected or body.get('options') != {'cas': 0} or self.value is not None:
                raise AssertionError('bad_or_repeated_write')
            if self.fault == 'unknown_write':
                raise TimeoutError('synthetic-write-no-response')
            self.value = copy.deepcopy(body['data'])
            if self.fault == 'expired_after_known_write':
                CLOCK.now = 160.0
            version = True if self.fault == 'bool_write_version' else 1
            return (409 if self.fault == 'known_write_error' else 200), {'data': {'version': version}}
        if method == 'DELETE':
            if path != 'secret/metadata/' + expected or self.deleted:
                raise AssertionError('bad_or_repeated_delete')
            if self.fault == 'unknown_delete':
                raise TimeoutError('synthetic-delete-no-response')
            self.deleted = True
            return (503 if self.fault == 'known_delete_error' else 204), {}
        if path == 'secret/metadata/' + expected:
            if self.fault == 'metadata_remains':
                return 200, {'data': {'current_version': 1}}
            return 404, {}
        if path == 'secret/data/' + expected:
            if self.deleted:
                return 404, {}
            if self.fault == 'changed_original_key_list':
                self.fixture.acknowledged['unexpected'] = 'x'
            value = {'value': 'wrong'} if self.fault == 'wrong_mac_data' else self.value
            return 200, {'data': {'data': value, 'metadata': {'version': 1}}}
        raise AssertionError(('unexpected_route', path))


class Fixture(GLOBALS['ExactCandidate']):
    def __init__(self, fault=None):
        CLOCK.now = 100.0
        self.run_id = 'ab' * 16
        self.path = 'native-ha-' + self.run_id + '/history'
        self.history = {1: 'h1', 2: 'h2', 3: 'h3'}
        self.acknowledged = {'native-ha-' + self.run_id + '/original-ack': 'a1'}
        self.retired = {1: 'deleted', 2: 'destroyed'}
        self.direction_witness_attempted = False
        self.started = {MAC, POCKET}
        self.controller_until = 2500.0
        self.report = {'directional_role_preparation': {'observations': []}}
        self.events = []
        self.context = None
        self.root_token = 'synthetic-only-token'
        self.stage = 'owned_missing_cipher_leader_recovery'
        self.recovery = Ledger()
        self.api = ApiAdapter(self, fault)
        BASE_NS.api = self.api
    def event(self, name, **details):
        self.events.append({'event': name, **copy.deepcopy(details)})
        if self.api.fault == 'expiry_during_witness_publication' and name == 'direction_committed_witness_known_and_deleted':
            CLOCK.now = 160.0
        if self.api.fault == 'expiry_during_numeric_publication' and name == 'direction_preparation_complete':
            CLOCK.now = 160.0


def mutations(fixture):
    return [row for row in fixture.api.calls if row['method'] in ('POST', 'DELETE')]


def expect_failure(name, invoke, fixture, expected_substring=None, expected_mutations=None):
    caught = None
    try:
        invoke()
    except (FixtureError, TimeoutError) as error:
        caught = error
    check(name, caught is not None and (expected_substring is None or expected_substring in str(caught)),
          error_type=type(caught).__name__ if caught else None,
          error=str(caught) if caught else None)
    if expected_mutations is not None:
        check(name + '.mutation_count', len(mutations(fixture)) == expected_mutations)
    return caught


def prepared(fault=None):
    fixture = Fixture(fault)
    fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0)
    frontier = {'leader_node': 3, 'leader_committed_index': 63,
                'mac_committed_index': 63, 'mac_applied_index': 63}
    before = {'is_self': False, 'committed_index': 61, 'applied_index': 61}
    return fixture, frontier, before


def main():
    check('original_higher_term_function_exact_bytes',
          exact(OLD, old_methods['_direction_verify_prepared_frontier']) ==
          exact(NEW, new_methods['_direction_verify_prepared_frontier']))
    changed = {'__init__', '_direction_quorum_frontier', 'missing_cipher_leader'}
    preserved = sorted(set(old_methods) - changed)
    check('all_other_existing_runner_method_bytes_preserved', all(
        exact(OLD, old_methods[name]) == exact(NEW, new_methods[name]) for name in preserved),
        exact_method_names=preserved)
    before_checks = next(item.value for item in ast.parse(OLD).body
        if isinstance(item, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'POSTCOLD_CHECKS' for t in item.targets))
    after_checks = next(item.value for item in ast.parse(NEW).body
        if isinstance(item, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'POSTCOLD_CHECKS' for t in item.targets))
    check('extra12_names_order_identical', ast.literal_eval(before_checks) == ast.literal_eval(after_checks)
          and len(ast.literal_eval(after_checks)) == 12)
    old_missing = exact(OLD, old_methods['missing_cipher_leader'])
    new_missing = exact(NEW, new_methods['missing_cipher_leader'])
    check('original_missing_cipher_before_stop_block_exact',
          old_missing.split('        prepare_until = ')[0] == new_missing.split('        prepare_until = ')[0])
    check('original_missing_cipher_after_quarantine_block_exact',
          old_missing.split('        missing = [node for node in self.nodes if node != healthy]')[1] ==
          new_missing.split('        missing = [node for node in self.nodes if node != healthy]')[1])
    check('new_prepare_is_min_original60_controller2400',
          'prepare_until = min(time.monotonic() + 60.0, self.controller_until)' in new_missing)
    check('mac_and_source_stops_explicit_shared_parent',
          'self.stop(mac, parent_deadline=prepare_until)' in new_missing and
          'self.stop(healthy, parent_deadline=prepare_until)' in new_missing)

    fixture, frontier, before = prepared()
    witness = fixture.report['directional_role_preparation']['committed_witness']
    check('known_witness_and_cleanup_two_exact_mutations',
          len(mutations(fixture)) == 2 and [x['method'] for x in mutations(fixture)] == ['POST', 'DELETE']
          and witness['completed'] is True and witness['known_mutations'] == 2
          and witness['write_sequence'] == 46 and witness['delete_sequence'] == 47)
    check('same_key_cas0_and_metadata_only_cleanup',
          mutations(fixture)[0]['body']['options'] == {'cas': 0}
          and mutations(fixture)[0]['path'].removeprefix('secret/data/') ==
              mutations(fixture)[1]['path'].removeprefix('secret/metadata/'))
    check('mac_exact_data_and_both_absences_observed', witness['mac_exact_read_confirmed'] is True
          and witness['mac_absence_confirmed'] is True and witness['mac_metadata_absence_confirmed'] is True)
    check('all_new_http_calls_same_absolute_deadline',
          all(row['parent_deadline'] == 160.0 and 0 < row['timeout'] <= 15 for row in fixture.api.calls))
    check('original_history_retired_acknowledged_unmodified',
          fixture.history == {1: 'h1', 2: 'h2', 3: 'h3'} and fixture.retired == {1: 'deleted', 2: 'destroyed'}
          and fixture.acknowledged == {'native-ha-' + fixture.run_id + '/original-ack': 'a1'})
    check('actual_original_ledger_records_known_pair', set(fixture.recovery.records) == {
        'mutation-00046.intent.json', 'mutation-00046.outcome.json',
        'mutation-00047.intent.json', 'mutation-00047.outcome.json'}
        and fixture.recovery.records['mutation-00046.intent.json']['expected_cas'] == 0
        and all(row.get('transport_returned') is True for name, row in fixture.recovery.records.items()
                if name.endswith('outcome.json')))
    fixture._direction_verify_witness_frontier(numeric(), numeric(index=63), frontier, before, 160.0)
    check('same_committed_leader_branch_accepts_strict_index_progress',
          fixture.report['directional_role_preparation']['frontier_branch'] == 'same-committed-leader-witness')
    count = len(fixture.api.calls)
    expect_failure('repeat_witness_refused_before_any_request',
                   lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0), fixture,
                   'would_be_repeated', 2)
    check('repeat_witness_no_read_or_mutation', len(fixture.api.calls) == count)

    for fault, expected_count, needle in [
        ('unknown_first_read', 0, 'synthetic-read-no-response'),
        ('unknown_write', 1, 'synthetic-write-no-response'),
        ('known_write_error', 1, 'cas0_not_acknowledged'),
        ('bool_write_version', 1, 'cas0_not_acknowledged'),
        ('wrong_mac_data', 1, 'exact_read_failed'),
        ('changed_original_key_list', 1, 'changed_original_key_lists'),
        ('unknown_delete', 2, 'synthetic-delete-no-response'),
        ('known_delete_error', 2, 'metadata_delete_not_acknowledged'),
        ('metadata_remains', 2, 'mac_metadata_still_present'),
        ('leader_changed', 2, 'postdelete_frontier_not_observed'),
        ('mac_not_applied', 2, 'postdelete_frontier_not_observed'),
        ('no_new_frontier', 2, 'postdelete_frontier_not_observed'),
        ('expiry_during_witness_publication', 2, 'publication_after_prepare_deadline'),
    ]:
        fixture = Fixture(fault)
        expect_failure(fault, lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0),
                       fixture, needle, expected_count)
        row = fixture.report['directional_role_preparation']['committed_witness']
        check(fault + '.not_completed', row['completed'] is False)
        if fault in ('unknown_write', 'unknown_delete'):
            check(fault + '.exact_original_ledger_marks_unknown',
                  fixture.recovery.public_receipt['unknown_transport_outcomes'] == 1
                  and fixture.recovery.public_receipt['mutation_responses'] == 45 + expected_count - 1)
        old_count = len(fixture.api.calls)
        expect_failure(fault + '.no_second_attempt',
            lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0), fixture, 'would_be_repeated')
        check(fault + '.no_cleanup_replay_after_failure', len(fixture.api.calls) == old_count)

    fixture = Fixture()
    expect_failure('expired_before_start_never_dispatches',
                   lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 100.0),
                   fixture, 'expired_before_dispatch', 0)
    check('expired_before_start_no_get_either', fixture.api.calls == [])
    fixture = Fixture('expired_after_known_write')
    expect_failure('known_write_at_expiry_never_dispatches_delete',
                   lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0), fixture,
                   'after_original_http_budget', 1)
    check('known_late_write_is_not_reclassified_as_transport_unknown',
          fixture.recovery.public_receipt['mutation_responses'] == 46
          and fixture.recovery.public_receipt['unknown_transport_outcomes'] == 0)

    fixture = Fixture()
    fixture.recovery.public_receipt['unknown_transport_outcomes'] = 1
    expect_failure('preexisting_unknown_refuses_before_new_request',
                   lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0),
                   fixture, 'all_known_mutations', 0)
    fixture = Fixture()
    fixture.acknowledged['native-ha-' + fixture.run_id + '/direction-prepare-witness'] = 'x'
    expect_failure('witness_original_key_alias_refused',
                   lambda: fixture._direction_commit_witness(MAC, POCKET, numeric(), 160.0), fixture,
                   'must_not_alias', 0)

    fixture, frontier, before = prepared()
    fixture._direction_verify_witness_frontier(numeric(), numeric(term=3, node=3, index=63), frontier, before, 160.0)
    check('original_higher_term_branch_still_invoked',
          fixture.report['directional_role_preparation']['frontier_branch'] == 'original-higher-term'
          and 'same_committed_leader_exact' not in fixture.report['directional_role_preparation']['persisted_frontier_proof'])

    changes = [
        ('index_progress_with_lower_term_refused', lambda o,n,f,b: n.update(numeric(term=1, node=3, index=64))),
        ('same_term_different_higher_node_not_same_branch', lambda o,n,f,b: (n.update(numeric(node=4, index=63)), f.update(leader_node=4))),
        ('old_committed_different_leader_refused', lambda o,n,f,b: o.update(committed_log_id=log(term=1, node=1, index=60))),
        ('old_vote_different_leader_refused', lambda o,n,f,b: o.update(final_vote={'leader_id': {'term': 2, 'node_id': 4}, 'committed': True})),
        ('old_vote_uncommitted_refused', lambda o,n,f,b: o['final_vote'].update(committed=False)),
        ('new_vote_uncommitted_refused', lambda o,n,f,b: n['final_vote'].update(committed=False)),
        ('vote_regression_refused', lambda o,n,f,b: n['final_vote']['leader_id'].update(term=1)),
        ('old_committed_beyond_last_refused', lambda o,n,f,b: o.update(committed_log_id=log(index=62))),
        ('new_last_below_full_committed_refused', lambda o,n,f,b: n.update(last_log_id=log(term=1,node=3,index=100))),
        ('index_no_progress_refused', lambda o,n,f,b: n.update(numeric(index=61))),
        ('prestop_committed_regression_refused', lambda o,n,f,b: b.update(committed_index=62)),
        ('mac_applied_mismatch_refused', lambda o,n,f,b: f.update(mac_applied_index=62)),
        ('boolean_numeric_field_refused', lambda o,n,f,b: n['committed_log_id'].update(index=True)),
        ('negative_u64_refused', lambda o,n,f,b: n['last_log_id'].update(index=-1)),
        ('overflow_u64_refused', lambda o,n,f,b: n['last_log_id'].update(index=1 << 64)),
        ('unknown_numeric_field_refused', lambda o,n,f,b: n['committed_log_id'].update(extra=0)),
    ]
    for name, mutate in changes:
        fixture, frontier, before = prepared()
        old, new = numeric(), numeric(index=63)
        mutate(old, new, frontier, before)
        expect_failure(name, lambda: fixture._direction_verify_witness_frontier(old, new, frontier, before, 160.0), fixture)

    fixture, frontier, before = prepared()
    fixture.report['directional_role_preparation']['committed_witness']['mac_metadata_absence_confirmed'] = False
    expect_failure('missing_mac_metadata_absence_cannot_qualify_frontier',
        lambda: fixture._direction_verify_witness_frontier(numeric(), numeric(index=63), frontier, before, 160.0), fixture,
        'witness_terminal_not_proven')
    fixture, frontier, before = prepared()
    fixture.report['directional_role_preparation']['committed_witness']['leader_frontier_after_delete'] = [64, 64]
    expect_failure('stopped_mac_before_delete_frontier_refused',
        lambda: fixture._direction_verify_witness_frontier(numeric(), numeric(index=63), frontier, before, 160.0), fixture,
        'full_log_or_committed_vote_regressed')
    fixture, frontier, before = prepared('expiry_during_numeric_publication')
    expect_failure('numeric_publication_past_shared_deadline_refused',
        lambda: fixture._direction_verify_witness_frontier(numeric(), numeric(index=63), frontier, before, 160.0), fixture,
        'completion_after_deadline')
    check('expired_numeric_proof_lacks_within_deadline_flag',
          fixture.report['directional_role_preparation']['persisted_frontier_proof'].get('within_new_total_prepare_deadline') is not True)

    fixture, _, _ = prepared()
    frontier = fixture._direction_quorum_frontier([MAC, POCKET], numeric(), 160.0)
    check('existing_real_quorum_window_retains_2point2_requirement',
          frontier['stable_seconds'] >= 2.2 and frontier['leader_node'] == 3
          and frontier['mac_applied_index'] == 63 and CLOCK.now < 160)
    check('all_quorum_requests_use_same_parent_and_max2',
          all(row['parent_deadline'] == 160 and 0 < row['timeout'] <= 2
              for row in fixture.api.calls if row['path'] in ('sys/health', 'sys/leader')))

    for stem in ('read_stopped_postrecovery_frontier', 'read_stopped_recovered_cipher'):
        old = (BEFORE / (stem + '_r1.py')).read_text()
        new = (AFTER / (stem + '_r2.py')).read_text()
        restored = new.replace('postrecovery-cold-node1-r2', 'postrecovery-cold-node1-r1').replace(
            'postrecovery-cold-node2-r2', 'postrecovery-cold-node2-r1')
        check(stem + '.only_fixed_fresh_root_literals_changed', restored == old)
        old_functions = {node.name: exact(old, node) for node in ast.parse(old).body
                         if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        new_functions = {node.name: exact(new, node) for node in ast.parse(new).body
                         if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        check(stem + '.all_function_bytes_identical', old_functions == new_functions)

    def literals(source):
        result = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    result[node.targets[0].id] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    pass
        return result

    old_launcher = (BEFORE / 'launch_normal_r10_pocket_postrecovery_cold_r1.py').read_text()
    new_launcher = (AFTER / 'launch_normal_r10_pocket_postrecovery_cold_r2.py').read_text()
    old_literals, new_literals = literals(old_launcher), literals(new_launcher)
    check('all_original24_fences_exact_plus4_failed_B_fences',
          len(old_literals['COMPARISON_PINS']) == 24 and len(new_literals['COMPARISON_PINS']) == 28
          and all(new_literals['COMPARISON_PINS'].get(key) == value
                  for key,value in old_literals['COMPARISON_PINS'].items()))
    check('product_builds_QA5_deadline_QA_and_extra12_unchanged', all(
        old_literals[key] == new_literals[key] for key in ('COMMIT', 'TREE', 'BUILDS', 'QA_PINS', 'DEADLINE_QA_PINS', 'POSTCOLD_CHECKS')))
    check('launcher_final_runner_SHA_exact',
          new_literals['RUNNER_SHA256'] == hashlib.sha256(NEW.encode()).hexdigest())
    new_runner_literals = literals(NEW)
    for name, constant in [('read_stopped_postrecovery_frontier_r2.py', 'NUMERIC_HELPER_SHA256'),
                           ('read_stopped_recovered_cipher_r2.py', 'CIPHER_HELPER_SHA256')]:
        digest = hashlib.sha256((AFTER / name).read_bytes()).hexdigest()
        check(name + '.both_callers_exact_SHA', new_literals[constant] == new_runner_literals[constant] == digest)
    old_carrier = (BEFORE / 'inert_carrier.py').read_text()
    new_carrier = (ROOT / 'inert_carrier_r2.py').read_text()
    def without_bindings(source):
        tree = ast.parse(source)
        tree.body = [node for node in tree.body if not (isinstance(node, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id in ('BASE', 'PINS') for t in node.targets))]
        return ast.dump(tree, include_attributes=False)
    check('inert_carrier_only_BASE_PINS_AST_delta', without_bindings(old_carrier) == without_bindings(new_carrier))
    payload = json.loads((ROOT / 'inert_stdin_r2.json').read_text())
    carrier_pins = literals(new_carrier)['PINS']
    check('inert_payload_exact_nine_sources_with_size_and_digest',
          len(payload['files']) == 9 and set(payload['files']) == set(carrier_pins)
          and all((raw := base64.b64decode(value, validate=True)) == (AFTER / name).read_bytes()
              and [len(raw), hashlib.sha256(raw).hexdigest()] == carrier_pins[name]
              for name,value in payload['files'].items()))
    check('original_probe_and_four_QA_full_bytes_unchanged', all(
        (BEFORE / name).read_bytes() == (AFTER / name).read_bytes() for name in carrier_pins
        if name.startswith('deadline_qa/') or name == 'probe_normal_build_r10_r1.py'))
    proposal = json.loads((ROOT / 'DISPATCH.proposed.json').read_text())
    check('proposed_dispatch_all_unsubmitted_and_original_caps',
          proposal['all_stages_authorized'] is False
          and all(proposal[key]['authorized'] is False for key in ('inert','prepare','live'))
          and proposal['inert']['timeout_seconds'] == 60 and proposal['prepare']['timeout_seconds'] == 360
          and proposal['live']['timeout_seconds'] == 3000 and proposal['live']['inner_seconds'] == 2400
          and proposal['live']['prepared_sha256'] is None and proposal['live']['role_preparation_seconds'] == 60)

    result = {'schema': 'heptabao.postcold-witness-r2-offline-components.v1',
              'status': 'passed', 'scope': 'exact AST-selected bodies with in-memory clock/HTTP/ledger storage adapters',
              'network_calls': 0, 'host_calls': 0, 'product_processes': 0, 'child_processes': 0,
              'no_actual_cas_or_delete': True, 'no_runtime_qualification': True,
              'request_and_ledger_logic_are_original_exact_methods': True,
              'source_sha256': hashlib.sha256(NEW.encode()).hexdigest(),
              'base_sha256': hashlib.sha256(OLD.encode()).hexdigest(),
              'component_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'python_version': sys.version, 'checks': ROWS,
              'passed_checks': sum(row['passed'] is True for row in ROWS), 'total_checks': len(ROWS)}
    output = ROOT / 'components-r2-final-result.public.json'
    with output.open('x') as stream:
        stream.write(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'passed_checks': result['passed_checks'],
                      'total_checks': result['total_checks'], 'source_sha256': result['source_sha256'],
                      'result_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        failure = {'status': 'component-failed', 'error_type': type(error).__name__, 'error': str(error),
                   'checks': ROWS, 'host_calls': 0, 'product_processes': 0, 'network_calls': 0}
        (ROOT / 'components-r2-final-failure.public.json').write_text(json.dumps(failure, sort_keys=True, indent=2) + '\n')
        raise
