#!/usr/bin/env python3
"""Installed-entry faults using real private files/locks and synthetic KV only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import tempfile
import unittest
from unittest.mock import patch
import uuid

SOURCE = Path(__file__).resolve().parents[2] / 'tools/authbus/authbus_coordinator_installed.py'
SPEC = importlib.util.spec_from_file_location('installed_entry_contract', SOURCE)
entry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entry)


class Crash(BaseException):
    pass


class FakeBao:
    def __init__(self, central):
        self.c = central
        self.values, self.history, self.attempts, self.reads = {}, {}, [], []
        self.secrets = ['synthetic-existing-bearer']
        self.hook = None

    def read(self, key, version=None):
        self.reads.append((key, version))
        return copy.deepcopy(self.values.get(key) if version is None else self.history.get(key, {}).get(version))

    def list(self, prefix, *, after=None, limit=32):
        return sorted(key[len(prefix) + 1:] for key in self.values
                      if key.startswith(prefix + '/') and '/' not in key[len(prefix) + 1:]
                      and (after is None or key[len(prefix) + 1:] > after))[:limit]

    def apply(self, key, value, cas):
        current = self.values.get(key)
        if (0 if current is None else current['version']) != cas:
            raise self.c.Conflict('kv_cas_conflict')
        item = {'version': cas + 1, 'data': copy.deepcopy(value)}
        self.values[key] = item
        self.history.setdefault(key, {})[cas + 1] = copy.deepcopy(item)
        return cas + 1

    def write(self, key, value, cas):
        self.attempts.append((key, cas, self.c.digest(value)))
        if self.hook:
            hook, self.hook = self.hook, None
            return hook(key, value, cas)
        return self.apply(key, value, cas)


class InstalledContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.owner = str(uuid.uuid4())
        self.sources = ['mac', 'rog', 'pocket4']
        self.state = self.root / 'state'
        entry.prepare_state(self.state, self.owner, self.sources)
        self.config_path = self.root / 'config.private.json'
        self.unit = self.root / 'owner.service'
        for name in ('ca', 'role', 'secret'):
            self.private(self.root / name, ('synthetic-' + name + '-material').encode())
        self.cfg = {'schema': entry.SCHEMA + '.config', 'production_cutover': True,
                    'service_scope': {'manager': 'user', **entry.current_service_identity()},
                    'state_dir': str(self.state), 'owner_id': self.owner,
                    'source_hosts': self.sources, 'address': 'https://fixture.invalid:8443',
                    'server_certificate_sha256': 'a' * 64, 'request_timeout_seconds': 10,
                    'ca_file': str(self.root / 'ca'), 'role_id_file': str(self.root / 'role'),
                    'secret_id_file': str(self.root / 'secret')}
        self.private(self.config_path, json.dumps(self.cfg).encode())
        self.binding_path = self.root / 'binding.private.json'
        self.bind()
        self.c = self.binding.central
        self.fake = FakeBao(self.c)
        self.client = entry.GuardedBao(self.binding, self.fake)

    def private(self, path, payload):
        path.write_bytes(payload)
        path.chmod(0o600)

    def bind(self, name=None):
        if name:
            self.binding_path = self.root / name
        pin = self.binding_path.with_suffix('.pin.env')
        self.private(self.unit, entry.service_file_bytes(self.cfg, self.binding_path, pin))
        entry.make_binding(self.config_path, entry.sha(self.config_path.read_bytes()),
                           self.unit, entry.sha(self.unit.read_bytes()), self.binding_path)
        self.binding = entry.Binding(self.binding_path, entry.sha(self.binding_path.read_bytes()))

    def test_actual_unit_activation_reference_has_no_hash_cycle(self):
        pin_path = Path(self.binding.value['activation_pin_file'])
        pin = pin_path.read_text().strip().split('=', 1)[1]
        self.assertEqual(pin, self.binding.expected)
        start = next(line.split('=', 1)[1] for line in self.unit.read_text().splitlines()
                     if line.startswith('ExecStart='))
        argv = shlex.split(start.replace('${HEPTABAO_BINDING_SHA256}', pin))
        self.assertEqual(argv[:5], ['/usr/bin/python3', '-I', '-S', '-B', str(entry.ENTRY)])
        parsed = entry.parser().parse_args(argv[5:])
        verified = entry.Binding(parsed.binding, parsed.binding_sha256)
        self.assertEqual((parsed.group, parsed.command, verified.expected), ('service', 'serve', pin))
        self.private(pin_path, entry.activation_bytes('f' * 64))
        with self.assertRaisesRegex(entry.InstallationError, 'activation_reference_changed'):
            self.binding.verify()

    def test_user_unit_cannot_bind_without_private_user_namespace(self):
        binding = self.root / 'weakened-binding.private.json'
        unit = self.root / 'weakened-owner.service'
        original = entry.service_file_bytes(self.cfg, binding, binding.with_suffix('.pin.env'))
        self.assertEqual(original.count(b'PrivateUsers=yes\n'), 1)
        self.private(unit, original.replace(b'PrivateUsers=yes\n', b'PrivateUsers=no\n'))
        with self.assertRaisesRegex(entry.InstallationError, 'installation_service_command_contract'):
            entry.make_binding(self.config_path, entry.sha(self.config_path.read_bytes()),
                               unit, entry.sha(unit.read_bytes()), binding)
        self.assertFalse(binding.exists())
        self.assertEqual((self.fake.reads, self.fake.attempts), ([], []))

    def test_system_scope_renders_only_exact_nonroot_operator_identity(self):
        identity = {'uid': 1000, 'gid': 1000, 'user': 'qian', 'group': 'qian'}
        cfg = {**self.cfg, 'service_scope': {'manager': 'system', **identity}}
        with patch.object(entry, 'current_service_identity', return_value=identity):
            raw = entry.service_file_bytes(cfg, self.binding_path, self.binding_path.with_suffix('.pin.env'))
            self.assertIn(b'User=qian\nGroup=qian\n', raw)
            self.assertIn(b'WantedBy=multi-user.target\n', raw)
            cfg['service_scope']['uid'] = 0
            with self.assertRaisesRegex(entry.InstallationError, 'service_identity_changed'):
                entry.service_file_bytes(cfg, self.binding_path, self.binding_path.with_suffix('.pin.env'))
        root = {'uid': 0, 'gid': 0, 'user': 'root', 'group': 'root'}
        with patch.object(entry, 'current_service_identity', return_value=root):
            with self.assertRaisesRegex(entry.InstallationError, 'must_be_nonroot'):
                entry.service_scope({'service_scope': {'manager': 'system', **root}})

    def test_service_scope_and_unit_custody_are_bound(self):
        self.assertEqual(self.binding.value['service_scope'], self.cfg['service_scope'])
        before = self.unit.read_bytes()
        old = self.root / 'original-owner.service'
        self.unit.rename(old)
        self.private(self.unit, before)
        with self.assertRaisesRegex(entry.InstallationError, 'service_unit_replaced'):
            self.binding.verify()
        self.assertEqual((self.fake.reads, self.fake.attempts), ([], []))

    def initialize(self):
        return entry.operator(self.binding, self.client, 'initialize', version=0, head_sha='absent')

    def head(self):
        snapshot = self.fake.values['manifest']
        return {'version': snapshot['version'], 'head_sha': self.c.digest(snapshot['data'])}

    def grant(self, credential=None, profile='managed-one', host='mac'):
        credential = credential or {
            'type': 'oauth', 'provider': 'openai', 'accountId': 'synthetic-stable-identity',
            'access': 'synthetic-access-current', 'refresh': 'synthetic-refresh-current', 'expires': 2000000000000}
        grant = {'authorizationId': str(uuid.uuid4()), 'profileId': profile, 'sourceHost': host,
                 'provider': credential['provider'], 'identityDigest': self.c.identity(credential),
                 'expectedCurrentDigest': None, 'nextDigest': self.c.digest(credential)}
        path = self.root / ('grant-' + grant['authorizationId'] + '.private.json')
        self.private(path, self.c.canonical(grant))
        return grant, credential, {'grant_path': path, 'grant_sha': entry.sha(path.read_bytes())}

    def test_original_candidate_cli_refuses_production_true(self):
        with self.assertRaisesRegex(self.c.Error, 'candidate_requires_explicit_uninstalled_scope'):
            self.c.load_config(self.config_path)

    def test_formal_binding_requires_true_and_exact_host_source_and_files(self):
        self.cfg['production_cutover'] = False
        self.private(self.config_path, json.dumps(self.cfg).encode())
        with self.assertRaisesRegex(entry.InstallationError, 'requires_explicit_production'):
            self.bind('binding-false.private.json')
        self.assertEqual(self.fake.attempts, [])

    def test_binding_rejects_config_drift_before_any_remote_call(self):
        self.private(self.root / 'role', b'synthetic-replaced-role-material')
        with self.assertRaisesRegex(entry.InstallationError, 'installation_input_changed'):
            self.initialize()
        self.assertEqual((self.fake.reads, self.fake.attempts), ([], []))

    def test_missing_original_lock_is_never_recreated(self):
        lock = self.state / 'operation.lock'
        lock.unlink()
        with self.assertRaises(FileNotFoundError):
            self.initialize()
        self.assertFalse(lock.exists())
        self.assertEqual(self.fake.attempts, [])

    def test_same_bytes_replacement_lock_is_refused(self):
        lock = self.state / 'operation.lock'
        old = self.state / 'original-operation.lock'
        lock.rename(old)
        self.private(lock, b'')
        with self.assertRaisesRegex(entry.InstallationError, 'original_lock_replaced'):
            self.initialize()

    def test_second_local_service_owner_is_refused(self):
        with self.binding.lock('service_lock'):
            with self.assertRaisesRegex(entry.InstallationError, 'installation_owner_busy'):
                with self.binding.lock('service_lock'):
                    self.fail('duplicate service entered')

    def test_prepare_state_is_create_only_and_requires_existing_private_parent(self):
        before = (self.state / 'owner.private.json').read_bytes()
        with self.assertRaises(FileExistsError):
            entry.prepare_state(self.state, self.owner, self.sources)
        self.assertEqual((self.state / 'owner.private.json').read_bytes(), before)

    def test_service_command_parser_cannot_run_administration(self):
        for command in ('initialize', 'authorize', 'revoke-authorization'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                entry.parser().parse_args(['service', command, '--binding', str(self.binding_path),
                                          '--binding-sha256', self.binding.expected])

    def test_one_shot_initialize_and_exact_authorize_revoke_use_original_methods(self):
        self.assertTrue(self.initialize()['initialized'])
        grant, _, args = self.grant()
        self.assertTrue(entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)['authorized'])
        self.assertEqual(self.fake.values['manifest']['data']['coordinator']['authorizations'], [grant])
        self.assertTrue(entry.operator(self.binding, self.client, 'revoke-authorization', **self.head(), **args)
                        ['authorization_revoked'])
        self.assertEqual(self.fake.values['manifest']['data']['coordinator']['authorizations'], [])
        self.assertEqual([x[:2] for x in self.fake.attempts], [('manifest', 0), ('manifest', 1), ('manifest', 2)])
        self.assertFalse(entry.pending_path(self.binding).exists())

    def test_wrong_head_or_grant_pin_cannot_dispatch(self):
        self.initialize()
        _, _, args = self.grant()
        before = list(self.fake.attempts)
        with self.assertRaisesRegex(entry.InstallationError, 'expected_manifest_changed'):
            entry.operator(self.binding, self.client, 'authorize', version=1, head_sha='f' * 64, **args)
        with self.assertRaisesRegex(entry.InstallationError, 'authorization_file_pin'):
            entry.operator(self.binding, self.client, 'authorize', **self.head(),
                           grant_path=args['grant_path'], grant_sha='0' * 64)
        self.assertEqual(self.fake.attempts, before)

    def test_same_authorization_id_changed_grant_cannot_revoke(self):
        self.initialize()
        grant, _, args = self.grant()
        entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        grant['nextDigest'] = 'b' * 64
        self.private(args['grant_path'], self.c.canonical(grant))
        args['grant_sha'] = entry.sha(args['grant_path'].read_bytes())
        before = list(self.fake.attempts)
        with self.assertRaisesRegex(entry.InstallationError, 'revoke_exact_grant_changed'):
            entry.operator(self.binding, self.client, 'revoke-authorization', **self.head(), **args)
        self.assertEqual(self.fake.attempts, before)

    def test_lost_initialize_reply_blocks_service_and_repeat_then_history_reconciles(self):
        def lost(key, value, cas):
            self.fake.apply(key, value, cas)
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            self.initialize()
        before = list(self.fake.attempts)
        with self.assertRaisesRegex(entry.InstallationError, 'pending_requires_reconciliation'):
            self.initialize()
        with self.assertRaisesRegex(entry.InstallationError, 'pending_requires_reconciliation'):
            entry.service_cycle(self.binding, self.client)
        result = entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(result['resolution'], 'desired_manifest_confirmed')
        self.assertEqual(result['remoteWrites'], 0)
        self.assertEqual(self.fake.attempts, before)

    def test_unknown_authorize_after_later_head_uses_exact_original_history(self):
        self.initialize()
        _, _, args = self.grant()
        def lost(key, value, cas):
            self.fake.apply(key, value, cas)
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        later = copy.deepcopy(self.fake.values['manifest']['data'])
        later['generation'] += 1
        self.fake.apply('manifest', later, 2)
        before = list(self.fake.attempts)
        result = entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(result['resolution'], 'desired_manifest_confirmed')
        self.assertIn(('manifest', 2), self.fake.reads)
        self.assertEqual(self.fake.attempts, before)

    def test_pruned_history_remains_unknown_and_does_not_repeat_cas(self):
        self.initialize()
        _, _, args = self.grant()
        def lost(key, value, cas):
            self.fake.apply(key, value, cas)
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        later = copy.deepcopy(self.fake.values['manifest']['data'])
        later['generation'] += 1
        self.fake.apply('manifest', later, 2)
        del self.fake.history['manifest'][2]
        before = list(self.fake.attempts)
        for _ in range(2):
            with self.assertRaisesRegex(self.c.UnknownOutcome, 'history_unavailable'):
                entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(self.fake.attempts, before)
        self.assertTrue(entry.pending_path(self.binding).exists())

    def test_unknown_uncommitted_head_is_not_invented_as_safe_retry(self):
        def unknown(*_):
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = unknown
        with self.assertRaises(self.c.UnknownOutcome):
            self.initialize()
        with self.assertRaisesRegex(self.c.UnknownOutcome, 'not_yet_classifiable'):
            entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(len(self.fake.attempts), 1)

    def test_successful_cas_bad_reply_version_is_reported_unknown_and_not_replayed(self):
        def bad_reply(key, value, cas):
            self.fake.apply(key, value, cas)
            raise self.c.Error('kv_write_version_mismatch')
        self.fake.hook = bad_reply
        with self.assertRaisesRegex(self.c.Error, 'kv_write_version_mismatch') as raised:
            self.initialize()
        text, status = entry.error_result(self.binding, self.client, raised.exception)
        report = json.loads(text)
        self.assertEqual(status, 3)
        self.assertTrue(report['unknown_outcome'] and report['operator_reconciliation_required'])
        with self.assertRaisesRegex(entry.InstallationError, 'pending_requires_reconciliation'):
            self.initialize()
        before = list(self.fake.attempts)
        self.assertEqual(entry.operator(self.binding, self.client, 'reconcile')['resolution'],
                         'desired_manifest_confirmed')
        self.assertEqual(self.fake.attempts, before)

    def test_successful_cas_archive_fsync_failure_is_reported_unknown_and_not_replayed(self):
        original = self.c.private_json
        def failed_archive(path, value, **kwargs):
            if path.name.startswith('operator-completed-'):
                raise OSError('synthetic archive persistence failure')
            return original(path, value, **kwargs)
        with patch.object(self.c, 'private_json', failed_archive), self.assertRaises(OSError) as raised:
            self.initialize()
        text, status = entry.error_result(self.binding, self.client, raised.exception)
        report = json.loads(text)
        self.assertEqual(status, 3)
        self.assertTrue(report['unknown_outcome'] and report['operator_reconciliation_required'])
        self.assertNotIn('synthetic archive', text)
        before = list(self.fake.attempts)
        with self.assertRaisesRegex(entry.InstallationError, 'pending_requires_reconciliation'):
            self.initialize()
        self.assertEqual(entry.operator(self.binding, self.client, 'reconcile')['resolution'],
                         'desired_manifest_confirmed')
        self.assertEqual(self.fake.attempts, before)

    def test_different_immutable_cas_successor_can_be_classified_without_write(self):
        self.initialize()
        _, _, args = self.grant()
        def lost(*_):
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        different = copy.deepcopy(self.fake.values['manifest']['data'])
        different['generation'] += 1
        self.fake.apply('manifest', different, 1)
        before = list(self.fake.attempts)
        result = entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(result['resolution'], 'cas_slot_contains_different_manifest')
        self.assertEqual(self.fake.attempts, before)

    def test_crash_after_completed_fsync_before_pending_unlink_is_recoverable(self):
        original_unlink = Path.unlink
        def crash(path, *args, **kwargs):
            if path == entry.pending_path(self.binding):
                raise Crash()
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', crash), self.assertRaises(Crash):
            self.initialize()
        self.assertTrue(entry.pending_path(self.binding).exists())
        before = list(self.fake.attempts)
        result = entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(result['resolution'], 'response_confirmed')
        self.assertFalse(entry.pending_path(self.binding).exists())
        self.assertEqual(self.fake.attempts, before)

    def test_unrelated_completed_archive_cannot_clear_unknown(self):
        def lost(*_):
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            self.initialize()
        record = json.loads(entry.pending_path(self.binding).read_bytes())
        bad = dict(record, resolution='cas_rejected', expectedVersion=99)
        self.c.private_json(self.state / ('operator-completed-' + record['operationId'] + '.private.json'), bad)
        with self.assertRaisesRegex(entry.InstallationError, 'completed_binding_mismatch'):
            entry.operator(self.binding, self.client, 'reconcile')
        self.assertTrue(entry.pending_path(self.binding).exists())

    def test_known_acl_denial_is_archived_and_does_not_become_unknown(self):
        def denied(*_):
            raise self.c.Error('bao_authentication_or_acl_denied')
        self.fake.hook = denied
        with self.assertRaisesRegex(self.c.Error, 'acl_denied'):
            self.initialize()
        self.assertFalse(entry.pending_path(self.binding).exists())
        archives = list(self.state.glob('operator-completed-*.private.json'))
        self.assertEqual(json.loads(archives[0].read_bytes())['resolution'], 'request_rejected')

    def test_changed_input_after_manifest_response_is_unknown(self):
        def changed(key, value, cas):
            result = self.fake.apply(key, value, cas)
            self.private(self.root / 'secret', b'synthetic-changed-secret-material')
            return result
        self.fake.hook = changed
        with self.assertRaisesRegex(self.c.UnknownOutcome, 'installation_changed_after_mutation'):
            self.initialize()
        self.assertTrue(entry.pending_path(self.binding).exists())

    def test_local_ungranted_identity_is_deferred_then_only_exact_grant_publishes(self):
        self.initialize()
        grant, credential, args = self.grant(profile='local-five', host='pocket4')
        event_id = str(uuid.uuid4())
        event = {'schemaVersion': 1, 'sourceHost': 'pocket4', 'eventId': event_id,
                 'reason': 'new-profile', 'profileId': grant['profileId'], 'credential': credential,
                 'digest': grant['nextDigest'], 'identity': grant['identityDigest']}
        self.fake.apply('inbox/pocket4/' + event_id, event, 0)
        first = entry.service_cycle(self.binding, self.client)
        self.assertEqual((first['committed'], first['deferred']), (0, 1))
        self.assertEqual(self.fake.values['manifest']['data']['profiles'], [])
        entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        second = entry.service_cycle(self.binding, self.client)
        self.assertEqual(second['committed'], 1)
        self.assertEqual(self.fake.values['manifest']['data']['profiles'][0]['profileId'], 'local-five')
        self.assertFalse(any(key == 'order-policy' for key, _, _ in self.fake.attempts))
        # The installed public guard still includes the actual current-cycle
        # credential, not only the AppRole bearer.
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
                entry.InstallationError, 'public_result_contains_secret'):
            entry.render(self.binding, self.client, {'unsafe': credential['access']})

    def test_full_owner_state_restore_needs_explicit_new_binding_and_original_kv_history(self):
        self.initialize()
        _, _, args = self.grant()
        def lost(key, value, cas):
            self.fake.apply(key, value, cas)
            raise self.c.UnknownOutcome('mutation_outcome_unknown')
        self.fake.hook = lost
        with self.assertRaises(self.c.UnknownOutcome):
            entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        old_binding = self.binding
        old_anchor = (self.state / 'owner.private.json').read_bytes()
        restored = self.root / 'restored-state'
        shutil.copytree(self.state, restored)
        self.state = restored
        self.cfg['state_dir'] = str(restored)
        self.private(self.config_path, json.dumps(self.cfg).encode())
        with self.assertRaisesRegex(entry.InstallationError, 'installation_input_changed'):
            old_binding.verify()
        self.bind('restored-binding.private.json')
        self.c = self.binding.central
        self.fake.c = self.c
        self.client = entry.GuardedBao(self.binding, self.fake)
        self.assertEqual((restored / 'owner.private.json').read_bytes(), old_anchor)
        before = list(self.fake.attempts)
        result = entry.operator(self.binding, self.client, 'reconcile')
        self.assertEqual(result['resolution'], 'desired_manifest_confirmed')
        self.assertEqual(self.fake.attempts, before)
        self.assertFalse(entry.pending_path(self.binding).exists())

    def test_event_commit_bad_reply_is_unknown_then_service_recovers_without_manifest_replay(self):
        self.initialize()
        grant, credential, args = self.grant()
        entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        event_id = str(uuid.uuid4())
        event = {'schemaVersion': 1, 'sourceHost': grant['sourceHost'], 'eventId': event_id,
                 'reason': 'new-profile', 'profileId': grant['profileId'], 'credential': credential,
                 'digest': grant['nextDigest'], 'identity': grant['identityDigest']}
        self.fake.apply('inbox/' + grant['sourceHost'] + '/' + event_id, event, 0)
        def bad_manifest_reply(key, value, cas):
            result = self.fake.apply(key, value, cas)
            if key == 'manifest':
                raise self.c.Error('kv_write_version_mismatch')
            self.fake.hook = bad_manifest_reply
            return result
        self.fake.hook = bad_manifest_reply
        with self.assertRaisesRegex(self.c.Error, 'kv_write_version_mismatch') as raised:
            entry.service_cycle(self.binding, self.client)
        pending = json.loads((self.state / 'pending.private.json').read_bytes())
        self.assertEqual(pending['phase'], 'manifest_dispatched')
        text, status = entry.error_result(self.binding, self.client, raised.exception)
        report = json.loads(text)
        self.assertEqual(status, 3)
        self.assertTrue(report['unknown_outcome'] and report['service_recovery_required'])
        self.assertFalse(report['operator_reconciliation_required'])
        before = [r for r in self.fake.attempts if r[0] == 'manifest']
        recovered = entry.service_cycle(self.binding, self.client, recover=True)
        self.assertTrue(recovered['recovered_pending'])
        self.assertEqual([r for r in self.fake.attempts if r[0] == 'manifest'], before)
        self.assertFalse((self.state / 'pending.private.json').exists())

    def test_unreadable_existing_event_pending_is_reported_unknown_without_values(self):
        self.private(self.state / 'pending.private.json', b'synthetic-invalid-private-json')
        text, status = entry.error_result(self.binding, self.client, ValueError('private input'))
        report = json.loads(text)
        self.assertEqual(status, 3)
        self.assertTrue(report['unknown_outcome'] and report['service_recovery_required'])
        self.assertFalse(report['operator_reconciliation_required'])
        self.assertNotIn('synthetic-invalid', text)
        self.assertNotIn('private input', text)

    def test_profile_cas_bad_reply_is_unknown_without_claiming_manifest_dispatch(self):
        self.initialize()
        grant, credential, args = self.grant()
        entry.operator(self.binding, self.client, 'authorize', **self.head(), **args)
        event_id = str(uuid.uuid4())
        event = {'schemaVersion': 1, 'sourceHost': grant['sourceHost'], 'eventId': event_id,
                 'reason': 'new-profile', 'profileId': grant['profileId'], 'credential': credential,
                 'digest': grant['nextDigest'], 'identity': grant['identityDigest']}
        self.fake.apply('inbox/' + grant['sourceHost'] + '/' + event_id, event, 0)
        def bad_profile_reply(key, value, cas):
            self.fake.apply(key, value, cas)
            self.assertTrue(key.startswith('profiles/'))
            raise self.c.Error('kv_write_version_mismatch')
        self.fake.hook = bad_profile_reply
        before_manifest = copy.deepcopy(self.fake.values['manifest'])
        with self.assertRaisesRegex(self.c.Error, 'kv_write_version_mismatch') as raised:
            entry.service_cycle(self.binding, self.client)
        pending = json.loads((self.state / 'pending.private.json').read_bytes())
        self.assertEqual(pending['phase'], 'prepared')
        text, status = entry.error_result(self.binding, self.client, raised.exception)
        report = json.loads(text)
        self.assertEqual(status, 3)
        self.assertTrue(report['unknown_outcome'] and report['service_recovery_required'])
        self.assertTrue(report['immutable_profile_write_may_have_dispatched'])
        self.assertFalse(report['event_manifest_write_may_have_dispatched'])
        self.assertEqual(self.fake.values['manifest'], before_manifest)
        before = list(self.fake.attempts)
        self.assertTrue(entry.service_cycle(self.binding, self.client, recover=True)['recovered_pending'])
        self.assertEqual(self.fake.attempts, before)
        self.assertTrue(any(key.startswith('profiles/') for key in self.fake.values))


if __name__ == '__main__':
    unittest.main(verbosity=2)
