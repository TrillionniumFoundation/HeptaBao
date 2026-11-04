#!/usr/bin/env python3
"""Synthetic fault regressions for the independent AuthBus coordinator.

The key/value transport is synthetic. The actual service implementation and
real mode-0600/fsynced owner journals are used. This is not a live HA/TLS or
production-coordinator qualification.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid


SOURCE = Path(__file__).resolve().parents[2] / 'tools/authbus/authbus_coordinator.py'
SPEC = importlib.util.spec_from_file_location('authbus_coordinator_candidate', SOURCE)
central = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(central)


class Crash(BaseException):
    pass


class FakeBao:
    def __init__(self):
        self.values = {}
        self.histories = {}
        self.attempts = []
        self.on_manifest_write = None
        self.list_calls = []

    def read(self, key, version=None):
        value = self.values.get(key) if version is None else self.histories.get(key, {}).get(version)
        return copy.deepcopy(value)

    def apply(self, key, value, cas):
        current = self.values.get(key)
        previous = 0 if current is None else current['version']
        if previous != cas:
            raise central.Conflict('kv_cas_conflict')
        result = {'version': previous + 1, 'data': copy.deepcopy(value)}
        self.values[key] = result
        self.histories.setdefault(key, {})[result['version']] = copy.deepcopy(result)
        return result['version']

    def write(self, key, value, cas):
        self.attempts.append((key, cas, central.digest(value)))
        if key == 'manifest' and self.on_manifest_write:
            hook, self.on_manifest_write = self.on_manifest_write, None
            return hook(key, value, cas)
        return self.apply(key, value, cas)

    def list(self, prefix, *, after=None, limit=central.MAX_SCAN_EVENTS):
        self.list_calls.append((prefix, after, limit))
        return sorted(key[len(prefix) + 1:] for key in self.values if key.startswith(prefix + '/')
                      and '/' not in key[len(prefix) + 1:]
                      and (after is None or key[len(prefix) + 1:] > after))[:limit]


class TransportContract(unittest.TestCase):
    """Deterministic clock/HTTPS boundary faults; no real network is used."""
    def setUp(self):
        self.now = 100.0
        self.sent, self.header_reads, self.timeouts = [], 0, []
        self.delays = {'connect': 0, 'send': 0, 'headers': 0, 'body': 0}
        self.reply = {'auth': {'client_token': 'synthetic-coordinator-bearer', 'lease_duration': 300, 'renewable': True}}
        self.client = object.__new__(central.Bao)
        self.client.host, self.client.port, self.client.context, self.client.timeout = 'fixture.invalid', 443, object(), 10
        self.client.pin = central.sha(b'synthetic-certificate')
        self.client.token, self.client.deadline, self.client.renewable = 'synthetic-coordinator-bearer', 500.0, True
        self.client.config = {'role_id_file': '/synthetic-role', 'secret_id_file': '/synthetic-secret'}
        self.client.secrets = []
        case = self

        class Socket:
            def getpeercert(self, binary_form):
                return b'synthetic-certificate'

            def settimeout(self, value):
                case.timeouts.append(value)

        class Response:
            status = 200

            def __init__(self):
                self.fp = object()

            def read1(self, _bound):
                case.now += case.delays['body']
                self.fp = None
                return json.dumps(case.reply).encode()

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.sock = Socket()

            def connect(self):
                case.now += case.delays['connect']

            def request(self, method, path, body, headers):
                case.sent.append({'method': method, 'path': path, 'headers': headers,
                                  'originalDeadlineAtSend': case.client.deadline})
                case.now += case.delays['send']

            def getresponse(self):
                case.header_reads += 1
                case.now += case.delays['headers']
                return Response()

            def close(self):
                pass

        self.clock_patch = patch.object(central.time, 'monotonic', lambda: self.now)
        self.transport_patch = patch.object(central.http.client, 'HTTPSConnection', Connection)
        self.clock_patch.start(); self.transport_patch.start()
        self.addCleanup(self.clock_patch.stop); self.addCleanup(self.transport_patch.stop)

    def test_slow_connect_exhausts_original_budget_without_dispatch(self):
        self.delays['connect'] = 11
        with self.assertRaisesRegex(central.Error, 'request_absolute_deadline') as raised:
            self.client.request('POST', 'synthetic/mutation', {'data': 'fixture'})
        self.assertNotIsInstance(raised.exception, central.UnknownOutcome)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.header_reads, 0)

    def test_send_exhaustion_is_unknown_and_never_reads_headers(self):
        self.delays['send'] = 11
        with self.assertRaises(central.UnknownOutcome):
            self.client.request('POST', 'synthetic/mutation', {})
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.header_reads, 0)

    def test_slow_headers_do_not_deliver_success(self):
        self.delays['headers'] = 11
        with self.assertRaises(central.UnknownOutcome):
            self.client.request('POST', 'synthetic/mutation', {})
        self.assertEqual(len(self.sent), 1)

    def test_decode_elapsed_deadline_does_not_deliver_success(self):
        actual_loads = central.json.loads
        def slow_loads(payload):
            result = actual_loads(payload)
            self.now += 11
            return result
        with patch.object(central.json, 'loads', slow_loads):
            with self.assertRaises(central.UnknownOutcome):
                self.client.request('POST', 'synthetic/mutation', {})
        self.assertEqual(len(self.sent), 1)

    def test_login_lease_starts_before_response_elapsed_time(self):
        self.client.token, self.client.deadline = None, 0
        self.delays.update(connect=2, headers=3, body=1)
        with patch.object(central, 'read_private', return_value=b'synthetic-approle-material'):
            self.client.ensure_token()
        self.assertEqual(self.now, 106)
        self.assertEqual(self.client.deadline, 400)
        self.assertEqual(len(self.sent), 1)
        self.assertNotIn('X-Vault-Token', self.sent[0]['headers'])

    def test_renewal_explicit_bearer_no_recursion_or_deadline_extension(self):
        self.client.deadline = 120
        self.delays.update(connect=2, headers=3, body=1)
        self.client.ensure_token()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['path'], '/v1/auth/token/renew-self')
        self.assertEqual(self.sent[0]['originalDeadlineAtSend'], 120)
        self.assertEqual(self.sent[0]['headers']['X-Vault-Token'], 'synthetic-coordinator-bearer')
        self.assertEqual(self.client.deadline, 400)
        self.assertEqual(self.now, 106)

    def test_failed_renewal_keeps_original_deadline_and_bearer(self):
        self.client.deadline = 120
        self.delays['send'] = 11
        with self.assertRaises(central.UnknownOutcome):
            self.client.ensure_token()
        self.assertEqual(self.client.deadline, 120)
        self.assertEqual(self.client.token, 'synthetic-coordinator-bearer')
        self.assertEqual(len(self.sent), 1)

    def test_successful_login_malformed_auth_reply_is_unknown_without_installing_token(self):
        for auth in ({'client_token': 'synthetic-issued-unaccepted-bearer'}, 'synthetic-nonobject-auth'):
            with self.subTest(nonobject=isinstance(auth, str)):
                self.client.token, self.client.deadline = None, 0
                self.sent.clear(); self.reply = {'auth': auth}
                with patch.object(central, 'read_private', return_value=b'synthetic-approle-material'):
                    with self.assertRaisesRegex(central.UnknownOutcome, 'approle_reply_shape'):
                        self.client.request('GET', 'synthetic/read')
                self.assertEqual([item['path'] for item in self.sent], ['/v1/auth/approle/login'])
                self.assertEqual((self.client.token, self.client.deadline), (None, 0))

    def test_successful_renewal_changed_bearer_is_unknown_without_replacing_original(self):
        self.client.deadline = 120
        self.reply['auth']['client_token'] = 'synthetic-unexpected-new-bearer'
        with self.assertRaisesRegex(central.UnknownOutcome, 'coordinator_renewal_token_changed'):
            self.client.request('GET', 'synthetic/read')
        self.assertEqual([item['path'] for item in self.sent], ['/v1/auth/token/renew-self'])
        self.assertEqual((self.client.token, self.client.deadline), ('synthetic-coordinator-bearer', 120))

    def test_original_lease_can_expire_before_renewal_dispatch(self):
        self.client.deadline = 105
        self.delays['connect'] = 6
        with self.assertRaisesRegex(central.Error, 'request_absolute_deadline'):
            self.client.ensure_token()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.client.deadline, 105)

    def test_elapsed_reply_lease_is_not_installed(self):
        self.client.token, self.client.deadline = None, 0
        def delayed_reply(*_args, **_kwargs):
            self.now += 301
            return self.reply
        with patch.object(central, 'read_private', return_value=b'synthetic-approle-material'), \
             patch.object(self.client, '_dispatch', delayed_reply):
            with self.assertRaisesRegex(central.UnknownOutcome, 'coordinator_reply_lease_elapsed'):
                self.client.ensure_token()
        self.assertIsNone(self.client.token)
        self.assertEqual(self.client.deadline, 0)

    def test_many_renewals_keep_only_current_authentication_guard(self):
        self.client.token, self.client.deadline = None, 0
        material = lambda path, _maximum: (b'synthetic-current-role' if str(path).endswith('role')
                                           else b'synthetic-current-secret')
        with patch.object(central, 'read_private', side_effect=material):
            self.client.ensure_token()
        expected = {'synthetic-current-role', 'synthetic-current-secret', 'synthetic-coordinator-bearer'}
        for _ in range(512):
            self.now = self.client.deadline - 10
            self.client.ensure_token()
            self.assertEqual(set(self.client.secrets), expected)
            self.assertEqual(len(self.client.secrets), 3)
        self.assertEqual(len(self.sent), 513)
        self.assertTrue(all(row['path'] == '/v1/auth/token/renew-self' for row in self.sent[1:]))

    def test_reauthentication_replaces_former_material_in_guard(self):
        previous = set()
        for number in range(32):
            role, secret, token = (f'synthetic-current-role-{number}',
                                   f'synthetic-current-secret-{number}',
                                   f'synthetic-current-token-{number}')
            self.client.token, self.client.deadline = None, 0
            self.reply['auth']['client_token'] = token
            material = lambda path, _maximum: (role if str(path).endswith('role') else secret).encode()
            with patch.object(central, 'read_private', side_effect=material):
                self.client.ensure_token()
            self.assertEqual(set(self.client.secrets), {role, secret, token})
            self.assertFalse(previous.intersection(self.client.secrets))
            previous = {role, secret, token}

    def test_failed_renewal_retains_current_authentication_guard(self):
        self.client.token, self.client.deadline = None, 0
        with patch.object(central, 'read_private', return_value=b'synthetic-current-approle-material'):
            self.client.ensure_token()
        expected = list(self.client.secrets)
        self.now = self.client.deadline - 5
        self.delays['send'] = 11
        with self.assertRaises(central.UnknownOutcome):
            self.client.ensure_token()
        self.assertEqual(self.client.secrets, expected)
        self.assertIn('synthetic-current-approle-material', self.client.secrets)
        self.assertIn('synthetic-coordinator-bearer', self.client.secrets)

    def test_oversized_inbox_page_refuses_without_mutating_or_deleting(self):
        self.reply = {'data': {'keys': [str(uuid.UUID(int=index)) for index in range(1, 1026)]}}
        with self.assertRaisesRegex(central.Error, 'inbox_list_bound'):
            self.client.list('inbox/producer')
        self.assertEqual([item['method'] for item in self.sent], ['LIST'])


    def test_page_request_uses_existing_exclusive_after_and_positive_limit(self):
        before, current = str(uuid.UUID(int=1024)), str(uuid.UUID(int=1025))
        self.reply = {'data': {'keys': [current]}}
        self.assertEqual(self.client.list('inbox/producer', after=before, limit=1), [current])
        self.assertEqual(self.sent[0]['path'],
                         '/v1/openclaw-auth/metadata/inbox/producer?limit=1&after=' + before)
        self.assertEqual(self.sent[0]['method'], 'LIST')

    def test_duplicate_unordered_or_nonadvancing_page_is_refused(self):
        first, second = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
        for keys, after in [([first, first], None), ([second, first], None), ([first], first)]:
            self.reply = {'data': {'keys': keys}}
            with self.assertRaisesRegex(central.Error, 'inbox_page_order_or_progress'):
                self.client.list('inbox/producer', after=after)
        self.assertEqual([row['method'] for row in self.sent], ['LIST'] * 3)

    def test_page_authentication_denial_does_not_reset_cursor_or_reauthenticate(self):
        with patch.object(self.client, 'request', side_effect=central.Error('bao_authentication_or_acl_denied')) as request:
            with self.assertRaisesRegex(central.Error, 'bao_authentication_or_acl_denied'):
                self.client.list('inbox/producer', after=str(uuid.UUID(int=1024)))
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.client.token, 'synthetic-coordinator-bearer')


class Contract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='authbus-coordinator-contract-')
        self.directory = Path(self.temporary.name)
        self.bao = FakeBao()
        self.owner = str(uuid.uuid4())
        self.worker = self.reopen()
        self.worker.initialize()
        self.number = 0

    def tearDown(self):
        self.temporary.cleanup()

    def reopen(self, hook=None):
        return central.Coordinator(self.bao, self.directory, self.owner, ['producer', 'follower'], hook)

    def event(self, *, profile='google:authbus-central-source', secret='synthetic-authbus-central-secret-a', source='producer'):
        self.number += 1
        credential = {'provider': 'google', 'type': 'api_key', 'key': secret}
        event = {'schemaVersion': 1, 'eventId': str(uuid.UUID(int=self.number)), 'sourceHost': source,
                 'reason': 'new-profile', 'createdAt': 123456789, 'profileId': profile,
                 'credential': credential, 'digest': central.digest(credential), 'identity': central.identity(credential)}
        return event

    def inbox(self, event, path_host=None):
        self.bao.write('inbox/' + (path_host or event['sourceHost']) + '/' + event['eventId'], event, 0)

    def grant(self, event, previous=None):
        value = {'authorizationId': str(uuid.uuid4()), 'profileId': event['profileId'], 'sourceHost': event['sourceHost'],
                 'provider': event['credential']['provider'], 'identityDigest': event['identity'],
                 'expectedCurrentDigest': previous, 'nextDigest': event['digest']}
        self.worker.authorize(value)
        return value

    def test_original_event_immutable_profile_manifest_and_dedup(self):
        event = self.event(); self.inbox(event); self.grant(event)
        result = self.worker.once()
        self.assertEqual(result['committed'], 1)
        manifest = self.bao.read('manifest')['data']
        self.assertEqual(manifest['generation'], 1)
        self.assertEqual(manifest['coordinator']['authorizations'], [])
        entry = manifest['profiles'][0]
        profile = self.bao.read('profiles/' + entry['key'])
        self.assertEqual(profile['version'], 1)
        self.assertEqual(profile['data']['credential'], event['credential'])
        self.assertEqual(entry['key'], 'sha256-' + central.digest(profile['data']))
        before = self.bao.read('manifest')
        repeat = self.reopen().once()
        self.assertEqual(repeat['already_recorded'], 1)
        self.assertEqual(self.bao.read('manifest'), before)
        self.assertNotIn(event['credential']['key'], json.dumps(result))

    def test_path_body_source_binding_and_canonical_digest(self):
        event = self.event(source='follower'); self.inbox(event, path_host='producer')
        with self.assertRaisesRegex(central.Error, 'inbox_body_path_identity_mismatch'):
            self.worker.once()
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])

    def test_rotation_requires_exact_operator_current_and_next(self):
        first = self.event(); self.inbox(first); self.grant(first); self.worker.once()
        second = self.event(secret='synthetic-authbus-central-secret-b'); second['createdAt'] = 9007199254740000
        self.inbox(second)
        self.assertEqual(self.worker.once()['deferred'], 1)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'][0]['digest'], first['digest'])
        self.grant(second, first['digest'])
        self.assertEqual(self.worker.once()['committed'], 1)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'][0]['digest'], second['digest'])

    def test_manifest_crash_cold_reopen_before_next_event(self):
        first = self.event(); self.inbox(first); self.grant(first)
        def hook(phase):
            if phase == 'manifest_committed_before_journal_reply':
                raise Crash()
        with self.assertRaises(Crash):
            self.reopen(hook).once()
        self.assertTrue((self.directory / 'pending.private.json').exists())
        self.assertIsNone(self.bao.read(central.receipt_key('producer', first['eventId'])))
        reopened = self.reopen(); self.worker = reopened
        result = reopened.once()
        self.assertTrue(result['recovered_pending'])
        self.assertEqual(result['committed'], 0)
        self.assertEqual(self.bao.read('manifest')['data']['generation'], 1)
        second = self.event(secret='synthetic-authbus-central-secret-b'); self.inbox(second); self.grant(second, first['digest'])
        self.assertEqual(reopened.once()['committed'], 1)
        self.assertIsNotNone(self.bao.read(central.receipt_key('producer', first['eventId'])))

    def test_unknown_reply_after_actual_synthetic_commit_uses_exact_history(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def lost(key, value, cas):
            self.bao.apply(key, value, cas)
            raise central.UnknownOutcome('mutation_outcome_unknown')
        self.bao.on_manifest_write = lost
        with self.assertRaises(central.UnknownOutcome):
            self.worker.once()
        dispatched = len(self.bao.attempts)
        result = self.reopen().once()
        self.assertTrue(result['recovered_pending'])
        writes = [row for row in self.bao.attempts[dispatched:] if row[0] == 'manifest']
        self.assertEqual(writes, [])

    def test_unknown_uncommitted_request_is_not_replayed(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def lost(_key, _value, _cas):
            raise central.UnknownOutcome('mutation_outcome_unknown')
        self.bao.on_manifest_write = lost
        with self.assertRaises(central.UnknownOutcome):
            self.worker.once()
        dispatched = len(self.bao.attempts)
        with self.assertRaisesRegex(central.UnknownOutcome, 'manifest_history_does_not_prove_pending_commit'):
            self.reopen().once()
        self.assertEqual(len(self.bao.attempts), dispatched)
        self.assertTrue((self.directory / 'pending.private.json').exists())

    def test_pruned_history_does_not_invent_old_commit(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def lost(key, value, cas):
            self.bao.apply(key, value, cas)
            raise central.UnknownOutcome('mutation_outcome_unknown')
        self.bao.on_manifest_write = lost
        with self.assertRaises(central.UnknownOutcome):
            self.worker.once()
        accepted = self.bao.read('manifest')
        advanced = copy.deepcopy(accepted['data']); advanced['operatorNote'] = 'synthetic-new-revision'
        self.bao.apply('manifest', advanced, accepted['version'])
        del self.bao.histories['manifest'][accepted['version']]
        with self.assertRaises(central.UnknownOutcome):
            self.reopen().once()
        self.assertTrue((self.directory / 'pending.private.json').exists())

    def test_known_cas_conflict_fresh_replan_has_distinct_journal(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def race(key, value, cas):
            old = self.bao.read('manifest'); old['data']['operatorNote'] = 'synthetic-conflict'
            self.bao.apply('manifest', old['data'], old['version'])
            return self.bao.apply(key, value, cas)
        self.bao.on_manifest_write = race
        self.assertEqual(self.worker.once()['deferred'], 1)
        self.assertEqual(self.reopen().once()['committed'], 1)
        self.assertEqual(len(list(self.directory.glob('completed-*.json'))), 2)

    def test_revocation_wins_manifest_cas_and_blocks_later_publication(self):
        event = self.event(); self.inbox(event); grant = self.grant(event)
        def revoke_race(key, value, cas):
            old = self.bao.read('manifest'); old['data']['coordinator']['authorizations'] = []
            self.bao.apply('manifest', old['data'], old['version'])
            return self.bao.apply(key, value, cas)
        self.bao.on_manifest_write = revoke_race
        self.assertEqual(self.worker.once()['deferred'], 1)
        self.assertEqual(self.reopen().once()['deferred'], 1)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])
        self.assertFalse(self.worker.revoke_authorization(grant['authorizationId'])['authorization_pending'])

    def test_immutable_collision_never_overwritten(self):
        event = self.event(); self.inbox(event); self.grant(event)
        payload = {'schemaVersion': 1, 'profileId': event['profileId'], 'credential': event['credential'],
                   'digest': event['digest'], 'identity': event['identity']}
        key = 'profiles/sha256-' + central.digest(payload)
        self.bao.write(key, {'invalid_existing_content': True}, 0)
        with self.assertRaisesRegex(central.Error, 'immutable_object_not_confirmed'):
            self.worker.once()
        self.assertEqual(self.bao.read(key)['version'], 1)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])

    def test_same_credential_different_profile_ids_have_distinct_immutable_keys(self):
        first = self.event(profile='google:authbus-source-a'); second = self.event(profile='google:authbus-source-b')
        self.inbox(first); self.inbox(second); self.grant(first); self.grant(second)
        self.assertEqual(self.worker.once()['committed'], 2)
        entries = self.bao.read('manifest')['data']['profiles']
        self.assertEqual(entries[0]['digest'], entries[1]['digest'])
        self.assertNotEqual(entries[0]['key'], entries[1]['key'])

    def test_same_id_changed_body_and_nonimmutable_event_rejected(self):
        event = self.event(); self.inbox(event); self.grant(event); self.worker.once()
        path = 'inbox/producer/' + event['eventId']
        replacement = copy.deepcopy(event); replacement['createdAt'] += 1
        self.bao.apply(path, replacement, 1)
        with self.assertRaisesRegex(central.Error, 'inbox_event_not_immutable'):
            self.worker.once()

    def crash_after_completed_archive(self, action):
        """Fault after the real file + directory fsync, before pending unlink."""
        original = central.private_json
        def after_write(path, value, replace=False):
            original(path, value, replace=replace)
            if path.name.startswith('completed-'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertTrue((self.directory / 'pending.private.json').exists())
                raise Crash()
        with patch.object(central, 'private_json', after_write):
            with self.assertRaises(Crash):
                action()

    def test_real_archive_fsync_cas_rejection_crash_recovers_without_replay(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def race(key, value, cas):
            other = self.bao.read('manifest'); other['data']['operatorNote'] = 'real-file-crash-fixture'
            self.bao.apply('manifest', other['data'], other['version'])
            return self.bao.apply(key, value, cas)
        self.bao.on_manifest_write = race
        self.crash_after_completed_archive(self.worker.once)
        pending = json.loads(central.read_private(self.directory / 'pending.private.json'))
        archive = json.loads(central.read_private(self.directory / ('completed-' + pending['operationId'] + '.json')))
        self.assertEqual(pending['phase'], 'manifest_dispatched')
        self.assertNotIn('result', pending)
        self.assertEqual(archive['result'], 'known_cas_conflict')
        attempts = len(self.bao.attempts)
        with central.operation_lock(self.directory):
            self.assertTrue(self.reopen().recover_locked())
        self.assertEqual(len(self.bao.attempts), attempts)
        self.assertFalse((self.directory / 'pending.private.json').exists())
        self.assertEqual(self.reopen().once()['committed'], 1)

    def test_completed_cas_rejection_recovery_does_not_resurrect_revoked_grant(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def revoke(key, value, cas):
            other = self.bao.read('manifest'); other['data']['coordinator']['authorizations'] = []
            self.bao.apply('manifest', other['data'], other['version'])
            return self.bao.apply(key, value, cas)
        self.bao.on_manifest_write = revoke
        self.crash_after_completed_archive(self.worker.once)
        attempts = len(self.bao.attempts)
        result = self.reopen().once()
        self.assertTrue(result['recovered_pending'])
        self.assertEqual((result['committed'], result['deferred']), (0, 1))
        self.assertEqual(len(self.bao.attempts), attempts)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])

    def test_unrelated_archive_cannot_classify_unknown_cas_as_rejected(self):
        first = self.event(); self.inbox(first); self.grant(first); self.worker.once()
        previous = next(self.directory.glob('completed-*.json'))
        previous_value = json.loads(central.read_private(previous))
        event = self.event(secret='synthetic-authbus-central-secret-b')
        self.inbox(event); self.grant(event, first['digest'])
        def unknown(_key, _value, _cas):
            raise central.UnknownOutcome('mutation_outcome_unknown')
        self.bao.on_manifest_write = unknown
        with self.assertRaises(central.UnknownOutcome):
            self.worker.once()
        pending = json.loads(central.read_private(self.directory / 'pending.private.json'))
        # Even an archive renamed to this operation UUID must match the
        # complete event/manifest binding, not just the owner and UUID.
        unrelated = {**previous_value, 'operationId': pending['operationId'],
                     'phase': 'manifest_dispatched', 'result': 'known_cas_conflict'}
        central.private_json(self.directory / ('completed-' + pending['operationId'] + '.json'), unrelated)
        attempts = len(self.bao.attempts)
        with self.assertRaisesRegex(central.Error, 'completed_journal_binding_mismatch'):
            self.reopen().once()
        self.assertTrue((self.directory / 'pending.private.json').exists())
        self.assertEqual(len(self.bao.attempts), attempts)

    def test_completed_commit_archive_cleans_pending_with_exact_existing_receipt(self):
        event = self.event(); self.inbox(event); self.grant(event)
        self.crash_after_completed_archive(self.worker.once)
        committed = self.bao.read('manifest')
        other = copy.deepcopy(committed['data']); other['operatorNote'] = 'later-confirmed-revision'
        self.bao.apply('manifest', other, committed['version'])
        del self.bao.histories['manifest'][committed['version']]
        attempts = len(self.bao.attempts)
        with central.operation_lock(self.directory):
            self.assertTrue(self.reopen().recover_locked())
        self.assertEqual(len(self.bao.attempts), attempts)
        self.assertFalse((self.directory / 'pending.private.json').exists())

    def test_completed_commit_archive_does_not_invent_missing_remote_receipt(self):
        event = self.event(); self.inbox(event); self.grant(event)
        self.crash_after_completed_archive(self.worker.once)
        del self.bao.values[central.receipt_key('producer', event['eventId'])]
        attempts = len(self.bao.attempts)
        with self.assertRaisesRegex(central.Error, 'completed_journal_receipt_not_confirmed'):
            self.reopen().once()
        self.assertTrue((self.directory / 'pending.private.json').exists())
        self.assertEqual(len(self.bao.attempts), attempts)

    def test_private_journal_mode_and_original_owner_lock(self):
        event = self.event(); self.inbox(event); self.grant(event)
        def hook(phase):
            if phase == 'journal_prepared':
                raise Crash()
        with self.assertRaises(Crash):
            self.reopen(hook).once()
        pending = self.directory / 'pending.private.json'
        self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(event['credential']['key'], pending.read_text())
        with central.operation_lock(self.directory):
            with self.assertRaisesRegex(central.Error, 'coordinator_operation_busy'):
                self.reopen().once()
        self.assertEqual(self.reopen().once()['committed'], 1)


    def report_event(self, number, source='producer'):
        return {'schemaVersion': 2, 'kind': 'agent-report', 'sourceHost': source,
                'eventId': str(uuid.UUID(int=number)), 'profiles': []}

    def test_more_than_1024_events_finish_in_bounded_pages_across_cold_reopens(self):
        total = 1057
        for number in range(1, total + 1):
            self.inbox(self.report_event(number))
        observed, cycles = 0, 0
        while observed < total and cycles < 40:
            result = self.reopen().once()
            observed += result['observed_reports']; cycles += 1
            self.assertLessEqual(result['scanned'], central.MAX_SCAN_EVENTS)
            self.assertLessEqual(result['list_requests'], 2)
            self.assertLessEqual((self.directory / 'inbox-scan.private.json').stat().st_size, 2048)
        self.assertEqual(observed, total)
        self.assertEqual(cycles, 34)
        self.assertTrue(all(1 <= limit <= 32 for _prefix, _after, limit in self.bao.list_calls))
        self.assertEqual(len([key for key in self.bao.values if key.startswith('inbox/')]), total)
        self.assertEqual(len([key for key in self.bao.values if key.startswith('coordinator-receipts/')]), total)
        self.assertEqual(self.bao.read('manifest')['data']['generation'], 0)

    def test_unapproved_early_events_do_not_starve_later_events_or_other_hosts(self):
        for _ in range(64):
            self.inbox(self.event())
        self.inbox(self.report_event(100, source='follower'))
        first = self.reopen().once()
        self.assertEqual((first['deferred'], first['scanned']), (32, 32))
        second = self.reopen().once()
        self.assertEqual(second['observed_reports'], 1)
        self.assertEqual(second['scanned'], 32)
        self.assertEqual(self.bao.list_calls[1][0], 'inbox/follower')
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])

    def test_wrap_revisits_new_lower_uuid_and_later_authorized_event(self):
        for number in range(100, 133):
            self.inbox(self.report_event(number))
        first = self.reopen().once()
        self.assertEqual(first['observed_reports'], 32)
        late = self.event(); self.inbox(late)
        self.assertEqual(self.reopen().once()['observed_reports'], 1)
        self.assertEqual(self.reopen().once()['deferred'], 1)
        self.grant(late)
        results = [self.reopen().once() for _ in range(3)]
        self.assertEqual(sum(row['committed'] for row in results), 1)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'][0]['digest'], late['digest'])

    def test_crash_before_cursor_save_reuses_receipts_without_repeating_publication(self):
        for number in range(1, 34):
            self.inbox(self.report_event(number))
        original = central.private_json
        def crash_before_save(path, value, replace=False):
            if path.name == 'inbox-scan.private.json':
                raise Crash()
            return original(path, value, replace=replace)
        with patch.object(central, 'private_json', crash_before_save):
            with self.assertRaises(Crash):
                self.worker.once()
        self.assertFalse((self.directory / 'inbox-scan.private.json').exists())
        before = len(self.bao.attempts)
        replay = self.reopen().once()
        self.assertEqual((replay['already_recorded'], replay['observed_reports']), (32, 0))
        self.assertEqual(len(self.bao.attempts), before)
        self.assertEqual(self.reopen().once()['observed_reports'], 1)

    def test_pending_unknown_recovery_precedes_saved_cursor_and_never_replays_manifest(self):
        for number in range(1, 34):
            self.inbox(self.report_event(number))
        self.number = 33
        event = self.event(); self.inbox(event); self.grant(event)
        self.worker.once()
        scan_path = self.directory / 'inbox-scan.private.json'
        original_cursor = scan_path.read_bytes()
        def lost(key, value, cas):
            self.bao.apply(key, value, cas)
            raise central.UnknownOutcome('mutation_outcome_unknown')
        self.bao.on_manifest_write = lost
        with self.assertRaises(central.UnknownOutcome):
            self.reopen().once()
        self.assertEqual(scan_path.read_bytes(), original_cursor)
        before = len(self.bao.attempts)
        resumed = self.reopen().once()
        self.assertTrue(resumed['recovered_pending'])
        self.assertEqual(resumed['committed'], 0)
        self.assertEqual(self.bao.read('manifest')['data']['generation'], 1)
        self.assertEqual([row for row in self.bao.attempts[before:] if row[0] == 'manifest'], [])

    def test_scan_cursor_rejects_wrong_owner_sources_and_out_of_range_host(self):
        self.worker.once()
        path = self.directory / 'inbox-scan.private.json'
        original = json.loads(path.read_text())
        for patch_value in [{'ownerId': str(uuid.uuid4())}, {'sourceHosts': ['follower', 'producer']},
                            {'nextHost': 2}, {'positions': {'producer': 'not-a-uuid', 'follower': None}}]:
            central.private_json(path, {**original, **patch_value}, replace=True)
            before = len(self.bao.attempts)
            with self.assertRaisesRegex(central.Error, 'inbox_scan_owner_or_cursor_binding'):
                self.reopen().once()
            self.assertEqual(len(self.bao.attempts), before)

    def test_revoked_grant_stays_revoked_when_deferred_event_is_revisited(self):
        for number in range(100, 133):
            self.inbox(self.report_event(number))
        event = self.event(); self.inbox(event); grant = self.grant(event)
        self.worker.revoke_authorization(grant['authorizationId'])
        for _ in range(4):
            self.assertEqual(self.reopen().once()['committed'], 0)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])
        self.assertIsNone(self.bao.read(central.receipt_key('producer', event['eventId'])))


    def test_many_deferred_cycles_keep_only_bounded_current_scan_guard(self):
        values = []
        for number in range(96):
            event = self.event(secret=f'synthetic-deferred-secret-{number}')
            values.append(event['credential']['key'])
            self.inbox(event)
        initial = self.bao.read('manifest')
        for _ in range(128):
            result = self.worker.once()
            self.assertEqual(result['committed'], 0)
            self.assertEqual(result['deferred'], result['scanned'])
            self.assertLessEqual(len(self.worker.secrets), central.MAX_SCAN_EVENTS)
            self.assertTrue(all(secret not in json.dumps(result) for secret in values))
        self.assertEqual(self.bao.read('manifest'), initial)
        self.assertEqual(len([key for key in self.bao.values if key.startswith('inbox/')]), 96)
        self.assertFalse(any(key.startswith('coordinator-receipts/') for key in self.bao.values))

    def test_failed_cycle_drops_prior_guard_and_keeps_current_event_secret(self):
        earlier = self.event(secret='synthetic-prior-cycle-only-secret')
        self.inbox(earlier)
        self.assertEqual(self.worker.once()['deferred'], 1)
        self.assertIn(earlier['credential']['key'], self.worker.secrets)
        invalid = self.event(secret='synthetic-current-failed-cycle-secret')
        invalid['eventId'] = str(uuid.UUID(int=0))
        invalid['digest'] = '0' * 64
        self.inbox(invalid)
        before_cursor = (self.directory / 'inbox-scan.private.json').read_bytes()
        with self.assertRaisesRegex(central.Error, 'event_credential_digest_mismatch'):
            self.worker.once()
        self.assertEqual(self.worker.secrets, [invalid['credential']['key']])
        self.assertEqual((self.directory / 'inbox-scan.private.json').read_bytes(), before_cursor)
        self.assertEqual(self.bao.read('manifest')['data']['profiles'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)

