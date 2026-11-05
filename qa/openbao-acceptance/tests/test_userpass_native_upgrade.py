from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from bao_http import Response
import userpass_native_upgrade as upgrade


class UserpassUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {'status':'passed', 'build_source_commit':upgrade.LEGACY_SOURCE,
                'source_and_binary_unchanged':True, 'runner_unchanged':True,
                'candidate_source':{'source_commit':upgrade.LEGACY_SOURCE, 'source_dirty':False,
                                    'binary_sha256':upgrade.LEGACY_SHA256}}

    def test_unknown_historical_pin_cannot_run(self):
        for field in ('LEGACY_SOURCE', 'LEGACY_SHA256', 'LEGACY_RECEIPT'):
            with patch.object(upgrade, field, None):
                with self.assertRaisesRegex(ValueError, 'pin_not_available'):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())

    def test_pin_requires_exact_clean_successful_runtime_evidence(self):
        with patch.multiple(upgrade, LEGACY_SOURCE='1'*40, LEGACY_SHA256='2'*64,
                            LEGACY_RECEIPT=Path('/synthetic/unit-only')):
            upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())
            for field, value in (('status','failed'), ('build_source_commit','0'*40),
                                 ('source_and_binary_unchanged',False), ('runner_unchanged',False)):
                with self.assertRaises(ValueError):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt() | {field:value})
            for field, value in (('source_commit','0'*40), ('binary_sha256','0'*64), ('source_dirty',True), ('source_dirty',0)):
                receipt = self.receipt(); receipt['candidate_source'][field] = value
                with self.assertRaises(ValueError):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, receipt)

    def old_user(self):
        return {'token_ttl':75, 'token_max_ttl':600, 'token_num_uses':0,
                'policies':['default', 'userpass-upgrade'], 'token_policies':['default', 'userpass-upgrade']}

    def test_old_user_cannot_be_silently_zeroed_or_have_default_policy_removed(self):
        old = self.old_user()
        current = old | {'token_period':0, 'token_explicit_max_ttl':0}
        self.assertTrue(upgrade.retained_user(current, old))
        for field, value in (('token_ttl',0), ('token_max_ttl',0), ('token_period',30),
                             ('token_explicit_max_ttl',600), ('token_period',False),
                             ('policies',['userpass-upgrade']), ('unexpected',1)):
            self.assertFalse(upgrade.retained_user(current | {field:value}, old))
        self.assertFalse(upgrade.retained_user(old, old))

    def test_old_token_must_keep_captured_expiry_and_cannot_gain_invented_username(self):
        old = {'ttl':75, 'creation_time':1000, 'explicit_max_ttl':600, 'expire_time':'synthetic-expiry'}
        self.assertTrue(upgrade.retained_token(old | {'ttl':74}, old))
        for field, value in (('creation_time',1001), ('explicit_max_ttl',0), ('expire_time','changed'),
                             ('meta',{'username':'guessed'}), ('ttl',0), ('ttl',True)):
            self.assertFalse(upgrade.retained_token(old | {field:value}, old))

    def test_actual_two_pure_read_phases_have_unique_names_and_do_not_require_fake_old_metadata(self):
        class ReachedMigration(Exception):
            pass
        saved = {profile:{'user':self.old_user(), 'auth':{'client_token':'synthetic-token'},
                          'token':{'ttl':75, 'creation_time':1000}}
                 for profile in upgrade.MOUNTS}
        def request(method, path, body=None, **_kwargs):
            if '/auth/token/renew' in path:
                raise ReachedMigration
            if path == '/v1/' + upgrade.VALUE:
                return Response(200, {'data':{'data':{'synthetic':True}}})
            if '/users/' in path:
                return Response(200, {'data':self.old_user() | {'token_period':0, 'token_explicit_max_ttl':0}})
            if path == '/v1/auth/token/lookup':
                return Response(200, {'data':{'ttl':74, 'creation_time':1000}})
            return Response(200, {})
        rows = []
        with tempfile.TemporaryDirectory() as directory:
            instance = SimpleNamespace(root=Path(directory), address='https://localhost:443', token='synthetic-root',
                                       start=lambda:None, stop=lambda:None)
            with patch.object(upgrade, 'Client', return_value=SimpleNamespace(request=request)):
                trace = upgrade.Trace(instance, rows)
            with patch.object(upgrade, 'prepare_legacy', return_value=(trace, 'synthetic-key', saved)), \
                 patch.object(upgrade, 'durable_manifest', return_value='unchanged'):
                with self.assertRaises(ReachedMigration):
                    upgrade.run_upgrade(instance, Path('candidate'), Path('legacy'), rows)
        names = [row['case'] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(row['passed'] is True for row in rows))
        for phase in ('current', 'untouched_restart'):
            self.assertIn(upgrade.PREFIX + phase + '.reads_preserve_entire_store', names)

    def test_failure_statuses_are_exact_and_no_auth_can_hide_under_204(self):
        auth = {'client_token':'synthetic-token', 'accessor':'synthetic-accessor'}
        with tempfile.TemporaryDirectory() as directory:
            instance = SimpleNamespace(root=Path(directory), address='https://localhost:443', token='synthetic-root')
            for status, body in ((200, {}), (500, {}), (204, {'auth':{'client_token':'sensitive'}})):
                with patch.object(upgrade, 'Client', return_value=SimpleNamespace(
                        request=lambda *a, **k: Response(status, body))):
                    trace = upgrade.Trace(instance, [])
                with self.assertRaises(upgrade.ScenarioFailure):
                    trace.renew('deleted', auth, rejected={'self':204, 'token':204, 'accessor':500})
                self.assertNotIn('sensitive', str(trace.rows))

    def test_completeness_uses_required_phase_identity_without_hard_count(self):
        for prepare in (True, False):
            end = upgrade.PREFIX + ('legacy.plaintext_credentials_absent' if prepare else 'complete')
            names = sorted(upgrade.required_cases(prepare) - {end}) + [end]
            rows = [{'case':name, 'passed':True} for name in names]
            self.assertTrue(upgrade.complete(rows, prepare))
            extra = {'case':upgrade.PREFIX+'extra', 'passed':True}
            self.assertTrue(upgrade.complete(rows[:-1] + [extra] + rows[-1:], prepare))
            for i in range(len(rows)):
                self.assertFalse(upgrade.complete(rows[:i] + rows[i+1:], prepare), rows[i])
            for damaged in ([], rows + [rows[-1]], rows[-1:] + rows[:-1],
                            rows[:-1] + [dict(rows[-1], passed=1)], rows[:-1] + [dict(rows[-1], raw='secret')]):
                self.assertFalse(upgrade.complete(damaged, prepare))


if __name__ == '__main__':
    unittest.main()
