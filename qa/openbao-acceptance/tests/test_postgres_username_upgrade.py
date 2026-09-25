"""Retain the deployed PostgreSQL contract and narrowly scoped recovery upgrade."""
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def function(sql, name):
    match = re.search(
        r"CREATE (?:OR REPLACE )?FUNCTION heptabao_provider\."
        + name + r"\(.*?END \$\$;", sql, re.S)
    if match is None:
        raise AssertionError("missing provider function: " + name)
    return match.group(0).replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION")


class PostgreSQLUsernameUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.current = (ROOT / 'bootstrap/postgresql/provider.sql').read_text()
        self.upgrade = (ROOT / 'bootstrap/postgresql/upgrade_v2_username_recovery.sql').read_text()
        self.legacy = (ROOT / 'qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql').read_bytes()

    def test_historical_contract_is_exact_not_a_rewritten_baseline(self):
        self.assertEqual(hashlib.sha256(self.legacy).hexdigest(),
            'c0422f3dda8de5ae8921f875859c858259264a2a92bca24701057f961398fcf6')
        self.assertEqual(self.legacy.count(b"p_name !~ '^hbp_[0-9a-f]{32}$'"), 3)

    def test_upgrade_matches_fresh_functions_without_another_semantic_dialect(self):
        for name in ('apply', 'retire', 'retired'):
            with self.subTest(name=name):
                self.assertEqual(function(self.current, name), function(self.upgrade, name))
        self.assertEqual(self.upgrade.count('CREATE OR REPLACE FUNCTION'), 3)

    def test_short_username_exception_is_only_for_cleanup(self):
        apply = function(self.current, 'apply')
        self.assertIn("p_action <> 'revoke' AND p_name !~ '^hbp_[0-9a-f]{32}$'", apply)
        for name in ('apply', 'retire', 'retired'):
            self.assertIn("p_name !~ '^hbp_([0-9a-f]{28}|[0-9a-f]{32})$'",
                          function(self.current, name))
        self.assertIn("provider global fence rejected stale operation", apply)
        self.assertIn("unowned role collision", apply)
        self.assertIn("provider role identity or ownership drift", apply)

    def test_upgrade_retains_existing_owner_and_acl_without_data_migration(self):
        sql = re.sub(r'--[^\n]*', '', self.upgrade)
        self.assertTrue(sql.strip().startswith('BEGIN;'))
        self.assertTrue(sql.strip().endswith('COMMIT;'))
        for forbidden in ('DROP FUNCTION', 'DROP TABLE', 'ALTER TABLE', 'TRUNCATE',
                          'CREATE TABLE', 'GRANT EXECUTE', 'REVOKE ALL'):
            self.assertNotIn(forbidden, sql)
        self.assertEqual(sql.count('LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog'), 3)
        self.assertIn("heptabao_provider.protocol() IS DISTINCT FROM 'heptabao-postgresql-provider-v2'", sql)
        self.assertEqual(sql.count('to_regprocedure('), 3)
        self.assertIn("SET LOCAL lock_timeout = '5s'", sql)
        self.assertIn("SET LOCAL statement_timeout = '30s'", sql)

    def test_real_profile_checks_old_install_and_post_upgrade_authority(self):
        source = (ROOT / 'qa/openbao-acceptance/postgres_live.py').read_text()
        for check in ('native_username_matches_deployed_v2_contract',
                      'historical_short_identity_can_be_revoked',
                      'historical_short_identity_can_be_retired',
                      'manager_cannot_upgrade_provider_functions',
                      'username_upgrade_preserves_function_owners_and_grants',
                      'username_upgrade_preserves_existing_live_credential',
                      'historical_cleanup_rejects_unowned_short_role',
                      'upgraded_v2_still_rejects_short_issuance'):
            self.assertIn(check, source)
        self.assertIn('pg.install(legacy)', source)


if __name__ == '__main__':
    unittest.main()
