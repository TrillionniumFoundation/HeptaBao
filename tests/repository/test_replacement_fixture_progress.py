"""Independent replacement fixtures must report failures without masking siblings."""
from pathlib import Path
import copy
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class ReplacementFixtureProgressTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / '.github/workflows/codex-openbao-replacement-ci.yml').read_text())
        self.job = self.workflow['jobs']['qualify']
        self.steps = self.job['steps']
        self.named = {s['name']: s for s in self.steps}

    def test_fixture_independence_does_not_swallow_failure(self):
        for step in self.steps:
            self.assertNotIn('continue-on-error', step)
        self.assertNotIn('continue-on-error', self.job)
        self.assertIs(self.job['strategy']['fail-fast'], False)
        self.assertIn('qualify', self.workflow['jobs']['qualification-verdict']['needs'])
        self.assertIn('always()', self.workflow['jobs']['qualification-verdict']['if'])

    def test_independent_runtime_profiles_follow_product_readiness_not_sibling_success(self):
        start = next(i for i,s in enumerate(self.steps) if s.get('id') == 'runtime_ready')
        for step in self.steps[start+1:]:
            with self.subTest(name=step['name']):
                condition = step.get('if', '')
                self.assertIn('!cancelled()', condition)
                self.assertIn("steps.runtime_ready.outcome == 'success'", condition)
                self.assertNotIn('success()', condition)
        native = self.named['Exercise actual Valkey ACL persistence and session revocation']['if']
        self.assertIn("steps.provider_packages_ready.outcome == 'success'", native)
        self.assertNotIn('oracle_ready', native)

    def assert_bound_oracle_prerequisite(self, step):
        lanes = {
            '${{ runner.temp }}/heptabao-official-oracle/bao':
                ('oracle_ready', '${{ runner.temp }}/heptabao-official-oracle/oracle-official.tar.gz'),
            '${{ runner.temp }}/heptabao-official-oracle270/bao':
                ('oracle270_ready', '${{ runner.temp }}/heptabao-official-oracle270/oracle-official.tar.gz'),
        }
        binary = step['env']['HB_ORACLE_BINARY']
        self.assertIn(binary, lanes)
        prerequisite, archive = lanes[binary]
        self.assertIn(f"steps.{prerequisite}.outcome == 'success'", step['if'])
        self.assertEqual(step['env'].get('HB_ORACLE_ARCHIVE'), archive)
        if prerequisite == 'oracle270_ready':
            self.assertIn('--oracle-version 2.7.0', step['run'])

    def test_oracle_lanes_cannot_swap_artifacts_or_readiness_requirements(self):
        for original in self.steps:
            if 'HB_ORACLE_BINARY' not in original.get('env', {}):
                continue
            self.assert_bound_oracle_prerequisite(original)
            changed = copy.deepcopy(original)
            changed['env']['HB_ORACLE_ARCHIVE'] = '/unverified/archive.tar.gz'
            with self.subTest(name=original['name'], change='archive'), self.assertRaises(AssertionError):
                self.assert_bound_oracle_prerequisite(changed)
            changed = copy.deepcopy(original)
            changed['if'] = "${{ !cancelled() && steps.runtime_ready.outcome == 'success' }}"
            with self.subTest(name=original['name'], change='readiness'), self.assertRaises(AssertionError):
                self.assert_bound_oracle_prerequisite(changed)
            changed = copy.deepcopy(original)
            changed['env']['HB_ORACLE_BINARY'] = '/unverified/bao'
            with self.subTest(name=original['name'], change='binary'), self.assertRaises(AssertionError):
                self.assert_bound_oracle_prerequisite(changed)

    def test_external_prerequisites_cannot_be_skipped_or_substituted(self):
        for step in self.steps:
            if 'HB_ORACLE_BINARY' in step.get('env', {}):
                self.assert_bound_oracle_prerequisite(step)
        for name in ('Exercise PostgreSQL physical storage transactions and crash recovery',
                     'Exercise PostgreSQL durable backend and server initialization recovery',
                     'Exercise actual PostgreSQL SQL and active-session revocation'):
            self.assertIn("steps.provider_packages_ready.outcome == 'success'",self.named[name]['if'])
        name = 'Compare operational Agent and Proxy behavior with official OpenBao'
        self.assertIn("steps.runtime_clients.outcome == 'success'", self.named[name]['if'])
        name = 'Exercise lower-capacity HA election and committed-state recovery'
        self.assertIn("steps.capacity_ready.outcome == 'success'", self.named[name]['if'])

    def test_rolling_upgrade_keeps_real_pr_base_requirement(self):
        step = self.named['Exercise exact-base to candidate HA rolling upgrade']
        self.assertIn("github.event_name == 'pull_request'", step['if'])
        self.assertIn('PR_BASE',step['run'])


if __name__ == '__main__':
    unittest.main()
