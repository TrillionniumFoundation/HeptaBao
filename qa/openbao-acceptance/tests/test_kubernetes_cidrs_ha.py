import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch
import kubernetes_cidrs_ha as fixture


class KubernetesCidrHaGuards(unittest.TestCase):
    def rows(self):
        return [{'case': fixture.PREFIX + name, 'passed': True} for name in sorted(fixture.REQUIRED_CASES)]

    def test_named_phases_and_bootstrap_cannot_be_skipped(self):
        rows = self.rows()
        inherited = sorted(fixture.REQUIRED_BOOTSTRAP)
        self.assertTrue(fixture.complete(rows, inherited))
        for index in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:index] + rows[index+1:], inherited), rows[index])
        for index in range(len(inherited)):
            self.assertFalse(fixture.complete(rows, inherited[:index] + inherited[index+1:]))
        self.assertTrue(fixture.complete(rows + [{'case': fixture.PREFIX + 'new_phase', 'passed': True}], inherited + ['new_bootstrap_check']))

    def test_duplicate_nonboolean_or_sensitive_observations_cannot_pass(self):
        rows, inherited = self.rows(), sorted(fixture.REQUIRED_BOOTSTRAP)
        self.assertFalse(fixture.complete(rows + [rows[0]], inherited))
        self.assertFalse(fixture.complete(rows, inherited + [inherited[0]]))
        self.assertFalse(fixture.complete(rows, inherited + [None]))
        for value in [False, 1, 'true', None]:
            self.assertFalse(fixture.complete(rows + [{'case': fixture.PREFIX + 'extra', 'passed': value}], inherited))
        self.assertFalse(fixture.complete(rows + [{'case': fixture.PREFIX + 'extra', 'passed': True, 'token': 'sentinel'}], inherited))
        self.assertFalse(fixture.complete([None], inherited))

    def test_real_status_without_expected_provider_count_is_not_success(self):
        for expected, calls, count in [(200, 0, 1), (403, 1, 0)]:
            reviewer = SimpleNamespace(calls=[], presented='synthetic', request_valid=True)
            def request(*args, **kwargs):
                reviewer.calls.extend(['synthetic-review'] * calls)
                return SimpleNamespace(status=expected, body={})
            trace = fixture.Trace(SimpleNamespace(request=request, last_family=4), reviewer, [])
            with self.assertRaises(fixture.ScenarioFailure):
                trace.call('provider_count', 'auth/login', expected=expected, reviews=count)
            self.assertIs(trace.rows[-1]['passed'], False)
            self.assertEqual(trace.rows[-1]['tokenreviews'], calls)

    def test_provider_failure_never_qualifies_as_ha_denial(self):
        for body in [{}, {'errors': []}, {'errors': 'HA unavailable'},
                     {'errors': ['Kubernetes TokenReview unavailable']},
                     {'errors': ['HA unavailable', 'provider rejected']}]:
            self.assertFalse(fixture.unavailable_from_ha(body))
        self.assertTrue(fixture.unavailable_from_ha({'errors': ['HA linearizable state is unavailable']}))

    def test_failure_after_complete_never_publishes_pass_or_exception_text(self):
        for interrupted in [False, True]:
            def run(binary, root, rows, inherited, diagnostics):
                rows.extend(self.rows())
                inherited.extend(sorted(fixture.REQUIRED_BOOTSTRAP))
                if interrupted:
                    raise RuntimeError('sensitive-exception-sentinel')
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'report.json'
                output.parent.chmod(0o700)
                with patch.object(sys, 'argv', [fixture.__name__, '--binary', __file__, '--output', str(output),
                                               '--build-source-commit', 'a'*40]), \
                     patch.object(fixture, 'run', side_effect=run), \
                     patch.object(fixture, 'source_identity', return_value={'binary_sha256': 'b'*64}), \
                     contextlib.redirect_stdout(io.StringIO()):
                    status = fixture.main()
                raw = output.read_text()
                report = json.loads(raw)
                self.assertEqual(status, 1 if interrupted else 0)
                self.assertEqual(report['status'], 'failed' if interrupted else 'passed')
                self.assertNotIn('sensitive-exception-sentinel', raw)


if __name__ == '__main__':
    unittest.main()
