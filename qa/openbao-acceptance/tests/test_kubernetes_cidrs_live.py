from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from bao_http import Response
from core_isolation import ScenarioFailure
from kubernetes_cidrs_live import DEVIATIONS, MILESTONES, Trace, complete, deviations_complete, scan_storage


class KubernetesCidrsGuards(unittest.TestCase):
    def valid_rows(self):
        names = sorted(MILESTONES - {"complete"}) + ["complete"]
        return [{"case":"kubernetes_cidrs." + name, "passed":True} for name in names]

    def test_every_semantic_milestone_is_required_without_a_fixed_count(self):
        rows = self.valid_rows()
        self.assertTrue(complete(rows))
        self.assertTrue(complete(rows[:-1] + [{"case":"kubernetes_cidrs.extra", "passed":True}] + rows[-1:]))
        for index in range(len(rows)):
            self.assertFalse(complete(rows[:index] + rows[index + 1:]), rows[index])
        self.assertFalse(complete([]))
        self.assertFalse(complete(rows + [rows[-1]]))
        self.assertFalse(complete(rows[:-1] + [dict(rows[-1], passed=1)]))
        self.assertFalse(complete(rows[:-1] + [{"case":"kubernetes_cidrs.extra", "passed":False}] + rows[-1:]))
        self.assertFalse(complete([None]))

    def test_observation_schema_rejects_raw_or_credential_values(self):
        rows = self.valid_rows()
        self.assertFalse(complete(rows[:-1] + [{"case":"kubernetes_cidrs.extra", "passed":True, "raw":"sensitive"}] + rows[-1:]))
        trace = Trace(None, None, None, [])
        with self.assertRaises(ValueError):
            trace.check("safe", True, raw="sensitive")
        self.assertEqual(trace.rows, [])

    def test_denied_login_cannot_pass_after_contacting_tokenreview(self):
        reviewer = SimpleNamespace(calls=[], request_valid=True)
        def request(*_args, **_kwargs):
            reviewer.calls.append("/apis/authentication.k8s.io/v1/tokenreviews")
            return Response(403, {})
        client = SimpleNamespace(request=request, last_family=4)
        trace = Trace(client, reviewer, None, [])
        with self.assertRaises(ScenarioFailure):
            trace.call("denied.login", "POST", "auth/kubernetes/login", {}, status=403, reviews=0)
        self.assertIs(trace.rows[-1]["passed"], False)
        self.assertEqual(trace.rows[-1]["tokenreview_count"], 1)

    def test_allowed_login_requires_exact_single_valid_provider_request(self):
        for amount, valid in ((0,True), (2,True), (1,False)):
            reviewer = SimpleNamespace(calls=[], request_valid=valid)
            def request(*_args, **_kwargs):
                reviewer.calls.extend(["review"] * amount)
                return Response(200, {"auth":{}})
            trace = Trace(SimpleNamespace(request=request, last_family=4), reviewer, None, [])
            with self.assertRaises(ScenarioFailure):
                trace.call("allowed.login", "POST", "auth/kubernetes/login", {}, reviews=1)
            self.assertIs(trace.rows[-1]["passed"], False)

    def test_profile_deviations_cannot_be_omitted_or_reported_as_parity(self):
        rows = [{"case":"kubernetes_cidrs." + label + suffix, "passed":True}
                for label in DEVIATIONS for suffix in
                (".before", ".write", ".read", ".readback", ".login", ".login.no_authority", ".restore")]
        self.assertTrue(deviations_complete(rows))
        for index in range(len(rows)):
            self.assertFalse(deviations_complete(rows[:index] + rows[index + 1:]))
        self.assertFalse(deviations_complete(rows[:-1] + [dict(rows[-1], passed=False)]))
        self.assertFalse(deviations_complete(rows[:-1] + [dict(rows[-1], raw="secret")]))
        self.assertFalse(deviations_complete([]))
        self.assertTrue(all(x["oracle_status"] != x["candidate_status"] for x in DEVIATIONS.values()))

    def test_plaintext_scan_covers_store_and_output_but_not_private_control_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "data" / "encrypted").write_bytes(b"opaque")
            (root / "server.log").write_bytes(b"safe")
            (root / "audit.jsonl").write_bytes(b"safe")
            for name in ("root.token", "unseal.key", "server.json", "tls.key"):
                (root / name).write_text("sentinel-secret")
            self.assertTrue(scan_storage(root, ["sentinel-secret"]))
            for path in (root / "data" / "encrypted", root / "server.log", root / "audit.jsonl"):
                before = path.read_bytes()
                path.write_text("sentinel-secret")
                self.assertFalse(scan_storage(root, ["sentinel-secret"]))
                path.write_bytes(before)
            self.assertFalse(scan_storage(root, []))
            self.assertFalse(scan_storage(root, [""]))
            (root / "data" / "encrypted").unlink()
            self.assertFalse(scan_storage(root, ["sentinel-secret"]))


if __name__ == "__main__":
    unittest.main()
