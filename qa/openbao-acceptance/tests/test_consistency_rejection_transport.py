"""Split-record negative requests keep exact status and private failures."""
import http.client
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import consistency_headers_live as profile

class RejectionTransportTests(unittest.TestCase):
    def test_arbitrary_status_line_is_not_reflected_into_failure_evidence(self):
        private="synthetic-status-line-canary"
        with patch.object(profile,"call",side_effect=http.client.BadStatusLine(private)):
            with self.assertRaises(profile.FixtureError) as captured:
                profile.Trace().request("write_rejected",None,"POST","fixture",400)
        self.assertEqual(str(captured.exception),"write_rejected.BadStatusLine")
        self.assertNotIn(private,str(captured.exception))

    def test_all_split_records_and_unchanged_state_checks_are_mandatory(self):
        for label in ["one_ms","ten_ms","twenty_ms"]:
            self.assertIn("split_body_"+label,profile.COMMON_REQUIRED)
            self.assertIn("split_absent_"+label,profile.COMMON_REQUIRED)
        self.assertIn("write_rejected",profile.COMMON_REQUIRED)
        self.assertIn("finite_unchanged",profile.COMMON_REQUIRED)
        self.assertEqual(len(profile.COMMON_REQUIRED),58)

if __name__=="__main__":unittest.main()
