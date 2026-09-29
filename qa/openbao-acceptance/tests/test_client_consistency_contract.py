from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client_consistency_live as profile
from online_evidence import complete_checks

class ClientConsistencyContractTests(unittest.TestCase):
    def test_fixed_denominators_reject_prefixes_duplicates_and_failures(self):
        for required,count in ((profile.COMMON,35),(profile.HA_REQUIRED,28),(profile.PROXY_REQUIRED,14)):
            self.assertEqual(len(required),count)
            rows=[{'case':name,'passed':True} for name in sorted(required)]
            self.assertTrue(complete_checks(rows,count,required_cases=required))
            self.assertFalse(complete_checks(rows[:-1],count,required_cases=required))
            self.assertFalse(complete_checks(rows+rows[:1],count,required_cases=required))
            rows[0]['passed']=False
            self.assertFalse(complete_checks(rows,count,required_cases=required))

    def test_duplicate_index_refused_before_constructing_transport(self):
        t=profile.ClientTrace(Path('/unused/ca'))
        with patch.object(profile,'Client') as client:
            with self.assertRaises(profile.BaoError):
                t.invoke(None,'GET','unused',headers=[('X-Vault-Index',''),('X-Vault-Index','')])
            client.assert_not_called()

    def test_native_client_profile_is_required_alongside_native_server(self):
        root=Path(__file__).resolve().parents[3]
        rows=(root/'.github/workflows/codex-openbao-replacement-ci.yml').read_text().splitlines()
        line=next(row for row in rows if 'for profile in core_isolation' in row and 'consistency_headers_live' in row)
        self.assertIn('client_consistency_live',line.split())
        self.assertIn('consistency_headers_live',line.split())

if __name__=='__main__':unittest.main()
