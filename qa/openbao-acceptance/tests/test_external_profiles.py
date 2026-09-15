"""Missing real-provider execution cannot be reclassified as synthetic success."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from external_tls_fixtures import PgWireFixture
from remote_jwks_compare import scenarios
from bao_http import Response

QA = Path(__file__).resolve().parents[1]

class FailedHttp:
    def request(self, *args, **kwargs):
        return Response(503, {"errors":["private-response-sentinel"]})

class Issuer:
    origin = "https://localhost:443"
    documents = {}

class ExternalProfileTests(unittest.TestCase):
    def run_missing_gate(self, directory=None):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)/"receipt.json"
            command = [sys.executable, str(QA/"postgres_live.py"),
                       "--binary", "/nonexistent-not-executed", "--output", str(out)]
            if directory is not None: command += ["--postgres-bin", directory]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 77)
            report = json.loads(out.read_text())
            self.assertEqual(report["status"], "blocked_prerequisite")
            self.assertIs(report["real_postgresql_executed"], False)
            self.assertIs(report["provider_sql_executed"], False)
            self.assertIs(report["independent_qualification"], False)
            self.assertEqual(report["check_count"], 0)
            self.assertEqual(report["checks"], [])
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
    def test_missing_postgres_is_blocked_not_passed(self): self.run_missing_gate()
    def test_empty_pg_installation_does_not_use_a_model(self):
        with tempfile.TemporaryDirectory() as path: self.run_missing_gate(path)
    def test_existing_receipt_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as path:
            out=Path(path)/"receipt.json";out.write_text("preserve")
            result=subprocess.run([sys.executable,str(QA/"postgres_live.py"),"--binary","/none","--output",str(out)],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertEqual(out.read_text(),"preserve")
    def test_failed_remote_comparison_retains_only_safe_case(self):
        rows=[]
        with self.assertRaisesRegex(RuntimeError,"^direct.mount$"):
            scenarios(FailedHttp(),Issuer(),"test CA",False,rows)
        self.assertEqual(rows,[{"case":"direct.mount","passed":False}])
        self.assertNotIn("private-response-sentinel",json.dumps(rows))
    def model(self):
        provider=object.__new__(PgWireFixture);provider.rows={};provider.events=[]
        return provider
    def params(self):
        return ["hb1:"+"a"*64,"hbp_"+"b"*32,"1","issue","4000000000","app_reader","c"*64,"d"*64]
    def test_model_same_sequence_requires_the_entire_payload(self):
        m=self.model();p=self.params();first=m.apply(p);self.assertIsInstance(first,dict)
        self.assertEqual(m.apply(p),first)
        for offset,value in [(4,"4000000001"),(6,"f"*64),(3,"renew")]:
            changed=list(p);changed[offset]=value
            self.assertEqual(m.apply(changed),"ERROR")
        self.assertEqual(m.rows[p[0]],first)
    def test_model_tombstone_rejects_delayed_issue_and_renew(self):
        m=self.model();p=self.params();m.apply(p)
        revoke=list(p);revoke[2:5]=["3","revoke","0"];revoke[6]="";revoke[7]="e"*64
        result=m.apply(revoke);self.assertIs(result["login"],False)
        self.assertEqual(m.apply(p),"ERROR")
        renew=list(p);renew[2:5]=["4","renew","4000000001"];renew[6]=""
        self.assertEqual(m.apply(renew),"ERROR")
    def test_model_missing_issue_can_be_cancelled_without_credentials(self):
        m=self.model();p=self.params();p[2:5]=["2","revoke","0"];p[6]=""
        result=m.apply(p);self.assertIs(result["login"],False);self.assertEqual(result["test_password"],"")

if __name__ == "__main__": unittest.main()
