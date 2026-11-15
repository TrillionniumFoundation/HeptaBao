"""Product online KV versioning uses the shared credential and TLS boundary."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from heptabao import cli,kv_cli
from heptabao.transport import BaoError,Response
class KVEnableVersioningTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.token=Path(self.tmp.name)/"token";self.token.write_text("synthetic-upgrade-bearer");self.token.chmod(0o600)
        self.base=["-address=https://localhost:8200","-ca-cert=unused.crt","-token-file="+str(self.token)]
    def run_cli(self,arguments,response=None,environment=None):
        out,err=io.StringIO(),io.StringIO()
        with patch.dict(os.environ,environment or {},clear=True),patch.object(kv_cli,"Client") as factory,contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            factory.return_value.request.return_value=response or Response(204,{})
            code=cli.main(["kv","enable-versioning"]+arguments)
        return code,out.getvalue(),err.getvalue(),factory
    def test_upgrade_targets_the_mount_tune_without_secret_discovery(self):
        code,out,err,factory=self.run_cli(self.base+["team/raw/"] ,Response(200,{"warnings":["completed conversion"]}))
        self.assertEqual((code,out,err),(0,"Success! Tuned the secrets engine at: team/raw/\n",""))
        self.assertEqual(factory.return_value.request.call_count,1)
        self.assertEqual(factory.return_value.request.call_args.args,("POST","/v1/sys/mounts/team/raw/tune",{"options":{"version":"2"}}))
        self.assertNotIn("synthetic-upgrade-bearer",out+err)
    def test_repeat_accepts_empty_204_and_preserves_output_format_flag(self):
        for fmt in ["table","json","yaml"]:
            with self.subTest(fmt=fmt):
                code,out,err,factory=self.run_cli(self.base+["-format="+fmt,"raw"])
                self.assertEqual((code,out,err),(0,"Success! Tuned the secrets engine at: raw/\n",""))
                self.assertEqual(factory.return_value.request.call_count,1)
    def test_mount_field_and_data_flags_are_not_accepted_for_mount_only_command(self):
        for flag in ["-mount=raw","-field=value","-cas=0"]:
            with self.subTest(flag=flag):
                code,out,err,factory=self.run_cli(self.base+[flag,"raw"])
                self.assertEqual(code,1);self.assertEqual(out,"");factory.assert_not_called()
    def test_local_paths_and_namespace_validation_precede_tls_and_mutation(self):
        for path in ["raw//","/raw","raw/../other","raw?version=2","raw%2fother","raw\nother"]:
            with self.subTest(path=path):
                code,out,err,factory=self.run_cli(self.base+[path]);self.assertEqual(code,1);self.assertEqual(out,"");factory.assert_not_called()
        code,_,_,factory=self.run_cli(self.base+["-namespace=team/../other","raw"]);self.assertEqual(code,1);factory.assert_not_called()
    def test_namespace_and_bao_environment_use_shared_client_configuration(self):
        env={"BAO_ADDR":"https://localhost:8200","BAO_CACERT":"unused.crt","BAO_TOKEN":"synthetic-upgrade-bearer","BAO_NAMESPACE":"team/","BAO_CLIENT_TIMEOUT":"2s"}
        code,_,_,factory=self.run_cli(["raw"],environment=env);self.assertEqual(code,0)
        self.assertEqual(factory.call_args.args,("https://localhost:8200","unused.crt","synthetic-upgrade-bearer","team/",2))
    def test_owner_only_token_failure_cannot_attempt_upgrade(self):
        self.token.chmod(0o644)
        code,out,err,factory=self.run_cli(self.base+["raw"]);self.assertEqual(code,1);self.assertEqual(out,"");factory.assert_not_called()
        self.assertNotIn("synthetic-upgrade-bearer",err)
    def test_remote_denial_is_exit_two_without_echo_or_replay(self):
        code,out,err,factory=self.run_cli(self.base+["raw"],Response(403,{"errors":["private-error-synthetic-upgrade-bearer"]}))
        self.assertEqual(code,2);self.assertEqual(out,"");self.assertEqual(factory.return_value.request.call_count,1)
        self.assertNotIn("private-error",err);self.assertNotIn("synthetic-upgrade-bearer",err)
        self.assertEqual(json.loads(err)["http_status"],403)
        self.assertTrue(json.loads(err)["response_received"]);self.assertFalse(json.loads(err)["automatic_retry"])
if __name__=="__main__":unittest.main()
