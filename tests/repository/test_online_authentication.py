"""Guard actual runtime ownership, format and non-admission of new profiles."""
from pathlib import Path
import json
import re
import unittest
ROOT=Path(__file__).resolve().parents[2]
SERVER=ROOT/'crates/heptabao-server/src'
class OnlineAuthenticationTests(unittest.TestCase):
    def test_callback_consumption_commit_precedes_code_exchange(self):
        # Field-level cfg(test) attributes are not the start of the test module.
        # Keep the durable callback ordering checks on the complete runtime path.
        source=(SERVER/'service_online_auth.rs').read_text()
        boundary=re.search(r'(?m)^#\[cfg\(test\)\]\nmod tests \{', source)
        self.assertIsNotNone(boundary)
        text=source[:boundary.start()]
        consume=text.index('.consume_oidc(');commit=text.index('self.commit_state(&state)',consume)
        publish=text.index('self.state = Some(state)',commit)
        plan=text.index('OnlineAuthEffect::OidcCallback {',publish)
        self.assertLess(consume,commit);self.assertLess(commit,publish);self.assertLess(publish,plan)
        # The code exchange is deliberately split out of the Service writer:
        # callback consumption is durable before the external plan can execute.
        execute=text.index('impl OnlineAuthEffectPlan')
        exchange=text.index('.execute(namespace, *now, *started, &self.outbound, deadline)',execute)
        self.assertLess(execute,exchange)
        self.assertLess(text.index('wrap_ttl_seconds.is_some()'),consume)
        self.assertIn('retry_allowed',text)
    def test_runtime_intercept_follows_existing_admitted_request(self):
        text=(SERVER/'service.rs').read_text()
        self.assertIn('self.online_login(&admitted, &request)',text)
        self.assertIn('mod online_auth;',text)
        self.assertIn('check_online_enrollment(namespace, path, &self.outbound)',text)
        auth=(SERVER/'auth.rs').read_text()
        self.assertIn('mod kubernetes;',auth);self.assertIn('mod oidc;',auth)
    def test_older_formats_cannot_silently_store_new_auth(self):
        text=(SERVER/'service_identity.rs').read_text()
        self.assertIn('has_online_auth_state()',text)
        self.assertRegex(text,r'self\.schema\s*<\s*5')
        self.assertIn('validate_online_auth()',text)
    def test_oidc_code_profile_does_not_weaken_static_jwt_requirement(self):
        text=(SERVER/'federated_auth.rs').read_text()
        self.assertIn('verify_oidc',text)
        self.assertIn('at_hash',text);self.assertIn('c_hash',text);self.assertIn('azp',text)
        text=(SERVER/'auth_oidc.rs').read_text()
        for value in ('code_challenge_method=S256','client_proof_hash','client_secret_basic','Ok(None)','clock'):
            self.assertIn(value,text)
    def test_native_client_and_three_profiles_remain_mandatory(self):
        text=(ROOT/'.github/workflows/codex-openbao-replacement-ci.yml').read_text()
        for file in ('kubernetes_online.py','oidc_code_live.py','online_auth_ha.py'):
            self.assertIn(file,text);self.assertTrue((ROOT/'qa/openbao-acceptance'/file).is_file())
        self.assertIn('heptabao-oidc-login',(ROOT/'clients/python/pyproject.toml').read_text())
        self.assertIn('oidc_login.py',(ROOT/'clients/python/README.md').read_text())
    def test_original_surface_states_are_not_promoted_by_new_profiles(self):
        doc=json.loads((ROOT/'planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json').read_text())
        self.assertNotIn('"full_surface_verified": true',json.dumps(doc))
        self.assertNotIn('"independently_admitted": true',json.dumps(doc))
        source=json.loads((ROOT/'qa/openbao-acceptance/complete_surface_corpus_v1.json').read_text())
        # The existing denominator validator owns exact row/case coverage.
        self.assertIsInstance(source,dict)
if __name__=='__main__':unittest.main()
