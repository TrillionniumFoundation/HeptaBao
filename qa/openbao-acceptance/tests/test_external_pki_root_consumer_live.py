import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3]
RUNNER=ROOT/"qa/openbao-acceptance/external_pki_root_consumer_live.py"
sys.path.insert(0,str(RUNNER.parent))
SPEC=importlib.util.spec_from_file_location("external_pki_root_contract",RUNNER)
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)

class ExternalPkiRootContractTests(unittest.TestCase):
    def rows(self):
        rows=[{"case":case,"passed":True} for case in MODULE.EXPECTED_CASES]
        for row in rows:
            if row["case"].endswith("provider_sign_exact"):
                count=0 if ".csr." in row["case"] else 3
                row.update(observed_provider_sign_entries=count,expected_provider_sign_entries=count)
        return rows

    def test_fresh_complete_trace_retains_the_original_failed_remote_binding_profile(self):
        cases=MODULE.EXPECTED_CASES
        self.assertEqual(91,len(cases));self.assertEqual(len(cases),len(set(cases)))
        self.assertEqual(85,len(MODULE.pki.EXPECTED_CASES))
        self.assertIn("official.csr.local_spki_distinct",cases)
        self.assertNotIn("official.csr.spki_matches",cases)
        self.assertIn("official.csr.spki_matches",MODULE.pki.EXPECTED_CASES)
        rows=self.rows()
        self.assertTrue(MODULE.trace_complete(rows))
        for bad in (rows[:27],rows[:-1],list(reversed(rows)),rows+[rows[-1]]):
            self.assertFalse(MODULE.trace_complete(bad))

    def test_both_native_local_csr_and_external_root_scopes_fail_closed(self):
        self.assertEqual(71,len(MODULE.ROOT_COMPARISON_CASES));self.assertEqual(20,len(MODULE.NATIVE_CSR_CASES))
        rows=self.rows()
        self.assertEqual((True,True),MODULE.scope_results(rows))
        for side in ("candidate","official"):
            for name in ("provider_sign_exact","actual_self_signature","local_spki_distinct"):
                required=side+".csr."+name
                failed=[dict(row,passed=False) if row["case"]==required else row for row in rows]
                self.assertFalse(MODULE.trace_complete(failed));self.assertEqual((True,False),MODULE.scope_results(failed))
        missing=[row for row in rows if row["case"]!="owned_processes_cleared"]
        self.assertEqual((False,True),MODULE.scope_results(missing))

    def test_actual_provider_sign_counts_require_root_three_and_each_csr_zero(self):
        rows=self.rows()
        for case,bad_counts in (("candidate.root.provider_sign_exact",(0,1,2,None)),
                ("candidate.csr.provider_sign_exact",(1,2,None)),("official.csr.provider_sign_exact",(1,2,None))):
            for bad_count in bad_counts:
                bad=[dict(row,observed_provider_sign_entries=bad_count) if row["case"]==case else row for row in rows]
                self.assertFalse(MODULE.trace_complete(bad))

    def test_native_csr_verifies_its_actual_local_key_and_refuses_provider_key_substitution(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec,ed25519
        local=ed25519.Ed25519PrivateKey.generate()
        provider=ed25519.Ed25519PrivateKey.generate()
        builder=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME,"actual.example.test")])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("actual.example.test")]),critical=False)
        csr=builder.sign(local,None)
        data={"csr":csr.public_bytes(serialization.Encoding.PEM).decode(),
            "key_id":"12345678-1234-1234-1234-123456789abc"}
        self.assertEqual((True,True,True),MODULE.pki.validate_native_local_csr(data,provider.public_key()))
        encoded=bytearray(csr.public_bytes(serialization.Encoding.DER));encoded[-1]^=1
        altered=x509.load_der_x509_csr(bytes(encoded))
        self.assertEqual((True,True,False),MODULE.pki.validate_native_local_csr(
            dict(data,csr=altered.public_bytes(serialization.Encoding.PEM).decode()),provider.public_key()))
        remote=builder.sign(provider,None)
        self.assertEqual((True,False,True),MODULE.pki.validate_native_local_csr(
            dict(data,csr=remote.public_bytes(serialization.Encoding.PEM).decode()),provider.public_key()))
        wrong_kind=builder.sign(ec.generate_private_key(ec.SECP256R1()),hashes.SHA256())
        self.assertEqual((False,True,True),MODULE.pki.validate_native_local_csr(
            dict(data,csr=wrong_kind.public_bytes(serialization.Encoding.PEM).decode()),provider.public_key()))

if __name__=="__main__":unittest.main()
