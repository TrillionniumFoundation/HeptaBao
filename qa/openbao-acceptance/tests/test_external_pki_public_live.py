import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import patch
import urllib.error
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/openbao-acceptance/external_pki_public_live.py"
sys.path.insert(0, str(RUNNER.parent))
SPEC = importlib.util.spec_from_file_location("external_pki_public_contract", RUNNER)
q = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(q)


class PublicPkiContractTests(unittest.TestCase):
    def rows(self, expected=q.EXPECTED_CASES):
        rows = [{"case": case, "passed": True} for case in expected]
        for row in rows:
            case = row["case"]
            if case in q.PUBLIC_CASES or case in q.RESTART_CASES:
                route = next(route for route in q.ROUTES if route[0] == case.rsplit(".", 1)[1])
                row.update(status=200, content_type="application/json" if route[3] == "json" else route[3],
                    public_material_valid=True, exact_response_shape=True, private_fields_absent=True,
                    audit_request_delta=1, audit_response_delta=1, observed_provider_sign_entries=0)
            if case.endswith("sign_exact"):
                count = 3 if case.endswith("root_sign_exact") else 1 if case.endswith("leaf_sign_exact") else 2
                row.update(observed_provider_sign_entries=count, expected_provider_sign_entries=count)
            if ".anonymous_denied." in case or case.startswith(("candidate.owner_revoked_", "candidate.owner_restart_")) and not case.endswith("health"):
                row.update(status=403 if ".anonymous_denied." in case else 503,
                    private_fields_absent=True, observed_provider_sign_entries=0)
        return rows

    def test_complete_public_matrix_and_native_safety_are_separate_fixed_traces(self):
        self.assertEqual(17, len(q.ROUTES)); self.assertEqual(6, len(q.TOKEN_MODES))
        self.assertEqual(204, len(q.PUBLIC_CASES)); self.assertEqual(34, len(q.RESTART_CASES))
        self.assertEqual(len(q.EXPECTED_CASES), len(set(q.EXPECTED_CASES)))
        self.assertTrue(q.trace_complete(self.rows()))
        oracle = self.rows(q.ORACLE_EXPECTED_CASES)
        self.assertTrue(q.trace_complete(oracle, q.ORACLE_EXPECTED_CASES))
        self.assertFalse(q.trace_complete(oracle))
        self.assertTrue(all(row["case"] not in q.NATIVE_OWNER_CASES for row in oracle))
        rows = self.rows()
        for bad in (rows[:-1], rows[:25], list(reversed(rows)), rows + [rows[-1]]):
            self.assertFalse(q.trace_complete(bad))
        rows[45]["passed"] = False
        self.assertFalse(q.trace_complete(rows))

    def test_public_rows_require_exact_material_shape_audit_and_zero_sign(self):
        rows = self.rows(); case = q.PUBLIC_CASES[0]
        for mutation in ({"status":403}, {"content_type":"text/plain"}, {"public_material_valid":False},
                {"exact_response_shape":False}, {"private_fields_absent":False}, {"audit_request_delta":0},
                {"audit_request_delta":True}, {"audit_response_delta":2}, {"observed_provider_sign_entries":1},
                {"observed_provider_sign_entries":False}):
            bad = [dict(row, **mutation) if row["case"] == case else row for row in rows]
            self.assertFalse(q.trace_complete(bad))
        for field in q.PUBLIC_REQUIRED_FIELDS:
            bad = copy.deepcopy(rows); next(row for row in bad if row["case"] == case).pop(field)
            self.assertFalse(q.trace_complete(bad))

    def test_sensitive_negative_and_provider_counts_cannot_accept_union(self):
        rows = self.rows()
        for case, mutation in (("candidate.root_sign_exact", {"observed_provider_sign_entries":2}),
                ("official.revoke_sign_exact", {"observed_provider_sign_entries":3}),
                ("candidate.owner_leaf_sign_exact", {"observed_provider_sign_entries":True}),
                ("candidate.anonymous_denied.issue", {"status":200}),
                ("candidate.owner_revoked_full", {"status":200}),
                ("candidate.owner_restart_delta", {"observed_provider_sign_entries":1})):
            self.assertFalse(q.trace_complete([dict(row, **mutation) if row["case"] == case else row for row in rows]))

    def test_public_request_distinguishes_absent_and_empty_header_and_never_retries(self):
        class Response:
            status = 200; headers = {"Content-Type":"application/pkix-cert"}
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self, bound): self.bound = bound; return b"synthetic-public-bytes"
        class Opener:
            def __init__(self): self.calls = []
            def open(self, request, **kwargs): self.calls.append((request, kwargs)); return Response()
        class Client: address = "https://127.0.0.1:1234"; _opener = Opener()
        client = Client()
        q.public_request(client, "LIST", "issuers", None)
        q.public_request(client, "GET", "cert/ca", "")
        first, second = client._opener.calls
        self.assertFalse(first[0].has_header("X-vault-token"))
        self.assertTrue(second[0].has_header("X-vault-token"))
        self.assertEqual("", second[0].get_header("X-vault-token"))
        self.assertEqual(2, first[1]["timeout"]); self.assertEqual(2, second[1]["timeout"])
        self.assertEqual("LIST", first[0].get_method())
        with patch.object(client._opener, "open", side_effect=urllib.error.URLError(ConnectionRefusedError())) as transport:
            with self.assertRaises(urllib.error.URLError): q.public_request(client,"GET","cert/ca",None)
            self.assertEqual(1, transport.call_count)

    def test_startup_bridge_exposes_only_original_health_transport_and_preserves_tls_error(self):
        class Instance:
            def __init__(self,binary,root): self.root=Path(root); self.address="https://127.0.0.1:1234"; self.token=""
        class Smoke: pass
        Smoke.Instance = Instance
        native = q.bounded_native_instance(Smoke,Path("binary"),Path("private"))
        causes = (urllib.error.URLError(ConnectionRefusedError()), urllib.error.URLError(ssl.SSLCertVerificationError()), ssl.SSLCertVerificationError())
        for cause in causes:
            def fail(*args,**kwargs):
                try: raise cause
                except BaseException: raise q.BaoError("transport_read_failed")
            with patch.object(q,"Client") as client:
                client.return_value.request.side_effect=fail
                with self.assertRaises(type(cause)) as caught: native.call("GET","sys/health")
                self.assertIs(cause,caught.exception); self.assertEqual(2,client.call_args.kwargs["timeout"])
                self.assertEqual(1,client.return_value.request.call_count)
                for method,path in (("POST","sys/unseal"),("GET","pki/cert/ca")):
                    with self.assertRaises(q.BaoError): native.call(method,path,{})

    def fixture(self):
        key = ed25519.Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Synthetic Public Fixture")])
        certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(17).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).sign(key,None)
        der = certificate.public_bytes(serialization.Encoding.DER)
        document={"root_pem":certificate.public_bytes(serialization.Encoding.PEM).decode(),"leaf_pem":certificate.public_bytes(serialization.Encoding.PEM).decode(),"ca_der":der,"leaf_der":der,"issuer_id":"synthetic-issuer","key_id":"synthetic-key",
            "root_serial":"11","serial_int":17,"revocation_time":100,"crls":{}}
        return key, certificate, document

    def test_public_schema_binds_real_der_issuer_ids_chain_types_and_revocation_clock(self):
        key, certificate, document = self.fixture()
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        route = next(route for route in q.ROUTES if route[0] == "leaf_json")
        body={"data":{"certificate":pem[:-1],"issuer_id":"synthetic-issuer","revocation_time":100,"revocation_time_rfc3339":"1970-01-01T00:01:40Z"}}
        self.assertTrue(all(q.material_predicates(route,json.dumps(body).encode(),document,key.public_key())))
        for mutation in ({"issuer_id":"different"},{"revocation_time":0},{"revocation_time_rfc3339":""},{"private_key":"never-record"}):
            changed={"data":dict(body["data"],**mutation)}
            self.assertFalse(all(q.material_predicates(route,json.dumps(changed).encode(),document,key.public_key())))
        route=next(route for route in q.ROUTES if route[0]=="chain_json")
        data={"certificate":pem[:-1],"ca_chain":pem[:-1],"revocation_time":0,"revocation_time_rfc3339":""}
        self.assertTrue(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))
        self.assertFalse(all(q.material_predicates(route,json.dumps({"data":dict(data,ca_chain=[pem])}).encode(),document,key.public_key())))
        route=next(route for route in q.ROUTES if route[0]=="issuers_list")
        data={"keys":["synthetic-issuer"],"key_info":{"synthetic-issuer":{"is_default":True,"issuer_name":"","key_id":"synthetic-key","serial_number":"11"}}}
        self.assertTrue(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))
        data["key_info"]["synthetic-issuer"]["key_id"]="different"
        self.assertFalse(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))

    def test_revocation_clock_binds_nanosecond_rfc3339_to_exact_integer_utc_floor(self):
        key, certificate, document = self.fixture()
        route = next(route for route in q.ROUTES if route[0] == "leaf_json")
        data = {"certificate":document["leaf_pem"][:-1],"issuer_id":document["issuer_id"],
            "revocation_time":100,"revocation_time_rfc3339":""}
        for rfc in ("1970-01-01T00:01:40Z", "1970-01-01T00:01:40.123456789Z",
                "1970-01-01T00:01:40.999999999Z", "1970-01-01T08:01:40.123+08:00"):
            self.assertTrue(q.revocation_clock_matches(rfc,100))
            data["revocation_time_rfc3339"] = rfc
            self.assertTrue(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))
            self.assertFalse(q.revocation_clock_matches(rfc,99))
            self.assertFalse(q.revocation_clock_matches(rfc,101))
        for bad in (None, True, 100, "", "1970-01-01T00:01:40", "1970-01-01T00:01:40.1234567890Z",
                "1970-01-01T00:01:41.000000001Z", "1970-02-30T00:01:40Z", "1970-01-01T24:01:40Z",
                "1970-01-01T00:01:40+00:60", "1970-01-01T00:01:40+24:00", "1970-01-01T00:01:40Z\n",
                "1970-01-01T00:01:40.Z", "1970-01-01T00:01:40,1Z", "1970-01-01T00:01:40.١Z"):
            self.assertFalse(q.revocation_clock_matches(bad,100))
        for seconds in (True, False, 100.0, "100", None):
            self.assertFalse(q.revocation_clock_matches("1970-01-01T00:01:40Z",seconds))
        self.assertTrue(q.revocation_clock_matches("",0))
        self.assertFalse(q.revocation_clock_matches("1970-01-01T00:00:00Z",0))
        self.assertTrue(q.revocation_clock_matches("1969-12-31T23:59:59.999999999Z",-1))

    def test_raw_certificate_pem_requires_the_pinned_endpoint_format(self):
        key, certificate, document = self.fixture()
        canonical = certificate.public_bytes(serialization.Encoding.PEM)
        for name in ("leaf_pem", "ca_pem"):
            route = next(route for route in q.ROUTES if route[0] == name)
            self.assertTrue(all(q.material_predicates(route,canonical[:-1],document,key.public_key())))
            for bad in (canonical, canonical+b"\n", canonical[:-2]):
                try: predicates = q.material_predicates(route,bad,document,key.public_key())
                except ValueError: continue
                self.assertFalse(all(predicates))
        route = next(route for route in q.ROUTES if route[0] == "chain_pem")
        self.assertTrue(all(q.material_predicates(route,canonical[:-1],document,key.public_key())))
        self.assertFalse(all(q.material_predicates(route,canonical,document,key.public_key())))

    def test_pem_diagnostics_record_only_exact_format_predicates(self):
        key, certificate, document = self.fixture()
        route = next(route for route in q.ROUTES if route[0] == "leaf_pem")
        canonical = certificate.public_bytes(serialization.Encoding.PEM)
        for payload, exact, without, count, delta in ((canonical,True,False,1,0),
                (canonical[:-1],False,True,0,-1), (canonical+b"\n",False,False,2,1)):
            facts = q.shape_diagnostics(route,payload,document)
            self.assertEqual(exact,facts["raw_pem_canonical_exact"])
            self.assertEqual(without,facts["raw_pem_without_final_lf_exact"])
            self.assertEqual(count,facts["raw_pem_trailing_lf_count"])
            self.assertEqual(delta,facts["raw_pem_canonical_length_delta"])
            self.assertNotIn(canonical.decode().splitlines()[1],json.dumps(facts))

    def test_chain_diagnostics_bind_each_public_string_without_serializing_it(self):
        key, certificate, document = self.fixture()
        route = next(route for route in q.ROUTES if route[0] == "chain_json")
        canonical = certificate.public_bytes(serialization.Encoding.PEM).decode()
        for cert, chain in ((canonical,canonical),(canonical[:-1],canonical),(canonical[:-1],canonical[:-1])):
            data = {"certificate":cert,"ca_chain":chain,"revocation_time":0,"revocation_time_rfc3339":""}
            facts = q.shape_diagnostics(route,json.dumps({"data":data}).encode(),document)
            self.assertEqual(cert == canonical,facts["certificate_canonical_exact"])
            self.assertEqual(cert == canonical[:-1],facts["certificate_without_final_lf_exact"])
            self.assertEqual(chain == canonical,facts["chain_canonical_exact"])
            self.assertEqual(chain == canonical[:-1],facts["chain_without_final_lf_exact"])
            self.assertEqual(cert == chain,facts["chain_certificate_equal"])
            self.assertNotIn(canonical.splitlines()[1],json.dumps(facts))

    def test_failed_shape_diagnostics_separate_fraction_and_floor_without_recording_material(self):
        route = next(route for route in q.ROUTES if route[0] == "leaf_json")
        document = {"revocation_time":100,"issuer_id":"synthetic-issuer","leaf_pem":"synthetic-public-material"}
        for rfc, digits, offset in (("1970-01-01T00:01:40Z",0,0),
                ("1970-01-01T00:01:40.123456789Z",9,0),
                ("1970-01-01T08:01:40.123+08:00",3,28800)):
            body = {"data":{"certificate":document["leaf_pem"],"issuer_id":document["issuer_id"],
                "revocation_time":100,"revocation_time_rfc3339":rfc}}
            facts = q.shape_diagnostics(route,json.dumps(body).encode(),document)
            self.assertTrue(facts["revocation_rfc_seconds_match"])
            self.assertTrue(facts["revocation_rfc_seconds_floor_exact"])
            self.assertEqual(digits,facts["revocation_rfc_fractional_digits"])
            self.assertEqual(offset,facts["revocation_rfc_timezone_offset_seconds"])
            self.assertTrue(facts["revocation_rfc_parse_valid"])
            self.assertEqual(digits==0 and offset==0,facts["revocation_rfc_utc_canonical_seconds"])
            rendered=json.dumps(facts)
            self.assertNotIn(rfc,rendered);self.assertNotIn(document["leaf_pem"],rendered)
            self.assertNotIn(document["issuer_id"],rendered)
        body["data"]["revocation_time_rfc3339"]="not-a-clock"
        facts=q.shape_diagnostics(route,json.dumps(body).encode(),document)
        self.assertFalse(facts["revocation_rfc_lexically_valid"])
        self.assertFalse(facts["revocation_rfc_seconds_match"])

    def test_full_and_delta_crl_require_actual_signatures_exact_serials_numbers_and_readback(self):
        key, certificate, document=self.fixture(); now=datetime.now(timezone.utc)
        revoked=x509.RevokedCertificateBuilder().serial_number(17).revocation_date(now).build()
        full=x509.CertificateRevocationListBuilder().issuer_name(certificate.subject).last_update(now).next_update(now+timedelta(hours=72)).add_revoked_certificate(revoked).add_extension(x509.CRLNumber(3),False).sign(key,None)
        delta=x509.CertificateRevocationListBuilder().issuer_name(certificate.subject).last_update(now).next_update(now+timedelta(hours=72)).add_extension(x509.CRLNumber(4),False).add_extension(x509.DeltaCRLIndicator(3),True).sign(key,None)
        for name,crl in (("full_crl_der",full),("delta_crl_der",delta)):
            route=next(route for route in q.ROUTES if route[0]==name)
            self.assertTrue(all(q.material_predicates(route,crl.public_bytes(serialization.Encoding.DER),document,key.public_key())))
            with self.assertRaises(Exception):
                q.material_predicates(route,crl.public_bytes(serialization.Encoding.DER),document,ed25519.Ed25519PrivateKey.generate().public_key())
        for stem,crl in (("full",full),("delta",delta)):
            canonical = crl.public_bytes(serialization.Encoding.PEM)
            route = next(route for route in q.ROUTES if route[0] == stem+"_crl_pem")
            self.assertTrue(all(q.material_predicates(route,canonical[:-1],document,key.public_key())))
            self.assertFalse(all(q.material_predicates(route,canonical,document,key.public_key())))
            route = next(route for route in q.ROUTES if route[0] == stem+"_crl_json")
            data = {"certificate":canonical[:-1].decode(),"revocation_time":0,"revocation_time_rfc3339":""}
            self.assertTrue(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))
            data["certificate"] = canonical.decode()
            self.assertFalse(all(q.material_predicates(route,json.dumps({"data":data}).encode(),document,key.public_key())))
        wrong=dict(document,serial_int=18,crls={})
        route=next(route for route in q.ROUTES if route[0]=="full_crl_der")
        self.assertFalse(all(q.material_predicates(route,full.public_bytes(serialization.Encoding.DER),wrong,key.public_key())))

if __name__ == "__main__": unittest.main()
