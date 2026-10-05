"""Synthetic current-producer integration and diagnostics; no runtime qualification."""
import ast
import argparse
import copy
import io
import hashlib
from types import SimpleNamespace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comparison_diagnostic as diagnostic
import acceptance

ROOT = Path(__file__).resolve().parents[3]
SECRET = "private-token-and-key-MUST-NOT-BE-EXPORTED"


class SyntheticAcceptanceClock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class SyntheticAcceptanceTransport:
    """HTTP-only fixture: the real Client, Suite and report writer run unchanged."""

    def __init__(self, clock, side, *, totp_valid=True, totp_creation_status=204, totp_validation_status=200):
        self.clock, self.side, self.totp_valid = clock, side, totp_valid
        self.totp_creation_status = totp_creation_status
        self.totp_validation_status = totp_validation_status
        self.calls, self.mounts, self.auth_mounts = [], {}, {}
        self.versions, self.tokens, self.leases, self.ciphertexts = {}, {}, {}, {}
        self.current, self.transit_version = 0, 1
        self.metadata, self.wrapped = {}, None
        self.wrapper_used, self.approle_used = False, False

    def open(self, request, *, timeout):
        parsed = urlsplit(request.full_url)
        payload = json.loads(request.data) if request.data is not None else None
        method, path = request.get_method(), parsed.path
        token = request.get_header("X-vault-token")
        self.calls.append((method, path))
        status, body = self.respond(method, path, parse_qs(parsed.query), payload, token)
        response = io.BytesIO(json.dumps(body).encode())
        response.code, response.headers = status, Message()
        return response

    def respond(self, method, path, query, payload, token):
        def data(value, status=200, **fields):
            return status, {"data": value, **fields}

        def denied(status=404):
            return status, {"errors": ["synthetic rejection"]}

        if path == "/v1/sys/health":
            return 200, {"initialized": True, "sealed": False,
                         "version": "2.7.0" if self.side == "oracle" else "synthetic-candidate",
                         "cluster_id": "synthetic-" + self.side}
        if path in ("/v1/sys/init", "/v1/sys/seal-status"):
            return 200, {"initialized": True, "sealed": False}
        if path.endswith("-unsupported"):
            return denied()
        for prefix, inventory in (("/v1/sys/mounts", self.mounts), ("/v1/sys/auth", self.auth_mounts)):
            if path == prefix and method == "GET":
                return data(copy.deepcopy(inventory))
            if path.startswith(prefix + "/"):
                key = path[len(prefix) + 1:] + "/"
                if method == "POST":
                    inventory[key] = copy.deepcopy(payload)
                    return 204, {}
                if method == "DELETE":
                    del inventory[key]
                    return 204, {}
        if path.startswith("/v1/sys/policies/acl/"):
            return denied() if method == "GET" else (204, {})
        if path == "/v1/auth/token/create":
            child = "synthetic-child-" + str(len(self.tokens))
            ttl = int(payload["ttl"].removesuffix("s"))
            self.tokens[child] = self.clock.time() + ttl
            return 200, {"auth": {"client_token": child, "policies": payload["policies"],
                                  "lease_duration": ttl}}
        if path == "/v1/auth/token/revoke":
            self.tokens[payload["token"]] = -1
            return 204, {}
        if path.startswith("/v1/auth/userpass/users/") or (
                path.startswith("/v1/auth/approle/role/") and not path.endswith(("/role-id", "/secret-id"))):
            return 204, {}
        if path.endswith("/role-id"):
            return data({"role_id": "synthetic-role"})
        if path.endswith("/secret-id"):
            return data({"secret_id": "synthetic-secret-id"})
        if path.startswith("/v1/auth/userpass/login/") or path == "/v1/auth/approle/login":
            if path == "/v1/auth/approle/login":
                if payload["secret_id"] != "synthetic-secret-id" or self.approle_used:
                    return denied(400)
                self.approle_used = True
            child = "synthetic-child-" + str(len(self.tokens))
            self.tokens[child] = self.clock.time() + 60
            return 200, {"auth": {"client_token": child, "policies": ["default"]}}
        if path == "/v1/sys/wrapping/wrap":
            self.wrapped = copy.deepcopy(payload)
            return 200, {"wrap_info": {"token": "synthetic-wrapper", "ttl": 60}}
        if path == "/v1/sys/wrapping/unwrap":
            if self.wrapper_used:
                return denied(400)
            self.wrapper_used = True
            return data(copy.deepcopy(self.wrapped))
        if path.startswith("/v1/sys/leases/"):
            lease = self.leases[payload["lease_id"]]
            if path.endswith("/revoke"):
                lease["expires"] = -1
                return 204, {}
            ttl = lease["expires"] - self.clock.time()
            return data({"id": payload["lease_id"], "renewable": False, "ttl": ttl}) if ttl > 0 else denied()
        mount, _, rest = path.removeprefix("/v1/").partition("/")
        kind = self.mounts.get(mount + "/", {}).get("type")
        if kind == "kv":
            if token != "synthetic-parent":
                if self.tokens.get(token, -1) <= self.clock.time() or method != "GET":
                    return denied(403)
            if rest == "data/item":
                if method == "POST":
                    if payload["options"]["cas"] != self.current:
                        return denied(400)
                    self.current += 1
                    self.versions[self.current] = {"data": copy.deepcopy(payload["data"]),
                                                   "destroyed": False, "deletion_time": ""}
                    return data({"version": self.current})
                if method == "DELETE":
                    self.versions[self.current]["deletion_time"] = "synthetic-deletion"
                    return 204, {}
                version = int(query.get("version", [self.current])[0])
                item = self.versions[version]
                return denied() if item["destroyed"] or item["deletion_time"] else data(
                    {"data": copy.deepcopy(item["data"]), "metadata": {"version": version}})
            if rest == "metadata/" and method == "LIST":
                return data({"keys": ["item"]})
            if rest == "metadata/item":
                if method == "POST":
                    self.metadata = copy.deepcopy(payload)
                    return 204, {}
                return data({"current_version": self.current,
                             "versions": {str(k): {"destroyed": v["destroyed"], "deletion_time": v["deletion_time"]}
                                          for k, v in self.versions.items()}, **self.metadata})
            if rest in ("undelete/item", "destroy/item"):
                for version in payload["versions"]:
                    self.versions[version]["deletion_time" if rest.startswith("undelete") else "destroyed"] = (
                        "" if rest.startswith("undelete") else True)
                return 204, {}
        if kind == "transit":
            if rest.endswith("/rotate"):
                self.transit_version += 1
            if rest.startswith("keys/"):
                return data({"latest_version": self.transit_version, "type": "aes256-gcm96"})
            if rest.startswith("encrypt/"):
                ciphertext = f"vault:v{self.transit_version}:synthetic"
                self.ciphertexts[ciphertext] = payload["plaintext"]
                return data({"ciphertext": ciphertext})
            if rest.startswith("decrypt/"):
                return data({"plaintext": self.ciphertexts[payload["ciphertext"]]})
        if kind == "pki":
            certificate = "-----BEGIN CERTIFICATE----- synthetic transport placeholder"
            if rest == "root/generate/internal":
                return data({"certificate": certificate, "issuing_ca": certificate,
                             "serial_number": "synthetic-serial", "expiration": 9999})
            if rest == "roles/web":
                return data({"allowed_domains": ["example.test"], "allow_subdomains": True,
                             "max_ttl": 7200, "generate_lease": True, "key_type": "ed25519"})
            if rest == "issue/web":
                ttl = 2 if payload["ttl"] == "2s" else 3600
                lease = "synthetic-lease-" + str(len(self.leases))
                self.leases[lease] = {"expires": self.clock.time() + ttl}
                return data({"certificate": certificate, "issuing_ca": certificate,
                             "serial_number": "synthetic-serial", "private_key_type": "ed25519",
                             "private_key": "-----BEGIN " + "PRIVATE KEY----- synthetic transport placeholder"},
                            lease_id=lease, renewable=False, lease_duration=ttl)
            if rest.startswith("cert/"):
                return data({"certificate": "-----BEGIN X509 CRL----- synthetic" if rest == "cert/crl" else certificate})
        if kind == "totp":
            if rest == "keys/fixture" and method == "POST":
                return (self.totp_creation_status, {}) if self.totp_creation_status in (200, 204) else denied(self.totp_creation_status)
            if rest == "code/fixture":
                if method == "POST" and self.totp_validation_status != 200:
                    return data({"valid": False}, self.totp_validation_status)
                return data({"code": "123456"} if method == "GET" else
                            {"valid": self.totp_valid and payload["code"] == "123456"})
        raise AssertionError(f"unhandled synthetic HTTP request: {method} {path}")


def current_producer_report(*, totp_valid=True, totp_creation_status=204, totp_validation_status=200, allow_writes=True):
    """Run both unchanged default Suites and acceptance.main's actual file output."""
    clock = SyntheticAcceptanceClock()
    clients, transports = {}, {}
    for prefix, side in (("HB_CANDIDATE", "candidate"), ("HB_ORACLE", "oracle")):
        transport = SyntheticAcceptanceTransport(clock, side, totp_valid=totp_valid if side == "candidate" else True,
            totp_creation_status=totp_creation_status if side == "candidate" else 204,
            totp_validation_status=totp_validation_status if side == "candidate" else 200)
        client = acceptance.Client.__new__(acceptance.Client)
        client.address, client.namespace, client.timeout = f"https://{side}.example.test:443", "", 1
        client._token, client._opener = "synthetic-parent", transport
        clients[prefix], transports[side] = client, transport
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        identity, output = root / "synthetic-oracle.json", root / "producer.json"
        archive, _binary = sorted(diagnostic.ORACLES["2.7.0"])[0]
        identity.write_text(json.dumps({"product": "OpenBao", "version": "2.7.0",
            "artifact_sha256": archive, "provenance_url": "https://github.com/openbao/openbao/releases/tag/v2.7.0",
            "endpoint": clients["HB_ORACLE"].address, "cluster_id": "synthetic-oracle"}))
        identity.chmod(0o600)
        args = ["--compare", "--oracle-version", "2.7.0", "--oracle-identity-file", str(identity), "--output", str(output)]
        if allow_writes:
            args.append("--allow-test-writes")
        with patch.object(acceptance.Client, "from_env", side_effect=lambda prefix: clients[prefix]), \
                patch.object(acceptance, "time", clock), \
                patch.object(acceptance, "secrets", SimpleNamespace(token_hex=lambda _n: "0123456789abcdef",
                                                                 token_urlsafe=lambda _n: "synthetic-invalid")):
            code = acceptance.main(args)
        return code, json.loads(output.read_text()), transports, output.stat().st_mode & 0o777


class ComparisonDiagnosticTests(unittest.TestCase):
    def binding(self):
        return {
            "candidate_binary_sha256": "a" * 64,
            "candidate_source_sha": "b" * 40,
            "candidate_source_tree": "c" * 40,
            "candidate_source_has_uncommitted_changes": False,
            "candidate_source_binding_basis": "operator_supplied_build_source_checkout",
            "runner_source_sha256": "d" * 64,
            "diagnostic_source_sha256": "e" * 64,
            "launcher_source_sha256": "f" * 64,
        }

    def report(self, version="2.7.0"):
        bound = {k: v for k, v in self.binding().items()
                 if k not in {"candidate_source_tree", "diagnostic_source_sha256", "launcher_source_sha256"}}
        archive, binary = sorted(diagnostic.ORACLES[version])[0]
        bound.update(build_log_sha256=None, official_oracle={
            "product": "OpenBao", "version": version, "artifact_sha256": archive,
            "binary_sha256": binary, "provenance_url": SECRET, "endpoint": SECRET,
            "cluster_id": SECRET, "archive_member_matches_executable": True,
            "server_mode": "server_not_dev", "storage": "pebbledb" if version == "2.7.0" else "file",
            "tls_verified": True, "synthetic_only": True, "launcher_source_sha256": "f" * 64,
        })
        passed = {"result": "passed", "http_status": 200, "expected_http_status": [200],
                  "semantics": {"version_is_one": True}, "method": "POST", "path_template": SECRET}
        failed = {**passed, "http_status": 403, "result": "failed", "semantics": {"version_is_one": False}}
        cleanup = {"result": "passed", "failure_count": 0, "scope": SECRET, "run_id": SECRET}
        return {
            "schema": "heptabao.live-acceptance.v1", "target": "OpenBao " + version,
            "observed_at_unix": 1.0, "tool_source_sha256": "0" * 64,
            "full_openbao_compatibility": False, "production_qualified": False,
            "mode": "differential", "status": "failed", "cases_match": False,
            "candidate": {"endpoint": SECRET, "version": SECRET, "namespace_digest": SECRET, "cluster_id_digest": SECRET},
            "oracle": {"endpoint": SECRET, "product": "OpenBao", "version": version,
                       "artifact_sha256": archive, "basis": SECRET, "cluster_id_digest": SECRET,
                       "independent_binary_attestation": False},
            "scope": ["kv", "token"], "uncovered": [SECRET],
            "candidate_results": {"cases": {"kv.write_v1": failed,
                "token.policy": {"result": "not_run", "reason": "token_cases_require_successful_kv_fixture"}}, "cleanup": cleanup},
            "oracle_results": {"cases": {"kv.write_v1": passed,
                "token.policy": {"result": "passed", "http_status": 204, "expected_http_status": [204], "semantics": {}}}, "cleanup": cleanup},
            "mismatched_cases": ["kv.write_v1", "token.policy"], "execution_binding": bound,
        }

    def project(self, report=None):
        return diagnostic.project(self.report() if report is None else report, self.binding(), "2.7.0")

    def producer_report(self, **options):
        code, report, transports, mode = current_producer_report(**options)
        self.assertEqual(mode, 0o600)
        self.assertEqual(report["tool_source_sha256"], hashlib.sha256(
            (ROOT / "qa/openbao-acceptance/acceptance.py").read_bytes()
            + (ROOT / "qa/openbao-acceptance/bao_http.py").read_bytes()).hexdigest())
        # run_official_comparison adds this binding after acceptance.main writes
        # its report. No Suite result or report case is manufactured here.
        report["execution_binding"] = copy.deepcopy(self.report()["execution_binding"])
        return code, report, transports

    def assert_complete_default_producer(self, report):
        self.assertEqual(set(report["scope"]), set(acceptance.CASES) - {"identity"})
        selected = {module + "." + name for module in report["scope"] for name in acceptance.CASES[module]}
        self.assertEqual(len(selected), 62)
        for side in ("candidate_results", "oracle_results"):
            cases = report[side]["cases"]
            self.assertEqual(set(cases), diagnostic.CASE_NAMES | {"totp.mount"})
            self.assertEqual(len(cases), 69)
            self.assertEqual(cases["totp.mount"]["result"], "passed")
            self.assertEqual(report[side]["cleanup"]["result"], "passed")
            self.assertEqual(report[side]["cleanup"]["failure_count"], 0)
            for name in acceptance.CASES["identity"]:
                self.assertEqual(cases["identity." + name], {
                    "result": "not_run", "reason": "module_not_selected_or_writes_not_authorized"})
        return selected

    def test_full_current_producer_success_projects_all_default_cases(self):
        code, report, transports = self.producer_report()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed_scoped_cases")
        self.assertIs(report["cases_match"], True)
        self.assertEqual(report["mismatched_cases"], [])
        selected = self.assert_complete_default_producer(report)
        for side in ("candidate_results", "oracle_results"):
            for name in selected:
                row = report[side]["cases"][name]
                self.assertEqual(row["result"], "passed", name)
                self.assertTrue(all(value is True for value in row["semantics"].values()), name)
        for transport in transports.values():
            totp = [(method, path.rsplit("/", 2)[-2:]) for method, path in transport.calls
                    if "-totp/" in path]
            self.assertEqual(totp, [("POST", ["keys", "fixture"]),
                                    ("GET", ["code", "fixture"]), ("POST", ["code", "fixture"])])
        with tempfile.TemporaryDirectory() as directory:
            code, safe, log, _output = self.invoke(directory, report, process_exit=0)
        self.assertEqual(code, 0)
        self.assertEqual(safe["status"], "available")
        self.assertEqual(safe["comparison_status"], "passed_scoped_cases")
        self.assertIs(safe["cases_match"], True)
        for side in ("candidate_results", "oracle_results"):
            self.assertEqual(set(safe[side]["cases"]), set(report[side]["cases"]))
            self.assertEqual(safe[side]["cases"]["totp.mount"]["method"], "POST")
            aggregate = safe[side]["cases"]["totp.roundtrip"]
            self.assertEqual(aggregate["method"], "MULTI")
            self.assertEqual(aggregate["method_kind"], "aggregate")
            self.assertEqual(aggregate["semantics"], {"key_created": True, "code_generated": True, "validation_true": True})
            for name in ("pki.lease_expire_lookup", "pki.revoked_lease_absent"):
                self.assertEqual(safe[side]["cases"][name]["http_status"], report[side]["cases"][name]["http_status"])
        for name in ("independent_admission", "full_openbao_compatibility", "production_qualified"):
            self.assertIs(safe[name], False)
        self.assertNotIn("path_template", json.dumps(safe))
        self.assertNotIn("example.test", json.dumps(safe) + log)

    def test_real_failed_totp_aggregate_remains_failed_with_false_predicate(self):
        for validation_status in (200, 400):
            with self.subTest(validation_status=validation_status):
                code, report, _transports = self.producer_report(totp_valid=False, totp_validation_status=validation_status)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "failed")
                selected = self.assert_complete_default_producer(report)
                self.assertEqual(report["mismatched_cases"], ["totp.roundtrip"])
                for name in selected - {"totp.roundtrip"}:
                    self.assertEqual(report["candidate_results"]["cases"][name]["result"], "passed", name)
                original = report["candidate_results"]["cases"]["totp.roundtrip"]
                self.assertEqual(original["method"], "MULTI")
                self.assertEqual(original["http_status"], validation_status)
                self.assertIs(original["semantics"]["validation_true"], False)
                with tempfile.TemporaryDirectory() as directory:
                    code, safe, _log, _output = self.invoke(directory, report, process_exit=2)
                self.assertEqual(code, 0)
                projected = safe["candidate_results"]["cases"]["totp.roundtrip"]
                self.assertEqual(projected["result"], "failed")
                self.assertEqual(projected["http_status"], original["http_status"])
                self.assertEqual(projected["semantics"], original["semantics"])
                self.assertEqual(projected["method_kind"], "aggregate")
                self.assertEqual(safe["comparison_status"], "failed")
                for name in ("cases_match", "independent_admission", "full_openbao_compatibility", "production_qualified"):
                    self.assertIs(safe[name], False)

    def test_multi_is_rejected_for_every_other_actual_producer_case(self):
        _code, report, _transports = self.producer_report()
        for side in ("candidate_results", "oracle_results"):
            for name in report[side]["cases"]:
                if name == "totp.roundtrip":
                    continue
                changed = copy.deepcopy(report)
                changed[side]["cases"][name]["method"] = "MULTI"
                with self.subTest(side=side, case=name), self.assertRaises(diagnostic.Rejected):
                    self.project(changed)

    def test_actual_not_run_and_pre_aggregate_failure_cannot_forge_multi(self):
        code, report, _transports = self.producer_report(allow_writes=False)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "not_run")
        self.assertEqual(self.project(report)["comparison_status"], "not_run")
        for side in ("candidate_results", "oracle_results"):
            self.assertEqual(report[side]["cases"]["totp.roundtrip"]["result"], "not_run")
            changed = copy.deepcopy(report)
            changed[side]["cases"]["totp.roundtrip"]["method"] = "MULTI"
            with self.subTest(side=side), self.assertRaises(diagnostic.Rejected):
                self.project(changed)
        code, failed, _transports = self.producer_report(totp_creation_status=400)
        self.assertEqual(code, 2)
        row = failed["candidate_results"]["cases"]["totp.roundtrip"]
        self.assertEqual(row["method"], "POST")
        self.assertEqual(row["semantics"], {"key_created": False})
        self.assertEqual(self.project(failed)["candidate_results"]["cases"]["totp.roundtrip"]["method"], "POST")
        row["method"] = "MULTI"
        with self.assertRaises(diagnostic.Rejected):
            self.project(failed)

    def test_full_producer_unknown_method_and_closed_fields_fail_cli(self):
        _code, report, _transports = self.producer_report()
        for method in ("CONNECT", "SCAN", SECRET, "multi", "MULTI ", None, True):
            changed = copy.deepcopy(report)
            changed["candidate_results"]["cases"]["totp.roundtrip"]["method"] = method
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                code, safe, log, _output = self.invoke(directory, changed, process_exit=0)
                self.assertEqual(code, 2)
                self.assertEqual(safe["status"], "report_rejected")
                self.assertNotIn("candidate_results", safe)
                self.assertNotIn(SECRET, json.dumps(safe) + log)
                for name in ("independent_admission", "full_openbao_compatibility", "production_qualified"):
                    self.assertIs(safe[name], False)
        for field, value in (("http_status", True), ("http_status", None),
                             ("http_status", "rejected_after_ttl"), ("expected_http_status", [200, 204]),
                             ("expected_http_status", [True]), ("method_kind", "aggregate"),
                             ("semantics", {"key_created": True, "code_generated": True, "validation_true": 1}),
                             ("semantics", {"key_created": True, "code_generated": True, "validation_true": True, "extra": True})):
            changed = copy.deepcopy(report)
            changed["candidate_results"]["cases"]["totp.roundtrip"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(diagnostic.Rejected):
                self.project(changed)

    def test_actual_auxiliary_mount_does_not_expand_selected_or_mismatch_vocabulary(self):
        _code, report, _transports = self.producer_report()
        for field in ("scope", "mismatched_cases"):
            changed = copy.deepcopy(report)
            changed[field] = ["totp.mount"]
            with self.subTest(field=field), self.assertRaises(diagnostic.Rejected):
                self.project(changed)
        changed = copy.deepcopy(report)
        changed["candidate_results"]["cases"]["totp.extra_mount"] = changed["candidate_results"]["cases"].pop("totp.mount")
        with self.assertRaises(diagnostic.Rejected):
            self.project(changed)

    def test_observed_http_difference_and_dependency_reason_survive(self):
        safe = self.project()
        left = safe["candidate_results"]["cases"]
        right = safe["oracle_results"]["cases"]
        self.assertEqual(left["kv.write_v1"]["http_status"], 403)
        self.assertEqual(right["kv.write_v1"]["http_status"], 200)
        self.assertEqual(left["kv.write_v1"]["expected_http_status"], [200])
        self.assertFalse(left["kv.write_v1"]["semantics"]["version_is_one"])
        self.assertEqual(left["token.policy"]["reason"], "token_cases_require_successful_kv_fixture")
        self.assertEqual(safe["official_oracle"]["version"], "2.7.0")
        self.assertNotIn(SECRET, json.dumps(safe))
        self.assertNotIn("path_template", json.dumps(safe))

    def test_private_payload_keys_at_each_boundary_are_rejected(self):
        for select in (lambda x: x, lambda x: x["execution_binding"],
                       lambda x: x["execution_binding"]["official_oracle"],
                       lambda x: x["candidate"], lambda x: x["oracle"],
                       lambda x: x["candidate_results"],
                       lambda x: x["candidate_results"]["cleanup"],
                       lambda x: x["candidate_results"]["cases"]["kv.write_v1"],
                       lambda x: x["candidate_results"]["cases"]["kv.write_v1"]["semantics"]):
            with self.subTest(select=select):
                report = self.report()
                select(report)["root_token"] = SECRET
                with self.assertRaises(diagnostic.Rejected):
                    self.project(report)

    def test_secret_strings_and_nonboolean_predicates_are_rejected(self):
        for field in ("result", "reason", "method", "http_status", "expected_http_status", "semantics"):
            with self.subTest(field=field):
                report = self.report()
                report["candidate_results"]["cases"]["kv.write_v1"][field] = SECRET
                with self.assertRaises(diagnostic.Rejected):
                    self.project(report)
        for value in (SECRET, 1, 0, None, [], {"key": SECRET}):
            report = self.report()
            report["candidate_results"]["cases"]["kv.write_v1"]["semantics"]["version_is_one"] = value
            with self.subTest(value=value), self.assertRaises(diagnostic.Rejected):
                self.project(report)

    def test_unknown_case_and_mismatch_and_scope_are_rejected(self):
        for field in ("scope", "mismatched_cases"):
            report = self.report()
            report[field] = [SECRET]
            with self.subTest(field=field), self.assertRaises(diagnostic.Rejected):
                self.project(report)
        report = self.report()
        report["candidate_results"]["cases"][SECRET] = {"result": "failed"}
        with self.assertRaises(diagnostic.Rejected):
            self.project(report)

    def test_binding_cannot_be_substituted_or_upgraded(self):
        for key, value in (("candidate_binary_sha256", "1" * 64), ("candidate_source_sha", "2" * 40),
                           ("runner_source_sha256", "3" * 64), ("candidate_source_has_uncommitted_changes", 0),
                           ("candidate_source_binding_basis", SECRET)):
            report = self.report()
            report["execution_binding"][key] = value
            with self.subTest(key=key), self.assertRaises(diagnostic.Rejected):
                self.project(report)
        for key, value in (("version", "2.6.2"), ("binary_sha256", "0" * 64), ("artifact_sha256", "0" * 64),
                           ("storage", "file"), ("launcher_source_sha256", "0" * 64), ("tls_verified", 1),
                           ("synthetic_only", False), ("server_mode", "dev")):
            report = self.report()
            report["execution_binding"]["official_oracle"][key] = value
            with self.subTest(key=key), self.assertRaises(diagnostic.Rejected):
                self.project(report)

    def test_historical_version_remains_distinct(self):
        safe = diagnostic.project(self.report("2.6.2"), self.binding(), "2.6.2")
        self.assertEqual(safe["official_oracle"]["storage"], "file")
        with self.assertRaises(diagnostic.Rejected):
            self.project(self.report("2.6.2"))

    def test_existing_rejection_status_normalization_is_preserved(self):
        for status in (None, "rejected_after_ttl", "rejected_400_or_404"):
            self.assertEqual(diagnostic.case_projection({"result": "failed", "http_status": status})["http_status"], status)
        for status in (True, False, 99, 600, SECRET, [200]):
            with self.subTest(status=status), self.assertRaises(diagnostic.Rejected):
                diagnostic.case_projection({"result": "failed", "http_status": status})

    def invoke(self, directory, report=None, raw=None, process_exit=2):
        root = Path(directory)
        source, output = root / "comparison-bound.json", root / "diagnostic.json"
        if report is not None or raw is not None:
            source.write_text(json.dumps(report) if raw is None else raw)
            source.chmod(0o600)
        log = io.StringIO()
        with patch.object(diagnostic, "observe", return_value=self.binding()), redirect_stdout(log):
            code = diagnostic.main(["--report", str(source), "--output", str(output), "--binary", "/synthetic/binary",
                                    "--candidate-source", "/synthetic/source", "--oracle-version", "2.7.0", "--process-exit", str(process_exit)])
        return code, json.loads(output.read_text()), log.getvalue(), output

    def test_missing_report_emits_bound_diagnostic_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            code, safe, log, output = self.invoke(directory)
            self.assertEqual(code, 2)
            self.assertEqual(safe["status"], "report_missing")
            self.assertEqual(safe["comparison_process_exit"], 2)
            self.assertEqual(safe["observed_binding"], self.binding())
            self.assertNotIn("official_oracle", safe)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(directory, log)

    def test_valid_failure_report_is_available_but_never_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            code, safe, log, _output = self.invoke(directory, self.report())
            self.assertEqual(code, 0)
            self.assertEqual(safe["status"], "available")
            self.assertEqual(safe["comparison_status"], "failed")
            self.assertEqual(safe["comparison_process_exit"], 2)
            for name in ("cases_match", "independent_admission", "full_openbao_compatibility", "production_qualified"):
                self.assertIs(safe[name], False)
            self.assertNotIn(SECRET, json.dumps(safe) + log)

    def test_malformed_duplicate_oversized_and_secret_reports_fail_without_leak(self):
        bad = self.report()
        bad["root_token"] = SECRET
        values = ["{" + SECRET, '{"schema":"one","schema":"' + SECRET + '"}',
                  '{"value":NaN}', json.dumps(bad), " " * (diagnostic.MAX_REPORT_BYTES + 1)]
        for raw in values:
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                code, safe, log, _output = self.invoke(directory, raw=raw)
                self.assertEqual(code, 2)
                self.assertEqual(safe["status"], "report_rejected")
                self.assertNotIn(SECRET, json.dumps(safe) + log)
                self.assertNotIn("candidate_results", safe)

    def test_input_symlink_hardlink_fifo_and_public_mode_are_rejected(self):
        for kind in ("symlink", "hardlink", "fifo", "public"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target, path = root / "private", root / "report"
                target.write_text(json.dumps(self.report()))
                target.chmod(0o600)
                if kind == "symlink":
                    path.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, path)
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    path.write_bytes(target.read_bytes())
                    path.chmod(0o644)
                with self.assertRaises((diagnostic.Rejected, OSError)):
                    diagnostic.read_report(path)

    def test_output_never_overwrites_existing_file_or_follows_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, link = root / "existing", root / "link"
            target.write_text(SECRET)
            link.symlink_to(target)
            for path in (target, link):
                with self.subTest(path=path.name), self.assertRaises(OSError):
                    diagnostic.write_report(path, {})
            self.assertEqual(target.read_text(), SECRET)

    def test_public_or_symlinked_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public"
            public.mkdir(mode=0o755)
            link = root / "linked"
            link.symlink_to(root)
            for path in (public / "out", link / "out"):
                with self.subTest(path=path), self.assertRaises(diagnostic.Rejected):
                    diagnostic.write_report(path, {})

    def test_input_and_delivery_require_caller_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report"
            source.write_text(json.dumps(self.report()))
            source.chmod(0o600)
            with patch.object(diagnostic.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(diagnostic.Rejected):
                    diagnostic.read_report(source)
                with self.assertRaises(diagnostic.Rejected):
                    diagnostic.write_report(root / "out", {})
            self.assertFalse((root / "out").exists())

    def test_fixed_vocabulary_matches_current_acceptance_source(self):
        tree = ast.parse((ROOT / "qa/openbao-acceptance/acceptance.py").read_text())
        cases = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets))
        semantics = {keyword.arg for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "check" for keyword in node.keywords}
        self.assertEqual(diagnostic.CASES, cases)
        self.assertEqual(diagnostic.SEMANTICS, semantics)

    def test_actual_suite_early_kv_failure_can_explain_27_mismatch_labels(self):
        # Execute the unchanged Suite control flow with synthetic responses only.
        source = ast.parse((ROOT / "qa/openbao-acceptance/acceptance.py").read_text())
        suite_node = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == "Suite")
        class FixtureError(Exception):
            def __init__(self, code):
                self.code = code
        namespace = {"Client": object, "BaoError": FixtureError, "CASES": diagnostic.CASES}
        exec(compile(ast.Module(body=[suite_node], type_ignores=[]), "synthetic-suite", "exec"), namespace)
        suite = namespace["Suite"](None, "synthetic", {"kv", "token"}, True)
        def early_kv_failure():
            suite.check("kv.mount", SimpleNamespace(status=204), 204)
            suite.check("kv.write_v1", SimpleNamespace(status=403), 200, version_is_one=False)
        suite.kv_cases = early_kv_failure
        suite.cleanup = lambda: {"result": "passed", "failure_count": 0, "scope": "synthetic", "run_id": SECRET}
        candidate = suite.run()
        oracle = {"cases": {name: dict(value) for name, value in candidate["cases"].items()}, "cleanup": candidate["cleanup"]}
        selected = [module + "." + case for module in ("kv", "token") for case in diagnostic.CASES[module]]
        for name in selected:
            if name != "kv.mount":
                oracle["cases"][name] = {"result": "passed", "http_status": 200, "expected_http_status": [200], "semantics": {}}
        mismatches = [name for name in selected if candidate["cases"][name] != oracle["cases"][name]]
        self.assertEqual(len(mismatches), 27)
        report = self.report()
        report.update(candidate_results=candidate, oracle_results=oracle, mismatched_cases=mismatches)
        safe = self.project(report)
        self.assertEqual(safe["candidate_results"]["cases"]["kv.write_v1"]["http_status"], 403)
        self.assertEqual(safe["candidate_results"]["cases"]["kv.read_v1"]["reason"], "case_status_or_semantics_mismatch")
        self.assertEqual(safe["candidate_results"]["cases"]["token.policy"]["reason"], "token_cases_require_successful_kv_fixture")
        self.assertEqual(len(safe["reported_mismatched_cases"]), 27)
        self.assertNotIn(SECRET, json.dumps(safe))

    def test_current_acceptance_main_report_shape_is_accepted(self):
        # Run the actual report assembly with synthetic clients/suites. No service
        # is started, and the private report is captured only in memory.
        path = ROOT / "qa/openbao-acceptance/acceptance.py"
        source = ast.parse(path.read_text())
        main_node = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        cases = {name: {"result": "passed", "http_status": 200, "expected_http_status": [200], "semantics": {}}
                 for name in diagnostic.CASE_NAMES}
        oracle_results = {"cases": cases, "cleanup": {"result": "passed", "failure_count": 0,
                          "scope": "only_newly_created_synthetic_resources", "run_id": "synthetic"}}
        candidate_results = {"cases": {**cases, "kv.write_v1": {"result": "failed", "http_status": 403,
                              "expected_http_status": [200], "semantics": {"version_is_one": False}}},
                             "cleanup": oracle_results["cleanup"]}
        class FixtureClient:
            namespace = ""
            def __init__(self, prefix):
                self.address = "https://" + prefix.lower() + ".example.test"
                self.candidate = prefix == "HB_CANDIDATE"
            @classmethod
            def from_env(cls, prefix):
                return cls(prefix)
            def health(self):
                return {"version": SECRET if self.candidate else "2.7.0", "cluster_id": SECRET}
        class FixtureSuite:
            def __init__(self, client, *_args):
                self.client = client
            def run(self):
                return candidate_results if self.client.candidate else oracle_results
        class FixtureError(Exception):
            pass
        captured = []
        identity = {"product": "OpenBao", "version": "2.7.0",
                    "artifact_sha256": sorted(diagnostic.ORACLES["2.7.0"])[0][0],
                    "basis": "operator_artifact_attestation_plus_verified_tls_and_live_health",
                    "independent_binary_attestation": False}
        namespace = {"__file__": str(path), "Path": Path, "hashlib": hashlib, "json": json,
                     "SafeArgumentParser": argparse.ArgumentParser, "CASES": diagnostic.CASES,
                     "Client": FixtureClient, "Suite": FixtureSuite, "BaoError": FixtureError,
                     "time": SimpleNamespace(time=lambda: 1.0), "secrets": SimpleNamespace(token_hex=lambda _size: "synthetic"),
                     "digest": lambda _value: "0" * 64, "distinct_endpoints": lambda *_args: None,
                     "private_json": lambda _path: {}, "verify_oracle_identity": lambda *_args, **_kw: dict(identity),
                     "private_write": lambda _path, report: captured.append(report)}
        exec(compile(ast.Module(body=[main_node], type_ignores=[]), str(path), "exec"), namespace)
        code = namespace["main"](["--compare", "--allow-test-writes", "--modules", "kv,token", "--oracle-version", "2.7.0",
                                  "--oracle-identity-file", "synthetic", "--output", "synthetic"])
        self.assertEqual(code, 2)
        self.assertEqual(len(captured), 1)
        report = captured[0]
        report["execution_binding"] = self.report()["execution_binding"]
        with tempfile.TemporaryDirectory() as directory:
            code, safe, log, _output = self.invoke(directory, report)
        self.assertEqual(code, 0)
        self.assertEqual(safe["status"], "available")
        self.assertEqual(safe["reported_mismatched_cases"], ["kv.write_v1"])
        self.assertNotIn(SECRET, json.dumps(safe) + log)

    def test_observed_binding_hashes_actual_supplied_bytes_and_git_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "qa/openbao-acceptance"
            harness.mkdir(parents=True)
            binary = root / "candidate"
            binary.write_bytes(b"synthetic-binary-no-execution")
            (harness / "run_official_comparison.py").write_bytes(b"synthetic-runner")
            (harness / "official_openbao_launcher.py").write_bytes(b"synthetic-launcher")
            with patch.object(diagnostic.subprocess, "check_output", side_effect=["a" * 40, "b" * 40, ""]) as git:
                observed = diagnostic.observe(binary, root)
            self.assertEqual(observed["candidate_binary_sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(observed["runner_source_sha256"], hashlib.sha256(b"synthetic-runner").hexdigest())
            self.assertEqual(observed["launcher_source_sha256"], hashlib.sha256(b"synthetic-launcher").hexdigest())
            self.assertEqual(observed["candidate_source_sha"], "a" * 40)
            self.assertEqual(observed["candidate_source_tree"], "b" * 40)
            self.assertIs(observed["candidate_source_has_uncommitted_changes"], False)
            self.assertEqual(git.call_count, 3)

    def test_workflow_preserves_original_exit_and_runs_diagnostic_after_failure(self):
        text = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        start = text.index("          comparison_exit=0\n")
        end = text.index('          timeout 300 python qa/openbao-acceptance/live_migration_rehearsal.py', start)
        block = "\n".join(line[10:] for line in text[start:end].splitlines())
        for comparison, capture, expected in ((0, 0, 0), (2, 0, 2), (77, 0, 77), (124, 0, 124),
                                              (2, 2, 2), (77, 2, 77), (124, 2, 124), (0, 2, 2)):
            with self.subTest(comparison=comparison, capture=capture), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "called"
                prelude = '''set -euo pipefail
binary=unused
work=unused
RUNNER_TEMP=unused
timeout() { return "$COMPARISON_EXIT"; }
python() { printf '%s\\n' "$@" > "$MARKER"; return "$DIAGNOSTIC_EXIT"; }
'''
                result = subprocess.run(["bash", "-c", prelude + block], capture_output=True, text=True,
                                        env={**os.environ, "COMPARISON_EXIT": str(comparison),
                                             "DIAGNOSTIC_EXIT": str(capture), "MARKER": str(marker)})
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertTrue(marker.read_text().endswith("--process-exit\n" + str(comparison) + "\n"))

    def test_upload_is_one_exact_registered_sanitized_file_and_verdict_unchanged(self):
        workflow = (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        self.assertNotIn('cp "$work/comparison/comparison-bound.json"', workflow)
        self.assertIn('if: ${{ always() }}\n        uses: actions/upload-artifact@', workflow)
        self.assertIn('test "$QUALIFY_RESULT" = success', workflow)
        self.assertNotIn('continue-on-error:', workflow)
        registry = json.loads((ROOT / "scripts/workflow_trust_action_registry_v2.json").read_text())
        rows = [entry for entry in registry["uploads"] if entry["file"] == "codex-openbao-replacement-ci.yml"]
        self.assertEqual(rows, [{"file": "codex-openbao-replacement-ci.yml", "location": "workflow.jobs.qualify.steps[73]",
                               "path": "${{ runner.temp }}/heptabao-safe-reports/comparison270-diagnostic.json"}])
        self.assertIn("          path: " + rows[0]["path"] + "\n", workflow)


if __name__ == "__main__":
    unittest.main()
