#!/usr/bin/env python3
"""Compare a bounded PKI issuance/revocation profile with OpenBao 2.6.2.

The profile intentionally covers only an internal Ed25519 root, one DNS role,
lease-backed issuance, exact lease revocation, certificate lookup, and JSON CRL
publication. It does not qualify intermediates, imported/KMS keys, CSR signing,
OCSP/ACME/EST, PKIext, issuer rotation, raw CRL endpoints, or the full PKI API.
"""
from pathlib import Path
from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(path, body=None, method="POST"):
        return client.request(method, "/v1/" + path, body)

    def status(name, response, expected):
        passed = response.status == expected
        results.append({"case": name, "status": response.status, "passed": passed})
        if not passed:
            raise ScenarioFailure(name)
        return response.body

    def truth(name, condition):
        passed = bool(condition)
        results.append({"case": name, "passed": passed})
        if not passed:
            raise ScenarioFailure(name)

    mount = "pki-compare"
    status("pki.mount", call("sys/mounts/" + mount, {
        "type": "pki", "config": {"max_lease_ttl": "8760h"}}), 204)
    root = status("pki.root", call(mount + "/root/generate/internal", {
        "common_name": "ca.example.test", "ttl": "8760h", "key_type": "ed25519"}), 200)
    root_data = root.get("data", {})
    truth("pki.root_material", root_data.get("certificate", "").startswith("-----BEGIN CERTIFICATE-----")
          and root_data.get("issuing_ca", "").startswith("-----BEGIN CERTIFICATE-----")
          and bool(root_data.get("serial_number")) and int(root_data.get("expiration", 0)) > 0)
    role = status("pki.role", call(mount + "/roles/web", {
        "allowed_domains": ["example.test"], "allow_subdomains": True,
        "max_ttl": "2h", "generate_lease": True, "key_type": "ed25519"}), 200)
    role_data = role.get("data", {})
    truth("pki.role_write_semantics", role_data.get("allowed_domains") == ["example.test"]
          and role_data.get("allow_subdomains") is True
          and int(role_data.get("max_ttl", 0)) == 7200
          and role_data.get("generate_lease") is True
          and role_data.get("key_type") == "ed25519")
    read_role = status("pki.role_read", call(mount + "/roles/web", method="GET"), 200).get("data", {})
    truth("pki.role_read_semantics", read_role.get("allowed_domains") == ["example.test"]
          and read_role.get("allow_subdomains") is True
          and int(read_role.get("max_ttl", 0)) == 7200
          and read_role.get("generate_lease") is True
          and read_role.get("key_type") == "ed25519")
    issued = status("pki.issue", call(mount + "/issue/web", {
        "common_name": "api.example.test", "alt_names": "www.example.test", "ttl": "1h"}), 200)
    data = issued.get("data", {})
    lease_id = issued.get("lease_id", "")
    serial = data.get("serial_number", "")
    truth("pki.issue_material", bool(lease_id) and issued.get("renewable") is False
          and 0 < int(issued.get("lease_duration", 0)) <= 3600 and bool(serial)
          and data.get("certificate", "").startswith("-----BEGIN CERTIFICATE-----")
          and data.get("issuing_ca", "").startswith("-----BEGIN CERTIFICATE-----")
          and data.get("private_key", "").startswith("-----BEGIN " + "PRIVATE KEY-----")
          and data.get("private_key_type") == "ed25519")
    lease = status("pki.lease_lookup", call("sys/leases/lookup", {"lease_id": lease_id}), 200).get("data", {})
    truth("pki.lease_metadata", lease.get("id") == lease_id and lease.get("renewable") is False
          and 0 < int(lease.get("ttl", 0)) <= 3600)
    cert = status("pki.cert_lookup", call(mount + "/cert/" + serial, method="GET"), 200).get("data", {})
    truth("pki.cert_lookup_material", cert.get("certificate", "").startswith("-----BEGIN CERTIFICATE-----"))
    status("pki.lease_revoke", call("sys/leases/revoke", {"lease_id": lease_id, "sync": True}), 204)
    revoked = call("sys/leases/lookup", {"lease_id": lease_id})
    truth("pki.revoked_lease_absent", revoked.status in (400, 404))
    crl = status("pki.crl_json", call(mount + "/cert/crl", method="GET"), 200).get("data", {})
    truth("pki.crl_material", crl.get("certificate", "").startswith("-----BEGIN X509 CRL-----"))
    return results


if __name__ == "__main__":
    raise SystemExit(core_isolation.main(
        scenario_runner=run_scenarios,
        profile="pki-live",
        scope="selected internal Ed25519 root/role/lease-backed issue/revoke/CRL behavior only",
        runner_path=Path(__file__),
    ))
