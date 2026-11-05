#!/usr/bin/env python3
"""Fixed public external-Ed25519 PKI contract on three fresh verified TLS servers.

Each of the 17 public routes is exercised with all six bearer states. Public
material is cryptographically bound to the enrolled remote issuer, and each
read must have one request/response audit pair and no remote provider Sign.
Necessary durable clock/lease maintenance remains allowed. The bounded profile
has no whole-PKI, migration, production or independent qualification authority.
"""
from __future__ import annotations
import base64
import calendar
from datetime import datetime, timezone
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from official_openbao_launcher import file_digest, pinned_artifact, start_oracle, stop_oracle, restart_oracle
import external_pki_leaf_crl_live as leaf
import external_transit_consumer_live as shared

ROOT = Path(__file__).resolve().parents[2]
VERSION = "2.7.0"
HTTP_TIMEOUT_SECONDS = 2
TOKEN_MODES = ("header_absent", "header_empty", "invalid", "expired", "finite", "wrapping")
# Paths use an owned serial placeholder, never a report value supplied by a user.
ROUTES = (
    ("leaf_json", "GET", "cert/{serial}", "json", "leaf"),
    ("leaf_der", "GET", "cert/{serial}/raw", "application/pkix-cert", "leaf"),
    ("leaf_pem", "GET", "cert/{serial}/raw/pem", "application/pem-certificate-chain", "leaf"),
    ("ca_json", "GET", "cert/ca", "json", "ca"),
    ("ca_der", "GET", "ca", "application/pkix-cert", "ca"),
    ("ca_pem", "GET", "ca/pem", "application/pem-certificate-chain", "ca"),
    ("chain_json", "GET", "cert/ca_chain", "json", "chain"),
    ("chain_pem", "GET", "ca_chain", "application/pkix-cert", "chain"),
    ("full_crl_json", "GET", "cert/crl", "json", "full"),
    ("full_crl_der", "GET", "crl", "application/pkix-crl", "full"),
    ("full_crl_pem", "GET", "crl/pem", "application/x-pem-file", "full"),
    ("delta_crl_json", "GET", "cert/delta-crl", "json", "delta"),
    ("delta_crl_der", "GET", "crl/delta", "application/pkix-crl", "delta"),
    ("delta_crl_pem", "GET", "crl/delta/pem", "application/x-pem-file", "delta"),
    ("issuers_list", "LIST", "issuers", "json", "issuers"),
    ("issuers_query", "GET", "issuers?list=true", "json", "issuers"),
    ("issuer_default_json", "GET", "issuer/default/json", "json", "issuer"),
)
NEGATIVES = (
    ("issue", "POST", "issue/leaf", {"common_name": "denied.example.test"}),
    ("revoke", "POST", "revoke", None),
    ("rotate", "GET", "crl/rotate", None),
    ("configuration", "GET", "config/crl", None),
    ("role", "GET", "roles/leaf", None),
)
SETUP_CASES = ("mount", "config", "mapping", "grant", "root", "root_sign_exact", "root_crypto_binding",
    "role", "owner_policy", "owner_token", "leaf", "leaf_sign_exact", "leaf_crypto_binding",
    "revoke", "revoke_sign_exact", "expired_token", "finite_token", "wrapping_token", "expired_lookup",
    "finite_before", "wrapping_before")

NATIVE_OWNER_CASES = ("candidate.owner_live_leaf", "candidate.owner_leaf_sign_exact", "candidate.owner_leaf_crypto_binding",
    "candidate.owner_revoke", "candidate.owner_revoked_full", "candidate.owner_revoked_delta",
    "candidate.owner_restart_health", "candidate.owner_restart_full", "candidate.owner_restart_delta")


def expected_cases():
    cases = ["candidate.binary_before_hash", "remote.health", "official.health", "candidate.health",
        "distinct_process_clusters", "oracle.selected_backend", "remote.mount", "remote.key", "remote.public_key"]
    for side in ("candidate", "official"):
        cases += [side + "." + name for name in SETUP_CASES]
        cases += [f"{side}.public.{mode}.{name}" for mode in TOKEN_MODES for name, *_ in ROUTES]
        cases += [side + "." + name for name in ("finite_after", "wrapping_after")]
        cases += [side + ".anonymous_denied." + name for name, *_ in NEGATIVES]
    for side in ("candidate", "official"):
        cases += [side + ".restart_health"]
        cases += [side + ".restart_public." + name for name, *_ in ROUTES]
    cases += list(NATIVE_OWNER_CASES)
    cases += ["candidate.audit_no_credentials", "owned_processes_cleared", "candidate.binary_after_hash"]
    return tuple(cases)


EXPECTED_CASES = expected_cases()
ORACLE_EXPECTED_CASES = tuple(case for case in EXPECTED_CASES if case not in NATIVE_OWNER_CASES)
PUBLIC_CASES = tuple(case for case in EXPECTED_CASES if ".public." in case)
RESTART_CASES = tuple(case for case in EXPECTED_CASES if ".restart_public." in case)
PUBLIC_REQUIRED_FIELDS = ("public_material_valid", "exact_response_shape", "private_fields_absent",
    "audit_request_delta", "audit_response_delta", "observed_provider_sign_entries", "content_type")


def trace_complete(rows, expected=EXPECTED_CASES):
    if not isinstance(rows, list) or tuple(row.get("case") for row in rows) != expected:
        return False
    if not all(row.get("passed") is True for row in rows):
        return False
    for row in rows:
        case = row["case"]
        if case in PUBLIC_CASES or case in RESTART_CASES:
            route = next(route for route in ROUTES if route[0] == case.rsplit(".", 1)[1])
            media = "application/json" if route[3] == "json" else route[3]
            if (type(row.get("status")) is not int or row.get("status") != 200 or any(field not in row for field in PUBLIC_REQUIRED_FIELDS)
                    or any(row.get(field) is not True for field in PUBLIC_REQUIRED_FIELDS[:3])
                    or any(type(row.get(field)) is not int for field in ("audit_request_delta", "audit_response_delta"))
                    or row.get("audit_request_delta") != 1 or row.get("audit_response_delta") != 1
                    or type(row.get("observed_provider_sign_entries")) is not int
                    or row["observed_provider_sign_entries"] != 0 or row.get("content_type") != media):
                return False
        if case.endswith("sign_exact"):
            expected = 3 if case.endswith("root_sign_exact") else 1 if case.endswith("leaf_sign_exact") else 2
            if (any(type(row.get(field)) is not int for field in ("observed_provider_sign_entries", "expected_provider_sign_entries"))
                    or row.get("observed_provider_sign_entries") != expected or row.get("expected_provider_sign_entries") != expected):
                return False
        if ".anonymous_denied." in case or case.startswith(("candidate.owner_revoked_", "candidate.owner_restart_")) and not case.endswith("health"):
            expected = 403 if ".anonymous_denied." in case else 503
            if (row.get("status") != expected or row.get("private_fields_absent") is not True
                    or type(row.get("observed_provider_sign_entries")) is not int or row.get("observed_provider_sign_entries") != 0):
                return False
    return True


def bounded_native_instance(smoke, binary, root):
    # Preserve original startup 100*50ms and TLS rejection. Only the original
    # transport cause for GET health reaches the existing readiness handler.
    class BoundedInstance(smoke.Instance):
        def call(self, method, path, body=None, *, token=None):
            selected = self.token if token is None else token
            client = Client(self.address, str(self.root / "ca.crt"), selected or "synthetic-uninitialized-client", timeout=2)
            try:
                response = client.request(method, "/v1/" + path, body, token=selected)
            except BaoError as error:
                if (method == "GET" and path == "sys/health" and str(error) == "transport_read_failed"
                        and isinstance(error.__context__, (OSError, urllib.error.URLError))):
                    raise error.__context__
                raise
            return response.status, response.body
    return BoundedInstance(binary, root)


def audit_counts(root, native):
    counts = {"request": 0, "response": 0}
    for line in (Path(root) / "audit.jsonl").read_text().splitlines():
        row = json.loads(line)
        kind = row.get("event", {}).get("kind") if native else row.get("type")
        if kind in counts:
            counts[kind] += 1
    return counts


def contains_private(value):
    if isinstance(value, dict):
        return any(key in ("private_key", "root_token", "client_token", "token", "keys_base64")
                   or contains_private(item) for key, item in value.items())
    return isinstance(value, list) and any(contains_private(item) for item in value)


def public_request(client, method, path, token):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["X-Vault-Token"] = token
    request = urllib.request.Request(client.address + "/v1/pki/" + path, headers=headers, method=method)
    try:
        response = client._opener.open(request, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read(512 * 1024 + 1)
        if len(payload) > 512 * 1024:
            raise shared.Failure("bounded_public_response")
        return response.status, response.headers.get("Content-Type", "").split(";", 1)[0], payload


RFC3339_NANOSECONDS = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.([0-9]{1,9}))?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def revocation_clock_matches(rfc, seconds):
    """Bind a parsed RFC3339 timestamp to its published whole UTC second.

    OpenBao 2.7.0 emits up to nanosecond precision. Calendar conversion uses
    integer UTC components, so fractional truncation cannot round into a new
    second. Zero is the API sentinel and requires the empty string.
    """
    if type(rfc) is not str or type(seconds) is not int:
        return False
    if seconds == 0:
        return rfc == ""
    if RFC3339_NANOSECONDS.fullmatch(rfc) is None:
        return False
    try:
        parsed = datetime.fromisoformat(rfc.replace("Z", "+00:00"))
        return calendar.timegm(parsed.astimezone(timezone.utc).utctimetuple()) == seconds
    except (ValueError, TypeError, OverflowError):
        return False


def material_predicates(route, payload, document, public):
    name, _method, _path, media, kind = route
    data = None
    body = json.loads(payload) if media == "json" else None
    if body is not None:
        data = body.get("data")
        if not isinstance(data, dict) or contains_private(body):
            return False, False, False
    shape = True
    expected_der = document["leaf_der"] if kind == "leaf" else document["ca_der"]
    material = True
    if kind in ("leaf", "ca", "chain", "issuer"):
        if media == "json":
            fields = {"certificate", "revocation_time", "revocation_time_rfc3339"}
            if kind == "leaf": fields.add("issuer_id")
            if kind == "chain": fields.add("ca_chain")
            if kind == "issuer": fields = {"certificate", "ca_chain", "issuer_id", "issuer_name"}
            shape = set(data) == fields and type(data.get("certificate")) is str
            cert = x509.load_pem_x509_certificate(data["certificate"].encode())
            canonical = cert.public_bytes(serialization.Encoding.PEM).decode()
            # Issuer projection returns canonical PEM; stored certificate and
            # chain JSON return the exact PEM without its final LF.
            expected_pem = canonical if kind == "issuer" else canonical[:-1]
            shape = shape and data["certificate"] == expected_pem
            if kind == "issuer":
                chain = data.get("ca_chain")
                shape = shape and data.get("issuer_id") == document["issuer_id"] and data.get("issuer_name") == "" and isinstance(chain, list) and len(chain) == 1
                if shape:
                    shape = chain[0] == canonical and x509.load_pem_x509_certificate(chain[0].encode()).public_bytes(serialization.Encoding.DER) == expected_der
            else:
                seconds = document["revocation_time"] if kind == "leaf" else 0
                shape = (shape and type(data.get("revocation_time")) is int
                    and data["revocation_time"] == seconds
                    and revocation_clock_matches(data.get("revocation_time_rfc3339"), seconds))
                if kind == "leaf": shape = shape and data.get("issuer_id") == document["issuer_id"]
                if kind == "chain":
                    shape = shape and type(data.get("ca_chain")) is str
                    if shape:
                        shape = data["ca_chain"] == canonical[:-1] and x509.load_pem_x509_certificate(data["ca_chain"].encode()).public_bytes(serialization.Encoding.DER) == expected_der
        else:
            cert = x509.load_der_x509_certificate(payload) if name.endswith("_der") else x509.load_pem_x509_certificate(payload)
            canonical = cert.public_bytes(serialization.Encoding.PEM)
            # Every selected public raw certificate/chain PEM endpoint omits
            # exactly the final LF. No format union.
            expected_pem = canonical[:-1]
            shape = payload == (expected_der if name.endswith("_der") else expected_pem)
        material = cert.public_bytes(serialization.Encoding.DER) == expected_der
        public.verify(cert.signature, cert.tbs_certificate_bytes)
    elif kind in ("full", "delta"):
        if media == "json":
            shape = set(data) == {"certificate", "revocation_time", "revocation_time_rfc3339"} and type(data["certificate"]) is str and type(data["revocation_time"]) is int and data["revocation_time"] == 0 and data["revocation_time_rfc3339"] == ""
            encoded = data["certificate"].encode()
        else:
            encoded = payload
        crl = x509.load_der_x509_crl(encoded) if name.endswith("_der") else x509.load_pem_x509_crl(encoded)
        expected_encoding = crl.public_bytes(serialization.Encoding.DER) if name.endswith("_der") else crl.public_bytes(serialization.Encoding.PEM)[:-1]
        shape = shape and encoded == expected_encoding
        public.verify(crl.signature, crl.tbs_certlist_bytes)
        expected_entries = [document["serial_int"]] if kind == "full" else []
        material = ([entry.serial_number for entry in crl] == expected_entries
                    and crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == (3 if kind == "full" else 4))
        if kind == "delta":
            material = material and crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator).value.crl_number == 3
        previous = document["crls"].setdefault(kind, crl.public_bytes(serialization.Encoding.DER))
        material = material and previous == crl.public_bytes(serialization.Encoding.DER)
    elif kind == "issuers":
        info = data.get("key_info", {}).get(document["issuer_id"], {})
        shape = (set(data) == {"keys", "key_info"} and data.get("keys") == [document["issuer_id"]]
            and isinstance(data.get("key_info"), dict) and set(data["key_info"]) == {document["issuer_id"]}
            and set(info) == {"is_default", "issuer_name", "key_id", "serial_number"}
            and info.get("is_default") is True and info.get("issuer_name") == ""
            and info.get("key_id") == document["key_id"] and info.get("serial_number") == document["root_serial"])
        material = shape
    return material is True, shape is True, body is None or not contains_private(body)


def shape_diagnostics(route, payload, document):
    if route[3] != "json":
        if route[0].endswith("_der"):
            return {}
        cert = x509.load_pem_x509_certificate(payload) if route[4] in ("leaf","ca","chain","issuer") else None
        crl = x509.load_pem_x509_crl(payload) if route[4] in ("full","delta") else None
        canonical = (cert or crl).public_bytes(serialization.Encoding.PEM)
        return {"raw_pem_canonical_exact":payload == canonical,
            "raw_pem_without_final_lf_exact":payload == canonical[:-1],
            "raw_pem_trailing_lf_count":len(payload)-len(payload.rstrip(b"\n")),
            "raw_pem_crlf_present":b"\r\n" in payload,
            "raw_pem_canonical_length_delta":len(payload)-len(canonical)}
    data = json.loads(payload).get("data", {})
    if not isinstance(data, dict): return {"public_data_is_object": False}
    facts = {"data_fields": sorted(data), "data_field_types": {key: type(value).__name__ for key, value in data.items()}}
    if route[4] in ("full","delta"):
        certificate = data.get("certificate")
        if isinstance(certificate,str):
            canonical = x509.load_pem_x509_crl(certificate.encode()).public_bytes(serialization.Encoding.PEM).decode()
            facts.update(crl_pem_canonical_exact=certificate == canonical,
                crl_pem_without_final_lf_exact=certificate == canonical[:-1],
                crl_pem_trailing_lf_count=len(certificate)-len(certificate.rstrip("\n")))
    if route[4] in ("leaf","ca","chain","issuer"):
        certificate = data.get("certificate")
        if isinstance(certificate,str) and certificate.startswith("-----BEGIN CERTIFICATE-----"):
            canonical = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(serialization.Encoding.PEM).decode()
            facts.update(certificate_canonical_exact=certificate == canonical,
                certificate_without_final_lf_exact=certificate == canonical[:-1],
                certificate_original_exact=certificate == document["leaf_pem" if route[4] == "leaf" else "root_pem"],
                certificate_trailing_lf_count=len(certificate)-len(certificate.rstrip("\n")))
            chain = data.get("ca_chain")
            if isinstance(chain,str):
                facts.update(chain_canonical_exact=chain == canonical,
                    chain_without_final_lf_exact=chain == canonical[:-1],
                    chain_certificate_equal=chain == certificate,
                    chain_trailing_lf_count=len(chain)-len(chain.rstrip("\n")))
    if route[4] == "leaf":
        seconds = data.get("revocation_time"); rfc = data.get("revocation_time_rfc3339")
        expected = datetime.fromtimestamp(document["revocation_time"], timezone.utc).isoformat().replace("+00:00", "Z")
        facts.update(certificate_matches_original=data.get("certificate") == document["leaf_pem"],
            issuer_matches_original=data.get("issuer_id") == document["issuer_id"],
            revocation_seconds_matches_original=seconds == document["revocation_time"],
            revocation_rfc_utc_canonical_seconds=rfc == expected)
        try: facts["revocation_rfc_seconds_match"] = isinstance(rfc, str) and int(datetime.fromisoformat(rfc.replace("Z", "+00:00")).timestamp()) == seconds
        except (ValueError, TypeError, OverflowError): facts["revocation_rfc_seconds_match"] = False
        if isinstance(rfc, str):
            match = RFC3339_NANOSECONDS.fullmatch(rfc)
            facts["revocation_rfc_lexically_valid"] = match is not None
            if match:
                fraction = match.group(1) or ""
                facts["revocation_rfc_fractional_digits"] = len(fraction)
                facts["revocation_rfc_fraction_nonzero"] = any(value != "0" for value in fraction)
                try:
                    parsed = datetime.fromisoformat(rfc.replace("Z", "+00:00"))
                    facts["revocation_rfc_timezone_offset_seconds"] = int(parsed.utcoffset().total_seconds())
                except (ValueError, TypeError, OverflowError): facts["revocation_rfc_parse_valid"] = False
                else:
                    facts["revocation_rfc_parse_valid"] = True
                    facts["revocation_rfc_seconds_floor_exact"] = type(seconds) is int and calendar.timegm(parsed.astimezone(timezone.utc).utctimetuple()) == seconds
    return facts


def observe_public(t, case, route, client, token, document, public, remote, audit_root, native):
    sign_before = leaf.sign_entries(remote)
    before = audit_counts(audit_root, native)
    status, media, payload = public_request(client, route[1], route[2].format(serial=document["serial"]), token)
    after = audit_counts(audit_root, native)
    delta = leaf.sign_entries(remote) - sign_before
    valid, exact, absent = (False, False, True)
    if status == 200:
        valid, exact, absent = material_predicates(route, payload, document, public)
    expected_media = "application/json" if route[3] == "json" else route[3]
    metadata = {"status": status, "content_type": media, "public_material_valid": valid,
        "exact_response_shape": exact, "private_fields_absent": absent,
        "audit_request_delta": after["request"] - before["request"],
        "audit_response_delta": after["response"] - before["response"], "observed_provider_sign_entries": delta}
    if status == 200: metadata.update(shape_diagnostics(route, payload, document))
    try:
        t.check(case, status == 200 and media == expected_media and valid and exact and absent
            and metadata["audit_request_delta"] == metadata["audit_response_delta"] == 1 and delta == 0, status)
    finally:
        if t.rows and t.rows[-1].get("case") == case: t.rows[-1].update(metadata)


def rejected(t, case, client, method, path, body, status, remote):
    before = leaf.sign_entries(remote)
    response = client.request(method, "/v1/pki/" + path, body, token="")
    absent = not contains_private(response.body)
    delta = leaf.sign_entries(remote) - before
    try: t.check(case, response.status == status and absent and delta == 0, response.status)
    finally:
        if t.rows and t.rows[-1].get("case") == case:
            t.rows[-1].update(private_fields_absent=absent, observed_provider_sign_entries=delta)


def run(binary, rows, *, oracle_contract=False):
    spec = importlib.util.spec_from_file_location("external_pki_public_smoke", ROOT / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-external-pki-public270-")); private_root.chmod(0o700)
    instances = []; native = None; contract = None; t = shared.Trace(rows); result = {}
    try:
        remote = start_oracle(shared.free_port(), version=VERSION, audit_file=True); instances.append(remote)
        official = start_oracle(shared.free_port(), version=VERSION, audit_file=True); instances.append(official)
        r = shared.oracle_client(remote); r.timeout = 2
        o = shared.oracle_client(official); o.timeout = 2
        remote_token = private_read(remote["token_file"], 8192).decode().strip(); ca = Path(remote["ca_file"]).read_text()
        if oracle_contract:
            contract = start_oracle(shared.free_port(), version=VERSION, audit_file=True); instances.append(contract)
            c = shared.oracle_client(contract); c.timeout = 2
            candidate_root = Path(contract["root"]); candidate_token = c._token
        else:
            native = bounded_native_instance(smoke, binary, private_root / "candidate")
            shared.native_configuration(native, remote, ca); native.start()
            status, initialized = native.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            if status != 200: raise shared.Failure("candidate_init")
            native.token, unseal = initialized["root_token"], initialized["keys_base64"][0]
            if native.call("POST", "sys/unseal", {"key": unseal})[0] != 200: raise shared.Failure("candidate_unseal")
            c = Client(native.address, str(native.root / "ca.crt"), native.token, timeout=2)
            candidate_root = native.root; candidate_token = native.token
        clients = {"candidate": c, "official": o}; roots = {"candidate": candidate_root, "official": Path(official["root"])}
        identities = {}; documents = {}; owners = {}
        for side, client in (("remote", r), ("official", o), ("candidate", c)):
            health = client.health()
            t.check(side + ".health", health.get("initialized") is True and health.get("sealed") is False
                and (side == "candidate" and not oracle_contract or health.get("version") == VERSION))
            identities[side] = {key: health[key] for key in ("cluster_id", "version")}
        t.check("distinct_process_clusters", len({value["cluster_id"] for value in identities.values()}) == 3)
        t.check("oracle.selected_backend", remote["storage_backend"] == official["storage_backend"] == "pebbledb"
            and (not oracle_contract or contract["storage_backend"] == "pebbledb"))
        t.call("remote.mount", r, "POST", "sys/mounts/transit", 204, {"type": "transit"})
        t.call("remote.key", r, "POST", "transit/keys/ca", 200, {"type": "ed25519"})
        descriptor = r.request("GET", "/v1/transit/keys/ca")
        raw = base64.b64decode(descriptor.body["data"]["keys"]["1"]["public_key"], validate=True)
        t.check("remote.public_key", descriptor.status == 200 and len(raw) == 32)
        public = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        for side, client in clients.items():
            prefix = side + "."; cfg = "sys/external-keys/configs/provider"
            config = {"plugin": "transit", "address": remote["address"], "token": remote_token, "mount_path": "transit", "verify": side == "official" or oracle_contract}
            if side == "official" or oracle_contract: config["tls_ca_cert_bytes"] = ca
            t.call(prefix + "mount", client, "POST", "sys/mounts/pki", 204, {"type": "pki"})
            t.call(prefix + "config", client, "POST", cfg, 204, config)
            t.call(prefix + "mapping", client, "POST", cfg + "/keys/fixed", 204, {"name": "ca", "version": 1, "verify": side == "official" or oracle_contract})
            t.call(prefix + "grant", client, "POST", cfg + "/keys/fixed/grants/pki", 204, {})
            before = leaf.sign_entries(remote); response = client.request("POST", "/v1/pki/root/generate/kms", {"external_key_ref": "provider:fixed", "common_name": "synthetic-public-ca.example.test", "ttl": "1h"})
            t.check(prefix + "root", response.status == 200, response.status); leaf.sign_count(t, prefix + "root_sign_exact", remote, before, 3)
            root_data = response.body["data"]; root_cert = x509.load_pem_x509_certificate(root_data["certificate"].encode())
            public.verify(root_cert.signature, root_cert.tbs_certificate_bytes)
            t.check(prefix + "root_crypto_binding", "private_key" not in root_data and root_cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == raw)
            t.call(prefix + "role", client, "POST", "pki/roles/leaf", 200, {"allowed_domains": ["example.test"], "allow_subdomains": True, "max_ttl": "30m", "generate_lease": True, "key_type": "ed25519"})
            policy = 'path "pki/issue/leaf" { capabilities = ["update"] }'
            t.call(prefix + "owner_policy", client, "PUT", "sys/policies/acl/public-leaf-owner", 204, {"policy": policy})
            owner = t.call(prefix + "owner_token", client, "POST", "auth/token/create", 200, {"policies": ["public-leaf-owner"], "no_default_policy": True, "ttl": "10m"})["auth"]["client_token"]
            owners[side] = owner
            before = leaf.sign_entries(remote)
            response = client.request("POST", "/v1/pki/issue/leaf", {"common_name": "leaf.example.test", "ttl": "10m"}, token=owner)
            t.check(prefix + "leaf", response.status == 200, response.status); leaf.sign_count(t, prefix + "leaf_sign_exact", remote, before, 1)
            data = response.body["data"]; issued = x509.load_pem_x509_certificate(data["certificate"].encode()); public.verify(issued.signature, issued.tbs_certificate_bytes)
            private = serialization.load_pem_private_key(data["private_key"].encode(), password=None)
            t.check(prefix + "leaf_crypto_binding", private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == issued.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            del private
            document = {"ca_der": root_cert.public_bytes(serialization.Encoding.DER), "leaf_der": issued.public_bytes(serialization.Encoding.DER),
                "root_pem": root_data["certificate"], "leaf_pem": data["certificate"],
                "serial": data["serial_number"], "serial_int": issued.serial_number, "issuer_id": root_data["issuer_id"],
                "key_id": root_data["key_id"], "root_serial": root_data["serial_number"], "crls": {}}
            data.clear(); response.body.clear()
            before = leaf.sign_entries(remote); response = client.request("POST", "/v1/pki/revoke", {"serial_number": document["serial"]})
            t.check(prefix + "revoke", response.status == 200, response.status); leaf.sign_count(t, prefix + "revoke_sign_exact", remote, before, 2)
            document["revocation_time"] = response.body["data"]["revocation_time"]; documents[side] = document
            expired = t.call(prefix + "expired_token", client, "POST", "auth/token/create", 200, {"policies": ["default"], "ttl": "1s", "renewable": False})["auth"]["client_token"]
            finite = t.call(prefix + "finite_token", client, "POST", "auth/token/create", 200, {"policies": ["default"], "ttl": "10m", "num_uses": 1, "renewable": False})["auth"]["client_token"]
            response = client.request("POST", "/v1/sys/wrapping/wrap", {"synthetic": True}, wrap_ttl="1m")
            t.check(prefix + "wrapping_token", response.status == 200, response.status); wrapping = response.body["wrap_info"]["token"]
            time.sleep(1.2)
            t.call(prefix + "expired_lookup", client, "POST", "auth/token/lookup", 403, {"token": expired})
            for mode, credential in (("finite", finite), ("wrapping", wrapping)):
                lookup = client.request("POST", "/v1/auth/token/lookup", {"token": credential})
                t.check(prefix + mode + "_before", lookup.status == 200 and lookup.body.get("data", {}).get("num_uses") == 1, lookup.status)
            modes = dict(header_absent=None, header_empty="", invalid="synthetic.invalid.public-read", expired=expired, finite=finite, wrapping=wrapping)
            for mode in TOKEN_MODES:
                for route in ROUTES:
                    observe_public(t, prefix + "public." + mode + "." + route[0], route, client, modes[mode], document, public, remote, roots[side], side == "candidate" and not oracle_contract)
            for mode, credential in (("finite", finite), ("wrapping", wrapping)):
                lookup = client.request("POST", "/v1/auth/token/lookup", {"token": credential})
                t.check(prefix + mode + "_after", lookup.status == 200 and lookup.body.get("data", {}).get("num_uses") == 1, lookup.status)
            for name, method, path, body in NEGATIVES:
                if name == "revoke": body = {"serial_number": document["serial"]}
                rejected(t, prefix + "anonymous_denied." + name, client, method, path, body, 403, remote)
        for side in clients:
            if side == "official": stop_oracle(official); restart_oracle(official); client = shared.oracle_client(official); client.timeout = 2
            elif oracle_contract: stop_oracle(contract); restart_oracle(contract); client = shared.oracle_client(contract); client.timeout = 2
            else:
                native.stop(); native.start()
                if native.call("POST", "sys/unseal", {"key": unseal})[0] != 200: raise shared.Failure("candidate_restart_unseal")
                client = Client(native.address, str(native.root / "ca.crt"), native.token, timeout=2)
            clients[side] = client
            t.check(side + ".restart_health", client.health()["cluster_id"] == identities[side]["cluster_id"])
            for route in ROUTES:
                observe_public(t, side + ".restart_public." + route[0], route, client, None, documents[side], public, remote, roots[side], side == "candidate" and not oracle_contract)
        if not oracle_contract:
            # A separately declared native-only safety section has no official
            # reference expectation and is excluded from oracle contract evidence.
            # Keep this certificate live until its actual owner is revoked;
            # the earlier explicitly revoked certificate cannot prove this fence.
            before = leaf.sign_entries(remote)
            response = clients["candidate"].request("POST", "/v1/pki/issue/leaf", {"common_name": "owned-live.example.test", "ttl": "10m"}, token=owners["candidate"])
            t.check("candidate.owner_live_leaf", response.status == 200, response.status)
            leaf.sign_count(t, "candidate.owner_leaf_sign_exact", remote, before, 1)
            data = response.body["data"]; issued = x509.load_pem_x509_certificate(data["certificate"].encode())
            public.verify(issued.signature, issued.tbs_certificate_bytes)
            private = serialization.load_pem_private_key(data["private_key"].encode(), password=None)
            t.check("candidate.owner_leaf_crypto_binding", private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == issued.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            del private
            data.clear(); response.body.clear()
            response = clients["candidate"].request("POST", "/v1/auth/token/revoke", {"token": owners["candidate"]})
            t.check("candidate.owner_revoke", response.status == 204, response.status)
            for kind, path in (("full", "crl"), ("delta", "crl/delta")):
                rejected(t, "candidate.owner_revoked_" + kind, clients["candidate"], "GET", path, None, 503, remote)
            native.stop(); native.start()
            if native.call("POST", "sys/unseal", {"key": unseal})[0] != 200: raise shared.Failure("owner_restart_unseal")
            clients["candidate"] = Client(native.address, str(native.root / "ca.crt"), native.token, timeout=2)
            t.check("candidate.owner_restart_health", clients["candidate"].health()["cluster_id"] == identities["candidate"]["cluster_id"])
            for kind, path in (("full", "crl"), ("delta", "crl/delta")):
                rejected(t, "candidate.owner_restart_" + kind, clients["candidate"], "GET", path, None, 503, remote)
        audit = (candidate_root / "audit.jsonl").read_text()
        t.check("candidate.audit_no_credentials", all(token not in audit for token in (remote_token, candidate_token, owners["candidate"])))
        result["identities"] = identities
    finally:
        native_handle = None if native is None else native.process
        if native: native.stop()
        for instance in reversed(instances): stop_oracle(instance)
        t.check("owned_processes_cleared", all(instance["process"].poll() is not None for instance in instances) and (native_handle is None or native_handle.poll() is not None))
    return result


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ("binary", "output", "build-source-commit", "build-source-tree", "expected-binary-sha256"): parser.add_argument("--" + name, required=True)
    parser.add_argument("--oracle-version", choices=(VERSION,), default=VERSION)
    parser.add_argument("--oracle-contract", action="store_true", help="QA contract preflight only; not candidate evidence")
    args = parser.parse_args(); binary = Path(args.binary).resolve(strict=True); output = Path(args.output).resolve()
    if output.exists(): parser.error("output already exists")
    stat = output.parent.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077: parser.error("output directory must be caller-owned mode 0700")
    for value, length in ((args.build_source_commit, 40), (args.build_source_tree, 40), (args.expected_binary_sha256, 64)):
        if len(value) != length or any(char not in "0123456789abcdef" for char in value): parser.error("source/binary identity malformed")
    pins = pinned_artifact(version=VERSION); rows = []
    report = {"schema": "heptabao.external-pki-public270-comparison.v1", "target_version": VERSION, "synthetic_only": True,
        "scope": "external_ed25519_17_public_routes_six_bearer_states_restart_and_native_owner_fence",
        "oracle_only": args.oracle_contract, "candidate_evidence": not args.oracle_contract,
        "full_openbao_compatibility": False, "compatibility_claim": False, "independent_qualification": False,
        "production_authority": False, "migration_authority": False, "release_authority": False,
        "build_source_commit": args.build_source_commit, "build_source_tree": args.build_source_tree,
        "expected_binary_sha256": args.expected_binary_sha256, "actual_binary_sha256_before": file_digest(binary),
        "oracle_binary_sha256": pins["binary_sha256"], "oracle_artifact_sha256": pins["artifact_sha256"],
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
        "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "runner_sha256": file_digest(__file__), "shared_leaf_runner_sha256": file_digest(leaf.__file__), "shared_transit_runner_sha256": file_digest(shared.__file__),
        "cargo_lock_sha256": file_digest(ROOT / "Cargo.lock"), "http_timeout_seconds": 2,
        "native_fixture_control_timeout_seconds": 2, "source_binary_binding": "recorded_not_independently_attested",
        "started_at_unix": time.time(), "required_case_count": len(ORACLE_EXPECTED_CASES if args.oracle_contract else EXPECTED_CASES), "required_public_case_count": len(PUBLIC_CASES), "cases": rows}
    try:
        shared.Trace(rows).check("candidate.binary_before_hash", report["actual_binary_sha256_before"] == args.expected_binary_sha256)
        report.update(run(binary, rows, oracle_contract=args.oracle_contract))
    except Exception as error:
        report["failure"] = str(error) if isinstance(error, shared.Failure) else type(error).__name__
    report["actual_binary_sha256_after"] = file_digest(binary)
    try: shared.Trace(rows).check("candidate.binary_after_hash", report["actual_binary_sha256_after"] == args.expected_binary_sha256)
    except shared.Failure as error: report["failure"] = str(error)
    complete = trace_complete(rows, ORACLE_EXPECTED_CASES if args.oracle_contract else EXPECTED_CASES)
    report.update(passed=not report.get("failure") and complete, finished_at_unix=time.time())
    private_write(output, report)
    print(json.dumps({"passed": report["passed"], "case_count": len(rows), "required_case_count": report["required_case_count"], "failure": report.get("failure"), "oracle_only": args.oracle_contract}))
    return 0 if report["passed"] else 1

if __name__ == "__main__": raise SystemExit(main())
