#!/usr/bin/env python3
"""Bounded external Transit interoperability on three fresh verified TLS servers.

Two checksum-pinned official 2.7.0 servers own the remote AES key and reference
external consumer. The production candidate CLI owns its independent external
consumer and deployment-enrolled egress. No existing endpoint/token is accepted.
Plaintext, ciphertext, credentials and provider configuration are never report
data. This profile does not qualify PKI, arbitrary KMS plugins or all-asset
migration; every wider authority remains false.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from official_openbao_launcher import (
    file_digest, pinned_artifact, restart_oracle, start_oracle, stop_oracle,
)

ROOT = Path(__file__).resolve().parents[2]
VERSION = "2.7.0"
CONFIG = "sys/external-keys/configs/provider"
PLAIN = base64.b64encode(b"external-transit270-synthetic-readback").decode()
AAD = base64.b64encode(b"external-transit270-synthetic-associated-data").decode()
DESCRIPTOR_FIELDS = frozenset(("allow_plaintext_backup", "auto_rotate_period",
    "deletion_allowed", "derived", "exportable", "imported_key", "keys",
    "latest_version", "min_available_version", "min_decryption_version",
    "min_encryption_version", "name", "soft_deleted", "supports_decryption",
    "supports_derivation", "supports_encryption", "supports_signing", "type"))
INITIAL_DESCRIPTOR = {"allow_plaintext_backup": False, "auto_rotate_period": 0,
    "deletion_allowed": False, "derived": False, "exportable": False,
    "imported_key": False, "keys": {"1": "provider:fixed1"}, "latest_version": 1,
    "min_available_version": 0, "min_decryption_version": 1, "min_encryption_version": 0,
    "name": "local", "soft_deleted": False, "supports_decryption": True,
    "supports_derivation": False, "supports_encryption": True,
    "supports_signing": False, "type": "external-key"}


class Failure(Exception):
    pass


def expected_cases():
    cases = ["candidate.binary_before_hash", "remote.health", "official.health", "candidate.health",
        "distinct_process_clusters", "oracle.selected_backend", "candidate.production_enrollment",
        "remote.mount", "remote.key", "remote.rotate", "remote.latest2"]
    for side in ("candidate", "official"):
        cases += [side + "." + name for name in ("mount", "config", "mapping1",
            "mapping2", "missing_grant_create", "missing_ref_create", "grant1",
            "grant2", "create", "descriptor")]
    for version in (1, 2):
        if version == 2:
            cases += [side + ".rotate_ref2" for side in ("candidate", "official")]
        for side in ("candidate", "official"):
            cases += [f"{side}.v{version}." + name for name in ("encrypt",
                "remote_readback", "remote_other_version_rejected", "own_decrypt", "cross_decrypt")]
    for side in ("candidate", "official"):
        cases += [side + "." + name for name in ("old_version_after_rotation",
            "minimum_config", "minimum_rejects_old", "minimum_allows_current",
            "grant_remove", "grant_removed_encrypt", "grant_removed_decrypt",
            "grant_restore", "grant_restored_decrypt", "acl_policy", "acl_token",
            "acl_denied", "namespace_create", "namespace_mount",
            "namespace_root_ref_denied", "namespace_config", "namespace_mapping",
            "namespace_grant", "namespace_key", "namespace_encrypt",
            "root_descriptor_unchanged")]
    cases += [side + ".namespace_cross_decrypt" for side in ("candidate", "official")]
    cases += ["remote.provider_namespace", "remote.provider_namespace_mount",
        "remote.provider_namespace_key"]
    for side in ("candidate", "official"):
        cases += [side + "." + name for name in ("remote_namespace_config",
            "remote_namespace_mapping", "remote_namespace_grant",
            "remote_namespace_key", "remote_namespace_encrypt")]
    cases += [side + ".remote_namespace_cross_decrypt" for side in ("candidate", "official")]
    cases += ["candidate.tls_skip_verify_config", "candidate.tls_skip_verify_refused",
        "candidate.restore_verified_config", "candidate.api_ca_override_config",
        "candidate.api_ca_override_refused", "candidate.restore_enrolled_config",
        "official.bad_ca_config", "official.bad_ca_refused", "official.restore_ca",
        "candidate.restart_health", "candidate.restart_decrypt",
        "official.restart_health", "official.restart_decrypt", "remote.restart_health",
        "candidate.remote_restart_decrypt", "official.remote_restart_decrypt",
        "candidate.wrong_deployment_ca_restart", "candidate.wrong_deployment_ca_refused",
        "candidate.wrong_deployment_ca_no_crypto_entry", "candidate.correct_ca_restart",
        "candidate.correct_ca_readback", "candidate.audit_no_credentials_or_plaintext", "candidate.binary_after_hash"]
    return tuple(cases)


EXPECTED_CASES = expected_cases()


def trace_complete(rows):
    return (tuple(row.get("case") for row in rows) == EXPECTED_CASES
        and all(row.get("passed") is True for row in rows))


def descriptor_matches(value, side="candidate"):
    # Python's bool is an int subclass; JSON number/boolean distinctions are
    # part of the descriptor contract, not interchangeable normalization.
    if side not in ("candidate", "official"):
        return False
    expected_descriptor = {**INITIAL_DESCRIPTOR, "supports_signing": side == "official"}
    return (type(value) is dict and value.keys() == expected_descriptor.keys()
        and all(type(value[key]) is type(expected) and value[key] == expected
            for key, expected in expected_descriptor.items()))


def remote_payload(ciphertext, version):
    if not isinstance(ciphertext, str) or not ciphertext.startswith(f"vault:v{version}:"):
        raise Failure("ciphertext_version_contract")
    payload = ciphertext.split(":", 2)[2]
    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, TypeError):
        raise Failure("ciphertext_base64_contract") from None
    if not 28 <= len(raw) <= 64 * 1024 + 64:
        raise Failure("ciphertext_bound_contract")
    # Exactly one wire representation. Nested vault-string envelopes are not a
    # second accepted format; actual remote readback validates the raw payload.
    return payload


class Trace:
    def __init__(self, rows):
        self.rows = rows

    def check(self, case, condition, status=None):
        self.rows.append({"case": case, "passed": condition is True,
            **({"status": status} if status is not None else {})})
        if condition is not True:
            raise Failure(case)

    def call(self, case, client, method, path, status, body=None, *, namespace="", token=None):
        scoped = copy.copy(client)
        scoped.namespace = namespace
        response = scoped.request(method, "/v1/" + path, body, token=token)
        self.check(case, response.status == status, response.status)
        return response.body


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def oracle_client(instance):
    return Client(instance["address"], instance["ca_file"],
        private_read(instance["token_file"], 8192).decode().strip())


def native_configuration(instance, remote, ca):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config.update(lifecycle_interval_seconds=0, outbound_endpoints=[{
        "origin": remote["address"], "address": remote["address"].removeprefix("https://"),
        "server_name": "127.0.0.1", "ca_pem": ca, "path_prefix": "/v1/transit/"}])
    path.write_text(json.dumps(config))
    path.chmod(0o600)


def restart_candidate(instance, unseal, remote, ca):
    instance.stop()
    native_configuration(instance, remote, ca)
    instance.start()
    if instance.call("POST", "sys/unseal", {"key": unseal})[0] != 200:
        raise Failure("candidate_restart_unseal")


def crypto_audit_count(remote):
    count = 0
    for line in (Path(remote["root"]) / "audit.jsonl").read_text().splitlines():
        record = json.loads(line)
        request = record.get("request", {})
        if record.get("type") == "request" and request.get("path", "").startswith((
                "transit/encrypt/", "transit/decrypt/")):
            count += 1
    return count


def run(binary, rows):
    spec = importlib.util.spec_from_file_location("external_consumer_smoke", ROOT / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-external-consumer270-"))
    private_root.chmod(0o700)
    instances = []
    native = None
    t = Trace(rows)
    try:
        remote = start_oracle(free_port(), version=VERSION, audit_file=True)
        instances.append(remote)
        official = start_oracle(free_port(), version=VERSION)
        instances.append(official)
        r, o = oracle_client(remote), oracle_client(official)
        remote_token = private_read(remote["token_file"], 8192).decode().strip()
        ca = Path(remote["ca_file"]).read_text()
        native = smoke.Instance(binary, private_root / "candidate")
        native_configuration(native, remote, ca)
        native.start()
        status, initialized = native.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise Failure("candidate_init")
        native.token, unseal = initialized["root_token"], initialized["keys_base64"][0]
        if native.call("POST", "sys/unseal", {"key": unseal})[0] != 200:
            raise Failure("candidate_unseal")
        c = Client(native.address, str(native.root / "ca.crt"), native.token)
        identities = {}
        for side, client in (("remote", r), ("official", o), ("candidate", c)):
            health = client.health()
            condition = health.get("initialized") is True and health.get("sealed") is False
            if side != "candidate":
                condition &= health.get("version") == VERSION
            t.check(side + ".health", condition)
            identities[side] = {key: health[key] for key in ("cluster_id", "version")}
        t.check("distinct_process_clusters", len({value["cluster_id"] for value in identities.values()}) == 3)
        t.check("oracle.selected_backend", remote["storage_backend"] == official["storage_backend"] == "pebbledb"
            and all(list(json.loads((Path(instance["root"]) / "server.json").read_text())["storage"]) == ["pebbledb"] for instance in (remote, official)))
        t.check("candidate.production_enrollment", native.process.poll() is None and
            json.loads((native.root / "server.json").read_text())["outbound_endpoints"][0]["path_prefix"] == "/v1/transit/")
        t.call("remote.mount", r, "POST", "sys/mounts/transit", 204, {"type": "transit"})
        t.call("remote.key", r, "POST", "transit/keys/remote", 200, {"type": "aes256-gcm96"})
        t.call("remote.rotate", r, "POST", "transit/keys/remote/rotate", 200, {})
        latest = r.request("GET", "/v1/transit/keys/remote")
        t.check("remote.latest2", latest.status == 200 and latest.body.get("data", {}).get("latest_version") == 2, latest.status)
        clients = {"candidate": c, "official": o}
        configs = {}
        for side, client in clients.items():
            t.call(side + ".mount", client, "POST", "sys/mounts/consumer", 204, {"type": "transit"})
            config = {"plugin": "transit", "address": remote["address"], "token": remote_token,
                "mount_path": "transit", "namespace": ""}
            if side == "official":
                config["tls_ca_cert_bytes"] = ca
            else:
                config["verify"] = False
            configs[side] = config
            t.call(side + ".config", client, "POST", CONFIG, 204, config)
            for version in (1, 2):
                mapping = {"name": "remote", "version": version}
                if side == "candidate":
                    mapping["verify"] = False
                t.call(side + f".mapping{version}", client, "POST", CONFIG + f"/keys/fixed{version}", 204, mapping)
            t.call(side + ".missing_grant_create", client, "POST", "consumer/keys/ungranted", 400,
                {"type": "external-key", "external_key_ref": "provider:fixed1"})
            t.call(side + ".missing_ref_create", client, "POST", "consumer/keys/missing", 400,
                {"type": "external-key", "external_key_ref": "absent:missing"})
            for version in (1, 2):
                t.call(side + f".grant{version}", client, "POST", CONFIG + f"/keys/fixed{version}/grants/consumer", 204)
            t.call(side + ".create", client, "POST", "consumer/keys/local", 200,
                {"type": "external-key", "external_key_ref": "provider:fixed1"})
            response = client.request("GET", "/v1/consumer/keys/local")
            data = response.body.get("data", {})
            t.check(side + ".descriptor", response.status == 200 and descriptor_matches(data, side), response.status)
        ciphertexts = {}
        for version in (1, 2):
            if version == 2:
                for side, client in clients.items():
                    t.call(side + ".rotate_ref2", client, "POST", "consumer/keys/local/rotate", 200,
                        {"external_key_ref": "provider:fixed2"})
            for side, client in clients.items():
                label = side + f".v{version}."
                response = client.request("POST", "/v1/consumer/encrypt/local", {"plaintext": PLAIN, "associated_data": AAD})
                data = response.body.get("data", {})
                t.check(label + "encrypt", response.status == 200 and set(data) == {"ciphertext", "key_version"}
                    and type(data.get("key_version")) is int and data.get("key_version") == version, response.status)
                ciphertext = data["ciphertext"]
                ciphertexts[side, version] = ciphertext
                payload = remote_payload(ciphertext, version)
                direct = r.request("POST", "/v1/transit/decrypt/remote", {"ciphertext": f"vault:v{version}:{payload}", "associated_data": AAD})
                t.check(label + "remote_readback", direct.status == 200 and direct.body.get("data") == {"plaintext": PLAIN}, direct.status)
                wrong = r.request("POST", "/v1/transit/decrypt/remote", {"ciphertext": f"vault:v{3-version}:{payload}", "associated_data": AAD})
                t.check(label + "remote_other_version_rejected", wrong.status == 400, wrong.status)
                for name, decryptor in (("own_decrypt", client), ("cross_decrypt", clients["official" if side == "candidate" else "candidate"])):
                    decrypted = decryptor.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertext, "associated_data": AAD})
                    t.check(label + name, decrypted.status == 200 and decrypted.body.get("data") == {"plaintext": PLAIN}, decrypted.status)
        for side, client in clients.items():
            old = client.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts[side, 1], "associated_data": AAD})
            t.check(side + ".old_version_after_rotation", old.status == 200 and old.body.get("data") == {"plaintext": PLAIN}, old.status)
            t.call(side + ".minimum_config", client, "POST", "consumer/keys/local/config", 200,
                {"min_encryption_version": 2, "min_decryption_version": 2})
            t.call(side + ".minimum_rejects_old", client, "POST", "consumer/decrypt/local", 400,
                {"ciphertext": ciphertexts[side, 1], "associated_data": AAD})
            current = client.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts[side, 2], "associated_data": AAD})
            t.check(side + ".minimum_allows_current", current.status == 200 and current.body.get("data") == {"plaintext": PLAIN}, current.status)
            grant = CONFIG + "/keys/fixed2/grants/consumer"
            t.call(side + ".grant_remove", client, "DELETE", grant, 204)
            t.call(side + ".grant_removed_encrypt", client, "POST", "consumer/encrypt/local", 400, {"plaintext": PLAIN})
            t.call(side + ".grant_removed_decrypt", client, "POST", "consumer/decrypt/local", 400, {"ciphertext": ciphertexts[side, 2], "associated_data": AAD})
            t.call(side + ".grant_restore", client, "POST", grant, 204)
            restored = client.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts[side, 2], "associated_data": AAD})
            t.check(side + ".grant_restored_decrypt", restored.status == 200 and restored.body.get("data") == {"plaintext": PLAIN}, restored.status)
            t.call(side + ".acl_policy", client, "POST", "sys/policies/acl/external-denied", 204,
                {"policy": 'path "consumer/keys/*" { capabilities = ["read"] }'})
            token = t.call(side + ".acl_token", client, "POST", "auth/token/create", 200,
                {"policies": ["external-denied"], "no_default_policy": True})["auth"]["client_token"]
            t.call(side + ".acl_denied", client, "POST", "consumer/encrypt/local", 403, {"plaintext": PLAIN}, token=token)
            t.call(side + ".namespace_create", client, "POST", "sys/namespaces/team", 200, {})
            t.call(side + ".namespace_mount", client, "POST", "sys/mounts/consumer", 204, {"type": "transit"}, namespace="team")
            t.call(side + ".namespace_root_ref_denied", client, "POST", "consumer/keys/local", 400,
                {"type": "external-key", "external_key_ref": "provider:fixed1"}, namespace="team")
            t.call(side + ".namespace_config", client, "POST", CONFIG, 204, configs[side], namespace="team")
            mapping = {"name": "remote", "version": 1, **({"verify": False} if side == "candidate" else {})}
            t.call(side + ".namespace_mapping", client, "POST", CONFIG + "/keys/fixed1", 204, mapping, namespace="team")
            t.call(side + ".namespace_grant", client, "POST", CONFIG + "/keys/fixed1/grants/consumer", 204, namespace="team")
            t.call(side + ".namespace_key", client, "POST", "consumer/keys/local", 200,
                {"type": "external-key", "external_key_ref": "provider:fixed1"}, namespace="team")
            team = copy.copy(client)
            team.namespace = "team"
            encrypted = team.request("POST", "/v1/consumer/encrypt/local", {"plaintext": PLAIN, "associated_data": AAD})
            t.check(side + ".namespace_encrypt", encrypted.status == 200 and type(encrypted.body.get("data", {}).get("key_version")) is int
                and encrypted.body.get("data", {}).get("key_version") == 1, encrypted.status)
            ciphertexts[side, "team"] = encrypted.body["data"]["ciphertext"]
            descriptor = client.request("GET", "/v1/consumer/keys/local")
            t.check(side + ".root_descriptor_unchanged", descriptor.status == 200 and descriptor.body.get("data", {}).get("latest_version") == 2, descriptor.status)
        for side, client in clients.items():
            peer = copy.copy(clients["official" if side == "candidate" else "candidate"])
            peer.namespace = "team"
            decrypted = peer.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts[side, "team"], "associated_data": AAD})
            t.check(side + ".namespace_cross_decrypt", decrypted.status == 200 and decrypted.body.get("data") == {"plaintext": PLAIN}, decrypted.status)
        t.call("remote.provider_namespace", r, "POST", "sys/namespaces/provider-team", 200, {})
        t.call("remote.provider_namespace_mount", r, "POST", "sys/mounts/transit", 204, {"type": "transit"}, namespace="provider-team")
        t.call("remote.provider_namespace_key", r, "POST", "transit/keys/remote", 200, {"type": "aes256-gcm96"}, namespace="provider-team")
        for side, client in clients.items():
            cfg = {**configs[side], "namespace": "provider-team"}
            path = "sys/external-keys/configs/namespaced"
            t.call(side + ".remote_namespace_config", client, "POST", path, 204, cfg)
            mapping = {"name": "remote", "version": 1, **({"verify": False} if side == "candidate" else {})}
            t.call(side + ".remote_namespace_mapping", client, "POST", path + "/keys/fixed", 204, mapping)
            t.call(side + ".remote_namespace_grant", client, "POST", path + "/keys/fixed/grants/consumer", 204)
            t.call(side + ".remote_namespace_key", client, "POST", "consumer/keys/namespaced", 200,
                {"type": "external-key", "external_key_ref": "namespaced:fixed"})
            encrypted = client.request("POST", "/v1/consumer/encrypt/namespaced", {"plaintext": PLAIN, "associated_data": AAD})
            t.check(side + ".remote_namespace_encrypt", encrypted.status == 200, encrypted.status)
            ciphertexts[side, "provider-team"] = encrypted.body["data"]["ciphertext"]
        for side, client in clients.items():
            peer = clients["official" if side == "candidate" else "candidate"]
            decrypted = peer.request("POST", "/v1/consumer/decrypt/namespaced", {"ciphertext": ciphertexts[side, "provider-team"], "associated_data": AAD})
            t.check(side + ".remote_namespace_cross_decrypt", decrypted.status == 200 and decrypted.body.get("data") == {"plaintext": PLAIN}, decrypted.status)
        t.call("candidate.tls_skip_verify_config", c, "POST", CONFIG, 204, {**configs["candidate"], "tls_skip_verify": True})
        t.call("candidate.tls_skip_verify_refused", c, "POST", "consumer/encrypt/local", 400, {"plaintext": PLAIN})
        t.call("candidate.restore_verified_config", c, "POST", CONFIG, 204, configs["candidate"])
        t.call("candidate.api_ca_override_config", c, "POST", CONFIG, 204, {**configs["candidate"], "tls_ca_cert_bytes": ca})
        t.call("candidate.api_ca_override_refused", c, "POST", "consumer/encrypt/local", 501, {"plaintext": PLAIN})
        t.call("candidate.restore_enrolled_config", c, "POST", CONFIG, 204, configs["candidate"])
        t.call("official.bad_ca_config", o, "POST", CONFIG, 204, {**configs["official"], "verify": False, "tls_ca_cert_bytes": (native.root / "ca.crt").read_text()})
        t.call("official.bad_ca_refused", o, "POST", "consumer/encrypt/local", 400, {"plaintext": PLAIN})
        t.call("official.restore_ca", o, "POST", CONFIG, 204, configs["official"])
        restart_candidate(native, unseal, remote, ca)
        t.check("candidate.restart_health", c.health()["cluster_id"] == identities["candidate"]["cluster_id"])
        data = c.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts["official", 2], "associated_data": AAD})
        t.check("candidate.restart_decrypt", data.status == 200 and data.body.get("data") == {"plaintext": PLAIN}, data.status)
        stop_oracle(official)
        restart_oracle(official)
        t.check("official.restart_health", o.health()["cluster_id"] == identities["official"]["cluster_id"])
        data = o.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts["candidate", 2], "associated_data": AAD})
        t.check("official.restart_decrypt", data.status == 200 and data.body.get("data") == {"plaintext": PLAIN}, data.status)
        stop_oracle(remote)
        restart_oracle(remote)
        t.check("remote.restart_health", r.health()["version"] == VERSION and r.health()["cluster_id"] == identities["remote"]["cluster_id"])
        for side, client in clients.items():
            data = client.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts["official" if side == "candidate" else "candidate", 2], "associated_data": AAD})
            t.check(side + ".remote_restart_decrypt", data.status == 200 and data.body.get("data") == {"plaintext": PLAIN}, data.status)
        before = crypto_audit_count(remote)
        restart_candidate(native, unseal, remote, (native.root / "ca.crt").read_text())
        t.check("candidate.wrong_deployment_ca_restart", c.health()["cluster_id"] == identities["candidate"]["cluster_id"])
        t.call("candidate.wrong_deployment_ca_refused", c, "POST", "consumer/encrypt/local", 503, {"plaintext": PLAIN})
        t.check("candidate.wrong_deployment_ca_no_crypto_entry", crypto_audit_count(remote) == before)
        restart_candidate(native, unseal, remote, ca)
        t.check("candidate.correct_ca_restart", c.health()["cluster_id"] == identities["candidate"]["cluster_id"])
        data = c.request("POST", "/v1/consumer/decrypt/local", {"ciphertext": ciphertexts["official", 2], "associated_data": AAD})
        t.check("candidate.correct_ca_readback", data.status == 200 and data.body.get("data") == {"plaintext": PLAIN}, data.status)
        audit = (native.root / "audit.jsonl").read_bytes()
        t.check("candidate.audit_no_credentials_or_plaintext", all(value.encode() not in audit
            for value in (remote_token, native.token, PLAIN, AAD, base64.b64decode(PLAIN).decode())))
        return {"identities": identities, "oracle_storage_backends": {"remote": remote["storage_backend"], "official": official["storage_backend"]}}
    finally:
        if native is not None:
            native.stop()
        for instance in reversed(instances):
            stop_oracle(instance)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--oracle-version", choices=(VERSION,), default=VERSION)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--build-source-tree", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    args = parser.parse_args()
    if (not re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit)
            or not re.fullmatch(r"[0-9a-f]{40}", args.build_source_tree)
            or not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256)):
        parser.error("build source and expected binary hashes must be exact lowercase digests")
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    if output.exists():
        parser.error("output already exists")
    parent = output.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        parser.error("output directory must be caller-owned mode 0700")
    pins = pinned_artifact(version=args.oracle_version)
    rows = []
    result = {"schema": "heptabao.external-transit-consumer270-comparison.v1",
        "target_version": args.oracle_version, "synthetic_only": True,
        "full_openbao_compatibility": False, "compatibility_claim": False,
        "independent_qualification": False, "production_authority": False,
        "migration_authority": False, "release_authority": False,
        "scope": "single_aes_remote_transit_external_consumers_bilateral_ciphertext_readback",
        "candidate_registry_verify": False, "official_registry_verify": True,
        "descriptor_signing_capability": {"candidate": False, "official": True},
        "deliberate_capability_differences": ["candidate external consumer implements encryption/decryption only; official advertises signing"],
        "candidate_transport_authority": "production_cli_deployment_enrolled_https",
        "build_source_commit": args.build_source_commit, "build_source_tree": args.build_source_tree,
        "expected_binary_sha256": args.expected_binary_sha256,
        "actual_binary_sha256_before": file_digest(binary), "oracle_binary_sha256": pins["binary_sha256"],
        "oracle_artifact_sha256": pins["artifact_sha256"],
        "runner_sha256": file_digest(__file__), "cargo_lock_sha256": file_digest(ROOT / "Cargo.lock"),
        "launcher_sha256": file_digest(ROOT / "qa/openbao-acceptance/official_openbao_launcher.py"),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "source_binary_binding": "recorded_not_independently_attested",
        "started_at_unix": time.time(), "cases": rows, "required_case_count": len(EXPECTED_CASES),
        "deliberate_transport_differences": ["candidate refuses API TLS trust overrides and skip-verify; only immutable deployment enrollment is authoritative"]}
    try:
        Trace(rows).check("candidate.binary_before_hash", result["actual_binary_sha256_before"] == args.expected_binary_sha256)
        result.update(run(binary, rows))
        result["passed"] = False
    except (Failure, BaoError) as error:
        result.update(passed=False, failure=str(error) if isinstance(error, Failure) else type(error).__name__)
    except Exception as error:
        result.update(passed=False, failure="unexpected_" + type(error).__name__)
    try:
        result["actual_binary_sha256_after"] = file_digest(binary)
        Trace(rows).check("candidate.binary_after_hash", result["actual_binary_sha256_after"] == args.expected_binary_sha256)
    except Exception:
        result.update(passed=False, failure=result.get("failure", "candidate_binary_after_hash_unavailable_or_mismatch"))
    result["candidate_binary_sha256"] = result["actual_binary_sha256_before"]
    result["passed"] = not result.get("failure") and trace_complete(rows)
    result["finished_at_unix"] = time.time()
    private_write(output, result)
    print(json.dumps({"passed": result["passed"], "case_count": len(rows), "required_case_count": len(EXPECTED_CASES),
        "failure": result.get("failure"), "full_openbao_compatibility": False, "production_authority": False}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
