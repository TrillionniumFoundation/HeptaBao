#!/usr/bin/env python3
"""Pure ML-DSA, independently exercised on disposable native 2.7.0 services.

Only case labels, status codes and predicates reach reports. Seeds, signatures
and fixture bearers remain inside each service's private test lifetime.
"""
import base64
import hashlib
from pathlib import Path
from core_isolation import ScenarioFailure, main as compare

_CONTEXT = {}
KINDS = (("mldsa-44", 1312, 2420), ("mldsa-65", 1952, 3309), ("mldsa-87", 2592, 4627))


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, name, condition):
        row = {"case": "mldsa270." + name, "passed": bool(condition)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, status, body=None, token=None):
        response = self.client.request(method, "/v1/" + path, body, token=token)
        row = {"case": "mldsa270." + name, "status": response.status,
               "passed": response.status == status}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body


def raw(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ScenarioFailure("mldsa270.invalid_encoding") from None


def run_scenarios(client, rows=None):
    rows = [] if rows is None else rows
    t = Trace(client, rows)
    t.call("mount", "POST", "sys/mounts/mlfixture", 204, {"type": "transit"})
    contexts = []
    for kind, public_len, signature_len in KINDS:
        path = "mlfixture/keys/" + kind
        t.call(kind + ".create", "POST", path, 200, {"type": kind, "exportable": True})
        data = t.call(kind + ".read", "GET", path, 200)["data"]
        t.check(kind + ".type_and_capabilities", data["type"] == kind
                and data["supports_signing"] is True and data["supports_encryption"] is False)
        public = data["keys"]["1"]["public_key"]
        t.check(kind + ".public_length", len(raw(public)) == public_len)
        exported = t.call(kind + ".export_public", "GET", "mlfixture/export/public-key/" + kind, 200)
        t.check(kind + ".public_matches", exported["data"]["keys"]["1"] == public)
        exported = t.call(kind + ".export_seed", "GET", "mlfixture/export/signing-key/" + kind, 200)
        t.check(kind + ".seed_length", len(raw(exported["data"]["keys"]["1"])) == 32)
        del exported
        message = base64.b64encode(("synthetic:" + kind).encode()).decode()
        sigs = []
        for i in range(2):
            result = t.call(kind + ".sign." + str(i), "POST", "mlfixture/sign/" + kind,
                            200, {"input": message})["data"]
            signature = result["signature"]
            t.check(kind + ".signature_shape." + str(i), result["key_version"] == 1
                    and signature.startswith("vault:v1:") and len(raw(signature[9:])) == signature_len)
            sigs.append(signature)
        t.check(kind + ".randomized", sigs[0] != sigs[1])
        for label, message_value, valid in (("valid", message, True),
                                           ("changed", base64.b64encode(b"changed").decode(), False)):
            result = t.call(kind + ".verify." + label, "POST", "mlfixture/verify/" + kind,
                            200, {"input": message_value, "signature": sigs[0]})
            t.check(kind + ".verified." + label, result["data"]["valid"] is valid)
        # FIPS 204 pure preprocessing, independently computed from this side's
        # public key. Signature and seed bytes never enter the report.
        tr = hashlib.shake_256(raw(public)).digest(64)
        mu = hashlib.shake_256(tr + b"\x00\x00" + raw(message)).digest(64)
        mu_input = base64.b64encode(mu).decode()
        result = t.call(kind + ".mu_sign", "POST", "mlfixture/sign/" + kind,
                        200, {"input": mu_input, "prehashed": True,
                              "hash_algorithm": "mldsa-mu"})["data"]
        mu_signature = result["signature"]
        t.check(kind + ".mu_signature_shape", result["key_version"] == 1
                and mu_signature.startswith("vault:v1:")
                and len(raw(mu_signature[9:])) == signature_len)
        result = t.call(kind + ".mu_verify_original", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": mu_signature})
        t.check(kind + ".mu_original_valid", result["data"]["valid"] is True)
        result = t.call(kind + ".mu_verify_changed", "POST", "mlfixture/verify/" + kind,
                        200, {"input": base64.b64encode(b"changed").decode(),
                              "signature": mu_signature})
        t.check(kind + ".mu_changed_invalid", result["data"]["valid"] is False)
        t.call(kind + ".mu_verification_not_supported", "POST", "mlfixture/verify/" + kind,
               400, {"input": mu_input, "prehashed": True,
                     "hash_algorithm": "mldsa-mu", "signature": mu_signature})
        t.call(kind + ".mu_requires_prehashed", "POST", "mlfixture/sign/" + kind,
               400, {"input": mu_input, "hash_algorithm": "mldsa-mu"})
        for length in (63, 65):
            t.call(kind + ".mu_length_" + str(length), "POST", "mlfixture/sign/" + kind,
                   500, {"input": base64.b64encode(bytes(length)).decode(),
                         "hash_algorithm": "mldsa-mu", "prehashed": True})
        result = t.call(kind + ".pure_options_ignored", "POST", "mlfixture/sign/" + kind,
                        200, {"input": message, "hash_algorithm": "sha2-512",
                              "prehashed": True, "context": "non-derived-context"})["data"]
        result = t.call(kind + ".pure_verify_default", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": result["signature"],
                              "context": "different-ignored-context"})
        t.check(kind + ".pure_options_no_hash_or_derivation", result["data"]["valid"] is True)
        t.call(kind + ".rotate", "POST", path + "/rotate", 200, {})
        result = t.call(kind + ".sign_rotated", "POST", "mlfixture/sign/" + kind,
                        200, {"input": message})["data"]
        t.check(kind + ".rotated_version", result["key_version"] == 2
                and result["signature"].startswith("vault:v2:"))
        t.call(kind + ".bad_base64", "POST", "mlfixture/sign/" + kind, 400, {"input": "!"})
        contexts.append((kind, message, sigs[0], result["signature"], mu_signature))
    t.call("least_privilege_policy", "POST", "sys/policies/acl/mlfixture-signer", 204,
           {"policy": 'path "mlfixture/sign/*" { capabilities=["update"] }'})
    issued = t.call("least_privilege_token", "POST", "auth/token/create", 200,
                    {"policies": ["mlfixture-signer"], "no_default_policy": True, "ttl": "10m"})
    signer = issued["auth"]["client_token"]
    t.call("least_privilege_sign", "POST", "mlfixture/sign/mldsa-44", 200, {"input": "eA=="}, signer)
    t.call("least_privilege_export_denied", "GET", "mlfixture/export/signing-key/mldsa-44", 403, token=signer)
    t.call("least_privilege_rotate_denied", "POST", "mlfixture/keys/mldsa-44/rotate", 403, {}, signer)
    _CONTEXT[id(rows)] = contexts
    return rows


def run_after_restart(client, rows):
    contexts = _CONTEXT.pop(id(rows), None)
    if not contexts or len(contexts) != len(KINDS):
        raise ScenarioFailure("mldsa270.restart_context_missing")
    t = Trace(client, rows)
    for kind, message, old, new, mu_signature in contexts:
        for label, signature in (("old", old), ("new", new), ("mu", mu_signature)):
            result = t.call(kind + ".restart_verify." + label, "POST", "mlfixture/verify/" + kind,
                            200, {"input": message, "signature": signature})
            t.check(kind + ".restart_valid." + label, result["data"]["valid"] is True)
        configured = t.call(kind + ".minimum_version", "POST",
                            "mlfixture/keys/" + kind + "/config", 200,
                            {"min_decryption_version": 2})["data"]
        t.check(kind + ".minimum_version_readback",
                configured["type"] == kind and configured["latest_version"] == 2
                and configured["min_decryption_version"] == 2)
        t.call(kind + ".retired_signature_denied", "POST", "mlfixture/verify/" + kind,
               400, {"input": message, "signature": old})
        result = t.call(kind + ".current_signature_retained", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": new})
        t.check(kind + ".current_valid", result["data"]["valid"] is True)
    t.check("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="transit-mldsa270", required_oracle_version="2.7.0",
                   scope="mldsa_pure_and_external_mu_signing_rotation_export_acl_and_native_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
