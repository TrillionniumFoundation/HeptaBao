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



def signing_options_cases():
    yield "pki_wire", {"key_version": "1", "prehashed": False,
                       "signature_algorithm": "pkcs1v15"}, 200, ""
    for index, value in enumerate(("pkcs1v15", "pss", "garbage", "", None, False, 7)):
        yield "rsa_padding_ignored." + str(index), {"signature_algorithm": value}, 200, ""
    for index, value in enumerate(("asn1", "jws", "garbage", "", None, False, 7)):
        yield "marshaling." + str(index), {"marshaling_algorithm": value}, (200 if index < 2 else 400), ""
    for prehashed in (False, True):
        for index, value in enumerate(("none", "sha2-256", "sha2-512", "sha1", "garbage", "")):
            yield "hash." + str(prehashed) + "." + str(index), {"prehashed": prehashed, "hash_algorithm": value}, (400 if value == "garbage" else 200), ""
    for index, value in enumerate((None, False, 7)):
        yield "hash_type." + str(index), {"hash_algorithm": value}, (200 if value is None else 400), ""
    for index, value in enumerate((None, "true", "false", "TRUE", "t", "1", "0", "", "garbage", 0, 1, 2, -1, 1.5, [], {})):
        yield "prehashed_type." + str(index), {"prehashed": value}, (400 if index in (8, 11, 12, 13, 14, 15) else 200), ""
    for label, options, suffix in (("path_only", {}, "/sha2-256"),
                                   ("path_over_body", {"hash_algorithm": "sha2-512"}, "/sha2-256"),
                                   ("path_over_empty", {"hash_algorithm": ""}, "/sha2-256"),
                                   ("path_over_null", {"hash_algorithm": None}, "/sha2-256"),
                                   ("path_over_invalid", {"hash_algorithm": "garbage"}, "/none")):
        yield label, options, 200, suffix


def run_signing_options(t, kind, message, baseline, signature_len):
    for label, options, status, suffix in signing_options_cases():
        name = kind + ".options." + label
        result = t.call(name + ".sign", "POST", "mlfixture/sign/" + kind + suffix,
                        status, dict(options, input=message))
        signature = result.get("data", {}).get("signature", baseline)
        verified = t.call(name + ".verify", "POST", "mlfixture/verify/" + kind + suffix,
                          status, dict(options, input=message, signature=signature))
        if status != 200:
            continue
        t.check(name + ".valid", verified["data"]["valid"] is True)
        t.check(name + ".version", result["data"]["key_version"] == 1
                and signature.startswith("vault:v1:"))
        if options.get("marshaling_algorithm") == "jws":
            payload = signature[9:]
            decoded = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
            t.check(name + ".encoding", len(decoded) == signature_len
                    and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == payload)
            # An all-0xff signature forces the URL-only alphabet, so the
            # standard parser rejection does not depend on randomized bytes.
            invalid = "vault:v1:" + base64.urlsafe_b64encode(bytes([255]) * signature_len).decode().rstrip("=")
            t.call(name + ".standard_encoding_rejected", "POST", "mlfixture/verify/" + kind,
                   400, {"input": message, "signature": invalid})
        else:
            ordinary = t.call(name + ".ordinary_verify", "POST", "mlfixture/verify/" + kind,
                              200, {"input": message, "signature": signature})
            t.check(name + ".pure_message", ordinary["data"]["valid"] is True)
        changed = t.call(name + ".changed_verify", "POST", "mlfixture/verify/" + kind + suffix,
                         200, dict(options, input=base64.b64encode(b"changed options message").decode(), signature=signature))
        t.check(name + ".changed_invalid", changed["data"]["valid"] is False)



def run_signing_context(t, kind, message, baseline):
    values = ((base64.b64encode(b"synthetic ignored context").decode(), 200),
              ("!", 400), ("non-derived-context", 400), ("", 200), (None, 200),
              (False, 400), (True, 400), (0, 400), (7, 400), (17, 400),
              (1234, 200), ([], 400), ({}, 400), (1234.0, 400),
              (12345678, 200), (1e19, 400), (10**19, 200), (-1234, 400))
    for index, (context, status) in enumerate(values):
        name = kind + ".context." + str(index)
        result = t.call(name + ".sign", "POST", "mlfixture/sign/" + kind,
                        status, {"input": message, "context": context})
        signature = result.get("data", {}).get("signature", baseline)
        verified = t.call(name + ".verify", "POST", "mlfixture/verify/" + kind,
                          status, {"input": message, "signature": signature, "context": context})
        if status != 200:
            continue
        t.check(name + ".valid", verified["data"]["valid"] is True)
        default = t.call(name + ".default_verify", "POST", "mlfixture/verify/" + kind,
                         200, {"input": message, "signature": signature})
        t.check(name + ".pure_message", default["data"]["valid"] is True)
        different = t.call(name + ".different_context_verify", "POST", "mlfixture/verify/" + kind,
                           200, {"input": message, "signature": signature,
                                 "context": base64.b64encode(b"different ignored context").decode()})
        t.check(name + ".context_is_not_derivation", different["data"]["valid"] is True)
        changed = t.call(name + ".changed_verify", "POST", "mlfixture/verify/" + kind,
                         200, {"input": base64.b64encode(b"changed context message").decode(),
                               "signature": signature, "context": context})
        t.check(name + ".changed_invalid", changed["data"]["valid"] is False)


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
        run_signing_options(t, kind, message, sigs[0], signature_len)
        run_signing_context(t, kind, message, sigs[0])
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
        extra = t.call(kind + ".mu_pki_jws_string_prehashed", "POST", "mlfixture/sign/" + kind + "/mldsa-mu",
                       200, {"input": mu_input, "hash_algorithm": "none", "prehashed": "true",
                             "signature_algorithm": "pkcs1v15", "marshaling_algorithm": "jws"})["data"]
        result = t.call(kind + ".mu_pki_jws_verify_original", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": extra["signature"], "marshaling_algorithm": "jws"})
        t.check(kind + ".mu_pki_jws_original_valid", result["data"]["valid"] is True)
        t.call(kind + ".mu_path_precedes_body_length", "POST", "mlfixture/sign/" + kind + "/mldsa-mu",
               500, {"input": base64.b64encode(bytes(63)).decode(), "hash_algorithm": "none", "prehashed": True})
        result = t.call(kind + ".pure_path_precedes_body_mu", "POST", "mlfixture/sign/" + kind + "/none",
                        200, {"input": message, "hash_algorithm": "mldsa-mu", "prehashed": True})
        result = t.call(kind + ".pure_path_verify", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": result["data"]["signature"]})
        t.check(kind + ".pure_path_original_valid", result["data"]["valid"] is True)
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
                              "prehashed": True, "context": base64.b64encode(b"non-derived-context").decode()})["data"]
        result = t.call(kind + ".pure_verify_default", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": result["signature"],
                              "context": base64.b64encode(b"different-ignored-context").decode()})
        t.check(kind + ".pure_options_no_hash_or_derivation", result["data"]["valid"] is True)
        t.call(kind + ".invalid_context_sign", "POST", "mlfixture/sign/" + kind,
               400, {"input": message, "context": "non-derived-context"})
        t.call(kind + ".invalid_context_verify", "POST", "mlfixture/verify/" + kind,
               400, {"input": message, "signature": sigs[0], "context": "!"})
        t.call(kind + ".rotate", "POST", path + "/rotate", 200, {})
        result = t.call(kind + ".sign_rotated", "POST", "mlfixture/sign/" + kind,
                        200, {"input": message})["data"]
        t.check(kind + ".rotated_version", result["key_version"] == 2
                and result["signature"].startswith("vault:v2:"))
        t.call(kind + ".bad_base64", "POST", "mlfixture/sign/" + kind, 400, {"input": "!"})
        contexts.append((kind, message, sigs[0], result["signature"], mu_signature))
    t.call("ed25519.options.create", "POST", "mlfixture/keys/ed25519", 200, {"type": "ed25519"})
    message = base64.b64encode(b"synthetic:ed25519").decode()
    signed = t.call("ed25519.options.baseline", "POST", "mlfixture/sign/ed25519", 200, {"input": message})
    run_signing_options(t, "ed25519", message, signed["data"]["signature"], 64)
    run_signing_context(t, "ed25519", message, signed["data"]["signature"])
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
        t.call(kind + ".retired_signature_version_hint_ignored", "POST", "mlfixture/verify/" + kind,
               400, {"input": message, "signature": old, "key_version": "2"})
        result = t.call(kind + ".current_signature_retained", "POST", "mlfixture/verify/" + kind,
                        200, {"input": message, "signature": new})
        t.check(kind + ".current_valid", result["data"]["valid"] is True)
    t.check("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="transit-mldsa270", required_oracle_version="2.7.0",
                   scope="non_rsa_pki_wire_signing_options_and_mldsa_pure_external_mu_rotation_export_acl_native_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
