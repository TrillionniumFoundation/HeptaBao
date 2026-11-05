#!/usr/bin/env python3
"""Strict OpenBao 2.7 EC/RSA differential with independent cryptographic checks.

Only ordered labels, status codes and predicates reach reports. Disposable
fixture credentials, private keys, inputs and signatures stay in test memory.
Public API contract: https://openbao.org/docs/api/secret/transit/
"""
import base64
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from core_isolation import ScenarioFailure, main as compare

KINDS = ("ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048", "rsa-3072", "rsa-4096")
HASHES = {"sha1": hashes.SHA1, "sha2-224": hashes.SHA224,
          "sha2-256": hashes.SHA256, "sha2-384": hashes.SHA384,
          "sha2-512": hashes.SHA512, "sha3-224": hashes.SHA3_224,
          "sha3-256": hashes.SHA3_256, "sha3-384": hashes.SHA3_384,
          "sha3-512": hashes.SHA3_512}
_CONTEXT = {}


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, name, predicate):
        row = {"case": "asymmetric270." + name, "passed": bool(predicate)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, status, body=None, token=None):
        response = self.client.request(method, "/v1/" + path, body, token=token)
        row = {"case": "asymmetric270." + name, "status": response.status,
               "passed": response.status == status}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body


def b64(value):
    return base64.b64encode(value).decode()


def decode_signature(signature, marshaling):
    payload = signature.split(":", 2)[2]
    if marshaling == "jws":
        return base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
    return base64.b64decode(payload, validate=True)


def independent_verify(public, kind, signature, input_bytes, hash_name, prehashed, marshaling, scheme, salt="auto"):
    raw = decode_signature(signature, marshaling)
    hash_type = HASHES[hash_name]
    algorithm = utils.Prehashed(hash_type()) if prehashed else hash_type()
    if kind.startswith("ecdsa"):
        if marshaling == "jws":
            width = {"ecdsa-p256": 32, "ecdsa-p384": 48, "ecdsa-p521": 66}[kind]
            if len(raw) != width * 2:
                return False
            raw = utils.encode_dss_signature(int.from_bytes(raw[:width], "big"), int.from_bytes(raw[width:], "big"))
        signature_scheme = ec.ECDSA(algorithm)
        args = (raw, input_bytes, signature_scheme)
    else:
        if scheme == "pss":
            salt_length = padding.PSS.AUTO if salt in ("auto", 0, False) else (hash_type().digest_size if salt in ("hash", -1) else int(salt))
            signature_scheme = padding.PSS(mgf=padding.MGF1(hash_type()), salt_length=salt_length)
        else:
            signature_scheme = padding.PKCS1v15()
        args = (raw, input_bytes, signature_scheme, algorithm)
    try:
        public.verify(*args)
        return True
    except InvalidSignature:
        return False


def actual_input(message, algorithm, prehashed):
    if not prehashed:
        return message
    digest = hashes.Hash(HASHES[algorithm]())
    digest.update(message)
    return digest.finalize()


def run_scenarios(client, rows=None):
    rows = [] if rows is None else rows
    t = Trace(client, rows)
    t.call("mount", "POST", "sys/mounts/asymfixture", 204, {"type": "transit"})
    contexts = []
    for kind in KINDS:
        kp = "asymfixture/keys/" + kind
        sp = "asymfixture/sign/" + kind
        vp = "asymfixture/verify/" + kind
        t.call(kind + ".create", "POST", kp, 200, {"type": kind, "exportable": True})
        data = t.call(kind + ".read", "GET", kp, 200)["data"]
        public_pem = data["keys"]["1"]["public_key"]
        public = serialization.load_pem_public_key(public_pem.encode())
        t.check(kind + ".descriptor_fields", set(data) == {
            "allow_plaintext_backup", "auto_rotate_period", "deletion_allowed", "derived", "exportable", "imported_key", "keys", "latest_version", "min_available_version", "min_decryption_version", "min_encryption_version", "name", "soft_deleted", "supports_decryption", "supports_derivation", "supports_encryption", "supports_signing", "type"})
        t.check(kind + ".version_fields", set(data["keys"]["1"]) == {"certificate_chain", "creation_time", "name", "public_key"})
        t.check(kind + ".capabilities", data["type"] == kind and data["supports_signing"] is True
                and data["supports_encryption"] is kind.startswith("rsa")
                and data["supports_decryption"] is kind.startswith("rsa") and data["supports_derivation"] is False)
        t.check(kind + ".public_spki", public_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        exported = t.call(kind + ".export_public", "GET", "asymfixture/export/public-key/" + kind + "/1", 200)["data"]
        t.check(kind + ".export_public_matches", set(exported) == {"name", "type", "keys"} and serialization.load_pem_public_key(exported["keys"]["1"].encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        exported = t.call(kind + ".export_signing", "GET", "asymfixture/export/signing-key/" + kind + "/1", 200)["data"]
        private_pem = exported["keys"]["1"]
        label = "-----BEGIN RSA PRIVATE KEY-----" if kind.startswith("rsa") else "-----BEGIN EC PRIVATE KEY-----"
        t.check(kind + ".private_export_label", private_pem.startswith(label))
        private_key = serialization.load_pem_private_key(private_pem.encode(), None)
        t.check(kind + ".private_export_public_matches", private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        encryption_export = t.call(kind + ".export_encryption", "GET", "asymfixture/export/encryption-key/" + kind + "/1", 200 if kind.startswith("rsa") else 400)
        if kind.startswith("rsa"):
            t.check(kind + ".encryption_export_matches", encryption_export["data"]["keys"]["1"] == private_pem)
        message = ("synthetic EC/RSA:" + kind).encode()
        baseline = t.call(kind + ".default_sign", "POST", sp, 200, {"input": b64(message)})["data"]["signature"]
        t.check(kind + ".default_independent_sha256", independent_verify(public, kind, baseline, message, "sha2-256", False, "asn1", "pss"))
        for algorithm in HASHES:
            for prehashed in (False, True):
                value = actual_input(message, algorithm, prehashed)
                for marshaling in ("asn1", "jws"):
                    for scheme in (("pss", "pkcs1v15") if kind.startswith("rsa") else ("ignored",)):
                        name = ".".join((kind, algorithm, str(prehashed), marshaling, scheme))
                        options = {"input": b64(value), "hash_algorithm": algorithm, "prehashed": prehashed,
                                   "marshaling_algorithm": marshaling, "signature_algorithm": scheme}
                        signed = t.call(name + ".sign", "POST", sp, 200, options)["data"]
                        signature = signed["signature"]
                        t.check(name + ".signature_fields", set(signed) == {"key_version", "signature"}
                                and signed["key_version"] == 1 and signature.startswith("vault:v1:"))
                        t.check(name + ".independent_signature", independent_verify(public, kind, signature, value, algorithm, prehashed, marshaling, scheme))
                        result = t.call(name + ".verify", "POST", vp, 200, dict(options, signature=signature))
                        t.check(name + ".provider_valid", result["data"]["valid"] is True)
                        changed = actual_input(b"changed synthetic asymmetric message", algorithm, prehashed)
                        result = t.call(name + ".changed_verify", "POST", vp, 200, dict(options, input=b64(changed), signature=signature))
                        t.check(name + ".changed_invalid", result["data"]["valid"] is False)
        for index, value in enumerate(("", None)):
            signed = t.call(kind + ".default_hash." + str(index), "POST", sp, 200, {"input": b64(message), "hash_algorithm": value})["data"]["signature"]
            t.check(kind + ".default_hash_valid." + str(index), independent_verify(public, kind, signed, message, "sha2-256", False, "asn1", "pss"))
        for index, value in enumerate(("YQ==", None, "!bad!", True)):
            status = 200 if index < 2 else 400
            result = t.call(kind + ".context_sign." + str(index), "POST", sp, status, {"input": b64(message), "context": value})
            if status == 200:
                result = t.call(kind + ".context_verify." + str(index), "POST", vp, 200, {"input": b64(message), "signature": result["data"]["signature"], "context": "Yg=="})
                t.check(kind + ".context_ignored." + str(index), result["data"]["valid"] is True)
        for index, scheme in enumerate(("garbage", False, 1, [], {})):
            status = (400 if index >= 3 else 500) if kind.startswith("rsa") else (400 if index >= 3 else 200)
            result = t.call(kind + ".signature_algorithm_sign." + str(index), "POST", sp, status, {"input": b64(message), "signature_algorithm": scheme})
            signature = result.get("data", {}).get("signature", baseline)
            result = t.call(kind + ".signature_algorithm_verify." + str(index), "POST", vp, status, {"input": b64(message), "signature": signature, "signature_algorithm": scheme})
            if status == 200:
                t.check(kind + ".signature_algorithm_ignored." + str(index), result["data"]["valid"] is True)
        for n in (0, 1, 31, 32, 33, 64):
            options = {"input": b64(bytes(n)), "prehashed": True, "hash_algorithm": "sha2-256"}
            status = 500 if n == 0 or (kind.startswith("rsa") and n != 32) else 200
            result = t.call(kind + ".prehash_length_sign." + str(n), "POST", sp, status, options)
            signature = result.get("data", {}).get("signature", baseline)
            result = t.call(kind + ".prehash_length_verify." + str(n), "POST", vp, 200, dict(options, signature=signature))
            t.check(kind + ".prehash_length_valid." + str(n), result["data"]["valid"] is (status == 200))
        none_options = {"input": b64(message), "prehashed": True, "hash_algorithm": "none", "signature_algorithm": "pkcs1v15"}
        result = t.call(kind + ".none_sign", "POST", sp, 200, none_options)
        result = t.call(kind + ".none_verify", "POST", vp, 200, dict(none_options, signature=result["data"]["signature"]))
        t.check(kind + ".none_valid", result["data"]["valid"] is True)
        for prehashed in (False, True):
            for scheme in ("pss", "garbage", ""):
                t.call(kind + ".none_rejected." + str(prehashed) + "." + (scheme or "empty"), "POST", sp, 400,
                       {"input": b64(message), "hash_algorithm": "none", "prehashed": prehashed, "signature_algorithm": scheme})
        if kind.startswith("rsa"):
            for index, salt in enumerate(("auto", "hash", 0, -1, 1, 17, True, False)):
                options = {"input": b64(message), "salt_length": salt}
                name = kind + ".pss_salt." + str(index)
                signature = t.call(name + ".sign", "POST", sp, 200, options)["data"]["signature"]
                t.check(name + ".independent_signature", independent_verify(public, kind, signature, message, "sha2-256", False, "asn1", "pss", salt))
                result = t.call(name + ".verify", "POST", vp, 200, dict(options, signature=signature))
                t.check(name + ".valid", result["data"]["valid"] is True)
            size = public.key_size // 8
            for length in (0, 1, size - 66):
                plaintext = bytes([0x51]) * length
                name = kind + ".oaep." + str(length)
                encrypted = t.call(name + ".encrypt", "POST", "asymfixture/encrypt/" + kind, 200, {"plaintext": b64(plaintext)})["data"]["ciphertext"]
                payload = base64.b64decode(encrypted.split(":", 2)[2], validate=True)
                t.check(name + ".independent_decrypt", private_key.decrypt(payload, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) == plaintext)
                result = t.call(name + ".decrypt", "POST", "asymfixture/decrypt/" + kind, 200, {"ciphertext": encrypted})
                t.check(name + ".roundtrip", result["data"]["plaintext"] == b64(plaintext))
                independent = public.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                result = t.call(name + ".independent_encrypt", "POST", "asymfixture/decrypt/" + kind, 200, {"ciphertext": "vault:v1:" + b64(independent)})
                t.check(name + ".cross_library_decrypt", result["data"]["plaintext"] == b64(plaintext))
            t.call(kind + ".oaep_oversized", "POST", "asymfixture/encrypt/" + kind, 500, {"plaintext": b64(bytes(size - 65))})
            for index, payload in enumerate((b"", bytes(3), bytes(size), bytes(size + 1))):
                t.call(kind + ".oaep_malformed." + str(index), "POST", "asymfixture/decrypt/" + kind, 500, {"ciphertext": "vault:v1:" + b64(payload)})
            for salt in (size - 33, 2**40):
                t.call(kind + ".salt_oversized_sign." + str(salt), "POST", sp, 500, {"input": b64(message), "salt_length": salt})
                t.call(kind + ".salt_oversized_verify." + str(salt), "POST", vp, 400, {"input": b64(message), "salt_length": salt, "signature": baseline})
        del private_key, private_pem, exported, encryption_export
        rotated = t.call(kind + ".rotate", "POST", kp + "/rotate", 200, {})["data"]
        t.check(kind + ".rotate_public_changed", rotated["latest_version"] == 2 and rotated["keys"]["2"]["public_key"] != public_pem)
        current = t.call(kind + ".rotated_sign", "POST", sp, 200, {"input": b64(message)})["data"]["signature"]
        contexts.append((kind, b64(message), baseline, current))
    _CONTEXT[id(rows)] = contexts
    return rows


def run_after_restart(client, rows):
    contexts = _CONTEXT.pop(id(rows), None)
    if not contexts or len(contexts) != 6:
        raise ScenarioFailure("asymmetric270.restart_context_missing")
    t = Trace(client, rows)
    for kind, message, old, current in contexts:
        for label, signature in (("old", old), ("current", current)):
            result = t.call(kind + ".restart_verify." + label, "POST", "asymfixture/verify/" + kind, 200, {"input": message, "signature": signature})
            t.check(kind + ".restart_valid." + label, result["data"]["valid"] is True)
        t.call(kind + ".minimum_versions", "POST", "asymfixture/keys/" + kind + "/config", 200, {"min_decryption_version": 2, "min_encryption_version": 2})
        t.call(kind + ".retired_sign_denied", "POST", "asymfixture/sign/" + kind, 500, {"input": message, "key_version": 1})
        t.call(kind + ".retired_verify_denied", "POST", "asymfixture/verify/" + kind, 400, {"input": message, "signature": old, "key_version": "2"})
        exported = t.call(kind + ".export_latest", "GET", "asymfixture/export/public-key/" + kind + "/latest", 200)
        t.check(kind + ".export_latest_only", set(exported["data"]["keys"]) == {"2"})
        t.call(kind + ".export_retired_denied", "GET", "asymfixture/export/signing-key/" + kind + "/1", 400)
    t.check("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="transit-asymmetric270", required_oracle_version="2.7.0",
                   scope="six_native_ec_rsa_types_independent_hash_prehash_jws_pss_oaep_export_rotation_minversions_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
