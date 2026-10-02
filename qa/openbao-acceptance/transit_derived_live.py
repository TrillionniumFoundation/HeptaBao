#!/usr/bin/env python3
"""Pinned 2.7 derived AEAD differential; reports contain labels and predicates.

Synthetic exported key bytes, ciphertexts, plaintexts and fixture credentials
remain in memory. HKDF/AEAD checks use cryptography's maintained primitives.
Public contract: https://openbao.org/docs/api/secret/transit/
"""
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from core_isolation import ScenarioFailure, main as compare

KINDS = ("aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "xchacha20-poly1305")
MODES = (("ordinary", False, False), ("derived", True, False), ("convergent", True, True))
DESCRIPTOR = {"allow_plaintext_backup", "auto_rotate_period", "deletion_allowed", "derived", "exportable", "imported_key", "keys", "latest_version", "min_available_version", "min_decryption_version", "min_encryption_version", "name", "soft_deleted", "supports_decryption", "supports_derivation", "supports_encryption", "supports_signing", "type"}
_CONTEXT = {}
ABSENT = object()


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, name, predicate):
        row = {"case": "derived270." + name, "passed": bool(predicate)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, status, body=None):
        response = self.client.request(method, "/v1/" + path, body)
        row = {"case": "derived270." + name, "status": response.status, "passed": response.status == status}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body


def b64(value):
    return base64.b64encode(value).decode()


def material(kind, master, context, derived, convergent):
    size = 16 if kind == "aes128-gcm96" else 32
    if not derived:
        return master
    return HKDF(algorithm=hashes.SHA256(), length=size + (32 if convergent else 0), salt=None, info=context).derive(master)


def payload(ciphertext):
    return base64.b64decode(ciphertext.split(":", 2)[2], validate=True)


def independent_decrypt(kind, master, context, derived, convergent, ciphertext, aad):
    key = material(kind, master, context, derived, convergent)
    cipher = AESGCM(key[:16 if kind == "aes128-gcm96" else 32]) if kind.startswith("aes") else ChaCha20Poly1305(key[:32])
    raw = payload(ciphertext)
    return cipher.decrypt(raw[:12], raw[12:], aad)


def nonce_matches(kind, master, context, ciphertext, message):
    size = 16 if kind == "aes128-gcm96" else 32
    key = material(kind, master, context, True, True)
    mac = hmac.HMAC(key[size:], hashes.SHA256())
    mac.update(message)
    length = 24 if kind.startswith("xchacha") else 12
    return mac.finalize()[:length] == payload(ciphertext)[:length]


def options(message, context=ABSENT, aad=ABSENT, **extra):
    result = {"plaintext": b64(message), **extra}
    if context is not ABSENT:
        result["context"] = context
    if aad is not ABSENT:
        result["associated_data"] = aad
    return result


def run_scenarios(client, rows=None):
    rows = [] if rows is None else rows
    t = Trace(client, rows)
    t.call("mount", "POST", "sys/mounts/derivedfixture", 204, {"type": "transit"})
    saved = []
    for kind in KINDS:
        for mode, derived, convergent in MODES:
            name = kind + "-" + mode
            label = kind + "." + mode
            kp = "derivedfixture/keys/" + name
            ep = "derivedfixture/encrypt/" + name
            dp = "derivedfixture/decrypt/" + name
            rp = "derivedfixture/rewrap/" + name
            context = b"synthetic derivation context"
            ctx = b64(context)
            message = b"synthetic message"
            aad = b"synthetic authenticated metadata"
            t.call(label + ".create", "POST", kp, 200, {"type": kind, "derived": derived, "convergent_encryption": convergent, "exportable": True})
            descriptor = t.call(label + ".read", "GET", kp, 200)["data"]
            fields = DESCRIPTOR | ({"kdf", "convergent_encryption"} if derived else set()) | ({"convergent_encryption_version"} if convergent else set())
            t.check(label + ".descriptor_fields", set(descriptor) == fields)
            t.check(label + ".descriptor_modes", descriptor["derived"] is derived and descriptor.get("convergent_encryption", False) is convergent and descriptor["supports_derivation"] is True and descriptor["supports_encryption"] is True and descriptor["supports_decryption"] is True and descriptor["supports_signing"] is False)
            t.check(label + ".descriptor_kdf", not derived or descriptor["kdf"] == "hkdf_sha256")
            t.check(label + ".descriptor_convergent_version", not convergent or descriptor["convergent_encryption_version"] == -1)
            exported = t.call(label + ".export_master", "GET", "derivedfixture/export/encryption-key/" + name + "/1", 200)["data"]
            master = base64.b64decode(exported["keys"]["1"], validate=True)
            t.check(label + ".master_length", len(master) == (16 if kind.startswith("aes128") else 32))
            old_cipher = None
            for n, plain in enumerate((b"", b"x", message * 3)):
                for a, authenticated in enumerate((b"", aad)):
                    case = label + ".message." + str(n) + ".aad." + str(a)
                    body = options(plain, ctx, b64(authenticated))
                    result = t.call(case + ".encrypt", "POST", ep, 200, body)["data"]
                    cipher = result["ciphertext"]
                    t.check(case + ".response_fields", set(result) == {"ciphertext", "key_version"} and result["key_version"] == 1 and cipher.startswith("vault:v1:"))
                    repeated = t.call(case + ".repeat", "POST", ep, 200, body)["data"]["ciphertext"]
                    t.check(case + ".determinism", (repeated == cipher) is convergent)
                    if convergent:
                        t.check(case + ".independent_nonce_prf", nonce_matches(kind, master, context, cipher, plain))
                    if not kind.startswith("xchacha"):
                        t.check(case + ".independent_hkdf_aead", independent_decrypt(kind, master, context, derived, convergent, cipher, authenticated) == plain)
                    decrypted = t.call(case + ".decrypt", "POST", dp, 200, {"ciphertext": cipher, "context": ctx, "associated_data": b64(authenticated)})
                    t.check(case + ".plaintext", decrypted["data"]["plaintext"] == b64(plain))
                    t.call(case + ".wrong_aad", "POST", dp, 400, {"ciphertext": cipher, "context": ctx, "associated_data": b64(b"changed authenticated metadata")})
                    if n == 2 and a == 0:
                        old_cipher = cipher
            for index, value in enumerate((ABSENT, None, "", b64(b"context"), b64(b"\0"), 1234, 12345678, 10**19, 1234.0, 1e19, True, False, [], {}, "not-base64", "1234")):
                missing = index < 3
                invalid = 8 <= index <= 14
                status = 400 if invalid or (derived and missing) else 200
                case = label + ".typed_context." + str(index)
                result = t.call(case + ".encrypt", "POST", ep, status, options(message, value))
                if status == 200:
                    body = {"ciphertext": result["data"]["ciphertext"]}
                    if value is not ABSENT:
                        body["context"] = value
                    plain = t.call(case + ".decrypt", "POST", dp, 200, body)
                    t.check(case + ".actual_plaintext", plain["data"]["plaintext"] == b64(message))
            for index, value in enumerate((None, "", b64(aad), True, False, 1234, [], {}, "invalid-base64")):
                status = 500 if index in (3, 4, 8) else 400 if index in (6, 7) else 200
                case = label + ".typed_aad." + str(index)
                result = t.call(case + ".encrypt", "POST", ep, status, options(message, ctx, value))
                if status == 200:
                    plain = t.call(case + ".decrypt", "POST", dp, 200, {"ciphertext": result["data"]["ciphertext"], "context": ctx, "associated_data": value})
                    t.check(case + ".actual_plaintext", plain["data"]["plaintext"] == b64(message))
            baseline = t.call(label + ".nonce_baseline", "POST", ep, 200, options(message, ctx))["data"]["ciphertext"]
            for index, value in enumerate((None, "", True, False, b64(bytes(3)), [], {}, "invalid-base64")):
                result = t.call(label + ".nonce_ignored." + str(index), "POST", ep, 200, options(message, ctx, nonce=value))
                t.check(label + ".nonce_behavior." + str(index), (result["data"]["ciphertext"] == baseline) is convergent)
            for index, value in enumerate((None, True, False, "true", "false", 1234, [], {})):
                status = 200 if index < 5 else 400
                result = t.call(label + ".request_mode." + str(index), "POST", ep, status, options(message, ctx, convergent_encryption=value))
                if status == 200:
                    t.check(label + ".request_mode_ignored." + str(index), (result["data"]["ciphertext"] == baseline) is convergent)
            result = t.call(label + ".wrong_context", "POST", dp, 400 if derived else 200, {"ciphertext": baseline, "context": b64(b"different context")})
            if not derived:
                t.check(label + ".ordinary_context_ignored", result["data"]["plaintext"] == b64(message))
            tag = t.call(label + ".hmac_baseline", "POST", "derivedfixture/hmac/" + name, 200, {"input": b64(message)})["data"]["hmac"]
            for index, value in enumerate((None, "", ctx, "not-base64", True, 1234, [], {})):
                result = t.call(label + ".hmac_context." + str(index), "POST", "derivedfixture/hmac/" + name, 200, {"input": b64(message), "context": value})
                t.check(label + ".hmac_context_ignored." + str(index), result["data"]["hmac"] == tag)
                result = t.call(label + ".hmac_verify_context." + str(index), "POST", "derivedfixture/verify/" + name, 400 if index >= 6 else 200, {"input": b64(message), "hmac": tag, "context": value})
                if index < 6:
                    t.check(label + ".hmac_verify_valid." + str(index), result["data"]["valid"] is True)
            for mode_name in ("plaintext", "wrapped"):
                for bits in (128, 256, 512):
                    case = label + ".datakey." + mode_name + "." + str(bits)
                    result = t.call(case + ".generate", "POST", "derivedfixture/datakey/" + mode_name + "/" + name, 200, {"bits": bits, "context": ctx})["data"]
                    t.check(case + ".fields", set(result) == ({"ciphertext", "key_version", "plaintext"} if mode_name == "plaintext" else {"ciphertext", "key_version"}))
                    plain = t.call(case + ".decrypt", "POST", dp, 200, {"ciphertext": result["ciphertext"], "context": ctx})["data"]["plaintext"]
                    t.check(case + ".size_and_binding", len(base64.b64decode(plain, validate=True)) == bits // 8 and (mode_name != "plaintext" or plain == result["plaintext"]))
            batch = [{"reference": "first", "plaintext": b64(message), "context": ctx}, {"reference": "second", "plaintext": b64(message), "context": b64(b"second context")}]
            result = t.call(label + ".batch_encrypt", "POST", ep, 200, {"plaintext": "invalid", "context": "invalid", "batch_input": batch})["data"]["batch_results"]
            t.check(label + ".batch_order", len(result) == 2 and [item["reference"] for item in result] == ["first", "second"])
            decrypted = t.call(label + ".batch_decrypt", "POST", dp, 200, {"context": "invalid", "batch_input": [{"ciphertext": item["ciphertext"], "context": batch[i]["context"], "reference": batch[i]["reference"]} for i, item in enumerate(result)]})["data"]["batch_results"]
            t.check(label + ".batch_actual_plaintext", all(item["plaintext"] == b64(message) for item in decrypted))
            if derived:
                t.call(label + ".batch_missing_context", "POST", ep, 400, {"context": ctx, "partial_failure_response_code": 207, "batch_input": [batch[0], {"reference": "missing", "plaintext": b64(message)}]})
                result = t.call(label + ".batch_partial", "POST", ep, 207, {"partial_failure_response_code": 207, "batch_input": [batch[0], {"reference": "missing", "plaintext": "invalid-base64", "context": ctx}]})["data"]["batch_results"]
                t.check(label + ".batch_partial_order", len(result) == 2 and result[0].get("ciphertext", "").startswith("vault:v1:") and isinstance(result[1].get("error"), str) and result[1]["reference"] == "missing")
            t.call(label + ".rotate", "POST", kp + "/rotate", 200, {})
            current = t.call(label + ".v2_encrypt", "POST", ep, 200, options(message, ctx))["data"]["ciphertext"]
            t.check(label + ".v2_prefix", current.startswith("vault:v2:"))
            for index, value in enumerate((0, 1, 2, 3, -1, None, "1", True, 1.0)):
                status = 400 if index in (3, 4, 8) else 200
                result = t.call(label + ".typed_key_version." + str(index), "POST", ep, status, options(message, ctx, key_version=value))
                if status == 200:
                    version = 1 if index in (1, 6, 7) else 2
                    t.check(label + ".selected_key_version." + str(index), result["data"]["key_version"] == version)
            result = t.call(label + ".rewrap_v1", "POST", rp, 200, {"ciphertext": old_cipher, "context": ctx})["data"]
            t.check(label + ".rewrap_v2", result["ciphertext"].startswith("vault:v2:") and result["key_version"] == 2)
            decrypted = t.call(label + ".rewrapped_decrypt", "POST", dp, 200, {"ciphertext": result["ciphertext"], "context": ctx})
            t.check(label + ".rewrapped_plaintext", decrypted["data"]["plaintext"] == b64(message * 3))
            saved.append((name, label, ctx, old_cipher, current, b64(message * 3), b64(message), derived, convergent))
    for index, body in enumerate((options(b"x", b64(b"ctx")), {"batch_input": [options(b"x", b64(b"ctx"))]}, {"batch_input": [options(b"x"), options(b"x", b64(b"ctx"))]}, {"batch_input": [options(b"x", b64(b"ctx")), options(b"x")]}, options(b"x", b64(b"ctx"), convergent_encryption=True))):
        name = "upsert" + str(index)
        status = 400 if index in (2, 3) else 200
        t.call(name + ".encrypt", "POST", "derivedfixture/encrypt/" + name, status, body)
        result = t.call(name + ".read", "GET", "derivedfixture/keys/" + name, 404 if status == 400 else 200)
        if status == 200:
            t.check(name + ".derived_metadata", result["data"]["derived"] is True and result["data"]["convergent_encryption"] is (index == 4))
    for index, value in enumerate((0, 1, 0.0, 1.0, "0", "1", "T", "F", "", None)):
        name = "weakflag" + str(index)
        status = 400 if index in (2, 3) else 200
        t.call(name + ".create", "POST", "derivedfixture/keys/" + name, status, {"derived": value})
        if status == 200:
            result = t.call(name + ".read", "GET", "derivedfixture/keys/" + name, 200)
            t.check(name + ".actual_mode", result["data"]["derived"] is (index in (1, 5, 6)))
    _CONTEXT[id(rows)] = saved
    return rows


def run_after_restart(client, rows):
    saved = _CONTEXT.pop(id(rows), None)
    if not saved or len(saved) != 12:
        raise ScenarioFailure("derived270.restart_context_missing")
    t = Trace(client, rows)
    for name, label, ctx, old, current, old_plain, current_plain, derived, convergent in saved:
        kp = "derivedfixture/keys/" + name
        dp = "derivedfixture/decrypt/" + name
        ep = "derivedfixture/encrypt/" + name
        descriptor = t.call(label + ".restart_read", "GET", kp, 200)["data"]
        t.check(label + ".restart_modes", descriptor["derived"] is derived and descriptor.get("convergent_encryption", False) is convergent and descriptor["latest_version"] == 2)
        for version, cipher, plaintext in (("old", old, old_plain), ("current", current, current_plain)):
            result = t.call(label + ".restart_decrypt." + version, "POST", dp, 200, {"ciphertext": cipher, "context": ctx})
            t.check(label + ".restart_plaintext." + version, result["data"]["plaintext"] == plaintext)
        t.call(label + ".minimum_versions", "POST", kp + "/config", 200, {"min_decryption_version": 2, "min_encryption_version": 2})
        t.call(label + ".retired_decrypt", "POST", dp, 400, {"ciphertext": old, "context": ctx})
        t.call(label + ".retired_encrypt", "POST", ep, 400, {"plaintext": current_plain, "context": ctx, "key_version": 1})
        t.call(label + ".retired_rewrap", "POST", "derivedfixture/rewrap/" + name, 400, {"ciphertext": old, "context": ctx})
        t.call(label + ".retired_export", "GET", "derivedfixture/export/encryption-key/" + name + "/1", 400)
        result = t.call(label + ".current_export", "GET", "derivedfixture/export/encryption-key/" + name + "/latest", 200)
        t.check(label + ".export_latest_only", set(result["data"]["keys"]) == {"2"})
        descriptor = t.call(label + ".minimum_read", "GET", kp, 200)["data"]
        t.check(label + ".minimum_visible_versions", set(descriptor["keys"]) == {"2"})
        result = t.call(label + ".current_decrypt", "POST", dp, 200, {"ciphertext": current, "context": ctx})
        t.check(label + ".current_plaintext", result["data"]["plaintext"] == current_plain)
    t.check("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart, profile="transit-derived270", required_oracle_version="2.7.0", scope="four_symmetric_types_hkdf_context_convergent_nonce_batch_upsert_datakeys_rotation_minversions_restart", runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
