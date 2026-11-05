#!/usr/bin/env python3
"""AES128/256 wrapped import: exact pinned 2.7 statuses and crypto predicates.

Only statuses, bounded metadata and independent crypto predicates leave RAM.
The fixed 87-row HTTP trace excludes launcher init/unseal/health operations.
An enclosing controller must independently audit owned exe/config/PIDs.
"""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import time

KINDS = ("aes128-gcm96", "aes256-gcm96")
HASHES = ("SHA1", "SHA224", "SHA256", "SHA384", "SHA512")
BOOL_FIELDS = ("imported_key", "imported_key_allow_rotation", "exportable", "allow_plaintext_backup",
               "derived", "soft_deleted", "supports_encryption", "supports_decryption")
INT_FIELDS = ("latest_version", "min_encryption_version", "min_decryption_version",
              "auto_rotate_period", "min_available_version")


class ProbeFailure(Exception):
    """Static diagnostics only; no response or request body in exceptions."""


def fixed_ids():
    ids = ["setup.mount", "wrapping.first", "wrapping.repeat"]
    for kind in KINDS:
        for name in HASHES:
            ids.extend(f"{kind}.{name}.{operation}" for operation in ("import", "read", "encrypt"))
        ids.extend(f"{kind}.default.{operation}" for operation in (
            "import", "read", "encrypt", "rotate", "read_after_rotate"))
        ids.extend(f"{kind}.allowed.{operation}" for operation in (
            "import", "read", "rotate", "read_after_rotate", "import_after_rotate", "read_after_import"))
        ids.extend(f"{kind}.version.{operation}" for operation in (
            "import_next", "read", "encrypt_latest", "decrypt_original"))
        ids.append(f"{kind}.wrong_length.import")
    ids.extend(("generated.create", "generated.import_version"))
    ids.extend("negative." + name for name in (
        "invalid_base64", "short_envelope", "wrong_oaep_hash", "rsa_tamper", "kwp_tamper",
        "unknown_hash", "ciphertext_public_precedence", "external_type", "raw_key"))
    ids.extend(("acl.read_policy", "acl.update_policy", "acl.read_token", "acl.update_token",
                "acl.read_wrapping", "acl.read_import", "acl.update_wrapping", "acl.update_import"))
    ids.extend(("restart.wrapping", "restart.aes128.decrypt", "restart.aes256.decrypt"))
    return tuple(ids)


def safe_metadata(body):
    if not isinstance(body, dict):
        raise ProbeFailure("response_shape")
    data = body.get("data")
    result = {"has_data": isinstance(data, dict), "has_errors": "errors" in body}
    if not isinstance(data, dict):
        return result
    result["bool_fields_present"] = [key for key in BOOL_FIELDS if key in data]
    result["int_fields_present"] = [key for key in INT_FIELDS if key in data]
    for key in BOOL_FIELDS:
        if key in data:
            if type(data[key]) is not bool:
                raise ProbeFailure("boolean_metadata_type")
            result[key] = data[key]
    for key in INT_FIELDS:
        if key in data:
            if type(data[key]) is not int or not 0 <= data[key] < 2 ** 64:
                raise ProbeFailure("integer_metadata_type")
            result[key] = data[key]
    versions = data.get("keys")
    if isinstance(versions, dict):
        if len(versions) > 10000 or any(not isinstance(k, str) or not k.isdecimal() for k in versions):
            raise ProbeFailure("version_metadata_shape")
        result["version_numbers"] = sorted(int(key) for key in versions)
    return result


class Recorder:
    def __init__(self):
        self.rows = []

    def record(self, case, response, elapsed):
        expected = fixed_ids()
        if len(self.rows) >= len(expected) or case != expected[len(self.rows)]:
            raise ProbeFailure("fixed_trace_order")
        if type(response.status) is not int or not 100 <= response.status <= 599:
            raise ProbeFailure("status_type")
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise ProbeFailure("elapsed_type")
        row = {"case": case, "status": response.status,
               "elapsed_ms": round(elapsed * 1000, 3), **safe_metadata(response.body)}
        self.rows.append(row)
        return response


def successful_for_prerequisite(response):
    # Observation is exact-status recording, not a union of accepted parity values.
    # The broad predicate only permits follow-up calls to inspect actual state.
    return 200 <= response.status < 300


def successful_plaintext(response, expected):
    return (type(response.status) is int and response.status == 200
            and type(response.body) is dict and type(response.body.get("data")) is dict
            and response.body["data"].get("plaintext") == expected)


def run_probe(client_factory, call, wrapping_read):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding

    hash_types = dict(zip(HASHES, (hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512)))
    message = b"PUBLIC_BYOK270_SYNTHETIC_MIGRATION_FIXTURE"
    plaintext = base64.b64encode(message).decode()
    mounted = call("setup.mount", "POST", "/v1/sys/mounts/transit", {"type": "transit"})
    if not successful_for_prerequisite(mounted):
        raise ProbeFailure("mount_prerequisite")
    first = call("wrapping.first", "GET", "/v1/transit/wrapping_key")
    public = wrapping_read(first)
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 4096:
        raise ProbeFailure("wrapping_rsa4096_prerequisite")
    public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    second = call("wrapping.repeat", "GET", "/v1/transit/wrapping_key")
    other = wrapping_read(second)
    call.rows[-1]["public_equal_first"] = public_der == other.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def wrap(target, name="SHA256"):
        ephemeral = os.urandom(32)
        wrapped_key = public.encrypt(ephemeral, padding.OAEP(
            mgf=padding.MGF1(hash_types[name]()), algorithm=hash_types[name](), label=None))
        wrapped_target = aes_key_wrap_with_padding(ephemeral, target)
        return base64.b64encode(wrapped_key + wrapped_target).decode()

    def independently_decrypt(response, target):
        if response.status != 200:
            return False
        value = response.body.get("data", {}).get("ciphertext")
        if not isinstance(value, str) or not value.startswith("vault:v"):
            raise ProbeFailure("ciphertext_response_shape")
        parts = value.split(":", 2)
        if len(parts) != 3 or not parts[1][1:].isdecimal():
            raise ProbeFailure("ciphertext_response_shape")
        payload = base64.b64decode(parts[2], validate=True)
        try:
            valid = AESGCM(target).decrypt(payload[:12], payload[12:], None) == message
        except Exception:
            valid = False
        call.rows[-1]["independent_aes_valid"] = valid
        call.rows[-1]["envelope_version"] = int(parts[1][1:])
        return valid

    saved = {}
    for kind in KINDS:
        length = 16 if kind == "aes128-gcm96" else 32
        target = os.urandom(length)
        for hash_name in HASHES:
            name = kind + "-" + hash_name.lower()
            response = call(f"{kind}.{hash_name}.import", "POST", "/v1/transit/keys/" + name + "/import",
                            {"type": kind, "ciphertext": wrap(target, hash_name), "hash_function": hash_name})
            if not successful_for_prerequisite(response):
                raise ProbeFailure("hash_import_prerequisite")
            call(f"{kind}.{hash_name}.read", "GET", "/v1/transit/keys/" + name)
            encrypted = call(f"{kind}.{hash_name}.encrypt", "POST", "/v1/transit/encrypt/" + name, {"plaintext": plaintext})
            independently_decrypt(encrypted, target)
        name = kind + "-default"
        call(f"{kind}.default.import", "POST", "/v1/transit/keys/" + name + "/import", {"type": kind, "ciphertext": wrap(target)})
        call(f"{kind}.default.read", "GET", "/v1/transit/keys/" + name)
        encrypted = call(f"{kind}.default.encrypt", "POST", "/v1/transit/encrypt/" + name, {"plaintext": plaintext})
        independently_decrypt(encrypted, target)
        original_ciphertext = encrypted.body.get("data", {}).get("ciphertext")
        if not isinstance(original_ciphertext, str):
            raise ProbeFailure("default_ciphertext_prerequisite")
        call(f"{kind}.default.rotate", "POST", "/v1/transit/keys/" + name + "/rotate", {})
        call(f"{kind}.default.read_after_rotate", "GET", "/v1/transit/keys/" + name)
        rotation_name = kind + "-rotation"
        call(f"{kind}.allowed.import", "POST", "/v1/transit/keys/" + rotation_name + "/import",
             {"type": kind, "ciphertext": wrap(target), "allow_rotation": True})
        call(f"{kind}.allowed.read", "GET", "/v1/transit/keys/" + rotation_name)
        call(f"{kind}.allowed.rotate", "POST", "/v1/transit/keys/" + rotation_name + "/rotate", {})
        call(f"{kind}.allowed.read_after_rotate", "GET", "/v1/transit/keys/" + rotation_name)
        call(f"{kind}.allowed.import_after_rotate", "POST", "/v1/transit/keys/" + rotation_name + "/import_version", {"ciphertext": wrap(target)})
        call(f"{kind}.allowed.read_after_import", "GET", "/v1/transit/keys/" + rotation_name)
        next_target = os.urandom(length)
        call(f"{kind}.version.import_next", "POST", "/v1/transit/keys/" + name + "/import_version", {"ciphertext": wrap(next_target)})
        call(f"{kind}.version.read", "GET", "/v1/transit/keys/" + name)
        latest = call(f"{kind}.version.encrypt_latest", "POST", "/v1/transit/encrypt/" + name, {"plaintext": plaintext})
        independently_decrypt(latest, next_target)
        call(f"{kind}.version.decrypt_original", "POST", "/v1/transit/decrypt/" + name, {"ciphertext": original_ciphertext})
        call.rows[-1]["plaintext_equal_original"] = successful_plaintext(call.last, plaintext)
        saved[kind] = {"name": name, "ciphertext": latest.body.get("data", {}).get("ciphertext")}
        call(f"{kind}.wrong_length.import", "POST", "/v1/transit/keys/" + kind + "-badlen/import", {"type": kind, "ciphertext": wrap(os.urandom(length - 1))})
    call("generated.create", "POST", "/v1/transit/keys/generated", {"type": "aes256-gcm96"})
    good = wrap(os.urandom(32))
    call("generated.import_version", "POST", "/v1/transit/keys/generated/import_version", {"ciphertext": good})
    blob = base64.b64decode(good)
    tamper_rsa = bytearray(blob); tamper_rsa[0] ^= 1
    tamper_kwp = bytearray(blob); tamper_kwp[-1] ^= 1
    public_pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    negative_bodies = (
        {"ciphertext": "***"},
        {"ciphertext": base64.b64encode(blob[:511]).decode()},
        {"ciphertext": good, "hash_function": "SHA512"},
        {"ciphertext": base64.b64encode(tamper_rsa).decode()},
        {"ciphertext": base64.b64encode(tamper_kwp).decode()},
        {"ciphertext": good, "hash_function": "not-an-algorithm"},
        {"ciphertext": good, "public_key": public_pem},
        {"type": "external-key", "ciphertext": good},
        {"ciphertext": base64.b64encode(os.urandom(32)).decode()},
    )
    negative_ids = [case for case in fixed_ids() if case.startswith("negative.")]
    for case, body in zip(negative_ids, negative_bodies):
        call(case, "POST", "/v1/transit/keys/negative-" + case.split(".", 1)[1] + "/import", body)
    call("acl.read_policy", "PUT", "/v1/sys/policies/acl/byok-read", {"policy": 'path "transit/wrapping_key" { capabilities = ["read"] }'})
    call("acl.update_policy", "PUT", "/v1/sys/policies/acl/byok-update", {"policy": 'path "transit/keys/acl-import/import" { capabilities = ["create", "update"] }'})
    reader = call("acl.read_token", "POST", "/v1/auth/token/create", {"policies": ["byok-read"], "no_default_policy": True})
    updater = call("acl.update_token", "POST", "/v1/auth/token/create", {"policies": ["byok-update"], "no_default_policy": True})
    reader_token = reader.body.get("auth", {}).get("client_token")
    updater_token = updater.body.get("auth", {}).get("client_token")
    if not isinstance(reader_token, str) or not isinstance(updater_token, str):
        raise ProbeFailure("policy_token_prerequisite")
    read_client = client_factory(reader_token)
    update_client = client_factory(updater_token)
    call("acl.read_wrapping", "GET", "/v1/transit/wrapping_key", alternate=read_client)
    call("acl.read_import", "POST", "/v1/transit/keys/acl-import/import", {"ciphertext": good}, alternate=read_client)
    call("acl.update_wrapping", "GET", "/v1/transit/wrapping_key", alternate=update_client)
    call("acl.update_import", "POST", "/v1/transit/keys/acl-import/import", {"ciphertext": good}, alternate=update_client)
    return public_der, saved, plaintext


def run_restart_probe(client_factory, call, wrapping_read, context):
    from cryptography.hazmat.primitives import serialization
    public_der, saved, plaintext = context
    after = call("restart.wrapping", "GET", "/v1/transit/wrapping_key")
    after_public = wrapping_read(after)
    call.rows[-1]["public_equal_first"] = public_der == after_public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for short, kind in (("aes128", "aes128-gcm96"), ("aes256", "aes256-gcm96")):
        response = call(f"restart.{short}.decrypt", "POST", "/v1/transit/decrypt/" + saved[kind]["name"], {"ciphertext": saved[kind]["ciphertext"]})
        call.rows[-1]["plaintext_equal_original"] = successful_plaintext(response, plaintext)



_EXPECTED = [{'case': 'setup.mount', 'has_data': False, 'has_errors': False, 'status': 204}, {'bool_fields_present': [], 'case': 'wrapping.first', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'public_key_bits': 4096, 'public_only_pem': True, 'status': 200}, {'bool_fields_present': [], 'case': 'wrapping.repeat', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'public_equal_first': True, 'public_key_bits': 4096, 'public_only_pem': True, 'status': 200}, {'case': 'aes128-gcm96.SHA1.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.SHA1.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.SHA1.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.SHA224.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.SHA224.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.SHA224.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.SHA256.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.SHA256.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.SHA256.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.SHA384.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.SHA384.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.SHA384.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.SHA512.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.SHA512.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.SHA512.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.default.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.default.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.default.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes128-gcm96.default.rotate', 'has_data': False, 'has_errors': True, 'status': 500}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.default.read_after_rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'case': 'aes128-gcm96.allowed.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.allowed.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': True}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.allowed.rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.allowed.read_after_rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'case': 'aes128-gcm96.allowed.import_after_rotate', 'has_data': False, 'has_errors': True, 'status': 500}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.allowed.read_after_import', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'case': 'aes128-gcm96.version.import_next', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes128-gcm96.version.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes128-gcm96.version.encrypt_latest', 'envelope_version': 2, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'bool_fields_present': [], 'case': 'aes128-gcm96.version.decrypt_original', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'plaintext_equal_original': True, 'status': 200}, {'case': 'aes128-gcm96.wrong_length.import', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'aes256-gcm96.SHA1.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.SHA1.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.SHA1.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.SHA224.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.SHA224.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.SHA224.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.SHA256.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.SHA256.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.SHA256.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.SHA384.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.SHA384.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.SHA384.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.SHA512.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.SHA512.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.SHA512.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.default.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.default.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.default.encrypt', 'envelope_version': 1, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'case': 'aes256-gcm96.default.rotate', 'has_data': False, 'has_errors': True, 'status': 500}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.default.read_after_rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': False}, {'case': 'aes256-gcm96.allowed.import', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.allowed.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1], 'imported_key_allow_rotation': True}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.allowed.rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.allowed.read_after_rotate', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'case': 'aes256-gcm96.allowed.import_after_rotate', 'has_data': False, 'has_errors': True, 'status': 500}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.allowed.read_after_import', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2]}, {'case': 'aes256-gcm96.version.import_next', 'has_data': False, 'has_errors': False, 'status': 204}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'imported_key_allow_rotation', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'aes256-gcm96.version.read', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': True, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 2, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1, 2], 'imported_key_allow_rotation': False}, {'bool_fields_present': [], 'case': 'aes256-gcm96.version.encrypt_latest', 'envelope_version': 2, 'has_data': True, 'has_errors': False, 'independent_aes_valid': True, 'int_fields_present': [], 'status': 200}, {'bool_fields_present': [], 'case': 'aes256-gcm96.version.decrypt_original', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'plaintext_equal_original': True, 'status': 200}, {'case': 'aes256-gcm96.wrong_length.import', 'has_data': False, 'has_errors': True, 'status': 500}, {'allow_plaintext_backup': False, 'auto_rotate_period': 0, 'bool_fields_present': ['imported_key', 'exportable', 'allow_plaintext_backup', 'derived', 'soft_deleted', 'supports_encryption', 'supports_decryption'], 'case': 'generated.create', 'derived': False, 'exportable': False, 'has_data': True, 'has_errors': False, 'imported_key': False, 'int_fields_present': ['latest_version', 'min_encryption_version', 'min_decryption_version', 'auto_rotate_period', 'min_available_version'], 'latest_version': 1, 'min_available_version': 0, 'min_decryption_version': 1, 'min_encryption_version': 0, 'soft_deleted': False, 'status': 200, 'supports_decryption': True, 'supports_encryption': True, 'version_numbers': [1]}, {'case': 'generated.import_version', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.invalid_base64', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.short_envelope', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.wrong_oaep_hash', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.rsa_tamper', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.kwp_tamper', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'negative.unknown_hash', 'has_data': False, 'has_errors': True, 'status': 400}, {'case': 'negative.ciphertext_public_precedence', 'has_data': False, 'has_errors': False, 'status': 204}, {'case': 'negative.external_type', 'has_data': False, 'has_errors': True, 'status': 400}, {'case': 'negative.raw_key', 'has_data': False, 'has_errors': True, 'status': 500}, {'case': 'acl.read_policy', 'has_data': False, 'has_errors': False, 'status': 204}, {'case': 'acl.update_policy', 'has_data': False, 'has_errors': False, 'status': 204}, {'case': 'acl.read_token', 'has_data': False, 'has_errors': False, 'status': 200}, {'case': 'acl.update_token', 'has_data': False, 'has_errors': False, 'status': 200}, {'bool_fields_present': [], 'case': 'acl.read_wrapping', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'status': 200}, {'case': 'acl.read_import', 'has_data': False, 'has_errors': True, 'status': 403}, {'case': 'acl.update_wrapping', 'has_data': False, 'has_errors': True, 'status': 403}, {'case': 'acl.update_import', 'has_data': False, 'has_errors': False, 'status': 204}, {'bool_fields_present': [], 'case': 'restart.wrapping', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'public_equal_first': True, 'public_key_bits': 4096, 'public_only_pem': True, 'status': 200}, {'bool_fields_present': [], 'case': 'restart.aes128.decrypt', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'plaintext_equal_original': True, 'status': 200}, {'bool_fields_present': [], 'case': 'restart.aes256.decrypt', 'has_data': True, 'has_errors': False, 'int_fields_present': [], 'plaintext_equal_original': True, 'status': 200}]

_CONTEXT = {}
_TOP_FIELDS = frozenset({"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth", "mount_type", "errors"})
_DESCRIPTOR_FIELDS = frozenset({"allow_plaintext_backup", "auto_rotate_period", "deletion_allowed", "derived", "exportable", "imported_key", "keys", "latest_version", "min_available_version", "min_decryption_version", "min_encryption_version", "name", "soft_deleted", "supports_decryption", "supports_derivation", "supports_encryption", "supports_signing", "type"})

def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys()
                and all(typed_equal(left[key], right[key]) for key in left))
    if type(left) in (tuple, list):
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def response_data_shape(case, response):
    if type(response.body) is not dict or not set(response.body).issubset(_TOP_FIELDS):
        return False
    data = response.body.get("data")
    if case.startswith("wrapping.") or case == "restart.wrapping":
        return (response.status == 200 and type(data) is dict
                and set(data) == {"public_key"} and type(data["public_key"]) is str)
    if response.status == 204:
        return response.body == {}
    if case.endswith(".read") or case.endswith(".read_after_rotate") or case.endswith(".read_after_import") or (case.endswith(".rotate") and response.status == 200):
        return (response.status == 200 and type(data) is dict
                and type(data.get("imported_key")) is bool
                and set(data) == (_DESCRIPTOR_FIELDS | {"imported_key_allow_rotation"}
                                  if data["imported_key"] else _DESCRIPTOR_FIELDS)
                and (not data["imported_key"]
                     or type(data["imported_key_allow_rotation"]) is bool)
                and type(data["name"]) is str and type(data["type"]) is str
                and type(data["keys"]) is dict
                and all(type(v) is int and v >= 0 for v in data["keys"].values())
                and type(data["supports_derivation"]) is bool
                and data["supports_derivation"] is True
                and data["supports_signing"] is False
                and data["deletion_allowed"] is False)
    if case.endswith(".encrypt") or case.endswith(".encrypt_latest"):
        return (response.status == 200 and type(data) is dict
                and set(data) == {"ciphertext", "key_version"}
                and type(data["ciphertext"]) is str and type(data["key_version"]) is int)
    if case.endswith(".decrypt_original") or case in ("restart.aes128.decrypt", "restart.aes256.decrypt"):
        return (response.status == 200 and type(data) is dict
                and set(data) == {"plaintext"} and type(data["plaintext"]) is str)
    if response.status >= 400:
        return ("data" not in response.body and type(response.body.get("errors")) is list
                and bool(response.body["errors"])
                and all(type(value) is str for value in response.body["errors"]))
    return True


def finalize_rows(recorder, start, end, output):
    from core_isolation import ScenarioFailure
    for index in range(start, end):
        row = recorder.rows[index]
        contract = {key: value for key, value in row.items() if key not in ("elapsed_ms", "data_shape_valid")}
        result = {"case": "byok270." + row["case"], "status": row["status"],
                  "passed": row.get("data_shape_valid") is True and typed_equal(contract, _EXPECTED[index])}
        output.append(result)
        if result["passed"] is not True:
            raise ScenarioFailure(result["case"])


def traced_call(client, recorder):
    def call(case, method, path, body=None, alternate=None):
        started = time.monotonic()
        response = (alternate or client).request(method, path, body)
        call.last = recorder.record(case, response, time.monotonic() - started)
        recorder.rows[-1]["data_shape_valid"] = response_data_shape(case, response)
        if response.status != _EXPECTED[len(recorder.rows) - 1]["status"]:
            from core_isolation import ScenarioFailure
            raise ScenarioFailure("byok270." + case)
        return response
    call.rows = recorder.rows
    call.last = None
    return call


def wrapping_reader(call):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    def read(response):
        pem = response.body.get("data", {}).get("public_key")
        if response.status != 200 or type(pem) is not str:
            raise ProbeFailure("wrapping_response_prerequisite")
        public = serialization.load_pem_public_key(pem.encode())
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 4096:
            raise ProbeFailure("wrapping_rsa4096_prerequisite")
        call.rows[-1]["public_key_bits"] = public.key_size
        call.rows[-1]["public_only_pem"] = pem.startswith("-----BEGIN PUBLIC KEY-----")
        return public
    return read


def token_client(client, token):
    # Use one verified fixture transport; no token/body is formatted into logs.
    class Alternate:
        def request(self, method, path, body=None):
            return client.request(method, path, body, token=token)
    return Alternate()


def run_scenarios(client, rows=None):
    rows = [] if rows is None else rows
    recorder = Recorder()
    call = traced_call(client, recorder)
    context = run_probe(lambda token: token_client(client, token), call, wrapping_reader(call))
    if len(recorder.rows) != 84:
        raise ProbeFailure("incomplete_fixed_pre_restart_trace")
    finalize_rows(recorder, 0, 84, rows)
    _CONTEXT[id(rows)] = (recorder, context)
    return rows


def run_after_restart(client, rows):
    saved = _CONTEXT.pop(id(rows), None)
    if saved is None:
        raise ProbeFailure("restart_context_missing")
    recorder, context = saved
    call = traced_call(client, recorder)
    run_restart_probe(lambda token: token_client(client, token), call, wrapping_reader(call), context)
    if len(recorder.rows) != 87 or tuple(row["case"] for row in recorder.rows) != fixed_ids():
        raise ProbeFailure("incomplete_fixed_trace")
    finalize_rows(recorder, 84, 87, rows)


def main():
    from core_isolation import main as compare
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="transit-byok270", required_oracle_version="2.7.0",
                   scope="aes128_aes256_wrapped_import_five_oaep_digests_rotation_import_version_acl_encrypted_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
