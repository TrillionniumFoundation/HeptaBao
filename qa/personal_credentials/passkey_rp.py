#!/usr/bin/env python3
"""Strict, local synthetic RP for the Android passkey preview.

This intentionally implements one small WebAuthn profile, not a public RP:
P-256/ES256, none attestation, one pinned native Android package certificate,
32-byte credential IDs, backup eligibility, mandatory UP/UV, and increasing
counters. It does not prove that a phone, biometric, platform provider, Digital
Asset Links association, or recovery ceremony has actually been exercised.

Only public WebAuthn material is stored. Request bodies, signatures, challenges,
and arbitrary exception messages are never written to stdout or access logs.
The HTTP endpoint itself necessarily returns fresh public challenges.

Run with a new or existing private directory:
  python3 passkey_rp.py --root /absolute/private-rp --fixture-cert-sha256 HEX64
  python3 passkey_rp.py --self-test

The service uses cryptography when installed, otherwise the OpenSSL executable.
--crypto-backend openssl forces the stdlib + OpenSSL path. All filesystem state
is serialized under an exclusive process lock. An uncertain write fences the
store until reopen. Restart invalidates every unfinished challenge.

Protocol references:
https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
https://developer.android.com/identity/sign-in/credential-provider
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


RP_ID = "passkeys.heptabao.test"
RP_NAME = "HeptaBao synthetic RP"
SCHEMA = "heptabao.synthetic.passkey-rp.v1"
MAX_BODY = 65536
MAX_STATE = 4 * 1024 * 1024
MAX_CREDENTIALS = 32
MAX_CEREMONIES = 1024
MAX_EVENTS = 4096
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
COUNTER_KEYS = {"options", "verification_attempts", "registrations", "authentications", "rejected", "restart_invalidated"}


class RPError(Exception):
    """A fixed, non-secret error code safe to return to the fixture."""

    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def require(value: bool, code: str, status: int = 400) -> None:
    if not value:
        raise RPError(code, status)


def encode64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode64(value: Any, *, size: int | None = None, maximum: int = 8192) -> bytes:
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3, "invalid_base64url")
    require(re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None, "invalid_base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise RPError("invalid_base64url") from None
    require(len(decoded) <= maximum and encode64(decoded) == value, "invalid_base64url")
    require(size is None or len(decoded) == size, "invalid_binary_length")
    return decoded


def exact(value: Any, keys: set[str], code: str = "unexpected_fields") -> dict:
    require(type(value) is dict and set(value) == keys, code)
    return value


def strict_json(raw: bytes, maximum: int = MAX_BODY) -> Any:
    require(type(raw) is bytes and len(raw) <= maximum, "json_size_limit")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def integer(value: str) -> int:
        require(len(value) <= 20, "invalid_json_number")
        return int(value)

    def no_float(_: str) -> Any:
        raise RPError("invalid_json_number")

    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                            parse_int=integer, parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, ValueError, RecursionError):
        raise RPError("invalid_json") from None
    nodes = 0

    def walk(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        require(depth <= 16 and nodes <= (100000 if maximum > MAX_BODY else 4096), "json_complexity_limit")
        if type(value) is str:
            try:
                value.encode("utf-8", "strict")
            except UnicodeError:
                raise RPError("invalid_json_unicode") from None
        elif type(value) is dict:
            for key, item in value.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
        elif type(value) is list:
            for item in value:
                walk(item, depth + 1)
        else:
            require(value is None or type(value) in (bool, int), "invalid_json_type")

    walk(result, 0)
    return result


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CBOR:
    """Bounded deterministic subset: integers, byte/text strings, and maps.

    WebAuthn fields outside this deliberately narrow profile are rejected;
    arrays, tags, indefinite lengths, floats, and simple values are not needed.
    No cryptographic algorithm is implemented by this decoder.
    """

    def __init__(self, data: bytes, start: int = 0):
        require(len(data) <= 4096, "cbor_size_limit")
        self.data = data
        self.pos = start
        self.nodes = 0

    def take(self, length: int) -> bytes:
        require(0 <= length <= len(self.data) - self.pos, "truncated_cbor")
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return value

    def item(self, depth: int = 0) -> Any:
        self.nodes += 1
        require(depth <= 6 and self.nodes <= 128, "cbor_complexity_limit")
        head = self.take(1)[0]
        major, minor = head >> 5, head & 31
        require(major in (0, 1, 2, 3, 5), "unsupported_cbor_type")
        if minor < 24:
            count = minor
        else:
            require(minor in (24, 25, 26, 27), "indefinite_cbor_rejected")
            width = 1 << (minor - 24)
            count = int.from_bytes(self.take(width), "big")
            require(count >= {1: 24, 2: 256, 4: 65536, 8: 4294967296}[width], "nonminimal_cbor_integer")
        if major == 0:
            return count
        if major == 1:
            return -1 - count
        if major in (2, 3):
            require(count <= (4096 if major == 2 else 128), "cbor_string_limit")
            value = self.take(count)
            if major == 2:
                return value
            try:
                return value.decode("utf-8", "strict")
            except UnicodeError:
                raise RPError("invalid_cbor_utf8") from None
        require(count <= 16, "cbor_map_limit")
        result: dict = {}
        for _ in range(count):
            key = self.item(depth + 1)
            require(type(key) in (int, str), "unsupported_cbor_map_key")
            require(key not in result, "duplicate_cbor_key")
            result[key] = self.item(depth + 1)
        return result

    def complete(self) -> Any:
        value = self.item()
        require(self.pos == len(self.data), "trailing_cbor_data")
        return value


def signature_der(signature: bytes) -> None:
    # P-256 ASN.1 DER contains two minimal, positive INTEGERs. This only checks
    # canonical framing; a mature crypto implementation verifies the signature.
    require(8 <= len(signature) <= 72 and signature[0] == 0x30 and signature[1] == len(signature) - 2,
            "invalid_signature_der")
    offset = 2
    for _ in range(2):
        require(offset + 2 <= len(signature) and signature[offset] == 2, "invalid_signature_der")
        length = signature[offset + 1]
        offset += 2
        require(1 <= length <= 33 and offset + length <= len(signature), "invalid_signature_der")
        value = signature[offset:offset + length]
        require(value[0] < 128 and (length == 1 or value[0] != 0 or value[1] >= 128), "invalid_signature_der")
        require(length < 33 or value[0] == 0, "invalid_signature_der")
        offset += length
    require(offset == len(signature), "invalid_signature_der")


class Crypto:
    def __init__(self, mode: str = "auto"):
        self.mode = mode
        self.ec = self.hashes = self.serialization = None
        if mode != "openssl":
            try:
                import cryptography
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                self.ec, self.hashes, self.serialization = ec, hashes, serialization
                self.description = {"name": "cryptography", "version": cryptography.__version__}
                return
            except ImportError:
                require(mode != "cryptography", "crypto_backend_unavailable", 503)
        self.openssl = shutil.which("openssl")
        require(self.openssl is not None, "crypto_backend_unavailable", 503)
        result = self.command(["version"])
        require(result.returncode == 0, "crypto_backend_unavailable", 503)
        self.description = {"name": "openssl", "version": result.stdout.decode("ascii", "replace").strip()[:160]}

    def command(self, args: list[str], data: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.openssl, *args], input=data, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RPError("crypto_backend_unavailable", 503) from None

    def point(self, x: bytes, y: bytes) -> bytes:
        require(type(x) is bytes and type(y) is bytes and len(x) == len(y) == 32, "invalid_public_key")
        der = SPKI_PREFIX + x + y
        if self.ec is not None:
            try:
                self.ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                 self.ec.SECP256R1()).public_key()
            except (ValueError, TypeError):
                raise RPError("invalid_public_key") from None
        else:
            result = self.command(["pkey", "-pubin", "-inform", "DER", "-pubcheck", "-noout"], der)
            require(result.returncode == 0, "invalid_public_key")
        return der

    def verify(self, der: bytes, signature: bytes, message: bytes) -> None:
        signature_der(signature)
        if self.ec is not None:
            from cryptography.exceptions import InvalidSignature
            try:
                key = self.serialization.load_der_public_key(der)
                require(isinstance(key, self.ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1", "invalid_public_key")
                key.verify(signature, message, self.ec.ECDSA(self.hashes.SHA256()))
            except (ValueError, TypeError, InvalidSignature):
                raise RPError("invalid_signature") from None
        else:
            # These files contain public key/signature material only. The RP
            # never receives or creates an authenticator's private key.
            with tempfile.TemporaryDirectory(prefix="heptabao-rp-public-verify-") as folder:
                key_path, signature_path = Path(folder) / "public.der", Path(folder) / "signature.der"
                key_path.write_bytes(der)
                signature_path.write_bytes(signature)
                result = self.command(["dgst", "-sha256", "-verify", str(key_path), "-keyform", "DER",
                                       "-signature", str(signature_path)], message)
            require(result.returncode == 0, "invalid_signature")


def flags_valid(flags: int, *, registration: bool) -> None:
    require(type(flags) is int and 0 <= flags <= 255, "invalid_flags")
    require(flags & ~0x5D == 0, "unsupported_flags")
    require(flags & 0x01 != 0, "user_presence_required")
    require(flags & 0x04 != 0, "user_verification_required")
    require(flags & 0x08 != 0 and (not flags & 0x10 or flags & 0x08), "backup_eligibility_required")
    require(bool(flags & 0x40) == registration, "attested_data_flag_mismatch")
    if registration:
        require(flags & 0x10 == 0, "initial_backup_state_rejected")


def client_data(response: dict, challenge: str, origin: str, kind: str) -> bytes:
    raw = decode64(response.get("clientDataJSON"), maximum=4096)
    value = exact(strict_json(raw), {"type", "challenge", "origin", "crossOrigin"}, "client_data_fields")
    require(value["type"] == ("webauthn.create" if kind == "registration" else "webauthn.get"), "ceremony_type_mismatch")
    decode64(value["challenge"], size=32)
    require(value["challenge"] == challenge, "challenge_mismatch")
    require(value["origin"] == origin, "origin_mismatch")
    require(value["crossOrigin"] is False, "cross_origin_rejected")
    return raw


def credential_envelope(value: Any) -> tuple[str, dict]:
    obj = exact(value, {"id", "rawId", "type", "authenticatorAttachment", "response", "clientExtensionResults"}, "credential_fields")
    decode64(obj["id"], size=32)
    require(obj["rawId"] == obj["id"], "credential_id_mismatch")
    require(obj["type"] == "public-key" and obj["authenticatorAttachment"] == "platform", "credential_type_rejected")
    exact(obj["clientExtensionResults"], set(), "extensions_rejected")
    require(type(obj["response"]) is dict, "response_fields")
    return obj["id"], obj["response"]


class Store:
    def __init__(self, root: str | Path, cert_sha256: str, *, ttl: int = 180,
                 backend: str = "auto", clock=time.monotonic):
        require(type(ttl) is int and 1 <= ttl <= 300, "invalid_challenge_ttl")
        require(type(cert_sha256) is str and re.fullmatch(r"[0-9a-fA-F]{64}", cert_sha256) is not None, "invalid_fixture_certificate")
        path = Path(root)
        require(path.is_absolute() and str(path) == str(path.resolve()), "root_must_be_absolute_without_symlinks")
        self.root, self.cert, self.ttl, self.clock = path, cert_sha256.lower(), ttl, clock
        self.origin = "android:apk-key-hash:" + encode64(bytes.fromhex(self.cert))
        self.crypto = Crypto(backend)
        self.source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.run_id = encode64(secrets.token_bytes(32))
        self.root_fd = self.lock_fd = None
        self.fenced = False
        self.deadlines: dict[str, float] = {}
        try:
            if not path.exists():
                path.mkdir(mode=0o700)
            self.root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self.root_fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "root_permissions_rejected", 503)
            self.lock_fd = os.open("rp.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.root_fd)
            self._private_file(self.lock_fd)
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RPError("root_in_use", 503) from None
            try:
                self.state = strict_json(self._read("state.public.json"), MAX_STATE)
                self._validate_state()
            except FileNotFoundError:
                self.state = {"schema": SCHEMA, "rp_id": RP_ID, "fixture_cert_sha256": self.cert,
                              "origin": self.origin, "user_id": encode64(secrets.token_bytes(32)),
                              "created_at": stamp(), "created_by_source_sha256": self.source_sha256,
                              "revision": 0, "last_run_id": self.run_id, "credentials": {}, "ceremonies": {},
                              "counters": {key: 0 for key in COUNTER_KEYS}, "events": []}
            data = copy.deepcopy(self.state)
            self.start_counters = data["counters"].copy()
            for ceremony in data["ceremonies"].values():
                if ceremony["status"] == "pending":
                    ceremony["status"] = "restart_invalidated"
                    data["counters"]["restart_invalidated"] += 1
            data["last_run_id"] = self.run_id
            self._commit(data, "server_started")
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        for name in ("lock_fd", "root_fd"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    @staticmethod
    def _private_file(fd: int) -> None:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "state_permissions_rejected", 503)

    def _read(self, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.root_fd)
        try:
            self._private_file(fd)
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, min(65536, MAX_STATE + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                require(total <= MAX_STATE, "state_size_limit", 503)
            # Reopening after an ambiguous acknowledgement validates and syncs
            # the actual descriptor and directory, not a separately opened path.
            os.fsync(fd)
            os.fsync(self.root_fd)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _validate_state(self) -> None:
        try:
            value = exact(self.state, {"schema", "rp_id", "fixture_cert_sha256", "origin", "user_id", "created_at",
                                      "created_by_source_sha256", "revision", "last_run_id", "credentials", "ceremonies", "counters", "events"})
            require(value["schema"] == SCHEMA and value["rp_id"] == RP_ID and value["fixture_cert_sha256"] == self.cert
                    and value["origin"] == self.origin, "state_policy_mismatch", 503)
            decode64(value["user_id"], size=32)
            decode64(value["last_run_id"], size=32)
            require(type(value["revision"]) is int and value["revision"] >= 1, "invalid_state")
            require(type(value["created_at"]) is str and type(value["created_by_source_sha256"]) is str
                    and re.fullmatch(r"[0-9a-f]{64}", value["created_by_source_sha256"]) is not None, "invalid_state")
            exact(value["counters"], COUNTER_KEYS)
            require(all(type(number) is int and number >= 0 for number in value["counters"].values()), "invalid_state")
            require(type(value["credentials"]) is dict and len(value["credentials"]) <= MAX_CREDENTIALS, "invalid_state")
            for identifier, credential in value["credentials"].items():
                decode64(identifier, size=32)
                exact(credential, {"x", "y", "public_key_sha256", "sign_count", "flags", "user_id", "created_at", "last_used_at"})
                der = self.crypto.point(decode64(credential["x"], size=32), decode64(credential["y"], size=32))
                require(hashlib.sha256(der).hexdigest() == credential["public_key_sha256"], "invalid_state")
                require(credential["user_id"] == value["user_id"] and type(credential["sign_count"]) is int
                        and 0 <= credential["sign_count"] <= 0xFFFFFFFF, "invalid_state")
                flags_valid(credential["flags"], registration=credential["sign_count"] == 0)
                require(type(credential["created_at"]) is str and type(credential["last_used_at"]) in (str, type(None)), "invalid_state")
            require(type(value["ceremonies"]) is dict and len(value["ceremonies"]) <= MAX_CEREMONIES, "invalid_state")
            for identifier, ceremony in value["ceremonies"].items():
                decode64(identifier, size=32)
                exact(ceremony, {"kind", "challenge", "status", "run_id", "created_at", "expires_at_ms", "allowed_ids"})
                require(ceremony["kind"] in ("registration", "authentication") and ceremony["status"]
                        in ("pending", "consumed", "restart_invalidated"), "invalid_state")
                decode64(ceremony["challenge"], size=32)
                decode64(ceremony["run_id"], size=32)
                require(type(ceremony["created_at"]) is str and type(ceremony["expires_at_ms"]) is int, "invalid_state")
                require(type(ceremony["allowed_ids"]) is list and len(ceremony["allowed_ids"]) <= MAX_CREDENTIALS
                        and len(set(ceremony["allowed_ids"])) == len(ceremony["allowed_ids"]), "invalid_state")
                for identifier in ceremony["allowed_ids"]:
                    decode64(identifier, size=32)
            require(type(value["events"]) is list and 1 <= len(value["events"]) <= MAX_EVENTS, "invalid_state")
            require(len(value["events"]) == value["revision"], "invalid_state")
            for number, event in enumerate(value["events"], 1):
                exact(event, {"sequence", "time", "kind", "code", "ceremony_sha256", "run_id", "source_sha256"})
                require(event["sequence"] == number and type(event["time"]) is str, "invalid_state")
                require(event["kind"] in ("server_started", "options_issued", "verification_consumed", "registration_accepted",
                                          "authentication_accepted", "verification_rejected"), "invalid_state")
                require(event["code"] is None or type(event["code"]) is str and re.fullmatch(r"[a-z0-9_]{1,80}", event["code"]) is not None, "invalid_state")
                require(event["ceremony_sha256"] is None or type(event["ceremony_sha256"]) is str
                        and re.fullmatch(r"[0-9a-f]{64}", event["ceremony_sha256"]) is not None, "invalid_state")
                decode64(event["run_id"], size=32)
                require(type(event["source_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", event["source_sha256"]) is not None, "invalid_state")
        except RPError as failure:
            if failure.code == "state_policy_mismatch":
                raise
            raise RPError("state_invalid", 503) from None
        except (TypeError, KeyError, ValueError):
            raise RPError("state_invalid", 503) from None

    def _atomic_write(self, name: str, raw: bytes) -> None:
        require(len(raw) <= MAX_STATE, "state_capacity_exceeded", 503)
        temporary = ".rp-write-" + secrets.token_hex(16)
        fd = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.root_fd)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                require(written > 0, "storage_unavailable", 503)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temporary, name, src_dir_fd=self.root_fd, dst_dir_fd=self.root_fd)
            os.fsync(self.root_fd)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=self.root_fd)
            except FileNotFoundError:
                pass

    def _available(self) -> None:
        require(not self.fenced and self.root_fd is not None, "store_fenced_reopen_required", 503)

    def _commit(self, data: dict, kind: str, ceremony_id: str | None = None, code: str | None = None) -> None:
        self._available()
        require(len(data["events"]) < MAX_EVENTS, "event_capacity_exceeded", 503)
        data["revision"] += 1
        data["events"].append({"sequence": data["revision"], "time": stamp(), "kind": kind, "code": code,
                               "ceremony_sha256": hashlib.sha256(ceremony_id.encode("ascii")).hexdigest() if ceremony_id else None,
                               "run_id": self.run_id, "source_sha256": self.source_sha256})
        raw = json_bytes(data)
        manifest = self._manifest(data, hashlib.sha256(raw).hexdigest())
        try:
            self._atomic_write("state.public.json", raw)
            self._atomic_write("result.manifest.json", json_bytes(manifest))
        except (OSError, RPError):
            self.fenced = True
            raise RPError("storage_uncertain_reopen_required", 503) from None
        self.state = data

    def _public(self, data: dict) -> dict:
        return {"rp_id": RP_ID, "fixture_cert_sha256": self.cert, "origin": self.origin,
                "revision": data["revision"], "credential_count": len(data["credentials"]),
                "ceremony_counts": {status: sum(value["status"] == status for value in data["ceremonies"].values())
                                    for status in ("pending", "consumed", "restart_invalidated")},
                "counters": data["counters"].copy(), "event_count": len(data["events"]),
                "credentials": [{"credential_id": identifier, "public_key_sha256": value["public_key_sha256"],
                                 "sign_count": value["sign_count"], "flags": value["flags"]}
                                for identifier, value in sorted(data["credentials"].items())]}

    def _manifest(self, data: dict, state_sha256: str) -> dict:
        return {"schema": SCHEMA, "scope": "local_synthetic_native_android_rp_only", "run_id": self.run_id,
                "source_sha256": self.source_sha256, "state_created_by_source_sha256": data["created_by_source_sha256"],
                "state_sha256": state_sha256, "crypto_backend": self.crypto.description,
                "public_key_hash_format": "sha256_of_spki_der", "challenge_ttl_seconds": self.ttl,
                "current_run_counters": {key: data["counters"][key] - self.start_counters[key] for key in COUNTER_KEYS},
                "state": self._public(data), "synthetic_only": True,
                "phone_create_qualified": False, "phone_login_qualified": False,
                "phone_migration_qualified": False, "phone_recovery_qualified": False,
                "hardware_or_biometric_attested": False, "digital_asset_links_qualified": False,
                "p5_qualified": False,
                "limitations": ["none attestation cannot independently attest UV or hardware",
                                "exact native fixture certificate policy, no website association claim",
                                "old backup counter rollback is rejected",
                                "restart invalidates pending challenges; consumed responses are never replayed",
                                "local owner UID is trusted; not same-UID isolation"]}

    def public_state(self) -> dict:
        self._available()
        return {"ok": True, **self._public(self.state)}

    def options(self, kind: str, body: Any) -> dict:
        self._available()
        require(kind in ("registration", "authentication"), "invalid_ceremony")
        require(type(body) is dict, "options_fields")
        credentials = self.state["credentials"]
        if kind == "registration":
            exact(body, set(), "options_fields")
            require(len(credentials) < MAX_CREDENTIALS, "credential_capacity_exceeded", 409)
            allowed = sorted(credentials)
        else:
            require(set(body) in (set(), {"credential_id"}), "options_fields")
            if body:
                decode64(body["credential_id"], size=32)
                require(body["credential_id"] in credentials, "unknown_credential", 404)
                allowed = [body["credential_id"]]
            else:
                allowed = sorted(credentials)
            require(bool(allowed), "no_registered_credentials", 409)
        require(len(self.state["ceremonies"]) < MAX_CEREMONIES, "ceremony_capacity_exceeded", 503)
        require(len(self.state["events"]) + 3 <= MAX_EVENTS, "event_capacity_exceeded", 503)
        ceremony_id, challenge = encode64(secrets.token_bytes(32)), encode64(secrets.token_bytes(32))
        deadline = self.clock() + self.ttl
        data = copy.deepcopy(self.state)
        data["ceremonies"][ceremony_id] = {"kind": kind, "challenge": challenge, "status": "pending",
                                           "run_id": self.run_id, "created_at": stamp(),
                                           "expires_at_ms": int(time.time() * 1000) + self.ttl * 1000,
                                           "allowed_ids": allowed}
        data["counters"]["options"] += 1
        self._commit(data, "options_issued", ceremony_id)
        self.deadlines[ceremony_id] = deadline
        public_key = {"challenge": challenge, "timeout": self.ttl * 1000}
        if kind == "registration":
            public_key.update({"rp": {"id": RP_ID, "name": RP_NAME},
                               "user": {"id": data["user_id"], "name": "synthetic-user", "displayName": "Synthetic passkey"},
                               "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                               "authenticatorSelection": {"authenticatorAttachment": "platform", "residentKey": "required",
                                                          "requireResidentKey": True, "userVerification": "required"},
                               "attestation": "none", "excludeCredentials": [{"type": "public-key", "id": identifier} for identifier in allowed]})
        else:
            public_key.update({"rpId": RP_ID, "allowCredentials": [{"type": "public-key", "id": identifier, "transports": ["internal"]}
                                                                   for identifier in allowed], "userVerification": "required"})
        return {"ceremony_id": ceremony_id, "publicKey": public_key}

    def _consume(self, identifier: str) -> dict:
        decode64(identifier, size=32)
        record = self.state["ceremonies"].get(identifier)
        require(record is not None and record["status"] == "pending", "challenge_unknown_or_consumed", 409)
        require(len(self.state["events"]) + 2 <= MAX_EVENTS, "event_capacity_exceeded", 503)
        expired = identifier not in self.deadlines or self.clock() >= self.deadlines[identifier]
        data = copy.deepcopy(self.state)
        data["ceremonies"][identifier]["status"] = "consumed"
        data["counters"]["verification_attempts"] += 1
        self._commit(data, "verification_consumed", identifier)
        self.deadlines.pop(identifier, None)
        require(not expired, "challenge_expired", 409)
        return record

    def verify(self, kind: str, body: Any) -> dict:
        self._available()
        identifier = None
        try:
            require(type(body) is dict and type(body.get("ceremony_id")) is str, "verification_fields")
            identifier = body["ceremony_id"]
            record = self._consume(identifier)
            exact(body, {"ceremony_id", "credential"}, "verification_fields")
            require(record["kind"] == kind, "ceremony_type_mismatch")
            credential_id, response = credential_envelope(body["credential"])
            if kind == "registration":
                result, credential = self._registration(credential_id, response, record)
            else:
                result, credential = self._authentication(credential_id, response, record)
            data = copy.deepcopy(self.state)
            data["credentials"][credential_id] = credential
            data["counters"]["registrations" if kind == "registration" else "authentications"] += 1
            self._commit(data, kind + "_accepted", identifier)
            return result
        except RPError as failure:
            if self.fenced or failure.status == 503:
                raise
            data = copy.deepcopy(self.state)
            data["counters"]["rejected"] += 1
            # Hash only syntactically canonical ceremony IDs; malformed input is
            # never reflected into events or exception text.
            safe_id = identifier if type(identifier) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", identifier) else None
            self._commit(data, "verification_rejected", safe_id, failure.code)
            raise

    def _registration(self, identifier: str, response: dict, ceremony: dict) -> tuple[dict, dict]:
        exact(response, {"clientDataJSON", "attestationObject", "transports"}, "registration_response_fields")
        require(response["transports"] == ["internal"], "transport_rejected")
        client_data(response, ceremony["challenge"], self.origin, "registration")
        obj = exact(CBOR(decode64(response["attestationObject"], maximum=4096)).complete(), {"fmt", "authData", "attStmt"}, "attestation_fields")
        require(obj["fmt"] == "none", "attestation_format_rejected")
        exact(obj["attStmt"], set(), "attestation_statement_rejected")
        auth = obj["authData"]
        require(type(auth) is bytes and len(auth) >= 55 + 32, "invalid_authenticator_data")
        require(auth[:32] == hashlib.sha256(RP_ID.encode("ascii")).digest(), "rp_id_hash_mismatch")
        flags, count = auth[32], int.from_bytes(auth[33:37], "big")
        flags_valid(flags, registration=True)
        require(count == 0, "initial_counter_rejected")
        require(auth[37:53] == bytes(16), "aaguid_rejected")
        require(int.from_bytes(auth[53:55], "big") == 32 and encode64(auth[55:87]) == identifier, "credential_id_mismatch")
        cose = CBOR(auth, 87).complete()
        require(type(cose) is dict and set(cose) == {1, 3, -1, -2, -3}, "cose_fields")
        require(cose[1] == 2 and cose[3] == -7 and cose[-1] == 1, "cose_algorithm_rejected")
        der = self.crypto.point(cose[-2], cose[-3])
        require(identifier not in self.state["credentials"], "credential_already_registered", 409)
        require(len(self.state["credentials"]) < MAX_CREDENTIALS, "credential_capacity_exceeded", 409)
        credential = {"x": encode64(cose[-2]), "y": encode64(cose[-3]), "public_key_sha256": hashlib.sha256(der).hexdigest(),
                      "sign_count": 0, "flags": flags, "user_id": self.state["user_id"], "created_at": stamp(), "last_used_at": None}
        return self._result(identifier, credential), credential

    def _authentication(self, identifier: str, response: dict, ceremony: dict) -> tuple[dict, dict]:
        exact(response, {"clientDataJSON", "authenticatorData", "signature", "userHandle"}, "authentication_response_fields")
        require(identifier in ceremony["allowed_ids"] and identifier in self.state["credentials"], "credential_not_allowed", 403)
        credential = copy.deepcopy(self.state["credentials"][identifier])
        raw_client = client_data(response, ceremony["challenge"], self.origin, "authentication")
        decode64(response["userHandle"], size=32)
        require(response["userHandle"] == credential["user_id"], "user_handle_mismatch")
        auth = decode64(response["authenticatorData"], size=37)
        require(auth[:32] == hashlib.sha256(RP_ID.encode("ascii")).digest(), "rp_id_hash_mismatch")
        flags, count = auth[32], int.from_bytes(auth[33:37], "big")
        flags_valid(flags, registration=False)
        require(count > credential["sign_count"], "counter_rollback_or_replay", 409)
        der = self.crypto.point(decode64(credential["x"], size=32), decode64(credential["y"], size=32))
        self.crypto.verify(der, decode64(response["signature"], maximum=72), auth + hashlib.sha256(raw_client).digest())
        credential.update(sign_count=count, flags=flags, last_used_at=stamp())
        return self._result(identifier, credential), credential

    @staticmethod
    def _result(identifier: str, credential: dict) -> dict:
        return {"ok": True, "credential_id": identifier, "public_key_sha256": credential["public_key_sha256"],
                "sign_count": credential["sign_count"], "flags": credential["flags"]}


class Server(http.server.HTTPServer):
    # Reopen our fixed loopback endpoint while previous accepted connections
    # remain in TIME_WAIT. SO_REUSEPORT stays disabled: an active listener still
    # owns the address exclusively.
    allow_reuse_address = True
    request_queue_size = 8

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address

    def handle_error(self, *_):
        # No traceback can reflect request material to stderr.
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "HeptaBaoSyntheticRP"
    sys_version = ""

    def log_message(self, *_):
        pass

    def log_error(self, *_):
        pass

    def send_error(self, code, message=None, explain=None):
        self.reply(int(code), {"ok": False, "error": "http_request_rejected"})

    def reply(self, status_code: int, value: dict) -> None:
        raw = json_bytes(value)
        self.close_connection = True
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, socket.timeout):
            # Verification was already committed before response delivery. A
            # lost acknowledgement must not enable a second use of the challenge.
            pass

    def envelope(self, *, post: bool) -> bytes:
        require(self.client_address[0] == "127.0.0.1", "loopback_required", 403)
        for header in ("Host", "Content-Length", "Content-Type", "Origin"):
            require(len(self.headers.get_all(header, [])) <= 1, "duplicate_http_header")
        require(len(self.headers) <= 32 and sum(len(key) + len(value) for key, value in self.headers.items()) <= 8192,
                "http_header_limit")
        port = self.server.server_address[1]
        require(self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}"), "host_rejected", 403)
        require("Origin" not in self.headers and "Transfer-Encoding" not in self.headers and "Content-Encoding" not in self.headers,
                "http_framing_or_origin_rejected", 403)
        require("?" not in self.path and "#" not in self.path, "path_rejected", 404)
        if not post:
            require(self.headers.get("Content-Length", "0") == "0", "unexpected_request_body")
            return b""
        require(self.headers.get("Content-Type", "").lower() in ("application/json", "application/json; charset=utf-8"),
                "json_content_type_required", 415)
        length = self.headers.get("Content-Length", "")
        require(re.fullmatch(r"0|[1-9][0-9]{0,5}", length) is not None and int(length) <= MAX_BODY, "body_size_limit", 413)
        raw = self.rfile.read(int(length))
        require(len(raw) == int(length), "truncated_request_body")
        return raw

    def do_GET(self) -> None:
        try:
            self.envelope(post=False)
            store = self.server.store
            if self.path == "/health":
                value = {"ok": not store.fenced, "scope": "local_synthetic_native_android_rp_only", "fenced": store.fenced}
                self.reply(503 if store.fenced else 200, value)
            elif self.path == "/state":
                self.reply(200, store.public_state())
            else:
                raise RPError("path_rejected", 404)
        except RPError as failure:
            self.reply(failure.status, {"ok": False, "error": failure.code})
        except (OSError, ValueError):
            self.reply(503, {"ok": False, "error": "request_unavailable"})

    def do_POST(self) -> None:
        try:
            raw = self.envelope(post=True)
            routes = {"/registration/options": ("registration", "options"), "/registration/verify": ("registration", "verify"),
                      "/authentication/options": ("authentication", "options"), "/authentication/verify": ("authentication", "verify")}
            require(self.path in routes, "path_rejected", 404)
            kind, operation = routes[self.path]
            value = getattr(self.server.store, operation)(kind, strict_json(raw))
            self.reply(200, value)
        except RPError as failure:
            self.reply(failure.status, {"ok": False, "error": failure.code})
        except (OSError, ValueError):
            self.reply(503, {"ok": False, "error": "request_unavailable"})


def self_test(backend: str = "auto") -> dict:
    """Synthetic protocol/storage tests, deliberately without a network socket."""
    results = []

    def check(name, function):
        try:
            function()
            results.append({"id": name, "passed": True})
        except Exception as failure:
            results.append({"id": name, "passed": False,
                            "error": failure.code if isinstance(failure, RPError) else type(failure).__name__})

    def denied(function, code=None):
        try:
            function()
        except RPError as failure:
            assert code is None or failure.code == code
            return failure.code
        raise AssertionError("expected rejection")

    def cbor(value):
        def header(major, number):
            if number < 24:
                return bytes([(major << 5) | number])
            for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
                if number < 1 << (width * 8):
                    return bytes([(major << 5) | marker]) + number.to_bytes(width, "big")
            raise ValueError("test cbor integer")
        if type(value) is int:
            return header(0 if value >= 0 else 1, value if value >= 0 else -1 - value)
        if type(value) is bytes:
            return header(2, len(value)) + value
        if type(value) is str:
            raw = value.encode("utf-8")
            return header(3, len(raw)) + raw
        if type(value) is dict:
            return header(5, len(value)) + b"".join(cbor(key) + cbor(item) for key, item in value.items())
        raise ValueError("test cbor type")

    with tempfile.TemporaryDirectory(prefix="heptabao-synthetic-rp-selftest-") as temporary:
        root = Path(temporary) / "rp"
        cert = "5a" * 32
        signer_path = Path(temporary) / "synthetic-signing-key.pem"
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            signer = ec.generate_private_key(ec.SECP256R1())
            numbers = signer.public_key().public_numbers()
            x, y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")

            def sign(message):
                return signer.sign(message, ec.ECDSA(hashes.SHA256()))
        except ImportError:
            openssl = shutil.which("openssl")
            require(openssl is not None, "crypto_backend_unavailable", 503)

            def command(arguments, raw=None):
                result = subprocess.run([openssl, *arguments], input=raw, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=5, check=False)
                require(result.returncode == 0, "self_test_crypto_failed", 503)
                return result.stdout

            command(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(signer_path)])
            os.chmod(signer_path, 0o600)
            der = command(["pkey", "-in", str(signer_path), "-pubout", "-outform", "DER"])
            require(der.startswith(SPKI_PREFIX) and len(der) == len(SPKI_PREFIX) + 64, "self_test_crypto_failed", 503)
            x, y = der[-64:-32], der[-32:]

            def sign(message):
                return command(["dgst", "-sha256", "-sign", str(signer_path)], message)

        store = Store(root, cert, backend=backend)
        backend_description = store.crypto.description
        credential_id = encode64(secrets.token_bytes(32))

        def credential(identifier, response):
            return {"id": identifier, "rawId": identifier, "type": "public-key", "authenticatorAttachment": "platform",
                    "response": response, "clientExtensionResults": {}}

        def client(options, kind, overrides=None):
            value = {"type": "webauthn.create" if kind == "registration" else "webauthn.get",
                     "challenge": options["publicKey"]["challenge"], "origin": store.origin, "crossOrigin": False}
            value.update(overrides or {})
            return json_bytes(value)

        def registration(options, identifier=None, *, flags=0x4D, counter=0, rp_hash=None, point=None, client_overrides=None):
            identifier = identifier or credential_id
            public_x, public_y = point or (x, y)
            auth = ((rp_hash if rp_hash is not None else hashlib.sha256(RP_ID.encode("ascii")).digest())
                    + bytes([flags]) + counter.to_bytes(4, "big") + bytes(16) + (32).to_bytes(2, "big")
                    + decode64(identifier, size=32) + cbor({1: 2, 3: -7, -1: 1, -2: public_x, -3: public_y}))
            response = {"clientDataJSON": encode64(client(options, "registration", client_overrides)),
                        "attestationObject": encode64(cbor({"fmt": "none", "authData": auth, "attStmt": {}})),
                        "transports": ["internal"]}
            return {"ceremony_id": options["ceremony_id"], "credential": credential(identifier, response)}

        def authentication(options, *, counter=None, flags=0x0D, rp_hash=None, client_overrides=None, user_handle=None):
            count = store.state["credentials"][credential_id]["sign_count"] + 1 if counter is None else counter
            auth = ((rp_hash if rp_hash is not None else hashlib.sha256(RP_ID.encode("ascii")).digest())
                    + bytes([flags]) + count.to_bytes(4, "big"))
            raw_client = client(options, "authentication", client_overrides)
            response = {"clientDataJSON": encode64(raw_client), "authenticatorData": encode64(auth),
                        "signature": encode64(sign(auth + hashlib.sha256(raw_client).digest())),
                        "userHandle": user_handle or store.state["user_id"]}
            return {"ceremony_id": options["ceremony_id"], "credential": credential(credential_id, response)}

        def positive_registration():
            options = store.options("registration", {})
            assert options["publicKey"]["rp"]["id"] == RP_ID
            result = store.verify("registration", registration(options))
            assert result["ok"] and result["sign_count"] == 0 and result["flags"] == 0x4D
            assert result["public_key_sha256"] == hashlib.sha256(SPKI_PREFIX + x + y).hexdigest()

        def positive_authentication(flags=0x0D):
            options = store.options("authentication", {"credential_id": credential_id})
            assert options["publicKey"]["allowCredentials"] == [{"type": "public-key", "id": credential_id, "transports": ["internal"]}]
            before = store.state["credentials"][credential_id]["sign_count"]
            result = store.verify("authentication", authentication(options, flags=flags))
            assert result["sign_count"] == before + 1 and result["flags"] == flags

        check("positive_registration_none_attestation_es256", positive_registration)
        check("positive_signed_authentication_counter_advances", positive_authentication)
        check("backup_state_signed_flag_and_increasing_counter", lambda: positive_authentication(0x1D))

        def registration_negative(code, builder=None, mutation=None):
            options = store.options("registration", {})
            body = registration(options, encode64(secrets.token_bytes(32)), **(builder or {}))
            if mutation:
                mutation(body)
            before = len(store.state["credentials"])
            denied(lambda: store.verify("registration", body), code)
            assert len(store.state["credentials"]) == before
            denied(lambda: store.verify("registration", body), "challenge_unknown_or_consumed")

        for name, builder, code in [
            ("registration_origin", {"client_overrides": {"origin": "https://passkeys.heptabao.test"}}, "origin_mismatch"),
            ("registration_challenge", {"client_overrides": {"challenge": encode64(bytes(32))}}, "challenge_mismatch"),
            ("registration_rp_hash", {"rp_hash": bytes(32)}, "rp_id_hash_mismatch"),
            ("registration_missing_up", {"flags": 0x4C}, "user_presence_required"),
            ("registration_missing_uv", {"flags": 0x49}, "user_verification_required"),
            ("registration_missing_be", {"flags": 0x45}, "backup_eligibility_required"),
            ("registration_initial_bs", {"flags": 0x5D}, "initial_backup_state_rejected"),
            ("registration_missing_at", {"flags": 0x0D}, "attested_data_flag_mismatch"),
            ("registration_initial_counter", {"counter": 1}, "initial_counter_rejected"),
            ("registration_invalid_curve_point", {"point": (bytes(32), bytes(32))}, "invalid_public_key"),
        ]:
            check(name + "_denied_and_challenge_consumed", lambda builder=builder, code=code: registration_negative(code, builder))

        def registration_attestation_mutation(transform):
            def apply(body):
                response = body["credential"]["response"]
                value = CBOR(decode64(response["attestationObject"])).complete()
                response["attestationObject"] = encode64(transform(value))
            return apply

        for name, mutation, code in [
            ("truncated_cbor", lambda body: body["credential"]["response"].update(attestationObject=encode64(b"\xa3\x63fmt")), "truncated_cbor"),
            ("trailing_cbor", registration_attestation_mutation(lambda value: cbor(value) + b"\x00"), "trailing_cbor_data"),
            ("duplicate_cbor_key", registration_attestation_mutation(lambda value: b"\xa4" + cbor("fmt") + cbor("none") + cbor("fmt") + cbor("none") + cbor("authData") + cbor(value["authData"]) + cbor("attStmt") + b"\xa0"), "duplicate_cbor_key"),
            ("extra_attestation_field", registration_attestation_mutation(lambda value: cbor({**value, "extra": 1})), "attestation_fields"),
            ("nonempty_none_statement", registration_attestation_mutation(lambda value: cbor({**value, "attStmt": {"extra": 1}})), "attestation_statement_rejected"),
            ("unexpected_aaguid", registration_attestation_mutation(lambda value: cbor({**value, "authData": value["authData"][:37] + b"\x01" + value["authData"][38:]})), "aaguid_rejected"),
            ("unknown_cose_algorithm", registration_attestation_mutation(lambda value: cbor({**value, "authData": value["authData"][:87] + cbor({1: 2, 3: -257, -1: 1, -2: x, -3: y})})), "cose_algorithm_rejected"),
        ]:
            check(name + "_denied", lambda mutation=mutation, code=code: registration_negative(code, mutation=mutation))

        def authentication_negative(code, builder=None, mutation=None):
            options = store.options("authentication", {})
            body = authentication(options, **(builder or {}))
            if mutation:
                mutation(body)
            before = store.state["credentials"][credential_id]["sign_count"]
            denied(lambda: store.verify("authentication", body), code)
            assert store.state["credentials"][credential_id]["sign_count"] == before
            denied(lambda: store.verify("authentication", body), "challenge_unknown_or_consumed")

        for name, builder, code in [
            ("signed_wrong_challenge", {"client_overrides": {"challenge": encode64(bytes(32))}}, "challenge_mismatch"),
            ("signed_wrong_android_origin", {"client_overrides": {"origin": "android:apk-key-hash:" + encode64(bytes(32))}}, "origin_mismatch"),
            ("signed_wrong_rp_hash", {"rp_hash": bytes(32)}, "rp_id_hash_mismatch"),
            ("signed_wrong_type", {"client_overrides": {"type": "webauthn.create"}}, "ceremony_type_mismatch"),
            ("signed_cross_origin", {"client_overrides": {"crossOrigin": True}}, "cross_origin_rejected"),
            ("signed_missing_up", {"flags": 0x0C}, "user_presence_required"),
            ("signed_missing_uv", {"flags": 0x09}, "user_verification_required"),
            ("signed_reserved_flag", {"flags": 0x0F}, "unsupported_flags"),
            ("signed_extension_data_flag", {"flags": 0x8D}, "unsupported_flags"),
            ("signed_authentication_at_flag", {"flags": 0x4D}, "attested_data_flag_mismatch"),
            ("signed_bs_without_be", {"flags": 0x15}, "backup_eligibility_required"),
            ("old_backup_counter_rollback", {"counter": 1}, "counter_rollback_or_replay"),
            ("unchanged_counter_replay", {"counter": 2}, "counter_rollback_or_replay"),
            ("zero_counter_rejected", {"counter": 0}, "counter_rollback_or_replay"),
            ("wrong_user_handle", {"user_handle": encode64(bytes(32))}, "user_handle_mismatch"),
        ]:
            check(name + "_denied_and_counter_unchanged", lambda builder=builder, code=code: authentication_negative(code, builder))

        def tamper_signature(body):
            response = body["credential"]["response"]
            value = bytearray(decode64(response["signature"]))
            value[-1] ^= 1
            response["signature"] = encode64(value)

        for name, mutation, code in [
            ("tampered_signature", tamper_signature, "invalid_signature"),
            ("trailing_signature_der", lambda body: body["credential"]["response"].update(signature=encode64(b"\x30\x06\x02\x01\x01\x02\x01\x01\x00")), "invalid_signature_der"),
            ("padded_base64url_id", lambda body: body["credential"].update(id=credential_id + "="), "invalid_base64url"),
            ("raw_id_mismatch", lambda body: body["credential"].update(rawId=encode64(bytes(32))), "credential_id_mismatch"),
            ("extra_credential_field", lambda body: body["credential"].update(extra=True), "credential_fields"),
            ("extra_response_field", lambda body: body["credential"]["response"].update(extra=True), "authentication_response_fields"),
            ("extra_verification_field", lambda body: body.update(extra=True), "verification_fields"),
            ("client_extension_output", lambda body: body["credential"].update(clientExtensionResults={"extra": True}), "extensions_rejected"),
            ("wrong_attachment", lambda body: body["credential"].update(authenticatorAttachment="cross-platform"), "credential_type_rejected"),
        ]:
            check(name + "_denied", lambda mutation=mutation, code=code: authentication_negative(code, mutation=mutation))

        def duplicate_client_key(body):
            response = body["credential"]["response"]
            raw = decode64(response["clientDataJSON"]).rstrip()
            response["clientDataJSON"] = encode64(raw[:-1] + b',"type":"webauthn.get"}')

        check("duplicate_client_json_key_denied", lambda: authentication_negative("duplicate_json_key", mutation=duplicate_client_key))
        check("extra_signed_client_json_field_denied", lambda: authentication_negative("client_data_fields", {"client_overrides": {"extra": True}}))

        def accepted_replay():
            body = authentication(store.options("authentication", {}))
            count = store.verify("authentication", body)["sign_count"]
            denied(lambda: store.verify("authentication", body), "challenge_unknown_or_consumed")
            assert store.state["credentials"][credential_id]["sign_count"] == count

        check("accepted_response_is_one_use", accepted_replay)

        def existing_registration():
            options = store.options("registration", {})
            assert {"type": "public-key", "id": credential_id} in options["publicKey"]["excludeCredentials"]
            denied(lambda: store.verify("registration", registration(options)), "credential_already_registered")

        check("duplicate_registration_cannot_replace_key", existing_registration)

        def expiry():
            now = [10.0]
            with Store(Path(temporary) / "expiry", cert, ttl=1, backend=backend, clock=lambda: now[0]) as expiring:
                options = expiring.options("registration", {})
                body = registration(options)
                now[0] = 11.0
                denied(lambda: expiring.verify("registration", body), "challenge_expired")
                denied(lambda: expiring.verify("registration", body), "challenge_unknown_or_consumed")

        check("monotonic_ttl_expiry_consumes_challenge", expiry)

        def public_projection():
            options = store.options("authentication", {})
            state = json_bytes(store.public_state())
            manifest = (root / "result.manifest.json").read_bytes()
            for raw in (state, manifest):
                assert options["ceremony_id"].encode("ascii") not in raw
                assert options["publicKey"]["challenge"].encode("ascii") not in raw
            value = strict_json(manifest, MAX_STATE)
            assert all(value[name] is False for name in ("phone_create_qualified", "phone_login_qualified", "phone_migration_qualified",
                                                         "phone_recovery_qualified", "hardware_or_biometric_attested", "digital_asset_links_qualified", "p5_qualified"))
            assert value["state_sha256"] == hashlib.sha256((root / "state.public.json").read_bytes()).hexdigest()

        check("public_state_omits_challenges_and_manifest_keeps_scope", public_projection)

        def process_restart():
            nonlocal store
            pending = authentication(store.options("authentication", {}))
            expected_count = store.state["credentials"][credential_id]["sign_count"]
            store.close()
            child = """import json,sys
sys.path.insert(0,sys.argv[1])
from passkey_rp import Store,RPError
payload=json.load(sys.stdin)
with Store(sys.argv[2],sys.argv[3],backend=sys.argv[4]) as store:
    try:
        store.verify('authentication',payload)
        code='unexpected_success'
    except RPError as failure:
        code=failure.code
    print(json.dumps({'code':code,'credential_count':len(store.state['credentials']),'sign_count':next(iter(store.state['credentials'].values()))['sign_count']}))
"""
            result = subprocess.run([sys.executable, "-c", child, str(Path(__file__).resolve().parent), str(root), cert, backend],
                                    input=json_bytes(pending), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
            assert result.returncode == 0
            value = strict_json(result.stdout)
            assert value == {"code": "challenge_unknown_or_consumed", "credential_count": 1, "sign_count": expected_count}
            store = Store(root, cert, backend=backend)
            positive_authentication()

        check("independent_process_restart_keeps_keys_counters_and_invalidates_old_challenges", process_restart)

        def uncertain_write():
            nonlocal store
            body = authentication(store.options("authentication", {}))
            expected = store.state["credentials"][credential_id]["sign_count"] + 1
            original = store._atomic_write

            def fault(name, raw):
                original(name, raw)
                if name == "state.public.json" and strict_json(raw, MAX_STATE)["credentials"][credential_id]["sign_count"] == expected:
                    raise OSError("synthetic failure after state fsync before manifest")

            store._atomic_write = fault
            denied(lambda: store.verify("authentication", body), "storage_uncertain_reopen_required")
            denied(lambda: store.options("authentication", {}), "store_fenced_reopen_required")
            store.close()
            store = Store(root, cert, backend=backend)
            assert store.state["credentials"][credential_id]["sign_count"] == expected
            denied(lambda: store.verify("authentication", body), "challenge_unknown_or_consumed")

        check("uncertain_post_fsync_ack_fences_and_reopens_without_counter_rollback", uncertain_write)
        check("exclusive_process_lock_rejects_second_owner", lambda: denied(lambda: Store(root, cert, backend=backend), "root_in_use"))

        def certificate_change():
            nonlocal store
            store.close()
            denied(lambda: Store(root, "6b" * 32, backend=backend), "state_policy_mismatch")
            store = Store(root, cert, backend=backend)

        check("restart_with_different_fixture_certificate_denied", certificate_change)

        def directory_mode():
            path = Path(temporary) / "unsafe-root"
            path.mkdir(mode=0o700)
            path.chmod(0o755)
            denied(lambda: Store(path, cert, backend=backend), "root_permissions_rejected")

        check("nonprivate_root_denied", directory_mode)

        def symlink_root():
            link = Path(temporary) / "root-link"
            link.symlink_to(root, target_is_directory=True)
            denied(lambda: Store(link, cert, backend=backend), "root_must_be_absolute_without_symlinks")

        check("symlink_root_denied", symlink_root)

        # Exercise HTTP framing and origin checks through the actual handler
        # method using byte streams. This is not a listener/browser test.
        import email.message
        import io
        from types import SimpleNamespace

        def http_envelope(headers=None, raw=b"{}", path="/registration/options"):
            handler = Handler.__new__(Handler)
            handler.client_address = ("127.0.0.1", 12345)
            handler.server = SimpleNamespace(server_address=("127.0.0.1", 38491))
            handler.path = path
            handler.headers = email.message.Message()
            for key, value in headers or [("Host", "127.0.0.1:38491"), ("Content-Type", "application/json"), ("Content-Length", str(len(raw)))]:
                handler.headers[key] = value
            handler.rfile = io.BytesIO(raw)
            return handler.envelope(post=True)

        check("http_native_json_envelope_positive_control", lambda: require(http_envelope() == b"{}", "self_test_http_failed"))
        base_headers = [("Host", "127.0.0.1:38491"), ("Content-Type", "application/json"), ("Content-Length", "2")]
        for name, headers, code in [
            ("http_browser_origin", base_headers + [("Origin", "https://attacker.invalid")], "http_framing_or_origin_rejected"),
            ("http_null_origin", base_headers + [("Origin", "null")], "http_framing_or_origin_rejected"),
            ("http_duplicate_length", base_headers + [("Content-Length", "2")], "duplicate_http_header"),
            ("http_transfer_encoding", base_headers + [("Transfer-Encoding", "chunked")], "http_framing_or_origin_rejected"),
            ("http_rebinding_host", [("Host", "attacker.invalid:38491"), *base_headers[1:]], "host_rejected"),
            ("http_form_content_type", [base_headers[0], ("Content-Type", "text/plain"), base_headers[2]], "json_content_type_required"),
            ("http_oversized_body", [*base_headers[:2], ("Content-Length", "65537")], "body_size_limit"),
        ]:
            check(name + "_denied", lambda headers=headers, code=code: denied(lambda: http_envelope(headers), code))

        for name, raw in [("duplicate_json", b'{"x":1,"x":2}'), ("nonfinite_json", b'{"x":NaN}'),
                          ("invalid_utf8_json", b'{"x":"\xff"}'), ("unpaired_surrogate_json", b'{"x":"\\ud800"}')]:
            check(name + "_denied", lambda raw=raw: denied(lambda: strict_json(raw)))
        store.close()
    return {"schema": "heptabao.synthetic.passkey-rp-selftest.v1", "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "crypto_backend": backend_description, "scope": "synthetic_protocol_storage_and_http_framing_unit_tests",
            "passed": sum(item["passed"] for item in results), "total": len(results), "results": results,
            "network_listener_exercised": False, "phone_exercised": False, "p4_qualified": False, "p5_qualified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", help="absolute directory, owned by the current UID, mode 0700")
    parser.add_argument("--fixture-cert-sha256", help="SHA-256 of the fixture's signing certificate DER, hex")
    parser.add_argument("--port", type=int, default=38491)
    parser.add_argument("--challenge-ttl", type=int, default=180)
    parser.add_argument("--crypto-backend", choices=("auto", "cryptography", "openssl"), default="auto")
    parser.add_argument("--self-test", action="store_true", help="run synthetic verifier/state tests; no listener or phone is used")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.self_test:
            report = self_test(args.crypto_backend)
            print(json_bytes(report).decode("ascii"), end="", flush=True)
            return 0 if report["passed"] == report["total"] else 1
        require(args.root is not None and args.fixture_cert_sha256 is not None, "root_and_fixture_certificate_required")
        require(1 <= args.port <= 65535, "invalid_port")

        def stop(_signum, _frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)
        with Store(args.root, args.fixture_cert_sha256, ttl=args.challenge_ttl, backend=args.crypto_backend) as store:
            with Server(("127.0.0.1", args.port), Handler) as server:
                server.store = store
                print(json_bytes({"status": "synthetic_rp_ready", "port": args.port, "device_qualified": False}).decode("ascii"), end="", flush=True)
                try:
                    server.serve_forever(poll_interval=0.2)
                except KeyboardInterrupt:
                    pass
        print('{"status":"synthetic_rp_stopped"}', flush=True)
        return 0
    except RPError as failure:
        print(json_bytes({"status": "synthetic_rp_rejected", "error": failure.code}).decode("ascii"), end="", flush=True)
        return 1
    except (OSError, ValueError):
        print('{"status":"synthetic_rp_unavailable"}', flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
