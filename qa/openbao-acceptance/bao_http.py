"""Small HTTPS-only OpenBao client. Errors never contain response or credential bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

MAX_BODY = 16 * 1024 * 1024


class BaoError(Exception):
    """Only a fixed diagnostic code may cross the reporting boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments, which may contain a rejected secret.
        self.exit(2, "invalid command line; use --help\n")


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def decode_json(raw: bytes):
    def bad_constant(_):
        raise ValueError("nonfinite")
    try:
        return json.loads(raw, parse_constant=bad_constant)
    except (ValueError, UnicodeError) as exc:
        raise BaoError("invalid_json") from None


def private_read(path: str | Path, limit: int = MAX_BODY) -> bytes:
    """Open once, reject symlinks, then validate actual descriptor ownership/mode."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise BaoError("private_files_require_posix")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BaoError("file_requires_owner_only_regular_file")
            value = handle.read(limit + 1)
            if len(value) > limit:
                raise BaoError("file_size_limit")
            return value
    except OSError:
        raise BaoError("private_file_open_failed") from None


def private_json(path: str | Path):
    return decode_json(private_read(path))


def private_write(path: str | Path, value, *, replace: bool = True):
    """Durable 0600 publication in an existing owner-only directory, without symlinks."""
    path = Path(path).absolute()
    if not hasattr(os, "O_NOFOLLOW"):
        raise BaoError("private_files_require_posix")
    directory = None
    temporary = ".bao-write-" + secrets.token_hex(12)
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise BaoError("output_directory_requires_owner_only_mode")
        try:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not replace:
                raise BaoError("output_already_exists")
            if not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid() or current.st_mode & 0o077:
                raise BaoError("existing_output_not_private_regular_file")
        except FileNotFoundError:
            pass
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    except BaoError:
        raise
    except OSError:
        raise BaoError("private_output_publication_failed") from None
    finally:
        if directory is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)


def endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or any(ord(c) < 33 for c in value)):
            raise ValueError("endpoint")
        port = parsed.port or 443
        host = parsed.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        return f"https://{host}:{port}"
    except ValueError:
        raise BaoError("https_origin_required") from None


def key_path(value: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if (not value or len(value.encode()) > 2048 or any(c in value for c in "?#\\%")
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise BaoError("noncanonical_api_path")
    return "/".join(urllib.parse.quote(part, safe="-._~") for part in value.split("/"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect must not move a bearer token to a different host/leader.
        return None


@dataclass(repr=False)
class Response:
    status: int
    body: dict

    def data(self) -> dict:
        value = self.body.get("data")
        if not isinstance(value, dict):
            raise BaoError("response_data_object_required")
        return value


class Client:
    def __init__(self, address: str, ca_file: str, token: str, namespace: str = "", timeout: float = 15):
        self.address = endpoint(address)
        self.namespace = namespace.strip("/")
        if self.namespace:
            key_path(self.namespace)
        if not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise BaoError("invalid_token_input")
        self._token = token
        self.timeout = timeout
        try:
            context = ssl.create_default_context(cafile=ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        except (OSError, ssl.SSLError):
            raise BaoError("ca_configuration_invalid") from None

    @classmethod
    def from_env(cls, prefix: str):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", prefix):
            raise BaoError("invalid_environment_prefix")
        address, ca = os.environ.get(prefix + "_ADDR"), os.environ.get(prefix + "_CACERT")
        direct, filename = os.environ.get(prefix + "_TOKEN"), os.environ.get(prefix + "_TOKEN_FILE")
        if not address or not ca or bool(direct) == bool(filename):
            raise BaoError("endpoint_ca_and_exactly_one_token_source_required")
        try:
            token = private_read(filename, 8192).decode("ascii").strip() if filename else direct
        except UnicodeError:
            raise BaoError("invalid_token_input") from None
        return cls(address, ca, token, os.environ.get(prefix + "_NAMESPACE", ""))

    def request(self, method: str, path: str, payload=None, *, token: str | None = None) -> Response:
        if not path.startswith("/v1/") or "\n" in path or "\r" in path:
            raise BaoError("invalid_request_path")
        headers = {"X-Vault-Token": self._token if token is None else token, "Accept": "application/json"}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        raw = None if payload is None else canonical(payload)
        if raw is not None:
            if len(raw) > MAX_BODY:
                raise BaoError("request_size_limit")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.address + path, data=raw, headers=headers, method=method)
        try:
            try:
                response = self._opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.code
                if 300 <= status < 400:
                    raise BaoError("redirect_rejected")
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise BaoError("response_size_limit")
            decoded = decode_json(body) if body else {}
            if not isinstance(decoded, dict):
                raise BaoError("response_object_required")
            return Response(status, decoded)
        except BaoError:
            raise
        except (OSError, urllib.error.URLError, ValueError):
            # Never retry a write automatically. Even a timeout can follow a commit.
            raise BaoError("transport_outcome_unknown" if method not in ("GET", "LIST", "HEAD")
                           else "transport_read_failed") from None

    def health(self) -> dict:
        response = self.request("GET", "/v1/sys/health")
        value = response.body
        if response.status not in (200, 429) or value.get("initialized") is not True or value.get("sealed") is not False:
            raise BaoError("endpoint_not_initialized_unsealed")
        cluster = value.get("cluster_id")
        version = value.get("version")
        if not isinstance(cluster, str) or not cluster or len(cluster) > 128:
            raise BaoError("cluster_identity_missing")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,80}", version):
            raise BaoError("version_identity_missing")
        return {"cluster_id": cluster, "version": version, "status": response.status,
                "initialized": True, "sealed": False}


def distinct_endpoints(left: Client, left_health: dict, right: Client, right_health: dict):
    if left.address == right.address or left_health["cluster_id"] == right_health["cluster_id"]:
        raise BaoError("same_endpoint_or_cluster_rejected")


def verify_oracle_identity(receipt: dict, oracle: Client, health: dict) -> dict:
    required = {"product", "version", "artifact_sha256", "provenance_url", "endpoint", "cluster_id"}
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        raise BaoError("oracle_identity_receipt_incomplete")
    if (receipt["product"] != "OpenBao" or receipt["version"] != "2.6.2"
            or health["version"] != "2.6.2" or receipt["cluster_id"] != health["cluster_id"]
            or endpoint(receipt["endpoint"]) != oracle.address
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["artifact_sha256"])
            or receipt["artifact_sha256"] == "0" * 64
            or receipt["provenance_url"] != "https://github.com/openbao/openbao/releases/tag/v2.6.2"):
        raise BaoError("oracle_identity_receipt_mismatch")
    return {"product": "OpenBao", "version": "2.6.2", "artifact_sha256": receipt["artifact_sha256"],
            "basis": "operator_artifact_attestation_plus_verified_tls_and_live_health",
            "independent_binary_attestation": False}
