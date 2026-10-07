"""Small HTTPS-only OpenBao client. Errors never contain response or credential bytes."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
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
from .consistency import Metadata, InvalidConsistency, HTTPSHandler, response_index, retry_after

MAX_BODY = 16 * 1024 * 1024


class BaoError(Exception):
    """Only a fixed diagnostic code may cross the reporting boundary."""

    def __init__(self, code: str, *, _diagnostic=None):
        self.code = code
        self._diagnostic = _diagnostic
        super().__init__(code)


@dataclass(frozen=True, repr=False)
class _TransportDiagnostic:
    phase: str
    exception_class: str
    errno: int | None = None
    reason_exception_class: str | None = None
    reason_errno: int | None = None


# Exact stdlib types only: subclass names and peer exception messages are not data.
_TRANSPORT_CLASSES = {
    OSError: "OSError", TimeoutError: "TimeoutError", ConnectionError: "ConnectionError",
    BrokenPipeError: "BrokenPipeError", ConnectionResetError: "ConnectionResetError",
    ConnectionAbortedError: "ConnectionAbortedError", ConnectionRefusedError: "ConnectionRefusedError",
    BlockingIOError: "BlockingIOError", InterruptedError: "InterruptedError",
    FileNotFoundError: "FileNotFoundError", PermissionError: "PermissionError", ValueError: "ValueError",
    ssl.SSLError: "ssl.SSLError", ssl.SSLCertVerificationError: "ssl.SSLCertVerificationError",
    ssl.SSLEOFError: "ssl.SSLEOFError", ssl.SSLZeroReturnError: "ssl.SSLZeroReturnError",
    ssl.SSLWantReadError: "ssl.SSLWantReadError", ssl.SSLWantWriteError: "ssl.SSLWantWriteError",
    urllib.error.URLError: "urllib.error.URLError",
    http.client.HTTPException: "http.client.HTTPException",
    http.client.BadStatusLine: "http.client.BadStatusLine",
    http.client.RemoteDisconnected: "http.client.RemoteDisconnected",
    http.client.IncompleteRead: "http.client.IncompleteRead",
    http.client.CannotSendRequest: "http.client.CannotSendRequest",
    http.client.ResponseNotReady: "http.client.ResponseNotReady",
    http.client.UnknownProtocol: "http.client.UnknownProtocol",
    http.client.LineTooLong: "http.client.LineTooLong", http.client.InvalidURL: "http.client.InvalidURL",
}
_TRANSPORT_PHASES = frozenset(("open_response", "response_context", "response_metadata",
                               "read_response", "close_response", "process_response", "fixture_call"))


def _bounded_errno(value):
    return value if type(value) is int and 0 <= value <= 65535 else None


def _transport_diagnostic(error, phase):
    if not isinstance(error, (OSError, urllib.error.URLError, ValueError, http.client.HTTPException)):
        return None
    name = _TRANSPORT_CLASSES.get(type(error), "other")
    number = _bounded_errno(getattr(error, "errno", None)) if type(error) in _TRANSPORT_CLASSES else None
    reason_name = reason_number = None
    if type(error) is urllib.error.URLError:
        reason = error.reason
        if isinstance(reason, BaseException):
            reason_name = _TRANSPORT_CLASSES.get(type(reason), "other")
            if type(reason) in _TRANSPORT_CLASSES:
                reason_number = _bounded_errno(getattr(reason, "errno", None))
    return _TransportDiagnostic(phase, name, number, reason_name, reason_number)


def transport_diagnostic(error):
    """Project closed diagnostics; never read exception args, messages or URLs."""
    diagnostic = error._diagnostic if type(error) is BaoError else _transport_diagnostic(error, "fixture_call")
    names = set(_TRANSPORT_CLASSES.values()) | {"other"}
    if (type(diagnostic) is not _TransportDiagnostic
            or type(diagnostic.phase) is not str or diagnostic.phase not in _TRANSPORT_PHASES
            or type(diagnostic.exception_class) is not str or diagnostic.exception_class not in names):
        return None
    result = {"phase": diagnostic.phase, "exception_class": diagnostic.exception_class}
    number = _bounded_errno(diagnostic.errno)
    if number is not None:
        result["errno"] = number
    if type(diagnostic.reason_exception_class) is str and diagnostic.reason_exception_class in names:
        result["reason_exception_class"] = diagnostic.reason_exception_class
        number = _bounded_errno(diagnostic.reason_errno)
        if number is not None:
            result["reason_errno"] = number
    return result


class SafeArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

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
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    try:
        return json.loads(raw, parse_constant=bad_constant, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise BaoError("invalid_json") from None


def private_read(path: str | Path, limit: int = MAX_BODY) -> bytes:
    """Open from an owner-only parent, reject symlinks, then validate the file.

    Checking only the leaf mode is insufficient: a same-user or group-writable
    parent could replace the leaf between validation and the next migration
    attempt.  Holding the parent directory descriptor and opening the basename
    relative to it binds the read to the directory that was checked.
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise BaoError("private_files_require_posix")
    directory = None
    try:
        path = Path(path).absolute()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        parent_info = os.fstat(directory)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or parent_info.st_mode & 0o077):
            raise BaoError("private_parent_directory_required")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BaoError("file_requires_owner_only_regular_file")
            value = handle.read(limit + 1)
            if len(value) > limit:
                raise BaoError("file_size_limit")
            return value
    except BaoError:
        raise
    except OSError:
        raise BaoError("private_file_open_failed") from None
    finally:
        if directory is not None:
            os.close(directory)


def private_json(path: str | Path):
    return decode_json(private_read(path))


def private_write(path: str | Path, value, *, replace: bool = True):
    """Publish canonical JSON through the common durable private-file boundary."""
    _private_write_bytes(path, canonical(value) + b"\n", replace=replace)


def private_write_text(path: str | Path, value: str, *, replace: bool = True):
    """Publish exact UTF-8 text, not a JSON string or an in-place truncation.

    Only caller-owned private fixture data belongs here. This is filesystem
    isolation, not encryption or protection from processes with the same UID.
    """
    if not isinstance(value, str):
        raise BaoError("private_text_requires_string")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        raise BaoError("private_text_requires_utf8") from None
    _private_write_bytes(path, raw, replace=replace)


def _private_write_bytes(path: str | Path, raw: bytes, *, replace: bool):
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
            handle.write(raw)
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
    consistency_index: str | None = None
    consistency_valid: bool = True
    retry_after_seconds: int | None = None

    def data(self) -> dict:
        value = self.body.get("data")
        if not isinstance(value, dict):
            raise BaoError("response_data_object_required")
        return value


class Client:
    def __init__(self, address: str, ca_file: str, token: str, namespace: str = "", timeout: float = 15, *, trusted_ca_pem: bytes | None = None):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise BaoError("invalid_timeout")
        self.address = endpoint(address)
        if not isinstance(namespace, str) or namespace.startswith("/") or "//" in namespace:
            raise BaoError("invalid_namespace")
        self.namespace = namespace.removesuffix("/")
        if self.namespace:
            key_path(self.namespace)
        if not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise BaoError("invalid_token_input")
        self._token = token
        self.timeout = timeout
        try:
            if trusted_ca_pem is None:
                context = ssl.create_default_context(cafile=ca_file)
            else:
                if not isinstance(trusted_ca_pem, bytes) or not 1 <= len(trusted_ca_pem) <= 1024 * 1024:
                    raise BaoError("invalid_frozen_ca_bytes")
                # Load the exact verified bytes, not a mutable second path open.
                context = ssl.create_default_context(cadata=trusted_ca_pem.decode("ascii"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        except (OSError, ssl.SSLError, UnicodeError):
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

    def request(self, method: str, path: str, payload=None, *, token: str | None = None,
                wrap_ttl: str | None = None, content_type: str = "application/json",
                consistency_index: str | None = None, inconsistent=None) -> Response:
        try:
            metadata = Metadata(consistency_index, inconsistent)
        except InvalidConsistency as error:
            raise BaoError(str(error)) from None
        if method not in ("GET", "HEAD", "LIST", "POST", "PUT", "PATCH", "DELETE", "SCAN"):
            raise BaoError("invalid_request_method")
        if not path.startswith("/v1/") or len(path) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in path):
            raise BaoError("invalid_request_path")
        if token is not None and (not isinstance(token, str) or len(token) > 8192
                                  or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise BaoError("invalid_token_input")
        if content_type not in ("application/json", "application/merge-patch+json"):
            raise BaoError("unsupported_content_type")
        headers = {"X-Vault-Token": self._token if token is None else token, "Accept": "application/json"}
        if wrap_ttl is not None:
            if (not isinstance(wrap_ttl, str) or not 1 <= len(wrap_ttl) <= 64
                    or any(ord(c) < 33 or ord(c) > 126 for c in wrap_ttl)):
                raise BaoError("invalid_wrapping_ttl_header")
            headers["X-Vault-Wrap-TTL"] = wrap_ttl
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        raw = None if payload is None else canonical(payload)
        if raw is not None:
            if len(raw) > MAX_BODY:
                raise BaoError("request_size_limit")
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.address + path, data=raw, headers=headers, method=method)
        if metadata.headers():
            request.heptabao_consistency = metadata
        phase = "open_response"
        try:
            try:
                response = self._opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            phase = "response_context"
            with response:
                phase = "response_metadata"
                status = response.code
                if 300 <= status < 400:
                    raise BaoError("redirect_rejected")
                index, index_valid = response_index(response.headers)
                retry_seconds = retry_after(response.headers)
                phase = "read_response"
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise BaoError("response_size_limit")
                phase = "close_response"
            phase = "process_response"
            decoded = decode_json(body) if body else {}
            if not isinstance(decoded, dict):
                raise BaoError("response_object_required")
            return Response(status, decoded, index, index_valid, retry_seconds)
        except BaoError:
            raise
        except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as error:
            # Never retry a write automatically. Even a timeout can follow a commit.
            raise BaoError("transport_outcome_unknown" if method not in ("GET", "LIST", "HEAD")
                           else "transport_read_failed",
                           _diagnostic=_transport_diagnostic(error, phase)) from None

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
