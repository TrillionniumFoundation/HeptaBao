#!/usr/bin/env python3
"""Actual native KV2/AppRole, OpenAI SDK/Undici and distinct cold SDK workers.

Linux only: the existing owned_process helper binds the original pidfd/SID.
All credentials, CA, server, SQLite stores and provider responses belong to a
new disposable fixture. Only the controller holds the native root/recovery
credential. The TLS proxy copies native bytes/Date and never issues a grant;
its one injected loss occurs after a real native UNKNOWN CAS acknowledgement.
There is no production cutover, external provider request or credential import.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from email.utils import formatdate, parsedate_to_datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qsl

sys.dont_write_bytecode = True
import owned_process
from native_v6_authbus_client_live import NativeInstance, CanaryFailure, private, sha

REPO = Path(__file__).resolve().parents[2]
PROFILE_SECONDS = 180
MAX_CONTROL_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_BYTES = 65536
PROVIDER_COUNTS = {"manager-success": 1, "intent-ack-lost": 0, "provider-ack-lost": 1,
                   "sqlite-abort": 1, "guard-after-await": 0}
CASES = tuple(PROVIDER_COUNTS)
RUNTIME = REPO / "qa/openbao-acceptance/authbus"
WORKER = RUNTIME / "authbus_refresh_sdk_native_openai_worker.mjs"
PROTOCOL = "heptabao-authbus-trusted-bootstrap-r5"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def value_sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def checked_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CanaryFailure("native_refresh_duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(CanaryFailure("native_refresh_nonfinite_json")))


def owned_read(path, limit, *, secret=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & (0o077 if secret else 0o022)
                or not 0 < before.st_size <= limit):
            raise CanaryFailure("native_refresh_input_custody")
        raw = bytearray()
        while len(raw) <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise CanaryFailure("native_refresh_input_changed")
        return bytes(raw)
    finally:
        os.close(fd)


def verify_manifest(path):
    raw = owned_read(path, 1024 * 1024, secret=False)
    manifest = checked_json(raw)
    if manifest.get("schema") != "authbus-r5-native-openai-cold-runtime-v1" or not isinstance(manifest.get("files"), list):
        raise CanaryFailure("native_refresh_manifest_shape")
    files = manifest["files"]
    if len(files) != 22:
        raise CanaryFailure("native_refresh_manifest_count")
    seen, observed = set(), []
    for item in files:
        name = item.get("path", "")
        relative = PurePosixPath(name)
        if (not name or name in seen or "\\" in name or relative.is_absolute()
                or any(part in ("", ".", "..") for part in relative.parts)
                or str(relative) != name or item.get("mode") != "100644"):
            raise CanaryFailure("native_refresh_manifest_path")
        seen.add(name)
        target = REPO / name
        if target.resolve(strict=True) != target:
            raise CanaryFailure("native_refresh_manifest_symlink")
        data = owned_read(target, 512 * 1024, secret=False)
        actual_sha = hashlib.sha256(data).hexdigest()
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if item.get("bytes") != len(data) or item.get("sha256") != actual_sha or item.get("git_blob") != actual_blob:
            raise CanaryFailure("native_refresh_manifest_pin")
        observed.append({"path": name, "sha256": actual_sha, "git_blob": actual_blob, "bytes": len(data)})
    required = {"qa/openbao-acceptance/native_v6_authbus_openai_refresh_live.py",
                "qa/openbao-acceptance/authbus/authbus_refresh_sdk_native_openai_worker.mjs",
                "qa/openbao-acceptance/authbus/authbus_refresh_sdk_native_openai_fixture.mjs",
                "qa/openbao-acceptance/authbus/authbus_refresh_sdk_openai_fixture.mjs",
                "qa/openbao-acceptance/native_v6_authbus_client_live.py",
                "qa/openbao-acceptance/owned_process.py", "qa/openbao-acceptance/cert_auth_live.py",
                "qa/openbao-acceptance/fixture_mounts.py", "qa/single-node/smoke.py"}
    if not required.issubset(seen):
        raise CanaryFailure("native_refresh_manifest_dependency_missing")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "files": observed}


def bounded_deadline(started_ns, external=None):
    deadline = started_ns + PROFILE_SECONDS * 1_000_000_000
    if external is not None:
        if type(external) is not int or external <= started_ns:
            raise CanaryFailure("native_refresh_original_deadline_invalid")
        deadline = min(deadline, external)
    return deadline


@dataclass(frozen=True)
class WireReply:
    status: int
    raw: bytes
    date: str
    content_type: str

    def document(self):
        return checked_json(self.raw) if self.raw else {}

    def server_ms(self):
        try:
            value = parsedate_to_datetime(self.date)
            if value.utcoffset() is None:
                raise ValueError()
            return int(value.timestamp() * 1000)
        except (ValueError, TypeError, OverflowError):
            raise CanaryFailure("native_refresh_native_date_invalid") from None


class DeadlineNativeInstance(NativeInstance):
    def __init__(self, binary, root, remaining):
        self.remaining = remaining
        super().__init__(binary, root)

    def wire(self, method, path, raw=None, *, token=""):
        if method not in ("GET", "POST", "PUT", "DELETE") or not re.fullmatch(r"[A-Za-z0-9_/-]+", path):
            raise CanaryFailure("native_refresh_internal_route_invalid")
        if raw is not None and len(raw) > MAX_CONTROL_BYTES:
            raise CanaryFailure("native_refresh_request_too_large")
        timeout = min(10, self.remaining())
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=timeout)
        def abort_original_io():
            if connection.sock is not None:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()
        timer = threading.Timer(self.remaining(), abort_original_io)
        timer.daemon = True
        timer.start()
        try:
            headers = {"Accept": "application/json", "Content-Type": "application/json", "Connection": "close"}
            if token:
                headers["X-Vault-Token"] = token
            if raw is not None:
                headers["Content-Length"] = str(len(raw))
            connection.request(method, "/v1/" + path, body=raw, headers=headers)
            response = connection.getresponse()
            dates = response.headers.get_all("Date", [])
            if len(dates) != 1:
                raise CanaryFailure("native_refresh_native_date_cardinality")
            payload = response.read(MAX_CONTROL_BYTES + 1)
            if len(payload) > MAX_CONTROL_BYTES:
                raise CanaryFailure("native_refresh_response_too_large")
            self.remaining()
            result = WireReply(response.status, payload, dates[0], response.getheader("Content-Type", "application/json"))
            result.server_ms()
            return result
        finally:
            timer.cancel()
            connection.close()

    def call(self, method, path, body=None, *, token=None, namespace="", extra_headers=None):
        if namespace or extra_headers:
            raise CanaryFailure("native_refresh_unconfigured_request_scope")
        result = self.wire(method, path, None if body is None else canonical(body), token=self.token if token is None else token)
        return result.status, result.document()


def admitted_route(method, target):
    exact = {("POST", "/v1/auth/approle/login"), ("GET", "/v1/auth/token/lookup-self"),
             ("POST", "/v1/auth/token/renew-self"), ("POST", "/v1/auth/token/revoke-self")}
    return ((method, target) in exact or method in ("GET", "POST")
            and target in {"/v1/authbus/data/" + case for case in CASES})


def request_length(headers, limit):
    lengths = headers.get_all("Content-Length", [])
    if headers.get_all("Transfer-Encoding", []) or len(lengths) > 1:
        raise CanaryFailure("native_refresh_http_framing_invalid")
    if not lengths:
        return 0
    if not re.fullmatch(r"0|[1-9][0-9]{0,8}", lengths[0]) or int(lengths[0]) > limit:
        raise CanaryFailure("native_refresh_http_body_limit")
    return int(lengths[0])


class FixtureGateway:
    """Two bounded loopback TLS listeners; native state is never stored here."""
    def __init__(self, native, root, cases, remaining):
        self.native, self.root, self.remaining = native, root, remaining
        self.cases = {item["scenario"]: item for item in cases}
        self.lock = threading.RLock()
        self.events = []
        self.tokens = []  # Private disposable AppRole tokens; never projected.
        self.phase = "setup"
        self.counts = {name: {"providerRequests": 0, "unknownAtProvider": 0, "unknownAckDrops": 0} for name in CASES}
        self.local_denials = 0
        self.backend_responses = 0
        self.failures = []
        self.servers, self.threads = [], []
        self.connections = set()

    def record(self, event):
        self.events.append(event)
        raw = canonical(event) + b"\n"
        fd = os.open(self.root / "transport-events.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, raw) != len(raw):
                raise CanaryFailure("native_refresh_event_short_write")
            os.fsync(fd)
        finally:
            os.close(fd)

    def observe(self, scenario):
        self.remaining()
        response = self.native.wire("GET", "authbus/data/" + scenario, token=self.native.token)
        if response.status != 200:
            raise CanaryFailure("native_refresh_control_observation_failed")
        body = response.document()
        if not isinstance(body.get("data", {}).get("data"), dict):
            raise CanaryFailure("native_refresh_control_observation_shape")
        return response, body["data"]["data"], body["data"]["metadata"]

    def forward(self, method, target, raw, token):
        self.remaining()
        if not admitted_route(method, target):
            raise CanaryFailure("native_refresh_unconfigured_proxy_route")
        response = self.native.wire(method, target[4:], raw if method == "POST" else None, token=token)
        with self.lock:
            self.backend_responses += 1
            if target == "/v1/auth/approle/login" and response.status == 200:
                bearer = response.document().get("auth", {}).get("client_token")
                if not isinstance(bearer, str) or not bearer or len(bearer) > 4096:
                    raise CanaryFailure("native_refresh_login_response_shape")
                self.tokens.append({"phase": self.phase, "token": bearer})
            if target == "/v1/authbus/data/intent-ack-lost" and method == "POST":
                body = checked_json(raw)
                document = body.get("data", {})
                attempt = (document.get("refreshAttempts") or [None])[-1]
                if isinstance(attempt, dict) and attempt.get("status") == "UNKNOWN" and self.counts["intent-ack-lost"]["unknownAckDrops"] == 0:
                    if (response.status != 200 or response.document().get("data", {}).get("version") != body.get("options", {}).get("cas", -2) + 1):
                        raise CanaryFailure("native_refresh_fault_requires_actual_cas_ack")
                    observed, actual, metadata = self.observe("intent-ack-lost")
                    if canonical(actual) != canonical(document) or metadata.get("version") != response.document()["data"]["version"]:
                        raise CanaryFailure("native_refresh_fault_native_readback_mismatch")
                    self.counts["intent-ack-lost"]["unknownAckDrops"] += 1
                    self.record({"phase": self.phase, "case": "intent-ack-lost", "event": "drop_after_native_cas_ack_and_readback",
                                 "nativeVersion": metadata["version"], "documentSha256": value_sha(actual), "nativeDateMs": observed.server_ms()})
                    return None
        return response

    def provider(self, method, target, content_type, raw):
        self.remaining()
        if method != "POST" or target != "/oauth/token" or content_type != "application/x-www-form-urlencoded":
            raise CanaryFailure("native_refresh_provider_route_invalid")
        try:
            fields = parse_qsl(raw.decode("utf-8", errors="strict"), keep_blank_values=True,
                               strict_parsing=True, max_num_fields=3)
        except (ValueError, UnicodeError):
            raise CanaryFailure("native_refresh_provider_fields_invalid") from None
        body = dict(fields)
        if (len(fields) != 3 or len(body) != 3 or set(body) != {"grant_type", "client_id", "refresh_token"}
                or body["grant_type"] != "refresh_token" or body["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann"):
            raise CanaryFailure("native_refresh_provider_fields_invalid")
        matches = [name for name, item in self.cases.items() if body["refresh_token"] == item["original"]["refresh"]]
        if len(matches) != 1:
            raise CanaryFailure("native_refresh_provider_credential_unbound")
        scenario = matches[0]
        with self.lock:
            if self.phase != "warm" or self.counts[scenario]["providerRequests"] != 0:
                raise CanaryFailure("native_refresh_duplicate_or_cold_provider_send")
            observed, document, metadata = self.observe(scenario)
            attempts, assignments = document.get("refreshAttempts", []), document.get("assignments", [])
            if (document.get("protocol") != PROTOCOL or len(attempts) != 1 or len(assignments) != 1
                    or attempts[0].get("status") != "UNKNOWN" or assignments[0].get("status") != "REFRESH_PENDING"
                    or attempts[0].get("credentialDigest") != self.cases[scenario]["originalDigest"]
                    or attempts[0].get("scopeDigest") != assignments[0].get("scopeDigest")
                    or attempts[0].get("bootId") != assignments[0].get("bootId")
                    or attempts[0].get("fenceEpoch") != assignments[0].get("epoch")):
                raise CanaryFailure("native_refresh_provider_requires_native_unknown")
            self.counts[scenario]["providerRequests"] += 1
            self.counts[scenario]["unknownAtProvider"] += 1
            self.record({"phase": self.phase, "case": scenario, "event": "actual_sdk_https_after_native_unknown",
                         "nativeVersion": metadata["version"], "documentSha256": value_sha(document), "nativeDateMs": observed.server_ms()})
            # Durable observation does not extend the inherited profile clock.
            # A slow fsync cannot qualify a provider response after that clock.
            self.remaining()
            if scenario == "provider-ack-lost":
                return None
            result = {"access_token": self.cases[scenario]["newAccess"], "refresh_token": self.cases[scenario]["newRefresh"], "expires_in": 900}
            return WireReply(200, canonical(result), formatdate(usegmt=True), "application/json")

    def start(self):
        gateway = self
        contexts = {}
        for kind, certificate, key in [("control", "tls.crt", "tls.key"),
                                        ("provider", "openai-provider.crt", "openai-provider.key")]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
            context.load_cert_chain(str(self.native.root / certificate), str(self.native.root / key))
            contexts[kind] = context
        def provider_servername(connection, servername, _context):
            if servername != "auth.openai.com":
                with gateway.lock:
                    gateway.local_denials += 1
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            connection._native_openai_servername = servername
        contexts["provider"].set_servername_callback(provider_servername)

        class BoundedHttpsServer(ThreadingHTTPServer):
            # A peer that connects without completing TLS cannot strand the
            # serving thread beyond the parent-owned original budget.
            def get_request(self):
                incoming, address = super().get_request()
                incoming.settimeout(min(10, gateway.remaining()))
                try:
                    return contexts[self.kind].wrap_socket(incoming, server_side=True), address
                except BaseException:
                    incoming.close()
                    raise

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                with gateway.lock:
                    gateway.connections.add(self.connection)
                def abort_original_io():
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.connection.close()
                self.original_io_timer = threading.Timer(gateway.remaining(), abort_original_io)
                self.original_io_timer.daemon = True
                self.original_io_timer.start()

            def finish(self):
                self.original_io_timer.cancel()
                with gateway.lock:
                    gateway.connections.discard(self.connection)
                super().finish()

            def log_message(self, *args):
                pass

            def handle_method(self):
                try:
                    self.connection.settimeout(min(10, gateway.remaining()))
                    if (self.headers.get("X-Vault-Namespace") or self.headers.get("Expect")
                            or self.server.kind == "control" and not admitted_route(self.command, self.path)):
                        gateway.local_denials += 1
                        self.send_wire(WireReply(403, b"{}", formatdate(usegmt=True), "application/json"))
                        return
                    size = request_length(self.headers, MAX_CONTROL_BYTES if self.server.kind == "control" else MAX_PROVIDER_BYTES)
                    if self.command == "GET" and size:
                        raise CanaryFailure("native_refresh_get_body_forbidden")
                    raw = self.rfile.read(size)
                    if len(raw) != size:
                        raise CanaryFailure("native_refresh_incomplete_request_body")
                    gateway.remaining()
                    if self.server.kind == "control":
                        token_headers = self.headers.get_all("X-Vault-Token", [])
                        if len(token_headers) > 1 or token_headers and len(token_headers[0]) > 4096:
                            raise CanaryFailure("native_refresh_token_header_invalid")
                        result = gateway.forward(self.command, self.path, raw, token_headers[0] if token_headers else "")
                    else:
                        if (self.request_version != "HTTP/1.1" or self.headers.get_all("Host", []) != ["auth.openai.com"]
                                or getattr(self.connection, "_native_openai_servername", None) != "auth.openai.com"
                                or len(self.headers.get_all("Content-Type", [])) != 1):
                            raise CanaryFailure("native_openai_provider_authority_or_tls_invalid")
                        result = gateway.provider(self.command, self.path, self.headers.get("Content-Type", ""), raw)
                    if result is None:
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                    else:
                        self.send_wire(result)
                except BaseException as error:
                    with gateway.lock:
                        gateway.failures.append({"phase": gateway.phase, "kind": self.server.kind,
                                                 "code": str(error) if isinstance(error, CanaryFailure) else "native_refresh_gateway_io_failure"})
                    try:
                        self.send_wire(WireReply(502, b"{}", formatdate(usegmt=True), "application/json"))
                    except OSError:
                        self.close_connection = True

            def send_wire(self, result):
                self.send_response_only(result.status)
                self.send_header("Date", result.date)
                self.send_header("Content-Type", result.content_type)
                self.send_header("Content-Length", str(len(result.raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(result.raw)
                self.wfile.flush()
                self.close_connection = True

            do_GET = handle_method
            do_POST = handle_method
            do_PUT = handle_method
            do_DELETE = handle_method

        try:
            for kind in ("control", "provider"):
                server = BoundedHttpsServer(("127.0.0.1", 0), Handler)
                server.kind = kind
                server.daemon_threads = False
                server.started = False
                self.servers.append(server)
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, name="owned-authbus-" + kind, daemon=True)
                thread.start()
                server.started = True
                self.threads.append(thread)
            return self.servers[0].server_port, self.servers[1].server_port
        except BaseException:
            self.close()
            raise

    def close(self):
        with self.lock:
            connections = tuple(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for server in self.servers:
            if server.started:
                server.shutdown()
        for server in self.servers:
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=1)
            if thread.is_alive():
                raise CanaryFailure("native_refresh_listener_not_closed")


def make_cases(run_id):
    result = []
    def encoded(value):
        return base64.urlsafe_b64encode(canonical(value)).rstrip(b"=").decode("ascii")
    for name in CASES:
        original = {"type": "oauth", "provider": "openai", "access": "synthetic-old-access-" + name + "-" + run_id,
                    "refresh": "synthetic-old-refresh-" + name + "-" + run_id, "expires": 1}
        # Only synthetic JWT-shaped fixture output. The SDK itself parses its
        # account field; no real token is decoded, read or placed in evidence.
        access = ".".join([encoded({"alg": "none", "typ": "JWT"}),
                           encoded({"exp": int(time.time()) + 900,
                                    "https://api.openai.com/auth": {"chatgpt_account_id": "synthetic-native-openai-" + name}}),
                           "synthetic-signature"])
        result.append({"scenario": name, "original": original, "originalDigest": value_sha(original),
                       "newAccess": access, "newRefresh": "synthetic-new-refresh-" + name + "-" + run_id})
    return result


def issue_owned_provider_leaf(root, remaining):
    """Use the existing owned exec gate for both disposable OpenSSL commands."""
    key, csr, cert = (root / ("openai-provider." + suffix) for suffix in ("key", "csr", "crt"))
    extension, serial = root / "openai-provider.ext", root / "openai-provider.srl"
    owned_process.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
        "-out", str(csr), "-subj", "/CN=auth.openai.com"], label="native-openai.provider-key", check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=remaining())
    private(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:auth.openai.com,IP:127.0.0.1\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    owned_process.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(root / "ca.crt"),
        "-CAkey", str(root / "ca.key"), "-CAserial", str(serial), "-CAcreateserial", "-out", str(cert),
        "-days", "2", "-sha256", "-extfile", str(extension)], label="native-openai.provider-certificate", check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=remaining())
    key.chmod(0o600)
    remaining()
    return cert, key


def run(args, report):
    started = time.monotonic_ns()
    inherited_deadline = os.environ.get("HB_QA_ORIGINAL_PROFILE_DEADLINE_NS")
    deadline = bounded_deadline(started, args.original_deadline_ns if args.original_deadline_ns is not None else
                                (int(inherited_deadline) if inherited_deadline is not None else None))
    os.umask(0o077)
    root = args.work_dir
    if not root.is_absolute() or root.exists() or root.parent.resolve(strict=True) != root.parent:
        raise CanaryFailure("native_refresh_new_canonical_workdir_required")
    root.mkdir(mode=0o700)
    report["ownedWorkDirectoryCreated"] = True
    private_root = root / "sdk"
    private_root.mkdir(mode=0o700)
    (private_root / "reports").mkdir(mode=0o700)
    binary = args.binary.resolve(strict=True)
    node = args.node.resolve(strict=True)
    sdk_root = args.openclaw_root.resolve(strict=True)
    binary_pin = owned_process.file_pin(binary)
    if not re.fullmatch(r"[a-f0-9]{64}", args.binary_sha256) or binary_pin["SHA256"] != args.binary_sha256:
        raise CanaryFailure("native_refresh_binary_pin_mismatch")
    source_before = verify_manifest(args.source_manifest)
    report.update(originalProfileSeconds=PROFILE_SECONDS, originalDeadlineNs=str(deadline), startedNs=str(started),
                  binarySha256=binary_pin["SHA256"], sourceManifest=source_before, checks=[], workerReceipts=[], nativeProcessCycles=[])
    owner = owned_process.Owner(root, deadline_ns=deadline, profile="authbus_refresh_native_openai_cold_r1")
    native, gateway = None, None
    check = lambda name, condition, **values: record_check(report, name, condition, **values)
    cases = make_cases(secrets.token_hex(16))
    confidential = []
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    env["PYTHONNOUSERSITE"] = "1"
    try:
        with owned_process.activated(owner):
            try:
                before = time.monotonic_ns()
                probe = owned_process.run([str(node), "-e", "process.stdout.write(JSON.stringify({node:process.version,mono:String(process.hrtime.bigint())}))"],
                                          label="native-refresh.node-clock", capture_output=True, timeout=10, env=env)
                after = time.monotonic_ns()
                if len(probe.stdout) > 1024 or len(probe.stderr) > 8192:
                    raise CanaryFailure("native_refresh_clock_probe_bounded")
                clock = checked_json(probe.stdout)
                check("node_and_parent_share_original_monotonic_clock", probe.returncode == 0 and before <= int(clock["mono"]) <= after)
                report["nodeVersion"] = clock["node"]
                native = DeadlineNativeInstance(binary, root / "server", owner.remaining)
                native.start()

                def call(name, method, route, body=None, expected=200, token=None):
                    status, reply = native.call(method, route, body, token=token)
                    check(name, status == expected, status=status, expected=expected)
                    return reply

                init = call("native.initialize_once", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
                native.token = init["root_token"]
                key = init["keys_base64"][0]
                confidential.extend([native.token, key])
                private(root / "recovery.private.json", canonical({"rootToken": native.token, "key": key}))
                call("native.unseal", "POST", "sys/unseal", {"key": key}, token="")
                call("native.authbus_kv2_mount", "POST", "sys/mounts/authbus", {"type": "kv", "options": {"version": "2"}}, expected=204)
                call("native.activate_once", "POST", "sys/internal/native-v6/activate", {}, expected=204)
                capacity = call("native.capacity", "GET", "sys/internal/capacity")
                check("native.graph_reader_format_two", capacity.get("data", {}).get("native_kv2_reader_format") == 2)
                call("native.approle_mount", "POST", "sys/auth/approle", {"type": "approle"}, expected=204)
                roles = {}
                for role in ("reader", "issuer"):
                    name = "authbus-r5-native-" + role
                    caps = '["read"]' if role == "reader" else '["create", "read", "update"]'
                    policy = "\n".join('path "authbus/data/' + case + '" { capabilities = ' + caps + ' }' for case in CASES)
                    policy += '\npath "auth/token/lookup-self" { capabilities = ["read"] }\n'
                    policy += 'path "auth/token/renew-self" { capabilities = ["update"] }\npath "auth/token/revoke-self" { capabilities = ["update"] }\n'
                    call("native." + role + "_policy", "PUT", "sys/policies/acl/" + name, {"policy": policy}, expected=204)
                    base = "auth/approle/role/" + name
                    call("native." + role + "_role", "POST", base, {"token_policies": [name], "token_ttl": "1200s",
                         "token_max_ttl": "1800s", "secret_id_num_uses": 0, "secret_id_ttl": "3600s"}, expected=204)
                    role_id = call("native." + role + "_role_id", "GET", base + "/role-id")["data"]["role_id"]
                    secret = call("native." + role + "_secret_id", "POST", base + "/secret-id", {})["data"]
                    roles[role] = {"name": name, "roleId": role_id, "secretId": secret["secret_id"]}
                    confidential.extend([role_id, secret["secret_id"]])
                    private(private_root / (role + ".role"), role_id)
                    private(private_root / (role + ".secret"), secret["secret_id"])
                private(private_root / "ca.crt", (native.root / "ca.crt").read_bytes())
                # The provider leaf uses the original native fixture's CA;
                # both new processes join the same 180-second owned registry.
                issue_owned_provider_leaf(native.root, owner.remaining)
                gateway = FixtureGateway(native, root, cases, owner.remaining)
                control_port, provider_port = gateway.start()
                report["listenerOrigins"] = {"native": native.address, "controlProxy": "https://127.0.0.1:" + str(control_port),
                                             "syntheticProvider": "https://127.0.0.1:" + str(provider_port)}
                module_pins = [{"name": Path(item["path"]).name, "sha256": item["sha256"]}
                               for item in source_before["files"] if item["path"].startswith("qa/openbao-acceptance/authbus/") and item["path"].endswith(".mjs")]
                previous_pids = []

                def worker(phase):
                    gateway.phase = phase
                    report_path = private_root / "reports" / (phase + ".json")
                    config = {"schema": "authbus-native-openai-refresh-sdk-worker-v1", "phase": phase, "parentRoot": str(root), "root": str(private_root),
                              "sdkRoot": str(sdk_root), "controlPort": control_port, "providerPort": provider_port, "caFile": str(private_root / "ca.crt"),
                              "reportFile": str(report_path), "originalDeadlineNs": str(deadline), "sourceManifest": module_pins,
                              "cases": [{key: item[key] for key in ("scenario", "original", "originalDigest")} for item in cases]}
                    for role in ("reader", "issuer"):
                        config[role] = {"roleIdFile": str(private_root / (role + ".role")), "secretIdFile": str(private_root / (role + ".secret"))}
                    config_path = private_root / (phase + ".config.json")
                    private(config_path, canonical(config))
                    stdout_path, stderr_path = root / (phase + ".stdout.private"), root / (phase + ".stderr.private")
                    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                        process = owned_process.popen([str(node), str(WORKER), "--config", str(config_path)],
                            label="native-refresh.sdk-" + phase, kind="utility", action="KILL", stop_timeout=5,
                            cwd=root, env=env, stdout=stdout, stderr=stderr)
                        exit_code = owned_process.wait(process, timeout=owner.remaining())
                    stdout_raw = owned_read(stdout_path, 262144) if stdout_path.stat().st_size else b""
                    stderr_raw = owned_read(stderr_path, 262144) if stderr_path.stat().st_size else b""
                    check(phase + ".redacted_process_diagnostics", all(value.encode() not in stdout_raw + stderr_raw for value in confidential))
                    raw = owned_read(report_path, 2 * 1024 * 1024)
                    result = checked_json(raw)
                    row = {"phase": phase, "pid": process.pid, "exitCode": exit_code, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                           "stdoutSha256": hashlib.sha256(stdout_raw).hexdigest(), "stderrSha256": hashlib.sha256(stderr_raw).hexdigest(),
                           "checksPassed": result.get("checksPassed"), "checksTotal": len(result.get("checks", []))}
                    report["workerReceipts"].append(row)
                    check(phase + ".actual_distinct_original_sdk_process", process.pid not in previous_pids and result.get("pid") == process.pid)
                    previous_pids.append(process.pid)
                    check(phase + ".all_worker_checks", exit_code == 0 and result.get("ok") is True and len(result.get("cases", [])) == len(CASES))
                    check(phase + ".bound_sources_and_installed_sdk_unchanged", result.get("installedSdkUnchanged") is True and result.get("sourceFilesUnchanged") is True
                          and result.get("configUnchanged") is True and result.get("originalDeadlineNs") == str(deadline))
                    check(phase + ".no_outside_sdk_attempts", all(result.get(field) == 0 for field in
                          ("externalNetworkAttempts", "externalProcessAttempts", "outsideFixtureWriteAttempts", "outsideFixtureHomeReadAttempts")))
                    expected_connects = 3 if phase == "warm" else 0
                    proxy = result.get("ownedUndiciProxy", {})
                    check(phase + ".actual_openai_undici_profile", result.get("actualUndiciRuntimeBound") is True
                          and proxy == {"connections": expected_connects, "denials": 0, "upstreamFailures": 0}
                          and result.get("fixtureProcessContextRestored") is True
                          and all(item.get("undiciConnects") == (PROVIDER_COUNTS[item["scenario"]] if phase == "warm" else 0)
                                  for item in result.get("cases", []))
                          and (phase != "warm" or all(result.get(field) is True for field in
                               ("actualOpenAiSdkOAuthManager", "actualOpenAiSdkGuard", "actualOpenAiFacade", "actualUndiciRefreshTransport"))))
                    return result

                def observe_all(label, results, previous=None, *, no_writes=False):
                    views = {}
                    for case in CASES:
                        response, document, metadata = gateway.observe(case)
                        row = next(item for item in results["cases"] if item["scenario"] == case)
                        attempts, assignments = document.get("refreshAttempts", []), document.get("assignments", [])
                        check(label + "." + case + ".exact_native_provenance", document.get("protocol") == PROTOCOL and
                              document.get("sourceDigest") == row["sourceDigest"] and len(attempts) == 1 and len(assignments) == 1 and
                              assignments[0].get("scopeDigest") == row["scopeDigest"] and attempts[0].get("credentialDigest") == row["originalDigest"])
                        if case == "manager-success":
                            check(label + ".manager.native_published_after_actual_sqlite", attempts[0].get("status") == "PUBLISHED" and attempts[0].get("sdkVerified") is True
                                  and attempts[0].get("publishedDigest") == row["credentialDigest"] and assignments[0].get("status") == "ASSIGNED"
                                  and assignments[0].get("digest") == row["credentialDigest"] and assignments[0].get("epoch") == row["epoch"]
                                  and assignments[0].get("epoch", -1) > attempts[0].get("publishedEpoch", 0))
                        else:
                            check(label + "." + case + ".native_unknown_and_old_owner_retained", attempts[0].get("status") == "UNKNOWN"
                                  and assignments[0].get("status") == "REFRESH_PENDING" and row["credentialDigest"] == row["originalDigest"])
                        views[case] = {"documentSha256": value_sha(document), "attemptSha256": value_sha(attempts[0]),
                                       "nativeVersion": metadata["version"], "nativeDateMs": response.server_ms(),
                                       "refreshOwnerExpiresAt": max((item["expiresAt"] for item in document.get("refreshLeases", [])), default=0)}
                        if previous:
                            check(label + "." + case + ".same_durable_attempt", views[case]["attemptSha256"] == previous[case]["attemptSha256"])
                            if case != "manager-success" or no_writes:
                                check(label + "." + case + ".unknown_document_and_version_unchanged", views[case]["documentSha256"] == previous[case]["documentSha256"]
                                      and views[case]["nativeVersion"] == previous[case]["nativeVersion"])
                    report.setdefault("nativeObservations", []).append({"stage": label, "cases": views})
                    return views

                def wait_previous_owner_expired():
                    # No new lease and no deadline reset. Use fresh native Date's
                    # lower bound, the same conservative ownership rule as issue.
                    count = 0
                    while True:
                        response, document, _ = gateway.observe("manager-success")
                        expires = max((item["expiresAt"] for item in document.get("refreshLeases", [])), default=0)
                        if response.server_ms() >= expires:
                            break
                        owner.remaining()
                        count += 1
                        if count > 30:
                            raise CanaryFailure("native_refresh_old_owner_did_not_expire")
                        time.sleep(min(0.5, owner.remaining()))
                    report.setdefault("leaseExpiryWaits", []).append({"reads": count + 1, "nativeDateMs": response.server_ms(), "oldLeaseExpiresAt": expires,
                                                                    "leaseRenewed": False, "originalDeadlineReset": False})

                warm = worker("warm")
                views = observe_all("after-warm", warm)
                check("warm.exact_actual_provider_counts", all(gateway.counts[name]["providerRequests"] == PROVIDER_COUNTS[name]
                      and gateway.counts[name]["unknownAtProvider"] == gateway.counts[name]["providerRequests"] for name in CASES))
                check("warm.native_unknown_cas_ack_lost_once", gateway.counts["intent-ack-lost"]["unknownAckDrops"] == 1)
                wait_previous_owner_expired()
                cold_before = worker("cold-before-server")
                views = observe_all("cold-sdk-before-native-restart", cold_before, views)
                before_restart_tokens = [item["token"] for item in gateway.tokens]
                old = native.process
                native.stop()
                check("native.original_sigkill_completed", old.returncode == -9)
                report["nativeProcessCycles"].append({"oldPid": old.pid, "stop": "SIGKILL", "exitCode": old.returncode})
                check("native.binary_unchanged_before_reopen", owned_process.file_pin(binary) == binary_pin)
                native.start()
                report["nativeProcessCycles"][-1]["newPid"] = native.process.pid
                call("native.reopen_starts_sealed", "GET", "sys/health", expected=503)
                call("native.reopen_unseal", "POST", "sys/unseal", {"key": key}, token="")
                check("native.reopen_preserves_graph_format", call("native.reopen_capacity", "GET", "sys/internal/capacity").get("data", {}).get("native_kv2_reader_format") == 2)
                views = observe_all("after-native-sigkill-reopen", cold_before, views, no_writes=True)
                for index, token in enumerate(before_restart_tokens):
                    call("native.revoked_bearer_" + str(index) + "_still_denied_after_reopen", "GET", "auth/token/lookup-self", expected=403, token=token)
                wait_previous_owner_expired()
                cold_after = worker("cold-after-server")
                observe_all("cold-sdk-after-native-restart", cold_after, views)
                check("cold.no_second_provider_request", all(gateway.counts[name]["providerRequests"] == PROVIDER_COUNTS[name] for name in CASES))
                check("native.no_proxy_local_denial_or_unclassified_failure", gateway.local_denials == 0 and not gateway.failures)
                for role, role_value in roles.items():
                    call("native." + role + "_secret_id_destroyed", "POST", "auth/approle/role/" + role_value["name"] + "/secret-id/destroy",
                         {"secret_id": role_value["secretId"]}, expected=204)
                    call("native." + role + "_reenrollment_closed", "POST", "auth/approle/login",
                         {"role_id": role_value["roleId"], "secret_id": role_value["secretId"]}, expected=400, token="")
                report["transport"] = {"counts": gateway.counts, "backendResponses": gateway.backend_responses,
                                       "events": gateway.events, "localDenials": gateway.local_denials, "failures": gateway.failures,
                                       "nativeDateForwarded": True, "rootBearerGivenToSdk": False}
                report["actualSdk"] = warm.get("actualSdk") is True
                report["actualSqlite"] = all(result.get("actualSqlite") is True for result in (warm, cold_before, cold_after))
                report["actualSdkOAuthManager"] = warm.get("actualSdkOAuthManager") is True
                report["actualProviderHttps"] = warm.get("actualProviderHttps") is True
                report["actualColdSdkProcess"] = cold_before.get("actualColdSdkProcess") is True and cold_after.get("actualColdSdkProcess") is True
                report["actualNativeHeptaBao"] = True
                report["actualNativeSigkillRecovery"] = True
                report["actualOpenAiSdkOAuthManager"] = warm.get("actualOpenAiSdkOAuthManager") is True
                report["actualOpenAiSdkGuard"] = warm.get("actualOpenAiSdkGuard") is True
                report["actualOpenAiFacade"] = warm.get("actualOpenAiFacade") is True
                report["actualUndiciRefreshTransport"] = warm.get("actualUndiciRefreshTransport") is True
                owner.remaining()
            finally:
                owned_process.close_all([lambda: gateway.close() if gateway else None, lambda: native.stop() if native else None])
        report["ownedProcesses"] = owner.receipt
        check("all_original_processes_closed_within_original_budget", owner.receipt["passed_process_method"])
        check("exact_bound_sources_unchanged", verify_manifest(args.source_manifest) == source_before)
        check("exact_native_binary_unchanged", owned_process.file_pin(binary) == binary_pin)
        check("all_required_native_and_cold_qualifications", all(report.get(key) is True for key in
              ("actualSdk", "actualSqlite", "actualSdkOAuthManager", "actualProviderHttps", "actualColdSdkProcess", "actualNativeHeptaBao", "actualNativeSigkillRecovery",
               "actualOpenAiSdkOAuthManager", "actualOpenAiSdkGuard", "actualOpenAiFacade", "actualUndiciRefreshTransport")))
        report["ok"] = True
    finally:
        if getattr(owner, "receipt", None):
            report["ownedProcesses"] = owner.receipt
        if gateway is not None:
            report.setdefault("transport", {"counts": gateway.counts, "backendResponses": gateway.backend_responses,
                                          "events": gateway.events, "localDenials": gateway.local_denials, "failures": gateway.failures,
                                          "rootBearerGivenToSdk": False})
        report["finishedNs"] = str(time.monotonic_ns())
        report["elapsedSeconds"] = (time.monotonic_ns() - started) / 1e9
        if time.monotonic_ns() >= deadline:
            report["ok"] = False
            report["originalDeadlineExceeded"] = True


def record_check(report, name, condition, **values):
    report["checks"].append({"case": name, "passed": bool(condition), **values})
    if not condition:
        raise CanaryFailure(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "node", "openclaw-root", "work-dir", "source-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--original-deadline-ns", type=int)
    args = parser.parse_args()
    report = {"schema": "authbus-refresh-r5-native-openai-cold-live", "ok": False, "syntheticCredentials": True,
              "pid": os.getpid(), "parentPid": os.getppid(),
              "syntheticProvider": True, "realExternalProvider": False, "tlsControlEmulator": False,
              "actualSdk": False, "actualSqlite": False, "actualSdkOAuthManager": False, "actualProviderHttps": False,
              "actualNativeHeptaBao": False, "actualColdSdkProcess": False, "actualNativeSigkillRecovery": False,
              "actualOpenAiSdkOAuthManager": False, "actualOpenAiSdkGuard": False, "actualOpenAiFacade": False, "actualUndiciRefreshTransport": False,
              "productionMutation": False, "realCredentialMigration": False, "scenarioInventory": list(CASES),
              "scope": "five_actual_native_openai_undici_cases_and_two_distinct_cold_sdk_processes",
              "originalNativeFourCaseDenominator": 120, "originalNativeFourCaseResultInherited": False,
              "sdk32ScenarioResultInherited": False}
    try:
        if sys.platform != "linux":
            raise CanaryFailure("native_refresh_linux_original_process_method_required")
        if not all(value.is_absolute() for value in (args.binary, args.node, args.openclaw_root, args.work_dir, args.source_manifest)):
            raise CanaryFailure("native_refresh_absolute_cli_paths_required")
        run(args, report)
    except BaseException as error:
        report["ok"] = False
        report["error"] = {"code": str(error) if isinstance(error, (CanaryFailure, owned_process.OwnedFailure)) else "native_refresh_live_failure",
                           "class": type(error).__name__, "messageSha256": hashlib.sha256(str(error).encode()).hexdigest()}
    report["checksPassed"] = sum(bool(item["passed"]) for item in report.get("checks", []))
    if report.get("ownedWorkDirectoryCreated") is True:
        private(args.work_dir / "public-receipt.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"schema": report["schema"], "ok": report["ok"], "checksPassed": report["checksPassed"],
                      "checksTotal": len(report.get("checks", [])), "error": report.get("error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
