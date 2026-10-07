"""Local synthetic TLS fixtures. PgWireFixture is NOT a PostgreSQL server.

It exercises the native TLS/SCRAM/extended-query transport and indeterminate
boundary, not the PL/pgSQL bootstrap or real database role/session semantics.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import threading
import time


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def exact(stream, n: int) -> bytes:
    if not 0 <= n <= 256 * 1024:
        raise ValueError("fixture_frame_bound")
    parts = bytearray()
    while len(parts) < n:
        block = stream.recv(n - len(parts))
        if not block:
            raise EOFError("fixture_peer_closed")
        parts.extend(block)
    return bytes(parts)


def frame(stream, tag: bytes, payload: bytes) -> None:
    stream.sendall(tag + struct.pack("!I", len(payload) + 4) + payload)


def receive(stream):
    tag = exact(stream, 1)
    size = struct.unpack("!I", exact(stream, 4))[0]
    return tag, exact(stream, size - 4)


class JsonIssuer:
    """No credential or arbitrary target accepted; a test-owned localhost IdP."""
    def __init__(self, cert: Path, key: Path):
        owner = self
        self.documents: dict[str, object] = {}
        self.calls: list[str] = []
        self.mode = "normal"
        self.block_path: str | None = None
        self.block_entered = threading.Event()
        self.block_release = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_):
                pass
            def do_GET(self):
                owner.calls.append(self.path)
                if owner.block_path == self.path:
                    owner.block_path = None
                    owner.block_entered.set()
                    if not owner.block_release.wait(timeout=8):
                        self.send_response(503)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                if owner.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://untrusted.invalid:443/keys")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if owner.mode == "duplicate":
                    payload = b'{"keys":[],"keys":[]}'
                elif owner.mode == "oversized":
                    payload = b" " * (128 * 1024 + 1)
                elif owner.mode == "unavailable":
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                else:
                    payload = json.dumps(owner.documents.get(self.path, {})).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ssl.SSLError):
                    pass
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.origin = f"https://localhost:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def block_next(self, path: str) -> None:
        if not isinstance(path, str) or not path.startswith("/") or self.block_path is not None:
            raise ValueError("invalid_fixture_block_path")
        self.block_entered.clear()
        self.block_release.clear()
        self.block_path = path

    def release_block(self) -> None:
        self.block_release.set()

    def close(self):
        self.release_block()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("issuer_shutdown_failed")


class PgWireFixture:
    """Protocol/side-effect model ONLY. Never report this as a real DB test."""
    manager = "hb_manager"
    password = "synthetic-pg-manager-" + "ab" * 24

    def __init__(self, cert: Path, key: Path):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.origin = f"postgresql://localhost:{self.port}"
        self.stop = threading.Event()
        self.rows: dict[str, dict] = {}
        self.retired_rows: dict[str, dict] = {}
        self.fences: dict[str, int] = {}
        self.lock = threading.Lock()
        self.events: list[tuple[str, str, int]] = []
        self.mode = "normal"
        self.server_errors: list[str] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError("pg_fixture_shutdown_failed")

    def serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            try:
                raw.settimeout(3)
                if self.mode == "before_entry":
                    raw.close()
                    continue
                self.handle(raw)
            except (EOFError, ssl.SSLError, OSError):
                pass
            except Exception as error:
                self.server_errors.append(type(error).__name__)
            finally:
                raw.close()

    def handle(self, raw):
        if exact(raw, 8) != struct.pack("!II", 8, 80877103):
            raise ValueError("ssl_request_mismatch")
        if self.mode == "refuse_tls":
            raw.sendall(b"N")
            return
        raw.sendall(b"S")
        with self.context.wrap_socket(raw, server_side=True) as stream:
            startup = exact(stream, struct.unpack("!I", exact(stream, 4))[0] - 4)
            if not startup.startswith(struct.pack("!I", 196608)) or b"user\0" + self.manager.encode() + b"\0" not in startup:
                raise ValueError("startup_profile_mismatch")
            frame(stream, b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\0\0")
            tag, first = receive(stream)
            mechanism, first = first.split(b"\0", 1)
            if tag != b"p" or mechanism != b"SCRAM-SHA-256" or struct.unpack("!I", first[:4])[0] != len(first[4:]):
                raise ValueError("invalid_client_first")
            bare = first[4:].removeprefix(b"n,,")
            nonce = bare.split(b",r=", 1)[1]
            salt = secrets.token_bytes(16)
            full_nonce = nonce + base64.b64encode(secrets.token_bytes(16))
            server_first = b"r=" + full_nonce + b",s=" + base64.b64encode(salt) + b",i=4096"
            frame(stream, b"R", struct.pack("!I", 11) + server_first)
            tag, final = receive(stream)
            final_bare, proof = final.rsplit(b",p=", 1)
            if tag != b"p" or final_bare != b"c=biws,r=" + full_nonce:
                raise ValueError("invalid_client_final")
            salted = hashlib.pbkdf2_hmac("sha256", self.password.encode(), salt, 4096)
            client = hmac.new(salted, b"Client Key", "sha256").digest()
            stored = hashlib.sha256(client).digest()
            message = bare + b"," + server_first + b"," + final_bare
            signature = hmac.new(stored, message, "sha256").digest()
            expected = bytes(a ^ b for a, b in zip(client, signature))
            if not hmac.compare_digest(expected, base64.b64decode(proof, validate=True)):
                raise ValueError("client_scram_proof_mismatch")
            server_key = hmac.new(salted, b"Server Key", "sha256").digest()
            server_proof = hmac.new(server_key, message, "sha256").digest()
            if self.mode == "wrong_server_proof":
                server_proof = b"\0" * 32
            frame(stream, b"R", struct.pack("!I", 12) + b"v=" + base64.b64encode(server_proof))
            frame(stream, b"R", struct.pack("!I", 0))
            frame(stream, b"Z", b"I")
            while not self.stop.is_set():
                tag, payload = receive(stream)
                if tag != b"P":
                    raise ValueError("query_parse_required")
                statement, query, rest = payload.split(b"\0", 2)
                if statement or rest != b"\0\0":
                    raise ValueError("query_profile_mismatch")
                tag, payload = receive(stream)
                if tag != b"B" or payload[:4] != b"\0\0\0\0":
                    raise ValueError("bind_profile_mismatch")
                count = struct.unpack("!H", payload[4:6])[0]
                offset, params = 6, []
                if count > 12:
                    raise ValueError("bind_count_exceeded")
                for _ in range(count):
                    length = struct.unpack("!i", payload[offset:offset+4])[0]
                    if not 0 <= length <= 4096:
                        raise ValueError("bind_length_exceeded")
                    offset += 4
                    params.append(payload[offset:offset+length].decode())
                    offset += length
                if payload[offset:] != b"\0\0":
                    raise ValueError("bind_trailing_bytes")
                if receive(stream) != (b"D", b"P\0") or receive(stream) != (b"E", b"\0" * 5) or receive(stream) != (b"S", b""):
                    raise ValueError("extended_query_sequence")
                query = query.decode()
                with self.lock:
                    if "current_user" in query:
                        result = self.manager
                    elif "protocol()" in query:
                        result = "heptabao-postgresql-provider-v2"
                    elif "provider.retired(" in query:
                        result = "true" if self.retired(params) else "false"
                    elif "provider.retire(" in query:
                        result = "true" if self.retire(params) else "false"
                    elif "provider.apply(" in query:
                        result = self.apply(params)
                        if self.mode == "drop_after_apply":
                            self.mode = "normal"
                            return
                    elif "provider.observe(" in query and len(params) == 1:
                        result = dict(self.rows.get(params[0], {"found": False}))
                        if self.mode == "wrong_observation":
                            self.mode = "normal"
                            result["request_digest"] = "0" * 64
                    else:
                        raise ValueError("unexpected_provider_statement")
                    if isinstance(result, dict):
                        result = json.dumps({k: v for k, v in result.items() if not k.startswith("test_")})
                if result == "ERROR":
                    frame(stream, b"E", b"SERROR\0CXX000\0Msynthetic provider rejected\0\0")
                    frame(stream, b"Z", b"I")
                    continue
                frame(stream, b"1", b"")
                frame(stream, b"2", b"")
                frame(stream, b"T", struct.pack("!H", 1) + b"value\0" + struct.pack("!IhIhih", 0, 0, 25, -1, -1, 0))
                data = result.encode()
                frame(stream, b"D", struct.pack("!Hi", 1, len(data)) + data)
                frame(stream, b"C", b"SELECT 1\0")
                frame(stream, b"Z", b"I")

    def retired(self, params):
        if len(params) != 4:
            raise ValueError("invalid_retired_arity")
        fence, identity, user, seq = params
        seq = int(seq)
        return (
            self.fences.get(fence, 0) >= seq
            and identity not in self.rows
            and all(row["username"] != user for row in self.rows.values())
        )

    def retire(self, params):
        if len(params) != 4:
            raise ValueError("invalid_retire_arity")
        fence, identity, user, seq = params
        seq = int(seq)
        if self.fences.get(fence, 0) < seq:
            return False
        row = self.rows.get(identity)
        if row is None:
            return self.retired(params)
        if (
            row["fence_id"] != fence
            or row["username"] != user
            or row["seq"] != seq
            or row["action"] != "revoke"
            or row["login"] is not False
            or row["active_sessions"] != 0
        ):
            return False
        self.retired_rows[identity] = dict(row)
        del self.rows[identity]
        return True

    def apply(self, params):
        if len(params) != 9:
            raise ValueError("invalid_apply_arity")
        fence, identity, user, seq, action, expires, group, password, digest = params
        seq, expires = int(seq), int(expires)
        payload_digest = hashlib.sha256(json.dumps(params, separators=(",", ":")).encode()).hexdigest()
        self.events.append((identity, action, seq))
        old = self.rows.get(identity)
        floor = self.fences.get(fence, 0)
        if old:
            if old["fence_id"] != fence or old["username"] != user or seq < old["seq"]:
                return "ERROR"
            if seq == old["seq"]:
                return old if floor == seq and digest == old["request_digest"] and payload_digest == old["test_payload_digest"] else "ERROR"
            if old["action"] == "revoke" and action != "revoke":
                return "ERROR"
        if seq <= floor:
            return "ERROR"
        if action == "issue" and (old or len(password) != 64):
            return "ERROR"
        if action == "renew" and (not old or password or expires <= old["expires"]):
            return "ERROR"
        if action not in {"issue", "renew", "revoke"} or group != "app_reader":
            return "ERROR"
        row = {"found": True, "fence_id": fence, "lease_id": identity, "username": user, "seq": seq,
               "action": action, "expires": expires, "request_digest": digest,
               "login": action != "revoke", "controlled": True, "active_sessions": 0,
               "test_password": password if action == "issue" else (old or {}).get("test_password", ""),
               "test_payload_digest": payload_digest}
        self.rows[identity] = row
        self.fences[fence] = seq
        return row
