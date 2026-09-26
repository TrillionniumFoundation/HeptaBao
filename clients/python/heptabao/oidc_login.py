"""Bounded native OIDC login with S256 PKCE, loopback callback and private output.

Tokens never enter stdout. A caller may explicitly display the temporary
login URL in a trusted terminal; do not capture that URL in shared logs.
The server owns the durable one-use session and upstream code exchange.
"""
from __future__ import annotations
import argparse
import base64
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import sys
import time
import urllib.parse
import webbrowser
from .transport import BaoError, Client, SafeArgumentParser, canonical, endpoint, key_path

MAX_CALLBACK_HEAD = 8192
MAX_ATTEMPTS = 32


def opaque(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
        return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == value
    except (ValueError, TypeError):
        return False


def authorization_url(value: str, issuer_origin: str, redirect: str) -> tuple[str, str]:
    try:
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("url")
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("authority")
        if endpoint(f"{parsed.scheme}://{parsed.netloc}") != endpoint(issuer_origin):
            raise ValueError("issuer")
        key_path(parsed.path.removeprefix("/"))
        pairs = urllib.parse.parse_qsl(parsed.query, strict_parsing=True, max_num_fields=16)
        params = dict(pairs)
        expected = {"response_type","scope","client_id","redirect_uri","state","nonce","code_challenge","code_challenge_method"}
        if (len(params) != len(pairs) or set(params) != expected or params["redirect_uri"] != redirect
                or params["response_type"] != "code" or params["scope"] != "openid"
                or params["code_challenge_method"] != "S256" or not params["client_id"]
                or not all(opaque(params[k]) for k in ("state","nonce","code_challenge"))):
            raise ValueError("binding")
        return value, params["state"]
    except (ValueError, TypeError):
        raise BaoError("invalid_authorization_url_binding") from None


def callback_code(head: bytes, port: int, state: str) -> str:
    """Strict one-request GET parser; no body, redirect, state echo or cookies."""
    try:
        if not 0 < len(head) <= MAX_CALLBACK_HEAD or not head.endswith(b"\r\n\r\n"):
            raise ValueError("bounds")
        lines = head[:-4].decode("ascii").split("\r\n")
        if len(lines) > 65:
            raise ValueError("headers")
        method, target, version = lines[0].split(" ")
        if method != "GET" or version != "HTTP/1.1":
            raise ValueError("method")
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            if not name or any(not (c.isalnum() or c in "!#$%&'*+-.^_`|~") for c in name):
                raise ValueError("header")
            name = name.lower();value = value.strip(" \t")
            if name in headers or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ValueError("duplicate_or_control")
            headers[name] = value
        if (headers.get("host") != f"127.0.0.1:{port}" or "transfer-encoding" in headers
                or "origin" in headers or headers.get("content-length", "0") != "0"):
            raise ValueError("authority_or_body")
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.path != "/oidc/callback" or parsed.fragment:
            raise ValueError("path")
        pairs = urllib.parse.parse_qsl(parsed.query, strict_parsing=True, max_num_fields=3)
        values = dict(pairs)
        if len(values) != len(pairs) or set(values) != {"state", "code"}:
            raise ValueError("shape")
        if not hmac.compare_digest(values["state"], state):
            raise ValueError("state")
        code = values["code"]
        if not 1 <= len(code) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in code):
            raise ValueError("code")
        return code
    except (ValueError, UnicodeError, KeyError):
        raise BaoError("invalid_loopback_callback") from None


class Loopback:
    def __init__(self, port: int, timeout: float):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise BaoError("invalid_callback_port")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 240:
            raise BaoError("invalid_callback_timeout")
        self.port = port
        self.deadline = time.monotonic() + timeout
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind(("127.0.0.1", port))
            self.socket.listen(4)
            self.socket.setblocking(False)
        except OSError:
            self.socket.close()
            raise BaoError("callback_listener_unavailable") from None
    @property
    def redirect(self):
        return f"http://127.0.0.1:{self.port}/oidc/callback"
    def close(self):
        self.socket.close()
    def wait(self, state: str) -> str:
        for _ in range(MAX_ATTEMPTS):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.socket], [], [], remaining)[0]:
                raise BaoError("callback_timeout_session_not_retried")
            connection, address = self.socket.accept()
            with connection:
                connection.setblocking(False)
                deadline = min(self.deadline, time.monotonic() + 2.0)
                head = bytearray()
                try:
                    if address[0] != "127.0.0.1":
                        raise BaoError("non_loopback_callback")
                    while not head.endswith(b"\r\n\r\n"):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
                            raise BaoError("callback_header_timeout")
                        chunk = connection.recv(min(4096, MAX_CALLBACK_HEAD + 1 - len(head)))
                        if not chunk:
                            raise BaoError("incomplete_callback")
                        head.extend(chunk)
                        if len(head) > MAX_CALLBACK_HEAD or (b"\r\n\r\n" in head and not head.endswith(b"\r\n\r\n")):
                            raise BaoError("callback_body_or_pipeline_forbidden")
                    code = callback_code(bytes(head), self.port, state)
                    message = b"Authorization response received. Return to the initiating terminal."
                    connection.settimeout(0.2)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: " + str(len(message)).encode() + b"\r\n\r\n" + message)
                    return code
                except (BaoError, OSError):
                    try:
                        connection.settimeout(0.2)
                        connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")
                    except OSError:
                        pass
        raise BaoError("callback_attempt_budget_exhausted")


class PrivateOutput:
    """Reserve a unique private destination before requesting a login session.

Descriptor-anchored directory traversal never follows symlinks. An incomplete
reserved file is deliberately retained after failure: no automatic re-login or
assumption that the upstream operation did not happen is permitted.
"""
    def __init__(self, path: Path):
        self.directory = None; self.file = None; self.name = None
        if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
            raise BaoError("absolute_output_path_required")
        try:
            directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.directory = directory
            for part in path.parent.parts[1:]:
                next_dir = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory);directory=next_dir;self.directory=directory
            info = os.fstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise BaoError("output_directory_requires_owner_only_mode")
            self.name = path.name
            self.file = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            os.fsync(directory)
        except (OSError, AttributeError):
            self.close()
            raise BaoError("private_output_reservation_failed") from None
        except BaoError:
            self.close();raise
    def publish(self, response: dict):
        try:
            current = os.stat(self.name, dir_fd=self.directory, follow_symlinks=False)
            opened = os.fstat(self.file)
            if ((current.st_dev,current.st_ino) != (opened.st_dev,opened.st_ino)
                    or opened.st_nlink != 1 or opened.st_uid != os.geteuid() or opened.st_mode & 0o077):
                raise BaoError("private_output_replaced_after_login")
            data = canonical(response) + b"\n"
            if len(data) > 1024 * 1024:
                raise BaoError("login_response_too_large")
            view = memoryview(data)
            while view:
                count = os.write(self.file, view)
                if not count: raise OSError("short write")
                view = view[count:]
            os.fsync(self.file);os.fsync(self.directory)
        except OSError:
            raise BaoError("private_output_publication_failed_do_not_retry_login") from None
    def close(self):
        if self.file is not None:
            os.close(self.file); self.file=None
        if self.directory is not None:
            os.close(self.directory); self.directory=None


def run(args):
    if not args.allow_write:
        raise BaoError("explicit_login_effect_permission_required")
    mount = key_path(args.mount)
    issuer_origin = endpoint(args.issuer_origin)
    proof = secrets.token_urlsafe(32)
    output = PrivateOutput(Path(args.output))
    receiver = None
    try:
        receiver = Loopback(args.listen_port, args.callback_timeout)
        client = Client(args.address, args.ca_file, "anonymous-login", args.namespace, timeout=15)
        response = client.request("POST", f"/v1/auth/{mount}/oidc/auth_url",
            {"role":args.role,"redirect_uri":receiver.redirect,"client_nonce":proof},token="")
        if response.status != 200:
            raise BaoError("oidc_session_creation_denied")
        url, state = authorization_url(response.data().get("auth_url"), issuer_origin, receiver.redirect)
        if args.display_auth_url:
            print(url, flush=True)
        elif not webbrowser.open(url, new=1, autoraise=True):
            raise BaoError("browser_launch_failed_session_not_retried")
        code = receiver.wait(state)
        # Exactly one request; lost acknowledgement is never blindly retried.
        response = client.request("POST",f"/v1/auth/{mount}/oidc/callback",
            {"state":state,"code":code,"client_nonce":proof},token="")
        auth = response.body.get("auth")
        if (response.status != 200 or not isinstance(auth,dict) or not isinstance(auth.get("client_token"),str)
                or not auth["client_token"] or len(auth["client_token"]) > 8192
                or not isinstance(auth.get("entity_id"),str) or not auth["entity_id"]):
            raise BaoError("oidc_exchange_or_publication_denied_start_new_login")
        output.publish(response.body)
        print("OIDC login completed; credentials written to the reserved private file.", flush=True)
    finally:
        if receiver: receiver.close()
        output.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument("--address",required=True)
    parser.add_argument("--ca-file",required=True)
    parser.add_argument("--issuer-origin",required=True)
    parser.add_argument("--mount",required=True)
    parser.add_argument("--role",required=True)
    parser.add_argument("--namespace",default="")
    parser.add_argument("--listen-port",required=True,type=int)
    parser.add_argument("--callback-timeout",default=180.0,type=float)
    parser.add_argument("--output",required=True)
    parser.add_argument("--allow-write",action="store_true")
    presentation=parser.add_mutually_exclusive_group(required=True)
    presentation.add_argument("--display-auth-url",action="store_true")
    presentation.add_argument("--open-browser",action="store_true")
    args=parser.parse_args()
    try:
        run(args)
        return 0
    except (BaoError,OSError) as error:
        print(error.code if isinstance(error,BaoError) else "native_login_failed",file=sys.stderr)
        return 1
if __name__=="__main__":raise SystemExit(main())
