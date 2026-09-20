#!/usr/bin/env python3
"""Bounded real UDP RADIUS PAP acceptance.

The fixture runs a disposable local RADIUS responder and exercises only the
process-enrolled PAP profile. It is not a claim of OpenBao RADIUS API parity,
CHAP/EAP support, IPv6 transport, or independent qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance

SECRET = b"radius-fixture-secret"
USERNAME = b"alice"
PASSWORD = b"radius-password"


def md5(*parts: bytes) -> bytes:
    digest = hashlib.md5()
    for part in parts:
        digest.update(part)
    return digest.digest()


def hide_password(password: bytes, request_authenticator: bytes) -> bytes:
    padded = password + b"\0" * ((16 - len(password) % 16) % 16)
    result = bytearray()
    previous = request_authenticator
    for offset in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[offset : offset + 16], md5(SECRET, previous)))
        result.extend(block)
        previous = block
    return bytes(result)


def hmac_md5(message: bytes) -> bytes:
    return hmac.new(SECRET, message, hashlib.md5).digest()


def attributes(packet: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 20
    while offset < len(packet):
        if len(packet) - offset < 2:
            raise ValueError("truncated attribute")
        kind, length = packet[offset], packet[offset + 1]
        if length < 2 or length > len(packet) - offset:
            raise ValueError("invalid attribute")
        result.append((kind, packet[offset + 2 : offset + length]))
        offset += length
    return result


class RadiusResponder:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.25)
        self.port = self.socket.getsockname()[1]
        self.mode = "normal"
        self.requests: list[dict[str, object]] = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        while not self.stopped.is_set():
            try:
                packet, source = self.socket.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                if len(packet) < 20 or packet[0] != 1:
                    continue
                declared = struct.unpack("!H", packet[2:4])[0]
                if declared != len(packet):
                    continue
                request_authenticator = packet[4:20]
                attrs = attributes(packet)
                username = next(value for kind, value in attrs if kind == 1)
                encrypted = next(value for kind, value in attrs if kind == 2)
                message = next(value for kind, value in attrs if kind == 80)
                signed = bytearray(packet)
                signed[-16:] = b"\0" * 16
                message_ok = hmac.compare_digest(message, hmac_md5(bytes(signed)))
                clear = bytearray()
                previous = request_authenticator
                for offset in range(0, len(encrypted), 16):
                    block = encrypted[offset : offset + 16]
                    clear.extend(a ^ b for a, b in zip(block, md5(SECRET, previous)))
                    previous = block
                password = bytes(clear).rstrip(b"\0")
                accepted = message_ok and username == USERNAME and password == PASSWORD
                self.requests.append({"username": username.decode("ascii", "replace"), "message_authenticator": message_ok, "accepted": accepted})
                code = 2 if accepted else 3
                response = bytearray([code, packet[1], 0, 38])
                response.extend(request_authenticator)
                response.extend([80, 18])
                response.extend(b"\0" * 16)
                response[22:38] = hmac_md5(bytes(response[:20] + response[20:22] + b"\0" * 16))
                response[4:20] = md5(bytes(response[:4]) + request_authenticator + bytes(response[20:]) + SECRET)
                if self.mode == "bad_authenticator":
                    response[4] ^= 1
                elif self.mode == "bad_message_authenticator":
                    response[22] ^= 1
                    response[4:20] = md5(bytes(response[:4]) + request_authenticator + bytes(response[20:]) + SECRET)
                self.mode = "normal"
                self.socket.sendto(response, source)
            except (OSError, StopIteration, ValueError):
                continue

    def close(self) -> None:
        self.stopped.set()
        try:
            self.socket.close()
        except OSError:
            pass
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("radius_responder_join_failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    checks: list[dict[str, object]] = []
    root = Path(tempfile.mkdtemp(prefix="heptabao-radius-"))
    root.chmod(0o700)
    responder = RadiusResponder()
    instance = Instance(args.binary, root / "candidate")
    origin = f"radius://127.0.0.1:{responder.port}"

    def check(name: str, passed: bool) -> None:
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise RuntimeError(name)

    try:
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["outbound_endpoints"] = [{
            "origin": origin,
            "address": f"127.0.0.1:{responder.port}",
            "server_name": "127.0.0.1",
            "ca_pem": "",
            "path_prefix": "/",
            "shared_secret": SECRET.decode(),
        }]
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        check("unseal", instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200)
        check("mount", instance.call("POST", "sys/auth/radius", {"type": "radius"})[0] == 204)
        check("config", instance.call("POST", "auth/radius/config", {"url": origin, "token_policies": ["default"]})[0] == 204)
        check("config_roundtrip", instance.call("GET", "auth/radius/config", {})[1].get("data", {}).get("url") == origin)
        status, logged = instance.call("POST", "auth/radius/login", {"username": "alice", "password": "radius-password"})
        check("pap_accept_with_message_authenticator", status == 200 and bool(logged.get("auth", {}).get("client_token")))
        check("request_message_authenticator", bool(responder.requests and responder.requests[-1]["message_authenticator"]))
        responder.mode = "bad_message_authenticator"
        status, _ = instance.call("POST", "auth/radius/login", {"username": "alice", "password": "radius-password"})
        check("reject_bad_authenticator", status == 503)
        responder.mode = "bad_authenticator"
        status, _ = instance.call("POST", "auth/radius/login", {"username": "alice", "password": "radius-password"})
        check("reject_bad_response_authenticator", status == 503)
        responder.mode = "normal"
        status, denied = instance.call("POST", "auth/radius/login", {"username": "alice", "password": "wrong-password"})
        check("provider_reject_does_not_issue_token", status == 403 and "auth" not in denied)
        responder.close()
        status, _ = instance.call("POST", "auth/radius/login", {"username": "alice", "password": "radius-password"})
        check("timeout_fails_closed", status == 503)
        report = {
            "schema": "heptabao.radius-bounded.v1",
            "status": "passed",
            "checks": checks,
            "bounded_profile": "PAP over process-enrolled IPv4 UDP; strict Message-Authenticator and Response Authenticator; one-shot timeout",
            "full_openbao_radius_compatibility": False,
            "independent_qualification": False,
        }
        output = Path(args.output)
        fd = output.open("x", encoding="utf-8")
        with fd:
            json.dump(report, fd, indent=2)
            fd.write("\n")
        print(json.dumps({"status": report["status"], "check_count": len(checks)}))
        return 0
    except Exception as error:
        output = Path(args.output)
        report = {"schema": "heptabao.radius-bounded.v1", "status": "failed", "checks": checks, "safe_error": type(error).__name__}
        with output.open("x", encoding="utf-8") as fd:
            json.dump(report, fd, indent=2)
            fd.write("\n")
        print(json.dumps({"status": "failed", "check_count": len(checks), "failure": type(error).__name__}))
        return 1
    finally:
        try:
            responder.close()
        finally:
            instance.stop()
            shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())
