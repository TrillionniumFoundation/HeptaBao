#!/usr/bin/env python3
"""Bounded external LDAPS authentication acceptance.

Runs a real TLS socket and LDAPv3 simple-bind exchange against the candidate's
production outbound path. The fixture intentionally implements only BindResponse,
not search/groups/referrals/StartTLS and is not independent OpenLDAP qualification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import socket
import ssl
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


def ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    if length <= 0xFFFF:
        return b"\x82" + length.to_bytes(2, "big")
    raise ValueError("length")


def ber_value(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(value)) + value


def take_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    count = first & 0x7F
    if count not in (1, 2):
        raise ValueError("length")
    end = offset + count
    if end > len(data):
        raise ValueError("length")
    return int.from_bytes(data[offset:end], "big"), end


def take(data: bytes, offset: int, tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != tag:
        raise ValueError("tag")
    length, offset = take_length(data, offset + 1)
    end = offset + length
    if end > len(data):
        raise ValueError("value")
    return data[offset:end], end


def bind_request(raw: bytes) -> tuple[str, str]:
    body, end = take(raw, 0, 0x30)
    if end != len(raw):
        raise ValueError("trailing")
    message_id, offset = take(body, 0, 0x02)
    if message_id != b"\x01":
        raise ValueError("message")
    bind, offset = take(body, offset, 0x60)
    if offset != len(body):
        raise ValueError("trailing")
    version, pos = take(bind, 0, 0x02)
    dn, pos = take(bind, pos, 0x04)
    password, pos = take(bind, pos, 0x80)
    if pos != len(bind) or version != b"\x03":
        raise ValueError("bind")
    return dn.decode("utf-8"), password.decode("utf-8")


def bind_response(code: int) -> bytes:
    inner = (
        ber_value(0x0A, bytes([code]))
        + ber_value(0x04, b"")
        + ber_value(0x04, b"" if code == 0 else b"invalid credentials")
    )
    body = ber_value(0x02, b"\x01") + ber_value(0x61, inner)
    return ber_value(0x30, body)


class Directory:
    def __init__(self, cert: Path, key: Path):
        self.expected_dn = "uid=alice,ou=people,dc=example,dc=test"
        self.password = "external-directory-secret"
        self.attempts: list[tuple[str, bool]] = []
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(16)
        self.socket.settimeout(0.25)
        self.port = self.socket.getsockname()[1]
        self.origin = f"ldaps://localhost:{self.port}"
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with self.context.wrap_socket(client, server_side=True) as stream:
                    stream.settimeout(3)
                    head = stream.recv(4)
                    if len(head) < 2 or head[0] != 0x30:
                        continue
                    if head[1] < 128:
                        total = 2 + head[1]
                        raw = bytearray(head[:2])
                    else:
                        count = head[1] & 0x7F
                        if count not in (1, 2):
                            continue
                        while len(head) < 2 + count:
                            part = stream.recv(2 + count - len(head))
                            if not part:
                                break
                            head += part
                        length = int.from_bytes(head[2:2 + count], "big")
                        total = 2 + count + length
                        raw = bytearray(head[:2 + count])
                    while len(raw) < total:
                        part = stream.recv(total - len(raw))
                        if not part:
                            break
                        raw.extend(part)
                    dn, password = bind_request(bytes(raw))
                    ok = dn == self.expected_dn and password == self.password
                    self.attempts.append((dn, ok))
                    stream.sendall(bind_response(0 if ok else 49))
            except (OSError, ssl.SSLError, UnicodeError, ValueError):
                continue

    def close(self):
        self.stopped.set()
        try:
            self.socket.close()
        except OSError:
            pass
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("ldap_directory_join_failed")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    checks = []
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-"))
    root.chmod(0o700)
    ins = Instance(a.binary, root / "candidate")
    directory = Directory(ins.root / "tls.crt", ins.root / "tls.key")

    def check(name, ok):
        checks.append({"case": name, "passed": bool(ok)})
        if not ok:
            raise RuntimeError(name)

    try:
        config_path = ins.root / "server.json"
        server_config = json.loads(config_path.read_text())
        server_config["outbound_endpoints"] = [{
            "origin": directory.origin,
            "address": f"127.0.0.1:{directory.port}",
            "server_name": "localhost",
            "ca_pem": (ins.root / "ca.crt").read_text(),
            "path_prefix": "/",
        }]
        config_path.write_text(json.dumps(server_config))
        config_path.chmod(0o600)

        ins.start()
        status, init = ins.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        key = init["keys_base64"][0]
        ins.token = init["root_token"]
        check("unseal", ins.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("mount", ins.call("POST", "sys/auth/ldap", {"type": "ldap"})[0] == 204)
        cfg = {
            "url": directory.origin,
            "bind_dn": "cn=heptabao,dc=example,dc=test",
            "user_dn_template": "uid={{username}},ou=people,dc=example,dc=test",
            "starttls": False,
        }
        check("config", ins.call("POST", "auth/ldap/config", cfg)[0] == 204)
        check("config_roundtrip", ins.call("GET", "auth/ldap/config", {})[1].get("url") == cfg["url"])

        # This local password is deliberately different. The durable user object
        # supplies bounded policies/TTL/MFA mapping only; it must not authenticate LDAP.
        local_only_password = "local-policy-record-secret"
        check("user_policy_mapping", ins.call("PUT", "auth/ldap/users/alice", {
            "password": local_only_password,
            "policies": ["default"],
        })[0] == 204)
        status, logged = ins.call("POST", "auth/ldap/login/alice", {"password": directory.password})
        token = logged.get("auth", {}).get("client_token")
        check("external_ldaps_bind_issues_token", status == 200 and bool(token))
        check("provider_observed_exact_user_dn", directory.attempts[-1] == (directory.expected_dn, True))

        before = len(directory.attempts)
        status, denied = ins.call("POST", "auth/ldap/login/alice", {"password": local_only_password})
        check("local_verifier_cannot_authenticate_ldap", status == 403 and "auth" not in denied)
        check("invalid_password_reached_external_directory", len(directory.attempts) == before + 1 and not directory.attempts[-1][1])

        ins.stop()
        ins.start()
        check("restart_unseal", ins.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, relogged = ins.call("POST", "auth/ldap/login/alice", {"password": directory.password})
        check("external_login_survives_restart", status == 200 and bool(relogged.get("auth", {}).get("client_token")))

        check("revoke_local_policy_mapping", ins.call("DELETE", "auth/ldap/users/alice", {})[0] == 204)
        before = len(directory.attempts)
        status, denied = ins.call("POST", "auth/ldap/login/alice", {"password": directory.password})
        check("revoked_mapping_denies_after_provider_success", status == 403 and "auth" not in denied)
        check("provider_success_does_not_bypass_local_authority", len(directory.attempts) == before + 1 and directory.attempts[-1][1])
        check("login_and_revocation", True)

        check("unenrolled_origin_rejected", ins.call("PUT", "auth/ldap/config", {
            **cfg, "url": "ldaps://directory.invalid:636"
        })[0] == 503)
        check("plaintext_ldap_rejected", ins.call("PUT", "auth/ldap/config", {
            **cfg, "url": f"ldap://localhost:{directory.port}"
        })[0] == 503)
        check("filter_injection_rejected", ins.call("PUT", "auth/ldap/config", {
            "url": "ldap://directory.test:389/??(|(uid=*))",
            "bind_dn": "cn=x",
            "user_dn_template": "uid={{username}}",
        })[0] >= 400)

        report = {
            "status": "passed" if all(c["passed"] for c in checks) else "failed",
            "checks": checks,
            "external_ldap_bind_executed": True,
            "actual_openldap_distribution": False,
            "search_and_group_mapping": False,
            "independent_qualification": False,
        }
        Path(a.output).write_text(json.dumps(report, indent=2) + "\n")
        return 0 if report["status"] == "passed" else 1
    finally:
        ins.stop()
        directory.close()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
