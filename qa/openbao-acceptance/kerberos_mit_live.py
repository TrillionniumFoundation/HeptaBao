#!/usr/bin/env python3
"""Linux-only live Kerberos acceptance using a disposable MIT KDC.

This harness deliberately has no mock provider path. On Linux it requires the
MIT Kerberos tools and system GSS-API, then creates a private realm, keytab, and
credential cache under one temporary directory and removes them on exit.
Ticket material and HTTP Negotiate tokens are kept in memory and are never
printed or written to the report.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
import smoke


REALM = "HBKERB.TEST"
SERVICE = "HTTP"
SERVICE_ACCOUNT = f"{SERVICE}/127.0.0.1@{REALM}"
CLIENT = f"alice@{REALM}"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def private_write(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)


def checked(command: list[str], env: dict[str, str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        # Provider output can contain principals, paths, or other sensitive
        # deployment details. Keep failure evidence intentionally generic.
        raise RuntimeError("MIT Kerberos command failed: " + command[0])
    return result.stdout


def have_mit_tools() -> bool:
    required = ("krb5kdc", "kdb5_util", "kadmin.local", "kinit", "kdestroy")
    if any(shutil.which(tool) is None for tool in required):
        return False
    library = ctypes.util.find_library("gssapi_krb5")
    return bool(library)


def kerberos_files(root: Path, port: int) -> tuple[Path, Path, Path, Path]:
    krb5_conf = root / "krb5.conf"
    kdc_conf = root / "kdc.conf"
    acl = root / "kadm5.acl"
    database = root / "principal-db"
    private_write(
        krb5_conf,
        f"""[libdefaults]
 default_realm = {REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 clockskew = 0
 ticket_lifetime = 10m
 forwardable = false

[realms]
 {REALM} = {{
  kdc = 127.0.0.1:{port}
  admin_server = 127.0.0.1:{port}
 }}
""",
    )
    private_write(
        kdc_conf,
        f"""[kdcdefaults]
 kdc_ports = {port}
 kdc_tcp_ports = {port}

[realms]
 {REALM} = {{
  database_name = {database}
  admin_keytab = {root / 'kadm5.keytab'}
  acl_file = {acl}
  key_stash_file = {root / 'stash'}
  max_life = 10m
  max_renewable_life = 10m
 }}
""",
    )
    private_write(acl, f"*/admin@{REALM} *\n")
    return krb5_conf, kdc_conf, acl, database


def start_kdc(
    root: Path,
    env: dict[str, str],
    port: int,
    master_password: str,
    client_password: str,
) -> subprocess.Popen[bytes]:
    krb5_conf, kdc_conf, _acl, _database = kerberos_files(root, port)
    env["KRB5_CONFIG"] = str(krb5_conf)
    env["KRB5_KDC_PROFILE"] = str(kdc_conf)
    checked(
        ["kdb5_util", "create", "-s", "-r", REALM],
        env,
        input_text=f"{master_password}\n{master_password}\n",
    )
    keytab = root / "service.keytab"
    admin_input = (
        f"addprinc -pw {client_password} {CLIENT}\n"
        f"addprinc -randkey {SERVICE_ACCOUNT}\n"
        f"ktadd -k {keytab} {SERVICE_ACCOUNT}\n"
        "quit\n"
    )
    checked(["kadmin.local", "-r", REALM], env, input_text=admin_input)
    keytab.chmod(0o600)
    process = subprocess.Popen(
        ["krb5kdc", "-n", "-P", str(root / "kdc.pid")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("MIT KDC exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return process
        except OSError:
            time.sleep(0.05)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    raise RuntimeError("MIT KDC did not become ready")


class GssOid(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("elements", ctypes.c_void_p)]


class GssBuffer(ctypes.Structure):
    _fields_ = [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)]


def negotiate_header(_instance: smoke.Instance, env: dict[str, str]) -> str:
    # This is the MIT GSS initiator path, not a token-shaped test value. The
    # ccache is selected through the process environment and the AP-REQ bytes
    # are retained only in memory until the HTTP request is sent.
    os.environ["KRB5CCNAME"] = env["KRB5CCNAME"]
    library = next(
        (
            candidate
            for candidate in (
                ctypes.util.find_library("gssapi_krb5"),
                "libgssapi_krb5.so.2",
                "/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2",
                "/usr/lib/aarch64-linux-gnu/libgssapi_krb5.so.2",
            )
            if candidate and (Path(candidate).exists() or "/" not in candidate)
        ),
        None,
    )
    if library is None:
        raise RuntimeError("MIT GSS-API library unavailable")
    gss = ctypes.CDLL(library)
    major_type = ctypes.c_uint32
    gss_name = ctypes.c_void_p
    gss_context = ctypes.c_void_p
    gss.import_name = gss.gss_import_name
    gss.import_name.argtypes = [
        ctypes.POINTER(major_type),
        ctypes.POINTER(GssBuffer),
        ctypes.POINTER(GssOid),
        ctypes.POINTER(gss_name),
    ]
    gss.import_name.restype = major_type
    gss.init_context = gss.gss_init_sec_context
    gss.init_context.argtypes = [
        ctypes.POINTER(major_type),
        ctypes.c_void_p,
        ctypes.POINTER(gss_context),
        gss_name,
        ctypes.c_void_p,
        major_type,
        major_type,
        ctypes.c_void_p,
        ctypes.POINTER(GssBuffer),
        ctypes.c_void_p,
        ctypes.POINTER(GssBuffer),
        ctypes.POINTER(major_type),
        ctypes.POINTER(major_type),
    ]
    gss.init_context.restype = major_type
    gss.release_buffer = gss.gss_release_buffer
    gss.release_buffer.argtypes = [ctypes.POINTER(major_type), ctypes.POINTER(GssBuffer)]
    gss.release_buffer.restype = major_type

    name_bytes = SERVICE_ACCOUNT.encode("ascii")
    name_storage = ctypes.create_string_buffer(name_bytes)
    name_buffer = GssBuffer(len(name_bytes), ctypes.cast(name_storage, ctypes.c_void_p))
    # GSS_NT_KRB5_PRINCIPAL: preserve the exact service/host@realm binding.
    oid_bytes = (ctypes.c_ubyte * 10)(42, 134, 72, 134, 247, 18, 1, 2, 2, 1)
    oid = GssOid(10, ctypes.cast(oid_bytes, ctypes.c_void_p))
    minor = major_type(0)
    target = gss_name()
    if gss.import_name(ctypes.byref(minor), ctypes.byref(name_buffer), ctypes.byref(oid), ctypes.byref(target)) != 0:
        raise RuntimeError("MIT GSS target import failed")
    context = gss_context()
    output = GssBuffer()
    major = gss.init_context(
        ctypes.byref(minor),
        None,
        ctypes.byref(context),
        target,
        None,
        0,
        0,
        None,
        None,
        None,
        ctypes.byref(output),
        None,
        None,
    )
    if major != 0 or not output.value or output.length == 0:
        raise RuntimeError("MIT GSS initiator did not produce an AP-REQ")
    try:
        token = ctypes.string_at(output.value, output.length)
    finally:
        gss.release_buffer(ctypes.byref(minor), ctypes.byref(output))
    return "Negotiate " + base64.b64encode(token).decode("ascii")


def run(binary: Path, work_dir: Path) -> dict[str, object]:
    if sys.platform != "linux":
        return {"status": "not_run", "reason": "MIT Kerberos acceptance is Linux-only"}
    if not have_mit_tools():
        raise RuntimeError("MIT Kerberos tools or GSS-API library unavailable")

    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = os.environ.copy()
    kdc = None
    instance = None
    ccache = work_dir / "client.ccache"
    try:
        port = free_port()
        master_password = secrets.token_urlsafe(24)
        client_password = secrets.token_urlsafe(24)
        kdc = start_kdc(work_dir, environment, port, master_password, client_password)
        keytab = work_dir / "service.keytab"
        environment["KRB5_KTNAME"] = f"FILE:{keytab}"
        environment["KRB5CCNAME"] = f"FILE:{ccache}"
        instance = smoke.Instance(binary, work_dir / "server")
        original = {name: os.environ.get(name) for name in ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5CCNAME")}
        os.environ.update({name: environment[name] for name in ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5CCNAME")})
        try:
            instance.start()
            def check(condition: bool, name: str) -> None:
                if not condition:
                    raise RuntimeError("scenario failed: " + name)

            status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            check(status == 200, "initialize")
            instance.token = initialized["root_token"]
            unseal = initialized["keys_base64"][0]
            check(instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200, "unseal")
            check(instance.call("POST", "sys/auth/kerberos", {"type": "kerberos"})[0] == 204, "mount")
            config = {
                "service_account": SERVICE_ACCOUNT,
                "realm": REALM,
                "service": SERVICE,
                "keytab_path": str(keytab),
                "token_policies": ["default"],
                "token_ttl": 300,
                "token_max_ttl": 600,
                "clock_skew_seconds": 60,
            }
            check(instance.call("POST", "auth/kerberos/config", config)[0] == 204, "config")
            status, readback = instance.call("GET", "auth/kerberos/config")
            check(status == 200 and "keytab_path" not in json.dumps(readback), "redacted_config")
            check(readback["data"]["clock_skew_seconds"] == 60, "config_roundtrip")

            checked(["kinit", "-c", str(ccache), CLIENT], environment, input_text=f"{client_password}\n")
            first_header = negotiate_header(instance, environment)
            first_status = instance.call(
                "POST", "auth/kerberos/login", {}, extra_headers={"Authorization": first_header}
            )[0]
            check(first_status == 200, "real_mit_ap_req_login")
            replay_status = instance.call(
                "POST", "auth/kerberos/login", {}, extra_headers={"Authorization": first_header}
            )[0]
            check(replay_status == 403, "replayed_negotiation_denied")

            bad_config = dict(config)
            bad_config["realm"] = "OTHER.TEST"
            bad_config["service_account"] = "HTTP/127.0.0.1@OTHER.TEST"
            check(instance.call("PUT", "auth/kerberos/config", bad_config)[0] == 204, "wrong_realm_configured")
            wrong_realm_status = instance.call(
                "POST", "auth/kerberos/login", {}, extra_headers={"Authorization": first_header}
            )[0]
            check(wrong_realm_status >= 400, "wrong_realm_denied")
            check(instance.call("PUT", "auth/kerberos/config", config)[0] == 204, "config_restored")

            wrong_service = dict(config)
            wrong_service["service_account"] = "HTTP/other.test@HBKERB.TEST"
            check(instance.call("PUT", "auth/kerberos/config", wrong_service)[0] == 204, "wrong_service_configured")
            wrong_service_status = instance.call(
                "POST", "auth/kerberos/login", {}, extra_headers={"Authorization": first_header}
            )[0]
            check(wrong_service_status >= 400, "wrong_service_identity_denied")
            check(instance.call("PUT", "auth/kerberos/config", config)[0] == 204, "service_config_restored")
            check(instance.call("PUT", "auth/kerberos/config", {**config, "clock_skew_seconds": 301})[0] >= 400, "clock_skew_denied")

            checked(["kdestroy", "-c", str(ccache)], environment)
            short_cache = work_dir / "expired.ccache"
            environment["KRB5CCNAME"] = f"FILE:{short_cache}"
            checked(["kinit", "-l", "5s", "-c", str(short_cache), CLIENT], environment, input_text=f"{client_password}\n")
            expired_header = negotiate_header(instance, environment)
            time.sleep(6)
            expired_status = instance.call("POST", "auth/kerberos/login", {}, extra_headers={"Authorization": expired_header})[0]
            check(expired_status >= 400, "expired_ticket_denied")

            environment["KRB5CCNAME"] = f"FILE:{ccache}"
            checked(["kinit", "-c", str(ccache), CLIENT], environment, input_text=f"{client_password}\n")
            second_header = negotiate_header(instance, environment)
            check(instance.call("POST", "auth/kerberos/login", {}, extra_headers={"Authorization": second_header})[0] == 200, "second_login")
            instance.stop()
            instance.start()
            check(instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200, "restart_unseal")
            restart_status = instance.call(
                "POST", "auth/kerberos/login", {}, extra_headers={"Authorization": second_header}
            )[0]
            check(restart_status == 403, "restart_replay_denied")
            return {"status": "passed", "checks": [
                "config_roundtrip", "real_mit_ap_req_login", "replayed_negotiation_denied",
                "wrong_realm_denied", "wrong_service_identity_denied", "expired_ticket_denied",
                "clock_skew_denied", "restart_replay_denied",
            ]}
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
    finally:
        if instance is not None:
            instance.stop()
        if kdc is not None:
            kdc.terminate()
            try:
                kdc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kdc.kill()
                kdc.wait(timeout=5)
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute():
        parser.error("paths must be absolute")
    try:
        print(json.dumps(run(args.binary.resolve(strict=True), args.work_dir)))
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": type(error).__name__}))
        raise SystemExit(1) from None
