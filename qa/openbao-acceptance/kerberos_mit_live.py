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
import re
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
# Match the declared role to the real native validator. A zero-skew native
# profile rejects even a valid authenticator delayed across a wall-clock second.
NATIVE_CLOCK_SKEW_SECONDS = 60
SHORT_TICKET_SECONDS = 5
EXPIRY_MARGIN_SECONDS = 2
NORMAL_REQUEST_DELAY_SECONDS = 2.1


def expired_ticket_wait_seconds() -> int:
    # MIT applies clockskew to ticket endtime as well as authenticator time.
    # Do not turn a still-native-valid ticket into a claimed expiry negative.
    return SHORT_TICKET_SECONDS + NATIVE_CLOCK_SKEW_SECONDS + EXPIRY_MARGIN_SECONDS


def wait_at_least(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while (remaining := deadline - time.monotonic()) > 0:
        time.sleep(remaining)

CORPUS_CASE_IDS = (
    "config_roundtrip", "real_mit_ap_req_login", "replayed_negotiation_denied",
    "wrong_realm_denied", "wrong_service_identity_denied", "expired_ticket_denied",
    "clock_skew_denied", "restart_replay_denied", "restart_native_cache_is_fresh",
    "cross_namespace_replay_denied", "restart_fresh_ticket_still_works",
)


class FixtureFailure(RuntimeError):
    """An allowlisted structural stage, never provider stderr or a credential."""
    def __init__(self, stage: str):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", stage):
            stage = "unclassified_failure"
        super().__init__(stage)
        self.stage = stage



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
        raise FixtureFailure("mit_command_failed")
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
 clockskew = {NATIVE_CLOCK_SKEW_SECONDS}
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
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}

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
            raise FixtureFailure("kdc_startup_exit")
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
    raise FixtureFailure("kdc_readiness_timeout")


class GssOid(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("elements", ctypes.c_void_p)]


class GssBuffer(ctypes.Structure):
    _fields_ = [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)]


def negotiate_header(_instance: smoke.Instance, env: dict[str, str]) -> str:
    """Create a real MIT AP-REQ, releasing every native context/name/buffer."""
    library = ctypes.util.find_library("gssapi_krb5")
    if not library:
        raise FixtureFailure("gss_library_missing")
    gss = ctypes.CDLL(library)
    major_type = ctypes.c_uint32
    pointer = ctypes.c_void_p

    def bind(name, argtypes):
        function = getattr(gss, name)
        function.argtypes = argtypes
        function.restype = major_type
        return function

    import_name = bind("gss_import_name", [ctypes.POINTER(major_type),
        ctypes.POINTER(GssBuffer), ctypes.POINTER(GssOid), ctypes.POINTER(pointer)])
    init_context = bind("gss_init_sec_context", [ctypes.POINTER(major_type), pointer,
        ctypes.POINTER(pointer), pointer, pointer, major_type, major_type, pointer,
        ctypes.POINTER(GssBuffer), pointer, ctypes.POINTER(GssBuffer),
        ctypes.POINTER(major_type), ctypes.POINTER(major_type)])
    release_buffer = bind("gss_release_buffer", [ctypes.POINTER(major_type), ctypes.POINTER(GssBuffer)])
    release_name = bind("gss_release_name", [ctypes.POINTER(major_type), ctypes.POINTER(pointer)])
    delete_context = bind("gss_delete_sec_context", [ctypes.POINTER(major_type),
        ctypes.POINTER(pointer), ctypes.POINTER(GssBuffer)])
    name_bytes = SERVICE_ACCOUNT.encode("ascii")
    name_storage = ctypes.create_string_buffer(name_bytes)
    name_buffer = GssBuffer(len(name_bytes), ctypes.cast(name_storage, pointer))
    # GSS_NT_KRB5_PRINCIPAL preserves service/host@realm rather than DNS inference.
    oid_bytes = (ctypes.c_ubyte * 10)(42, 134, 72, 134, 247, 18, 1, 2, 2, 1)
    oid = GssOid(10, ctypes.cast(oid_bytes, pointer))
    minor = major_type(0)
    target, context, output = pointer(), pointer(), GssBuffer()
    original_cache = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = env["KRB5CCNAME"]
    try:
        if import_name(ctypes.byref(minor), ctypes.byref(name_buffer), ctypes.byref(oid),
                       ctypes.byref(target)) != 0:
            raise FixtureFailure("gss_target_import")
        major = init_context(ctypes.byref(minor), None, ctypes.byref(context), target,
            None, 0, 0, None, None, None, ctypes.byref(output), None, None)
        if major != 0 or not output.value or not 0 < output.length <= 128 * 1024:
            raise FixtureFailure("gss_ap_req_creation")
        token = ctypes.string_at(output.value, output.length)
        return "Negotiate " + base64.b64encode(token).decode("ascii")
    finally:
        if output.value:
            release_buffer(ctypes.byref(minor), ctypes.byref(output))
        if context.value:
            delete_context(ctypes.byref(minor), ctypes.byref(context), None)
        if target.value:
            release_name(ctypes.byref(minor), ctypes.byref(target))
        if original_cache is None:
            os.environ.pop("KRB5CCNAME", None)
        else:
            os.environ["KRB5CCNAME"] = original_cache


def run(binary: Path, work_dir: Path) -> dict[str, object]:
    if sys.platform != "linux":
        return {"status": "not_run", "reason": "MIT Kerberos acceptance is Linux-only"}
    if not have_mit_tools():
        raise FixtureFailure("mit_prerequisites_missing")

    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = os.environ.copy()
    kdc = None
    instance = None
    ccache = work_dir / "client.ccache"
    passed = []
    try:
        port = free_port()
        master_password = secrets.token_urlsafe(24)
        client_password = secrets.token_urlsafe(24)
        kdc = start_kdc(work_dir, environment, port, master_password, client_password)
        keytab = work_dir / "service.keytab"
        environment["KRB5_KTNAME"] = f"FILE:{keytab}"
        environment["KRB5CCNAME"] = f"FILE:{ccache}"
        environment["KRB5RCACHENAME"] = "file2:" + str(work_dir / "server-generation-0.replay")
        instance = smoke.Instance(binary, work_dir / "server")
        original = {name: os.environ.get(name) for name in ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5CCNAME", "KRB5RCACHENAME")}
        os.environ.update({name: environment[name] for name in ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5CCNAME", "KRB5RCACHENAME")})
        try:
            instance.start()
            def check(condition: bool, name: str) -> None:
                if not condition:
                    raise FixtureFailure(name)
                if name in passed:
                    raise FixtureFailure("duplicate_observation")
                passed.append(name)

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
                "clock_skew_seconds": NATIVE_CLOCK_SKEW_SECONDS,
            }
            check(instance.call("POST", "auth/kerberos/config", config)[0] == 204, "config")
            status, readback = instance.call("GET", "auth/kerberos/config")
            check(status == 200 and "keytab_path" not in json.dumps(readback), "redacted_config")
            check(readback["data"]["clock_skew_seconds"] == NATIVE_CLOCK_SKEW_SECONDS, "config_roundtrip")

            checked(["kinit", "-c", str(ccache), CLIENT], environment, input_text=f"{client_password}\n")
            first_header = negotiate_header(instance, environment)
            # Mandatory cross-second delivery guards against reintroducing the
            # accidentally zero-skew fixture. No retry is allowed after failure.
            wait_at_least(NORMAL_REQUEST_DELAY_SECONDS)
            first_status = instance.call(
                "POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": first_header}
            )[0]
            check(first_status == 200, "real_mit_ap_req_login")
            replay_status = instance.call(
                "POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": first_header}
            )[0]
            check(replay_status == 403, "replayed_negotiation_denied")

            # Never reuse a consumed AP-REQ for realm/service negative cases:
            # a replay rejection would mask a broken target-identity check.
            wrong_realm_header = negotiate_header(instance, environment)
            bad_config = dict(config)
            bad_config["realm"] = "OTHER.TEST"
            bad_config["service_account"] = "HTTP/127.0.0.1@OTHER.TEST"
            check(instance.call("PUT", "auth/kerberos/config", bad_config)[0] == 204, "wrong_realm_configured")
            wrong_realm_status = instance.call(
                "POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": wrong_realm_header}
            )[0]
            check(wrong_realm_status >= 400, "wrong_realm_denied")
            check(instance.call("PUT", "auth/kerberos/config", config)[0] == 204, "config_restored")
            check(instance.call("POST", "auth/kerberos/login", {}, token="",
                  extra_headers={"Authorization": wrong_realm_header})[0] == 200,
                  "wrong_realm_control_login")

            wrong_service_header = negotiate_header(instance, environment)
            wrong_service = dict(config)
            wrong_service["service_account"] = "HTTP/other.test@HBKERB.TEST"
            check(instance.call("PUT", "auth/kerberos/config", wrong_service)[0] == 204, "wrong_service_configured")
            wrong_service_status = instance.call(
                "POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": wrong_service_header}
            )[0]
            check(wrong_service_status >= 400, "wrong_service_identity_denied")
            check(instance.call("PUT", "auth/kerberos/config", config)[0] == 204, "service_config_restored")
            check(instance.call("POST", "auth/kerberos/login", {}, token="",
                  extra_headers={"Authorization": wrong_service_header})[0] == 200,
                  "wrong_service_control_login")
            check(instance.call("PUT", "auth/kerberos/config", {**config, "clock_skew_seconds": 301})[0] >= 400, "clock_skew_denied")

            checked(["kdestroy", "-c", str(ccache)], environment)
            short_cache = work_dir / "expired.ccache"
            environment["KRB5CCNAME"] = f"FILE:{short_cache}"
            checked(["kinit", "-l", f"{SHORT_TICKET_SECONDS}s", "-c", str(short_cache), CLIENT], environment, input_text=f"{client_password}\n")
            expired_header = negotiate_header(instance, environment)
            # This AP-REQ has never been presented. Replaying a consumed request
            # here could mask a broken expiry check with a replay rejection.
            wait_at_least(expired_ticket_wait_seconds())
            expired_status = instance.call("POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": expired_header})[0]
            check(expired_status >= 400, "expired_ticket_denied")

            environment["KRB5CCNAME"] = f"FILE:{ccache}"
            checked(["kinit", "-c", str(ccache), CLIENT], environment, input_text=f"{client_password}\n")
            second_header = negotiate_header(instance, environment)
            check(instance.call("POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": second_header})[0] == 200, "second_login")
            check(instance.call("POST", "sys/namespaces/kerberos-peer", {})[0] == 200, "peer_namespace")
            check(instance.call("POST", "sys/auth/kerberos", {"type":"kerberos"},
                  namespace="kerberos-peer")[0] == 204, "peer_mount")
            check(instance.call("POST", "auth/kerberos/config", config,
                  namespace="kerberos-peer")[0] == 204, "peer_configuration")
            instance.stop()
            # A new, still-enabled MIT replay cache models another host. No
            # cache is disabled, and no old cache is copied into this process.
            fresh_native_cache = work_dir / "server-generation-1.replay"
            check(not fresh_native_cache.exists(), "restart_native_cache_is_fresh")
            environment["KRB5RCACHENAME"] = "file2:" + str(fresh_native_cache)
            os.environ["KRB5RCACHENAME"] = environment["KRB5RCACHENAME"]
            instance.start()
            check(instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200, "restart_unseal")
            # Check the other namespace FIRST: trying the original namespace
            # through GSS could populate the cold native cache and mask a
            # missing cross-namespace application-level replay fence.
            cross_status = instance.call("POST", "auth/kerberos/login", {}, token="",
                namespace="kerberos-peer", extra_headers={"Authorization":second_header})[0]
            check(cross_status == 403, "cross_namespace_replay_denied")
            check(not fresh_native_cache.exists(), "durable_replay_rejects_before_gss_entry")
            restart_status = instance.call(
                "POST", "auth/kerberos/login", {}, token="", extra_headers={"Authorization": second_header}
            )[0]
            check(restart_status == 403, "restart_replay_denied")
            fresh_header = negotiate_header(instance, environment)
            check(instance.call("POST", "auth/kerberos/login", {}, token="",
                  extra_headers={"Authorization":fresh_header})[0] == 200
                  and fresh_native_cache.exists(), "restart_fresh_ticket_still_works")
            check(set(CORPUS_CASE_IDS).issubset(passed), "corpus_complete")
            return {"status": "passed", "checks": [name for name in passed if name in CORPUS_CASE_IDS],
                    "native_replay_cache_enabled": True,
                    "native_clock_skew_seconds": NATIVE_CLOCK_SKEW_SECONDS,
                    "valid_ap_req_delivery_delay_seconds": NORMAL_REQUEST_DELAY_SECONDS,
                    "expiry_wait_seconds": expired_ticket_wait_seconds(),
                    "expiry_semantics": "beyond_ticket_endtime_plus_native_clockskew",
                    "independent_qualification": False,
                    "openbao_api_parity": False}
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
        result = run(args.binary.resolve(strict=True), args.work_dir)
        print(json.dumps(result))
        if result.get("status") != "passed":
            raise SystemExit(77 if result.get("status") == "not_run" else 1)
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": type(error).__name__,
                          "stage": error.stage if isinstance(error, FixtureFailure) else "unclassified_failure"}))
        raise SystemExit(1) from None
