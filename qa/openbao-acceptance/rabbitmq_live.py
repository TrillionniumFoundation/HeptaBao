#!/usr/bin/env python3
"""Real RabbitMQ 4.1 provider acceptance through the checksum-bound database plugin."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa" / "single-node"))
import smoke

IMAGE = "rabbitmq@sha256:3574a8edaca320282b9c848f0b2661566b7e74f52c1b590f401b10224d294642"
VHOST = "app"
DENIED_VHOST = "denied"
MANAGER = "admin"
CORPUS_CASE_IDS = (
    "real_rabbitmq_4_1_ready",
    "rabbitmq_public_mount_type",
    "rabbitmq_unbound_vhost_rejected",
    "rabbitmq_plugin_configuration_readback",
    "rabbitmq_dynamic_user_reaches_provider",
    "rabbitmq_issued_user_is_not_administrator",
    "rabbitmq_exact_vhost_permissions",
    "rabbitmq_foreign_vhost_denied",
    "rabbitmq_issued_login_is_real",
    "rabbitmq_dynamic_credential_renew_reaches_provider",
    "rabbitmq_provider_state_survives_restart",
    "rabbitmq_service_state_survives_restart",
    "rabbitmq_revoke_removes_provider_user",
    "rabbitmq_outage_retains_revoke_intent",
    "rabbitmq_restart_reconciles_pending_revoke",
)

class RabbitError(RuntimeError):
    pass

class RabbitContainer:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = "heptabao-rabbitmq-" + secrets.token_hex(8)
        self.password = secrets.token_hex(24)
        self.port = 0
        self.created = False
        self.running = False
        self.opener = build_opener(ProxyHandler({}))

    @property
    def origin(self) -> str:
        if not self.port:
            raise RuntimeError("rabbitmq_port_not_bound")
        return "http://127.0.0.1:" + str(self.port)

    def api(self, method: str, path: str, *, username: str | None = None,
            password: str | None = None, body: dict | None = None) -> tuple[int, object]:
        user = MANAGER if username is None else username
        secret = self.password if password is None else password
        token = base64.b64encode((user + ":" + secret).encode()).decode()
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        req = Request(self.origin + path, data=data, method=method, headers={
            "Authorization": "Basic " + token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        try:
            with self.opener.open(req, timeout=7) as response:
                raw = response.read(262145)
                status = response.status
        except HTTPError as error:
            raw = error.read(262145)
            status = error.code
        except (URLError, TimeoutError, OSError) as error:
            raise RabbitError("rabbitmq_unavailable") from error
        if len(raw) > 262144:
            raise RabbitError("rabbitmq_response_too_large")
        if not raw:
            return status, {}
        try:
            return status, json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RabbitError("rabbitmq_invalid_json") from error

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                status, _ = self.api("GET", "/api/overview")
                if status == 200:
                    return
            except RabbitError:
                pass
            time.sleep(0.5)
        raise RuntimeError("rabbitmq_readiness_failed")

    def start_fresh(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        result = subprocess.run([
            "docker", "run", "-d", "--name", self.name,
            "--hostname", self.name,
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "-e", "RABBITMQ_DEFAULT_USER=" + MANAGER,
            "--env-file", "/dev/stdin",
            "-p", f"127.0.0.1:{self.port}:15672",
            IMAGE,
        ], input="RABBITMQ_DEFAULT_PASS=" + self.password + "\n",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError("rabbitmq_container_start_failed")
        self.created = True
        self.running = True
        mapped = subprocess.run(
            ["docker", "port", self.name, "15672/tcp"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=12)
        match = re.search(r":(\d+)\s*$", mapped.stdout.strip())
        if mapped.returncode != 0 or match is None or int(match.group(1)) != self.port:
            raise RuntimeError("rabbitmq_port_binding_mismatch")
        self._wait_ready()
        for vhost in (VHOST, DENIED_VHOST):
            status, _ = self.api("PUT", "/api/vhosts/" + quote(vhost, safe=""), body={})
            if status not in (201, 204):
                raise RuntimeError("rabbitmq_vhost_creation_failed")

    def restart(self) -> None:
        if not self.created:
            raise RuntimeError("rabbitmq_container_not_created")
        result = subprocess.run(
            ["docker", "restart", "-t", "10", self.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=35)
        if result.returncode != 0:
            raise RuntimeError("rabbitmq_container_restart_failed")
        self.running = True
        self._wait_ready()

    def stop(self) -> None:
        if self.created and self.running:
            subprocess.run(
                ["docker", "stop", "-t", "1", self.name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            self.running = False

    def destroy(self) -> None:
        if self.created:
            subprocess.run(
                ["docker", "rm", "-f", self.name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        self.running = False
        self.created = False

    def user(self, username: str) -> dict | None:
        status, value = self.api("GET", "/api/users/" + quote(username, safe=""))
        return value if status == 200 and isinstance(value, dict) else None

    def permission(self, username: str, vhost: str = VHOST) -> dict | None:
        path = "/api/permissions/" + quote(vhost, safe="") + "/" + quote(username, safe="")
        status, value = self.api("GET", path)
        return value if status == 200 and isinstance(value, dict) else None

    def login_ok(self, username: str, password: str) -> bool:
        try:
            status, value = self.api(
                "GET", "/api/whoami", username=username, password=password)
            return status == 200 and isinstance(value, dict) and value.get("name") == username
        except RabbitError:
            return False


def make_exec(path: Path, text: str) -> str:
    compile(text, str(path), "exec")
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_plugin(instance: smoke.Instance, root: Path, provider: RabbitContainer) -> None:
    wrapper = root / "rabbitmq-sandbox-wrapper.py"
    plugin = root / "rabbitmq-plugin.py"
    wrapper_sha = make_exec(wrapper, f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(flag): return a[a.index(flag)+1]
if v("--heptabao-profile")!="rabbitmq_database_profile" or v("--heptabao-protocol")!="1":
    raise SystemExit(64)
if v("--heptabao-operation") not in ("read","issue","renew","revoke"):
    raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""")

    plugin_source = r'''#!__PYTHON__
import base64,json,re,struct,sys
from urllib.error import HTTPError,URLError
from urllib.parse import quote,urlsplit
from urllib.request import ProxyHandler,Request,build_opener

ORIGIN=__ORIGIN__
APP=__APP__
MANAGER=__MANAGER__
OPENER=build_opener(ProxyHandler({}))
MAX_RESPONSE=262144

class ProviderUnavailable(Exception):
    pass

def emit(value):
    payload=json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    if len(payload)>MAX_RESPONSE:
        raise SystemExit(65)
    sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(payload))+payload)
    sys.stdout.buffer.flush()

def api(method,path,username,password,body=None):
    token=base64.b64encode((username+":"+password).encode()).decode()
    data=None if body is None else json.dumps(body,separators=(",",":")).encode()
    req=Request(ORIGIN+path,data=data,method=method,headers={
        "Authorization":"Basic "+token,
        "Accept":"application/json",
        "Content-Type":"application/json",
    })
    try:
        with OPENER.open(req,timeout=7) as response:
            raw=response.read(MAX_RESPONSE+1)
            status=response.status
    except HTTPError as error:
        raw=error.read(MAX_RESPONSE+1)
        status=error.code
    except (URLError,TimeoutError,OSError) as error:
        raise ProviderUnavailable from error
    if len(raw)>MAX_RESPONSE:
        raise ProviderUnavailable
    if not raw:
        return status,{}
    try:
        value=json.loads(raw.decode())
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        raise ProviderUnavailable from error
    return status,value

def connection_ok(value):
    if not isinstance(value,str) or value!=ORIGIN+"/"+APP:
        return False
    try:
        parsed=urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme=="http" and parsed.hostname=="127.0.0.1"
        and parsed.username is None and parsed.password is None
        and parsed.query=="" and parsed.fragment==""
        and parsed.path=="/"+APP and parsed.port is not None
    )

def exact_permission(value):
    return (
        isinstance(value,dict)
        and value.get("vhost")==APP
        and value.get("configure")==""
        and value.get("write")==""
        and value.get("read")==".*"
    )

raw=sys.stdin.buffer.read(1048588)
if len(raw)<11 or raw[:4]!=b"HBP1" or raw[4:6]!=bytes([0,1]):
    raise SystemExit(65)
op=raw[6]
size=struct.unpack(">I",raw[7:11])[0]
if size==0 or size>262144 or len(raw)!=11+size:
    raise SystemExit(65)
try:
    q=json.loads(raw[11:].decode())
except (UnicodeDecodeError,json.JSONDecodeError):
    raise SystemExit(65)
if not isinstance(q,dict):
    raise SystemExit(65)
manager=q.get("manager_username")
manager_password=q.get("manager_password")
if manager!=MANAGER or not isinstance(manager_password,str) or not re.fullmatch(r"[0-9a-f]{48}",manager_password):
    raise SystemExit(66)
action=q.get("action")
bound=connection_ok(q.get("connection_url"))

if op==1:
    if action!="configure":
        raise SystemExit(67)
    if not bound:
        emit({"configured":False,"error":"connection_rejected"})
        raise SystemExit(0)
    try:
        status,user=api("GET","/api/users/"+quote(MANAGER,safe=""),manager,manager_password)
        vstatus,_=api("GET","/api/vhosts/"+quote(APP,safe=""),manager,manager_password)
    except ProviderUnavailable:
        raise SystemExit(71)
    tags=user.get("tags",[]) if isinstance(user,dict) else []
    if status!=200 or user.get("name")!=MANAGER or "administrator" not in tags or vstatus!=200:
        raise SystemExit(67)
    emit({"configured":True,"manager_identity":manager})
    raise SystemExit(0)

if not bound or {"issue":3,"renew":4,"revoke":5}.get(action)!=op:
    raise SystemExit(68)
provider_id=q.get("provider_id")
username=q.get("username")
password=q.get("password")
role=q.get("provider_role")
seq=q.get("seq")
digest=q.get("request_digest")
expires=q.get("expires")
if not isinstance(provider_id,str) or not re.fullmatch(r"hb1:[0-9a-f]{64}",provider_id):
    raise SystemExit(68)
if not isinstance(username,str) or not re.fullmatch(r"hbp_[0-9a-f]+",username):
    raise SystemExit(68)
if not isinstance(seq,int) or seq<=0 or not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest):
    raise SystemExit(68)
if not isinstance(expires,int) or expires<0 or role!="readonly":
    raise SystemExit(68)
if action=="issue" and (not isinstance(password,str) or not re.fullmatch(r"[0-9a-f]{64}",password)):
    raise SystemExit(68)
if action=="revoke" and expires!=0:
    raise SystemExit(68)
if action!="revoke" and expires<=0:
    raise SystemExit(68)

user_path="/api/users/"+quote(username,safe="")
perm_path="/api/permissions/"+quote(APP,safe="")+"/"+quote(username,safe="")
try:
    if action=="issue":
        status,_=api("PUT",user_path,manager,manager_password,{"password":password,"tags":"management"})
        if status not in (201,204):
            raise SystemExit(69)
        status,_=api("PUT",perm_path,manager,manager_password,{"configure":"","write":"","read":".*"})
        if status not in (201,204):
            raise SystemExit(69)
        active=True
    elif action=="renew":
        ustatus,user=api("GET",user_path,manager,manager_password)
        pstatus,permission=api("GET",perm_path,manager,manager_password)
        if ustatus!=200 or pstatus!=200 or not exact_permission(permission):
            raise SystemExit(69)
        tags=user.get("tags",[]) if isinstance(user,dict) else []
        if "administrator" in tags:
            raise SystemExit(69)
        active=True
    else:
        status,_=api("DELETE",user_path,manager,manager_password)
        if status not in (204,404):
            raise SystemExit(69)
        active=False
except ProviderUnavailable:
    # The provider was unreachable before this branch observed any accepted
    # mutation. Return a bounded no-effect receipt instead of crashing the
    # plugin process; crashing after runner entry would correctly fence the
    # host as outcome-unknown and would make a safe retry indistinguishable
    # from a post-effect ambiguity.
    emit({"applied":False,"provider_id":provider_id,"seq":seq,"request_digest":digest,
          "username":username,"active":action!="revoke","expires":expires})
    raise SystemExit(0)

try:
    ustatus,user=api("GET",user_path,manager,manager_password)
    pstatus,permission=api("GET",perm_path,manager,manager_password)
except ProviderUnavailable:
    raise SystemExit(71)
if active:
    tags=user.get("tags",[]) if isinstance(user,dict) else []
    if ustatus!=200 or "administrator" in tags or pstatus!=200 or not exact_permission(permission):
        raise SystemExit(69)
elif ustatus!=404:
    raise SystemExit(69)

emit({"applied":True,"provider_id":provider_id,"seq":seq,"request_digest":digest,
      "username":username,"active":active,"expires":expires})
'''
    plugin_source = (
        plugin_source.replace("__PYTHON__", sys.executable)
        .replace("__ORIGIN__", repr(provider.origin))
        .replace("__APP__", repr(VHOST))
        .replace("__MANAGER__", repr(MANAGER))
    )
    plugin_sha = make_exec(plugin, plugin_source)
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["plugin_database"] = [{
        "id": "rabbitmq-database-plugin",
        "command": str(plugin),
        "command_sha256": plugin_sha,
        "sandbox_provider_id": "fixture_sandbox",
        "sandbox_command": str(wrapper),
        "sandbox_command_sha256": wrapper_sha,
        "sandbox_profile_id": "rabbitmq_database_profile",
        "maximum_request_bytes": 262144,
        "maximum_response_bytes": 262144,
        "timeout_ms": 20000,
    }]
    config["lifecycle_interval_seconds"] = 1
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)


def run(binary: Path, root: Path, output: Path) -> int:
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    provider = RabbitContainer(root / "rabbitmq")
    instance = smoke.Instance(binary, root / "server")
    checks: list[dict[str, object]] = []
    key = ""

    def check(name: str, condition: bool) -> None:
        checks.append({"case": name, "passed": bool(condition)})
        if condition is not True:
            raise RuntimeError(name)

    try:
        provider.start_fresh()
        status, manager = provider.api("GET", "/api/users/" + quote(MANAGER, safe=""))
        check(
            "real_rabbitmq_4_1_ready",
            status == 200 and isinstance(manager, dict)
            and "administrator" in manager.get("tags", []),
        )
        configure_plugin(instance, root, provider)
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check(
            "mount_rabbitmq",
            instance.call("POST", "sys/mounts/rabbitmq", {"type": "rabbitmq"})[0] == 204,
        )
        status, descriptor = instance.call("GET", "sys/mounts/rabbitmq")
        check(
            "rabbitmq_public_mount_type",
            status == 200 and descriptor.get("data", {}).get("type") == "rabbitmq",
        )

        config = {
            "plugin_name": "rabbitmq-database-plugin",
            "connection_url": provider.origin + "/" + VHOST,
            "username": MANAGER,
            "password": provider.password,
            "allowed_roles": ["readonly"],
            "verify_connection": True,
        }
        bad = dict(config, connection_url=provider.origin + "/" + DENIED_VHOST)
        check(
            "rabbitmq_unbound_vhost_rejected",
            instance.call("POST", "rabbitmq/config/wrong", bad)[0] == 400
            and instance.call("GET", "rabbitmq/config/wrong")[0] == 404,
        )
        configured = instance.call("POST", "rabbitmq/config/local", config)[0] == 204
        status, readback = instance.call("GET", "rabbitmq/config/local")
        check(
            "rabbitmq_plugin_configuration_readback",
            configured and status == 200
            and readback.get("data", {}).get("plugin_name") == "rabbitmq-database-plugin",
        )
        check(
            "readonly_role",
            instance.call("POST", "rabbitmq/roles/readonly", {
                "db_name": "local",
                "provider_role": "readonly",
                "default_ttl": 30,
                "max_ttl": 180,
            })[0] == 204,
        )

        status, issued = instance.call("GET", "rabbitmq/creds/readonly")
        check("rabbitmq_dynamic_user_reaches_provider", status == 200)
        credential = issued["data"]
        lease_id = issued["lease_id"]
        user = provider.user(credential["username"])
        check(
            "rabbitmq_issued_user_is_not_administrator",
            user is not None
            and "management" in user.get("tags", [])
            and "administrator" not in user.get("tags", []),
        )
        permission = provider.permission(credential["username"], VHOST)
        check(
            "rabbitmq_exact_vhost_permissions",
            permission is not None
            and permission.get("configure") == ""
            and permission.get("write") == ""
            and permission.get("read") == ".*",
        )
        check(
            "rabbitmq_foreign_vhost_denied",
            provider.permission(credential["username"], DENIED_VHOST) is None,
        )
        check(
            "rabbitmq_issued_login_is_real",
            provider.login_ok(credential["username"], credential["password"]),
        )

        status, renewed = instance.call(
            "POST", "sys/leases/renew", {"lease_id": lease_id, "increment": 60})
        check(
            "rabbitmq_dynamic_credential_renew_reaches_provider",
            status == 200 and renewed.get("renewable") is True
            and provider.user(credential["username"]) is not None
            and provider.permission(credential["username"], VHOST) is not None,
        )

        provider.restart()
        check(
            "rabbitmq_provider_state_survives_restart",
            provider.login_ok(credential["username"], credential["password"])
            and provider.permission(credential["username"], VHOST) is not None,
        )

        instance.stop()
        instance.start()
        check("restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        lookup_status, lookup = instance.call(
            "POST", "sys/leases/lookup", {"lease_id": lease_id})
        check(
            "rabbitmq_service_state_survives_restart",
            instance.call("GET", "rabbitmq/config/local")[0] == 200
            and lookup_status == 200 and lookup.get("data", {}).get("id") == lease_id,
        )
        check(
            "rabbitmq_revoke_removes_provider_user",
            instance.call("POST", "sys/leases/revoke", {"lease_id": lease_id})[0] == 204
            and provider.user(credential["username"]) is None,
        )

        status, outage = instance.call("GET", "rabbitmq/creds/readonly")
        check("outage_seed", status == 200)
        outage_lease = outage["lease_id"]
        outage_user = outage["data"]["username"]
        check("outage_user_live", provider.user(outage_user) is not None)
        provider.stop()
        status, body = instance.call(
            "POST", "sys/leases/revoke", {"lease_id": outage_lease})
        check(
            "rabbitmq_outage_retains_revoke_intent",
            status == 503 and body.get("reconcile_required") is True
            and body.get("lease_id") == outage_lease,
        )
        provider.restart()
        status, _ = instance.call(
            "POST", "sys/leases/reconcile/" + outage_lease, {})
        if status != 204:
            status, _ = instance.call(
                "POST", "sys/leases/revoke", {"lease_id": outage_lease})
        check(
            "rabbitmq_restart_reconciles_pending_revoke",
            status == 204 and provider.user(outage_user) is None,
        )

        missing = sorted(set(CORPUS_CASE_IDS) - {
            item["case"] for item in checks if item["passed"]
        })
        if missing:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing))
        evidence = {
            "schema": "heptabao.rabbitmq-bounded-live.v1",
            "status": "passed",
            "checks": checks,
            "provider_image": IMAGE,
            "provider_api": "RabbitMQ 4.1 Management HTTP API",
            "real_rabbitmq_provider": True,
            "dynamic_credentials": True,
            "vhost_permission_readback": True,
            "provider_restart": True,
            "service_restart": True,
            "outage_reconciliation": True,
            "full_openbao_rabbitmq_compatibility": False,
            "ha": False,
            "migration": False,
            "independent_qualification": False,
            "production_authority": False,
            "candidate_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "passed", "check_count": len(checks)}))
        return 0
    except Exception as error:
        evidence = {
            "schema": "heptabao.rabbitmq-bounded-live.v1",
            "status": "failed",
            "checks": checks,
            "safe_error": type(error).__name__,
        }
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "failed", "check_count": len(checks)}))
        return 1
    finally:
        instance.stop()
        provider.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(
        args.binary.resolve(),
        args.work_dir.resolve(),
        args.output.resolve(),
    ))
