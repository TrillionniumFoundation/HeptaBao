#!/usr/bin/env python3
"""Real InfluxDB 1.8 provider acceptance through the checksum-bound database plugin.

This fixture uses the legacy authenticated InfluxDB 1.8 HTTP API. It creates a
fresh provider, verifies actual CREATE USER/GRANT/DROP USER effects, and keeps
secrets in stdin/request bodies or HTTP headers rather than argv/logs.
"""
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
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa" / "single-node"))
import smoke

IMAGE = "influxdb@sha256:299ebda2c7e308dbef42e26ac9b8fd1d9b3bcb8a0aee80c6509aa0219c1d0290"
APP_DATABASE = "app"
UNGRANTED_DATABASE = "denied"
FENCE_DATABASE = "heptabao_provider"
MANAGER_USERNAME = "admin"
CORPUS_CASE_IDS = (
    "real_influxdb_1_8_ready",
    "influxdb_plugin_configuration_readback",
    "influxdb_unbound_database_rejected",
    "influxdb_readonly_issue_reaches_provider",
    "influxdb_readonly_query_succeeds",
    "influxdb_ungranted_database_denied",
    "influxdb_readonly_write_denied",
    "influxdb_dynamic_credential_renew_reaches_provider",
    "influxdb_provider_state_survives_restart",
    "influxdb_service_state_survives_restart",
    "influxdb_revoke_removes_provider_login",
    "influxdb_outage_retains_revoke_intent",
    "influxdb_restart_reconciles_pending_revoke",
)


class InfluxError(RuntimeError):
    pass


class InfluxContainer:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = "heptabao-influxdb-" + secrets.token_hex(8)
        self.password = secrets.token_hex(24)
        self.port = 0
        self.running = False
        self.created = False
        self.opener = build_opener(ProxyHandler({}))

    @staticmethod
    def available() -> bool:
        return shutil.which("docker") is not None

    @staticmethod
    def image_present() -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=12,
        )
        return result.returncode == 0

    @property
    def origin(self) -> str:
        if not self.port:
            raise RuntimeError("influxdb_port_not_bound")
        return "http://127.0.0.1:" + str(self.port)

    def _json_request(self, request: Request) -> tuple[int, dict]:
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(262145)
                if len(raw) > 262144:
                    raise InfluxError("influxdb_response_too_large")
                value = json.loads(raw.decode("utf-8")) if raw else {}
                if not isinstance(value, dict):
                    raise InfluxError("influxdb_response_not_object")
                return response.status, value
        except HTTPError as error:
            raw = error.read(262145)
            if len(raw) > 262144:
                raise InfluxError("influxdb_error_response_too_large") from error
            try:
                value = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as decode_error:
                raise InfluxError("influxdb_error_response_invalid") from decode_error
            if not isinstance(value, dict):
                raise InfluxError("influxdb_error_response_not_object") from error
            return error.code, value
        except (URLError, TimeoutError, OSError) as error:
            raise InfluxError("influxdb_unavailable") from error

    def _request(
        self,
        path: str,
        *,
        username: str,
        password: str,
        params: dict[str, str] | None = None,
        body: str | None = None,
    ) -> tuple[int, dict]:
        url = self.origin + path
        if params:
            url += "?" + urlencode(params)
        basic = base64.b64encode((username + ":" + password).encode()).decode()
        data = None if body is None else body.encode("utf-8")
        request = Request(
            url,
            data=data,
            method="POST" if data is not None else "GET",
            headers={
                "Authorization": "Basic " + basic,
                "Content-Type": "application/x-www-form-urlencoded"
                if path == "/query"
                else "text/plain; charset=utf-8",
            },
        )
        return self._json_request(request)

    def query(
        self,
        statement: str,
        *,
        username: str | None = None,
        password: str | None = None,
        database: str = "",
        allow_error: bool = False,
    ) -> tuple[int, dict]:
        params = {"db": database} if database else {}
        body = None
        if statement.lstrip().upper().startswith(("SELECT", "SHOW")):
            params["q"] = statement
        else:
            body = urlencode({"q": statement})
        status, response = self._request(
            "/query",
            username=MANAGER_USERNAME if username is None else username,
            password=self.password if password is None else password,
            params=params,
            body=body,
        )
        if status >= 300:
            if allow_error:
                return status, response
            raise InfluxError("influxdb_query_rejected")
        if any(isinstance(result, dict) and result.get("error")
               for result in response.get("results", [])):
            if allow_error:
                return status, response
            raise InfluxError("influxdb_query_failed")
        return status, response

    def write(
        self,
        line: str,
        *,
        username: str | None = None,
        password: str | None = None,
        database: str = APP_DATABASE,
        allow_error: bool = False,
    ) -> int:
        status, _ = self._request(
            "/write",
            username=MANAGER_USERNAME if username is None else username,
            password=self.password if password is None else password,
            params={"db": database},
            body=line,
        )
        if status >= 300 and not allow_error:
            raise InfluxError("influxdb_write_rejected")
        return status

    @staticmethod
    def _rows(response: dict) -> list[dict]:
        rows: list[dict] = []
        for result in response.get("results", []):
            if not isinstance(result, dict):
                continue
            for series in result.get("series", []):
                if not isinstance(series, dict):
                    continue
                columns = series.get("columns", [])
                for values in series.get("values", []):
                    if isinstance(columns, list) and isinstance(values, list):
                        rows.append(dict(zip(columns, values)))
        return rows

    def users(self) -> list[dict]:
        return self._rows(self.query("SHOW USERS")[1])

    def user_present(self, username: str, password: str) -> bool:
        try:
            self.query(
                "SELECT value FROM items WHERE id='seed'",
                username=username,
                password=password,
                database=APP_DATABASE,
            )
            return True
        except InfluxError:
            return False

    def _assert_port_binding(self) -> None:
        mapped = subprocess.run(
            ["docker", "port", self.name, "8086/tcp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=12,
        )
        match = re.search(r":(\d+)\s*$", mapped.stdout.strip())
        if (
            mapped.returncode != 0
            or match is None
            or int(match.group(1)) != self.port
        ):
            raise RuntimeError("influxdb_port_binding_changed")

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                admin = any(
                    row.get("user") == MANAGER_USERNAME and row.get("admin") is True
                    for row in self.users()
                )
                databases = self._rows(self.query("SHOW DATABASES")[1])
                if admin and any(row.get("name") == APP_DATABASE for row in databases):
                    return
            except InfluxError:
                pass
            time.sleep(0.5)
        raise RuntimeError("influxdb_readiness_failed")

    def start_fresh(self) -> None:
        # The checksum-bound plugin embeds the provider endpoint, so the
        # loopback mapping must remain stable across provider restarts. Pick a
        # candidate port and let Docker claim it; bounded retries close the
        # bind/close race without accepting a mutable endpoint.
        for _ in range(16):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                self.port = int(listener.getsockname()[1])
            result = subprocess.run(
                [
                    "docker", "run", "-d", "--name", self.name,
                    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
                    "-e", "INFLUXDB_DB=" + APP_DATABASE,
                    "-e", "INFLUXDB_ADMIN_USER=" + MANAGER_USERNAME,
                    "-e", "INFLUXDB_HTTP_AUTH_ENABLED=true",
                    "--env-file", "/dev/stdin",
                    "-p", f"127.0.0.1:{self.port}:8086", IMAGE,
                ],
                input="INFLUXDB_ADMIN_PASSWORD=" + self.password + "\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=45,
            )
            if result.returncode == 0:
                break
            subprocess.run(
                ["docker", "rm", "-f", self.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            retryable = result.stderr.lower()
            if not any(
                marker in retryable
                for marker in (
                    "port is already allocated",
                    "address already in use",
                    "failed to bind host port",
                )
            ):
                raise RuntimeError("influxdb_container_start_failed")
        else:
            raise RuntimeError("influxdb_port_allocation_exhausted")
        self.created = True
        self.running = True
        self._assert_port_binding()
        self._wait_ready()
        self.query("CREATE DATABASE \"" + UNGRANTED_DATABASE + "\"")
        self.query("CREATE DATABASE \"" + FENCE_DATABASE + "\"")
        self.write('items,id=seed value="seed"')
        self.write(
            'items,id=seed value="denied"',
            database=UNGRANTED_DATABASE,
        )

    def restart(self) -> None:
        if not self.created:
            raise RuntimeError("influxdb_container_not_created")
        result = subprocess.run(
            ["docker", "restart", "-t", "10", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError("influxdb_container_restart_failed")
        self.running = True
        # A changed mapping would invalidate the checksum-bound endpoint.
        self._assert_port_binding()
        self._wait_ready()

    def stop(self) -> None:
        if self.created and self.running:
            subprocess.run(
                ["docker", "stop", "-t", "1", self.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12,
            )
            self.running = False

    def destroy(self) -> None:
        if self.created:
            subprocess.run(
                ["docker", "rm", "-f", self.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        self.running = False
        self.created = False

    def fence_for_username(self, username: str) -> dict | None:
        try:
            response = self.query(
                'SELECT * FROM fences WHERE "username"='
                + repr(username) + " ORDER BY time DESC LIMIT 1",
                database=FENCE_DATABASE,
            )[1]
        except InfluxError:
            return None
        rows = self._rows(response)
        return rows[0] if rows else None


def make_exec(path: Path, text: str) -> str:
    compile(text, str(path), "exec")
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_plugin(instance: smoke.Instance, root: Path, provider: InfluxContainer) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker_missing")
    wrapper = root / "influxdb-sandbox-wrapper.py"
    plugin = root / "influxdb-plugin.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def value(flag): return a[a.index(flag)+1]
if value("--heptabao-profile")!="influxdb_database_profile" or value("--heptabao-protocol")!="1":
    raise SystemExit(64)
if value("--heptabao-operation") not in ("read","issue","renew","revoke"):
    raise SystemExit(64)
os.execv(value("--heptabao-plugin"),[value("--heptabao-plugin")])
""",
    )
    plugin_source = r'''#!__PYTHON__
import base64,json,re,struct,sys
from urllib.error import HTTPError,URLError
from urllib.parse import urlencode,urlsplit
from urllib.request import ProxyHandler,Request,build_opener

BASE=__BASE__
APP=__APP__
FENCE=__FENCE__
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

def validate_connection(value):
    if not isinstance(value,str) or value!=BASE+"/"+APP:
        return False
    try:
        parsed=urlsplit(value)
    except ValueError:
        return False
    return not (
        parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or
        parsed.username or parsed.password or parsed.query or parsed.fragment or
        parsed.path!="/"+APP or parsed.port is None
    )

def request(path,params,username,password,body=None):
    token=base64.b64encode((username+":"+password).encode()).decode()
    url=BASE+path+"?"+urlencode(params)
    data=None if body is None else body.encode()
    req=Request(url,data=data,method="POST" if data is not None else "GET",headers={
        "Authorization":"Basic "+token,
        "Content-Type":"application/x-www-form-urlencoded" if path=="/query"
        else "text/plain; charset=utf-8"})
    try:
        with OPENER.open(req,timeout=5) as response:
            raw=response.read(MAX_RESPONSE+1)
            status=response.status
    except HTTPError as error:
        try:
            error.read(MAX_RESPONSE+1)
        except (OSError,ValueError):
            pass
        raise ProviderUnavailable from error
    except (URLError,TimeoutError,OSError) as error:
        raise ProviderUnavailable from error
    if len(raw)>MAX_RESPONSE:
        raise ProviderUnavailable
    try:
        value=json.loads(raw.decode()) if raw else {}
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        raise ProviderUnavailable from error
    if status>=300 or not isinstance(value,dict):
        raise ProviderUnavailable
    for result in value.get("results",[]):
        if isinstance(result,dict) and result.get("error"):
            raise ProviderUnavailable
    return value

def query(statement,username,password,database=""):
    params={}
    if database:
        params["db"]=database
    if statement.lstrip().upper().startswith(("SELECT","SHOW")):
        params["q"]=statement
        return request("/query",params,username,password)
    return request("/query",params,username,password,urlencode({"q":statement}))

def write(line,username,password,database):
    request("/write",{"db":database},username,password,line)

def rows(value):
    result=[]
    for item in value.get("results",[]):
        if not isinstance(item,dict):
            continue
        for series in item.get("series",[]):
            if not isinstance(series,dict):
                continue
            columns=series.get("columns",[])
            for values in series.get("values",[]):
                if isinstance(columns,list) and isinstance(values,list):
                    result.append(dict(zip(columns,values)))
    return result

def quote_identifier(value):
    if not re.fullmatch(r"[A-Za-z0-9_]+",value):
        raise SystemExit(70)
    return '"'+value+'"'

def users(username,password):
    return rows(query("SHOW USERS",username,password))

def has_user(username,password,target):
    return any(row.get("user")==target for row in users(username,password))

def fence(username,password,provider_id):
    result=query("SELECT * FROM fences WHERE \"provider_id\"='"+provider_id+
                 "' ORDER BY time DESC LIMIT 1",username,password,FENCE)
    found=rows(result)
    return found[0] if found else None

def number(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)):
        raise SystemExit(69)
    return int(value)

raw=sys.stdin.buffer.read(1048588)
if len(raw)<11 or raw[:4]!=b"HBP1" or raw[4:6]!=b"\x00\x01":
    raise SystemExit(65)
op=raw[6]
size=struct.unpack(">I",raw[7:11])[0]
if size==0 or size>262144 or len(raw)!=11+size:
    raise SystemExit(65)
try:
    request_value=json.loads(raw[11:].decode())
except (UnicodeDecodeError,json.JSONDecodeError):
    raise SystemExit(65)
if not isinstance(request_value,dict):
    raise SystemExit(65)
manager=request_value.get("manager_username")
manager_password=request_value.get("manager_password")
if manager!=MANAGER or not isinstance(manager_password,str) or not re.fullmatch(r"[0-9a-f]{48}",manager_password):
    raise SystemExit(66)
connection_ok=validate_connection(request_value.get("connection_url"))
action=request_value.get("action")
if op==1:
    if action!="configure":
        raise SystemExit(67)
    if not connection_ok:
        emit({"configured":False,"error":"connection_rejected"})
        raise SystemExit(0)
    try:
        visible=users(manager,manager_password)
        databases=rows(query("SHOW DATABASES",manager,manager_password))
    except ProviderUnavailable:
        raise SystemExit(71)
    if not any(row.get("user")==MANAGER and row.get("admin") is True for row in visible):
        raise SystemExit(67)
    if (not any(row.get("name")==APP for row in databases)
        or not any(row.get("name")==FENCE for row in databases)):
        raise SystemExit(67)
    emit({"configured":True,"manager_identity":manager})
    raise SystemExit(0)

if not connection_ok:
    raise SystemExit(68)
if {"issue":3,"renew":4,"revoke":5}.get(action)!=op:
    raise SystemExit(67)
provider_id=request_value.get("provider_id")
username=request_value.get("username")
password=request_value.get("password")
role=request_value.get("provider_role")
seq=request_value.get("seq")
digest=request_value.get("request_digest")
expires=request_value.get("expires")
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

try:
    query("SHOW DATABASES",manager,manager_password)
    previous=fence(manager,manager_password,provider_id)
except ProviderUnavailable:
    emit({"applied":False,"provider_id":provider_id,"seq":seq,"request_digest":digest,
          "username":username,"active":action!="revoke","expires":expires})
    raise SystemExit(0)
if previous:
    old_seq=number(previous.get("seq"))
    if seq<old_seq or (seq==old_seq and digest!=previous.get("request_digest")):
        raise SystemExit(69)

app=quote_identifier(APP)
user=quote_identifier(username)
if action=="issue":
    if not has_user(manager,manager_password,username):
        query("CREATE USER "+user+" WITH PASSWORD '"+password+"'",manager,manager_password)
    query("GRANT READ ON "+app+" TO "+user,manager,manager_password)
    query("SHOW MEASUREMENTS",username,password,APP)
    if not rows(query("SELECT value FROM items WHERE id='seed'",username,password,APP)):
        raise SystemExit(69)
    active=True
elif action=="renew":
    if not previous or previous.get("username")!=username or previous.get("active") is not True or not has_user(manager,manager_password,username):
        raise SystemExit(69)
    active=True
else:
    if has_user(manager,manager_password,username):
        query("DROP USER "+user,manager,manager_password)
    active=False

fields=("seq="+str(seq)+"i,request_digest=\""+digest+"\",active="+
        ("true" if active else "false")+",expires="+str(expires)+"i")
write("fences,provider_id="+provider_id+",username="+username+" "+fields,
      manager,manager_password,FENCE)
observed=fence(manager,manager_password,provider_id)
if not observed or number(observed.get("seq"))!=seq or observed.get("request_digest")!=digest or observed.get("username")!=username or bool(observed.get("active"))!=active or number(observed.get("expires"))!=expires:
    raise SystemExit(69)
if (active and not has_user(manager,manager_password,username)) or ((not active) and has_user(manager,manager_password,username)):
    raise SystemExit(69)
emit({"applied":True,"provider_id":provider_id,"seq":seq,"request_digest":digest,
      "username":username,"active":active,"expires":expires})
'''
    plugin_source = (
        plugin_source.replace("__PYTHON__", sys.executable)
        .replace("__BASE__", repr(provider.origin))
        .replace("__APP__", repr(APP_DATABASE))
        .replace("__FENCE__", repr(FENCE_DATABASE))
        .replace("__MANAGER__", repr(MANAGER_USERNAME))
    )
    plugin_sha = make_exec(plugin, plugin_source)
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["plugin_database"] = [{
        "id": "influxdb-database-plugin",
        "command": str(plugin),
        "command_sha256": plugin_sha,
        "sandbox_provider_id": "fixture_sandbox",
        "sandbox_command": str(wrapper),
        "sandbox_command_sha256": wrapper_sha,
        "sandbox_profile_id": "influxdb_database_profile",
        "maximum_request_bytes": 262144,
        "maximum_response_bytes": 262144,
        "timeout_ms": 20000,
    }]
    config["lifecycle_interval_seconds"] = 1
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def run(binary: Path, root: Path, output: Path) -> int:
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks: list[dict[str, object]] = []
    provider = InfluxContainer(root / "influxdb")
    instance = smoke.Instance(binary, root / "server")
    key = ""

    def check(name: str, condition: bool) -> None:
        checks.append({"case": name, "passed": bool(condition)})
        if condition is not True:
            raise RuntimeError(name)

    try:
        provider.start_fresh()
        check("real_influxdb_1_8_ready", any(
            row.get("user") == MANAGER_USERNAME and row.get("admin") is True
            for row in provider.users()
        ))
        configure_plugin(instance, root, provider)
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check(
            "mount_database",
            instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204,
        )
        config = {
            "plugin_name": "influxdb-database-plugin",
            "connection_url": provider.origin + "/" + APP_DATABASE,
            "username": MANAGER_USERNAME,
            "password": provider.password,
            "allowed_roles": ["readonly"],
            "verify_connection": True,
        }
        wrong_config = dict(
            config,
            connection_url=provider.origin + "/" + UNGRANTED_DATABASE,
        )
        check(
            "influxdb_unbound_database_rejected",
            instance.call("POST", "database/config/wrong", wrong_config)[0] == 400
            and instance.call("GET", "database/config/wrong")[0] == 404,
        )
        configured = instance.call("POST", "database/config/local", config)[0] == 204
        readback_status, readback = instance.call("GET", "database/config/local")
        check(
            "influxdb_plugin_configuration_readback",
            configured
            and readback_status == 200
            and readback.get("data", {}).get("plugin_name") == "influxdb-database-plugin",
        )
        check(
            "readonly_role",
            instance.call("POST", "database/roles/readonly", {
                "db_name": "local",
                "provider_role": "readonly",
                "default_ttl": 30,
                "max_ttl": 180,
            })[0] == 204,
        )

        status, issued = instance.call("GET", "database/creds/readonly")
        check("influxdb_readonly_issue_reaches_provider", status == 200)
        ro = issued["data"]
        ro_lease = issued["lease_id"]
        selected = provider.query(
            "SELECT value FROM items WHERE id='seed'",
            username=ro["username"], password=ro["password"], database=APP_DATABASE,
        )
        shown = provider.query(
            "SHOW MEASUREMENTS",
            username=ro["username"], password=ro["password"], database=APP_DATABASE,
        )
        check(
            "influxdb_readonly_query_succeeds",
            any(row.get("value") == "seed" for row in provider._rows(selected[1]))
            and any(row.get("name") == "items" for row in provider._rows(shown[1])),
        )
        try:
            provider.query(
                "SELECT value FROM items WHERE id='seed'",
                username=ro["username"], password=ro["password"],
                database=UNGRANTED_DATABASE,
            )
            ungranted = False
        except InfluxError:
            ungranted = True
        check("influxdb_ungranted_database_denied", ungranted)
        check(
            "influxdb_readonly_write_denied",
            provider.write(
                'items,id=denied value="denied"',
                username=ro["username"], password=ro["password"],
                database=APP_DATABASE, allow_error=True,
            ) >= 300,
        )

        before_fence = provider.fence_for_username(ro["username"])
        status, renewed = instance.call(
            "POST", "sys/leases/renew", {"lease_id": ro_lease, "increment": 60}
        )
        after_fence = provider.fence_for_username(ro["username"])
        check(
            "influxdb_dynamic_credential_renew_reaches_provider",
            status == 200 and renewed.get("renewable") is True
            and before_fence is not None
            and after_fence is not None
            and int(after_fence.get("seq", 0)) > int(before_fence.get("seq", 0))
            and after_fence.get("username") == ro["username"]
            and after_fence.get("active") is True
            and int(after_fence.get("expires", 0)) > 0,
        )

        provider.restart()
        check(
            "influxdb_provider_state_survives_restart",
            provider.user_present(ro["username"], ro["password"])
            and any(row.get("value") == "seed" for row in provider._rows(
                provider.query(
                    "SELECT value FROM items WHERE id='seed'",
                    username=ro["username"], password=ro["password"], database=APP_DATABASE,
                )[1]
            )),
        )
        instance.stop()
        instance.start()
        check("restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        lookup_status, lookup = instance.call(
            "POST", "sys/leases/lookup", {"lease_id": ro_lease}
        )
        check(
            "influxdb_service_state_survives_restart",
            instance.call("GET", "database/config/local")[0] == 200
            and lookup_status == 200
            and lookup.get("data", {}).get("id") == ro_lease,
        )
        check(
            "influxdb_revoke_removes_provider_login",
            instance.call("POST", "sys/leases/revoke", {"lease_id": ro_lease})[0] == 204
            and not provider.user_present(ro["username"], ro["password"]),
        )

        status, outage = instance.call("GET", "database/creds/readonly")
        check("outage_seed", status == 200)
        outage_lease = outage["lease_id"]
        outage_cred = outage["data"]
        check(
            "outage_user_live",
            provider.user_present(outage_cred["username"], outage_cred["password"]),
        )
        provider.stop()
        status, body = instance.call(
            "POST", "sys/leases/revoke", {"lease_id": outage_lease}
        )
        check(
            "influxdb_outage_retains_revoke_intent",
            status == 503 and body.get("reconcile_required") is True
            and "data" not in body,
        )
        provider.restart()
        deadline = time.monotonic() + 30
        terminal = False
        while time.monotonic() < deadline:
            instance.call(
                "POST", "sys/leases/reconcile/" + outage_lease, {}
            )
            lookup_status, lookup = instance.call(
                "POST", "sys/leases/lookup", {"lease_id": outage_lease}
            )
            phase = (
                lookup.get("data", {}).get("phase")
                if lookup_status == 200
                else ""
            )
            revoke_status, _ = instance.call(
                "POST", "sys/leases/revoke", {"lease_id": outage_lease}
            )
            terminal = revoke_status == 204 and (
                (lookup_status == 200 and phase == "Revoked")
                or lookup_status in (400, 404)
            )
            if terminal:
                break
            time.sleep(0.1)
        check(
            "influxdb_restart_reconciles_pending_revoke",
            terminal
            and not provider.user_present(
                outage_cred["username"], outage_cred["password"]
            ),
        )

        passed = {item["case"] for item in checks if item["passed"]}
        missing = sorted(set(CORPUS_CASE_IDS) - passed)
        if missing:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing))
        report = {
            "schema": "heptabao.influxdb-bounded-live.v1",
            "status": "passed",
            "checks": checks,
            "provider_image": IMAGE,
            "provider_api": "InfluxDB 1.8 legacy authenticated HTTP API",
            "real_influxdb_provider": True,
            "dynamic_credentials": True,
            "readonly_and_ungranted_denials": True,
            "provider_restart": True,
            "service_restart": True,
            "outage_reconciliation": True,
            "full_openbao_influxdb_compatibility": False,
            "static_roles": False,
            "root_rotation": False,
            "ha": False,
            "migration": False,
            "independent_qualification": False,
            "production_authority": False,
            "candidate_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "passed", "check_count": len(checks)}))
        return 0
    except Exception as error:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({
            "schema": "heptabao.influxdb-bounded-live.v1",
            "status": "failed",
            "checks": checks,
            "safe_error": type(error).__name__,
        }, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "failed", "check_count": len(checks)}))
        return 1
    finally:
        instance.stop()
        provider.destroy()
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not InfluxContainer.available():
        print("BLOCKED: docker is required for real InfluxDB provider qualification", file=sys.stderr)
        return 77
    if not InfluxContainer.image_present():
        print("BLOCKED: pinned InfluxDB 1.8 image is not present; pull it explicitly", file=sys.stderr)
        return 77
    try:
        return run(args.binary.resolve(), args.work_dir.resolve(), args.output.resolve())
    except FileExistsError:
        print("influxdb live failed: private work directory already exists", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
