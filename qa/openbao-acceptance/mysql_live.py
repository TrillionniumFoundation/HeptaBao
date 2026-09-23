#!/usr/bin/env python3
"""Real MySQL 8.4 provider acceptance through the checksum-bound database plugin.

The fixture creates only a fresh Docker container with a random root password and
private HeptaBao work directory. Provider credentials are delivered over stdin,
never argv. Missing Docker or the pinned image is BLOCKED (exit 77); no model or
wire emulator is accepted as provider evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa" / "single-node"))
import smoke

IMAGE = "mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d"
CORPUS_CASE_IDS = (
    "real_mysql_8_4_ready",
    "mysql_plugin_configuration_readback",
    "mysql_readonly_issue_reaches_provider",
    "mysql_readonly_select_succeeds",
    "mysql_readonly_write_denied",
    "mysql_readwrite_statement_matrix",
    "mysql_transaction_rollback_is_observed",
    "mysql_dynamic_credential_renew_reaches_provider",
    "mysql_provider_state_survives_restart",
    "mysql_service_state_survives_restart",
    "mysql_revoke_removes_provider_login",
    "mysql_outage_retains_revoke_intent",
    "mysql_restart_reconciles_pending_revoke",
)


class MySqlContainer:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = "heptabao-mysql-" + secrets.token_hex(8)
        self.password = secrets.token_hex(24)
        self.running = False
        self.created = False

    @staticmethod
    def available() -> bool:
        return shutil.which("docker") is not None

    @staticmethod
    def image_present() -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    def start_fresh(self) -> None:
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            self.name,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "-e",
            "MYSQL_ROOT_PASSWORD=" + self.password,
            "-e",
            "MYSQL_DATABASE=app",
            IMAGE,
            "--skip-name-resolve",
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=45
        )
        if result.returncode != 0:
            raise RuntimeError("mysql_container_start_failed")
        self.created = True
        self.running = True
        self._wait_ready()
        self.sql(
            "CREATE TABLE IF NOT EXISTS app.items("
            "id BIGINT PRIMARY KEY, value VARCHAR(128) NOT NULL);"
            "CREATE DATABASE IF NOT EXISTS heptabao_provider;"
            "CREATE TABLE IF NOT EXISTS heptabao_provider.fences("
            "provider_id VARCHAR(80) PRIMARY KEY,"
            "seq BIGINT UNSIGNED NOT NULL,"
            "request_digest CHAR(64) NOT NULL,"
            "username VARCHAR(96) NOT NULL,"
            "active BOOLEAN NOT NULL,"
            "expires BIGINT UNSIGNED NOT NULL"
            ");"
        )

    def _client(self, user: str, password: str, sql: str, *, database: str = ""):
        script = (
            'IFS= read -r HB_USER; IFS= read -r HB_PASSWORD; '
            'MYSQL_PWD="$HB_PASSWORD" exec mysql --protocol=socket '
            '--batch --raw --skip-column-names -u"$HB_USER"'
        )
        if database:
            if not re.fullmatch(r"[A-Za-z0-9_]+", database):
                raise RuntimeError("invalid_database_name")
            script += " " + database
        payload = user + "\n" + password + "\n" + sql + "\n"
        return subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-lc", script],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=12,
        )

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self._client("root", self.password, "SELECT 1;").returncode == 0:
                return
            time.sleep(0.25)
        raise RuntimeError("mysql_readiness_failed")

    def sql(self, sql: str, *, user: str = "root", password: str | None = None, database: str = ""):
        return self._client(user, self.password if password is None else password, sql, database=database)

    def login(self, user: str, password: str) -> bool:
        result = self.sql("SELECT 1;", user=user, password=password, database="app")
        return result.returncode == 0 and result.stdout.strip() == "1"

    def stop(self) -> None:
        if self.created and self.running:
            subprocess.run(
                ["docker", "stop", "-t", "1", self.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            self.running = False

    def restart(self) -> None:
        if not self.created:
            raise RuntimeError("mysql_container_not_created")
        if self.running:
            self.stop()
        result = subprocess.run(
            ["docker", "start", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError("mysql_container_restart_failed")
        self.running = True
        self._wait_ready()

    def destroy(self) -> None:
        if not self.created:
            return
        subprocess.run(
            ["docker", "rm", "-f", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        self.running = False
        self.created = False


def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_plugin(instance: smoke.Instance, root: Path, provider: MySqlContainer) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker_missing")
    wrapper = root / "mysql-sandbox-wrapper.py"
    plugin = root / "mysql-plugin.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="mysql_database_profile" or v("--heptabao-protocol")!="1":
    raise SystemExit(64)
if v("--heptabao-operation") not in ("read","issue","renew","revoke"):
    raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""",
    )
    plugin_sha = make_exec(
        plugin,
        f"""#!{sys.executable}
import json,re,struct,subprocess,sys

DOCKER={docker!r}
CONTAINER={provider.name!r}

def emit(value):
    payload=json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(payload))+payload)

def sql(user,password,text,database=""):
    if not re.fullmatch(r"[A-Za-z0-9_]+",user):
        raise SystemExit(70)
    if database and not re.fullmatch(r"[A-Za-z0-9_]+",database):
        raise SystemExit(70)
    script='IFS= read -r HB_USER; IFS= read -r HB_PASSWORD; MYSQL_PWD="$HB_PASSWORD" exec mysql --protocol=socket --batch --raw --skip-column-names -u"$HB_USER"'
    if database:
        script+=" "+database
    result=subprocess.run(
        [DOCKER,"exec","-i",CONTAINER,"sh","-lc",script],
        input=user+"\\n"+password+"\\n"+text+"\\n",
        text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,
    )
    if result.returncode:
        raise SystemExit(71)
    return result.stdout.strip()

raw=sys.stdin.buffer.read(1048588)
if len(raw)<11 or raw[:4]!=b"HBP1" or raw[4:6]!=b"\\x00\\x01":
    raise SystemExit(65)
op=raw[6]
size=struct.unpack(">I",raw[7:11])[0]
if size==0 or len(raw)!=11+size:
    raise SystemExit(65)
request=json.loads(raw[11:].decode())
if not isinstance(request,dict):
    raise SystemExit(65)
manager=request.get("manager_username")
manager_password=request.get("manager_password")
if manager!="root" or not isinstance(manager_password,str) or not re.fullmatch(r"[0-9a-f]{{48}}",manager_password):
    raise SystemExit(66)
action=request.get("action")
if op==1:
    if action!="configure" or sql(manager,manager_password,"SELECT CURRENT_USER();").split("@",1)[0]!="root":
        raise SystemExit(67)
    sql(manager,manager_password,
        "CREATE DATABASE IF NOT EXISTS heptabao_provider;"
        "CREATE TABLE IF NOT EXISTS heptabao_provider.fences("
        "provider_id VARCHAR(80) PRIMARY KEY,seq BIGINT UNSIGNED NOT NULL,"
        "request_digest CHAR(64) NOT NULL,username VARCHAR(96) NOT NULL,"
        "active BOOLEAN NOT NULL,expires BIGINT UNSIGNED NOT NULL);")
    emit({{"configured":True,"manager_identity":"root"}})
    raise SystemExit(0)

expected={{"issue":3,"renew":4,"revoke":5}}
if expected.get(action)!=op:
    raise SystemExit(67)
provider_id=request.get("provider_id")
username=request.get("username")
password=request.get("password")
role=request.get("provider_role")
seq=request.get("seq")
digest=request.get("request_digest")
expires=request.get("expires")
if not isinstance(provider_id,str) or not re.fullmatch(r"hb1:[0-9a-f]{{64}}",provider_id):
    raise SystemExit(68)
if not isinstance(username,str) or not re.fullmatch(r"hbp_[0-9a-f]+",username):
    raise SystemExit(68)
if not isinstance(seq,int) or seq<=0 or not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{{64}}",digest):
    raise SystemExit(68)
if not isinstance(expires,int) or expires<0 or role not in ("readonly","readwrite"):
    raise SystemExit(68)
if action=="revoke":
    if expires!=0:
        raise SystemExit(68)
elif expires<=0:
    raise SystemExit(68)
if action=="issue" and (not isinstance(password,str) or not re.fullmatch(r"[0-9a-f]{{64}}",password)):
    raise SystemExit(68)

def q(value):
    return "'" + value.replace("'","''") + "'"

# Prove a provider outage before any mutating statement. A bounded no-effect
# receipt keeps the plugin host active while the durable lease intent remains
# pending, so an explicit reconcile can safely re-enter after provider recovery.
probe_script='IFS= read -r HB_USER; IFS= read -r HB_PASSWORD; MYSQL_PWD="$HB_PASSWORD" exec mysql --protocol=socket --batch --raw --skip-column-names -u"$HB_USER"'
probe=subprocess.run(
    [DOCKER,"exec","-i",CONTAINER,"sh","-lc",probe_script],
    input=manager+"\\n"+manager_password+"\\nSELECT 1;\\n",
    text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,
)
if probe.returncode:
    emit({{
        "applied":False,
        "provider_id":provider_id,
        "seq":seq,
        "request_digest":digest,
        "username":username,
        "active":action!="revoke",
        "expires":expires,
    }})
    raise SystemExit(0)

previous=sql(manager,manager_password,
    "SELECT CONCAT(seq,'|',request_digest,'|',username,'|',active,'|',expires) "
    "FROM heptabao_provider.fences WHERE provider_id="+q(provider_id)+";")
if previous:
    fields=previous.split("|")
    if len(fields)!=5:
        raise SystemExit(69)
    old_seq=int(fields[0])
    if seq<old_seq or (seq==old_seq and digest!=fields[1]):
        raise SystemExit(69)

if action=="issue":
    sql(manager,manager_password,"CREATE USER IF NOT EXISTS "+q(username)+"@'%' IDENTIFIED BY "+q(password)+";")
    sql(manager,manager_password,"ALTER USER "+q(username)+"@'%' IDENTIFIED BY "+q(password)+";")
    sql(manager,manager_password,"REVOKE ALL PRIVILEGES, GRANT OPTION FROM "+q(username)+"@'%';")
    grant="SELECT" if role=="readonly" else "SELECT,INSERT,UPDATE,DELETE"
    sql(manager,manager_password,"GRANT "+grant+" ON app.* TO "+q(username)+"@'%';")
    active=True
elif action=="renew":
    if not previous or fields[2]!=username or fields[3]!="1":
        raise SystemExit(69)
    active=True
else:
    sql(manager,manager_password,"DROP USER IF EXISTS "+q(username)+"@'%';")
    active=False

sql(manager,manager_password,
    "INSERT INTO heptabao_provider.fences(provider_id,seq,request_digest,username,active,expires) VALUES("+
    q(provider_id)+","+str(seq)+","+q(digest)+","+q(username)+","+("1" if active else "0")+","+str(expires)+") "
    "ON DUPLICATE KEY UPDATE seq=VALUES(seq),request_digest=VALUES(request_digest),"
    "username=VALUES(username),active=VALUES(active),expires=VALUES(expires);")
observed=sql(manager,manager_password,
    "SELECT CONCAT(seq,'|',request_digest,'|',username,'|',active,'|',expires) "
    "FROM heptabao_provider.fences WHERE provider_id="+q(provider_id)+";")
expected_observed=str(seq)+"|"+digest+"|"+username+"|"+("1" if active else "0")+"|"+str(expires)
if observed!=expected_observed:
    raise SystemExit(69)
user_count=sql(manager,manager_password,
    "SELECT COUNT(*) FROM mysql.user WHERE user="+q(username)+";")
if (active and user_count!="1") or ((not active) and user_count!="0"):
    raise SystemExit(69)
emit({{
    "applied":True,
    "provider_id":provider_id,
    "seq":seq,
    "request_digest":digest,
    "username":username,
    "active":active,
    "expires":expires,
}})
""",
    )
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["plugin_database"] = [
        {
            "id": "mysql_fixture",
            "command": str(plugin),
            "command_sha256": plugin_sha,
            "sandbox_provider_id": "fixture_sandbox",
            "sandbox_command": str(wrapper),
            "sandbox_command_sha256": wrapper_sha,
            "sandbox_profile_id": "mysql_database_profile",
            "maximum_request_bytes": 262144,
            "maximum_response_bytes": 262144,
            "timeout_ms": 12000,
        }
    ]
    config["lifecycle_interval_seconds"] = 1
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)


def run(binary: Path, root: Path, output: Path) -> int:
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    provider = MySqlContainer(root / "mysql")
    instance = smoke.Instance(binary, root / "server")
    key = ""

    def check(name: str, condition: bool) -> None:
        checks.append({"case": name, "passed": bool(condition)})
        if condition is not True:
            raise RuntimeError(name)

    try:
        provider.start_fresh()
        check("real_mysql_8_4_ready", provider.sql("SELECT VERSION();").returncode == 0)
        provider.sql("INSERT INTO app.items(id,value) VALUES(1,'seed');")
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
            "plugin_name": "mysql_fixture",
            "connection_url": "mysql://fixture/app",
            "username": "root",
            "password": provider.password,
            "allowed_roles": ["readonly", "readwrite"],
            "verify_connection": True,
        }
        check(
            "mysql_plugin_configuration_readback",
            instance.call("POST", "database/config/mysql", config)[0] == 204
            and instance.call("GET", "database/config/mysql")[0] == 200,
        )
        check(
            "readonly_role",
            instance.call(
                "POST",
                "database/roles/readonly",
                {
                    "db_name": "mysql",
                    "provider_role": "readonly",
                    "default_ttl": 30,
                    "max_ttl": 180,
                },
            )[0]
            == 204,
        )
        check(
            "readwrite_role",
            instance.call(
                "POST",
                "database/roles/readwrite",
                {
                    "db_name": "mysql",
                    "provider_role": "readwrite",
                    "default_ttl": 30,
                    "max_ttl": 180,
                },
            )[0]
            == 204,
        )

        status, issued = instance.call("GET", "database/creds/readonly")
        check("mysql_readonly_issue_reaches_provider", status == 200)
        ro = issued["data"]
        ro_lease = issued["lease_id"]
        selected = provider.sql(
            "SELECT value FROM items WHERE id=1;",
            user=ro["username"],
            password=ro["password"],
            database="app",
        )
        check("mysql_readonly_select_succeeds", selected.returncode == 0 and selected.stdout.strip() == "seed")
        denied = provider.sql(
            "INSERT INTO items(id,value) VALUES(2,'denied');",
            user=ro["username"],
            password=ro["password"],
            database="app",
        )
        check("mysql_readonly_write_denied", denied.returncode != 0)

        status, writer = instance.call("GET", "database/creds/readwrite")
        check("issue_readwrite", status == 200)
        rw = writer["data"]
        matrix = provider.sql(
            "INSERT INTO items(id,value) VALUES(2,'a');"
            "UPDATE items SET value='b' WHERE id=2;"
            "DELETE FROM items WHERE id=2;"
            "SELECT COUNT(*) FROM items WHERE id=2;",
            user=rw["username"],
            password=rw["password"],
            database="app",
        )
        check(
            "mysql_readwrite_statement_matrix",
            matrix.returncode == 0 and matrix.stdout.strip().endswith("0"),
        )
        rollback = provider.sql(
            "START TRANSACTION;"
            "INSERT INTO items(id,value) VALUES(3,'rollback');"
            "ROLLBACK;"
            "SELECT COUNT(*) FROM items WHERE id=3;",
            user=rw["username"],
            password=rw["password"],
            database="app",
        )
        check(
            "mysql_transaction_rollback_is_observed",
            rollback.returncode == 0 and rollback.stdout.strip().endswith("0"),
        )
        status, renewed = instance.call(
            "POST", "sys/leases/renew", {"lease_id": ro_lease, "increment": 60}
        )
        check(
            "mysql_dynamic_credential_renew_reaches_provider",
            status == 200 and renewed.get("renewable") is True,
        )

        provider.restart()
        check(
            "mysql_provider_state_survives_restart",
            provider.login(ro["username"], ro["password"]),
        )
        instance.stop()
        instance.start()
        check("restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check(
            "mysql_service_state_survives_restart",
            instance.call("GET", "database/config/mysql")[0] == 200,
        )
        check(
            "mysql_revoke_removes_provider_login",
            instance.call("POST", "sys/leases/revoke", {"lease_id": ro_lease})[0] == 204
            and not provider.login(ro["username"], ro["password"]),
        )

        status, outage = instance.call("GET", "database/creds/readwrite")
        check("outage_seed", status == 200)
        outage_lease = outage["lease_id"]
        outage_cred = outage["data"]
        check("outage_user_live", provider.login(outage_cred["username"], outage_cred["password"]))
        provider.stop()
        status, body = instance.call(
            "POST", "sys/leases/revoke", {"lease_id": outage_lease}
        )
        check(
            "mysql_outage_retains_revoke_intent",
            status == 503
            and body.get("reconcile_required") is True
            and "data" not in body,
        )
        provider.restart()
        reconcile_deadline = time.monotonic() + 12
        status = 503
        while time.monotonic() < reconcile_deadline:
            status, body = instance.call(
                "POST", "sys/leases/reconcile/" + outage_lease, {}
            )
            if status == 204:
                break
            errors = body.get("errors", [])
            in_flight = (
                status == 503
                and body.get("reconcile_required") is True
                and any("already in flight" in str(error) for error in errors)
            )
            if not in_flight:
                break
            time.sleep(0.1)
        check(
            "mysql_restart_reconciles_pending_revoke",
            status == 204
            and not provider.login(outage_cred["username"], outage_cred["password"]),
        )

        passed = {item["case"] for item in checks if item["passed"]}
        missing = sorted(set(CORPUS_CASE_IDS) - passed)
        if missing:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing))
        report = {
            "schema": "heptabao.mysql-bounded-live.v1",
            "status": "passed",
            "checks": checks,
            "provider_image": IMAGE,
            "real_mysql_provider": True,
            "dynamic_credentials": True,
            "statement_matrix": True,
            "transaction_rollback": True,
            "provider_restart": True,
            "service_restart": True,
            "outage_reconciliation": True,
            "full_openbao_mysql_compatibility": False,
            "static_roles": False,
            "root_rotation": False,
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
        output.write_text(
            json.dumps(
                {
                    "schema": "heptabao.mysql-bounded-live.v1",
                    "status": "failed",
                    "checks": checks,
                    "safe_error": type(error).__name__,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
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
    if not MySqlContainer.available():
        print("BLOCKED: docker is required for real MySQL provider qualification", file=sys.stderr)
        return 77
    if not MySqlContainer.image_present():
        print("BLOCKED: pinned MySQL 8.4 image is not present; pull it explicitly", file=sys.stderr)
        return 77
    try:
        return run(args.binary.resolve(), args.work_dir.resolve(), args.output.resolve())
    except FileExistsError:
        print("mysql live failed: private work directory already exists", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
