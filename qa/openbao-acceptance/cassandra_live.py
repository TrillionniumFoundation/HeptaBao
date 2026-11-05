#!/usr/bin/env python3
"""Real Cassandra 5.0 provider acceptance through the checksum-bound database plugin."""
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

IMAGE = "cassandra@sha256:ee178b38a2746a8e15a115bd038ad1f864391d04a84162a018cb0dd79511709a"
CORPUS_CASE_IDS = (
    "real_cassandra_5_ready",
    "cassandra_plugin_configuration_readback",
    "cassandra_readonly_issue_reaches_provider",
    "cassandra_readonly_select_succeeds",
    "cassandra_readonly_write_denied",
    "cassandra_readwrite_mutation_succeeds",
    "cassandra_dynamic_credential_renew_reaches_provider",
    "cassandra_provider_state_survives_restart",
    "cassandra_service_state_survives_restart",
    "cassandra_revoke_removes_provider_login",
    "cassandra_outage_retains_revoke_intent",
    "cassandra_restart_reconciles_pending_revoke",
)


class CassandraContainer:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = "heptabao-cassandra-" + secrets.token_hex(8)
        self.running = False
        self.created = False

    @staticmethod
    def available() -> bool:
        return shutil.which("docker") is not None

    @staticmethod
    def image_present() -> bool:
        return subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0

    def start_fresh(self) -> None:
        result = subprocess.run(
            [
                "docker", "run", "-d", "--name", self.name,
                "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m",
                IMAGE,
                "bash", "-lc",
                "sed -ri 's/^authenticator:.*/authenticator: PasswordAuthenticator/' /etc/cassandra/cassandra.yaml; "
                "sed -ri 's/^authorizer:.*/authorizer: CassandraAuthorizer/' /etc/cassandra/cassandra.yaml; "
                "exec gosu cassandra /opt/cassandra/bin/cassandra -f",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=45,
        )
        if result.returncode != 0:
            raise RuntimeError("cassandra_container_start_failed")
        self.created = True
        self.running = True
        self._wait_ready()
        self.cql(
            "CREATE KEYSPACE IF NOT EXISTS app WITH replication = "
            "{'class':'SimpleStrategy','replication_factor':1};"
            "CREATE TABLE IF NOT EXISTS app.items(id int PRIMARY KEY, value text);"
            "CREATE KEYSPACE IF NOT EXISTS heptabao_provider WITH replication = "
            "{'class':'SimpleStrategy','replication_factor':1};"
            "CREATE TABLE IF NOT EXISTS heptabao_provider.fences("
            "provider_id text PRIMARY KEY, seq bigint, request_digest text, "
            "username text, active boolean, expires bigint);"
        )

    def _run_cql(self, user: str, password: str, sql: str) -> subprocess.CompletedProcess[str]:
        rc = "/tmp/heptabao-cqlshrc-" + str(os.getpid()) + "-" + secrets.token_hex(8)
        config = f"[authentication]\nusername = {user}\npassword = {password}\n"
        put = subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", 'umask 077; cat > "$1"', "sh", rc],
            input=config,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
        if put.returncode != 0:
            return subprocess.CompletedProcess([], put.returncode, "", "")
        try:
            return subprocess.run(
                ["docker", "exec", "-i", self.name, "cqlsh", "--cqlshrc=" + rc],
                input=sql + "\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            )
        finally:
            subprocess.run(
                ["docker", "exec", self.name, "rm", "-f", rc],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )

    def cql(self, sql: str, *, user: str = "cassandra", password: str = "cassandra"):
        result = self._run_cql(user, password, sql)
        if result.returncode != 0:
            raise RuntimeError("cassandra_cql_failed")
        return result

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            result = self._run_cql("cassandra", "cassandra", "SELECT release_version FROM system.local;")
            if result.returncode == 0 and "release_version" in result.stdout:
                return
            time.sleep(1)
        raise RuntimeError("cassandra_readiness_failed")

    def login(self, user: str, password: str) -> bool:
        result = self._run_cql(user, password, "SELECT release_version FROM system.local;")
        return result.returncode == 0 and "release_version" in result.stdout

    def wait_login(self, user: str, password: str, expected: bool, timeout: float = 12.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.login(user, password) is expected:
                return True
            time.sleep(0.5)
        return False

    def stop(self) -> None:
        if self.created and self.running:
            subprocess.run(
                ["docker", "stop", "-t", "1", self.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12,
            )
            self.running = False

    def restart(self) -> None:
        if not self.created:
            raise RuntimeError("cassandra_container_not_created")
        if self.running:
            self.stop()
        result = subprocess.run(
            ["docker", "start", self.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError("cassandra_container_restart_failed")
        self.running = True
        self._wait_ready()

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


def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_plugin(instance: smoke.Instance, root: Path, provider: CassandraContainer) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker_missing")
    wrapper = root / "cassandra-sandbox-wrapper.py"
    plugin = root / "cassandra-plugin.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="cassandra_database_profile" or v("--heptabao-protocol")!="1":
    raise SystemExit(64)
if v("--heptabao-operation") not in ("read","issue","renew","revoke"):
    raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""",
    )
    plugin_sha = make_exec(
        plugin,
        f"""#!{sys.executable}
import json,os,re,secrets,struct,subprocess,sys
DOCKER={docker!r}
CONTAINER={provider.name!r}
def emit(value):
    p=json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(p))+p)

def run_cql(user,password,sql):
    rc="/tmp/heptabao-cqlshrc-"+str(os.getpid())+"-"+secrets.token_hex(8)
    cfg="[authentication]\\nusername = "+user+"\\npassword = "+password+"\\n"
    put=subprocess.run([DOCKER,"exec","-i",CONTAINER,"sh","-c",'umask 077; cat > "$1"',"sh",rc],
        input=cfg,text=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
    if put.returncode:
        return put
    try:
        return subprocess.run([DOCKER,"exec","-i",CONTAINER,"cqlsh","--cqlshrc="+rc],
            input=sql+"\\n",text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
    finally:
        subprocess.run([DOCKER,"exec",CONTAINER,"rm","-f",rc],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)

def cql(user,password,sql):
    r=run_cql(user,password,sql)
    if r.returncode: raise SystemExit(71)
    return r.stdout

def q(v):
    return "'" + v.replace("'","''") + "'"

raw=sys.stdin.buffer.read(1048588)
if len(raw)<11 or raw[:4]!=b"HBP1" or raw[4:6]!=b"\\x00\\x01": raise SystemExit(65)
op=raw[6]; n=struct.unpack(">I",raw[7:11])[0]
if n==0 or len(raw)!=11+n: raise SystemExit(65)
request=json.loads(raw[11:].decode())
if not isinstance(request,dict): raise SystemExit(65)
manager=request.get("manager_username"); manager_password=request.get("manager_password")
if manager!="cassandra" or manager_password!="cassandra": raise SystemExit(66)
action=request.get("action")
if op==1:
    if action!="configure" or run_cql(manager,manager_password,"SELECT release_version FROM system.local;").returncode:
        raise SystemExit(67)
    cql(manager,manager_password,
        "CREATE KEYSPACE IF NOT EXISTS heptabao_provider WITH replication = "
        "{{'class':'SimpleStrategy','replication_factor':1}};"
        "CREATE TABLE IF NOT EXISTS heptabao_provider.fences("
        "provider_id text PRIMARY KEY, seq bigint, request_digest text, username text, active boolean, expires bigint);")
    emit({{"configured":True,"manager_identity":"cassandra"}}); raise SystemExit(0)

expected={{"issue":3,"renew":4,"revoke":5}}
if expected.get(action)!=op: raise SystemExit(67)
provider_id=request.get("provider_id"); username=request.get("username")
password=request.get("password"); role=request.get("provider_role")
seq=request.get("seq"); digest=request.get("request_digest"); expires=request.get("expires")
if not isinstance(provider_id,str) or not re.fullmatch(r"hb1:[0-9a-f]{{64}}",provider_id): raise SystemExit(68)
if not isinstance(username,str) or not re.fullmatch(r"hbp_[0-9a-f]+",username): raise SystemExit(68)
if not isinstance(seq,int) or seq<=0 or not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{{64}}",digest): raise SystemExit(68)
if not isinstance(expires,int) or expires<0 or role not in ("readonly","readwrite"): raise SystemExit(68)
if action=="issue" and (not isinstance(password,str) or not re.fullmatch(r"[0-9a-f]{{64}}",password)): raise SystemExit(68)
if action=="revoke" and expires!=0: raise SystemExit(68)
if action!="revoke" and expires<=0: raise SystemExit(68)

probe=run_cql(
    manager,
    manager_password,
    "SELECT release_version FROM system.local;"
    "SELECT seq FROM heptabao_provider.fences WHERE provider_id="+q(provider_id)+";"
    "SELECT role FROM system_auth.roles WHERE role="+q(username)+";",
)
if probe.returncode:
    emit({{"applied":False,"provider_id":provider_id,"seq":seq,"request_digest":digest,
          "username":username,"active":action!="revoke","expires":expires}})
    raise SystemExit(0)

numbers=[int(v) for v in re.findall(r"(?m)^\\s*(\\d+)\\s*$",probe.stdout)]
if numbers and seq<numbers[-1]: raise SystemExit(69)
if action=="renew" and username not in probe.stdout: raise SystemExit(69)

fence=(
    "INSERT INTO heptabao_provider.fences(provider_id,seq,request_digest,username,active,expires) VALUES("+
    q(provider_id)+","+str(seq)+","+q(digest)+","+q(username)+","+
    ("false" if action=="revoke" else "true")+","+str(expires)+");"
)
if action=="issue":
    permission="SELECT" if role=="readonly" else "SELECT, MODIFY"
    mutation=(
        "CREATE ROLE IF NOT EXISTS "+q(username)+" WITH PASSWORD = "+q(password)+" AND LOGIN = true;"
        "GRANT "+permission+" ON KEYSPACE app TO "+q(username)+";"+
        fence
    )
    active=True
elif action=="renew":
    mutation=fence
    active=True
else:
    mutation="DROP ROLE IF EXISTS "+q(username)+";"+fence
    active=False

roles=cql(
    manager,
    manager_password,
    mutation+"SELECT role FROM system_auth.roles WHERE role="+q(username)+";",
)
if (active and username not in roles) or ((not active) and username in roles): raise SystemExit(69)
emit({{"applied":True,"provider_id":provider_id,"seq":seq,"request_digest":digest,
      "username":username,"active":active,"expires":expires}})
""",
    )
    path = instance.root / "server.json"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    cfg["plugin_database"] = [{
        "id": "cassandra_fixture",
        "command": str(plugin),
        "command_sha256": plugin_sha,
        "sandbox_provider_id": "fixture_sandbox",
        "sandbox_command": str(wrapper),
        "sandbox_command_sha256": wrapper_sha,
        "sandbox_profile_id": "cassandra_database_profile",
        "maximum_request_bytes": 262144,
        "maximum_response_bytes": 262144,
        "timeout_ms": 20000,
    }]
    cfg["lifecycle_interval_seconds"] = 1
    path.write_text(json.dumps(cfg), encoding="utf-8")
    path.chmod(0o600)


def run(binary: Path, root: Path, output: Path) -> int:
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    provider = CassandraContainer(root / "cassandra")
    instance = smoke.Instance(binary, root / "server")

    def check(name: str, condition: bool) -> None:
        checks.append({"case": name, "passed": bool(condition)})
        if condition is not True:
            raise RuntimeError(name)

    try:
        provider.start_fresh()
        check("real_cassandra_5_ready", "release_version" in provider.cql("SELECT release_version FROM system.local;").stdout)
        provider.cql("INSERT INTO app.items(id,value) VALUES(1,'seed');")
        configure_plugin(instance, root, provider)
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = init["root_token"]
        key = init["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("mount_database", instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204)
        cfg = {
            "plugin_name": "cassandra_fixture",
            "connection_url": "cassandra://fixture/app",
            "username": "cassandra",
            "password": "cassandra",
            "allowed_roles": ["readonly", "readwrite"],
            "verify_connection": True,
        }
        check(
            "cassandra_plugin_configuration_readback",
            instance.call("POST", "database/config/cassandra", cfg)[0] == 204
            and instance.call("GET", "database/config/cassandra")[0] == 200,
        )
        for name in ("readonly", "readwrite"):
            check(
                name + "_role",
                instance.call("POST", "database/roles/" + name, {
                    "db_name": "cassandra", "provider_role": name,
                    "default_ttl": 300, "max_ttl": 900,
                })[0] == 204,
            )

        status, issued = instance.call("GET", "database/creds/readonly")
        check("cassandra_readonly_issue_reaches_provider", status == 200)
        ro = issued["data"]
        ro_lease = issued["lease_id"]
        selected = provider._run_cql(ro["username"], ro["password"], "SELECT value FROM app.items WHERE id=1;")
        check("cassandra_readonly_select_succeeds", selected.returncode == 0 and "seed" in selected.stdout)
        denied = provider._run_cql(ro["username"], ro["password"], "INSERT INTO app.items(id,value) VALUES(2,'denied');")
        check("cassandra_readonly_write_denied", denied.returncode != 0)

        status, writer = instance.call("GET", "database/creds/readwrite")
        check("issue_readwrite", status == 200)
        rw = writer["data"]
        mutation = provider._run_cql(
            rw["username"], rw["password"],
            "INSERT INTO app.items(id,value) VALUES(2,'writer'); SELECT value FROM app.items WHERE id=2;",
        )
        check("cassandra_readwrite_mutation_succeeds", mutation.returncode == 0 and "writer" in mutation.stdout)
        status, renewed = instance.call("POST", "sys/leases/renew", {"lease_id": ro_lease, "increment": 600})
        check("cassandra_dynamic_credential_renew_reaches_provider", status == 200 and renewed.get("renewable") is True)

        provider.restart()
        check("cassandra_provider_state_survives_restart", provider.wait_login(ro["username"], ro["password"], True))
        instance.stop()
        instance.start()
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("cassandra_service_state_survives_restart", instance.call("GET", "database/config/cassandra")[0] == 200)
        check(
            "cassandra_revoke_removes_provider_login",
            instance.call("POST", "sys/leases/revoke", {"lease_id": ro_lease})[0] == 204
            and provider.wait_login(ro["username"], ro["password"], False),
        )

        status, outage = instance.call("GET", "database/creds/readwrite")
        check("outage_seed", status == 200)
        outage_lease = outage["lease_id"]
        outage_cred = outage["data"]
        provider.stop()
        status, body = instance.call("POST", "sys/leases/revoke", {"lease_id": outage_lease})
        check(
            "cassandra_outage_retains_revoke_intent",
            status == 503 and body.get("reconcile_required") is True and "data" not in body,
        )
        provider.restart()
        deadline = time.monotonic() + 30
        terminal = False
        while time.monotonic() < deadline:
            # The explicit request and the host lifecycle worker may race to
            # reconcile. A successful current revoke removes the durable lease;
            # older retained terminal rows report phase=Revoked. Require an
            # idempotent 204 plus either terminal representation.
            instance.call("POST", "sys/leases/reconcile/" + outage_lease, {})
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
            time.sleep(0.15)
        check(
            "cassandra_restart_reconciles_pending_revoke",
            terminal
            and provider.wait_login(
                outage_cred["username"], outage_cred["password"], False
            ),
        )

        passed = {item["case"] for item in checks if item["passed"]}
        missing = sorted(set(CORPUS_CASE_IDS) - passed)
        if missing:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing))
        report = {
            "schema": "heptabao.cassandra-bounded-live.v1",
            "status": "passed",
            "checks": checks,
            "provider_image": IMAGE,
            "real_cassandra_provider": True,
            "dynamic_credentials": True,
            "provider_restart": True,
            "service_restart": True,
            "outage_reconciliation": True,
            "network_partition_matrix": False,
            "full_openbao_cassandra_compatibility": False,
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
            "schema": "heptabao.cassandra-bounded-live.v1",
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
    p = argparse.ArgumentParser()
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--work-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not CassandraContainer.available() or not CassandraContainer.image_present():
        print(json.dumps({"status": "blocked", "reason": "pinned_cassandra_provider_unavailable"}))
        return 77
    return run(args.binary.resolve(), args.work_dir.resolve(), args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
