#!/usr/bin/env python3
"""Real Service -> checksum-bound database plugin -> durable dynamic lease lifecycle."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


CORPUS_CASE_IDS = (
    "catalog_lists_admitted_database_plugin",
    "unknown_database_plugin_config_fails_closed",
    "database_plugin_configuration_readback",
    "dynamic_credential_issue_reaches_plugin",
    "issued_secret_matches_plugin_digest",
    "dynamic_credential_renew_reaches_plugin",
    "database_plugin_binding_survives_service_restart",
    "changed_plugin_executable_is_fenced_before_revoke",
    "digest_fence_does_not_claim_external_revoke",
    "restored_plugin_completes_pending_revoke",
    "revoked_plugin_credential_is_inactive",
)


def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure(instance: smoke.Instance, root: Path):
    provider_state = root / "database-plugin-state.json"
    fingerprint_key = os.urandom(32)
    wrapper = root / "database-sandbox-wrapper.py"
    plugin = root / "database-plugin.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="database_profile" or v("--heptabao-protocol")!="1":
    raise SystemExit(64)
if v("--heptabao-operation") not in ("read","issue","renew","revoke"):
    raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""",
    )
    plugin_sha = make_exec(
        plugin,
        f"""#!{sys.executable}
import hashlib,hmac,json,os,struct,sys
STATE={str(provider_state)!r}
FINGERPRINT_KEY={fingerprint_key!r}
r=sys.stdin.buffer.read(1048588)
if len(r)<11 or r[:4]!=b"HBP1" or r[4:6]!=b"\\x00\\x01":
    raise SystemExit(65)
op=r[6]
n=struct.unpack(">I",r[7:11])[0]
if n==0 or len(r)!=11+n:
    raise SystemExit(65)
q=json.loads(r[11:].decode())
if not isinstance(q,dict):
    raise SystemExit(65)
if q.get("manager_username")!="manager" or q.get("manager_password")!="manager-password":
    raise SystemExit(66)
state={{}}
if os.path.exists(STATE):
    with open(STATE,"r",encoding="utf-8") as f:
        state=json.load(f)
def emit(value):
    p=json.dumps(value,sort_keys=True,separators=(",",":")).encode()
    sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(p))+p)
if op==1:
    if q.get("action")!="configure":
        raise SystemExit(67)
    emit({{"configured":True,"manager_identity":"manager"}})
    raise SystemExit(0)
expected={{"issue":3,"renew":4,"revoke":5}}
action=q.get("action")
if expected.get(action)!=op:
    raise SystemExit(67)
provider=q.get("provider_id")
username=q.get("username")
seq=q.get("seq")
digest=q.get("request_digest")
expires=q.get("expires")
if not isinstance(provider,str) or not provider.startswith("hb1:") or len(provider)!=68:
    raise SystemExit(68)
if not isinstance(username,str) or not username.startswith("hbp_"):
    raise SystemExit(68)
if not isinstance(seq,int) or seq<=0 or not isinstance(digest,str) or len(digest)!=64:
    raise SystemExit(68)
if action=="issue":
    password=q.get("password")
    if not isinstance(password,str) or len(password)!=64:
        raise SystemExit(68)
    if state and (
        state.get("provider_id")!=provider
        or state.get("username")!=username
        or state.get("seq")!=seq
        or state.get("request_digest")!=digest
    ):
        raise SystemExit(69)
    state={{
        "provider_id":provider,
        "username":username,
        "seq":seq,
        "request_digest":digest,
        "expires":expires,
        "active":True,
        "password_hmac_sha256":hmac.new(FINGERPRINT_KEY,password.encode(),hashlib.sha256).hexdigest(),
    }}
elif action=="renew":
    if (
        state.get("provider_id")!=provider
        or state.get("username")!=username
        or state.get("active") is not True
        or seq<=int(state.get("seq",0))
    ):
        raise SystemExit(69)
    state["seq"]=seq
    state["request_digest"]=digest
    state["expires"]=expires
elif action=="revoke":
    if (
        state.get("provider_id")!=provider
        or state.get("username")!=username
        or seq<=int(state.get("seq",0))
    ):
        raise SystemExit(69)
    state["seq"]=seq
    state["request_digest"]=digest
    state["expires"]=expires
    state["active"]=False
tmp=STATE+".tmp"
with open(tmp,"w",encoding="utf-8") as f:
    json.dump(state,f,sort_keys=True)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp,STATE)
emit({{
    "applied":True,
    "provider_id":provider,
    "seq":seq,
    "request_digest":digest,
    "username":username,
    "active":state["active"],
    "expires":expires,
}})
""",
    )
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    config["plugin_database"] = [
        {
            "id": "database_fixture",
            "command": str(plugin),
            "command_sha256": plugin_sha,
            "sandbox_provider_id": "fixture_sandbox",
            "sandbox_command": str(wrapper),
            "sandbox_command_sha256": wrapper_sha,
            "sandbox_profile_id": "database_profile",
            "maximum_request_bytes": 262144,
            "maximum_response_bytes": 262144,
            "timeout_ms": 5000,
        }
    ]
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    return plugin, provider_state, plugin.read_bytes(), plugin_sha, fingerprint_key


def run(binary: Path, root: Path):
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    instance = smoke.Instance(binary, root / "server")
    plugin, provider_state, original_plugin, plugin_sha, fingerprint_key = configure(
        instance, root
    )
    passed = []

    def check(name, condition):
        if condition is not True:
            raise RuntimeError(name)
        passed.append(name)

    try:
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)

        status, body = instance.call("LIST", "sys/plugins/catalog/database")
        check(
            "catalog_lists_admitted_database_plugin",
            status == 200 and body.get("data", {}).get("keys") == ["database_fixture"],
        )
        status, body = instance.call(
            "GET", "sys/plugins/catalog/database/database_fixture"
        )
        check(
            "catalog_read_is_checksum_bound",
            status == 200
            and body.get("data", {}).get("type") == "database"
            and body["data"].get("sha256") == plugin_sha
            and body["data"].get("state") == "active",
        )

        check(
            "mount_database",
            instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204,
        )
        unknown = {
            "plugin_name": "not_admitted",
            "connection_url": "plugin://fixture",
            "username": "manager",
            "password": "manager-password",
            "allowed_roles": ["reader"],
            "verify_connection": True,
        }
        check(
            "unknown_database_plugin_config_fails_closed",
            instance.call("POST", "database/config/unknown", unknown)[0] == 400,
        )
        check(
            "unknown_database_plugin_config_absent",
            instance.call("GET", "database/config/unknown")[0] == 404,
        )

        config = dict(unknown)
        config["plugin_name"] = "database_fixture"
        check(
            "database_plugin_configuration_readback",
            instance.call("POST", "database/config/local", config)[0] == 204,
        )
        status, body = instance.call("GET", "database/config/local")
        check(
            "database_plugin_configuration_persisted",
            status == 200
            and body.get("data", {}).get("plugin_name") == "database_fixture",
        )
        check(
            "database_plugin_role",
            instance.call(
                "POST",
                "database/roles/reader",
                {
                    "db_name": "local",
                    "provider_role": "reader",
                    "default_ttl": 60,
                    "max_ttl": 600,
                },
            )[0]
            == 204,
        )

        status, issued = instance.call("GET", "database/creds/reader")
        check("dynamic_credential_issue_reaches_plugin", status == 200)
        lease_id = issued["lease_id"]
        credential = issued["data"]
        provider = json.loads(provider_state.read_text())
        check(
            "issued_secret_matches_plugin_digest",
            provider.get("active") is True
            and provider.get("username") == credential["username"]
            and provider.get("password_hmac_sha256")
            == hmac.new(
                fingerprint_key,
                credential["password"].encode(),
                hashlib.sha256,
            ).hexdigest(),
        )
        issue_seq = provider["seq"]

        status, renewed = instance.call(
            "POST", "sys/leases/renew", {"lease_id": lease_id, "increment": 120}
        )
        check(
            "dynamic_credential_renew_reaches_plugin",
            status == 200 and renewed.get("lease_id") == lease_id,
        )
        provider = json.loads(provider_state.read_text())
        check(
            "renew_advances_exact_plugin_generation",
            provider["seq"] > issue_seq and provider.get("active") is True,
        )

        instance.stop()
        instance.start()
        check(
            "restart_unseal",
            instance.call("POST", "sys/unseal", {"key": key})[0] == 200,
        )
        status, lookup = instance.call(
            "POST", "sys/leases/lookup", {"lease_id": lease_id}
        )
        check(
            "database_plugin_binding_survives_service_restart",
            status == 200 and lookup.get("data", {}).get("id") == lease_id,
        )

        with plugin.open("ab") as handle:
            handle.write(b"\n# mutated after deployment admission\n")
        status, body = instance.call(
            "POST", "sys/leases/revoke", {"lease_id": lease_id}
        )
        check(
            "changed_plugin_executable_is_fenced_before_revoke",
            status == 503
            and body.get("reconcile_required") is True
            and body.get("lease_id") == lease_id,
        )
        provider = json.loads(provider_state.read_text())
        check(
            "digest_fence_does_not_claim_external_revoke",
            provider.get("active") is True,
        )

        plugin.write_bytes(original_plugin)
        plugin.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        status, _ = instance.call(
            "POST", "sys/leases/reconcile/" + lease_id, {}
        )
        if status != 204:
            status, _ = instance.call(
                "POST", "sys/leases/revoke", {"lease_id": lease_id}
            )
        check("restored_plugin_completes_pending_revoke", status == 204)
        provider = json.loads(provider_state.read_text())
        check(
            "revoked_plugin_credential_is_inactive",
            provider.get("active") is False,
        )
        check(
            "revoked_lease_is_not_renewable",
            instance.call(
                "POST", "sys/leases/renew", {"lease_id": lease_id, "increment": 60}
            )[0]
            == 400,
        )

        missing = sorted(set(CORPUS_CASE_IDS) - set(passed))
        if missing:
            raise RuntimeError("corpus_case_missing:" + ",".join(missing))
        print(
            json.dumps(
                {
                    "status": "passed",
                    "checks": passed,
                    "openbao_plugin_rpc_compatibility": False,
                    "static_roles": False,
                    "root_rotation": False,
                    "database_plugin_dynamic_lifecycle": True,
                    "durable_authority": "heptabao_server_state",
                }
            )
        )
    finally:
        instance.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.binary.resolve(), args.work_dir.resolve())
    except Exception as error:
        print("plugin database live failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
