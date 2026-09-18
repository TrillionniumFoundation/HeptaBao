#!/usr/bin/env python3
"""Real Service -> checksum-bound sandbox -> authentication plugin -> local token."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure(instance: smoke.Instance, root: Path):
    count = root / "auth-plugin-invocations.txt"
    wrapper = root / "auth-sandbox-wrapper.py"
    plugin = root / "auth-plugin.py"
    wrapper_sha = make_exec(
        wrapper,
        f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="auth_profile" or v("--heptabao-protocol")!="1" or v("--heptabao-operation")!="read": raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""",
    )
    plugin_sha = make_exec(
        plugin,
        f"""#!{sys.executable}
import json,struct,sys
r=sys.stdin.buffer.read(1048588)
if len(r)<11 or r[:4]!=b"HBP1" or r[4:6]!=b"\\x00\\x01" or r[6]!=1: raise SystemExit(65)
n=struct.unpack(">I",r[7:11])[0]
if n==0 or len(r)!=11+n: raise SystemExit(65)
q=json.loads(r[11:].decode())
with open({str(count)!r},"a",encoding="utf-8") as f: f.write("1\\n")
d=q.get("data",{{}})
ok=d.get("password")=="correct" and isinstance(d.get("username"),str)
p=json.dumps({{"authenticated":ok,**({{"alias":d["username"]}} if ok else {{}})}},sort_keys=True).encode()
sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(p))+p)
""",
    )
    p = instance.root / "server.json"
    c = json.loads(p.read_text())
    c["plugin_auth"] = [
        {
            "id": "auth_fixture",
            "command": str(plugin),
            "command_sha256": plugin_sha,
            "sandbox_provider_id": "fixture_sandbox",
            "sandbox_command": str(wrapper),
            "sandbox_command_sha256": wrapper_sha,
            "sandbox_profile_id": "auth_profile",
            "maximum_request_bytes": 262144,
            "maximum_response_bytes": 262144,
            "timeout_ms": 5000,
        }
    ]
    p.write_text(json.dumps(c))
    p.chmod(0o600)
    return plugin, count, plugin_sha


def run(binary: Path, root: Path):
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    instance = smoke.Instance(binary, root / "server")
    plugin, count, plugin_sha = configure(instance, root)
    passed = []

    def ck(name, condition):
        if not condition:
            raise RuntimeError(name)
        passed.append(name)

    try:
        instance.start()
        status, body = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        ck("init", status == 200)
        instance.token = body["root_token"]
        key = body["keys_base64"][0]
        ck("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)

        status, body = instance.call("LIST", "sys/plugins/catalog/auth")
        ck(
            "catalog_list",
            status == 200 and body.get("data", {}).get("keys") == ["auth_fixture"],
        )
        status, body = instance.call(
            "GET", "sys/plugins/catalog/auth/auth_fixture"
        )
        ck(
            "catalog_read",
            status == 200
            and body.get("data", {}).get("type") == "auth"
            and body["data"].get("sha256") == plugin_sha,
        )

        ck(
            "mount",
            instance.call(
                "POST",
                "sys/auth/external",
                {"type": "plugin", "description": "fixture"},
            )[0]
            == 204,
        )
        ck(
            "policy",
            instance.call(
                "POST",
                "sys/policies/acl/plugin-user",
                {
                    "policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'
                },
            )[0]
            == 204,
        )
        ck(
            "config",
            instance.call(
                "POST",
                "auth/external/config",
                {
                    "plugin_id": "auth_fixture",
                    "policies": ["plugin-user"],
                    "token_ttl": "1h",
                    "token_max_ttl": "2h",
                },
            )[0]
            == 204,
        )

        before = count.read_text().count("\n") if count.exists() else 0
        status, _ = instance.call(
            "POST",
            "auth/external/login",
            {"username": "alice", "password": "wrong"},
            token="",
        )
        ck("denied", status == 403 and count.read_text().count("\n") == before + 1)

        status, body = instance.call(
            "POST",
            "auth/external/login",
            {"username": "alice", "password": "correct"},
            token="",
        )
        ck(
            "login",
            status == 200
            and isinstance(body.get("auth", {}).get("client_token"), str),
        )
        issued = body["auth"]["client_token"]
        ck(
            "server_owned_policy",
            set(body["auth"].get("token_policies", []))
            == {"default", "plugin-user"},
        )
        ck(
            "lookup_self",
            instance.call("GET", "auth/token/lookup-self", token=issued)[0] == 200,
        )

        instance.stop()
        instance.start()
        ck(
            "restart_unseal",
            instance.call("POST", "sys/unseal", {"key": key})[0] == 200,
        )
        status, body = instance.call(
            "POST",
            "auth/external/login",
            {"username": "alice", "password": "correct"},
            token="",
        )
        ck("restart_login", status == 200)
        issued_after_restart = body["auth"]["client_token"]

        before = count.read_text().count("\n")
        with plugin.open("a", encoding="utf-8") as handle:
            handle.write("\n#mutated\n")
        ck(
            "digest_fence",
            instance.call(
                "POST",
                "auth/external/login",
                {"username": "alice", "password": "correct"},
                token="",
            )[0]
            == 503
            and count.read_text().count("\n") == before,
        )

        ck(
            "disable_mount",
            instance.call("DELETE", "sys/auth/external", {})[0] == 204,
        )
        ck(
            "issued_token_revoked_on_disable",
            instance.call(
                "GET", "auth/token/lookup-self", token=issued_after_restart
            )[0]
            == 403,
        )

        print(
            json.dumps(
                {
                    "status": "passed",
                    "checks": passed,
                    "plugin_authority": "authentication_only",
                    "server_owns_policies": True,
                    "openbao_plugin_rpc_compatibility": False,
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
        print(
            "plugin auth live failed: " + type(error).__name__,
            file=sys.stderr,
        )
        raise SystemExit(1)
