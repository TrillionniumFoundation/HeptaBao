#!/usr/bin/env python3
"""Bounded LDAP mount profile acceptance.

Exercises the durable mount/config/login contract using the candidate's local
directory fixture. It intentionally does not claim an external LDAP server
bind/search; that remains an independent provider qualification gate.
"""
from __future__ import annotations
import argparse, json, tempfile
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--binary", required=True); ap.add_argument("--output", required=True)
    a = ap.parse_args(); checks=[]; root=Path(tempfile.mkdtemp(prefix="heptabao-ldap-")); ins=Instance(a.binary, root)
    def check(name, ok): checks.append({"case":name,"passed":bool(ok)}); return ok
    try:
        ins.start(); status, init = ins.call("POST", "sys/init", {"secret_shares":1,"secret_threshold":1}); check("initialize", status == 200)
        key=init["keys_base64"][0]; ins.token=init["root_token"]; check("unseal", ins.call("POST","sys/unseal",{"key":key})[0] == 200)
        check("mount", ins.call("POST","sys/auth/ldap",{"type":"ldap"})[0] == 204)
        cfg={"url":"ldaps://directory.example.test","bind_dn":"cn=heptabao,dc=example,dc=test","user_dn_template":"uid={{username}},ou=people,dc=example,dc=test","starttls":False}
        check("config", ins.call("POST","auth/ldap/config",cfg)[0] == 204)
        check("config_roundtrip", ins.call("GET","auth/ldap/config",{})[1].get("url") == cfg["url"])
        check("user_fixture", ins.call("PUT","auth/ldap/users/alice",{"password":"correct horse battery staple"})[0] == 204)
        login=ins.call("POST","auth/ldap/login/alice",{"password":"correct horse battery staple"}); check("login", login[0] == 200 and bool(login[1].get("auth",{}).get("client_token")))
        check("revocation", ins.call("DELETE", "auth/ldap/users/alice", {})[0] == 204 and ins.call("POST", "auth/ldap/login/alice", {"password":"correct horse battery staple"})[0] >= 400)
        check("filter_injection_rejected", ins.call("PUT","auth/ldap/config",{"url":"ldap://directory.test/??(|(uid=*))","bind_dn":"cn=x","user_dn_template":"uid={{username}}"})[0] >= 400)
        report={"status":"passed" if all(c["passed"] for c in checks) else "failed","checks":checks,"external_ldap_bind_executed":False,"independent_qualification":False}
        Path(a.output).write_text(json.dumps(report,indent=2)); return 0 if report["status"] == "passed" else 1
    finally:
        ins.stop()
if __name__ == "__main__": raise SystemExit(main())
