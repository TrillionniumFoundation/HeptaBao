#!/usr/bin/env python3
"""Run bounded LDAPS login against an actual host-installed OpenLDAP slapd."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, secrets, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"qa/single-node"))
from smoke import Instance

def port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def ssha(secret):
    salt=secrets.token_bytes(16)
    return "{SSHA}"+base64.b64encode(hashlib.sha1(secret.encode()+salt).digest()+salt).decode()
def private(path,text):
    path.write_text(text);path.chmod(0o600)

class Directory:
    def __init__(self,root,cert,key,ca):
        if any(shutil.which(x) is None for x in ("slapd","ldapadd")):raise FileNotFoundError
        self.root=root;root.mkdir(mode=0o700);(root/"db").mkdir(mode=0o700)
        self.port=port();self.origin=f"ldaps://localhost:{self.port}"
        self.admin_dn="cn=admin,dc=example,dc=test";self.admin_password=secrets.token_urlsafe(30)
        self.user_password=secrets.token_urlsafe(30)
        pw=root/"admin.pass";private(pw,self.admin_password+"\n")
        conf=root/"slapd.conf";private(conf,f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile {root}/slapd.pid
argsfile {root}/slapd.args
TLSCertificateFile {cert}
TLSCertificateKeyFile {key}
TLSCACertificateFile {ca}
modulepath /usr/lib/ldap
moduleload back_mdb
database mdb
maxsize 67108864
suffix "dc=example,dc=test"
rootdn "{self.admin_dn}"
rootpw {ssha(self.admin_password)}
directory {root/"db"}
""")
        self.conf=conf;self.proc=None;self.start()
        ldif=root/"seed.ldif";private(ldif,f"""dn: dc=example,dc=test
objectClass: top
objectClass: dcObject
objectClass: organization
o: HeptaBao synthetic LDAP
dc: example

dn: ou=people,dc=example,dc=test
objectClass: top
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=test
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Alice Example
sn: Example
uid: alice
userPassword: {ssha(self.user_password)}
""")
        env={**os.environ,"LDAPTLS_CACERT":str(ca),"LDAPTLS_REQCERT":"demand"}
        subprocess.run(["ldapadd","-x","-H",self.origin,"-D",self.admin_dn,"-y",str(pw),"-f",str(ldif)],
            env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    def start(self):
        if self.proc is not None and self.proc.poll() is None:return
        log=open(self.root/"slapd.log","ab",buffering=0)
        self.proc=subprocess.Popen(["slapd","-f",str(self.conf),"-h",f"ldaps://127.0.0.1:{self.port}/","-d","0"],
            stdout=log,stderr=subprocess.STDOUT)
        end=time.monotonic()+10
        while time.monotonic()<end:
            if self.proc.poll() is not None:raise RuntimeError("slapd_exited")
            try:
                with socket.create_connection(("127.0.0.1",self.port),timeout=.2):return
            except OSError:time.sleep(.05)
        raise RuntimeError("slapd_timeout")
    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)

def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",required=True,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    root=Path(tempfile.mkdtemp(prefix="hb-openldap-"));root.chmod(0o700);ins=Instance(a.binary,root/"candidate");checks=[]
    try:
        try:d=Directory(root/"openldap",ins.root/"tls.crt",ins.root/"tls.key",ins.root/"ca.crt")
        except FileNotFoundError:return 77
        def check(name,ok):
            checks.append({"case":name,"passed":ok is True})
            if ok is not True:raise RuntimeError(name)
        try:
            cfgp=ins.root/"server.json";cfg=json.loads(cfgp.read_text())
            cfg["outbound_endpoints"]=[{"origin":d.origin,"address":f"127.0.0.1:{d.port}","server_name":"localhost",
                "ca_pem":(ins.root/"ca.crt").read_text(),"path_prefix":"/"}];private(cfgp,json.dumps(cfg))
            ins.start();st,init=ins.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1});check("initialize",st==200)
            key=init["keys_base64"][0];ins.token=init["root_token"];check("unseal",ins.call("POST","sys/unseal",{"key":key})[0]==200)
            check("mount",ins.call("POST","sys/auth/ldap",{"type":"ldap"})[0]==204)
            lc={"url":d.origin,"bind_dn":d.admin_dn,"user_dn_template":"uid={{username}},ou=people,dc=example,dc=test","starttls":False}
            check("configure_real_openldap",ins.call("POST","auth/ldap/config",lc)[0]==204)
            check("local_policy_mapping",ins.call("PUT","auth/ldap/users/alice",{"password":"local-only-secret","policies":["default"]})[0]==204)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});tok=res.get("auth",{}).get("client_token")
            check("real_openldap_bind_mints_token",st==200 and bool(tok));check("issued_token_usable",ins.call("GET","auth/token/lookup-self",token=tok)[0]==200)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":"local-only-secret"});check("wrong_directory_password_denied",st==403 and "auth" not in res)
            d.stop();st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_outage_fails_closed",st==503 and "auth" not in res)
            d.start();st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_restart_recovers",st==200 and bool(res.get("auth",{}).get("client_token")))
            ins.stop();ins.start();check("service_restart_unseal",ins.call("POST","sys/unseal",{"key":key})[0]==200)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("config_survives_restart",st==200)
            check("remove_local_authority",ins.call("DELETE","auth/ldap/users/alice",{})[0]==204)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_success_cannot_bypass_local_revocation",st==403 and "auth" not in res)
            report={"schema":"heptabao.openldap-live.v1","status":"passed" if all(x["passed"] for x in checks) else "failed","checks":checks,
                "actual_slapd_distribution":True,"tls_simple_bind":True,"search_and_group_mapping":False,"independent_qualification":False}
            private(a.output,json.dumps(report,indent=2)+"\n");return 0 if report["status"]=="passed" else 1
        finally:d.stop()
    finally:ins.stop();shutil.rmtree(root,ignore_errors=True)
if __name__=="__main__":raise SystemExit(main())
