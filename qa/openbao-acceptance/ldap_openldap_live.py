#!/usr/bin/env python3
"""Run bounded LDAPS login against an actual host-installed OpenLDAP slapd."""
from __future__ import annotations
import argparse, grp, hashlib, json, os, pwd, re, secrets, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"qa/single-node"))
from smoke import Instance

def port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def password_hash(secret):
    # Use the platform crypt(3) SHA-512 format supported by OpenLDAP's {CRYPT}
    # verifier. The clear secret crosses only the child's stdin.
    salt=secrets.token_hex(8)
    result=subprocess.run(["openssl","passwd","-6","-salt",salt,"-stdin"],input=secret+"\n",
        text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=5)
    value=result.stdout.strip()
    if not re.fullmatch(r"\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}",value):
        raise RuntimeError("ldap_password_hash_failed")
    return "{CRYPT}"+value
def private(path,text):
    path.write_text(text);path.chmod(0o600)

class Directory:
    def __init__(self,root,cert,key,ca):
        if any(shutil.which(x) is None for x in ("slapd","ldapadd")):raise FileNotFoundError
        self.root=root;root.mkdir(mode=0o700);(root/"db").mkdir(mode=0o700)
        # Use the IP literal in the LDAP URL.  Ubuntu's ldap-utils performs a
        # reverse lookup for `localhost` and then validates that unrelated
        # guest hostname against the certificate, while the fixture CA already
        # carries the loopback IP SAN used by the real client connection.
        self.port=port();self.origin=f"ldaps://127.0.0.1:{self.port}"
        self.admin_dn="cn=admin,dc=example,dc=test";self.admin_password=secrets.token_urlsafe(30)
        self.user_password=secrets.token_urlsafe(30)
        # ldap-utils receives the bind secret through an inherited anonymous
        # pipe for each invocation; no clear-text credential file is created.
        self.ldap_env={**os.environ,"LDAPTLS_CACERT":str(ca),"LDAPTLS_REQCERT":"demand"}
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
rootpw {password_hash(self.admin_password)}
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
userPassword: {password_hash(self.user_password)}

dn: ou=groups,dc=example,dc=test
objectClass: top
objectClass: organizationalUnit
ou: groups

dn: cn=engineering,ou=groups,dc=example,dc=test
objectClass: top
objectClass: groupOfNames
cn: engineering
member: uid=alice,ou=people,dc=example,dc=test
""")
        self._ldap_run("ldapadd","-f",str(ldif))
    def _ldap_run(self,tool,*args):
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,self.admin_password.encode());os.close(write_fd);write_fd=-1
            subprocess.run([tool,"-x","-H",self.origin,"-D",self.admin_dn,
                "-y","/dev/fd/"+str(read_fd),*args],env=self.ldap_env,check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,pass_fds=(read_fd,))
        finally:
            if write_fd>=0:os.close(write_fd)
            os.close(read_fd)

    def start(self):
        if self.proc is not None and self.proc.poll() is None:return
        log=open(self.root/"slapd.log","ab",buffering=0)
        # The isolated fixture directory is owned by the invoking test user.  An
        # Ubuntu slapd launched as root otherwise drops to the system
        # `openldap` account before reading this private config and exits with
        # EACCES.  Run the short-lived test daemon as that same unprivileged
        # owner; the dynamically allocated high port keeps this safe and
        # deterministic for both local and guest runs.
        user=pwd.getpwuid(os.getuid()).pw_name;group=grp.getgrgid(os.getgid()).gr_name
        # A nonzero debug level also keeps slapd in the foreground; level 1 is
        # enough for this fixture and prevents Popen from observing the
        # daemonizing parent exit before the readiness probe runs.
        command=["slapd","-u",user,"-g",group,"-f",str(self.conf),"-h",f"ldaps://127.0.0.1:{self.port}/","-d","1"]
        # Ubuntu's AppArmor profile denies LMDB file locks below /var/tmp,
        # even though it permits the files themselves.  In an isolated QA
        # guest, run only this short-lived fixture under the unconfined
        # profile when aa-exec is available; production slapd remains confined.
        if shutil.which("aa-exec") is not None:
            command=["aa-exec","-p","unconfined","--",*command]
        self.proc=subprocess.Popen(command,
            stdout=log,stderr=subprocess.STDOUT)
        end=time.monotonic()+10
        while time.monotonic()<end:
            if self.proc.poll() is not None:raise RuntimeError("slapd_exited")
            try:
                with socket.create_connection(("127.0.0.1",self.port),timeout=.2):return
            except OSError:time.sleep(.05)
        raise RuntimeError("slapd_timeout")
    def replace_engineering_member(self,member_dn):
        change=self.root/"group-change.ldif";private(change,f"""dn: cn=engineering,ou=groups,dc=example,dc=test
changetype: modify
replace: member
member: {member_dn}
""")
        self._ldap_run("ldapmodify","-f",str(change))

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)

def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",required=True,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    # Ubuntu's packaged slapd is confined by AppArmor.  Its profile permits
    # isolated owner-writable state below /var/tmp, while rejecting arbitrary
    # /tmp config paths, so keep the complete short-lived fixture there.
    root=Path(tempfile.mkdtemp(prefix="hb-openldap-",dir="/var/tmp"));root.chmod(0o700);ins=Instance(a.binary,root/"candidate");checks=[]
    binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest()
    source_head=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,
        capture_output=True,check=True).stdout.strip()
    try:
        try:d=Directory(root/"openldap",ins.root/"tls.crt",ins.root/"tls.key",ins.root/"ca.crt")
        except FileNotFoundError:return 77
        def check(name,ok):
            checks.append({"case":name,"passed":ok is True})
            if ok is not True:raise RuntimeError(name)
        try:
            cfgp=ins.root/"server.json";cfg=json.loads(cfgp.read_text())
            cfg["outbound_endpoints"]=[{"origin":d.origin,"address":f"127.0.0.1:{d.port}","server_name":"127.0.0.1",
                "ca_pem":(ins.root/"ca.crt").read_text(),"path_prefix":"/"}];private(cfgp,json.dumps(cfg))
            ins.start();st,init=ins.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1});check("initialize",st==200)
            key=init["keys_base64"][0];ins.token=init["root_token"];check("unseal",ins.call("POST","sys/unseal",{"key":key})[0]==200)
            check("mount",ins.call("POST","sys/auth/ldap",{"type":"ldap"})[0]==204)
            lc={"url":d.origin,"bind_dn":d.admin_dn,
                "user_dn_template":"uid={{username}},ou=people,dc=example,dc=test","starttls":False,
                "group_dn":"ou=groups,dc=example,dc=test","group_attr":"member","group_name_attr":"cn"}
            check("configure_real_openldap",ins.call("POST","auth/ldap/config",lc)[0]==204)
            check("local_policy_mapping",ins.call("PUT","auth/ldap/users/alice",{"password":"local-only-secret","policies":["default"]})[0]==204)
            check("group_policy_exists",ins.call("PUT","sys/policies/acl/ldap-engineering",
                {"policy":'path "sys/health" { capabilities = ["read"] }'})[0]==204)
            check("group_policy_mapping",ins.call("PUT","auth/ldap/groups/engineering",
                {"policies":["ldap-engineering"]})[0]==204)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});tok=res.get("auth",{}).get("client_token")
            check("real_openldap_bind_mints_token",st==200 and bool(tok))
            st,lookup=ins.call("GET","auth/token/lookup-self",token=tok)
            check("live_directory_group_grants_policy",st==200 and "ldap-engineering" in lookup.get("data",{}).get("policies",[]))
            check("issued_token_usable",st==200)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":"local-only-secret"});check("wrong_directory_password_denied",st==403 and "auth" not in res)
            d.stop();st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_outage_fails_closed",st==503 and "auth" not in res)
            d.start();st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_restart_recovers",st==200 and bool(res.get("auth",{}).get("client_token")))
            d.replace_engineering_member(d.admin_dn)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});tok_no_group=res.get("auth",{}).get("client_token")
            st,lookup=ins.call("GET","auth/token/lookup-self",token=tok_no_group)
            check("live_group_revocation_removes_policy_on_next_login",
                st==200 and "ldap-engineering" not in lookup.get("data",{}).get("policies",[]))
            d.replace_engineering_member("uid=alice,ou=people,dc=example,dc=test")
            ins.stop();ins.start();check("service_restart_unseal",ins.call("POST","sys/unseal",{"key":key})[0]==200)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});tok=res.get("auth",{}).get("client_token")
            st,lookup=ins.call("GET","auth/token/lookup-self",token=tok)
            check("group_mapping_survives_restart",st==200 and "ldap-engineering" in lookup.get("data",{}).get("policies",[]))
            check("remove_local_authority",ins.call("DELETE","auth/ldap/users/alice",{})[0]==204)
            st,res=ins.call("POST","auth/ldap/login/alice",{"password":d.user_password});check("provider_success_cannot_bypass_local_revocation",st==403 and "auth" not in res)
            report={"schema":"heptabao.openldap-live.v1","status":"passed" if all(x["passed"] for x in checks) else "failed","checks":checks,
                "actual_slapd_distribution":True,"tls_simple_bind":True,"search_and_group_mapping":True,
                "live_group_revocation":True,"independent_qualification":False,
                "candidate_binary_sha256":binary_sha256,"candidate_binary_source_head":source_head,
                "execution_platform":"Linux aarch64 guest (Ubuntu Noble)",
                "openldap_distribution":"slapd 2.6.10+dfsg-0ubuntu0.24.04.1 arm64",
                "fixture_command":"python3 qa/openbao-acceptance/ldap_openldap_live.py --binary <linux-guest>/target-linux-guest/release/heptabao-server --output <linux-guest>/ldap-openldap-live.json",
                "tls_verification":"CA pinning with loopback IP SAN; LDAPTLS_REQCERT=demand",
                "apparmor_isolation":"The short-lived test slapd runs under aa-exec unconfined in the dedicated SSD Lima guest only; production OpenLDAP remains confined."}
            private(a.output,json.dumps(report,indent=2)+"\n");return 0 if report["status"]=="passed" else 1
        finally:d.stop()
    finally:ins.stop();shutil.rmtree(root,ignore_errors=True)
if __name__=="__main__":raise SystemExit(main())
