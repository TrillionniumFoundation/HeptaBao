#!/usr/bin/env python3
"""Real PostgreSQL 17 prerequisite gate and isolated provider acceptance.

Requires an operator-supplied local PostgreSQL 17 installation (postgres, initdb,
psql). Creates/destroys ONLY a fresh private loopback test cluster. No external
DSN, existing data directory, live credential or production endpoint is accepted.
Missing binaries are BLOCKED, exit 77; never fall back to the PG-wire model.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'qa/single-node'))
from smoke import Instance


@contextmanager
def psql_environment(root: Path, *, port: int, database: str, user: str,
                     password: str, ca: Path, application: str = "hb-provider-test"):
    """Use an owner-only passfile, never secret argv/PGPASSWORD or inherited PG routing."""
    def escape(value):
        if not isinstance(value, str) or any(c in value for c in "\n\r\0"):
            raise ValueError("invalid_pgpass_field")
        return value.replace("\\", "\\\\").replace(":", "\\:")
    fields = ["localhost", str(port), database, user, password]
    line = ":".join(escape(value) for value in fields) + "\n"
    fd, name = tempfile.mkstemp(prefix="pgpass-", dir=root)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(line)
        env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
        env.update(PGHOST="localhost", PGHOSTADDR="127.0.0.1", PGPORT=str(port),
                   PGDATABASE=database, PGUSER=user, PGPASSFILE=name,
                   PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca),
                   PGREQUIREAUTH="scram-sha-256", PGGSSENCMODE="disable",
                   PGCONNECT_TIMEOUT="3", PGAPPNAME=application,
                   PGOPTIONS="-c statement_timeout=5000", LC_ALL="C")
        yield env
    finally:
        Path(name).unlink(missing_ok=True)


class Postgres:
    def __init__(self,bin_dir:Path,root:Path,certificate:Path,key:Path,ca:Path):
        self.bin=bin_dir;self.root=root;self.root.mkdir(mode=0o700);self.process=None
        self.password=secrets.token_hex(32);self.manager_password=secrets.token_hex(32);self.ca=ca
        with socket.socket() as s:s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
        self.origin=f'postgresql://localhost:{self.port}'
        self.identity={}
        if os.geteuid()==0:
            nobody=pwd.getpwnam('nobody');os.chown(root,nobody.pw_uid,nobody.pw_gid)
            self.identity=dict(user=nobody.pw_uid,group=nobody.pw_gid,extra_groups=[])
        for source,dest in [(certificate,'tls.crt'),(key,'tls.key')]:
            p=root/dest;shutil.copyfile(source,p);p.chmod(0o600)
            if self.identity:os.chown(p,self.identity['user'],self.identity['group'])
        secret=root/'init-password';secret.write_text(self.password);secret.chmod(0o600)
        if self.identity:os.chown(secret,self.identity['user'],self.identity['group'])
        r=subprocess.run([str(bin_dir/'initdb'),'-D',str(root/'data'),'-U','hb_bootstrap','--pwfile='+str(secret),'--auth=scram-sha-256','--encoding=UTF8','--locale=C'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45,**self.identity)
        secret.unlink()
        if r.returncode:raise RuntimeError('postgres_initdb_failed')
        p=root/'data'/'postgresql.conf'
        with p.open('a') as f:
            f.write("\nlisten_addresses = '127.0.0.1'\nport = "+str(self.port)+"\nunix_socket_directories = ''\nssl = on\nssl_cert_file = '"+str(root/'tls.crt')+"'\nssl_key_file = '"+str(root/'tls.key')+"'\npassword_encryption = 'scram-sha-256'\nmax_connections = 24\nfsync = on\nsynchronous_commit = on\n")
    def sql(self,text,user='hb_bootstrap',password=None,database='app',timeout=10):
        with psql_environment(self.root.parent, port=self.port, database=database, user=user,
                              password=self.password if password is None else password, ca=self.ca) as env:
            return subprocess.run([str(self.bin/'psql'),'-X','-qAt','-w','-v','ON_ERROR_STOP=1'],input=text,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,timeout=timeout)
    @contextmanager
    def active_session(self, user, password):
        application='hb-session-'+secrets.token_hex(12)
        with psql_environment(self.root.parent, port=self.port, database='app', user=user,
                              password=password, ca=self.ca, application=application) as env:
            env['PGOPTIONS']='-c statement_timeout=90000'
            process=subprocess.Popen([str(self.bin/'psql'),'-X','-qAt','-w','-v','ON_ERROR_STOP=1'],
                stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,text=True)
            try:
                process.stdin.write('SELECT pg_sleep(60);\n');process.stdin.close()
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    result=self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='"+application+"' AND state='active'")
                    if result.returncode==0 and result.stdout.strip()=='1':break
                    if process.poll() is not None:raise RuntimeError('active_session_failed_to_connect')
                    time.sleep(.05)
                else:raise RuntimeError('active_session_not_observed')
                yield process, application
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
    def start(self):
        if self.process is not None:raise RuntimeError('postgres_already_started')
        self.log=(self.root/'postgres.log').open('ab');(self.root/'postgres.log').chmod(0o600)
        self.process=subprocess.Popen([str(self.bin/'postgres'),'-D',str(self.root/'data')],stdin=subprocess.DEVNULL,stdout=self.log,stderr=self.log,start_new_session=True,**self.identity)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            if self.process.poll() is not None:raise RuntimeError('postgres_start_failed')
            if self.sql('SELECT 1',database='postgres').returncode==0:return
            time.sleep(.1)
        raise RuntimeError('postgres_readiness_failed')
    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:os.killpg(self.process.pid,signal.SIGKILL)
            self.process.wait(timeout=10);self.process=None;self.log.close()
    def login(self,user,password):
        p=self.sql('SELECT current_user',user,password)
        return p.returncode==0 and p.stdout.strip()==user
    def install(self):
        q=self.sql("CREATE ROLE hb_manager LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+self.manager_password+"'; CREATE ROLE app_reader NOLOGIN; CREATE DATABASE app;",database='postgres')
        if q.returncode:raise RuntimeError('postgres_operator_bootstrap_failed')
        q=self.sql((ROOT/'bootstrap/postgresql/provider.sql').read_text())
        if q.returncode:raise RuntimeError('postgres_provider_sql_failed')
        q=self.sql("GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager; INSERT INTO heptabao_provider.allowed_groups VALUES('hb_manager','app_reader');")
        if q.returncode:raise RuntimeError('postgres_provider_enrollment_failed')


def run(binary,bin_dir,root,checks):
    instance=Instance(binary,root/'candidate');pg=None
    def check(name,c):
        checks.append(dict(case=name,passed=c is True))
        if c is not True:raise RuntimeError(name)
    try:
        pg=Postgres(bin_dir,root/'postgres',instance.root/'tls.crt',instance.root/'tls.key',instance.root/'ca.crt')
        pg.start();pg.install();check('real_postgres_bootstrap_sql_executed',True)
        p=instance.root/'server.json';c=json.loads(p.read_text());c['lifecycle_interval_seconds']=1;c['outbound_endpoints']=[dict(origin=pg.origin,address=f'127.0.0.1:{pg.port}',server_name='localhost',ca_pem=(instance.root/'ca.crt').read_text())];p.write_text(json.dumps(c));p.chmod(0o600)
        instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1});check('initialize',status==200)
        instance.token=init['root_token'];key=init['keys_base64'][0];check('unseal',instance.call('POST','sys/unseal',{'key':key})[0]==200)
        check('mount',instance.call('POST','sys/mounts/database',{'type':'database'})[0]==204)
        config=dict(plugin_name='postgresql-database-plugin',connection_url=pg.origin+'/app',username='hb_manager',password=pg.manager_password,allowed_roles=['reader','short'])
        check('native_pg_tls_scram_config',instance.call('POST','database/config/local',config)[0]==204)
        for role,ttl in [('reader',30),('short',2)]:check('role_'+role,instance.call('POST','database/roles/'+role,dict(db_name='local',provider_role='app_reader',default_ttl=ttl,max_ttl=300))[0]==204)
        status,issued=instance.call('GET','database/creds/reader');check('issue',status==200)
        cred=issued['data'];identity=issued['lease_id'];check('credential_really_logs_into_postgresql',pg.login(cred['username'],cred['password']))
        check('wrong_password_really_denied',not pg.login(cred['username'],'wrong-synthetic-password'))
        check('renew',instance.call('POST','sys/leases/renew',dict(lease_id=identity,increment=120))[0]==200)
        instance.stop();instance.start();check('service_restart_unseal',instance.call('POST','sys/unseal',{'key':key})[0]==200)
        check('renewed_credential_survives_service_restart',pg.login(cred['username'],cred['password']))
        with pg.active_session(cred['username'],cred['password']) as (session,application):
            check('real_active_database_session_observed',session.poll() is None)
            check('revoke_provider_side',instance.call('POST','sys/leases/revoke',dict(lease_id=identity))[0]==204)
            try:exit_status=session.wait(timeout=5)
            except subprocess.TimeoutExpired:exit_status=0
            check('revoke_terminates_existing_database_session',exit_status!=0)
            remaining=pg.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='"+application+"'")
            check('revoked_database_session_absent',remaining.returncode==0 and remaining.stdout.strip()=='0')
        check('revoke_really_prevents_pg_login',not pg.login(cred['username'],cred['password']))
        check('provider_manager_cannot_bypass_ledger',pg.sql('DELETE FROM heptabao_provider.leases','hb_manager',pg.manager_password).returncode!=0)
        status,issued=instance.call('GET','database/creds/reader');check('outage_seed',status==200);cred=issued['data'];identity=issued['lease_id']
        pg.stop();status,body=instance.call('POST','sys/leases/renew',dict(lease_id=identity,increment=120));check('provider_outage_is_pending_not_success',status==503 and body.get('reconcile_required') is True)
        instance.stop();pg.start();instance.start();check('both_restart',instance.call('POST','sys/unseal',{'key':key})[0]==200)
        # Worker or explicit reconciliation may win; both must disable the role.
        status,_=instance.call('POST','sys/leases/reconcile/'+identity,{})
        check('restart_reconcile',status==204);check('reconciled_role_denied',not pg.login(cred['username'],cred['password']))
        status,issued=instance.call('GET','database/creds/short');check('idle_expiry_seed',status==200);cred=issued['data']
        deadline=time.monotonic()+15
        while True:
            q=pg.sql("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='"+cred['username']+"'")
            disabled=q.returncode==0 and q.stdout.strip()=='t'
            if disabled or time.monotonic()>=deadline:break
            time.sleep(.1)
        check('worker_really_disabled_pg_role_not_only_ttl',disabled)
        check('idle_expiry_provider_login_denied',not pg.login(cred['username'],cred['password']))
        check('stored_provider_contract_version',pg.sql('SELECT heptabao_provider.protocol()','hb_manager',pg.manager_password).stdout.strip()=='heptabao-postgresql-provider-v1')
    finally:
        instance.stop()
        if pg is not None:pg.stop()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--postgres-bin');p.add_argument('--output',required=True);a=p.parse_args()
    out=Path(a.output).resolve()
    if out.exists():p.error('output must be new')
    checks=[];report={'schema':'heptabao.postgresql-provider-real.v1','independent_qualification':False,'real_postgresql_executed':False,'provider_sql_executed':False,'checks':checks}
    bin_dir=Path(a.postgres_bin).resolve() if a.postgres_bin else None
    paths=[bin_dir/n for n in ('postgres','initdb','psql')] if bin_dir else []
    if not paths or not all(x.is_file() and os.access(x,os.X_OK) for x in paths):
        report.update(status='blocked_prerequisite',reason='actual_PostgreSQL_17_server_initdb_psql_not_available',check_count=0)
        out.write_text(json.dumps(report,indent=2)+'\n');out.chmod(0o600);print(json.dumps(report));return 77
    version=subprocess.check_output([str(bin_dir/'postgres'),'--version'],text=True,timeout=5).strip()
    if not re.fullmatch(r'postgres \(PostgreSQL\) 17\.[0-9]+(?:\s.*)?',version):p.error('PostgreSQL 17.x required')
    binary=Path(a.binary).resolve(strict=True);digest=hashlib.sha256(binary.read_bytes()).hexdigest();root=Path(tempfile.mkdtemp(prefix='hb-real-postgres-'));root.chmod(0o711 if os.geteuid()==0 else 0o700)
    report.update(postgres_version=version,binary_sha256=digest,provider_sql_sha256=hashlib.sha256((ROOT/'bootstrap/postgresql/provider.sql').read_bytes()).hexdigest())
    try:
        run(binary,bin_dir,root,checks);report.update(status='passed',real_postgresql_executed=True,provider_sql_executed=True)
    except Exception as error:report.update(status='failed',failure=str(error) if type(error) is RuntimeError else type(error).__name__)
    finally:
        report['real_postgresql_executed']=any(x['case']=='real_postgres_bootstrap_sql_executed' and x['passed'] for x in checks)
        report['provider_sql_executed']=report['real_postgresql_executed']
        shutil.rmtree(root);report['binary_unchanged']=hashlib.sha256(binary.read_bytes()).hexdigest()==digest
        if not report['binary_unchanged']:report['status']='failed'
        report['check_count']=len(checks);out.write_text(json.dumps(report,indent=2)+'\n');out.chmod(0o600)
    print(json.dumps({'status':report['status'],'check_count':len(checks),'failure':report.get('failure')}));return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
