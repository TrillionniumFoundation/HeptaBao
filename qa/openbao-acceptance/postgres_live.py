#!/usr/bin/env python3
"""Real PostgreSQL 17 prerequisite gate and isolated provider acceptance.

Requires an operator-supplied local PostgreSQL 17 installation (postgres, initdb,
psql). Creates/destroys ONLY a fresh private loopback test cluster. No external
DSN, existing data directory, live credential or production endpoint is accepted.
Missing binaries are BLOCKED, exit 77; never fall back to the PG-wire model.
"""
from __future__ import annotations
import argparse
import concurrent.futures
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
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,(self.password+'\n').encode());os.close(write_fd);write_fd=-1
            r=subprocess.run([str(bin_dir/'initdb'),'-D',str(root/'data'),'-U','hb_bootstrap',
                '--pwfile=/dev/fd/'+str(read_fd),'--auth=scram-sha-256','--encoding=UTF8','--locale=C'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45,pass_fds=(read_fd,),**self.identity)
        finally:
            if write_fd>=0:os.close(write_fd)
            os.close(read_fd)
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
    @contextmanager
    def hold_provider_fence(self, fence_id):
        if not re.fullmatch(r'hbf1:[0-9a-f]{64}', fence_id):
            raise RuntimeError('invalid_fence_id_for_lock_fixture')
        with psql_environment(
            self.root.parent,
            port=self.port,
            database='app',
            user='hb_bootstrap',
            password=self.password,
            ca=self.ca,
            application='hb-provider-lock-fixture',
        ) as env:
            process=subprocess.Popen(
                [str(self.bin/'psql'),'-X','-qAt','-w','-v','ON_ERROR_STOP=1'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                env=env,text=True,
            )
            try:
                process.stdin.write(
                    "SELECT pg_advisory_lock(hashtextextended('hb_manager:' || '"
                    +fence_id+"',0)); SELECT 'locked';\n"
                )
                process.stdin.flush()
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    line=process.stdout.readline()
                    if line.strip()=='locked':
                        break
                    if process.poll() is not None:
                        raise RuntimeError('provider_lock_fixture_exited')
                else:
                    raise RuntimeError('provider_lock_fixture_not_ready')
                yield process
            finally:
                if process.poll() is None:
                    process.stdin.write(
                        "SELECT pg_advisory_unlock(hashtextextended('hb_manager:' || '"
                        +fence_id+"',0));\n"
                    )
                    process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=5)
    def install(self, provider_sql=None):
        q=self.sql("CREATE ROLE hb_manager LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+self.manager_password+"'; CREATE ROLE app_reader NOLOGIN; CREATE DATABASE app;",database='postgres')
        if q.returncode:raise RuntimeError('postgres_operator_bootstrap_failed')
        source=ROOT/'bootstrap/postgresql/provider.sql' if provider_sql is None else provider_sql
        q=self.sql(source.read_text())
        if q.returncode:raise RuntimeError('postgres_provider_sql_failed')
        q=self.sql("GRANT USAGE ON SCHEMA heptabao_provider TO hb_manager; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA heptabao_provider TO hb_manager; INSERT INTO heptabao_provider.allowed_groups VALUES('hb_manager','app_reader');")
        if q.returncode:raise RuntimeError('postgres_provider_enrollment_failed')


def qualify_username_recovery(pg, check):
    """Upgrade an actually installed v2 without rewriting owner/fence/lease data."""
    fence='hbf1:'+('a1'*32)
    provider='hb1:'+('b2'*32)
    short='hbp_'+('c3'*14)
    digest='d4'*32
    expires=int(time.time())+300

    def apply(action, seq, username=short, lease_id=provider):
        password='e5'*32 if action=='issue' else ''
        expiry=expires if action!='revoke' else 0
        # Every substituted value is fixed synthetic fixture data, never an
        # inbound API value. Passwords travel over psql stdin, never argv.
        return pg.sql(
            "SELECT heptabao_provider.apply('"+fence+"','"+lease_id+"','"+username
            +"',"+str(seq)+",'"+action+"',"+str(expiry)+",'app_reader','"
            +password+"','"+digest+"')::text", 'hb_manager', pg.manager_password)

    check('legacy_v2_rejects_short_issuance', apply('issue',1).returncode!=0)
    check('legacy_rejection_publishes_no_provider_fence', pg.sql(
        "SELECT count(*) FROM heptabao_provider.fences WHERE fence_id='"+fence+"'"
    ).stdout.strip()=='0')
    identity_query="""SELECT p.oid,p.proname,p.proowner,p.proacl,p.prosecdef,p.proconfig
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='heptabao_provider' ORDER BY p.proname"""
    before=pg.sql(identity_query)
    check('legacy_function_identities_observed',before.returncode==0 and len(before.stdout.splitlines())==5)
    upgrade=(ROOT/'bootstrap/postgresql/upgrade_v2_username_recovery.sql').read_text()
    check('manager_cannot_upgrade_provider_functions',pg.sql(upgrade,'hb_manager',pg.manager_password).returncode!=0)
    check('owner_installs_username_recovery_atomically',pg.sql(upgrade).returncode==0)
    after=pg.sql(identity_query)
    check('username_upgrade_preserves_function_owners_and_grants',after.returncode==0 and after.stdout==before.stdout)
    check('username_upgrade_is_repeatable',pg.sql(upgrade).returncode==0)
    check('username_upgrade_preserves_protocol_version',pg.sql(
        'SELECT heptabao_provider.protocol()','hb_manager',pg.manager_password
    ).stdout.strip()=='heptabao-postgresql-provider-v2')
    check('upgraded_v2_still_rejects_short_issuance',apply('issue',2).returncode!=0)
    check('upgraded_v2_still_rejects_short_renewal',apply('renew',3).returncode!=0)
    result=apply('revoke',4)
    check('historical_short_identity_can_be_revoked',result.returncode==0
          and json.loads(result.stdout).get('username')==short
          and json.loads(result.stdout).get('login') is False)
    args="('"+fence+"','"+provider+"','"+short+"',4)"
    check('historical_short_identity_can_be_retired',pg.sql(
        'SELECT heptabao_provider.retire'+args,'hb_manager',pg.manager_password
    ).stdout.strip()=='t')
    check('historical_short_retirement_has_authoritative_readback',pg.sql(
        'SELECT heptabao_provider.retired'+args,'hb_manager',pg.manager_password
    ).stdout.strip()=='t')
    check('historical_short_retirement_keeps_global_fence',pg.sql(
        "SELECT last_seq FROM heptabao_provider.fences WHERE fence_id='"+fence+"'"
    ).stdout.strip()=='4')
    check('retirement_does_not_reenable_stale_issuance',apply(
        'issue',3,username='hbp_'+('f6'*16),lease_id='hb1:'+('f6'*32)
    ).returncode!=0)
    collision='hbp_'+('a7'*14)
    check('foreign_short_role_fixture_created',pg.sql('CREATE ROLE '+collision+' NOLOGIN').returncode==0)
    try:
        check('historical_cleanup_rejects_unowned_short_role',apply(
            'revoke',5,username=collision,lease_id='hb1:'+('a7'*32)
        ).returncode!=0)
        check('rejected_cleanup_does_not_delete_foreign_role',pg.sql(
            "SELECT count(*) FROM pg_roles WHERE rolname='"+collision+"'"
        ).stdout.strip()=='1')
        check('rejected_cleanup_does_not_advance_global_fence',pg.sql(
            "SELECT last_seq FROM heptabao_provider.fences WHERE fence_id='"+fence+"'"
        ).stdout.strip()=='4')
    finally:
        # Only the role this fixture just created in its private cluster.
        if pg.sql('DROP ROLE '+collision).returncode:
            raise RuntimeError('foreign_short_fixture_cleanup_failed')


def qualify_pending_revoke_fence(instance, pg, key, check):
    """A rejected revoke must recover after another lease overtakes its fence."""
    status, first=instance.call('GET','database/creds/churn')
    check('overtaken_revoke_first_credential',status==200)
    username=first['data']['username']
    check('overtaken_revoke_username_bound',re.fullmatch(r'hbp_[0-9a-f]{32}',username) is not None)
    check('overtaken_revoke_drift_fixture',pg.sql(
        'CREATE ROLE hb_fixture_extra NOLOGIN; GRANT hb_fixture_extra TO '+username
    ).returncode==0)
    status, failure=instance.call('POST','sys/leases/revoke',dict(lease_id=first['lease_id']))
    check('ownership_drift_retains_pending_revoke',status==503
          and failure.get('reconcile_required') is True and 'data' not in failure)
    status, second=instance.call('GET','database/creds/churn')
    check('independent_lease_overtakes_pending_revoke',status==200)
    instance.stop()
    check('overtaken_revoke_ownership_restored',pg.sql(
        'REVOKE hb_fixture_extra FROM '+username+'; DROP ROLE hb_fixture_extra'
    ).returncode==0)
    instance.start()
    check('overtaken_revoke_restart_unseal',instance.call('POST','sys/unseal',{'key':key})[0]==200)
    deadline=time.monotonic()+10
    while True:
        status, result=instance.call('POST','sys/leases/revoke',dict(lease_id=first['lease_id']))
        if status==204:break
        if status!=503 or result.get('reconcile_required') is not True or time.monotonic()>=deadline:
            raise RuntimeError('pending_revoke_recovers_after_other_lease_advanced_fence')
        time.sleep(.1)
    check('pending_revoke_recovers_after_other_lease_advanced_fence',True)
    check('overtaken_revoke_does_not_disable_unrelated_lease',pg.login(
        second['data']['username'],second['data']['password']))
    check('overtaken_revoke_recovered_credential_is_unusable',not pg.login(
        first['data']['username'],first['data']['password']))
    check('overtaken_revoke_unrelated_cleanup',instance.call(
        'POST','sys/leases/revoke',dict(lease_id=second['lease_id']))[0]==204)


def run(binary,bin_dir,root,checks):
    instance=Instance(binary,root/'candidate');pg=None
    def check(name,c):
        checks.append(dict(case=name,passed=c is True))
        if c is not True:raise RuntimeError(name)
    try:
        pg=Postgres(bin_dir,root/'postgres',instance.root/'tls.crt',instance.root/'tls.key',instance.root/'ca.crt')
        pg.start()
        legacy=ROOT/'qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql'
        if hashlib.sha256(legacy.read_bytes()).hexdigest()!='c0422f3dda8de5ae8921f875859c858259264a2a92bca24701057f961398fcf6':
            raise RuntimeError('legacy_postgresql_provider_fixture_changed')
        pg.install(legacy);check('real_postgres_bootstrap_sql_executed',True)
        p=instance.root/'server.json';c=json.loads(p.read_text());c['lifecycle_interval_seconds']=1;c['outbound_endpoints']=[dict(origin=pg.origin,address=f'127.0.0.1:{pg.port}',server_name='localhost',ca_pem=(instance.root/'ca.crt').read_text())];p.write_text(json.dumps(c));p.chmod(0o600)
        instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1});check('initialize',status==200)
        instance.token=init['root_token'];key=init['keys_base64'][0];check('unseal',instance.call('POST','sys/unseal',{'key':key})[0]==200)
        check('mount',instance.call('POST','sys/mounts/database',{'type':'database'})[0]==204)
        config=dict(plugin_name='postgresql-database-plugin',connection_url=pg.origin+'/app',username='hb_manager',password=pg.manager_password,allowed_roles=['reader','short','churn','retiretest'])
        check('native_pg_tls_scram_config',instance.call('POST','database/config/local',config)[0]==204)
        status,listed=instance.call('LIST','database/config')
        check('database_config_list',status==200 and listed.get('data',{}).get('keys')==['local'])
        for role,ttl in [('reader',30),('short',2),('churn',300),('retiretest',30)]:check('role_'+role,instance.call('POST','database/roles/'+role,dict(db_name='local',provider_role='app_reader',default_ttl=ttl,max_ttl=300))[0]==204)
        status,listed=instance.call('LIST','database/roles')
        check('database_role_list',status==200 and listed.get('data',{}).get('keys')==['churn','reader','retiretest','short'])
        check('referenced_database_config_delete_rejected',instance.call('DELETE','database/config/local')[0]==409)
        check('database_role_delete',instance.call('DELETE','database/roles/retiretest')[0]==204)
        check('deleted_database_role_absent',instance.call('GET','database/roles/retiretest')[0]==404)
        status,listed=instance.call('LIST','database/roles')
        check('database_role_list_after_delete',status==200 and listed.get('data',{}).get('keys')==['churn','reader','short'])
        status,issued=instance.call('GET','database/creds/reader');check('issue',status==200)
        cred=issued['data'];identity=issued['lease_id'];check('credential_really_logs_into_postgresql',pg.login(cred['username'],cred['password']))
        check('native_username_matches_deployed_v2_contract',re.fullmatch(r'hbp_[0-9a-f]{32}',cred['username']) is not None)
        qualify_username_recovery(pg,check)
        check('username_upgrade_preserves_existing_live_credential',pg.login(cred['username'],cred['password']))
        check('wrong_password_really_denied',not pg.login(cred['username'],'wrong-synthetic-password'))
        provider_id=pg.sql(
            "SELECT lease_id FROM heptabao_provider.leases WHERE username='"+cred['username']+"'"
        ).stdout.strip()
        fence_id=pg.sql(
            "SELECT fence_id FROM heptabao_provider.leases WHERE lease_id='"+provider_id+"'"
        ).stdout.strip()
        check('provider_fence_identity_observed',re.fullmatch(r'hb1:[0-9a-f]{64}',provider_id) is not None)
        check('provider_fence_binding_observed',re.fullmatch(r'hbf1:[0-9a-f]{64}',fence_id) is not None)
        executor=concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            with pg.hold_provider_fence(fence_id) as holder:
                future=executor.submit(
                    instance.call,'POST','sys/leases/renew',
                    dict(lease_id=identity,increment=120)
                )
                # The native PostgreSQL client bounds lock wait at 1.5s; keep
                # this real-provider fence hold well inside that budget while
                # still observing the blocked query before unrelated KV I/O.
                deadline=time.monotonic()+0.5
                waiting=False
                while time.monotonic()<deadline:
                    q=pg.sql(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE usename='hb_manager' AND wait_event_type='Lock' "
                        "AND query LIKE 'SELECT heptabao_provider.apply%'"
                    )
                    waiting=q.returncode==0 and int(q.stdout.strip() or '0')>=1
                    if waiting:break
                    if future.done():break
                    time.sleep(.02)
                check('provider_call_really_waiting_on_postgres_fence',waiting and not future.done())
                status,_=instance.call(
                    'POST','secret/data/provider-isolation',
                    {'data':{'value':'write-completed-during-provider-lock'}}
                )
                check('slow_provider_does_not_block_unrelated_kv_write',status==200)
                status,read=instance.call('GET','secret/data/provider-isolation')
                check(
                    'unrelated_kv_read_completes_while_provider_still_blocked',
                    status==200
                    and read['data']['data']['value']=='write-completed-during-provider-lock'
                    and holder.poll() is None
                    and not future.done()
                )
            status,_=future.result(timeout=5)
            check('renew_after_provider_fence_release',status==200)
        finally:
            executor.shutdown(wait=True,cancel_futures=True)
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
        check('revoked_provider_ledger_retired',pg.sql("SELECT count(*) FROM heptabao_provider.leases WHERE lease_id='"+provider_id+"'").stdout.strip()=='0')
        check('revoked_postgres_role_retired',pg.sql("SELECT count(*) FROM pg_roles WHERE rolname='"+cred['username']+"'").stdout.strip()=='0')
        prefix_credentials=[]
        for _ in range(2):
            status,prefix_issue=instance.call('GET','database/creds/reader')
            check('prefix_revoke_seed_'+str(len(prefix_credentials)),status==200)
            prefix_credentials.append((prefix_issue['lease_id'],prefix_issue['data']))
        status,_=instance.call('POST','sys/leases/revoke-prefix/database/creds/reader',{})
        check('database_prefix_revoke',status==204)
        for index,(lease_id,prefix_cred) in enumerate(prefix_credentials):
            check('database_prefix_revoke_login_denied_'+str(index),not pg.login(prefix_cred['username'],prefix_cred['password']))
            check('database_prefix_revoke_lookup_absent_'+str(index),instance.call('POST','sys/leases/lookup',{'lease_id':lease_id})[0]==400)
        qualify_pending_revoke_fence(instance,pg,key,check)
        for index in range(132):
            status,churn=instance.call('GET','database/creds/churn')
            if status!=200:
                raise RuntimeError('provider_retirement_churn_issue_'+str(index)+'_'+str(status))
            status,revoke_body=instance.call('POST','sys/leases/revoke',dict(lease_id=churn['lease_id']))
            if status!=204:
                raise RuntimeError('provider_retirement_churn_revoke_'+str(index)+'_'+str(status))
            # Let the lifecycle worker observe the terminal retirement before
            # the next real provider effect; this keeps the stress run focused
            # on the >128 retirement invariant rather than HTTP burst timing.
            time.sleep(0.1)
        check('lease_retirement_survives_more_than_old_128_lifetime_limit',True)
        check('provider_ledger_compacts_after_churn',pg.sql("SELECT count(*) FROM heptabao_provider.leases").stdout.strip()=='0')
        check('provider_generated_roles_compact_after_churn',pg.sql("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'hbp_%'").stdout.strip()=='0')
        # The upgrade regression intentionally retains a separate recovery
        # fence. Compaction is one durable floor per cluster/manager, not one
        # row for all independent cluster identities sharing a provider.
        fence=pg.sql("SELECT count(*),min(last_seq),max(last_seq) FROM heptabao_provider.fences WHERE manager='hb_manager' AND fence_id='"+fence_id+"'")
        check('provider_global_fence_is_compact_and_monotonic',fence.returncode==0 and fence.stdout.strip().split('|')[0]=='1' and int(fence.stdout.strip().split('|')[2])>128)
        recovery=pg.sql("SELECT count(*),min(last_seq),max(last_seq) FROM heptabao_provider.fences WHERE fence_id='hbf1:"+('a1'*32)+"'")
        check('recovery_fixture_fence_is_retained_and_isolated',recovery.returncode==0 and recovery.stdout.strip()=='1|4|4')
        check('provider_manager_cannot_bypass_ledger',pg.sql('DELETE FROM heptabao_provider.leases','hb_manager',pg.manager_password).returncode!=0)
        status,issued=instance.call('GET','database/creds/reader');check('outage_seed',status==200);cred=issued['data'];identity=issued['lease_id']
        pg.stop();status,body=instance.call('POST','sys/leases/renew',dict(lease_id=identity,increment=120))
        check('provider_outage_is_pending_not_success',
              status==503 and body.get('reconcile_required') is True and 'data' not in body)
        instance.stop();pg.start();instance.start();check('both_restart',instance.call('POST','sys/unseal',{'key':key})[0]==200)
        # Worker or explicit reconciliation may win; both must disable the role.
        status,_=instance.call('POST','sys/leases/reconcile/'+identity,{})
        check('restart_reconcile',status==204);check('reconciled_role_denied',not pg.login(cred['username'],cred['password']))
        status,issued=instance.call('GET','database/creds/short');check('idle_expiry_seed',status==200);cred=issued['data']
        deadline=time.monotonic()+15
        while True:
            q=pg.sql("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname='"+cred['username']+"'")
            # A successful retirement may already have dropped the provider
            # role; PostgreSQL then returns no row, which is as fail-closed as
            # an observed NOLOGIN role for this expiry assertion.
            disabled=q.returncode==0 and q.stdout.strip() in ('t','')
            if disabled or time.monotonic()>=deadline:break
            time.sleep(.1)
        check('worker_retires_role_not_only_ttl',disabled)
        check('idle_expiry_provider_login_denied',not pg.login(cred['username'],cred['password']))
        check('stored_provider_contract_version',pg.sql('SELECT heptabao_provider.protocol()','hb_manager',pg.manager_password).stdout.strip()=='heptabao-postgresql-provider-v2')
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
    report['legacy_provider_sql_sha256']=hashlib.sha256((ROOT/'qa/openbao-acceptance/fixtures/postgresql-provider-v2-legacy.sql').read_bytes()).hexdigest()
    report['username_recovery_sql_sha256']=hashlib.sha256((ROOT/'bootstrap/postgresql/upgrade_v2_username_recovery.sql').read_bytes()).hexdigest()
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
