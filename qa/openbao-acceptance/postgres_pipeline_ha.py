#!/usr/bin/env python3
"""Real same-version HA Service with explicitly SIMULATED PG provider.

PG-wire/SCRAM fixture tests durable intents through quorum, forwarding, failover
and restart. No SQL, actual PostgreSQL roles or production database is executed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from ha_destructive import Cluster,FixtureError
from external_tls_fixtures import PgWireFixture

class ProviderCluster(Cluster):
    def configure(self):
        super().configure()
        self.provider=PgWireFixture(self.nodes[0].root/'tls.crt',self.nodes[0].root/'tls.key')
        ca=(self.root/'ca.crt').read_text()
        for node in self.nodes:
            path=node.root/'server.json';c=json.loads(path.read_text());c['lifecycle_interval_seconds']=1
            c['outbound_endpoints']=[dict(origin=self.provider.origin,address=f'127.0.0.1:{self.provider.port}',server_name='localhost',ca_pem=ca)]
            path.write_text(json.dumps(c));path.chmod(0o600)
    def close(self):
        try:super().close()
        finally:self.provider.close()
    def run(self):
        super().run();leader=self.leader();standby=next(n for n in self.nodes if n is not leader)
        def call(node,method,path,body=None):return node.call(method,path,body,token=self.root_token,timeout=12)
        self.check('db_ha.mount',call(leader,'POST','sys/mounts/database',{'type':'database'})[0]==204)
        p=self.provider
        self.check('db_ha.config',call(leader,'POST','database/config/local',dict(plugin_name='postgresql-database-plugin',connection_url=p.origin+'/app',username=p.manager,password=p.password,allowed_roles=['reader']))[0]==204)
        self.check('db_ha.role',call(leader,'POST','database/roles/reader',dict(db_name='local',provider_role='app_reader',default_ttl=120,max_ttl=300))[0]==204)
        status,issued=call(standby,'GET','database/creds/reader');self.check('db_ha.forwarded_issue',status==200)
        identity=issued['lease_id'];user=issued['data']['username']
        for n in self.nodes:self.check('db_ha.lease_seen_'+str(n.node_id),call(n,'POST','sys/leases/lookup',dict(lease_id=identity))[1].get('data',{}).get('phase')=='Active')
        leader.stop();successor=self.leader();self.check('db_ha.new_leader',successor is not leader)
        self.check('db_ha.revoke_after_failover',call(successor,'POST','sys/leases/revoke',dict(lease_id=identity))[0]==204)
        self.check('db_ha.provider_model_retired',all(r['username']!=user for r in p.rows.values()))
        self.restart(leader);leader=self.leader()
        status,_=call(leader,'POST','sys/leases/lookup',dict(lease_id=identity))
        self.check('db_ha.old_leader_cannot_resurrect',status in (400,404))
        self.check('db_ha_retired_revoke_is_idempotent',call(leader,'POST','sys/leases/revoke',dict(lease_id=identity))[0]==204)
        p.mode='drop_after_apply';status,pending=call(leader,'GET','database/creds/reader')
        self.check('db_ha.provider_unknown_no_secret',status==503 and pending.get('reconcile_required') is True and 'data' not in pending)
        identity=pending['lease_id'];provider_id=p.events[-1][0]
        leader.stop();successor=self.leader()
        deadline=time.monotonic()+15
        while provider_id in p.rows and time.monotonic()<deadline:time.sleep(.1)
        self.check('db_ha.new_leader_reconciles_without_client_request',provider_id not in p.rows)
        status,_=call(successor,'POST','sys/leases/lookup',dict(lease_id=identity))
        self.check('db_ha.pending_is_durable_terminal_after_reconcile',status in (400,404))
        self.restart(leader);leader=self.leader();others=[n for n in self.nodes if n is not leader]
        for n in others:n.stop()
        events=len(p.events);status,body=call(leader,'GET','database/creds/reader')
        self.check('db_ha.quorum_loss_no_provider_entry',status==503 and 'data' not in body and len(p.events)==events)
        for n in others:self.restart(n)
        self.leader();self.check('db_ha.provider_model_protocol_valid',p.server_errors==[])


def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--binary',required=True);a.add_argument('--output',required=True);args=a.parse_args()
    binary=Path(args.binary).resolve(strict=True);out=Path(args.output).resolve()
    if out.exists():a.error('output must be new')
    digest=hashlib.sha256(binary.read_bytes()).hexdigest();temp=Path(tempfile.mkdtemp(prefix='hb-db-ha-'));cluster=None
    r={'schema':'heptabao.database-ha-model.v1','binary_sha256':digest,'provider_kind':'SIMULATED_PG_WIRE_NOT_POSTGRESQL','real_postgresql_executed':False,'provider_sql_executed':False,'independent_qualification':False,'scenarios':[]}
    try:cluster=ProviderCluster(binary,temp/'cluster');cluster.run();r['status']='passed'
    except Exception as e:r.update(status='failed',failure=str(e) if isinstance(e,FixtureError) else type(e).__name__)
    finally:
        if cluster is not None:r['scenarios']=cluster.scenarios;cluster.close()
        shutil.rmtree(temp);r['binary_unchanged']=hashlib.sha256(binary.read_bytes()).hexdigest()==digest
        if not r['binary_unchanged']:r['status']='failed'
        r['scenario_count']=len(r['scenarios']);out.write_text(json.dumps(r,indent=2)+'\n');out.chmod(0o600)
    print(json.dumps({k:r.get(k) for k in ('status','scenario_count','failure','real_postgresql_executed')}));return 0 if r['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
