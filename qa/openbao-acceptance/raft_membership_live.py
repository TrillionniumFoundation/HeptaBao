#!/usr/bin/env python3
"""Five actual same-version loopback processes: consensus membership/snapshots.

Pre-enrolled mTLS identities, not OpenBao join challenge/API-format parity. Tests
real learner catch-up, stabilized promotion, demotion/removal and optional dead
voter cleanup. No external host, production snapshot or arbitrary endpoint input.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from ha_destructive import Cluster,FixtureError,checked_binary
ROOT=Path(__file__).resolve().parents[2]


class AdminCluster(Cluster):
    NODE_IDS=(1,2,3,4,5)
    def configure_ha(self):
        super().configure_ha()
        for node in self.nodes:
            p=node.root/'ha.json';v=json.loads(p.read_text());v['initial_voters']=[1,2,3];p.write_text(json.dumps(v));p.chmod(0o600)
            p=node.root/'server.json';v=json.loads(p.read_text());v['lifecycle_interval_seconds']=1;p.write_text(json.dumps(v));p.chmod(0o600)
    def configuration(self,node=None):
        node=node or self.leader_cached
        status,response=node.call('GET','sys/storage/raft/configuration',token=self.root_token)
        if status!=200:raise FixtureError('configuration_read_failed')
        c=response.get('data',{}).get('config',{})
        if c.get('committed') is not True or c.get('joint') is not False:raise FixtureError('configuration_not_stable_committed')
        return c
    @staticmethod
    def voters(c):return {int(n['node_id']) for n in c['servers'] if n['voter']}
    @staticmethod
    def members(c):return {int(n['node_id']) for n in c['servers']}
    def change(self,action,node,**extra):
        c=self.configuration();return self.leader_cached.call('POST','sys/storage/raft/'+action,dict(server_id=str(node),expected_index=c['index'],**extra),token=self.root_token,timeout=12)
    def wait_voter(self,number,present=True,limit=20):
        deadline=time.monotonic()+limit
        while time.monotonic()<deadline:
            c=self.configuration()
            if (number in self.voters(c)) is present:return c
            time.sleep(.2)
        raise FixtureError('autopilot_voter_transition_unobserved')
    def run(self):
        seed=self.nodes[0];seed.start(ha=False)
        status,body=seed.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        self.check('initialize_seed',status==200);self.root_token=body['root_token'];self.unseal_key=body['keys_base64'][0]
        self.check('seed_unseal',seed.call('POST','sys/unseal',{'key':self.unseal_key})[0]==200)
        self.cluster_id=seed.call('GET','sys/health')[1]['cluster_id'];seed.stop();self.configure_ha()
        for n in self.nodes[1:]:shutil.copytree(seed.data_dir,n.data_dir)
        for n in self.nodes[1:]+self.nodes[:1]:n.start()
        self.check('five_distinct_processes',len({n.process.pid for n in self.nodes})==5)
        self.wait_quorum()
        for n in self.nodes[:3]:self.check('unseal_initial_'+str(n.node_id),n.call('POST','sys/unseal',{'key':self.unseal_key})[0]==200)
        self.leader_cached=self.leader();leader=self.leader_cached
        c=self.configuration();self.check('configured_peers_not_automatically_voters',self.members(c)=={1,2,3} and self.voters(c)=={1,2,3})
        self.check('configuration_requires_auth',leader.call('GET','sys/storage/raft/configuration')[0]==403)
        self.check('unsafe_minimum_rejected',leader.call('POST','sys/storage/raft/autopilot/configuration',{'min_quorum':2},token=self.root_token)[0]==400)
        self.check('too_short_dead_threshold_rejected',leader.call('POST','sys/storage/raft/autopilot/configuration',{'dead_server_last_contact_threshold':'1s'},token=self.root_token)[0]==400)
        status,_=leader.call('POST','sys/storage/raft/autopilot/configuration',{'server_stabilization_time':'3s','last_contact_threshold':'2s','min_quorum':3},token=self.root_token)
        self.check('persist_stabilization_policy',status==204)
        for i in range(5):self.write(leader,f'snapshot-before-join-{i}',f'synthetic-value-{i}')
        status,snapshot=leader.call('GET','sys/storage/raft/snapshot',token=self.root_token,timeout=12)
        self.check('snapshot_waits_durable_readback',status==200 and isinstance(snapshot.get('data'),dict))
        s=leader.call('GET','sys/storage/raft/snapshot-status',token=self.root_token)[1]['data']
        self.check('snapshot_committed_frontier_exists',isinstance(s.get('snapshot_index'),int) and s['snapshot_index']>0)
        deadline=time.monotonic()+5
        while not s.get('purged_index') and time.monotonic()<deadline:
            time.sleep(.1);s=leader.call('GET','sys/storage/raft/snapshot-status',token=self.root_token)[1]['data']
        self.check('prejoin_logs_really_purged',isinstance(s.get('purged_index'),int) and s['purged_index']>0)
        status,_=self.change('join',4,non_voter=True);self.check('native_learner_join_acknowledged',status==200)
        c=self.configuration();self.check('learner_is_not_a_voter',4 in self.members(c) and 4 not in self.voters(c))
        n4,n5=self.nodes[3:]
        self.check('snapshot_caught_up_learner_unseals',n4.call('POST','sys/unseal',{'key':self.unseal_key})[0]==200)
        self.read(n4,'snapshot-before-join-4','synthetic-value-4');self.check('learner_recovers_pre_purge_state',True)
        status,_=leader.call('POST','sys/storage/raft/promote',dict(server_id='4',expected_index=c['index']-1),token=self.root_token)
        self.check('stale_membership_index_rejected',status==409)
        self.check('unenrolled_node_rejected',self.change('join',999,non_voter=True)[0]==400)
        self.check('join_cannot_change_network_identity',leader.call('POST','sys/storage/raft/join',dict(server_id='5',expected_index=c['index'],leader_api_addr='https://untrusted.invalid'),token=self.root_token)[0]==400)
        status,_=self.change('join',5,non_voter=False);self.check('autopilot_candidate_initially_learner',status==200 and 5 not in self.voters(self.configuration()))
        self.check('new_learner_unseal',n5.call('POST','sys/unseal',{'key':self.unseal_key})[0]==200)
        c=self.wait_voter(5);self.check('continuous_stabilization_promotes_voter',5 in self.voters(c))
        # Node 4 deliberately joined non-voting: policy must not silently promote.
        self.check('permanent_nonvoter_remains_nonvoter',4 not in self.voters(c))
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            observed=leader.call('GET','sys/storage/raft/autopilot/state',token=self.root_token)[1]['data']
            if observed['servers']['4'].get('stabilized') is True:break
            time.sleep(.2)
        self.check('manual_promotion_stabilization_observed',observed['servers']['4'].get('stabilized') is True)
        status,_=self.change('promote',4);self.check('manual_promote_after_observed_stabilization',status==200)
        self.check('five_native_voters',self.voters(self.configuration())=={1,2,3,4,5})
        status,health=leader.call('GET','sys/storage/raft/autopilot/state',token=self.root_token)
        self.check('health_derived_from_replication',status==200 and health['data']['healthy'] is True and health['data']['failure_tolerance']==2)
        self.check('demote_through_joint_consensus',self.change('demote',4)[0]==200 and 4 not in self.voters(self.configuration()))
        self.check('remove_existing_learner',self.change('remove-peer',4)[0]==200 and 4 not in self.members(self.configuration()))
        n4.stop()
        if self.cleanup:
            status,_=leader.call('POST','sys/storage/raft/autopilot/configuration',{'cleanup_dead_servers':True,'dead_server_last_contact_threshold':'60s'},token=self.root_token)
            self.check('dead_cleanup_explicitly_enabled',status==204)
            n5.stop();time.sleep(3)
            state=leader.call('GET','sys/storage/raft/autopilot/state',token=self.root_token)[1]['data']
            self.check('dead_voter_unhealthy_not_fabricated',state['servers']['5']['healthy'] is False and state['healthy'] is False)
            self.check('dead_voter_retained_during_grace',5 in self.voters(self.configuration()))
            c=self.wait_voter(5,False,limit=72)
            self.check('dead_voter_removed_after_real_contact_threshold',5 not in self.members(c) and self.voters(c)=={1,2,3})
        else:
            self.check('remove_voter_observed_committed',self.change('remove-peer',5)[0]==200)
            n5.stop()
        c=self.configuration();self.check('minimum_three_voters_preserved',self.voters(c)=={1,2,3})
        victim=next(n for n in self.nodes[:3] if n is not leader)
        self.check('cannot_remove_below_minimum',self.change('remove-peer',victim.node_id)[0]==409)
        leader.stop();self.leader_cached=self.leader();self.check('failover_after_membership_changes',self.leader_cached is not leader)
        self.restart(leader);self.leader_cached=self.leader()
        c=self.configuration();self.check('membership_persists_across_old_leader_restart',self.members(c)=={1,2,3})
        policy=self.leader_cached.call('GET','sys/storage/raft/autopilot/configuration',token=self.root_token)[1]['data']
        self.check('autopilot_policy_persists_across_restart',policy['server_stabilization_time']=='3s' and policy['min_quorum']==3)
        self.write(leader,'after-membership','final-value');self.read(self.leader_cached,'after-membership','final-value')
        self.check('post_change_forwarding_preserves_committed_data',True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--output',required=True);p.add_argument('--dead-cleanup',action='store_true');a=p.parse_args()
    binary=Path(a.binary).resolve(strict=True);out=Path(a.output).resolve()
    if out.exists():p.error('output must be new')
    digest=hashlib.sha256(binary.read_bytes()).hexdigest();checked_binary(binary,digest)
    temp=Path(tempfile.mkdtemp(prefix='hb-raft-admin-'));c=None
    report={'schema':'heptabao.raft-administration-live.v1','binary_sha256':digest,'independent_qualification':False,'same_version_loopback_only':True,'native_membership':True,'dead_cleanup':a.dead_cleanup,'scenario_count':0,'scenarios':[]}
    try:
        c=AdminCluster(binary,temp/'cluster');c.cleanup=a.dead_cleanup;c.run();report['status']='passed';checked_binary(binary,digest)
    except Exception as error:report.update(status='failed',failure=str(error) if isinstance(error,FixtureError) else type(error).__name__)
    finally:
        if c is not None:
            report['scenarios']=c.scenarios;report['scenario_count']=len(c.scenarios);c.close()
        shutil.rmtree(temp);out.write_text(json.dumps(report,indent=2)+'\n');out.chmod(0o600)
    print(json.dumps({'status':report['status'],'scenarios':report['scenario_count'],'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
