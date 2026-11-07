#!/usr/bin/env python3
"""Finite host controls of actual workflow functions; no top-level driver execution."""
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
SOURCES={
 'runtime-sources/G07-real-CM-cancel-r9.py':'c1b52486e9f8520612a5a845272b7b4acb14fc2c76acb7c7ef3f2620dea90c13',
 'runtime-sources/G01-G08-G09-G10-ordinary-SAF-guards-r9.py':'ad9ac360041028c8522df1330ade5305cbd1f612cff03830ee92a238cb944444',
}
attempts=[]
def audit(event,args):
 if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn','os.posix_spawnp'):
  attempts.append(event);raise AssertionError('external_action_forbidden')
sys.addaudithook(audit)

def actual_functions(path,names):
 raw=(ROOT/path).read_bytes();assert hashlib.sha256(raw).hexdigest()==SOURCES[path]
 tree=ast.parse(raw)
 nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
 assert {node.name for node in nodes}==set(names)
 return compile(ast.Module(body=nodes,type_ignores=[]),path,'exec')

class Clock:
 def __init__(self,values):self.values=iter(values)
 def monotonic(self):return next(self.values)

class WriteBoundary(Exception):pass

def main():
 checks=[]
 code=actual_functions('runtime-sources/G07-real-CM-cancel-r9.py',{'inspect','wait_screen','record'})
 def should_reject(label,fn):
  try:fn()
  except AssertionError:checks.append(label)
  else:raise AssertionError(label)
 def screen_ns(clock,phase):
  ns={'time':clock,'phase':phase};exec(code,ns);return ns
 late=screen_ns(Clock([0,8.0001]),lambda *_:{'ok':True})
 should_reject('late_successful_inspect_rejected',late['inspect'])
 valid=screen_ns(Clock([0,7.99]),lambda *_:{'ok':True})
 assert valid['inspect']()=={'ok':True};checks.append('within_deadline_inspect_accepted')
 target=['provider','Operation'];screen={'foreground':target,'nodes':[{'text':'APPROVE'}]}
 ns=screen_ns(Clock([0,8.0001]),None);ns['inspect']=lambda:screen
 should_reject('late_successful_wait_screen_rejected',lambda:ns['wait_screen'](target,'APPROVE'))
 ns=screen_ns(Clock([0,7.99]),None);ns['inspect']=lambda:screen
 assert ns['wait_screen'](target,'APPROVE')==screen;checks.append('within_deadline_wait_screen_accepted')
 before={'credentials':[{'credential_id':'synthetic','public_key_sha256':'a'*64,'sign_count':9}],
         'counters':{'options':17,'verification_attempts':10,'authentications':9,'registrations':1,'rejected':0},'revision':40}
 after=json.loads(json.dumps(before));after['counters']['options']=18;after['revision']=41
 def record_ns():
  calls=[]
  def no_rp():raise AssertionError('unvalidated_second_RP_fetch')
  def first_write(*args):calls.append(args);raise WriteBoundary()
  ns={'rp':no_rp,'save':first_write,'root':Path('/not-used'),'LABEL':'G07',
      'negative_started':100_000_000_000,'index_started':0,'before':before,
      'provider_backs':1,'chooser_backs':1}
  exec(code,ns);return ns,calls
 ns,writes=record_ns()
 try:ns['record']('passed',final_observation=(after,b'actual snapshot bytes',150_000_000_000))
 except WriteBoundary:pass
 else:raise AssertionError('valid_record_did_not_reach_write_boundary')
 assert len(writes)==1;checks.append('validated_final_snapshot_used_without_second_RP_fetch')
 ns,writes=record_ns()
 should_reject('original_180_second_boundary_rejected',lambda:ns['record']('passed',final_observation=(after,b'x',280_000_000_000)))
 assert not writes
 ns,writes=record_ns();ns['negative_started']=250_000_000_000
 should_reject('original_300_second_boundary_rejected',lambda:ns['record']('passed',final_observation=(after,b'x',300_000_000_000)))
 assert not writes
 ns,writes=record_ns();changed=json.loads(json.dumps(after));changed['credentials'][0]['sign_count']=10
 should_reject('changed_accepted_counter_rejected',lambda:ns['record']('passed',final_observation=(changed,b'x',150_000_000_000)))
 assert not writes
 ns,writes=record_ns();ns['chooser_backs']=0
 should_reject('single_Back_not_enough_for_declared_two_step_cancellation',lambda:ns['record']('passed',final_observation=(after,b'x',150_000_000_000)))
 assert not writes
 scode=actual_functions('runtime-sources/G01-G08-G09-G10-ordinary-SAF-guards-r9.py',{'require_unconsumed_selection'})
 seed='bb527d9aa00987a243b378ac31eb15d2caf203e106348a8e1ed60cff7f674917'
 path='/sdcard/Download/HeptaBao-Passkey-QA-20261106-r9/G10-target/HeptaBao-passkey-backup.hbv'
 selected={'foreground':['org.heptabao.passkey.preview','org.heptabao.passkey.preview.HomeActivity'],
           'nodes':[{'text':'Destination chosen; enter password and write encrypted backup'}]}
 baseline={'device_path':path,'bytes':615,'sha256':seed}
 def saf_ns(writes):
  ns={'product_write_count':writes,'SEED_SHA':seed};exec(scode,ns);return ns
 saf_ns(0)['require_unconsumed_selection'](selected,baseline,path);checks.append('fresh_nonempty_selected_target_accepted')
 should_reject('prior_Write_consumption_rejected',lambda:saf_ns(1)['require_unconsumed_selection'](selected,baseline,path))
 wrong_screen=dict(selected,nodes=[{'text':'Encrypted backup written and read-back verified'}])
 should_reject('successful_prior_export_state_not_a_fresh_selection',lambda:saf_ns(0)['require_unconsumed_selection'](wrong_screen,baseline,path))
 changed=dict(baseline,sha256='0'*64)
 should_reject('wrong_target_baseline_rejected',lambda:saf_ns(0)['require_unconsumed_selection'](selected,changed,path))
 assert not attempts and len(checks)==13
 for path,digest in SOURCES.items():assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest
 print(json.dumps({'schema':1,'scope':'actual_QA_function_host_boundary_controls_only','passed':len(checks),'checks':checks,'source_sha256':SOURCES,'external_attempts':attempts,'adb_calls':0,'network_calls':0,'phone_cases_executed':0,'phone_qualified':False,'production_qualified':False},sort_keys=True))
if __name__=='__main__':main()
