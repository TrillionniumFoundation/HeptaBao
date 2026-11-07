#!/usr/bin/env python3
"""Pure preserve-absence/once failure cases; no launchd or application process."""
import hashlib,importlib.util,json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
path=HERE/'mac_gateway_preserve_absent_primitives_r1.py'
spec=importlib.util.spec_from_file_location('preserve_absent_fixture',path)
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
cases=[]
def need(value):
 if not value:raise AssertionError('synthetic_case_failed')
def refused(fn):
 try:fn()
 except (core.Refused,RuntimeError):return
 raise AssertionError('expected_refusal')
def fixture(*,command_failure=None,event_failure=None):
 q=core.Qualification.__new__(core.Qualification)
 state={'registered':False,'disabled':None,'calls':[],'events':[]}
 q.unknown=False;q.mutations={};q.generation_closed=set();q.until=time.monotonic()+5
 q.runtime_fence=lambda:None;q.check_root=lambda:None;q.check_plist=lambda _:None
 q.plists={key:{'path':str(core.ROOT/'original-service.plist')} for key in ('first','recovery')}
 q.query=lambda *_:{} if state['registered'] else None
 q.disabled=lambda:state['disabled']
 q.same_running=lambda _:need(state['registered'])
 def event(kind,value):
  state['events'].append(kind)
  if kind==event_failure:raise RuntimeError('synthetic_durable_publication_unknown')
 q.event=event
 def command(operation,argv):
  state['calls'].append((operation,list(argv)))
  if operation==command_failure:raise RuntimeError('synthetic_original_command_unknown')
  if operation.startswith('bootstrap-'):state['registered']=True
  elif operation.startswith('bootout-'):state['registered']=False
  else:raise AssertionError('disabled_namespace_mutation_unexpected')
  return {'exitCode':0},b'',b''
 q.command=command
 return q,state
def test(name,fn):fn();cases.append({'case':name,'passed':True})
def complete():
 q,s=fixture();q.dispatch('bootstrap-first','first');q.dispatch('bootout-first','first')
 q.generation_closed.add('first');q.dispatch('bootstrap-recovery','recovery');q.dispatch('bootout-recovery','recovery')
 need(len(s['calls'])==4 and tuple(q.mutations)==core.GRAPH and s['disabled'] is None and not s['registered'])
 need(all(value['outcome']=='complete' and value['intentPersisted'] and value['dispatched'] for value in q.mutations.values()))
 need([row[1][1] for row in s['calls']]==['bootstrap','bootout','bootstrap','bootout'])
 need(s['calls'][0][1][-1]==s['calls'][2][1][-1])
test('A01_same_original_plist_four_actions_preserve_absence',complete)
def forbidden(op):
 q,s=fixture();refused(lambda:q.dispatch(op,'first'));need(not s['calls'] and not q.mutations)
test('A02_disable_has_no_dispatch_path',lambda:forbidden('disable'))
test('A03_enable_has_no_dispatch_path',lambda:forbidden('enable'))
def false_entry():
 q,s=fixture();s['disabled']=False;refused(lambda:q.dispatch('bootstrap-first','first'));need(not s['calls'])
test('A04_false_override_is_not_absence',false_entry)
def pending_absence():
 q,s=fixture();q.dispatch('bootstrap-first','first');q.dispatch('bootout-first','first')
 refused(lambda:q.dispatch('bootstrap-recovery','recovery'));need(len(s['calls'])==2)
test('A05_cold_restore_requires_completed_two_round_absence',pending_absence)
def unknown(operation):
 q,s=fixture(command_failure=operation)
 if operation=='bootout-first':q.dispatch('bootstrap-first','first')
 refused(lambda:q.dispatch(operation,'first'))
 need(q.unknown and q.mutations[operation]['outcome']=='unknown')
 before=len(s['calls']);refused(lambda:q.dispatch(operation,'first'))
 refused(lambda:q.dispatch('bootstrap-recovery','recovery'));need(len(s['calls'])==before)
test('A06_unknown_bootstrap_never_replayed_or_compensated',lambda:unknown('bootstrap-first'))
test('A07_unknown_bootout_blocks_cold_restore',lambda:unknown('bootout-first'))
def intent_unknown():
 q,s=fixture(event_failure='mutation-intent');refused(lambda:q.dispatch('bootstrap-first','first'))
 need(q.unknown and not s['calls'] and not q.mutations['bootstrap-first']['intentPersisted']
  and not q.mutations['bootstrap-first']['dispatched'])
 refused(lambda:q.dispatch('bootstrap-first','first'));need(not s['calls'])
test('A08_intent_fsync_unknown_consumes_slot_without_dispatch',intent_unknown)
def completion_unknown():
 q,s=fixture(event_failure='mutation-complete');refused(lambda:q.dispatch('bootstrap-first','first'))
 need(q.unknown and len(s['calls'])==1 and q.mutations['bootstrap-first']['outcome']=='unknown')
 refused(lambda:q.dispatch('bootout-first','first'));need(len(s['calls'])==1)
test('A09_completion_fsync_unknown_not_reported_complete',completion_unknown)
def replay():
 q,s=fixture();q.dispatch('bootstrap-first','first');refused(lambda:q.dispatch('bootstrap-first','first'));need(len(s['calls'])==1)
test('A10_known_action_not_replayed',replay)
def namespace():
 need(core.parse_disabled(b'\ndisabled services = {\n "other.fixed.synthetic" => disabled\n}\n') is None)
 need(core.parse_disabled(('disabled services = {\n "'+core.LABEL+'" => enabled\n}\n').encode()) is False)
test('A11_actual_envelope_absence_distinct_from_enabled_literal',namespace)
result={'schema':'heptabao.preserve-absent-service-primitives-local.r1','ok':True,
 'cases':cases,'passed':len(cases),'expected':11,'actualMacLaunchdExecuted':False,
 'sourceSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'productionOrServiceActions':0}
(HERE/'preserve-absent-primitives-local-r1.result.public.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
