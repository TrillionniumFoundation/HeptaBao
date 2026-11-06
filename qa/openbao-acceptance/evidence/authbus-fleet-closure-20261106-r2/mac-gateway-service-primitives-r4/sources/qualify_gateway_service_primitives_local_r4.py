#!/usr/bin/env python3
"""Pure action-latch and selected-label parser cases, not launchd execution."""
import hashlib,importlib.util,json,time
from pathlib import Path

BASE=Path(__file__).resolve().parent;source=BASE/'mac_gateway_service_primitives_r4.py'
spec=importlib.util.spec_from_file_location('gateway_service_primitives',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
report={'schema':'heptabao.gateway-service-primitives-pure-guards.r4','ok':False,
 'actualLaunchdExecuted':False,'productionActions':0,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'cases':[]}
def check(name,fn):
 fn();report['cases'].append({'case':name,'passed':True})
def require(v):
 if not v:raise AssertionError('case_failed')
def refusal(fn):
 try:fn()
 except m.Refused:return
 raise AssertionError('expected_refusal')
def mapping(value=None,wrapped=False):
 body='disabled services = {\n'
 if value is not None:body+='    "'+m.LABEL+'" => '+value+'\n'
 body+='}\n'
 return (m.DOMAIN+' = {\n'+body+'}\n' if wrapped else body).encode()
def fixture(*,unknown_at=None):
 q=m.Qualification.__new__(m.Qualification)
 state={'registered':False,'disabled':None,'calls':[],'events':[]}
 q.commands=None;q.reader=None;q.until=time.monotonic()+5;q.runtime_fence=lambda:None
 q.check_root=lambda:None;q.check_plist=lambda generation:None
 q.unknown=False;q.finished=False;q.mutations={};q.generation_closed=set();q.active_generation=None
 q.plists={key:{'path':str(m.ROOT/(key+'.plist'))} for key in ('first','recovery')}
 q.query=lambda generation=None: {} if state['registered'] else None
 q.disabled=lambda:state['disabled']
 q.same_running=lambda generation:require(state['registered'])
 q.event=lambda kind,value:state['events'].append((kind,value))
 def command(label,argv):
  state['calls'].append((label,list(argv)))
  if label==unknown_at:raise RuntimeError('synthetic_original_helper_unknown')
  if label.startswith('bootstrap-'):state['registered']=True
  elif label.startswith('bootout-'):state['registered']=False
  elif label=='disable':state['disabled']=True
  elif label=='enable':state['disabled']=False
  return {'exitCode':0},b'',b''
 q.command=command
 return q,state
check('P01_plain_absent_mapping',lambda:require(m.parse_disabled(mapping()) is None))
check('P02_plain_disabled_true',lambda:require(m.parse_disabled(mapping('true')) is True))
check('P03_wrapped_explicit_false',lambda:require(m.parse_disabled(mapping('false',True)) is False))
check('P04_other_labels_do_not_grant_target_state',lambda:require(m.parse_disabled(b'disabled services = {\n "org.synthetic.other" => true\n}\n') is None))
check('P05_duplicate_target_refused',lambda:refusal(lambda:m.parse_disabled(b'disabled services = {\n'+(' "'+m.LABEL+'" => false\n').encode()*2+b'}\n')))
check('P06_numeric_false_not_boolean',lambda:refusal(lambda:m.parse_disabled(mapping('0'))))
check('P07_wrong_wrapped_domain_refused',lambda:refusal(lambda:m.parse_disabled(mapping('false',True).replace(b'gui/501',b'gui/502'))))
check('P08_trailing_unparsed_record_refused',lambda:refusal(lambda:m.parse_disabled(mapping()+b'unparsed\n')))
def complete():
 q,s=fixture()
 q.dispatch('bootstrap-first','first');q.dispatch('disable','first');q.dispatch('bootout-first','first')
 q.generation_closed.add('first');q.dispatch('enable');q.dispatch('bootstrap-recovery','recovery');q.dispatch('bootout-recovery','recovery')
 require(tuple(q.mutations)==m.GRAPH and len(s['calls'])==6 and all(x['outcome']=='complete' for x in q.mutations.values()))
 require(not s['registered'] and s['disabled'] is False)
check('P09_six_exact_original_actions_complete_in_order',complete)
def replay():
 q,s=fixture();q.dispatch('bootstrap-first','first');refusal(lambda:q.dispatch('bootstrap-first','first'));require(len(s['calls'])==1)
check('P10_completed_action_not_replayed',replay)
def unknown():
 q,s=fixture(unknown_at='bootstrap-first')
 try:q.dispatch('bootstrap-first','first')
 except RuntimeError:pass
 else:raise AssertionError('unknown_missing')
 require(q.unknown and q.mutations['bootstrap-first']['outcome']=='unknown')
 refusal(lambda:q.dispatch('bootstrap-first','first'));refusal(lambda:q.dispatch('disable','first'))
 require(len(s['calls'])==1)
check('P11_unknown_original_stops_all_later_mutations',unknown)
def order():
 q,s=fixture();refusal(lambda:q.dispatch('enable'));require(not s['calls'] and not q.mutations)
check('P12_out_of_order_enable_cannot_dispatch',order)
def no_absence():
 q,s=fixture();q.dispatch('bootstrap-first','first');q.dispatch('disable','first');q.dispatch('bootout-first','first')
 refusal(lambda:q.dispatch('enable'));require(len(s['calls'])==3)
check('P13_enable_requires_completed_original_absence',no_absence)
def privacy():
 original={'argv':['/bin/launchctl','print-disabled',m.DOMAIN],'stdoutSha256':'not-public','stderrSha256':'not-public','exitCode':0}
 p=m.safe_command_public(original)
 require('stdoutSha256' not in p and 'stderrSha256' not in p and p['fullDisabledDomainOutputAndDigestsWithheld'])
 require(original['stdoutSha256']=='not-public')
check('P14_full_domain_output_digests_only_private',privacy)
check('P15_actual_leading_blank_and_enabled_literal',lambda:require(m.parse_disabled(b'\n'+mapping('enabled')) is False))
check('P16_actual_disabled_literal_true',lambda:require(m.parse_disabled(b'\n'+mapping('disabled')) is True))
check('P17_boundary_blank_lines_only',lambda:require(m.parse_disabled(b' \n'+mapping('enabled')+b'\t\n') is False))
check('P18_trailing_nonblank_record_refused',lambda:refusal(lambda:m.parse_disabled(b'\n'+mapping('enabled')+b'junk\n')))
check('P19_two_mappings_on_one_line_refused',lambda:refusal(lambda:m.parse_disabled(b'disabled services = {\n'+(' "'+m.LABEL+'" => enabled "other" => disabled\n').encode()+b'}\n')))
check('P20_unobserved_comma_separator_refused',lambda:refusal(lambda:m.parse_disabled(mapping('enabled,'))))
check('P21_unknown_status_literal_refused',lambda:refusal(lambda:m.parse_disabled(mapping('enable'))))
report.update(ok=True,executed=len(report['cases']),passed=len(report['cases']))
value=json.dumps(report,sort_keys=True)+'\n';(BASE/'gateway-service-primitives-local-r4.result.public.json').write_text(value);print(value,end='')
