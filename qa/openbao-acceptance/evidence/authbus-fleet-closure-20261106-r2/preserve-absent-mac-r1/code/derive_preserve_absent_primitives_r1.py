#!/usr/bin/env python3
"""Derive the concrete four-action, KeepAlive=true, preserve-absence fixture."""
import ast,difflib,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
old=(HERE/'mac_gateway_service_primitives_r4.py').read_text()
assert sha(old.encode())=='0f9f7fe2c3293c8790ca6e906906e7ce6797b382a1b314569fd33acecc0fb652'
source=old
def replace(a,b):
 global source
 assert source.count(a)==1,(a,source.count(a))
 source=source.replace(a,b)
replace('"""Six once-only launchd primitives for one new, credential-free QA label.\n\nThis is not a production gateway controller. Its sleep service has KeepAlive\nfalse and a finite natural lifetime. Effective disabled state, not the absence\nof a persisted false override entry, is the restoration claim.\n"""',
 '"""Four once-only actions preserve an absent disabled override.\n\nOne new credential-free label uses KeepAlive=true and the same original plist\nfor both cold generations. No disable/enable command is available. Unknown\nstate dispatches no compensation; a remaining KeepAlive registration is\nreported and requires reconciliation of its original identity. This is not a\nproduction gateway, cold-credential-consumption, or full-state rollback proof.\n"""')
replace("heptabao-authbus-gateway-service-primitives-20261106-r4","heptabao-authbus-preserve-absent-20261106-r1")
replace("org.heptabao.qa.gateway-maintenance-actions-20261106-r4","org.heptabao.qa.preserve-absent-20261106-r1")
replace("GRAPH=('bootstrap-first','disable','bootout-first','enable','bootstrap-recovery','bootout-recovery')",
 "GRAPH=('bootstrap-first','bootout-first','bootstrap-recovery','bootout-recovery')")
replace("self.active_generation=None;self.unknown=False;self.finished=False;self.generation_closed=set()",
 "self.active_generation=None;self.unknown=False;self.finished=False;self.generation_closed=set();self.disabled_observations=[]")
replace("'heptabao.mac-gateway-service-primitives.r4'","'heptabao.mac-preserve-absent-service-primitives.r1'")
replace("'keepAliveFalseSyntheticServiceOnly':True","'keepAliveTrueSyntheticServiceOnly':True")
replace("'effectiveDisabledStateRestorationOnly':True", "'disableOrEnableActionPermitted':False,'disabledOverrideObservations':self.disabled_observations")
replace("  return parse_disabled(out)","  value=parse_disabled(out);self.disabled_observations.append(value)\n  need(value is None,'original_disabled_override_stays_absent')\n  return value")
replace("'six_action_graph_order'","'four_preserve_absence_action_graph_order'")
replace("self.disabled() in (None,False)","self.disabled() is None")
replace("   self.check_plist(generation);argv=['/bin/launchctl','bootstrap',DOMAIN,self.plists[generation]['path']]",
 "   need(operation!='bootstrap-recovery' or 'first' in self.generation_closed,\n    'recovery_requires_two_round_original_generation_absence')\n   self.check_plist(generation);argv=['/bin/launchctl','bootstrap',DOMAIN,self.plists[generation]['path']]")
replace("  elif operation=='disable':\n   need(generation=='first' and self.disabled() is None,'disable_only_new_initially_unoverridden_label');self.same_running(generation)\n   argv=['/bin/launchctl','disable',TARGET]\n  elif operation.startswith('bootout-'):\n   need(generation in self.plists,'fixed_bootout_generation');self.same_running(generation)\n   argv=['/bin/launchctl','bootout',TARGET]\n  else:\n   need(operation=='enable' and 'first' in self.generation_closed and self.query() is None and self.disabled() is True,\n    'enable_only_after_disabled_generation_absence')\n   argv=['/bin/launchctl','enable',TARGET]",
 "  else:\n   need(operation.startswith('bootout-') and generation in self.plists and self.disabled() is None,\n    'bootout_exact_original_generation_without_disabled_override')\n   self.same_running(generation);argv=['/bin/launchctl','bootout',TARGET]")
replace("  self.event('mutation-intent',{'operation':operation,'argv':argv,'generation':generation})\n  self.mutations[operation]={'intentPersisted':True,'dispatched':True,'outcome':'unknown'}\n  try:\n   row,out,err=self.command(operation,argv)",
 "  self.mutations[operation]={'intentPersisted':False,'dispatched':False,'outcome':'unknown'}\n  try:\n   self.event('mutation-intent',{'operation':operation,'argv':argv,'generation':generation})\n   self.mutations[operation]['intentPersisted']=True\n   self.mutations[operation]['dispatched']=True\n   row,out,err=self.command(operation,argv)")
replace("  self.mutations[operation]['outcome']='complete';self.mutations[operation]['exitCode']=row['exitCode']\n  self.event('mutation-complete',{'operation':operation,'generation':generation,'exitCode':row['exitCode']})",
 "  try:self.event('mutation-complete',{'operation':operation,'generation':generation,'exitCode':row['exitCode']})\n  except BaseException:self.unknown=True;raise\n  self.mutations[operation]['outcome']='complete';self.mutations[operation]['exitCode']=row['exitCode']")
replace("   need(self.query() is None and self.process_absent(process['pid']) and not self.rows(process['pid']),",
 "   need(self.disabled() is None and self.query() is None and self.process_absent(process['pid']) and not self.rows(process['pid']),")
replace("rounds.append({'round':number,'labelAbsent':True,'originalPidEsrch':True,'relatedRowsEmpty':True})",
 "rounds.append({'round':number,'labelAbsent':True,'originalPidEsrch':True,'relatedRowsEmpty':True,'disabledOverrideAbsent':True})")
start=source.index('  for generation in (\'first\',\'recovery\'):',source.index(' def run(self):'))
end=source.index('  return self.report',start)
source=source[:start]+'''  p=ROOT/'original-service.plist'
  raw=plistlib.dumps({'Label':LABEL,'ProgramArguments':ARGS,'RunAtLoad':True,'KeepAlive':True,
   'WorkingDirectory':str(ROOT),'StandardOutPath':str(ROOT/'service.stdout.private'),
   'StandardErrorPath':str(ROOT/'service.stderr.private')},fmt=plistlib.FMT_XML,sort_keys=True)
  self.write(p.name,raw);original_identity=identity(p.lstat())
  for generation in ('first','recovery'):
   self.plists[generation]={'path':str(p),'raw':raw,'identity':original_identity}
  self.dispatch('bootstrap-first','first');first=self.bind_running('first')
  need(self.disabled() is None,'first_running_override_absent')
  self.dispatch('bootout-first','first');self.absence('first')
  need(self.disabled() is None,'first_retired_override_absent')
  self.check_plist('first');self.check_plist('recovery')
  self.dispatch('bootstrap-recovery','recovery');second=self.bind_running('recovery')
  need(first['pid']!=second['pid'] and (first['birthSec'],first['birthUsec'])!=(second['birthSec'],second['birthUsec']),
   'new_recovery_process_birth')
  need(self.disabled() is None,'cold_restored_override_absent')
  self.check_plist('first');self.check_plist('recovery')
  self.dispatch('bootout-recovery','recovery');self.absence('recovery')
  need(self.disabled() is None,'final_original_override_absent');self.runtime_fence();self.remaining()
  need(tuple(self.mutations)==GRAPH and all(x['outcome']=='complete' for x in self.mutations.values()),
   'all_four_original_mutations_known')
  need(self.disabled_observations and all(value is None for value in self.disabled_observations),
   'all_actual_disabled_override_observations_absent')
  self.finished=True;self.report.update(ok=True,allFourOriginalMutationsKnown=True,allOwnedServiceGenerationsAbsent=True,
   sameOriginalPlistWholeBytesAndFull9ColdRestored=True,originalKeepAliveTrue=True,
   originalOverrideAbsencePreserved=True,disabledNamespaceEntryCreated=False,
   productionGatewayOrRollbackQualified=False)
''' +source[end:]
compile(source,'mac_gateway_preserve_absent_primitives_r1.py','exec')
(HERE/'mac_gateway_preserve_absent_primitives_r1.py').write_text(source)
old_template=(HERE/'launch_gateway_service_primitives_r4.template.py').read_text()
template=old_template.replace('heptabao-authbus-gateway-service-primitives-20261106-r4','heptabao-authbus-preserve-absent-20261106-r1')
template=template.replace('mac_gateway_service_primitives_r4','mac_gateway_preserve_absent_primitives_r1')
template=template.replace('heptabao.actual-mac-gateway-service-primitives-launcher.r4','heptabao.actual-mac-preserve-absent-primitives-launcher.r1')
template=template.replace('heptabao.gateway-service-primitives.payload.r4','heptabao.preserve-absent-service-primitives.payload.r1')
template=template.replace("'originalMutationsExpected':6","'originalMutationsExpected':4")
template=template.replace('Launchd owns the two finite\nsleep services.','Launchd owns the two KeepAlive=true\nsleep generations. A failed attempt can leave its original QA registration.')
compile(template,'launch_preserve_absent_primitives_r1.template.py','exec')
(HERE/'launch_preserve_absent_primitives_r1.template.py').write_text(template)
diff=''.join(difflib.unified_diff(old.splitlines(True),source.splitlines(True),fromfile='qualified-r4-core',tofile='preserve-absent-r1-core'))
diff+=''.join(difflib.unified_diff(old_template.splitlines(True),template.splitlines(True),fromfile='qualified-r4-launcher',tofile='preserve-absent-r1-launcher'))
(HERE/'preserve-absent-primitives-r1.diff').write_text(diff)
original=ast.parse((HERE/'launch_gateway_service_primitives_r4.py').read_text())
prior=ast.literal_eval(next(n.value for n in original.body if isinstance(n,ast.Assign)
 and any(isinstance(t,ast.Name) and t.id=='PAYLOAD' for t in n.targets)))
sources={name:value for name,value in prior['sources'].items() if name!='mac_gateway_service_primitives_r4.py'}
sources['mac_gateway_preserve_absent_primitives_r1.py']={'text':source,'bytes':len(source.encode()),'sha256':sha(source.encode())}
payload={'schema':'heptabao.preserve-absent-service-primitives.payload.r1','sources':sources,'parserNames':prior['parserNames']}
assert template.count('# PAYLOAD_PLACEHOLDER')==1
assembled=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD='+repr(payload))
compile(assembled,'launch_preserve_absent_primitives_r1.py','exec')
(HERE/'launch_preserve_absent_primitives_r1.py').write_text(assembled)
result={'schema':'heptabao.preserve-absent-service-primitives.prepared.public.r1','actualMacRun':False,
 'originalQualifiedHelperBytesUnchanged':True,'sameOriginalPlistForBothGenerations':True,
 'keepAliveTrue':True,'disableEnableActions':0,'originalServiceActions':4,'originalServiceGenerations':2,
 'productionServiceActions':0,'sharedSeconds':45,'supervisorSeconds':70,
 'unknownDoesNotDispatchCompensation':True,'unknownCanLeaveOriginalQaKeepAliveRegistration':True,
 'core':{'bytes':len(source.encode()),'sha256':sha(source.encode())},
 'template':{'bytes':len(template.encode()),'sha256':sha(template.encode())},
 'assembled':{'bytes':len(assembled.encode()),'sha256':sha(assembled.encode())},
 'sourcePins':{name:{k:value[k] for k in ('bytes','sha256')} for name,value in sources.items()}}
(HERE/'preserve-absent-primitives-r1.prepared.public.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
