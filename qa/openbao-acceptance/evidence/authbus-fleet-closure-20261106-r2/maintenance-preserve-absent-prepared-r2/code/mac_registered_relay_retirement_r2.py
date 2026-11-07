#!/usr/bin/env python3
"""Finite retirement of exactly four source-bound, registered legacy relays.

Prepared actuator; no import-time or automatic execution. Every private input
comes from the same original RegisteredRelayInputs instance while its held
descriptors remain open. A numeric PID or an earlier JSON receipt cannot admit
an action. This module never sends an application signal, rewrites a plist,
deletes an old binary, or restores an old publishing service after rotation.
"""
from __future__ import annotations
import copy
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import time

from mac_registered_relays_r1 import RegisteredRelayInputs,DOMAIN,HOME,LABELS,STABLE_PRINT,identity

class RelayRetirementRefused(RuntimeError):pass
def need(value,code):
 if not value:raise RelayRetirementRefused(code)
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def safe_command(value):
 names=('label','pid','exitCode','completeBeforeDeadline','elapsedSeconds','errorType','errorCode',
  'cleanup','stdoutBytes','stderrBytes','streamsClosed','outcomeUnknown')
 return {key:copy.deepcopy(value[key]) for key in names if key in value}

class RegisteredRelayRetirement:
 def __init__(self,*,inputs,commands,reader,bsd_info,parse_print,parse_disabled,missing_service,
              until,source_fence,private_write,clock=time.monotonic):
  need(type(inputs) is RegisteredRelayInputs and inputs.transferred and not inputs.closed
   and not inputs.failed and inputs.packet is not None and inputs.report['ok'] is True,
   'relay_retirement_actual_original_held_inputs')
  need(commands is inputs.commands and reader is inputs.reader and inputs.parent_until==until
   and inputs.until==until and clock()<until<=clock()+600,
   'relay_retirement_same_original_parent_and_budget')
  need(all(callable(value) for value in (parse_print,parse_disabled,missing_service,source_fence,private_write)),
   'relay_retirement_source_bound_functions')
  self.inputs,self.commands,self.reader,self.bsd_info=inputs,commands,reader,bsd_info
  self.parse_print,self.parse_disabled,self.missing_service=parse_print,parse_disabled,missing_service
  self.until,self.source_fence,self.private_write,self.clock=until,source_fence,private_write,clock
  self.actions=[];self.commands_public=[];self.phase='new';self.unknown=False;self.blocked=False;self.closed=False
  self.retired=[];self.restored=[];self.parking=None
  self.launchagents_snapshot=None
  self.report={'schema':'heptabao.fixed-four-relay-retirement.public.r2','ok':False,
   'phase':'new','actions':self.actions,'commands':self.commands_public,
   'maximumOriginalServiceActions':8,'disabledOverrideMutations':0,'originalApplicationSignals':0,
   'oldBinariesPlistsOrConfigurationDeleted':False,'credentialDatabaseReads':0,
   'automaticRetry':False,'automaticCompensation':False,
   'oldRelayRestartAfterProviderDispatchAllowed':False,
   'originalDisabledOverrideAbsencePreserved':False,
   'productionRollbackQualified':False,'allConsumersQuiesced':False,
   'sourceValuesArgumentsEnvironmentOrDigestsPublished':False}

 def within(self):
  need(not self.closed and not self.unknown and not self.blocked and self.clock()<self.until,
   'relay_retirement_known_original_lifetime')
  return self.until-self.clock()
 def _write(self,name,value):
  need(type(name) is str and re.fullmatch(r'[a-z0-9.-]{1,140}',name) is not None,
   'relay_retirement_fixed_private_output_name')
  raw=value if isinstance(value,bytes) else encoded(value)
  need(len(raw)<=2*1048576,'relay_retirement_bounded_private_record')
  try:self.private_write(name,raw)
  except BaseException:self.unknown=True;raise
 def _command(self,label,argv):
  self.within();self.source_fence()
  need(len(self.commands_public)<(3*96+64)*6,'relay_retirement_finite_readonly_and_action_helpers')
  ordinal=len(self.commands_public)
  try:
   row,out,err=self.commands.run(label,argv,until=min(self.until,self.clock()+8),maximum=262144)
  except BaseException:self.unknown=True;raise
  self.commands_public.append(safe_command(row))
  self._write('relay-retire-command-%03d.record.private.json'%ordinal,row)
  self._write('relay-retire-command-%03d.stdout.private'%ordinal,out)
  self._write('relay-retire-command-%03d.stderr.private'%ordinal,err)
  if row.get('outcomeUnknown') is not False or row.get('completeBeforeDeadline') is not True:
   self.unknown=True;raise RelayRetirementRefused('relay_retirement_original_helper_unknown')
  need(type(row.get('exitCode')) is int and type(out) is bytes and type(err) is bytes,
   'relay_retirement_exact_original_helper_result')
  self.within();return row,out,err
 def _disabled(self,slot):
  row,out,err=self._command('relay-retire-disabled',['/bin/launchctl','print-disabled',DOMAIN])
  need(row['exitCode']==0 and not err,'relay_retirement_complete_disabled_observation')
  value=self.parse_disabled(out,LABELS[slot])
  need(value is None or type(value) is bool,'relay_retirement_three_state_override')
  return value
 def _query(self,slot):
  label=LABELS[slot];target=DOMAIN+'/'+label
  row,out,err=self._command('relay-retire-label',['/bin/launchctl','print',target])
  if self.missing_service(row['exitCode'],out,err,label):return None
  need(row['exitCode']==0 and not err,'relay_retirement_complete_selected_registration')
  return self.parse_print(out,target)
 def _related(self,slot):
  row,out,err=self._command('relay-retire-related',['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='])
  need(row['exitCode']==0 and not err,'relay_retirement_complete_process_metadata')
  record=self.inputs.packet['registrations'][slot]
  originals=record['originalFamilies'];pids=set(originals);groups={value['pgid'] for value in originals.values()}
  result=[]
  for line in out.decode('ascii','strict').splitlines():
   fields=line.split()
   need(len(fields)==5 and all(value.isdecimal() for value in fields[:3])
    and (fields[3].isdecimal() or fields[3]=='-2'),'relay_retirement_typed_ps_fields')
   pid,parent,group,uid=map(int,fields[:4])
   if pid in pids or parent in pids or group in groups:
    result.append({'pid':pid,'ppid':parent,'pgid':group,'uid':uid,'state':fields[4]})
  return result
 def _pid_absent(self,pid):
  info=self.bsd_info();ctypes.set_errno(0)
  count=self.reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
  return count==0 and ctypes.get_errno()==errno.ESRCH
 def _same_running(self,slot):
  self.within();record=self.inputs.packet['registrations'][slot]
  current=self._query(slot)
  need(current is not None and all(current.get(key)==record['loadedSecond'].get(key) for key in STABLE_PRINT),
   'relay_retirement_same_original_registration')
  self.inputs._verify_family(record['originalFamilies'],record['originalChildRelations'])
  related=self._related(slot);originals=record['originalFamilies']
  need({value['pid'] for value in related}==set(originals)
   and all(all(value[key]==originals[value['pid']][key] for key in ('pid','ppid','pgid','uid')) for value in related),
   'relay_retirement_exact_original_groups_and_children')
  return True
 def _sources(self):
  self.within()
  if self.parking is None:self.inputs.verify_sources()
  else:self.parking.verify()
  need(len(self.inputs.packet['registrations'])==4 and all(
   value['label']==LABELS[slot] and value['target']==DOMAIN+'/'+LABELS[slot]
   for slot,value in enumerate(self.inputs.packet['registrations'])),
   'relay_retirement_exact_fixed_four_packet')
 def _launchagents_snapshot(self):
  self.within();path=HOME/'Library/LaunchAgents'
  parent_rows=[]
  for plist in self.inputs.plists:
   matches=[row for row in plist.rows if row['path']==path]
   need(len(matches)==1 and not matches[0]['closeAttempts'],
    'relay_retirement_original_launchagents_descriptor')
   parent_rows.append(matches[0])
  before=identity(os.fstat(parent_rows[0]['fd']))
  need(before==identity(path.lstat()) and all(identity(os.fstat(row['fd']))==before for row in parent_rows),
   'relay_retirement_same_original_launchagents_named_directory')
  names=sorted(os.listdir(parent_rows[0]['fd']))
  need(len(names)<=1024 and all(type(name) is str and 0<len(name.encode())<=255
   and name not in ('.','..') and '/' not in name and '\0' not in name for name in names),
   'relay_retirement_bounded_launchagents_metadata_inventory')
  entries={}
  for name in names:
   self.within()
   entries[name]=identity(os.stat(name,dir_fd=parent_rows[0]['fd'],follow_symlinks=False))
  need(sorted(os.listdir(parent_rows[0]['fd']))==names
   and before==identity(path.lstat())
   and all(identity(os.fstat(row['fd']))==before for row in parent_rows),
   'relay_retirement_complete_stable_launchagents_metadata_inventory')
  return {'directoryFull9':before,'entries':entries}
 def bind(self):
  need(self.phase=='new' and not self.actions,'relay_retirement_original_binding_once')
  self.phase='binding';self._sources();self.inputs.verify()
  for slot,record in enumerate(self.inputs.packet['registrations']):
   need(record['registeredProgramResolvesToKernelImage'] is True
    and record['plist'].get('AbandonProcessGroup',False) is False
    and record['plist'].get('KeepAlive') is True
    and record['originalDisabledOverride'] is None and record['originalPlistDisabled'] is False,
    'relay_retirement_direct_registered_image_and_group_retirement')
   need(self._disabled(slot) is record['originalDisabledOverride'],
    'relay_retirement_same_original_override_including_absence')
   self._same_running(slot)
  # All four exact restore packets were durably published by the producer
  # before this second complete admission. Nothing has been disabled yet.
  self._write('four-relay-before-first-action.private.json',self.inputs.packet)
  self.launchagents_snapshot=self._launchagents_snapshot()
  need('ai.openclaw.gateway.plist' in self.launchagents_snapshot['entries'],
   'relay_retirement_original_gateway_entry_in_held_directory')
  self._write('four-relay-launchagents-before.private.json',self.launchagents_snapshot)
  self.phase='bound';self.report['allFourRestoreInputsDurableBeforeAnyAction']=True
  return self
 def _intent(self,slot,operation):
  self.within();self.source_fence();self._sources()
  need(0<=slot<4 and operation in ('bootout','bootstrap-original-before-provider')
   and len(self.actions)<8 and not any(value['ordinal']==slot and value['operation']==operation for value in self.actions),
   'relay_retirement_exact_ordinal_and_once_operation')
  if operation=='bootout':
   need(slot==len(self.retired) and self.phase=='retiring','relay_retirement_original_next_bootout')
  else:
   need(slot==len(self.restored) and self.phase=='restoring-original'
    and self.parking is not None and self.parking.phase=='restored',
    'relay_retirement_only_explicit_known_pre_provider_restore')
  value={'ordinal':slot,'operation':operation,'intentDurable':False,'outcome':'UNKNOWN'}
  self.actions.append(value)
  self._write('relay-%02d-%s-intent.private.json'%(slot+1,operation),
   {'ordinal':slot,'operation':operation,'target':DOMAIN+'/'+LABELS[slot],
    'originalFamilies':self.inputs.packet['registrations'][slot]['originalFamilies']})
  value['intentDurable']=True
  return value
 def _dispatch(self,slot,operation):
  row=self._intent(slot,operation)
  try:
   result,_out,err=self._command('relay-retire-'+operation,
    ['/bin/launchctl',operation,DOMAIN+'/'+LABELS[slot]])
   need(result['exitCode']==0 and not err,'relay_retirement_original_service_action_known_zero')
   self._write('relay-%02d-%s-complete.private.json'%(slot+1,operation),
    {'ordinal':slot,'operation':operation,'originalCommand':result})
   row['outcome']='COMPLETE'
  except BaseException:self.unknown=True;raise
 def _known_absence(self,slot):
  record=self.inputs.packet['registrations'][slot]
  return self._query(slot) is None and all(self._pid_absent(pid) for pid in record['originalFamilies']) and not self._related(slot)
 def retire_next(self):
  need(self.phase in ('bound','retiring') and len(self.retired)<4 and self.parking is not None,
   'relay_retirement_next_fixed_ordinal_and_five_plists_bound')
  slot=len(self.retired);self.phase='retiring'
  try:
   self._sources()
   for previous in self.retired:self.verify_one_retired(previous)
   for remaining_slot in range(slot,4):self._same_running(remaining_slot)
   need(self._disabled(slot) is None,'relay_retirement_original_override_absent_before_action')
   self._same_running(slot);self._dispatch(slot,'bootout')
   deadline=min(self.until,self.clock()+15)
   while not self._known_absence(slot):
    need(self.clock()<deadline,'relay_retirement_original_family_absence_deadline')
    time.sleep(min(0.1,max(0,deadline-self.clock())))
   rounds=[]
   for number in range(2):
    need(self._disabled(slot) is None and self._known_absence(slot),
     'relay_retirement_two_complete_preserved_absence_rounds')
    rounds.append({'round':number,'disabledOverrideAbsent':True,'exactLabelAbsent':True,
     'allOriginalPidsEsrch':True,'allOriginalGroupsAndDirectChildrenAbsent':True})
    if number==0:time.sleep(min(0.15,self.within()))
   self._sources()
   self._write('relay-%02d-retired.private.json'%(slot+1),{'ordinal':slot,'rounds':rounds})
   self.retired.append(slot)
   self.report.setdefault('retiredRegistrations',[]).append({'ordinal':slot,'rounds':rounds,
    'originalPlistAndExecutableRetainedUnchanged':True,'oldPublishingServiceRestarted':False})
   if len(self.retired)==4:
    self.phase='retired';self.verify_retired();self.report['ok']=True
   return slot
  except BaseException:self.blocked=True;raise
 def verify_one_retired(self,slot):
  self.within();need(slot in self.retired,'relay_retirement_known_original_retired_ordinal')
  need(self._disabled(slot) is None and self._known_absence(slot),
   'relay_retirement_override_still_absent_and_original_family_absent')
  return True
 def verify_retired(self):
  need(self.phase=='retired' and self.retired==list(range(4)),
   'relay_retirement_four_original_registrations_known_closed')
  self._sources()
  row,out,err=self._command('relay-retire-all-disabled',['/bin/launchctl','print-disabled',DOMAIN])
  need(row['exitCode']==0 and not err and all(self.parse_disabled(out,label) is None for label in LABELS),
   'relay_retirement_four_original_overrides_remain_absent')
  originals={}
  for slot,record in enumerate(self.inputs.packet['registrations']):
   need(self._query(slot) is None and all(self._pid_absent(pid) for pid in record['originalFamilies']),
    'relay_retirement_four_labels_and_original_pids_absent')
   originals.update(record['originalFamilies'])
  row,out,err=self._command('relay-retire-all-related',['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='])
  need(row['exitCode']==0 and not err,'relay_retirement_complete_union_process_rows')
  pids=set(originals);groups={value['pgid'] for value in originals.values()}
  for line in out.decode('ascii','strict').splitlines():
   fields=line.split()
   need(len(fields)==5 and all(value.isdecimal() for value in fields[:3])
    and (fields[3].isdecimal() or fields[3]=='-2'),'relay_retirement_typed_union_ps_fields')
   pid,parent,group=map(int,fields[:3])
   need(pid not in pids and parent not in pids and group not in groups,
    'relay_retirement_all_original_groups_and_direct_children_absent')
  self.report['fourRegisteredLegacyRelaysRetired']=True
  self.report['originalDisabledOverrideAbsencePreserved']=True
  return True
 def restore_originals_before_any_provider(self,parent):
  from mac_owned_refresh_parent_r2 import OwnedRefreshParent
  need(type(parent) is OwnedRefreshParent and parent.maintenance is self.parking.gateway
   and parent.until==self.until and self.phase=='retired' and not self.restored
   and self.parking is not None and self.parking.phase=='restored',
   'relay_original_restore_only_same_parent_before_any_provider_attempt')
  parent.assert_no_provider_dispatch();self.verify_retired();self.phase='restoring-original'
  try:
   for slot in range(4):
    parent.assert_no_provider_dispatch();self._sources()
    need(self._disabled(slot) is None and self._known_absence(slot),
     'relay_original_restore_absent_before_bootstrap')
    action=self._intent(slot,'bootstrap-original-before-provider')
    result,_out,err=self._command('relay-restore-original',
     ['/bin/launchctl','bootstrap',DOMAIN,self.inputs.packet['registrations'][slot]['plistPath']])
    need(result['exitCode']==0 and not err,'relay_original_restore_known_bootstrap_zero')
    self._write('relay-%02d-bootstrap-original-before-provider-complete.private.json'%(slot+1),
     {'ordinal':slot,'originalCommand':result})
    action['outcome']='COMPLETE'
    deadline=min(self.until,self.clock()+15);current=None
    while True:
     current=self._query(slot)
     if current is not None and current.get('state')=='running' and type(current.get('pid')) is int:break
     need(self.clock()<deadline,'relay_original_restore_startup_budget')
     time.sleep(min(.1,max(0,deadline-self.clock())))
    record=self.inputs.packet['registrations'][slot];old=record['loadedSecond']
    need(all(current.get(key)==old.get(key) for key in ('path','program','arguments')),
     'relay_original_restore_exact_registered_configuration')
    family,relations=self.inputs._family(current['pid'])
    root=family[current['pid']]
    need(current['pid'] not in record['originalFamilies']
     and root['executable']==record['originalExecutable']['path']
     and root not in record['originalFamilies'].values(),
     'relay_original_restore_fresh_complete_birth_same_image')
    for number in range(2):
     parent.assert_no_provider_dispatch();self._sources()
     need(self._disabled(slot) is None and self._query(slot)==current,
      'relay_original_restore_two_same_registration_absent_override')
     self.inputs._verify_family(family,relations)
     if number==0:time.sleep(min(.15,self.within()))
    self._write('relay-%02d-original-restored.private.json'%(slot+1),
     {'ordinal':slot,'actualRegistration':current,'actualFamily':family,'relations':relations,
      'originalOverrideAbsent':True,'credentialOrProviderLivenessClaimed':False})
    self.restored.append(slot)
   self.phase='originals-restored-before-provider'
   self.report['knownOriginalRegistrationRestoredBeforeProviderCount']=4
  except BaseException:self.unknown=self.blocked=True;raise
 def close(self):
  self.closed=True
  self.report.update(phase=self.phase,unknown=self.unknown,operationGraphBlocked=self.blocked,
   retiredCount=len(self.retired),originalServiceActionCount=len(self.actions),
   anyLegacyRelayMayRemainStopped=bool(self.actions) and len(self.restored)<4,
   originalDisabledNamespaceMutated=False,
   automaticRestoreAttempted=False,sourceDescriptorsOwnedByOriginalInputs=True)
  if self.unknown or self.blocked:self.report['ok']=False
  return copy.deepcopy(self.report)
