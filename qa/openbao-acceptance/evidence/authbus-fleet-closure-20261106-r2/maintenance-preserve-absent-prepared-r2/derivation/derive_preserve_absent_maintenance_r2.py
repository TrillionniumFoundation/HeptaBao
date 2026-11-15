#!/usr/bin/env python3
"""Derive R2 from retained R1 sources; no host/service/provider execution."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = {
 'mac_gateway_writer_maintenance_r1.py':'8125b19591fc66b946c13b3230729782b1d7a3e444996583386f9d4c27bdc1a1',
 'mac_registered_relay_retirement_r1.py':'5f4223ca2a04c49411eb3b4dd0de051fb591bc549b763b2c5f59c99ab194139f',
 'mac_owned_refresh_parent_r1.py':'1327fde8f79877a6b9362b6dc2e49da628cf2d13bcfdf58f14ebcbdca65497cb',
 'mac_refresh_capture_sequence_r1.py':'b8ffa650859c9c59797dee68ae4ac84b3266634b4d60c3a227bb3aa1fcf1bf14',
 'mac_post_commit_epoch_r1.py':'ab4a64f355f3769f7ce2dcfe1a847435b11f9411d856633a25f4ce72a4daed23'}
def prior(name):
 raw=(HERE/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest()==PINS[name],name
 return raw.decode()
def replace(source,old,new,count=1):
 assert source.count(old)==count,(old[:100],source.count(old),count)
 return source.replace(old,new)
def method(source,name,new):
 tree=ast.parse(source)
 candidates=[n for c in tree.body if isinstance(c,ast.ClassDef) for n in c.body
             if isinstance(n,ast.FunctionDef) and n.name==name]
 assert len(candidates)==1,name
 n=candidates[0];lines=source.splitlines(True)
 return ''.join(lines[:n.lineno-1])+new.rstrip()+'\n'+''.join(lines[n.end_lineno:])
rows=[]
def save(old,new,source):
 ast.parse(source)
 (HERE/new).write_text(source)
 (HERE/(new+'.diff')).write_text(''.join(difflib.unified_diff(prior(old).splitlines(True),source.splitlines(True),
     fromfile='retained/'+old,tofile='prepared/'+new)))
 rows.append({'name':new,'bytes':len(source.encode()),'sha256':hashlib.sha256(source.encode()).hexdigest(),
              'priorName':old,'priorSha256':PINS[old]})

# Four observed KeepAlive=true services, original None override preserved.
old='mac_registered_relay_retirement_r1.py';r=prior(old)
r=replace(r,"self.retired=[];self.disabled_confirmed=[];self.gateway_parent_handoff=None\n  self.launchagents_snapshot=None",
 "self.retired=[];self.restored=[];self.parking=None\n  self.launchagents_snapshot=None")
r=replace(r,"heptabao.fixed-four-relay-retirement.public.r1","heptabao.fixed-four-relay-retirement.public.r2")
r=replace(r,"'maximumOriginalServiceActions':8","'maximumOriginalServiceActions':8,'disabledOverrideMutations':0")
r=replace(r,"'originalDisabledOverrideAbsenceRestored':False","'originalDisabledOverrideAbsencePreserved':False")
r=replace(r,"len(self.commands_public)<256","len(self.commands_public)<(3*96+64)*6")
r=method(r,'_sources',''' def _sources(self):
  self.within()
  if self.parking is None:self.inputs.verify_sources()
  else:self.parking.verify()
  need(len(self.inputs.packet['registrations'])==4 and all(
   value['label']==LABELS[slot] and value['target']==DOMAIN+'/'+LABELS[slot]
   for slot,value in enumerate(self.inputs.packet['registrations'])),
   'relay_retirement_exact_fixed_four_packet')
''')
r=replace(r,"and record['plist'].get('AbandonProcessGroup',False) is False,",
 "and record['plist'].get('AbandonProcessGroup',False) is False\n    and record['plist'].get('KeepAlive') is True\n    and record['originalDisabledOverride'] is None and record['originalPlistDisabled'] is False,")
r=method(r,'_intent',''' def _intent(self,slot,operation):
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
''')
r=method(r,'retire_next',''' def retire_next(self):
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
''')
r=method(r,'verify_one_retired',''' def verify_one_retired(self,slot):
  self.within();need(slot in self.retired,'relay_retirement_known_original_retired_ordinal')
  need(self._disabled(slot) is None and self._known_absence(slot),
   'relay_retirement_override_still_absent_and_original_family_absent')
  return True
''')
# One disabled read, four selected prints, one ps for the union; exact birth
# ESRCH is checked directly for each original process.
r=method(r,'verify_retired',''' def verify_retired(self):
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
''')
r=method(r,'accept_known_gateway_directory_publication',''' def restore_originals_before_any_provider(self,parent):
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
''')
r=replace(r,"anyLegacyRelayMayRemainDisabledOrStopped=bool(self.actions),",
 "anyLegacyRelayMayRemainStopped=bool(self.actions) and len(self.restored)<4,\n   originalDisabledNamespaceMutated=False,")
save(old,'mac_registered_relay_retirement_r2.py',r)

# Gateway source handoff is now private-only until the provider epoch is known.
old='mac_gateway_writer_maintenance_r1.py';g=prior(old)
g=replace(g,"SERVICE_GRAPH = ('disable', 'bootout', 'publish-safe-plist', 'enable-safe-local', 'bootstrap-safe-local')",
 "SERVICE_GRAPH = ('bootout', 'publish-safe-plist', 'bootstrap-safe-local')")
g=replace(g,"self.new_process = None","self.new_process = None\n        self.parking = None\n        self.safe_files_attempted = False")
g=replace(g,"heptabao.registered-gateway-maintenance.public.r1","heptabao.registered-gateway-maintenance.public.r2")
g=replace(g,"'originalOverrideAbsenceRestorationClaimed': False}",
 "'originalOverrideAbsencePreserved': False, 'disabledOverrideMutations': 0}")
g=replace(g,"len(self.command_rows) < 768","len(self.command_rows) < (3 * 96 + 64) * 3")
g=replace(g,"need(self.original_disabled is None or self.original_disabled is False,\n             'maintenance_original_gateway_effectively_enabled')",
 "original_plist = plistlib.loads(plist_bytes)\n        need(self.original_disabled is None and original_plist.get('Disabled', False) is False\n             and original_plist.get('KeepAlive') is True\n             and original_plist.get('AbandonProcessGroup', False) is False,\n             'maintenance_observed_keepalive_true_original_override_absent')")
g=replace(g,"('binding-original', 'original-bound', 'disabled')","('binding-original', 'original-bound')")
g=method(g,'_intent','''    def _intent(self, operation, extra=None):
        original_restore = operation == 'bootstrap-original-before-provider'
        need(not self.unknown and (operation in SERVICE_GRAPH or original_restore)
             and operation not in self.actions, 'maintenance_original_service_effect_once')
        if original_restore:
            need(tuple(self.actions) == ('bootout',)
                 and self.actions['bootout']['outcome'] == 'COMPLETE'
                 and self.phase == 'restoring-original-before-provider',
                 'maintenance_original_restore_is_separate_pre_provider_branch')
        else:
            need(len(self.actions) < len(SERVICE_GRAPH) and SERVICE_GRAPH[len(self.actions)] == operation,
                 'maintenance_fixed_post_commit_service_effect_graph')
        self.source_fence();self.within()
        row = {'attempted': True, 'intentDurable': False, 'outcome': 'UNKNOWN'}
        self.actions[operation] = row
        try:
            self._write('intent-%s.private.json' % operation,
                        {'operation': operation, 'target': TARGET, 'detail': extra})
            row['intentDurable'] = True
        except BaseException:
            self.unknown = True
            raise
        return row
''')
g=method(g,'disable','''    def prepare_safe_private_files(self):
        need(self.phase == 'original-bound' and not self.safe_files_attempted and not self.unknown,
             'maintenance_safe_private_files_prepared_before_first_service_action')
        self.safe_files_attempted = True
        try:
            self.same_original_running('before-private-fallback-preparation')
            self.selector_fence('before-private-fallback-preparation', self.safe)
            self._create_fallback_file(FALLBACK_CONFIG, self.safe['configBytes'])
            self._create_fallback_file(FALLBACK_ENVIRONMENT, self.safe['environmentBytes'])
            self._verify_fallback_files()
            self._write('safe-private-fallback-prepared.private.json',
                {'authbusExplicitlyDisabled': True, 'autoloadEntryPublished': False,
                 'configurationFull9': self.fallback_files[FALLBACK_CONFIG]['identity'],
                 'environmentFull9': self.fallback_files[FALLBACK_ENVIRONMENT]['identity']})
            self.report['safeFallbackPrivateFilesPreparedWithoutAutoload'] = True
        except BaseException:
            self.unknown = True
            raise
''')
g=method(g,'bootout','''    def bootout(self):
        need(self.phase == 'original-bound' and self.disabled() is None
             and self.parking is not None and self.parking.phase == 'bound'
             and self.parking.relays.phase == 'retired',
             'maintenance_original_bootout_after_four_known_relay_retirements')
        self.parking.verify();self.parking.relays.verify_retired()
        self._verify_fallback_files()
        self.same_original_running('before-bootout')
        self._intent('bootout')
        try:
            row, _, stderr = self._command('maintenance-bootout', ['/bin/launchctl', 'bootout', TARGET])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_original_bootout_known_zero')
            self._complete('bootout', {'exitCode': 0, 'disabledOverrideMutation': False})
            self.phase = 'quiescing'
            deadline = min(self.until, self.clock() + 15)
            while True:
                gone = self.query() is None and all(self._pid_absent(pid) for pid in self.original_rows)
                if gone and not self._related_rows():break
                need(self.clock() < deadline, 'maintenance_original_family_retirement_budget')
                time.sleep(min(0.1, deadline - self.clock()))
            self.phase = 'quiesced'
            for number in range(2):
                self.verify_quiesced('after-bootout')
                if number == 0:time.sleep(min(0.15, self.within()))
            self.report.update(originalRegisteredFamilyRetiredTwice=True,
                               originalOverrideAbsencePreserved=True)
        except BaseException:
            self.unknown = True
            raise
''')
g=method(g,'verify_quiesced','''    def verify_quiesced(self, stage):
        need(not self.unknown and self.phase in ('quiesced', 'parked-for-refresh', 'refreshing',
             'committed', 'safe-plist-published'), 'maintenance_quiesced_original_phase')
        self.within();self.source_fence()
        need(self.disabled() is None and self.query() is None
             and all(self._pid_absent(pid) for pid in self.original_rows)
             and not self._related_rows(), 'maintenance_preserved_override_absence_and_original_family_absent')
        if self.owned_refresh_child is not None:
            original = self.owned_refresh_child
            need(self.reader.read(original['pid']) == original and not self.reader.children(original['pid']),
                 'maintenance_same_original_refresh_child_before_consumer_check')
        self.consumer_fence(stage, self.original_rows, copy.deepcopy(self.owned_refresh_child))
        need(self.parking is not None, 'maintenance_concrete_original_five_plist_owner')
        self.parking.verify()
        if self.phase != 'quiesced':self.parking.verify_parked()
        self._verify_fallback_files()
        return True
''')
g=replace(g,"self.phase in ('safe-plist-published', 'refreshing')","self.phase in ('parked-for-refresh', 'refreshing')")
g=method(g,'publish_safe_plist','''    def accept_known_original_park(self, parking):
        from mac_fixed_launchagent_park_r1 import FixedLaunchAgentParking
        need(type(parking) is FixedLaunchAgentParking and parking is self.parking
             and parking.gateway is self and parking.until == self.until
             and parking.phase == 'parked' and parking.parked == list(range(5))
             and not parking.unknown and not parking.blocked and self.phase == 'quiesced',
             'maintenance_actual_five_original_inodes_known_parked')
        parking.verify_parked()
        self.phase = 'parked-for-refresh'
        self.report['fiveOriginalAutoloadEntriesParkedBeforeProvider'] = True

    def publish_safe_plist(self, *, sequence):
        from mac_refresh_capture_sequence_r2 import FreshOwnerRefreshSequence
        need(type(sequence) is FreshOwnerRefreshSequence and sequence.maintenance is self
             and sequence.until == self.until and sequence.report['ok'] is True
             and self.phase == 'committed' and self.parking is not None,
             'maintenance_actual_three_committed_before_safe_autoload')
        self.verify_quiesced('before-safe-autoload-publication')
        sequence.verify_current_epoch('before-safe-plist-intent')
        self._intent('publish-safe-plist')
        try:
            self.parking.publish_safe_gateway(sequence=sequence)
        except BaseException:
            self.unknown = True
            raise

    def accept_known_safe_autoload(self, parking):
        from mac_fixed_launchagent_park_r1 import FixedLaunchAgentParking
        need(type(parking) is FixedLaunchAgentParking and parking is self.parking
             and parking.phase == 'safe-published' and parking.safe_file is not None
             and not parking.unknown and not parking.blocked and self.phase == 'committed'
             and self.actions.get('publish-safe-plist', {}).get('outcome') == 'UNKNOWN',
             'maintenance_original_known_safe_publication_handoff')
        parking.verify_parked()
        self.safe_plist_identity = parking.safe_file['expected']
        self._read_plist(self.safe_plist_identity, self.safe['plistBytes'])
        self._verify_fallback_files()
        self.selector_fence('after-safe-plist', self.safe)
        self._complete('publish-safe-plist', {'newFull9': self.safe_plist_identity,
            'authbusExplicitlyDisabled': True, 'originalOverrideAbsent': True,
            'threeCommittedEpochRequiredBeforePublication': True})
        self.phase = 'safe-plist-published'
        self.verify_quiesced('after-safe-plist')
        self.report['persistentOriginalLabelPlistNowUsesSafeLocalConfig'] = True
''')
g=method(g,'restore_safe_local','''    def restore_safe_local(self, *, current_epoch_fence, current_baseline_fence, retired_source_resources):
        need(not self.unknown and self.phase == 'safe-plist-published'
             and callable(current_epoch_fence) and callable(current_baseline_fence),
             'maintenance_known_current_post_refresh_epoch_required')
        need(retired_source_resources.get('allOwnedResourcesClosedOnce') is True,
             'maintenance_original_source_handles_closed_before_restore')
        current_epoch_fence();current_baseline_fence()
        self.selector_fence('before-safe-restore', self.safe)
        self.verify_quiesced('before-safe-restore')
        need(self.owned_refresh_child is None, 'maintenance_no_owned_refresh_child_before_restore')
        self._read_plist(self.safe_plist_identity, self.safe['plistBytes'])
        self._verify_fallback_files()
        self._intent('bootstrap-safe-local')
        try:
            row, _, stderr = self._command('maintenance-bootstrap-safe',
                ['/bin/launchctl', 'bootstrap', DOMAIN, str(PLIST)])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_bootstrap_safe_local_known_zero')
            self._complete('bootstrap-safe-local', {'exitCode': 0})
            self.phase = 'safe-local-bootstrap-complete'
            need(self.disabled() is None, 'maintenance_original_override_absence_preserved_after_bootstrap')
            self.report.update(safeLocalBootstrapKnown=True, restoredEffectiveDisabledFalse=True,
                originalOverrideAbsencePreserved=True, gatewayRuntimeQualified=False,
                productionRollbackQualified=False)
            # The outer still must observe actual new birth/config/memory,
            # real cold consumption and the post-refresh full-state baseline.
        except BaseException:
            self.unknown = True
            raise
''')
marker='    def close(self):\n'
assert g.count(marker)==1
g=g.replace(marker,'''    def restore_original_before_any_provider(self, parent):
        from mac_owned_refresh_parent_r2 import OwnedRefreshParent
        need(type(parent) is OwnedRefreshParent and parent.maintenance is self
             and parent.until == self.until and not self.unknown
             and self.phase == 'parked-for-refresh' and self.parking is not None
             and self.parking.phase == 'restored' and self.owned_refresh_child is None,
             'maintenance_original_restore_only_before_any_provider_attempt')
        parent.assert_no_provider_dispatch()
        self.parking.verify();self.wrapper_inputs.verify()
        need(self.disabled() is None and self.query() is None
             and all(self._pid_absent(pid) for pid in self.original_rows) and not self._related_rows(),
             'maintenance_original_restore_no_original_registration_or_family')
        restored = self.parking.files[4]
        need(restored['location'] == 'restored' and restored['raw'] == self.plist_bytes,
             'maintenance_same_original_parked_inode_and_bytes_restored')
        self._read_plist(restored['expected'], self.plist_bytes)
        self.consumer_fence('before-pre-provider-original-bootstrap', self.original_rows, None)
        parent.assert_no_provider_dispatch()
        self.phase = 'restoring-original-before-provider'
        self._intent('bootstrap-original-before-provider')
        try:
            row, _, stderr = self._command('maintenance-bootstrap-original-before-provider',
                ['/bin/launchctl', 'bootstrap', DOMAIN, str(PLIST)])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_original_restore_bootstrap_known_zero')
            self._complete('bootstrap-original-before-provider', {'exitCode': 0,
                'providerAttemptCount': 0, 'originalOverrideAbsent': True})
            deadline = min(self.until, self.clock() + 15)
            while True:
                current = self.query()
                if current is not None and current.get('state') == 'running' and type(current.get('pid')) is int:
                    break
                need(self.clock() < deadline, 'maintenance_original_restore_cold_start_budget')
                time.sleep(min(.1, max(0, deadline - self.clock())))
            prior = self.binding['loadedSecond']
            need(all(current.get(key) == prior.get(key) for key in
                 ('path', 'program', 'arguments', 'observedEnvironmentScope')),
                 'maintenance_original_restored_exact_registration_configuration')
            pid = current['pid'];new = self.reader.read(pid)
            need(pid not in self.original_rows and new['uid'] == 501 and new['ppid'] == 1
                 and new['executable'] == NODE and not self.reader.children(pid),
                 'maintenance_original_restored_new_node_birth_without_unclassified_children')
            for number in range(2):
                parent.assert_no_provider_dispatch();self.parking.verify();self.wrapper_inputs.verify()
                need(self.disabled() is None and self.query() == current
                     and self.reader.read(pid) == new and not self.reader.children(pid),
                     'maintenance_original_restored_same_new_birth_twice')
                if number == 0:time.sleep(min(.15, self.within()))
            self._write('original-gateway-restored-before-provider.private.json',
                {'registration': current, 'process': new, 'originalOverrideAbsent': True,
                 'sameOriginalPlistInodeAndBytes': True, 'sourceCredentialRollbackExecuted': False})
            self.new_process = new
            self.phase = 'original-restored-before-provider'
            self.report.update(originalRegistrationRestoredBeforeAnyProviderAttempt=True,
                originalOverrideAbsencePreserved=True, gatewayRuntimeQualified=False,
                productionRollbackQualified=False)
        except BaseException:
            self.unknown = True
            raise

'''+marker)
g=replace(g,"('new', 'binding-original', 'original-bound', 'safe-local-bootstrap-complete')",
 "('new', 'binding-original', 'original-bound', 'safe-local-bootstrap-complete', 'original-restored-before-provider')")
save(old,'mac_gateway_writer_maintenance_r2.py',g)

# Keep the proven provider/CAS protocol unchanged; add a strict pre-attempt
# recovery gate and bind new service phases via the original maintenance object.
old='mac_owned_refresh_parent_r1.py';p=prior(old)
p=replace(p,"heptabao.owned-refresh-parent.public.r1","heptabao.owned-refresh-parent.public.r2")
marker='    def _ledger_commit(self, ordinal, once):\n'
assert p.count(marker)==1
p=p.replace(marker,'''    def assert_no_provider_dispatch(self):
        from mac_maintenance_private_files_r1 import MaintenancePrivateFiles
        private = getattr(self.read_private, '__self__', None)
        need(type(private) is MaintenancePrivateFiles and private.until == self.until
             and not private.closed and not private.failed and not self.closed
             and not self.attempts and not self.committed and self.maintenance.owned_refresh_child is None,
             'parent_actual_private_owner_zero_original_attempts_before_restore')
        self._within(self.until);self.source_fence()
        ledger = private.directory(LEDGER)
        need(os.listdir(ledger['fd']) == [], 'parent_fixed_once_ledger_still_empty_before_original_restore')
        private.verify_parents()
        self._within(self.until)
        return True

'''+marker)
save(old,'mac_owned_refresh_parent_r2.py',p)

old='mac_refresh_capture_sequence_r1.py';s=prior(old)
for name in ('mac_gateway_writer_maintenance','mac_owned_refresh_parent','mac_post_commit_epoch'):
 s=replace(s,name+'_r1',name+'_r2')
s=replace(s,"self.maintenance.phase in ('safe-plist-published', 'refreshing')",
 "self.maintenance.phase in ('parked-for-refresh', 'refreshing')")
s=s.replace('heptabao.main3-same-parent-fresh-clone-refresh.public.r1','heptabao.main3-same-parent-fresh-clone-refresh.public.r2')
save(old,'mac_refresh_capture_sequence_r2.py',s)

old='mac_post_commit_epoch_r1.py';e=prior(old)
e=replace(e,'from mac_owned_refresh_parent_r1 import','from mac_owned_refresh_parent_r2 import')
# New epoch source/SQL semantics and observation denominator remain unchanged.
save(old,'mac_post_commit_epoch_r2.py',e)

(HERE/'preserve-absent-maintenance-r2.derivation.public.json').write_text(json.dumps({
 'schema':'heptabao.preserve-absent-maintenance-source-derivation.r2','preparedOnly':True,
 'productionActions':0,'providerCalls':0,'retainedR1SourcesUnchanged':True,'sources':rows},sort_keys=True,indent=2)+'\n')
print(json.dumps({'ok':True,'preparedOnly':True,'sourceCount':len(rows),'sources':rows},sort_keys=True))
