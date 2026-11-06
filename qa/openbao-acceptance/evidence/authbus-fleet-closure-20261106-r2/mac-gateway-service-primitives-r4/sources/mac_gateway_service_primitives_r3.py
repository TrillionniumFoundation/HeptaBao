#!/usr/bin/env python3
"""Six once-only launchd primitives for one new, credential-free QA label.

This is not a production gateway controller. Its sleep service has KeepAlive
false and a finite natural lifetime. Effective disabled state, not the absence
of a persisted false override entry, is the restoration claim.
"""
from __future__ import annotations
import ctypes,errno,hashlib,json,os,plistlib,re,stat,time
from pathlib import Path

ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-service-primitives-20261106-r3')
DOMAIN='gui/501'
LABEL='org.heptabao.qa.gateway-maintenance-actions-20261106-r3'
TARGET=DOMAIN+'/'+LABEL
SLEEP='/bin/sleep'
ARGS=[SLEEP,'30']
GRAPH=('bootstrap-first','disable','bootout-first','enable','bootstrap-recovery','bootout-recovery')
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

class Refused(RuntimeError):pass
def need(value,code):
 if not value:raise Refused(code)
def identity(s):return tuple(getattr(s,key) for key in FIELDS)
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def parse_disabled(raw):
 """Discard all unrelated labels; accept exactly one complete domain mapping."""
 need(isinstance(raw,bytes) and len(raw)<=262144,'bounded_disabled_projection')
 lines=raw.decode('utf-8','strict').splitlines()
 if len(lines)>=2 and lines[0].strip()=='disabled services = {' and lines[-1].strip()=='}':
  body=lines[1:-1]
 elif len(lines)>=4 and lines[0].strip()==DOMAIN+' = {' and lines[1].strip()=='disabled services = {' and lines[-2].strip()=='}' and lines[-1].strip()=='}':
  body=lines[2:-2]
 else:raise Refused('exact_disabled_domain_record')
 found=None;seen=set()
 for line in body:
  match=re.fullmatch(r'\s*"([^"\x00-\x1f\x7f]{1,255})" => (true|false)\s*',line)
  need(match is not None,'typed_disabled_service_mapping')
  label,value=match.groups();need(label not in seen,'unique_disabled_service_mapping');seen.add(label)
  if label==LABEL:found=value=='true'
 return found
def safe_command_public(row):
 value=dict(row)
 if value.get('argv')==['/bin/launchctl','print-disabled',DOMAIN]:
  # The qualified helper's original record remains private. Its full-domain
  # output hash is not part of this public, selected-label projection.
  value.pop('stdoutSha256',None);value.pop('stderrSha256',None)
  value['fullDisabledDomainOutputAndDigestsWithheld']=True
 return value

class Qualification:
 def __init__(self,*,commands,reader,bsd_info,parse_print,missing_service,until,runtime_fence):
  need(os.getuid()==501 and time.monotonic()<until<=time.monotonic()+45,'one_original_service_qualification_budget')
  self.commands=commands;self.reader=reader;self.bsd_info=bsd_info;self.parse_print=parse_print
  self.missing_service=missing_service;self.until=until;self.runtime_fence=runtime_fence
  self.root_identity=identity(ROOT.lstat());self.events=[];self.mutations={};self.identities=[]
  self.active_generation=None;self.unknown=False;self.finished=False;self.generation_closed=set()
  self.plists={};self.public_commands=[]
  self.report={'schema':'heptabao.mac-gateway-service-primitives.r3','ok':False,
   'productionServiceChanged':False,'providerCalls':0,'credentialReads':0,'configurationReads':0,
   'keepAliveFalseSyntheticServiceOnly':True,'actualGatewayRegistrationQualified':False,
   'productionKeepAliveRollbackQualified':False,'fullDisabledDomainOutputPublished':False,
   'effectiveDisabledStateRestorationOnly':True,'automaticRetry':False,'events':self.events,
   'mutations':self.mutations,'serviceIdentities':self.identities,'commands':self.public_commands}
 def remaining(self,cap=45):
  left=self.until-time.monotonic();need(left>0,'original_service_primitives_deadline');return min(cap,left)
 def check_root(self):
  self.remaining();s=ROOT.lstat()
  need(stat.S_ISDIR(s.st_mode) and s.st_uid==501 and stat.S_IMODE(s.st_mode)==0o700 and identity(s)[:5]==self.root_identity[:5],
   'fixed_owned_service_root')
 def write(self,name,raw):
  self.check_root();need(isinstance(name,str) and re.fullmatch(r'[a-z0-9.-]{1,100}',name),'fixed_owned_service_artifact_name')
  need(isinstance(raw,bytes) and len(raw)<=262144,'bounded_owned_service_artifact')
  fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   view=memoryview(raw)
   while view:
    self.remaining();n=os.write(fd,view);need(n>0,'owned_service_write_progress');view=view[n:]
   os.fsync(fd)
  finally:os.close(fd)
  fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 def event(self,kind,value):
  packet={'kind':kind,'index':len(self.events),**value};self.write('%03d-%s.public.json'%(len(self.events),kind),encoded(packet));self.events.append(packet)
 def command(self,label,argv):
  self.remaining();need(len(self.public_commands)<96,'finite_service_commands')
  try:row,out,err=self.commands.run(label,argv,until=min(self.until,time.monotonic()+4),maximum=262144)
  except BaseException:self.unknown=True;raise
  self.public_commands.append(safe_command_public(row))
  # Full records and any full-domain mapping never leave the private QA root.
  self.write('command-%03d.private.json'%(len(self.public_commands)-1),encoded(row))
  if argv==['/bin/launchctl','print-disabled',DOMAIN]:
   self.write('disabled-%03d.stdout.private'%(len(self.public_commands)-1),out)
  need(isinstance(out,bytes) and isinstance(err,bytes),'original_command_bytes')
  if row['outcomeUnknown'] or not row['completeBeforeDeadline']:
   self.unknown=True;raise Refused('original_service_helper_unknown')
  self.remaining();return row,out,err
 def disabled(self):
  row,out,err=self.command('read-disabled',['/bin/launchctl','print-disabled',DOMAIN])
  need(row['exitCode']==0 and not err,'complete_disabled_projection')
  return parse_disabled(out)
 def query(self,generation=None):
  row,out,err=self.command('read-owned-label',['/bin/launchctl','print',TARGET])
  if self.missing_service(row['exitCode'],out,err,LABEL):return None
  need(row['exitCode']==0 and not err,'complete_owned_label_projection')
  value=self.parse_print(out,TARGET)
  if generation is not None:
   entry=self.plists[generation];self.check_plist(generation)
   need(value.get('path')==entry['path'] and value.get('program')==SLEEP and value.get('arguments')==ARGS
    and value.get('runs') in (0,1),'exact_synthetic_service_registration')
  return value
 def check_plist(self,generation):
  self.check_root();entry=self.plists[generation];p=Path(entry['path']);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd);need(identity(before)==entry['identity'],'same_owned_plist_identity')
   raw=os.read(fd,16385);need(len(raw)<=16384 and raw==entry['raw'] and identity(os.fstat(fd))==identity(p.lstat())==entry['identity'],
    'same_owned_plist_complete_bytes')
  finally:os.close(fd)
 def rows(self,pid):
  row,out,err=self.command('read-related-processes',['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,stat='])
  need(row['exitCode']==0 and not err,'complete_related_process_projection');found=[]
  for line in out.decode('ascii','strict').splitlines():
   fields=line.split();need(len(fields)==5 and all(x.isdecimal() for x in fields[:3]) and
    (fields[3].isdecimal() or fields[3]=='-2'),'typed_process_metadata')
   process,parent,group,uid=map(int,fields[:4])
   if pid in (process,parent,group):found.append({'pid':process,'ppid':parent,'pgid':group,'uid':uid,'state':fields[4]})
  return found
 def process_absent(self,pid):
  info=self.bsd_info();ctypes.set_errno(0)
  size=self.reader.lib.proc_pidinfo(pid,3,0,ctypes.byref(info),ctypes.sizeof(info));error=ctypes.get_errno()
  return size==0 and error==errno.ESRCH
 def bind_running(self,generation):
  deadline=min(self.until,time.monotonic()+5);value=None
  while time.monotonic()<deadline:
   value=self.query(generation)
   need(value is not None,'bootstrap_registration_not_missing')
   if value.get('state')=='running' and type(value.get('pid')) is int:break
   time.sleep(min(0.1,self.remaining()))
  need(value is not None and value.get('state')=='running' and value.get('runs')==1 and type(value.get('pid')) is int,'owned_sleep_running_once')
  process=self.reader.read(value['pid'])
  need(process['uid']==501 and process['ppid']==1 and process['pgid']==process['pid'] and process['executable']==SLEEP
   and self.reader.children(process['pid'])==[],'actual_owned_sleep_birth_and_no_children')
  rows=self.rows(process['pid'])
  need(len(rows)==1 and all(rows[0][key]==process[key] for key in ('pid','ppid','pgid','uid')),'exact_single_sleep_process_group')
  need(self.reader.read(process['pid'])==process,'same_sleep_birth_after_group_read')
  entry=self.plists[generation];entry['process']=process;self.identities.append({'generation':generation,**process})
  self.active_generation=generation;self.event('running',{'generation':generation,'identity':process})
  return process
 def same_running(self,generation):
  entry=self.plists[generation];value=self.query(generation);process=entry.get('process')
  need(process is not None and value is not None and value.get('pid')==process['pid'] and value.get('state')=='running'
   and value.get('runs')==1 and self.reader.read(process['pid'])==process and self.reader.children(process['pid'])==[],
   'same_owned_running_birth_before_mutation')
  need(len(self.rows(process['pid']))==1,'same_owned_group_before_mutation')
 def dispatch(self,operation,generation=None):
  need(not self.unknown and operation in GRAPH and operation not in self.mutations,'original_service_mutation_once')
  self.runtime_fence();self.check_root()
  expected_index=len(self.mutations);need(expected_index<len(GRAPH) and GRAPH[expected_index]==operation,'six_action_graph_order')
  if operation.startswith('bootstrap-'):
   need(generation in self.plists and self.query() is None and self.disabled() in (None,False),'bootstrap_only_absent_enabled_owned_label')
   self.check_plist(generation);argv=['/bin/launchctl','bootstrap',DOMAIN,self.plists[generation]['path']]
  elif operation=='disable':
   need(generation=='first' and self.disabled() is None,'disable_only_new_initially_unoverridden_label');self.same_running(generation)
   argv=['/bin/launchctl','disable',TARGET]
  elif operation.startswith('bootout-'):
   need(generation in self.plists,'fixed_bootout_generation');self.same_running(generation)
   argv=['/bin/launchctl','bootout',TARGET]
  else:
   need(operation=='enable' and 'first' in self.generation_closed and self.query() is None and self.disabled() is True,
    'enable_only_after_disabled_generation_absence')
   argv=['/bin/launchctl','enable',TARGET]
  self.event('mutation-intent',{'operation':operation,'argv':argv,'generation':generation})
  self.mutations[operation]={'intentPersisted':True,'dispatched':True,'outcome':'unknown'}
  try:
   row,out,err=self.command(operation,argv)
   need(row['exitCode']==0 and not err,'original_service_mutation_complete_zero')
  except BaseException:self.unknown=True;raise
  self.mutations[operation]['outcome']='complete';self.mutations[operation]['exitCode']=row['exitCode']
  self.event('mutation-complete',{'operation':operation,'generation':generation,'exitCode':row['exitCode']})
 def absence(self,generation):
  process=self.plists[generation]['process'];rounds=[];deadline=min(self.until,time.monotonic()+5)
  while True:
   state=self.query();gone=self.process_absent(process['pid']);related=self.rows(process['pid'])
   if state is None and gone and not related:break
   need(time.monotonic()<deadline,'bounded_original_service_retirement_wait')
   if state is not None:
    need(state.get('path')==self.plists[generation]['path'] and state.get('program')==SLEEP and state.get('arguments')==ARGS,
     'no_replaced_label_during_retirement')
   time.sleep(min(0.1,self.remaining()))
  for number in range(2):
   need(self.query() is None and self.process_absent(process['pid']) and not self.rows(process['pid']),
    'exact_label_pid_group_and_child_absence')
   rounds.append({'round':number,'labelAbsent':True,'originalPidEsrch':True,'relatedRowsEmpty':True})
   if number==0:time.sleep(min(0.15,self.remaining()))
  self.generation_closed.add(generation);self.active_generation=None
  self.event('absence',{'generation':generation,'rounds':rounds})
 def run(self):
  self.runtime_fence();need(self.query() is None and self.disabled() is None,'new_unregistered_unoverridden_qa_label')
  for generation in ('first','recovery'):
   p=ROOT/(generation+'.plist')
   raw=plistlib.dumps({'Label':LABEL,'ProgramArguments':ARGS,'RunAtLoad':True,'KeepAlive':False,
    'WorkingDirectory':str(ROOT),'StandardOutPath':str(ROOT/(generation+'.stdout.private')),
    'StandardErrorPath':str(ROOT/(generation+'.stderr.private'))},fmt=plistlib.FMT_XML,sort_keys=True)
   self.write(p.name,raw);self.plists[generation]={'path':str(p),'raw':raw,'identity':identity(p.lstat())}
  self.dispatch('bootstrap-first','first');first=self.bind_running('first')
  self.dispatch('disable','first');need(self.disabled() is True,'disabled_effective_true')
  self.same_running('first');self.event('disable-keeps-running',{'sameOriginalBirth':True})
  self.dispatch('bootout-first','first');self.absence('first');need(self.disabled() is True,'disabled_persists_after_bootout')
  self.dispatch('enable');need(self.disabled() is False,'enabled_effective_false')
  self.dispatch('bootstrap-recovery','recovery');second=self.bind_running('recovery')
  need(first['pid']!=second['pid'] and (first['birthSec'],first['birthUsec'])!=(second['birthSec'],second['birthUsec']),
   'new_recovery_process_birth')
  self.dispatch('bootout-recovery','recovery');self.absence('recovery')
  need(self.disabled() is False,'restored_effective_enabled_state');self.runtime_fence();self.remaining()
  need(tuple(self.mutations)==GRAPH and all(x['outcome']=='complete' for x in self.mutations.values()),'all_six_original_mutations_known')
  self.finished=True;self.report.update(ok=True,allSixOriginalMutationsKnown=True,allOwnedServiceGenerationsAbsent=True,
   restoredEffectiveDisabledFalse=True,persistedFalseOverrideEntryCreatedForNewQaLabel=True,
   originalOverrideAbsenceRestored=False,productionGatewayOrRollbackQualified=False)
  return self.report
 def public(self):
  self.report.update(unknown=self.unknown,finished=self.finished,
   registeredServiceMayRemain=any(key.startswith('bootstrap-') and key.removeprefix('bootstrap-') not in self.generation_closed for key in self.mutations),
   automaticFailureMutationAttempted=False)
  return self.report
