#!/usr/bin/env python3
"""Derive one new readonly namespace with full9 diagnostics; retain r1 unchanged."""
import ast,hashlib,json
from pathlib import Path
B=Path(__file__).resolve().parent
old_template=(B/'launch_current_refresh_flags_r1.template.py').read_bytes()
old_worker=(B/'mac_current_refresh_flags_r1.mjs').read_bytes()
assert hashlib.sha256(old_template).hexdigest()=='5ddead60326f4d2aad88724a127eacd84f20653487bc99ebf8fe88c80fba889d'
assert hashlib.sha256(old_worker).hexdigest()=='05e28d4f56d8c9e857f219bee83dfb984ab2a7007110dc97ae7aa7e5015eb55a'
template=old_template.decode().replace('heptabao-authbus-current-refresh-flags-20261106-r1','heptabao-authbus-current-refresh-flags-20261106-r2').replace('current-main3-refresh-flags-owned.r1','current-main3-refresh-flags-owned.r2')
worker=old_worker.decode().replace('heptabao-authbus-current-refresh-flags-20261106-r1','heptabao-authbus-current-refresh-flags-20261106-r2').replace('current-main3-refresh-flags-readonly.r1','current-main3-refresh-flags-readonly.r2')
before=' def __init__(self):self.rows=[];self.absent=set();self.opened=0;self.closed=0;self.finished=False;self.close_errors=[]'
after=before+';self.observations=[];self.changes=[];self.verification_count=0'
assert template.count(before)==1;template=template.replace(before,after)
start=template.index(' def verify(self):');end=template.index(' def close(self):',start)
template=template[:start]+''' def verify(self):
  self.verification_count+=1;changed=False
  fields=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
  def role(name):
   if name==str(LIVE/'authbus'):return 'state_directory'
   if name in {str(LIVE/'authbus'/item) for item in STATES}:return 'state_file'
   return 'ancestor_directory'
  for ordinal,row in enumerate(self.rows,1):
   remaining();current=None;held=None;unavailable=False
   try:current=ident(Path(row['path']).lstat())
   except OSError:unavailable=True
   if not self.finished:
    try:held=ident(os.fstat(row['fd']))
    except OSError:unavailable=True
   changed_fields=[]
   if unavailable:changed_fields.append('metadata_unavailable')
   for index,field in enumerate(fields):
    if (current is not None and current[index]!=row['expected'][index]) or (held is not None and held[index]!=row['expected'][index]):changed_fields.append(field)
   self.observations.append({'verificationOrdinal':self.verification_count,'sourceOrdinal':ordinal,
    'sourceRole':role(row['path']),'expectedFull9':row['expected'],'currentFull9':current,
    'heldFull9':held,'descriptorsAlreadyClosed':self.finished})
   if changed_fields:
    changed=True;self.changes.append({'verificationOrdinal':self.verification_count,
      'sourceOrdinal':ordinal,'sourceRole':role(row['path']),'changedFields':changed_fields})
  for ordinal,name in enumerate(sorted(self.absent),len(self.rows)+1):
   remaining();current=None;absent=False
   try:current=ident(Path(name).lstat())
   except FileNotFoundError:absent=True
   except OSError:pass
   self.observations.append({'verificationOrdinal':self.verification_count,'sourceOrdinal':ordinal,
    'sourceRole':role(name),'expectedAbsence':True,'currentFull9':current,'currentAbsence':absent})
   if not absent:
    changed=True;self.changes.append({'verificationOrdinal':self.verification_count,
      'sourceOrdinal':ordinal,'sourceRole':role(name),'changedFields':['absence']})
  need(not changed,'state_full9_name_or_absence_unchanged')
''' +template[end:]
before="   'closeErrors':list(self.close_errors),'full9ComparisonWeakened':False}"
after="   'closeErrors':list(self.close_errors),'full9ComparisonWeakened':False,\n   'verificationCount':self.verification_count,'changedRows':list(self.changes)}"
assert template.count(before)==1;template=template.replace(before,after)
before=" if state_guard is not None:state_guard.close();report['stateGuardClosure']=state_guard.public()"
after=""" if state_guard is not None:
  state_guard.close();report['stateGuardClosure']=state_guard.public()
  try:
   new(ROOT/'output/state-generation-observations.private.json',json.dumps({
    'schema':'heptabao.current-two-state-private-generation-diagnostics.r2',
    'containsCredentialValues':False,'containsCredentialDigests':False,
    'observations':state_guard.observations},sort_keys=True).encode()+b'\\n')
   report['privateFull9DiagnosticSaved']=True
  except BaseException:
   report['privateFull9DiagnosticSaved']=False;report['ok']=False"""
assert template.count(before)==1;template=template.replace(before,after)
template=template.replace('mac_current_refresh_flags_r1.mjs','mac_current_refresh_flags_r2.mjs')
ast.parse(template)
payload=json.loads((B/'current-refresh-flags-r1.payload.public.json').read_text())
payload['sources'].pop('mac_current_refresh_flags_r1.mjs')
payload['sources']['mac_current_refresh_flags_r2.mjs']=worker
payload['sourcePins']={name:hashlib.sha256(value.encode()).hexdigest() for name,value in payload['sources'].items()}
launcher=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD=json.loads('+repr(json.dumps(payload,sort_keys=True,separators=(',',':')))+')')
ast.parse(launcher)
files={'mac_current_refresh_flags_r2.mjs':worker,'launch_current_refresh_flags_r2.template.py':template,
 'launch_current_refresh_flags_r2.py':launcher,'current-refresh-flags-r2.payload.public.json':json.dumps(payload,sort_keys=True,indent=2)+'\n'}
for name,source in files.items():
 with (B/name).open('x') as out:out.write(source)
 print(json.dumps({'name':name,'bytes':len(source.encode()),'sha256':hashlib.sha256(source.encode()).hexdigest()}))
