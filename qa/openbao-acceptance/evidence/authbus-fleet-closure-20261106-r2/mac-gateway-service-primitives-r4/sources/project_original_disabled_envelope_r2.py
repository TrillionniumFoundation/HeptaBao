#!/usr/bin/env python3
"""Read only the retained QA command bytes; publish syntax classes, never labels."""
import ast,hashlib,json,os,re,stat,time
from pathlib import Path
ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-service-primitives-20261106-r3')
START=time.monotonic();UNTIL=START+10
report={'schema':'heptabao.original-disabled-envelope-projection.r2','ok':False,
 'launchctlCalls':0,'serviceMutations':0,'providerCalls':0,'configurationReads':0,
 'unrelatedServiceLabelsOrDigestsPublished':False,'descriptors':[]}
def need(v):
 if not v:raise RuntimeError('original_disabled_projection_refused')
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(name,cap):
 need(time.monotonic()<UNTIL);p=ROOT/name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 row={'closeAttempts':0,'closed':False};report['descriptors'].append(row)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1
   and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=cap)
  raw=os.read(fd,cap+1);need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(p.lstat()))
  return raw
 finally:row['closeAttempts']+=1;os.close(fd);row['closed']=True
try:
 need(os.getuid()==501 and stat.S_ISDIR(ROOT.lstat().st_mode) and stat.S_IMODE(ROOT.lstat().st_mode)==0o700)
 raw=read('disabled-001.stdout.private',262144);command=json.loads(read('command-001.private.json',65536))
 need(len(raw)==1435 and command['argv']==['/bin/launchctl','print-disabled','gui/501']
  and command['exitCode']==0 and command['completeBeforeDeadline'] is True and command['outcomeUnknown'] is False
  and command['stdoutBytes']==len(raw) and command['stdoutSha256']==hashlib.sha256(raw).hexdigest())
 report['boundToOriginalCommandBytesPrivately']=True
 lines=raw.decode('utf-8','strict').splitlines();projected=[]
 for ordinal,line in enumerate(lines):
  text=line.strip();kind='other-unparsed'
  if text=='':kind='blank'
  elif text=='disabled services = {':kind='disabled-open'
  elif text=='gui/501 = {':kind='domain-open'
  elif text=='}':kind='close'
  elif re.fullmatch(r'"[^"\x00-\x1f\x7f]{1,255}" => (true|false)',text):kind='boolean-entry'
  row={'ordinal':ordinal,'kind':kind,'characters':len(line)}
  if kind=='other-unparsed':
   match=re.fullmatch(r'\s*"[^"\x00-\x1f\x7f]{1,255}"\s*=>\s*([a-z]+)([,;]?)\s*',line)
   if match and match.group(1) in ('true','false','enabled','disabled'):
    row.update(kind='typed-known-state-entry',stateLiteral=match.group(1),terminalSeparator=match.group(2))
  projected.append(row)
 report['lines']=projected;report['lineCount']=len(lines)
 source=read('mac_gateway_service_primitives_r3.py',32768)
 need(hashlib.sha256(source).hexdigest()=='368235ff7afc60bda70a3ed8565e5820ced55b43ca1a3f334666b037677c9fdd')
 tree=ast.parse(source);names={'Refused','need','parse_disabled'}
 selected=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in names]
 need([n.name for n in selected]==['Refused','need','parse_disabled'])
 scope={'re':re,'DOMAIN':'gui/501','LABEL':'org.heptabao.qa.gateway-maintenance-actions-20261106-r3'}
 exec(compile(ast.Module(body=selected,type_ignores=[]),'original-three-pure-parser-definitions','exec'),scope)
 try:
  value=scope['parse_disabled'](raw);report['originalParserAccepted']=True;report['selectedLabelAbsent']=value is None
 except scope['Refused'] as error:
  need(str(error) in ('exact_disabled_domain_record','typed_disabled_service_mapping','unique_disabled_service_mapping'))
  report['originalParserAccepted']=False;report['originalParserRefusalCode']=str(error)
 report['ok']=True
except BaseException as error:report['errorType']=type(error).__name__
finally:
 report['allOriginalDescriptorsClosedOnce']=all(x['closeAttempts']==1 and x['closed'] for x in report['descriptors'])
 report['ok']=report['ok'] and report['allOriginalDescriptorsClosedOnce'];report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
