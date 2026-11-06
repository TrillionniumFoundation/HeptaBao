#!/usr/bin/env python3
"""The exact fixed parser on retained private original bytes; no launchctl call."""
import ast,hashlib,json,os,re,stat,time
from pathlib import Path
ROOT=Path('/Users/qianqi/heptabao-authbus-gateway-service-primitives-20261106-r3')
START=time.monotonic();UNTIL=START+10
# SOURCE_PLACEHOLDER
report={'schema':'heptabao.actual-original-disabled-parser.r4','ok':False,
 'launchctlCalls':0,'serviceMutations':0,'providerCalls':0,'configurationReads':0,
 'unrelatedServiceLabelsOrDigestsPublished':False,'descriptors':[],'cases':[]}
def need(value,code='original_disabled_parser_qualification_refused'):
 if not value:raise RuntimeError(code)
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
def check(label,fn):
 need(time.monotonic()<UNTIL);fn();report['cases'].append({'case':label,'passed':True})
try:
 need(os.getuid()==501 and stat.S_ISDIR(ROOT.lstat().st_mode) and stat.S_IMODE(ROOT.lstat().st_mode)==0o700)
 raw=read('disabled-001.stdout.private',262144);command=json.loads(read('command-001.private.json',65536))
 need(len(raw)==1435 and command['argv']==['/bin/launchctl','print-disabled','gui/501']
  and command['exitCode']==0 and command['completeBeforeDeadline'] is True and command['outcomeUnknown'] is False
  and command['stdoutBytes']==len(raw) and command['stdoutSha256']==hashlib.sha256(raw).hexdigest())
 report['boundToOriginalCommandBytesPrivately']=True
 source=FIXED_SOURCE.encode();need(hashlib.sha256(source).hexdigest()==FIXED_SHA256)
 tree=ast.parse(source);names={'Refused','need','parse_disabled'}
 nodes=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in names]
 need([n.name for n in nodes]==['Refused','need','parse_disabled'])
 scope={'re':re,'DOMAIN':'gui/501','LABEL':'org.heptabao.qa.gateway-maintenance-actions-20261106-r4'}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'exact-three-fixed-parser-definitions','exec'),scope)
 parse=scope['parse_disabled'];label=scope['LABEL']
 def mapping(value):return ('\ndisabled services = {\n "'+label+'" => '+value+'\n}\n').encode()
 def refuses(value):
  try:parse(value)
  except scope['Refused']:return
  raise RuntimeError('fixed_parser_expected_refusal')
 check('A01_private_original_complete_output',lambda:need(parse(raw) is None))
 check('A02_observed_enabled_means_disabled_false',lambda:need(parse(mapping('enabled')) is False))
 check('A03_observed_disabled_means_disabled_true',lambda:need(parse(mapping('disabled')) is True))
 check('A04_legacy_true_means_disabled_true',lambda:need(parse(mapping('true')) is True))
 check('A05_legacy_false_means_disabled_false',lambda:need(parse(mapping('false')) is False))
 check('A06_duplicate_target_rejected',lambda:refuses(('disabled services = {\n'+(' "'+label+'" => enabled\n')*2+'}\n').encode()))
 check('A07_unknown_state_literal_rejected',lambda:refuses(mapping('enable')))
 check('A08_two_records_on_one_line_rejected',lambda:refuses(mapping('enabled "another-synthetic" => disabled')))
 check('A09_trailing_nonblank_record_rejected',lambda:refuses(mapping('enabled')+b'extra\n'))
 check('A10_unobserved_record_comma_rejected',lambda:refuses(mapping('enabled,')))
 report.update(ok=True,selectedQaLabelAbsentInOriginal=True,privateOriginalFullyParsed=True,
  exactFixedCoreSha256=FIXED_SHA256,actualBusinessCommandsExecuted=False)
except BaseException as error:report['errorType']=type(error).__name__
finally:
 report['allOriginalDescriptorsClosedOnce']=all(x['closeAttempts']==1 and x['closed'] for x in report['descriptors'])
 report['ok']=report['ok'] and report['allOriginalDescriptorsClosedOnce'];report['elapsedSeconds']=time.monotonic()-START
 report['passed']=len(report['cases']);report['expectedCases']=10
 print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
