#!/usr/bin/env python3
"""Only the requested X230 policy reads or Mac alias and two port-22 connects.

Full command output stays in a new private directory. Public output contains
only the declared LAN projection. This never modifies a rule or a service.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import types

PINS = {
 'owned_process': (28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
 'kv2_dr_process_custody': (26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
}
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
LINUX_QA = Path('/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1/source-4bde9/qa/openbao-acceptance')
MAC_QA = BASE / 'ha-qa-af91-preparation-20261106-r1/source/qa/openbao-acceptance'
START = time.monotonic()
UNTIL = START + 25


def need(value, code):
 if not value: raise RuntimeError(code)


def identity(s):
 return tuple(getattr(s, k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read_public(path, maximum):
 need(time.monotonic() < UNTIL, 'metadata_deadline')
 s=path.lstat()
 need(path.resolve(strict=True)==path and stat.S_ISREG(s.st_mode) and s.st_nlink==1
      and s.st_uid in (0,os.getuid()) and not s.st_mode&0o022 and s.st_size<=maximum,'fixed_public_input')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  need(identity(os.fstat(fd))==identity(s),'same_public_input')
  raw=bytearray()
  while len(raw)<=s.st_size:
   part=os.read(fd,min(65536,s.st_size+1-len(raw)))
   if not part:break
   raw.extend(part);need(len(raw)<=s.st_size,'bounded_public_input')
  need(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'stable_public_input')
  return bytes(raw),identity(s)
 finally:os.close(fd)


def write_private(root,name,data):
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False) as out:out.write(data);out.flush();os.fsync(out.fileno())
 finally:os.close(fd)


def command(root,path,label,args):
 need(time.monotonic()<UNTIL,'metadata_deadline')
 result=subprocess.run([str(path),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       timeout=min(5,UNTIL-time.monotonic()),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 need(len(result.stdout)<=131072 and len(result.stderr)<=16384,'bounded_fixed_command_output')
 write_private(root,label+'.stdout.private',result.stdout);write_private(root,label+'.stderr.private',result.stderr)
 need(result.returncode==0,'fixed_readonly_command_failed')
 return result.stdout


def main():
 report={'schema':'heptabao.fixed-lan-policy-observation.r1','ok':False,'productionChanged':False,
         'serviceActions':0,'networkRulesChanged':False,'permissionsChanged':False,'credentialFilesRead':False,
         'rawSshArgumentsPublished':False,'unrelatedNetworkEntriesPublished':False}
 sources={};owner=None;created=False
 try:
  mac=sys.platform=='darwin'
  need((mac and os.getuid()==501 and platform.machine()=='arm64') or
       (sys.platform=='linux' and os.getuid()==1000 and platform.node()=='qian-ThinkPad-X230'),'expected_observation_host')
  qa=MAC_QA if mac else LINUX_QA
  root=(BASE/'ha128-fixed-lan-policy-observation-20261106-r1') if mac else Path('/home/qian/heptabao-fixed-lan-policy-observation-20261106-r1')
  parent=root.parent.lstat();need(root.parent.resolve(strict=True)==root.parent and stat.S_ISDIR(parent.st_mode)
   and parent.st_uid==os.getuid() and not parent.st_mode&0o022 and not root.exists() and not root.is_symlink(),'new_private_observation_root')
  for name,(size,digest) in PINS.items():
   path=qa/(name+'.py');raw,ident=read_public(path,32768)
   need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest and name not in sys.modules,'fixed_custody_source')
   module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
   exec(compile(raw,str(path),'exec'),module.__dict__);sources[path]=(raw,ident)
  custody=sys.modules['kv2_dr_process_custody']
  if mac:
   tool=Path('/usr/bin/ssh');tool_raw,tool_ident=read_public(tool,2*1048576)
   need(len(tool_raw)==1584576 and hashlib.sha256(tool_raw).hexdigest()=='17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3','existing_mac_ssh_pin')
  else:
   found=shutil.which('ip',path='/usr/sbin:/usr/bin:/sbin:/bin');need(found is not None,'existing_ip_tool_required')
   tool=Path(found).resolve(strict=True);need(tool in (Path('/usr/bin/ip'),Path('/usr/sbin/ip')),'fixed_system_ip_tool')
   tool_raw,tool_ident=read_public(tool,2*1048576);need(tool.stat().st_uid==0,'root_owned_system_ip_tool')
  sources[tool]=(tool_raw,tool_ident)
  root.mkdir(mode=0o700,exist_ok=False);created=True
  with custody.activated() as current_owner:
   owner=current_owner
   if mac:
    raw=command(root,tool,'ssh-g-x230',['-G','x230']);parsed={}
    for line in raw.decode('utf-8').splitlines():
     key,separator,value=line.partition(' ')
     if key in ('hostname','user','proxyjump'):
      need(separator and key not in parsed and re.fullmatch(r'[A-Za-z0-9._,@:\[\]-]{1,256}',value),'bounded_requested_alias_projection')
      parsed[key]=value
    need('hostname' in parsed and 'user' in parsed,'requested_alias_fields_present')
    report['aliasProjection']=parsed;report['tcp22Observations']=[]
    for address in ('192.168.0.13','192.168.0.3'):
     started=time.monotonic();entry={'address':address,'port':22,'connected':False,'bytesSent':0,'bytesRead':0,'budgetSeconds':1.5};sock=None
     try:
      sock=socket.create_connection((address,22),timeout=1.5);entry['connected']=True
     except OSError as error:
      entry['errorType']=type(error).__name__
      if type(error.errno) is int:entry['errno']=error.errno
     finally:
      if sock is not None:sock.close()
      entry['socketClosed']=sock is None or sock.fileno()==-1;entry['elapsedSeconds']=time.monotonic()-started
     report['tcp22Observations'].append(entry)
   else:
    raw=command(root,tool,'ip-rule',['-j','rule','show']);rules=json.loads(raw);need(isinstance(rules,list),'ip_rule_array')
    relevant=[]
    for row in rules:
     if row.get('table') in (4503,'4503','main','local','default',254,255,253):
      selected={k:row[k] for k in ('priority','table','fwmark','fwmask','not','action','goto','suppress_prefixlength') if k in row}
      for key in ('src','dst'):
       if key in row:selected[key]=row[key] if row[key] in ('all','192.168.0.0/24','192.168.0.13','192.168.0.3','192.168.0.8') else 'outside_declared_lan'
      selected['otherSelectorKeys']=[k for k in row if k not in selected and k not in ('src','dst')]
      relevant.append(selected)
    report['relevantRuleProjection']=relevant;report['otherRulesOmitted']=len(rules)-len(relevant)
    report['ruleProjectionIsNotCompletePolicyEvaluation']=True;report['kernelRouteQueries']=[]
    for ordinal,address in enumerate(('192.168.0.13','192.168.0.3'),1):
     raw=command(root,tool,'ip-route-from-'+str(ordinal),['-j','route','get','192.168.0.8','from',address]);rows=json.loads(raw)
     need(isinstance(rows,list) and len(rows)==1 and rows[0].get('dst')=='192.168.0.8','fixed_kernel_route_result')
     selected={k:rows[0][k] for k in ('dst','dev','table','flags','uid') if k in rows[0]}
     for key in ('from','prefsrc','src','gateway'):
      if key in rows[0]:selected[key]=rows[0][key] if rows[0][key] in ('192.168.0.8','192.168.0.13','192.168.0.3','192.168.0.1') else 'outside_declared_lan'
     report['kernelRouteQueries'].append({'requestedSource':address,'destination':'192.168.0.8','observation':selected})
    report['rpFilter']={}
    for interface in ('all','enp0s25','wlp3s0'):
     path=Path('/proc/sys/net/ipv4/conf')/interface/'rp_filter'
     with path.open('rb') as f:raw=f.read(17)
     need(raw.strip() in (b'0',b'1',b'2'),'bounded_rp_filter_value');report['rpFilter'][interface]=int(raw)
  report['processCustody']=owner.assert_retired()
  for path,(raw,ident) in sources.items():
   now,now_ident=read_public(path,max(32768,len(raw)))
   need(now==raw and now_ident==ident,'source_or_tool_changed')
  report.update(ok=True,allSourceAndToolInputsUnchanged=True,hostRole='mac' if mac else 'x230',
   tool={'path':str(tool),'bytes':len(tool_raw),'sha256':hashlib.sha256(tool_raw).hexdigest()})
 except BaseException as error:
  report['errorType']=type(error).__name__
  if type(error) is RuntimeError:report['errorCode']=str(error)
 finally:
  if owner is not None:report['processCustody']=owner.receipt()
  report['elapsedSeconds']=time.monotonic()-START
  if created:write_private(root,'result.public.json',(json.dumps(report,sort_keys=True)+'\n').encode())
  print(json.dumps(report,sort_keys=True,separators=(',',':')))
 return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
