#!/usr/bin/env python3
"""Observe the two Mac QA ports and three new HA root paths.

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
 report={'schema':'heptabao.mac-fixed-ha-port-observation.r1','ok':False,'ports':[31040,31041],'networkCalls':0,'productionChanged':False,'rulesChanged':False,'permissionsChanged':False}
 sources={};owner=None;created=False
 try:
  need(sys.platform=='darwin' and os.getuid()==501 and platform.machine()=='arm64','fixed_mac_host')
  root=BASE/'ha128-fixed-port-observation-20261106-r2'
  parent=root.parent.lstat()
  need(root.parent.resolve(strict=True)==root.parent and stat.S_ISDIR(parent.st_mode) and parent.st_uid==501 and not parent.st_mode&0o022 and not root.exists() and not root.is_symlink(),'new_private_observation_root')
  for name,(size,digest) in PINS.items():
   path=MAC_QA/(name+'.py');raw,ident=read_public(path,32768)
   need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest and name not in sys.modules,'fixed_custody_source')
   module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
   exec(compile(raw,str(path),'exec'),module.__dict__);sources[path]=(raw,ident)
  tool_pins={Path('/usr/sbin/netstat'):(400016,'86b32ffdf451da6357e4e4325629b5e28a8d4b46c5b4268efc85eeff6973182a'),Path('/usr/libexec/ApplicationFirewall/socketfilterfw'):(553680,'865bd93ae5cd3065367c3ffc2ee7bbfa3f6e10dec80d7dd86039dbdd8ace485c'),Path('/sbin/pfctl'):(483360,'675449d18fdca83c4e892b719215832092f8362d193fe9c72cd230918b5d150b')}
  for path,(size,digest) in tool_pins.items():
   raw,ident=read_public(path,1048576)
   need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'fixed_system_tool')
   sources[path]=(raw,ident)
  root.mkdir(mode=0o700,exist_ok=False);created=True
  with sys.modules['kv2_dr_process_custody'].activated() as current_owner:
   owner=current_owner
   raw=command(root,Path('/usr/sbin/netstat'),'netstat-tcp',['-an','-p','tcp'])
   lines=raw.decode().splitlines();need(any('Local Address' in x and 'Foreign Address' in x for x in lines),'complete_netstat_header')
   matches=[]
   for line in lines:
    fields=line.split()
    if not fields or not fields[0].startswith('tcp'):continue
    need(len(fields)>=6,'netstat_tcp_row_shape')
    if fields[-1]!='LISTEN':continue
    local=fields[3];host,sep,port=local.rpartition('.')
    need(sep and port.isdigit(),'netstat_numeric_listener')
    if int(port) in (31040,31041):matches.append({'protocol':fields[0],'port':int(port),'bindKind':'wildcard' if host=='*' else 'specific_local_address'})
   report['candidatePortListeners']=matches;report['bothCandidateTcpPortsUnoccupiedInObservedKernelTables']=not matches
   raw=command(root,Path('/usr/libexec/ApplicationFirewall/socketfilterfw'),'application-firewall-state',['--getglobalstate'])
   text=raw.decode();states=re.findall(r'State = ([012])',text)
   need(len(states)==1 and len(raw)<=4096,'application_firewall_state_shape')
   report['applicationFirewallGlobalState']=int(states[0]);report['applicationFirewallDisabled']=states[0]=='0'
  report['processCustody']=owner.assert_retired()
  report['originalPfPtyPidObservations']=[]
  for pid in (4553,4554,4721,4722):
   try:os.kill(pid,0);absent=False
   except ProcessLookupError:absent=True
   except PermissionError:absent=False
   report['originalPfPtyPidObservations'].append({'pid':pid,'absentByZeroSignalProbe':absent})
  report['allOriginalPfPtyPidsAbsent']=all(x['absentByZeroSignalProbe'] for x in report['originalPfPtyPidObservations'])
  for path,(raw,ident) in sources.items():
   now,now_ident=read_public(path,max(32768,len(raw)))
   need(now==raw and now_ident==ident,'source_or_tool_changed')
  report['newOwnedHaRoots']=[]
  for name in ('ha128-current-launch-20261106-r2','native-ha-official-history-4bde9-authbus-r2','native-ha-4bde9-authbus-node-r2'):
   path=BASE/name
   try:path.lstat();absent=False
   except FileNotFoundError:absent=True
   report['newOwnedHaRoots'].append({'path':str(path),'absent':absent})
   need(absent,'new_ha_root_must_be_absent')
  report.update(ok=True,allSourceAndToolInputsUnchanged=True,readOnlySnapshotDoesNotReservePorts=True)
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
