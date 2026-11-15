#!/usr/bin/env python3
"""Finite create-only filesystem metadata probe, no process or service command."""
import json,os,stat,sys,time
from pathlib import Path
ROOT=Path('/Users/qianqi/heptabao-authbus-owned-directory-nlink-20261106-r1')
START=time.monotonic();UNTIL=START+10
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
report={'schema':'heptabao.actual-mac-owned-directory-link-count.r1','ok':False,
 'productionReads':0,'productionWrites':0,'serviceMutations':0,'children':0,
 'providerCalls':0,'automaticRetry':False,'observations':[],'descriptors':[]}
held=[]
def need(v):
 if not v:raise RuntimeError('owned_directory_metadata_refused')
def identity(s):return tuple(getattr(s,k) for k in FIELDS)
def opened(path,flags,mode=0o777,dir_fd=None):
 fd=os.open(path,flags,mode,dir_fd=dir_fd);row={'closeAttempts':0,'closed':False};report['descriptors'].append(row);held.append((fd,row));return fd,row
def close(item):
 fd,row=item;need(row['closeAttempts']==0);row['closeAttempts']=1;os.close(fd);row['closed']=True
try:
 need(sys.platform=='darwin' and os.getuid()==501 and time.monotonic()<UNTIL);os.umask(0o077)
 p=opened(ROOT.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);before=os.fstat(p[0])
 need(stat.S_ISDIR(before.st_mode) and before.st_uid==501 and not stat.S_IMODE(before.st_mode)&0o022)
 os.mkdir(ROOT.name,0o700,dir_fd=p[0]);r=opened(ROOT.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=p[0])
 initial=identity(os.fstat(r[0]));need(initial==identity(ROOT.lstat()) and stat.S_IMODE(initial[4])==0o700)
 previous=initial
 for ordinal in range(5):
  need(time.monotonic()<UNTIL)
  f=opened('source-%d.synthetic'%ordinal,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=r[0])
  need(os.write(f[0],b'synthetic public code\n')==22);os.fsync(f[0]);close(f);os.fsync(r[0])
  current=identity(os.fstat(r[0]));need(current==identity(ROOT.lstat()) and current[:5]==initial[:5])
  report['observations'].append({'ordinal':ordinal,'changedFields':[name[3:] for i,name in enumerate(FIELDS) if current[i]!=previous[i]],
   'firstFiveUnchanged':current[:5]==initial[:5],'firstSixUnchanged':current[:6]==previous[:6],
   'linkCountDelta':current[5]-previous[5]})
  previous=current
 report['ok']=True
except BaseException as error:report['errorType']=type(error).__name__
finally:
 for item in reversed(held):
  if item[1]['closeAttempts']==0:
   try:close(item)
   except BaseException:report['ok']=False
 report['allOriginalDescriptorsClosedOnce']=all(row['closeAttempts']==1 and row['closed'] for row in report['descriptors'])
 report['ok']=report['ok'] and report['allOriginalDescriptorsClosedOnce'];report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True),flush=True)
sys.exit(0 if report['ok'] else 1)
