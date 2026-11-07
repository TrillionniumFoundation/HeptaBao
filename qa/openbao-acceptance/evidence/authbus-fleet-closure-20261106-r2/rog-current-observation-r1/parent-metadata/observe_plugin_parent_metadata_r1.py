#!/usr/bin/env python3
import os,stat,json,time
from pathlib import Path
root=Path("/home/qian-qi/.openclaw/extensions/openclaw-authbus/index.js")
paths=[*reversed(root.parents),root]
rows=[]
for p in paths:
 s=p.lstat();rows.append({"path":str(p),"uid":s.st_uid,"gid":s.st_gid,"mode":oct(stat.S_IMODE(s.st_mode)),"isDirectory":stat.S_ISDIR(s.st_mode),"isSymlink":stat.S_ISLNK(s.st_mode),"ownerMatches":s.st_uid in (0,os.getuid()),"groupOrWorldWrite":bool(s.st_mode&0o022),"identity":[str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)]})
print(json.dumps({"schema":"heptabao.rog-selected-public-source-parent-metadata.r1","uid":os.getuid(),"rows":rows,"sourceFileContentsRead":False,"permissionsChanged":False,"productionChanged":False,"childProcesses":0,"networkOpened":False,"priorFailedJob":"1a1b279171a-fc05-7e2b","priorFailureReclassified":False},sort_keys=True))
