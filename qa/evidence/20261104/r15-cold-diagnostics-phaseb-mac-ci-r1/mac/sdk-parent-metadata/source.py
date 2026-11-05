#!/usr/bin/env python3
"""One fixed public SDK path: alias and parent metadata only; no file reads."""
import json, os, stat, time
from pathlib import Path
START=time.monotonic();UNTIL=START+5
TARGET=Path('/opt/homebrew/lib/node_modules/openclaw/package.json')
PREFIX=Path('/opt/homebrew')
MAX_OPERATIONS=64
operations=0
report={'schema':'heptabao.mac-public-sdk-parent-observation.r1',
 'status':'failed','requested':str(TARGET),'new_inner_seconds':5,
 'new_outer_seconds':60,'metadata_operation_cap':MAX_OPERATIONS,
 'files_opened':False,'files_written':False,'private_inputs_read':False,
 'children_started':False,'network_used':False,'permission_changed':False,
 'business_replayed':False,'unsafe_parent_admitted':False}
def need(value,code):
    if not value:raise RuntimeError(code)
def remaining():
    need(time.monotonic()<UNTIL,'original_observation_deadline')
def count():
    global operations
    remaining();operations+=1;need(operations<=MAX_OPERATIONS,'finite_metadata_bound')
def ident(s):
    return [str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
            s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)]
def observe(path):
    count();s=os.lstat(path)
    row={'path':str(path),'identity':ident(s),'directory':stat.S_ISDIR(s.st_mode),
      'regular':stat.S_ISREG(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode),
      'permission_octal':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,
      'owner_allowed_by_original':s.st_uid in (0,501),
      'group_or_other_write':bool(stat.S_IMODE(s.st_mode)&0o022)}
    if stat.S_ISLNK(s.st_mode):
        count();row['readlink']=os.readlink(path)
    remaining();return row
def chain(path):
    values=[*reversed(path.parents),path]
    need(len(values)<=12,'finite_path_depth')
    return [observe(p) for p in values]
try:
    lexical_before=chain(TARGET);report['lexical_before']=lexical_before
    count();resolved=TARGET.resolve(strict=True);report['resolved']=str(resolved)
    need(resolved.is_relative_to(PREFIX),'resolved_public_sdk_stays_under_homebrew')
    resolved_before=chain(resolved);report['resolved_before']=resolved_before
    count();need(TARGET.resolve(strict=True)==resolved,'resolved_alias_stable')
    resolved_after=chain(resolved);lexical_after=chain(TARGET)
    report['resolved_after']=resolved_after;report['lexical_after']=lexical_after
    need(lexical_before==lexical_after and resolved_before==resolved_after,'named_metadata_drift')
    report['named_metadata_stable']=True
    report['original_nonanchor_predicate_failures']=[
       x['path'] for x in resolved_before[:-1] if x['path']!='/'
       and (not x['directory'] or not x['owner_allowed_by_original'] or x['group_or_other_write'])]
    report['status']='complete_finite_metadata_observation'
except BaseException as error:
    report['error_type']=type(error).__name__
    report['error_code']=str(error) if type(error) is RuntimeError else None
report['metadata_operations']=operations
report['elapsed_seconds']=time.monotonic()-START
report['original_inner_deadline_met']=time.monotonic()<UNTIL
if not report['original_inner_deadline_met']:report['status']='failed'
print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['status']=='complete_finite_metadata_observation' and time.monotonic()<UNTIL else 1)
