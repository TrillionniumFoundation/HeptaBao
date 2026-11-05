#!/usr/bin/env python3
"""Metadata-only audit of a fixed forty-entry public-code set."""
import hashlib, json, os, stat, sys, time
from pathlib import Path
START=time.monotonic();UNTIL=START+5
MANIFEST_BYTES=10832;MANIFEST_SHA='a6f6eb77a2949f076e88fcbc4ac281c033c568aa27eb1723e6dc7aee1d212941'
MAX_EXPLICIT_METADATA=512;MAX_RESOLVES=80;MAX_UNIQUE_PARENTS=128
counts={'lstat':0,'readlink':0,'resolve':0}
report={'schema':'heptabao.mac-public-code-parent-closed-observation.r1',
 'status':'failed','new_inner_seconds':5,'new_outer_seconds':60,
 'disk_file_content_opened':False,'files_written':False,'directory_enumeration':False,
 'private_inputs_read':False,'sqlite_opened':False,'children_started':False,
 'network_used':False,'permissions_changed':False,'business_replayed':False,
 'resolve_internal_metadata_calls_not_individually_counted':True}
def need(value,code):
    if not value:raise RuntimeError(code)
def tick(kind):
    need(time.monotonic()<UNTIL,'original_observation_deadline')
    counts[kind]+=1
    need(counts['lstat']+counts['readlink']<=MAX_EXPLICIT_METADATA
         and counts['resolve']<=MAX_RESOLVES,'fixed_call_bounds')
def ident(s):
    return [str(v) for v in (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,
             s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)]
def observe(path):
    tick('lstat');s=os.lstat(path)
    row={'path':str(path),'identity':ident(s),'directory':stat.S_ISDIR(s.st_mode),
      'regular':stat.S_ISREG(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode),
      'permission_octal':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,
      'owner_allowed_by_original':s.st_uid in (0,501),
      'group_or_other_write':bool(stat.S_IMODE(s.st_mode)&0o022)}
    if row['symlink']:
        tick('readlink');row['readlink']=os.readlink(path)
    return row
def resolve(path):
    tick('resolve');return path.resolve(strict=True)
def allowed(row,resolved):
    if row['kind']=='normal_server':return str(resolved)==row['path']
    if row['kind']=='utility':
        return any(resolved.is_relative_to(Path(p)) for p in ('/System','/usr','/bin','/sbin'))
    return any(resolved.is_relative_to(Path(p)) for p in (
        '/opt/homebrew','/Users/qianqi/.openclaw/extensions/openclaw-authbus',
        '/Users/qianqi/.openclaw/npm/projects'))
try:
    raw=sys.stdin.buffer.read(MANIFEST_BYTES+1)
    need(len(raw)==MANIFEST_BYTES and hashlib.sha256(raw).hexdigest()==MANIFEST_SHA,'exact_public_manifest')
    manifest=json.loads(raw)
    rows=manifest['paths']
    need(len(rows)==40 and len({x['path'] for x in rows})==40,'closed_forty')
    aliases=[];parents=set();targets=set()
    for row in rows:
        path=Path(row['path']);before=observe(path);resolved=resolve(path)
        need(allowed(row,resolved),'original_public_resolved_scope')
        need(len(resolved.parts)<=24,'bounded_path_depth')
        aliases.append({'path':str(path),'kind':row['kind'],'pinned_source_sha256':row['sha256'],
                        'resolved':str(resolved),'before':before})
        parents.update(str(p) for p in resolved.parents);targets.add(str(resolved))
    need(len(parents)<=MAX_UNIQUE_PARENTS,'bounded_unique_parent_set')
    report['aliases']=aliases
    before={p:observe(Path(p)) for p in sorted(parents|targets)}
    after={p:observe(Path(p)) for p in sorted(parents|targets,reverse=True)}
    for row in aliases:
        path=Path(row['path']);resolved=resolve(path);observed=observe(path)
        need(str(resolved)==row['resolved'] and observed==row['before'],'public_alias_drift')
        row['after']=observed
    need(before==after,'named_public_parent_or_target_drift')
    anchors={x['path']:tuple(x['identity']) for x in manifest['exact_original_volume_anchors']}
    failures=[]
    for p in sorted(parents):
        row=before[p]
        ok=(row['directory'] and row['owner_allowed_by_original'] and
            (tuple(row['identity'])==anchors[p] if p in anchors else not row['group_or_other_write']))
        if not ok:failures.append(row)
    report.update({'status':'complete_finite_metadata_observation',
      'path_count':len(rows),'unique_parent_count':len(parents),
      'unique_resolved_leaf_count':len(targets),'metadata_before':before,
      'metadata_after':after,'all_named_metadata_stable':True,
      'original_parent_predicate_failures':failures,
      'all_code_hashes_rechecked':False,'guard_relaxed':False})
except BaseException as error:
    report['error_type']=type(error).__name__
    report['error_code']=str(error) if type(error) is RuntimeError else None
report['counts']=counts
report['elapsed_seconds']=time.monotonic()-START
report['original_inner_deadline_met']=time.monotonic()<UNTIL
if not report['original_inner_deadline_met']:report['status']='failed'
print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['status']=='complete_finite_metadata_observation' and time.monotonic()<UNTIL else 1)
