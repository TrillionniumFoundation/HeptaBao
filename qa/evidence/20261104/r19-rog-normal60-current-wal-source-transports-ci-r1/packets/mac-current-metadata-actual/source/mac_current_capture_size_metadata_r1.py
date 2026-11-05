#!/usr/bin/env python3
"""Fixed 46 current Mac leaf metadata observations; no file-body reads or SQL.

This new observation cannot identify which leaf triggered an earlier size
refusal. The original capture limits and UNKNOWN result remain unchanged.
"""
import json, os, signal, stat, sys, time
from contextlib import contextmanager
from pathlib import Path
START=time.monotonic();UNTIL=START+5.0
LIVE=Path('/Users/qianqi/.openclaw')
TARGETS=[
    {"label": "config", "path": "/Users/qianqi/.openclaw/openclaw.json", "role": "small_read", "maximum": 1048576, "optional": False, "privateMode": True},
    {"label": "auth_main", "path": "/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "auth_main_wal", "path": "/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_main_shm", "path": "/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "auth_main_journal", "path": "/Users/qianqi/.openclaw/agents/main/agent/openclaw-agent.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_trnm", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "auth_trnm_wal", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_trnm_shm", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "auth_trnm_journal", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/openclaw-agent.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta-ui", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "auth_hepta-ui_wal", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta-ui_shm", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "auth_hepta-ui_journal", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/openclaw-agent.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "auth_hepta_wal", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta_shm", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "auth_hepta_journal", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/openclaw-agent.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta-backend", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "auth_hepta-backend_wal", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "auth_hepta-backend_shm", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "auth_hepta-backend_journal", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/openclaw-agent.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "cache_applied-profiles.json", "path": "/Users/qianqi/.openclaw/authbus/applied-profiles.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "cache_publish-baseline.json", "path": "/Users/qianqi/.openclaw/authbus/publish-baseline.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "cache_bad-refresh-quarantine.json", "path": "/Users/qianqi/.openclaw/authbus/bad-refresh-quarantine.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "cache_refresh-backoff.json", "path": "/Users/qianqi/.openclaw/authbus/refresh-backoff.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "cache_lease-epochs.json", "path": "/Users/qianqi/.openclaw/authbus/lease-epochs.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "cache_status.json", "path": "/Users/qianqi/.openclaw/authbus/status.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "native_main_config.toml", "path": "/Users/qianqi/.openclaw/agents/main/agent/codex-home/config.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_main_requirements.toml", "path": "/Users/qianqi/.openclaw/agents/main/agent/codex-home/requirements.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_main_auth.json", "path": "/Users/qianqi/.openclaw/agents/main/agent/codex-home/auth.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "native_trnm_config.toml", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/codex-home/config.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_trnm_requirements.toml", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/codex-home/requirements.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_trnm_auth.json", "path": "/Users/qianqi/.openclaw/agents/trnm/agent/codex-home/auth.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "native_hepta-ui_config.toml", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/codex-home/config.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta-ui_requirements.toml", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/codex-home/requirements.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta-ui_auth.json", "path": "/Users/qianqi/.openclaw/agents/hepta-ui/agent/codex-home/auth.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "native_hepta_config.toml", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/codex-home/config.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta_requirements.toml", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/codex-home/requirements.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta_auth.json", "path": "/Users/qianqi/.openclaw/agents/hepta/agent/codex-home/auth.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "native_hepta-backend_config.toml", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/codex-home/config.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta-backend_requirements.toml", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/codex-home/requirements.toml", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": False},
    {"label": "native_hepta-backend_auth.json", "path": "/Users/qianqi/.openclaw/agents/hepta-backend/agent/codex-home/auth.json", "role": "small_read", "maximum": 1048576, "optional": True, "privateMode": True},
    {"label": "installed_registry", "path": "/Users/qianqi/.openclaw/state/openclaw.sqlite", "role": "database_main", "maximum": None, "optional": False, "privateMode": True},
    {"label": "installed_registry_wal", "path": "/Users/qianqi/.openclaw/state/openclaw.sqlite-wal", "role": "database_wal", "maximum": 0, "optional": True, "privateMode": True},
    {"label": "installed_registry_shm", "path": "/Users/qianqi/.openclaw/state/openclaw.sqlite-shm", "role": "database_shm", "maximum": 8388608, "optional": True, "privateMode": True},
    {"label": "installed_registry_journal", "path": "/Users/qianqi/.openclaw/state/openclaw.sqlite-journal", "role": "database_journal", "maximum": 0, "optional": True, "privateMode": True}
]
PARENTS=[
    "/",
    "/Users",
    "/Users/qianqi",
    "/Users/qianqi/.openclaw",
    "/Users/qianqi/.openclaw/agents",
    "/Users/qianqi/.openclaw/authbus",
    "/Users/qianqi/.openclaw/state",
    "/Users/qianqi/.openclaw/agents/hepta",
    "/Users/qianqi/.openclaw/agents/hepta-backend",
    "/Users/qianqi/.openclaw/agents/hepta-ui",
    "/Users/qianqi/.openclaw/agents/main",
    "/Users/qianqi/.openclaw/agents/trnm",
    "/Users/qianqi/.openclaw/agents/hepta-backend/agent",
    "/Users/qianqi/.openclaw/agents/hepta-ui/agent",
    "/Users/qianqi/.openclaw/agents/hepta/agent",
    "/Users/qianqi/.openclaw/agents/main/agent",
    "/Users/qianqi/.openclaw/agents/trnm/agent",
    "/Users/qianqi/.openclaw/agents/hepta-backend/agent/codex-home",
    "/Users/qianqi/.openclaw/agents/hepta-ui/agent/codex-home",
    "/Users/qianqi/.openclaw/agents/hepta/agent/codex-home",
    "/Users/qianqi/.openclaw/agents/main/agent/codex-home",
    "/Users/qianqi/.openclaw/agents/trnm/agent/codex-home"
]
MAX_METADATA=22*8+46*6
MAX_REGISTERED_FDS=22+46
MAX_LIVE_FDS=22+1
metadata=0;protected=0;pending=None
rows=[];directories={}
report={'schema':'heptabao.mac-current-capture-size-metadata.r1','status':'failed',
 'innerSeconds':5,'outerSeconds':60,'originalFailedJob':'1a1aa2ac597-fc05-3e8f',
 'originalFailedLibrarySha256':'606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
 'originalFailureCode':'current_input_size_bound','originalOutcomeUnknownRetained':True,
 'scope':'sequential current metadata, not a reconstruction or atomic snapshot',
 'expectedLeafCount':46,'expectedDirectoryCount':22,'maxMetadataCalls':MAX_METADATA,
 'maxRegisteredFds':MAX_REGISTERED_FDS,'maxLiveFds':MAX_LIVE_FDS,
 'fileBodyBytesRead':0,'regularFileBodiesRead':False,'fileBodiesHashed':False,
 'metadataOnlyFileDescriptors':True,'sqlExecuted':False,'filesWritten':False,
 'childrenStarted':False,'networkUsed':False,'serviceOperationDispatched':False,
 'captureGuardChanged':False,'sizeCapsChanged':False,'businessReplayed':False,
 'priorExactFailedLeafIdentified':False,'captureOrConsumerQualified':False,
 'directories':[],'leaves':[]}
class Refused(RuntimeError):pass
def need(value,code):
    if not value:raise Refused(code)
def remaining():
    need(pending is None,'observation_cancelled')
    need(time.monotonic()<UNTIL,'original_observation_deadline')
def count():
    global metadata
    remaining();metadata+=1;need(metadata<=MAX_METADATA,'finite_metadata_bound')
def ident(value):
    return [str(x) for x in (value.st_dev,value.st_ino,value.st_uid,value.st_gid,
         value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)]
def on_signal(signum,_):
    global pending
    pending=signum
    if not protected:raise KeyboardInterrupt()
@contextmanager
def critical():
    global protected
    protected+=1
    try:yield
    finally:protected-=1
def close_row(row):
    if row['close_attempted']:return
    with critical():
        row['close_attempted']=True
        try:os.close(row['fd']);row['closed']=True
        except BaseException as error:row['close_error_type']=type(error).__name__
def named(parent,name):
    count()
    return os.lstat('/') if parent is None else os.stat(
        name,dir_fd=parent['fd'],follow_symlinks=False)
def held(row):
    count();return os.fstat(row['fd'])
def open_row(parent,name,path,kind):
    remaining()
    need(len(rows)<MAX_REGISTERED_FDS
         and sum(not r['closed'] for r in rows)<MAX_LIVE_FDS,'finite_descriptor_bound')
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    if kind=='directory':flags|=os.O_DIRECTORY
    with critical():
        fd=os.open(name,flags,**({} if parent is None else {'dir_fd':parent['fd']}))
        row={'fd':fd,'path':path,'kind':kind,'parent':parent,'name':name,
             'close_attempted':False,'closed':False}
        rows.append(row)
    return row
def observe_directory(path):
    global stage
    stage='directory:'+path
    current=Path(path);parent=None if path=='/' else directories.get(str(current.parent))
    public={'path':path,'status':'unobserved','fdOpened':False}
    report['directories'].append(public)
    if path!='/' and (parent is None or parent['status']!='held'):
        need(parent is not None and parent['status'] in ('absent','parent_absent'),'fixed_parent_chain_unavailable')
        public['status']='parent_absent'
        directories[path]={'status':'parent_absent','public':public}
        return
    parent_before=None if parent is None else ident(held(parent))
    name='/' if parent is None else current.name
    try:before=named(parent,name)
    except FileNotFoundError:
        need(parent is not None,'root_directory_required')
        try:named(parent,name)
        except FileNotFoundError:pass
        else:raise Refused('directory_absence_changed')
        after_parent=ident(held(parent))
        need(parent_before==after_parent,'directory_absence_parent_changed')
        public.update(status='absent',twoEnoent=True,heldParentIdentity=parent_before)
        directories[path]={'status':'absent','parent':parent,'name':name,'public':public}
        return
    public['identityBefore']=ident(before)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0,501)
         and not stat.S_IMODE(before.st_mode)&0o022,'fixed_directory_custody')
    row=open_row(parent,name,path,'directory')
    public['fdOpened']=True
    observed=ident(held(row));public['heldIdentity']=observed
    need(observed==ident(before),'directory_named_fd_identity')
    parent_after=None if parent is None else ident(held(parent))
    need(parent_before==parent_after,'directory_parent_changed')
    row.update(status='held',identity=observed,public=public)
    directories[path]=row;public['status']='held'
    remaining()
def observe_leaf(item):
    global stage
    stage='leaf:'+item['label']
    path=Path(item['path']);parent=directories[str(path.parent)]
    public={'label':item['label'],'path':str(path),'role':item['role'],
        'originalMaximumBytes':item['maximum'],'originalOptional':item['optional'],
        'originalPrivateModeRule':item['privateMode'],'status':'unobserved','fdOpened':False}
    report['leaves'].append(public)
    if parent['status']!='held':
        need(parent['status'] in ('absent','parent_absent'),'leaf_parent_unavailable')
        public.update(status='parent_absent',directLeafStatPerformed=False)
        return
    parent_before=ident(held(parent))
    try:before=named(parent,path.name)
    except FileNotFoundError:
        try:named(parent,path.name)
        except FileNotFoundError:pass
        else:raise Refused('leaf_absence_changed')
        parent_after=ident(held(parent))
        need(parent_before==parent_after,'leaf_absence_parent_changed')
        public.update(status='absent',twoEnoent=True,directLeafStatPerformed=True,
                      heldParentIdentity=parent_before)
        return
    first=ident(before);public.update(identityBefore=first,directLeafStatPerformed=True)
    kind=('regular' if stat.S_ISREG(before.st_mode) else
          'symlink' if stat.S_ISLNK(before.st_mode) else
          'directory' if stat.S_ISDIR(before.st_mode) else 'other')
    public['type']=kind
    if kind!='regular':
        last=ident(named(parent,path.name));parent_after=ident(held(parent))
        public.update(identityAfter=last,status='nonregular_not_opened')
        need(first==last and parent_before==parent_after,'nonregular_metadata_changed')
        remaining();return
    row=None
    try:
        row=open_row(parent,path.name,str(path),'regular_metadata_only');public['fdOpened']=True
        observed=ident(held(row));public['heldIdentity']=observed
        need(first==observed,'leaf_named_fd_identity')
        last=ident(named(parent,path.name));last_fd=ident(held(row))
        parent_after=ident(held(parent))
        public.update(identityAfter=last,heldIdentityAfter=last_fd,
                      parentFullIdentityStable=parent_before==parent_after)
        need(first==observed==last==last_fd and parent_before==parent_after,
             'leaf_full_identity_changed')
        private_mode_ok=(stat.S_IMODE(before.st_mode)==0o600 if item['privateMode']
                         else not stat.S_IMODE(before.st_mode)&0o022)
        public.update(status='stable_regular_metadata',
            sizeBytes=str(before.st_size),modeOctal=oct(stat.S_IMODE(before.st_mode)),
            ownerUid=str(before.st_uid),ownerGid=str(before.st_gid),linkCount=str(before.st_nlink),
            originalCaptureCustodyMatches=bool(before.st_uid==501 and before.st_nlink==1
                                               and before.st_size>=0 and private_mode_ok),
            sizeWithinOriginalMaximum=(None if item['maximum'] is None
                                       else before.st_size<=item['maximum']),
            originalDatabaseMinimum512Met=(None if item['role']!='database_main'
                                          else before.st_size>=512),
            presentJournalForbiddenByOriginalContract=item['role']=='database_journal')
    finally:
        if row is not None:
            close_row(row);public['metadataFdClosed']=row['closed']
    need(row is not None and row['closed'],'leaf_metadata_fd_close_unconfirmed')
    remaining()
def final_directories():
    for path in PARENTS:
        remaining();row=directories.get(path)
        if row is None:continue
        if row['status']=='parent_absent':continue
        if row['status']=='absent':
            before=ident(held(row['parent']))
            for _ in range(2):
                try:named(row['parent'],row['name'])
                except FileNotFoundError:pass
                else:raise Refused('final_directory_absence_changed')
            after=ident(held(row['parent']))
            need(before==after,'final_absence_parent_changed')
            row['public']['finalTwoEnoent']=True
            continue
        now=ident(named(row['parent'],row['name']));actual=ident(held(row))
        row['public'].update(identityAfter=now,heldIdentityAfter=actual)
        need(now==actual==row['identity'],'final_directory_identity_changed')
    remaining()
stage='preflight'
try:
    need(sys.platform=='darwin' and os.getuid()==501 and os.getgid()==20,'fixed_mac_owner')
    need(len(TARGETS)==46 and len({t['path'] for t in TARGETS})==46
         and len({t['label'] for t in TARGETS})==46 and len(PARENTS)==22
         and len(set(PARENTS))==22,'fixed_finite_denominator')
    need(all(Path(t['path']).is_relative_to(LIVE)
         and str(Path(t['path']))==t['path'] for t in TARGETS),'fixed_leaf_scope')
    for signum in (signal.SIGTERM,signal.SIGINT):signal.signal(signum,on_signal)
    for path in PARENTS:observe_directory(path)
    for item in TARGETS:observe_leaf(item)
    final_directories()
    need(len(report['leaves'])==46,'complete_finite_leaf_denominator')
    remaining();report['status']='complete_finite_metadata_observation'
except BaseException as error:
    report['errorType']=type(error).__name__
    report['errorCode']=str(error) if type(error) is Refused else None
    error_errno=getattr(error,'errno',None) if isinstance(error,OSError) else None
    report['errorErrno']=error_errno if type(error_errno) is int and 0<error_errno<=4095 else None
    report['errorStage']=stage
finally:
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
    for row in reversed(rows):close_row(row)
    report['descriptorClosure']=[{'path':r['path'],'kind':r['kind'],
        'attempted':r['close_attempted'],'closed':r['closed'],
        'errorType':r.get('close_error_type')} for r in rows]
    report['allOwnedDescriptorsClosed']=all(r['closed'] for r in rows)
    report['registeredDescriptors']=len(rows);report['metadataCalls']=metadata
    report['observedLeafCount']=len(report['leaves'])
    report['observedDirectoryCount']=len(report['directories'])
    completed=time.monotonic();report['elapsedSeconds']=completed-START
    report['originalDeadlineAfterClosure']=completed<UNTIL
    report['outcomeUnknown']=bool(pending is not None or not report['allOwnedDescriptorsClosed'])
    if report['outcomeUnknown'] or completed>=UNTIL:report['status']='failed'
    raw=(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=98304,'bounded_public_metadata_report')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
raise SystemExit(0 if report['status']=='complete_finite_metadata_observation' and time.monotonic()<UNTIL else 1)
