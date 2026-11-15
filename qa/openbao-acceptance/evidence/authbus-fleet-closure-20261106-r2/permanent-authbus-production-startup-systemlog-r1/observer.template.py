"""Read a fixed historical startup interval; keep all raw system logs private."""
import ast, hashlib, json, os, re, stat, sys, time, types
from pathlib import Path

# PAYLOAD_PLACEHOLDER
START=time.monotonic(); END=START+45
HOME=Path('/Users/qianqi')
CUSTODY=HOME/'heptabao-authbus-production-custody'
ROOT=CUSTODY/'service-startup-systemlog-r1'
PYTHON=Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
BINARY='/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production/releases/4bde9aee03fcd27c59e13607e529b1cee594b249/heptabao-server'
LABEL='org.heptabao.authbus'
PREDICATE='(process == "tccd" OR process == "syspolicyd" OR process == "amfid" OR process == "launchd") AND (eventMessage CONTAINS[c] "19077" OR eventMessage CONTAINS[c] "org.heptabao.authbus" OR eventMessage CONTAINS[c] "heptabao-server")'
ARGV=['/usr/bin/log','show','--style','json','--start','@1794021555','--end','@1794021590',
      '--info','--debug','--no-pager','--predicate',PREDICATE]
ROWS=[]; PARENTS=[]; root=None; commands=None; signals=None
REPORT={'schema':'heptabao.permanent-startup-fixed-systemlog-observation.r1','ok':False,
    'originalServiceJob':'1a1b4048166-fc05-85db','originalServicePid':19077,
    'startEpoch':1794021555,'endEpoch':1794021590,'parentSeconds':45,'supervisorSeconds':70,
    'serviceActions':0,'networkRequests':0,'keyOrCredentialFilesRead':0,
    'rawSystemLogContentsOrHashesPublished':False,'permissionSettingsChanged':False,
    'causalityEstablishedByMarkerAlone':False,'automaticRetry':False}

class Refused(Exception):pass
def need(value,code):
    if not value:raise Refused(code)
def remaining():
    need(signals is None or signals.pending is None,'original_observer_cancelled')
    left=END-time.monotonic();need(left>0,'original_observer_deadline');return left
def full(s):return tuple(getattr(s,key) for key in
    ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def opened(name,flags,parent=None):
    remaining();fd=os.open(name,flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600,
        **({} if parent is None else {'dir_fd':parent['fd']}))
    row={'fd':fd,'attempts':0,'closed':False};ROWS.append(row);return row
def close(row):
    if row['attempts']:return
    row['attempts']=1;os.close(row['fd']);row['closed']=True
def verify_parents():
    remaining()
    for path,row,identity in PARENTS:
        need(full(os.fstat(row['fd']))[:5]==full(path.lstat())[:5]==identity,
             'same_original_observer_directory_anchor')
def private(name,raw):
    verify_parents();need(name in ('request.public.json','source-pins.public.json',
        'command.original.private.json','stdout.original.private.bin','stderr.original.private.bin'),
        'finite_observer_private_filename')
    need(type(raw)is bytes and len(raw)<=2097152,'bounded_private_observer_output')
    row=opened(name,os.O_RDWR|os.O_CREAT|os.O_EXCL,root)
    try:
        first=os.fstat(row['fd'])
        need(stat.S_ISREG(first.st_mode) and first.st_uid==501 and first.st_gid==20
             and first.st_nlink==1 and stat.S_IMODE(first.st_mode)==0o600 and first.st_size==0,
             'new_private_observer_file')
        at=0
        while at<len(raw):
            remaining();n=os.write(row['fd'],raw[at:at+65536]);need(n>0,'private_write_progress');at+=n
        os.fsync(row['fd']);os.fsync(root['fd']);final=full(os.fstat(row['fd']))
        need(final[:6]==full(first)[:6] and final[6]==len(raw)
             and final==full(os.stat(name,dir_fd=root['fd'],follow_symlinks=False)),
             'private_output_original_generation')
        actual=bytearray()
        while len(actual)<=len(raw):
            remaining();b=os.pread(row['fd'],min(65536,len(raw)+1-len(actual)),len(actual))
            if not b:break
            actual.extend(b)
        need(bytes(actual)==raw and full(os.fstat(row['fd']))==final
             ==full(os.stat(name,dir_fd=root['fd'],follow_symlinks=False)),
             'private_output_complete_readback')
    finally:close(row)
    verify_parents()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def safe_command(row):
    result=dict(row);result.pop('stdoutSha256',None);result.pop('stderrSha256',None)
    result['rawSystemLogDigestsWithheld']=True;return result

try:
    os.umask(0o077);sys.dont_write_bytecode=True
    need(sys.platform=='darwin' and os.getuid()==501 and os.getgid()==20
         and Path(sys.executable).resolve(strict=True)==PYTHON,'exact_mac_observer_runtime')
    for name,source in PAYLOAD['sources'].items():
        raw=source.encode();need(len(raw)==PAYLOAD['pins'][name]['bytes'] and
            hashlib.sha256(raw).hexdigest()==PAYLOAD['pins'][name]['sha256'],'exact_qualified_observer_module')
        ast.parse(raw);module=types.ModuleType(Path(name).stem)
        need(module.__name__ not in sys.modules,'no_preloaded_observer_module')
        module.__file__=str(ROOT/name);sys.modules[module.__name__]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
    from mac_owned_commands_r1 import Commands,Signals
    from mac_public_code_pin_excerpt_r1 import public_code_pin
    signals=Signals();signals.install();commands=Commands(signals)
    tools={path:public_code_pin(path,remaining=remaining,critical=signals.critical)
           for path in (str(PYTHON),'/usr/bin/log','/bin/ps')}
    parent=None
    for path in (Path('/'),Path('/Users'),HOME,CUSTODY):
        row=opened(str(path) if parent is None else path.name,os.O_RDONLY|os.O_DIRECTORY,parent)
        info=os.fstat(row['fd'])
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==(0 if path in (Path('/'),Path('/Users')) else 501)
             and not stat.S_IMODE(info.st_mode)&0o022 and full(info)==full(path.lstat()),
             'private_observer_parent')
        if path==CUSTODY:need(stat.S_IMODE(info.st_mode)==0o700,'original_private_custody_mode')
        PARENTS.append((path,row,full(info)[:5]));parent=row
    os.mkdir(ROOT.name,0o700,dir_fd=parent['fd']);os.fsync(parent['fd'])
    root=opened(ROOT.name,os.O_RDONLY|os.O_DIRECTORY,parent);info=os.fstat(root['fd'])
    need(info.st_uid==501 and info.st_gid==20 and stat.S_IMODE(info.st_mode)==0o700
         and full(info)==full(ROOT.lstat()),'new_private_observer_root')
    PARENTS.append((ROOT,root,full(info)[:5]))
    private('source-pins.public.json',encoded(PAYLOAD['pins']))
    private('request.public.json',encoded({'argv':ARGV,'originalPid':19077,
        'fixedHistoricalWindowSeconds':35,'commandCapSeconds':20,'maximumOutputBytesPerStream':2097152}))
    row,out,err=commands.run('read-original-startup-system-log',ARGV,
        until=min(END,time.monotonic()+20),maximum=2097152)
    private('command.original.private.json',encoded(row))
    private('stdout.original.private.bin',out);private('stderr.original.private.bin',err)
    REPORT['command']=safe_command(row)
    need(row['exitCode']==0 and not row['outcomeUnknown'],'original_systemlog_command_known_zero')
    events=json.loads(out)
    need(type(events)is list and len(events)<=4096,'bounded_complete_systemlog_array')
    projected=[]
    marker_words={'removable_volume':'kTCCServiceSystemPolicyRemovableVolumes',
        'all_files':'kTCCServiceSystemPolicyAllFiles','network_volumes':'kTCCServiceSystemPolicyNetworkVolumes',
        'local_network':'kTCCServiceLocalNetwork','prompt':'prompt','denied':'denied',
        'deny':'deny','granted':'granted','auth_request':'AUTHREQ','exec':'exec',
        'assessment':'assessment','quarantine':'quarantine','signature':'signature',
        'not_permitted':'not permitted','waiting':'waiting'}
    for ordinal,event in enumerate(events):
        need(type(event)is dict and type(event.get('eventMessage'))is str,
             'complete_typed_systemlog_event')
        message=event['eventMessage'];lower=message.lower()
        actor=Path(event.get('processImagePath','')).name
        item={'ordinal':ordinal,'actor':actor if actor in ('tccd','syspolicyd','amfid','launchd') else 'other',
            'originalPidTextPresent':'19077' in message,'exactLabelPresent':LABEL in message,
            'exactBinaryPathPresent':BINARY in message,'productBasenamePresent':'heptabao-server' in message,
            'markers':[key for key,value in marker_words.items() if value.lower() in lower]}
        matches=re.findall(r'\bauthValue[=: ]+(\d{1,2})\b',message)
        item['observedAuthValueFields']=[int(value) for value in matches]
        projected.append(item)
    for path,pin in tools.items():
        need(public_code_pin(path,remaining=remaining,critical=signals.critical)==pin,
             'original_systemlog_runtime_unchanged')
    verify_parents()
    REPORT.update(ok=True,systemLogEvents=len(events),eventProjections=projected,
        rawOutputBytes=len(out),rawErrorBytes=len(err),originalOutputsDurableAndReadBack=True,
        runtimePublicPins=tools)
except BaseException as error:
    REPORT['errorType']=type(error).__name__
    REPORT['errorCode']=str(error) if isinstance(error,Refused) else 'systemlog_observation_refused'
finally:
    if commands is not None:
        state=commands.public()
        REPORT['commands']={**state,'commands':[safe_command(row) if row is not None else None
            for row in state['commands']]}
        if not state['allOwnedCommandsStopped'] or state['unknownCommandCount']:
            REPORT['ok']=False
    for row in reversed(ROWS):
        try:close(row)
        except BaseException:REPORT['ok']=False
    REPORT['allDescriptorsClosedOnce']=all(row['attempts']==1 and row['closed'] for row in ROWS)
    REPORT['descriptorCount']=len(ROWS);REPORT['elapsedSeconds']=time.monotonic()-START
    REPORT['ok']=bool(REPORT['ok'] and REPORT['allDescriptorsClosedOnce'] and
        REPORT['elapsedSeconds']<45 and (signals is None or signals.pending is None))
    print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['ok'] else 1)
