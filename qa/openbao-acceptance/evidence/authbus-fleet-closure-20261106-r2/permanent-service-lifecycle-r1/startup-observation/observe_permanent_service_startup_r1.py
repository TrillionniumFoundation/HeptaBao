"""Read the original closed launchd attempt's two logs and exact plist only."""
import json, os, plistlib, stat, sys, time
from pathlib import Path

START = time.monotonic(); END = START + 20
HOME = Path('/Users/qianqi')
CUSTODY = HOME / 'heptabao-authbus-production-custody'
ROOT = CUSTODY / 'service-lifecycle-r1'
RUNTIME = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-authbus-production')
BINARY = RUNTIME / 'releases/4bde9aee03fcd27c59e13607e529b1cee594b249/heptabao-server'
ROWS, PARENTS, FILES = [], [], []
REPORT = {'schema':'heptabao.permanent-service-original-startup-observation.r1', 'ok':False,
    'originalJob':'1a1b4048166-fc05-85db', 'originalServicePid':19077,
    'serviceActions':0, 'childrenStarted':0, 'httpRequests':0, 'keyOrCredentialFilesRead':0,
    'rawLogContentsOrHashesPublished':False, 'files':[]}

class Refused(Exception): pass
def need(value, code):
    if not value: raise Refused(code)
def live(): need(time.monotonic() < END, 'original_readonly_deadline')
def full(info): return tuple(getattr(info, field) for field in
    ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def opened(name, flags, parent=None):
    live()
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        **({} if parent is None else {'dir_fd':parent}))
    row = {'fd':fd, 'attempts':0, 'closed':False}; ROWS.append(row)
    return row

try:
    need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20,
         'exact_original_mac_owner')
    parent = None
    for path in (Path('/'),Path('/Users'),HOME,CUSTODY,ROOT):
        named = path.lstat() if parent is None else os.stat(path.name,
            dir_fd=parent['fd'],follow_symlinks=False)
        need(stat.S_ISDIR(named.st_mode) and named.st_uid == (0 if path in (Path('/'),Path('/Users')) else 501)
             and not stat.S_IMODE(named.st_mode)&0o022, 'private_original_directory_chain')
        row = opened(str(path) if parent is None else path.name, os.O_RDONLY|os.O_DIRECTORY,
                     None if parent is None else parent['fd'])
        need(full(os.fstat(row['fd'])) == full(named), 'original_parent_name_and_fd')
        PARENTS.append((path,row,full(named))); parent=row
    for name in ('service.stdout.private','service.stderr.private','original-service.plist'):
        named = os.stat(name,dir_fd=parent['fd'],follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) and named.st_uid == 501 and named.st_gid == 20
             and named.st_nlink == 1 and stat.S_IMODE(named.st_mode) == 0o600
             and 0 <= named.st_size <= (16384 if name.endswith('.plist') else 2097152),
             'bounded_original_private_file')
        row=opened(name,os.O_RDONLY,parent['fd']); expected=full(named)
        need(full(os.fstat(row['fd'])) == expected,'original_file_name_and_fd')
        raw=bytearray()
        while len(raw)<=named.st_size:
            live(); block=os.read(row['fd'],min(65536,named.st_size+1-len(raw)))
            if not block: break
            raw.extend(block)
        need(len(raw)==named.st_size and full(os.fstat(row['fd']))==expected
             ==full(os.stat(name,dir_fd=parent['fd'],follow_symlinks=False)),
             'complete_original_file_generation')
        FILES.append((ROOT/name,row,expected))
        item={'kind':'plist' if name.endswith('.plist') else 'stdout' if 'stdout' in name else 'stderr',
              'bytes':len(raw),'completeStableRead':True}
        if name.endswith('.plist'):
            expected_plist={'Label':'org.heptabao.authbus',
                'ProgramArguments':[str(BINARY),'--config',str(RUNTIME/'etc/server-r2.json')],
                'RunAtLoad':True,'KeepAlive':True,'WorkingDirectory':str(RUNTIME),
                'EnvironmentVariables':{'HOME':str(HOME),'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'},
                'ThrottleInterval':10,'ExitTimeOut':30,'Umask':0o077,
                'StandardOutPath':str(ROOT/'service.stdout.private'),
                'StandardErrorPath':str(ROOT/'service.stderr.private')}
            need(plistlib.loads(raw)==expected_plist,'original_service_exact_whole_plist')
            item['exactOriginalPlist']=True
        else:
            lines=bytes(raw).splitlines()
            exact={b'HeptaBao single-node TLS listener ready at 192.168.0.8:31080':'configured_lan_listener_ready',
                b'heptabao-server: cannot open configuration':'configuration_open_refused',
                b'heptabao-server: cannot read configuration':'configuration_read_refused',
                b'heptabao-server: cannot open TLS file':'tls_file_open_refused',
                b'heptabao-server: cannot bind configured listener':'configured_listener_bind_refused'}
            item.update(lineCount=len(lines),recognizedFixedMessages=[exact[line] for line in lines if line in exact],
                unrecognizedLineCount=sum(line not in exact for line in lines),
                productErrorPrefixPresent=any(line.startswith(b'heptabao-server: ') for line in lines),
                dynamicLoaderPrefixPresent=any(line.startswith(b'dyld[') or line.startswith(b'dyld:') for line in lines))
        REPORT['files'].append(item)
    for path,row,expected in PARENTS+FILES:
        need(full(os.fstat(row['fd']))==full(path.lstat())==expected,'all_original_inputs_still_exact')
    live();REPORT['ok']=True
except BaseException as error:
    REPORT['errorCode']=str(error) if isinstance(error,Refused) else type(error).__name__
finally:
    for row in reversed(ROWS):
        row['attempts']=1
        try: os.close(row['fd']);row['closed']=True
        except BaseException: REPORT['ok']=False
    REPORT['allDescriptorsClosedOnce']=all(row['attempts']==1 and row['closed'] for row in ROWS)
    REPORT['descriptors']=len(ROWS)
    try:
        for path,_row,expected in PARENTS+FILES:
            need(full(path.lstat())==expected,'closed_original_names_still_exact')
        live();REPORT['closedOriginalNamesStillExact']=True
    except BaseException: REPORT['ok']=False
    REPORT['elapsedSeconds']=time.monotonic()-START
    REPORT['ok']=bool(REPORT['ok'] and REPORT['allDescriptorsClosedOnce'])
    print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['ok'] else 1)
