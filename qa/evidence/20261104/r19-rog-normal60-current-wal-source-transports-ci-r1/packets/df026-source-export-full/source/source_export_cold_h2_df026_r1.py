#!/usr/bin/env python3
"""New fixed df026 standalone source export; no source import or application runs.

The source is the independently qualified ROG normal-build canonical clone.
The bundle contains exactly HEAD and its complete ancestry, with zero prerequisites.
"""
from pathlib import Path
import hashlib, json, os, platform, re, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE=Path('/home/qian-qi')
SOURCE=BASE/'heptabao-cold-h2-normal-20261105-r1/source'
ROOT=BASE/'heptabao-cold-h2-source-export-20261105-r1'
CONTROL=ROOT
BUNDLE=ROOT/'canonical-df026-full.bundle'
CANONICAL='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
PARENT='6304a898192bfdf7eabec3c4ea40f7166e59a137'
ROOT_COMMIT='67d79b3b5442ed033d38929eab2010403463e56d'
CANONICAL_COUNT=3757
MAX_BUNDLE=64*1024*1024
UID=1000
SYSTEM=('Linux','x86_64')
ACTION='export-standalone-cold-h2-df026'
START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
result={'schema':'heptabao.cold-h2.rog-df026-standalone-source-export.v1','action':ACTION,
 'started_unix_ns':time.time_ns(),'canonical_commit':CANONICAL,'canonical_tree':TREE,
 'expected_full_commit_count':CANONICAL_COUNT,'expected_prerequisites':[],
 'source_imported':False,'network_git_protocols_enabled':False,
 'server_started':False,'compiler_started':False,'runtime_qualification':False,
 'product_tests_executed':0,'overall_seconds':300,'git_command_seconds':90,
 'maximum_bundle_bytes':MAX_BUNDLE,'status':'failed'}

class Cancelled(BaseException):pass

def on_signal(signum,_frame):
    global pending_signal
    pending_signal=signum
    if not protected:raise Cancelled()

for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,on_signal)

def digest(raw):return hashlib.sha256(raw).hexdigest()

def identity(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def remaining(until=UNTIL):
    n=until-time.monotonic()
    assert n>0,'original controller deadline exhausted'
    return n

def stable(path,cap=2*1024*1024):
    assert path.resolve(strict=True)==path
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        assert stat.S_ISREG(s.st_mode) and s.st_uid==UID and s.st_nlink==1 and 0<=s.st_size<=cap
        chunks=[];n=0
        while True:
            block=os.read(fd,min(65536,cap+1-n))
            if not block:break
            chunks.append(block);n+=len(block);assert n<=cap
        raw=b''.join(chunks)
        assert n==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat())
        return raw,{'bytes':n,'sha256':digest(raw),'identity':identity(s)}
    finally:os.close(fd)

def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def create(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())

def public(path,value):
    create(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())
    fsync_dir(path.parent)

def process_snapshot():
    p=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,stat='],
       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=True)
    found=[]
    for line in p.stdout.decode('ascii').splitlines():
        v=line.split()
        if len(v)>=4:
            found.append({'pid':int(v[0]),'ppid':int(v[1]),'pgid':int(v[2]),'state':v[3]})
    return found

def group_members(pgid):
    return [row for row in process_snapshot() if row['pgid']==pgid]

def stop_active(p):
    if p.poll() is None:
        try:os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=5)

def stop_owned(p):
    stop_active(p)
    return group_members(p.pid)

environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',
 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
 'GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1',
 'GIT_ALLOW_PROTOCOL':'file'}

def persist_command(prefix,out,err,row):
    if not created_control:
        deferred_logs.append((prefix,out,err,row))
        return
    create(CONTROL/(prefix+'.stdout'),out)
    create(CONTROL/(prefix+'.stderr'),err)
    public(CONTROL/(prefix+'.public.json'),row)

def owned_argv(label,argv,limit,allowed=(0,)):
    global protected
    begin=time.monotonic();until=min(UNTIL,begin+limit)
    remaining(until)
    prefix='%03d-%s'%(len(children),label)
    protected+=1
    try:
        remaining(until)
        p=subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        children.append((prefix,p))
    finally:protected-=1
    if pending_signal is not None:raise Cancelled()
    timed_out=False
    try:out,err=p.communicate(timeout=remaining(until))
    except subprocess.TimeoutExpired:
        timed_out=True;stop_owned(p);out,err=p.communicate(timeout=5)
    finally:
        if p.poll() is None:stop_owned(p)
    rem=group_members(p.pid)
    assert len(out)<=2*1024*1024 and len(err)<=2*1024*1024
    row={'label':prefix,'argv':argv,'exit_code':p.returncode,'pid':p.pid,
      'elapsed_seconds':time.monotonic()-begin,'limit_seconds':limit,'timed_out':timed_out,
      'stdout_bytes':len(out),'stdout_sha256':digest(out),'stderr_bytes':len(err),
      'stderr_sha256':digest(err),'direct_child_reaped':p.returncode is not None,'remaining':rem}
    commands.append(row);persist_command(prefix,out,err,row)
    assert not timed_out and not rem and p.returncode in allowed,'owned command failed: '+label
    return p.returncode,out

def owned(label,path,*command,allowed=(0,)):
    argv=['/usr/bin/git','-c','gc.auto=0','-c','maintenance.auto=false',
       '-c','core.hooksPath='+str(CONTROL/'empty-hooks'),
       '-c','core.fsmonitor=false','-c','log.showSignature=false',
       '-c','protocol.allow=never','-c','protocol.file.allow=always',
       '-c','pack.threads=1','-C',str(path),*command]
    return owned_argv(label,argv,90,allowed)

def git(label,path,*command,**kwargs):
    code,raw=owned(label,path,*command,**kwargs)
    return code,raw.decode('utf-8').strip()

def freeze(name,path,head,tree,independent):
    assert path.resolve(strict=True)==path and path.is_dir() and path.stat().st_uid==UID
    _,actual_head=git(name+'-head',path,'rev-parse','--verify','HEAD')
    _,actual_tree=git(name+'-tree',path,'rev-parse','HEAD^{tree}')
    _,status=owned(name+'-status',path,'status','--porcelain=v1','--untracked-files=all')
    _,absolute=git(name+'-git-dir',path,'rev-parse','--absolute-git-dir')
    gitdir=Path(absolute)
    assert gitdir.resolve(strict=True)==gitdir and gitdir.is_relative_to(BASE) and gitdir.is_dir()
    _,common=git(name+'-common-dir',path,'rev-parse','--git-common-dir')
    common_path=(path/common).resolve(strict=True)
    assert common_path.is_relative_to(BASE) and common_path.is_dir()
    if independent:assert gitdir==path/'.git' and common_path==gitdir and gitdir.stat().st_uid==UID
    assert not (common_path/'objects/info/alternates').exists()
    _,shallow=git(name+'-shallow',path,'rev-parse','--is-shallow-repository')
    _,partial=owned(name+'-partial-config',path,'config','--local','--get-regexp',
       r'^(extensions[.]partialclone|remote[.].*[.]promisor|remote[.].*[.]partialclonefilter)$',allowed=(0,1))
    assert actual_head==head and actual_tree==tree and not status and shallow=='false' and not partial
    locks={x:(gitdir/x).exists() for x in ('index.lock','packed-refs.lock','shallow.lock','config.lock')}
    assert not any(locks.values())
    return {'head':actual_head,'tree':actual_tree,'clean':True,'shallow':False,
       'git_directory':str(gitdir),'git_common_directory':str(common_path),
       'independent_git_directory':gitdir==path/'.git' and common_path==gitdir,
       'no_alternates':True,'no_partial_clone':True,'lock_files':locks}

def source_snapshot(label):
    snapshot=freeze(label,SOURCE,CANONICAL,TREE,True)
    gitdir=Path(snapshot['git_directory'])
    for relative in ('info/grafts','objects/info/alternates'):
        path=gitdir/relative
        assert not path.exists() and not path.is_symlink()
    _,origin=owned(label+'-origin',SOURCE,'config','--local','--get','remote.origin.url')
    assert origin.endswith(b'\n') and len(origin)<=4096
    _,refs=owned(label+'-refs',SOURCE,'for-each-ref','--format=%(refname) %(objectname)')
    snapshot['origin_bytes']=len(origin)
    snapshot['origin_sha256']=digest(origin)
    snapshot['refs_bytes']=len(refs)
    snapshot['refs_sha256']=digest(refs)
    snapshot['no_grafts']=True
    return snapshot

def bundle_header(raw):
    end=raw.find(b'\n\n',0,65536)
    assert end>0 and raw[end+2:end+6]==b'PACK'
    lines=raw[:end].split(b'\n')
    assert lines==[b'# v2 git bundle',(CANONICAL+' HEAD').encode('ascii')]
    return {'version':2,'prerequisites':[],'heads':[[CANONICAL,'HEAD']],
            'header_bytes':end+2,'header_sha256':digest(raw[:end+2])}

def prove_canonical(label):
    _,kind=git(label+'-kind',SOURCE,'cat-file','-t',CANONICAL);assert kind=='commit'
    _,tree=git(label+'-tree',SOURCE,'rev-parse',CANONICAL+'^{tree}');assert tree==TREE
    _,parents=git(label+'-parents',SOURCE,'show','-s','--format=%P',CANONICAL);assert parents==PARENT
    _,count=git(label+'-count',SOURCE,'rev-list','--count',CANONICAL);assert count==str(CANONICAL_COUNT)
    _,roots=git(label+'-roots',SOURCE,'rev-list','--max-parents=0',CANONICAL);assert roots==ROOT_COMMIT
    owned(label+'-full-fsck',SOURCE,'fsck','--full','--strict','--no-reflogs','--no-dangling',CANONICAL)
    return {'commit':CANONICAL,'tree':tree,'parents':[parents],'root':roots,
            'commit_count':int(count),'full_fsck_passed':True}

try:
    assert (platform.system(),platform.machine())==SYSTEM and os.getuid()==UID
    assert BASE.resolve(strict=True)==BASE and BASE.is_dir() and BASE.stat().st_uid==UID
    assert SOURCE.resolve(strict=True)==SOURCE and SOURCE.is_dir() and SOURCE.stat().st_uid==UID
    assert not ROOT.exists() and not ROOT.is_symlink()
    remaining()
    ROOT.mkdir(mode=0o700);created_control=True
    fsync_dir(BASE)
    (CONTROL/'empty-hooks').mkdir(mode=0o700)
    source_raw,source_id=stable(Path(__file__).resolve(strict=True))
    result['controller']=source_id
    result['source']=str(SOURCE)
    public(CONTROL/'intent.public.json',{'schema':result['schema'],'action':ACTION,
      'controller':source_id,'canonical_commit':CANONICAL,'canonical_tree':TREE,
      'expected_prerequisites':[],'expected_full_commit_count':CANONICAL_COUNT,
      'source':str(SOURCE),'bundle':str(BUNDLE),'maximum_bundle_bytes':MAX_BUNDLE,
      'overall_seconds':300,'git_command_seconds':90,
      'network_git_protocols_enabled':False,'compiler_started':False,'server_started':False})
    result['source_before']=source_snapshot('source-before')
    result['canonical_proof']=prove_canonical('export-proof')
    assert not BUNDLE.exists() and not BUNDLE.is_symlink()
    owned('bundle-create',SOURCE,'bundle','create','--version=2',str(BUNDLE),'HEAD')
    raw,binding=stable(BUNDLE,MAX_BUNDLE)
    assert 0<len(raw)<=MAX_BUNDLE
    fd=os.open(BUNDLE,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        assert identity(os.fstat(fd))==binding['identity']
        os.fsync(fd)
        assert identity(os.fstat(fd))==identity(BUNDLE.lstat())==binding['identity']
    finally:os.close(fd)
    fsync_dir(CONTROL)
    result['bundle']={'path':str(BUNDLE),**binding,'header':bundle_header(raw)}
    owned('bundle-verify',SOURCE,'bundle','verify',str(BUNDLE))
    _,heads=git('bundle-heads',SOURCE,'bundle','list-heads',str(BUNDLE))
    assert heads==CANONICAL+' HEAD'
    result['source_after']=source_snapshot('source-after')
    assert result['source_before']==result['source_after']
    assert stable(BUNDLE,MAX_BUNDLE)[1]==binding
    assert stable(Path(__file__).resolve(strict=True))[1]==source_id
    remaining()
    result['status']='exported'
except BaseException as error:
    result['status']='failed'
    result['error_type']=type(error).__name__
    frames=[];tb=error.__traceback__
    while tb is not None:
        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
    result['failure_frames']=frames
finally:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    signal.signal(signal.SIGINT,signal.SIG_IGN)
    stop_errors={}
    for label,p in reversed(children):
        try:stop_active(p)
        except BaseException as error:stop_errors[label]=type(error).__name__
    try:
        snapshot=process_snapshot()
        snapshot_error=None
    except BaseException as error:
        snapshot=None;snapshot_error=type(error).__name__
    cleanup=[]
    for label,p in reversed(children):
        row={'label':label,'pid':p.pid,'exit_code':p.returncode,
             'direct_child_reaped':p.returncode is not None,
             'remaining':None if snapshot is None else [x for x in snapshot if x['pgid']==p.pid]}
        if label in stop_errors:row['cleanup_error_type']=stop_errors[label]
        if snapshot_error is not None:row['snapshot_error_type']=snapshot_error
        cleanup.append(row)
    result['commands']=commands
    result['cleanup']=cleanup
    result['all_owned_stopped']=bool(cleanup) and all(
        x.get('direct_child_reaped') and x.get('remaining')==[] and
        'cleanup_error_type' not in x and 'snapshot_error_type' not in x for x in cleanup)
    if pending_signal is not None or not result['all_owned_stopped']:result['status']='failed'
    result['deadline_before_receipt_passed']=time.monotonic()<UNTIL
    if not result['deadline_before_receipt_passed']:result['status']='failed'
    result['success_requires_authoritative_exit_zero']=True
    result['success_requires_terminal_publication_within_original_deadline']=True
    result['elapsed_seconds']=time.monotonic()-START
    result['terminal_unix_ns']=time.time_ns()
    if created_control:
        public(CONTROL/'result.public.json',result)
        fsync_dir(ROOT)
    publication_within_deadline=time.monotonic()<UNTIL
    terminal_status=result['status'] if publication_within_deadline else 'failed'
    terminal={'status':terminal_status,'action':ACTION,
       'receipt':str(CONTROL/'result.public.json') if created_control else None,
       'receipt_candidate_status':result['status'],
       'canonical_commit':CANONICAL,'canonical_tree':TREE,
       'all_owned_stopped':result['all_owned_stopped'],
       'publication_within_original_deadline':publication_within_deadline,
       'elapsed_after_publication_seconds':time.monotonic()-START,
       'server_started':False,'compiler_started':False}
    if not created_control:
        terminal['unpublished_failed_result']=result
    print(json.dumps(terminal,sort_keys=True),flush=True)
sys.exit(0 if terminal_status=='exported' and time.monotonic()<UNTIL else 1)
