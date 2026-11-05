#!/usr/bin/env python3
"""Receive fixed R10 public artifacts and one standalone full Git bundle.

No old X230 repository is used as a prerequisite. No binary, compiler, provider
request, acceptance suite or production service is started.
"""
from pathlib import Path
import hashlib, json, os, platform, re, select, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE=Path('/home/qian')
ROOT=BASE/'heptabao-blocker-closure-r10-49503322-20261104-r1'
CONTROL=ROOT/'control'
ART=ROOT/'artifacts'
SOURCE=ROOT/'source'
CANONICAL='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
PARENT='1d12abc45a83d4b32e7185d01a876eb93110b1e2'
ROOT_COMMIT='67d79b3b5442ed033d38929eab2010403463e56d'
CANONICAL_COUNT=3752
TRACKED_FILES=3911
MAX_BUNDLE=64*1024*1024
UID=1000
SYSTEM=('Linux','x86_64')
FILES=[
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming/heptabao-server",
    "name": "heptabao-server",
    "bytes": 109091112,
    "sha256": "67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113",
    "source_mode": 320,
    "target_mode": 320,
    "version": "2050:58120239:109091112:1793819286714153802:1793819286714153802"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming/native-build.public.json",
    "name": "native-build.public.json",
    "bytes": 801,
    "sha256": "0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:58120241:801:1793819287399134926:1793819287399134926"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-shared-artifacts-r1/incoming/normal-release-result.public.json",
    "name": "result.public.json",
    "bytes": 3227,
    "sha256": "75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:58120242:3227:1793819287404134788:1793819287404134788"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-x230-source-export-r1/canonical-r10-full.bundle",
    "name": "canonical-r10-full.bundle",
    "bytes": 20091909,
    "sha256": "6fb2b73c52a880475ce8c45c67a4179575834313ee24ed761af94ea3faaaa858",
    "source_mode": 384,
    "target_mode": 256,
    "version": "2050:58372900:20091909:1793819761984976492:1793819761988976381"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-x230-source-export-r1/result.public.json",
    "name": "source-export.result.public.json",
    "bytes": 40100,
    "sha256": "6342a59b3a953c5e701887cceac8cc7274850f76f65b718b427485bd5b29951e",
    "source_mode": 384,
    "target_mode": 256,
    "version": "2050:58372937:40100:1793819763173944963:1793819763173944963"
  }
]

START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
result={'schema':'heptabao.r10.x230-standalone-source-receiver.v1','status':'failed',
 'source_commit':CANONICAL,'source_tree':TREE,'expected_full_commit_count':CANONICAL_COUNT,
 'expected_prerequisites':[],'network_git_protocols_enabled':False,'old_source_opened':False,
 'server_started':False,'compiler_started':False,'runtime_qualification':False,
 'product_tests_executed':0,'overall_seconds':300,'git_command_seconds':60,
 'clone_seconds':90,'maximum_bundle_bytes':MAX_BUNDLE,'automatic_retry':False,
 'production_changed':False,'partial_root_retained_on_failure':True}

class Cancelled(BaseException):pass

def on_signal(signum,_frame):
    global pending_signal
    pending_signal=signum
    if not protected:raise Cancelled()

for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,on_signal)

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

def owned(label,path,*command,allowed=(0,),limit=60):
    argv=['/usr/bin/git','-c','gc.auto=0','-c','maintenance.auto=false',
       '-c','core.hooksPath='+str(CONTROL/'empty-hooks'),
       '-c','core.fsmonitor=false','-c','log.showSignature=false',
       '-c','protocol.allow=never','-c','protocol.file.allow=always',
       '-c','pack.threads=1','-C',str(path),*command]
    return owned_argv(label,argv,limit,allowed)

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

def read_file(fd,size,expected,retain=False):
    os.lseek(fd,0,os.SEEK_SET)
    h=hashlib.sha256();n=0;parts=[]
    while True:
        remaining();block=os.read(fd,65536)
        if not block:break
        n+=len(block);assert n<=size;h.update(block)
        if retain:parts.append(block)
    assert n==size and h.hexdigest()==expected
    return {'bytes':n,'sha256':h.hexdigest()},b''.join(parts) if retain else None

def receive_files():
    results=[];json_bytes={}
    for item in FILES:
        remaining();path=ART/item['name']
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            count=0;h=hashlib.sha256()
            while count<item['bytes']:
                assert select.select([0],[],[],remaining())[0]
                try:block=os.read(0,min(65536,item['bytes']-count))
                except (BlockingIOError,InterruptedError):continue
                assert block,'truncated fixed public artifact stream'
                count+=len(block);h.update(block);view=memoryview(block)
                while view:
                    remaining();n=os.write(fd,view);assert n>0;view=view[n:]
            assert count==item['bytes'] and h.hexdigest()==item['sha256']
            os.fchmod(fd,item['target_mode']);os.fsync(fd)
            before=os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
            assert before.st_size==item['bytes'] and stat.S_IMODE(before.st_mode)==item['target_mode']
            same_fd,raw=read_file(fd,item['bytes'],item['sha256'],item['name'].endswith('.json'))
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
            if raw is not None:json_bytes[item['name']]=raw
            results.append({'name':item['name'],'path':str(path),'bytes':count,
                'sha256':h.hexdigest(),'mode':item['target_mode'],'create_only':True,
                'fsynced':True,'identity':identity(before),'same_fd_readback':same_fd})
        finally:os.close(fd)
    assert select.select([0],[],[],remaining())[0]
    assert os.read(0,1)==b'','unexpected fixed public artifact stream trailer'
    assert sorted(os.listdir(ART))==sorted(x['name'] for x in FILES)
    fsync_dir(ART);remaining()
    return results,json_bytes

def verify_receipts(raw):
    native=json.loads(raw['native-build.public.json'])
    build=json.loads(raw['result.public.json'])
    exported=json.loads(raw['source-export.result.public.json'])
    assert native['source_commit']==build['source_commit']==CANONICAL
    assert native['source_tree']==build['source_tree']==TREE
    assert native['binary_sha256']==build['artifacts']['heptabao-server']['sha256']==FILES[0]['sha256']
    assert build['artifacts']['heptabao-server']['bytes']==FILES[0]['bytes']
    assert native['provenance']['result_sha256']==FILES[2]['sha256']
    assert native['build_exit_code']==build['build_exit_code']==0
    assert native['features']==build['artifacts']['heptabao-server']['features']==['default','native-v6-ha','native-v6-storage']
    assert native['native_abi']==build['native_abi']=='x86_64-unknown-linux-gnu'
    assert native['source_freeze_verified'] and build['source_freeze_verified']
    assert build['normal_default_candidate'] and build['build_finished_success']
    assert not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert exported['status']=='exported' and exported['all_owned_stopped']
    assert exported['canonical_commit']==CANONICAL and exported['canonical_tree']==TREE
    assert exported['deadline_before_receipt_passed']
    assert exported['canonical_proof']=={
        'commit':CANONICAL,'tree':TREE,'parents':[PARENT],'root':ROOT_COMMIT,
        'commit_count':CANONICAL_COUNT,'full_fsck_passed':True}
    assert exported['source_before']==exported['source_after']
    assert exported['bundle']['bytes']==FILES[3]['bytes']
    assert exported['bundle']['sha256']==FILES[3]['sha256']
    assert exported['bundle']['header']['prerequisites']==[]
    assert exported['bundle']['header']['heads']==[[CANONICAL,'HEAD']]
    result['normal_release_provenance_verified']=True
    result['export_receipt_verified']=True
    result['raw_receipts_preserved']=True

def bundle_header(raw):
    end=raw.find(b'\n\n',0,65536)
    assert end>0 and raw[end+2:end+6]==b'PACK'
    assert raw[:end].split(b'\n')==[b'# v2 git bundle',(CANONICAL+' HEAD').encode('ascii')]
    return {'version':2,'prerequisites':[],'heads':[[CANONICAL,'HEAD']],
            'header_bytes':end+2,'header_sha256':digest(raw[:end+2])}

def prove_canonical():
    _,kind=git('canonical-kind',SOURCE,'cat-file','-t',CANONICAL);assert kind=='commit'
    _,tree=git('canonical-tree',SOURCE,'rev-parse',CANONICAL+'^{tree}');assert tree==TREE
    _,parents=git('canonical-parents',SOURCE,'show','-s','--format=%P',CANONICAL);assert parents==PARENT
    _,count=git('canonical-count',SOURCE,'rev-list','--count',CANONICAL);assert count==str(CANONICAL_COUNT)
    _,roots=git('canonical-roots',SOURCE,'rev-list','--max-parents=0',CANONICAL);assert roots==ROOT_COMMIT
    owned('canonical-full-fsck',SOURCE,'fsck','--full','--strict','--no-reflogs','--no-dangling',CANONICAL)
    return {'commit':CANONICAL,'tree':tree,'parents':[parents],'root':roots,
            'commit_count':int(count),'full_fsck_passed':True}

def verify_materialized_and_fsync():
    _,tree_raw=owned('materialized-tree',SOURCE,'ls-tree','-rz','--full-tree',CANONICAL)
    _,index_raw=owned('materialized-index',SOURCE,'ls-files','--stage','-z')
    expected={}
    for row in tree_raw.split(b'\0'):
        if not row:continue
        meta,path=row.split(b'\t',1);mode,kind,oid=meta.split(b' ')
        assert kind==b'blob' and mode in (b'100644',b'100755')
        relative=path.decode('utf-8')
        assert relative and not relative.startswith('/') and '..' not in Path(relative).parts
        assert relative not in expected
        expected[relative]=(mode.decode('ascii'),oid.decode('ascii'))
    indexed={}
    for row in index_raw.split(b'\0'):
        if not row:continue
        meta,path=row.split(b'\t',1);mode,oid,stage=meta.split(b' ')
        assert stage==b'0'
        relative=path.decode('utf-8');assert relative not in indexed
        indexed[relative]=(mode.decode('ascii'),oid.decode('ascii'))
    assert len(expected)==TRACKED_FILES and indexed==expected
    _,sparse=owned('no-sparse-config',SOURCE,'config','--local','--get-regexp',
        r'^(core[.]sparseCheckout|core[.]sparseCheckoutCone|extensions[.]worktreeConfig)$',allowed=(0,1))
    assert not sparse
    gitdir=SOURCE/'.git'
    for relative in ('objects/info/alternates','info/grafts','commondir','info/sparse-checkout'):
        path=gitdir/relative
        assert not path.exists() and not path.is_symlink()
    tracked_fsynced=set()
    for relative,(mode,oid) in expected.items():
        remaining();path=SOURCE/relative
        assert path.resolve(strict=True)==path
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
            assert bool(before.st_mode&0o111)==(mode=='100755')
            h=hashlib.sha1();h.update(('blob '+str(before.st_size)+'\0').encode('ascii'));count=0
            while True:
                remaining();block=os.read(fd,65536)
                if not block:break
                count+=len(block);assert count<=before.st_size;h.update(block)
            assert count==before.st_size and h.hexdigest()==oid
            os.fsync(fd)
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        finally:os.close(fd)
        tracked_fsynced.add(path)
    files=0;directories=0
    def walk_error(error):
        raise error
    for directory,dirs,names in os.walk(SOURCE,followlinks=False,onerror=walk_error):
        remaining();directory=Path(directory)
        assert directory.resolve(strict=True)==directory
        for name in dirs:
            path=directory/name;before=path.lstat()
            assert stat.S_ISDIR(before.st_mode) and before.st_uid==UID
        for name in names:
            path=directory/name;before=path.lstat()
            assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
            if path not in tracked_fsynced:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    assert identity(before)==identity(os.fstat(fd))
                    os.fsync(fd)
                    assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
                finally:os.close(fd)
            files+=1
        fsync_dir(directory);directories+=1
    fsync_dir(ROOT)
    return {'tracked_files':len(expected),'tree_equals_index':True,'actual_git_blob_bytes_verified':True,
            'no_sparse_checkout':True,'no_symlinks_or_hardlinks':True,
            'fsynced_files':files,'fsynced_directories':directories}

def recheck_artifacts(before_rows):
    for item,before_row in zip(FILES,before_rows,strict=True):
        path=ART/item['name']
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            assert identity(before)==before_row['identity']
            read_file(fd,item['bytes'],item['sha256'])
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        finally:os.close(fd)

try:
    assert (platform.system(),platform.machine())==SYSTEM and os.getuid()==UID
    assert BASE.resolve(strict=True)==BASE and BASE.is_dir() and BASE.stat().st_uid==UID
    assert len(sys.argv)==2 and re.fullmatch(r'[0-9a-f]{64}',sys.argv[1])
    assert sys.orig_argv[:5]==['/usr/bin/python3','-I','-S','-B','-c']
    assert len(sys.orig_argv)==7 and sys.orig_argv[6]==sys.argv[1]
    controller_raw=sys.orig_argv[5].encode('utf-8')
    assert digest(controller_raw)==sys.argv[1]
    assert not ROOT.exists() and not ROOT.is_symlink()
    remaining();ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700);created_control=True
    ART.mkdir(mode=0o700);(CONTROL/'empty-hooks').mkdir(mode=0o700)
    fsync_dir(BASE);fsync_dir(ROOT)
    create(CONTROL/'receiver.py',controller_raw)
    result['controller']={'bytes':len(controller_raw),'sha256':digest(controller_raw)}
    public(CONTROL/'intent.public.json',{**result,'files':FILES,'source':str(SOURCE),
        'receipt':str(ART/'transfer.result.public.json'),'binary_execution_allowed':False})
    file_rows,json_bytes=receive_files()
    result['file_results']=file_rows
    verify_receipts(json_bytes)
    bundle=ART/'canonical-r10-full.bundle'
    raw,binding=stable(bundle,MAX_BUNDLE)
    assert binding['bytes']==FILES[3]['bytes'] and binding['sha256']==FILES[3]['sha256']
    result['bundle_header']=bundle_header(raw)
    del raw
    owned('standalone-clone',ROOT,'clone','--no-checkout','--no-hardlinks','--',str(bundle),str(SOURCE),limit=90)
    owned('bundle-verify',SOURCE,'bundle','verify',str(bundle))
    _,heads=git('bundle-heads',SOURCE,'bundle','list-heads',str(bundle))
    assert heads==CANONICAL+' HEAD'
    owned('canonical-checkout',SOURCE,'checkout','--detach',CANONICAL)
    owned('remove-local-origin',SOURCE,'remote','remove','origin')
    result['canonical_proof']=prove_canonical()
    result['materialized']=verify_materialized_and_fsync()
    result['source_after']=freeze('source-after',SOURCE,CANONICAL,TREE,True)
    recheck_artifacts(file_rows)
    assert stable(bundle,MAX_BUNDLE)[1]==binding
    assert stable(CONTROL/'receiver.py')[0]==controller_raw
    remaining()
    result['transfer_passed']=True
    result['status']='complete'
except BaseException as error:
    result['status']='failed';result['transfer_passed']=False
    result['error_type']=type(error).__name__
    frames=[];tb=error.__traceback__
    while tb is not None:
        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
    result['failure_frames']=frames
finally:
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
    errors={}
    for label,p in reversed(children):
        try:stop_active(p)
        except BaseException as error:errors[label]=type(error).__name__
    rows=None;snapshot_error=None
    try:rows=process_snapshot() if children else []
    except BaseException as error:snapshot_error=type(error).__name__
    cleanup=[]
    for label,p in children:
        row={'label':label,'pid':p.pid,'exit_code':p.returncode,
             'direct_child_reaped':p.returncode is not None,
             'remaining':None if rows is None else [x for x in rows if x['pgid']==p.pid]}
        if label in errors:row['cleanup_error_type']=errors[label]
        if snapshot_error is not None:row['snapshot_error_type']=snapshot_error
        cleanup.append(row)
    result['commands']=commands;result['cleanup']=cleanup
    result['all_owned_stopped']=not errors and snapshot_error is None and all(
        row['direct_child_reaped'] and row['remaining']==[] for row in cleanup)
    result['within_original_deadline']=time.monotonic()<UNTIL
    result['elapsed_seconds']=time.monotonic()-START
    if pending_signal is not None or not result['all_owned_stopped'] or not result['within_original_deadline']:
        result['status']='failed';result['transfer_passed']=False
    result['success_requires_authoritative_exit_zero']=True
    result['success_requires_terminal_publication_within_original_deadline']=True
    if created_control:
        receipt=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
        public_path=ART/'transfer.result.public.json'
        create(public_path,receipt);fsync_dir(ART);fsync_dir(ROOT)
        result['receipt']={'path':str(public_path),'bytes':len(receipt),'sha256':digest(receipt)}
    result['publication_within_original_deadline']=time.monotonic()<UNTIL
    if not result['publication_within_original_deadline']:
        result['status']='failed';result['transfer_passed']=False
    sys.stderr.write(json.dumps(result,sort_keys=True)+'\n');sys.stderr.flush()
sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)
