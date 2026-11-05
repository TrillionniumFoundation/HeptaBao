#!/usr/bin/env python3
"""Import one fixed, already received standalone 3cb public source bundle locally.

This is a new source-only draft: unresolved actual transport metadata refuses
before any filesystem access or Git child. No old source, binary, compiler,
provider request, acceptance suite or production service is used or started.
"""
from pathlib import Path
import hashlib, json, os, platform, re, select, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
ROOT=BASE/'normal-phaseb-ingress-observer-source-import-r1'
CONTROL=ROOT/'control'
CARRIER=BASE/'normal-phaseb-ingress-observer-source-carrier-r1'
ART=CARRIER/'incoming'
SOURCE=BASE/'normal-phaseb-ingress-observer-source-r1'
CANONICAL='3cb873919170cc77101b27f6a3ab9e98f41f8d93'
TREE='7f4d48a647a81ca96e8a24a0a057c2c829459060'
PARENT='bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24'
ROOT_COMMIT='67d79b3b5442ed033d38929eab2010403463e56d'
CANONICAL_COUNT=3755
TRACKED_FILES=3911
MAX_BUNDLE=64*1024*1024
UID=1000
SYSTEM=('Linux','x86_64')
ACTUAL_INPUTS_READY=False
SOURCE_FILES=[
  {
    "bytes": 23335023,
    "name": "canonical-3cb-full.bundle",
    "path": "/home/qian-qi/heptabao-phaseb-ingress-observer-source-export-20261104-r1/canonical-3cb-full.bundle",
    "sha256": "25020ee42fe92f95c9408cb937dc507430f18b84fdaef7ec438a0a233de1438b",
    "source_mode": 384,
    "target_mode": 256,
    "version": "66306:28324895:23335023:1793839385060504547:1793839385063504533"
  },
  {
    "bytes": 39965,
    "name": "source-export.result.public.json",
    "path": "/home/qian-qi/heptabao-phaseb-ingress-observer-source-export-20261104-r1/result.public.json",
    "sha256": "3619fafe30f3a025b193139e55800d19cc5d4e8772c6388cbd3f3c170d4bf448",
    "source_mode": 384,
    "target_mode": 256,
    "version": "66306:28324969:39965:1793839385327147652:1793839385327147652"
  }
]
FILES=[
  {
    "name": "canonical-3cb-full.bundle",
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1/incoming/canonical-3cb-full.bundle",
    "bytes": 23335023,
    "sha256": "25020ee42fe92f95c9408cb937dc507430f18b84fdaef7ec438a0a233de1438b",
    "mode": 256,
    "version": None
  },
  {
    "name": "source-export.result.public.json",
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1/incoming/source-export.result.public.json",
    "bytes": 39965,
    "sha256": "3619fafe30f3a025b193139e55800d19cc5d4e8772c6388cbd3f3c170d4bf448",
    "mode": 256,
    "version": None
  }
]
TRANSFER={
  "name": "source-carrier.result.public.json",
  "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1/control/result.public.json",
  "bytes": None,
  "sha256": None,
  "mode": 384,
  "version": None
}

START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
input_handles=[]
input_directories=[]
result={'schema':'heptabao.phaseb3cb.desktop-standalone-source-import.v1','status':'failed',
 'source_commit':CANONICAL,'source_tree':TREE,'expected_full_commit_count':CANONICAL_COUNT,
 'expected_prerequisites':[],'network_git_protocols_enabled':False,'old_source_opened':False,
 'server_started':False,'compiler_started':False,'runtime_qualification':False,
 'product_tests_executed':0,'overall_seconds':300,'git_command_seconds':60,
 'clone_seconds':90,'maximum_bundle_bytes':MAX_BUNDLE,'automatic_retry':False,
 'production_changed':False,'partial_root_retained_on_failure':True,
 'source_imported':False,'input_transport_performed':False}

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

def directory_key(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]

def hold_input_directories():
    global protected
    specs=[(BASE,None,None,None),(CARRIER,0,CARRIER.name,0o700),
           (ART,1,'incoming',0o500),(CARRIER/'control',1,'control',0o700)]
    for path,parent_index,name,mode in specs:
        remaining()
        if parent_index is None:assert path.resolve(strict=True)==path
        protected+=1
        try:
            if parent_index is None:
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            else:
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                           dir_fd=input_directories[parent_index]['fd'])
            row={'path':path,'parent_index':parent_index,'name':name,'fd':fd,'key':None}
            input_directories.append(row)
        finally:protected-=1
        if pending_signal is not None:raise Cancelled()
        before=os.fstat(fd)
        assert stat.S_ISDIR(before.st_mode) and before.st_uid==UID
        if mode is not None:assert stat.S_IMODE(before.st_mode)==mode
        row['key']=directory_key(before)
    check_input_directories()

def check_input_directories():
    for row in input_directories:
        remaining()
        parent=row['parent_index']
        named=(row['path'].lstat() if parent is None else
               os.stat(row['name'],dir_fd=input_directories[parent]['fd'],follow_symlinks=False))
        assert row['key']==directory_key(os.fstat(row['fd']))==directory_key(named)

def hold_fixed_inputs():
    global protected
    hold_input_directories()
    raw={}
    for item in [*FILES,TRANSFER]:
        remaining()
        directory_index=2 if item in FILES else 3
        basename=Path(item['path']).name
        assert Path(item['path']).parent==input_directories[directory_index]['path']
        protected+=1
        try:
            fd=os.open(basename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                       dir_fd=input_directories[directory_index]['fd'])
            row={'item':item,'fd':fd,'directory_index':directory_index,'basename':basename,'identity':None}
            input_handles.append(row)
        finally:protected-=1
        if pending_signal is not None:raise Cancelled()
        before=os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
        assert stat.S_IMODE(before.st_mode)==item['mode'] and before.st_size==item['bytes']
        version=':'.join(map(str,(before.st_dev,before.st_ino,before.st_size,
                                  before.st_mtime_ns,before.st_ctime_ns)))
        assert version==item['version']
        row['identity']=identity(before)
        summary,data=read_file(fd,item['bytes'],item['sha256'],item['name'].endswith('.json'))
        named=os.stat(basename,dir_fd=input_directories[directory_index]['fd'],follow_symlinks=False)
        assert identity(before)==identity(os.fstat(fd))==identity(named)
        row['summary']={'name':item['name'],'path':item['path'],'version':version,
                        'mode':item['mode'],'identity':identity(before),'same_fd_readback':summary}
        if data is not None:raw[item['name']]=data
    check_input_directories()
    return [row['summary'] for row in input_handles],raw

def recheck_held_inputs():
    check_input_directories()
    for row in input_handles:
        remaining();item=row['item'];fd=row['fd']
        before=os.fstat(fd)
        assert identity(before)==row['identity']
        read_file(fd,item['bytes'],item['sha256'])
        named=os.stat(row['basename'],dir_fd=input_directories[row['directory_index']]['fd'],
                      follow_symlinks=False)
        assert identity(before)==identity(os.fstat(fd))==identity(named)
    check_input_directories()

def verify_receipts(raw,input_rows):
    exported=json.loads(raw['source-export.result.public.json'])
    transported=json.loads(raw['source-carrier.result.public.json'])
    assert exported['schema']=='heptabao.phaseb.rog-3cb-standalone-source-export.v1'
    assert exported['status']=='exported' and exported['all_owned_stopped']
    assert exported['canonical_commit']==CANONICAL and exported['canonical_tree']==TREE
    assert exported['canonical_proof']=={
        'commit':CANONICAL,'tree':TREE,'parents':[PARENT],'root':ROOT_COMMIT,
        'commit_count':CANONICAL_COUNT,'full_fsck_passed':True}
    assert exported['expected_prerequisites']==[] and exported['expected_full_commit_count']==CANONICAL_COUNT
    assert exported['source_before']==exported['source_after']
    assert exported['source_before']['head']==CANONICAL and exported['source_before']['tree']==TREE
    assert exported['source_before']['clean'] and exported['source_before']['independent_git_directory']
    assert exported['controller']['bytes']==15352
    assert exported['controller']['sha256']=='7c8912c99b86742a072329d883d4c28c5f36a6581114197bfd5638b06076a72a'
    assert exported['bundle']['path']==SOURCE_FILES[0]['path']
    assert exported['bundle']['bytes']==FILES[0]['bytes'] and exported['bundle']['sha256']==FILES[0]['sha256']
    assert exported['bundle']['header']['prerequisites']==[]
    assert exported['bundle']['header']['heads']==[[CANONICAL,'HEAD']]
    assert exported['deadline_before_receipt_passed'] and exported['overall_seconds']==300
    assert exported['git_command_seconds']==90 and exported['elapsed_seconds']<300
    assert len(exported['cleanup'])==27 and all(row['direct_child_reaped'] and row['remaining']==[] for row in exported['cleanup'])
    assert not exported['network_git_protocols_enabled'] and not exported['server_started'] and not exported['compiler_started']
    assert not exported['source_imported'] and not exported['runtime_qualification'] and exported['product_tests_executed']==0
    assert transported['schema']=='heptabao.phaseb3cb.public-source-carrier-relay.v1'
    assert transported['status']=='transferred' and transported['all_owned_stopped']
    assert transported['all_local_owned_stopped'] and transported['remote_endpoint_completion_verified']
    assert not transported['remote_cleanup_unknown'] and not transported['cleanup_errors']
    assert transported['source_commit']==CANONICAL and transported['source_tree']==TREE
    assert transported['source_alias']=='rog-ts' and transported['destination_host']=='desktop'
    assert transported['destination_root']==str(CARRIER) and transported['files']==SOURCE_FILES
    assert transported['overall_seconds']==300 and transported['elapsed_seconds']<300
    assert transported['ssh_child_seconds']==transported['endpoint_seconds']==90
    assert transported['git_operations']==0 and not transported['server_started'] and not transported['compiler_started']
    assert not transported['runtime_qualification'] and not transported['production_changed']
    assert transported['controller']['bytes']==15395
    assert transported['controller']['sha256']=='f98ef18f25583506e7ff6072b8f383115ea826a399286f22bff1517b6eeb4432'
    assert transported['helpers']['sender.py']['sha256']=='8681201f587a3c5d2da07f01404e4b74e1db2e3ada2614f3482915c6543fb650'
    assert transported['helpers']['receiver.py']['sha256']=='2280d96c79b5e8fe8a0b3a9b601196cc61dbc43c11f4ded31780617f0533a6e5'
    assert len(transported['cleanup'])==3
    assert all(row['direct_child_reaped'] and row['remaining']==[] and row['exit_code']==0
               for row in transported['cleanup'])
    assert transported['trust_before']==transported['trust_after']
    assert transported['original_ha_controller_before']==transported['original_ha_controller_after']
    sender=transported['sender'];receiver=transported['receiver']
    for endpoint in (sender,receiver):
        assert endpoint['status']=='complete' and endpoint['all_owned_stopped']
        assert endpoint['within_original_deadline'] and endpoint['request_seconds']==90
        assert endpoint['git_operations']==0 and not endpoint['server_started'] and not endpoint['compiler_started']
        assert endpoint['source_commit']==CANONICAL and endpoint['source_tree']==TREE
    assert sender['role']=='sender' and receiver['role']=='receiver'
    assert receiver['source_export_provenance_verified'] and receiver['raw_receipts_preserved']
    assert receiver['destination_created_exclusive'] and receiver['destination_directory_mode']==0o500
    assert receiver['destination_fsynced']
    for item,source,sent,received,held in zip(FILES,SOURCE_FILES,sender['files'],receiver['files'],input_rows[:2],strict=True):
        assert sent['name']==received['name']==held['name']==item['name']
        assert sent['source']==source['path'] and sent['source_version']==source['version']
        assert sent['source_identity_before']==sent['source_identity_after']
        expected={'bytes':item['bytes'],'sha256':item['sha256']}
        assert sent['initial_file']==sent['stream']==received['same_fd_readback']==held['same_fd_readback']==expected
        assert received['bytes']==item['bytes'] and received['sha256']==item['sha256']
        assert received['path']==item['path'] and received['identity']==held['identity']
        assert received['mode']==item['mode'] and received['create_only'] and received['fsynced']
    result['export_receipt_verified']=True
    result['transport_receipt_verified']=True
    result['raw_input_receipts_unchanged']=True

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

try:
    assert len(sys.argv)==2 and re.fullmatch(r'[0-9a-f]{64}',sys.argv[1])
    assert sys.orig_argv[:5]==['/usr/bin/python3','-I','-S','-B','-c']
    assert len(sys.orig_argv)==7 and sys.orig_argv[6]==sys.argv[1]
    controller_raw=sys.orig_argv[5].encode('utf-8')
    assert digest(controller_raw)==sys.argv[1]
    assert ACTUAL_INPUTS_READY is True,'actual source-carrier metadata unresolved'
    for item in [*FILES,TRANSFER]:
        assert type(item['bytes']) is int and 0<item['bytes']<=MAX_BUNDLE
        assert isinstance(item['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',item['sha256'])
        assert isinstance(item['version'],str) and re.fullmatch(r'[0-9]+(:[0-9]+){4}',item['version'])
    assert FILES[1]['bytes']<=262144 and TRANSFER['bytes']<=262144
    assert (platform.system(),platform.machine())==SYSTEM and os.getuid()==UID
    assert BASE.resolve(strict=True)==BASE and BASE.is_dir() and BASE.stat().st_uid==UID
    assert not ROOT.exists() and not ROOT.is_symlink()
    assert not SOURCE.exists() and not SOURCE.is_symlink()
    input_rows,json_bytes=hold_fixed_inputs()
    result['input_files_before']=input_rows
    verify_receipts(json_bytes,input_rows)
    remaining()
    bundle_fd=input_handles[0]['fd']
    header=os.pread(bundle_fd,65536,0)
    result['bundle_header']=bundle_header(header)
    recheck_held_inputs()
    ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700);created_control=True
    (CONTROL/'empty-hooks').mkdir(mode=0o700)
    fsync_dir(BASE);fsync_dir(ROOT)
    create(CONTROL/'importer.py',controller_raw)
    result['controller']={'bytes':len(controller_raw),'sha256':digest(controller_raw)}
    public(CONTROL/'intent.public.json',{**result,'files':FILES,'transport_receipt':TRANSFER,
        'source':str(SOURCE),'receipt':str(CONTROL/'result.public.json'),
        'binary_execution_allowed':False,'existing_source_used':False})
    bundle=Path(FILES[0]['path'])
    owned('standalone-clone',ROOT,'clone','--no-checkout','--no-hardlinks','--',str(bundle),str(SOURCE),limit=90)
    fsync_dir(BASE)
    owned('bundle-verify',SOURCE,'bundle','verify',str(bundle))
    _,heads=git('bundle-heads',SOURCE,'bundle','list-heads',str(bundle))
    assert heads==CANONICAL+' HEAD'
    owned('canonical-checkout',SOURCE,'checkout','--detach',CANONICAL)
    owned('remove-local-origin',SOURCE,'remote','remove','origin')
    result['canonical_proof']=prove_canonical()
    result['materialized']=verify_materialized_and_fsync()
    result['source_after']=freeze('source-after',SOURCE,CANONICAL,TREE,True)
    fsync_dir(SOURCE);fsync_dir(BASE)
    recheck_held_inputs()
    result['input_files_after']=[row['summary'] for row in input_handles]
    result['input_sources_unchanged']=True
    assert stable(CONTROL/'importer.py')[0]==controller_raw
    remaining()
    result['source_imported']=True
    result['status']='complete'
except BaseException as error:
    result['status']='failed';result['source_imported']=False
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
    close_errors=[];closed_files=0;closed_directories=0
    for row in reversed(input_handles):
        try:os.close(row['fd']);closed_files+=1
        except BaseException as error:close_errors.append({'kind':'input-file','path':row['item']['path'],'error_type':type(error).__name__})
    for row in reversed(input_directories):
        try:os.close(row['fd']);closed_directories+=1
        except BaseException as error:close_errors.append({'kind':'input-directory','path':str(row['path']),'error_type':type(error).__name__})
    result['input_fd_closure']={'opened_files':len(input_handles),'closed_files':closed_files,
        'opened_directories':len(input_directories),'closed_directories':closed_directories,
        'errors':close_errors,'complete':not close_errors and closed_files==len(input_handles) and closed_directories==len(input_directories)}
    completed=time.monotonic()
    result['within_original_deadline']=completed<UNTIL
    result['elapsed_seconds']=completed-START
    if pending_signal is not None or not result['all_owned_stopped'] or not result['input_fd_closure']['complete'] or not result['within_original_deadline']:
        result['status']='failed';result['source_imported']=False
    result['success_requires_authoritative_exit_zero']=True
    result['success_requires_terminal_publication_within_original_deadline']=True
    if created_control:
        receipt=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
        public_path=CONTROL/'result.public.json'
        create(public_path,receipt);fsync_dir(CONTROL);fsync_dir(ROOT);fsync_dir(BASE)
        result['receipt']={'path':str(public_path),'bytes':len(receipt),'sha256':digest(receipt)}
    result['publication_within_original_deadline']=time.monotonic()<UNTIL
    if not result['publication_within_original_deadline']:
        result['status']='failed';result['source_imported']=False
    sys.stderr.write(json.dumps(result,sort_keys=True)+'\n');sys.stderr.flush()
sys.exit(0 if result['status']=='complete' and time.monotonic()<UNTIL else 1)
