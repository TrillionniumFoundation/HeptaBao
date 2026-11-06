#!/usr/bin/env python3
"""Stage two fixed public Git bundles in one new isolated X230 checkout.

The historical exact 4e source is a read-only local prerequisite. This source
does not copy or execute a product binary, publish build controls or run tests.
All candidate and transported bundle facts reside in the single BINDING block.
"""
from pathlib import Path
import base64, hashlib, json, os, platform, re, select, signal, stat, subprocess, sys, time

BINDING = json.loads("{\"schema\":\"heptabao.x230.two-incremental-bundle-source-binding.v1\",\"fresh_root\":\"/home/qian/hb-5767739c-src-20261106-r1\",\"readonly_base\":\"/home/qian/heptabao-same-root-publication-normal-20261105-r1/source\",\"base_commit\":\"4e808d0ecb1bcded22870a7ec960dfb2491cf6ec\",\"base_tree\":\"eba5e650bd080b8ad41ea52a2bc68867f541d255\",\"base_history\":3763,\"first_prerequisite\":\"49503322c7f446e5eb41e7744f1fdbd7f1192ecc\",\"intermediate_commit\":\"02b90762b3d6cc8699cc88bffb6f76cb1f07e270\",\"candidate\":{\"commit\":\"5767739cd25e458ac052dc8d384019bab8688ae0\",\"tree\":\"42477d622dcf96e1e2b0929fe9ecc6b7ba484740\",\"parent\":\"02b90762b3d6cc8699cc88bffb6f76cb1f07e270\",\"leaves\":3932,\"tracked_bytes\":62553540,\"full_index_sha256\":\"20ff64f463eb63a45a6dda92a17f23e814503b77ca5325d1b2c4a0ee4f4a5423\",\"history\":3769},\"root_commit\":\"67d79b3b5442ed033d38929eab2010403463e56d\",\"carrier\":{\"schema\":\"heptabao.x230576.two-bundle-source-only-carrier.v1\",\"blob\":\"79d6845b1826171788333c906e77faf02ac02bb6\",\"bytes\":235828,\"sha256\":\"746de82dd389c7fe3cd1a169c5ace88737b3d94c00cf953eef4c0be9b5d7e1b0\"},\"bundles\":[{\"field\":\"canonical_02b_base64\",\"name\":\"canonical-hb-02b-from495.bundle\",\"bytes\":171016,\"sha256\":\"069e0e07ef05dc6ec7f75407f8a06edd5efd53764833334fee74dcbf5719a800\",\"target_mode\":256,\"prerequisite\":\"49503322c7f446e5eb41e7744f1fdbd7f1192ecc\",\"head\":\"02b90762b3d6cc8699cc88bffb6f76cb1f07e270\",\"header\":\"# v2 git bundle\\n-49503322c7f446e5eb41e7744f1fdbd7f1192ecc test: witness authenticated native state in NoForward HA regressions\\n02b90762b3d6cc8699cc88bffb6f76cb1f07e270 HEAD\\n\\n\",\"header_sha256\":\"bc421f87f1547daeef2cdd4ffce357d0eac193e380297296919658640be05ab5\"},{\"field\":\"canonical_576_base64\",\"name\":\"canonical-hb-5767739c-from02b.bundle\",\"bytes\":5766,\"sha256\":\"0683ebe3bcc1648387b5a891c958d1c855fef2aa6effa2c35910ffbfa3e6940a\",\"target_mode\":256,\"prerequisite\":\"02b90762b3d6cc8699cc88bffb6f76cb1f07e270\",\"head\":\"5767739cd25e458ac052dc8d384019bab8688ae0\",\"header\":\"# v2 git bundle\\n-02b90762b3d6cc8699cc88bffb6f76cb1f07e270 fix(storage,auth): integrate streaming snapshots and JWT policy schema 147\\n5767739cd25e458ac052dc8d384019bab8688ae0 HEAD\\n\\n\",\"header_sha256\":\"5599413cdc4c2e70cb471de0d407313f4d157a8bc6f0fba4c5e3ac1c458879c9\"}]}")
assert isinstance(BINDING,dict), 'source binding is not frozen'
os.umask(0o077)
BASE=Path('/home/qian')
ROOT=Path(BINDING['fresh_root'])
CONTROL=ROOT/'control'
ART=ROOT/'artifacts'
SOURCE=ROOT/'source'
OLD_SOURCE=Path(BINDING['readonly_base'])
CANONICAL=BINDING['candidate']['commit']
TREE=BINDING['candidate']['tree']
PARENT=BINDING['candidate']['parent']
ROOT_COMMIT=BINDING['root_commit']
CANONICAL_COUNT=BINDING['candidate']['history']
TRACKED_FILES=BINDING['candidate']['leaves']
MAX_BUNDLE=262144
MAX_CARRIER=262144
UID=1000
SYSTEM=('Linux','x86_64')
FILES=BINDING['bundles']

START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
base_before=None
base_after=None
result={'schema':'heptabao.x230-two-bundle-source-only-stage.v1','status':'failed',
 'source_commit':CANONICAL,'source_tree':TREE,'source':str(SOURCE),'root':str(ROOT),
 'expected_full_commit_count':CANONICAL_COUNT,
 'expected_prerequisites':[item['prerequisite'] for item in FILES],
 'network_git_protocols_enabled':False,'old_source_opened':False,
 'server_started':False,'compiler_started':False,'controls_published':False,
 'runtime_qualification':False,'product_tests_executed':0,
 'overall_seconds':300,'git_command_seconds':60,'clone_seconds':90,
 'maximum_bundle_bytes':MAX_BUNDLE,'maximum_carrier_bytes':MAX_CARRIER,
 'automatic_retry':False,'production_changed':False,
 'partial_root_retained_on_failure':True,'input_descriptors':[]}

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

def read_carrier():
    chunks=[];count=0
    while True:
        remaining()
        assert select.select([0],[],[],remaining())[0]
        try:block=os.read(0,min(65536,MAX_CARRIER+1-count))
        except (BlockingIOError,InterruptedError):continue
        if not block:break
        chunks.append(block);count+=len(block)
        assert count<=MAX_CARRIER, 'carrier exceeds original stdin ceiling'
    raw=b''.join(chunks)
    assert len(raw)==BINDING['carrier']['bytes'] and digest(raw)==BINDING['carrier']['sha256']
    value=json.loads(raw)
    assert isinstance(value,dict) and set(value)=={'schema',FILES[0]['field'],FILES[1]['field']}
    assert value['schema']==BINDING['carrier']['schema']
    decoded=[]
    for item in FILES:
        encoded=value[item['field']]
        assert isinstance(encoded,str) and encoded.isascii()
        body=base64.b64decode(encoded,validate=True)
        assert base64.b64encode(body).decode('ascii')==encoded
        assert len(body)==item['bytes'] and digest(body)==item['sha256']
        bundle_header(body,item)
        decoded.append(body)
    remaining()
    return raw,decoded

def receive_files(decoded):
    global protected
    results=[]
    assert len(decoded)==len(FILES)==2
    for item,raw in zip(FILES,decoded,strict=True):
        remaining();path=ART/item['name'];fd=None
        ledger={'name':item['name'],'path':str(path),'open_attempted':False,
                'acquired':False,'close_attempted':False,'closed':False}
        result['input_descriptors'].append(ledger)
        try:
            protected+=1
            try:
                ledger['open_attempted']=True
                fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                ledger['acquired']=True
            finally:protected-=1
            if pending_signal is not None:raise Cancelled()
            view=memoryview(raw);written=0
            while view:
                remaining();n=os.write(fd,view[:65536]);assert n>0
                view=view[n:];written+=n
            assert written==item['bytes'] and digest(raw)==item['sha256']
            os.fchmod(fd,item['target_mode']);os.fsync(fd)
            before=os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
            assert before.st_size==item['bytes'] and stat.S_IMODE(before.st_mode)==item['target_mode']
            same_fd,_=read_file(fd,item['bytes'],item['sha256'])
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
            results.append({'name':item['name'],'path':str(path),'bytes':written,
                'sha256':item['sha256'],'mode':item['target_mode'],'create_only':True,
                'fsynced':True,'identity':identity(before),'same_fd_readback':same_fd,
                'header':bundle_header(raw,item)})
        finally:
            if fd is not None:
                protected+=1
                try:
                    ledger['close_attempted']=True
                    os.close(fd);ledger['closed']=True
                finally:protected-=1
        if pending_signal is not None:raise Cancelled()
    assert sorted(os.listdir(ART))==sorted(x['name'] for x in FILES)
    fsync_dir(ART);remaining()
    return results

def binding_ready():
    assert BINDING['schema']=='heptabao.x230.two-incremental-bundle-source-binding.v1'
    assert ROOT.parent==BASE and ROOT.name.startswith('hb-') and ROOT.name.endswith('-src-20261106-r1')
    assert OLD_SOURCE==BASE/'heptabao-same-root-publication-normal-20261105-r1'/'source'
    assert BINDING['base_commit']=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
    assert BINDING['base_tree']=='eba5e650bd080b8ad41ea52a2bc68867f541d255'
    assert BINDING['base_history']==3763
    assert BINDING['first_prerequisite']=='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
    assert BINDING['intermediate_commit']=='02b90762b3d6cc8699cc88bffb6f76cb1f07e270'
    assert len(FILES)==2 and len({x['field'] for x in FILES})==len({x['name'] for x in FILES})==2
    assert FILES[0]['prerequisite']==BINDING['first_prerequisite']
    assert FILES[0]['head']==FILES[1]['prerequisite']==BINDING['intermediate_commit']
    assert FILES[1]['head']==CANONICAL
    assert type(BINDING['carrier']['bytes']) is int and 0<BINDING['carrier']['bytes']<=MAX_CARRIER
    assert sum(x['bytes'] for x in FILES)<=MAX_BUNDLE
    for value in (CANONICAL,TREE,PARENT,ROOT_COMMIT):
        assert re.fullmatch(r'[0-9a-f]{40}',value)
    assert type(CANONICAL_COUNT) is int and CANONICAL_COUNT>BINDING['base_history']
    assert type(TRACKED_FILES) is int and TRACKED_FILES>0
    for item in FILES:
        assert re.fullmatch(r'[A-Za-z0-9._-]{1,96}[.]bundle',item['name'])
        assert type(item['bytes']) is int and 0<item['bytes']<=MAX_BUNDLE
        assert re.fullmatch(r'[0-9a-f]{64}',item['sha256'])
        assert re.fullmatch(r'[0-9a-f]{64}',item['header_sha256'])
        assert item['target_mode']==0o400

def bundle_header(raw,item):
    end=raw.find(b'\n\n',0,65536)
    assert end>0 and raw[end+2:end+6]==b'PACK'
    header=raw[:end+2]
    assert header==item['header'].encode('ascii') and digest(header)==item['header_sha256']
    lines=header[:-2].split(b'\n')
    assert len(lines)==3 and lines[0]==b'# v2 git bundle'
    prerequisite,sep,_message=lines[1][1:].partition(b' ')
    assert lines[1].startswith(b'-') and sep and prerequisite.decode('ascii')==item['prerequisite']
    assert lines[2]==(item['head']+' HEAD').encode('ascii')
    return {'version':2,'prerequisites':[item['prerequisite']],'heads':[[item['head'],'HEAD']],
            'header_bytes':len(header),'header_sha256':digest(header)}

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
    tracked_fsynced=set();total=0;proof=hashlib.sha256()
    for relative,(mode,oid) in expected.items():
        remaining();path=SOURCE/relative
        assert path.resolve(strict=True)==path
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_nlink==1
            assert bool(before.st_mode&0o111)==(mode=='100755')
            assert 0<=before.st_size<=2*1024*1024 and not before.st_mode&0o022
            h=hashlib.sha1();h.update(('blob '+str(before.st_size)+'\0').encode('ascii'));count=0
            while True:
                remaining();block=os.read(fd,65536)
                if not block:break
                count+=len(block);assert count<=before.st_size;h.update(block)
            assert count==before.st_size and h.hexdigest()==oid
            total+=count;assert total<=128*1024*1024
            proof.update((relative+'\0'+mode+'\0'+oid+'\0'+str(count)+'\n').encode('utf-8'))
            os.fsync(fd)
            assert identity(before)==identity(os.fstat(fd))==identity(path.lstat())
        finally:os.close(fd)
        tracked_fsynced.add(path)
    assert total==BINDING['candidate']['tracked_bytes']
    assert proof.hexdigest()==BINDING['candidate']['full_index_sha256']
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
    return {'tracked_files':len(expected),'tracked_bytes':total,'full_leaf_index_sha256':proof.hexdigest(),
            'tree_equals_index':True,'actual_git_blob_bytes_verified':True,
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
    binding_ready()
    assert (platform.system(),platform.machine())==SYSTEM and os.getuid()==UID
    assert BASE.resolve(strict=True)==BASE and BASE.is_dir() and BASE.stat().st_uid==UID
    assert len(sys.argv)==2 and re.fullmatch(r'[0-9a-f]{64}',sys.argv[1])
    assert sys.orig_argv[:5]==['/usr/bin/python3','-I','-S','-B','-c']
    assert len(sys.orig_argv)==7 and sys.orig_argv[6]==sys.argv[1]
    controller_raw=sys.orig_argv[5].encode('utf-8')
    assert digest(controller_raw)==sys.argv[1]
    assert not ROOT.exists() and not ROOT.is_symlink()
    carrier_raw,decoded=read_carrier()
    base_before=freeze('base-before',OLD_SOURCE,BINDING['base_commit'],BINDING['base_tree'],True)
    result['old_source_opened']=True;result['base_before']=base_before
    _,base_count=git('base-count',OLD_SOURCE,'rev-list','--count',BINDING['base_commit'])
    assert base_count==str(BINDING['base_history'])
    owned('base-has-first-prerequisite',OLD_SOURCE,'merge-base','--is-ancestor',
          BINDING['first_prerequisite'],BINDING['base_commit'])
    result['base_first_prerequisite_verified']=True
    remaining();ROOT.mkdir(mode=0o700)
    CONTROL.mkdir(mode=0o700);created_control=True
    ART.mkdir(mode=0o700);(CONTROL/'empty-hooks').mkdir(mode=0o700)
    fsync_dir(BASE);fsync_dir(ROOT)
    create(CONTROL/'stage.py',controller_raw)
    result['controller']={'bytes':len(controller_raw),'sha256':digest(controller_raw)}
    result['carrier']={'bytes':len(carrier_raw),'sha256':digest(carrier_raw)}
    public(CONTROL/'intent.public.json',{**result,'binding':BINDING,
        'receipt':str(CONTROL/'stage-result.public.json'),'binary_execution_allowed':False})
    for prefix,out,err,row in deferred_logs:persist_command(prefix,out,err,row)
    deferred_logs.clear()
    file_rows=receive_files(decoded);result['file_results']=file_rows
    del decoded,carrier_raw
    owned('independent-readonly-base-clone',ROOT,'clone','--no-checkout','--no-hardlinks',
          '--',str(OLD_SOURCE),str(SOURCE),limit=90)
    _,origin=git('new-clone-origin',SOURCE,'remote','get-url','origin')
    assert origin==str(OLD_SOURCE)
    owned('remove-new-local-origin',SOURCE,'remote','remove','origin')
    for ordinal,item in enumerate(FILES):
        remaining();bundle=ART/item['name'];raw,binding=stable(bundle,MAX_BUNDLE)
        assert binding['bytes']==item['bytes'] and binding['sha256']==item['sha256']
        bundle_header(raw,item);del raw
        owned('bundle%d-verify'%ordinal,SOURCE,'bundle','verify',str(bundle))
        _,heads=git('bundle%d-heads'%ordinal,SOURCE,'bundle','list-heads',str(bundle))
        assert heads==item['head']+' HEAD'
        owned('bundle%d-import'%ordinal,SOURCE,'-c','fetch.writeCommitGraph=false',
              'fetch','--no-tags',str(bundle),'HEAD')
        _,fetched=git('bundle%d-import-head'%ordinal,SOURCE,'rev-parse','FETCH_HEAD')
        assert fetched==item['head']
        assert stable(bundle,MAX_BUNDLE)[1]==binding
    owned('canonical-checkout',SOURCE,'checkout','--detach',CANONICAL)
    result['canonical_proof']=prove_canonical()
    result['materialized']=verify_materialized_and_fsync()
    result['source_after']=freeze('source-after',SOURCE,CANONICAL,TREE,True)
    recheck_artifacts(file_rows)
    assert stable(CONTROL/'stage.py')[0]==controller_raw
    base_after=freeze('base-after',OLD_SOURCE,BINDING['base_commit'],BINDING['base_tree'],True)
    result['base_after']=base_after
    assert base_after==base_before
    result['old_source_unchanged']=True
    remaining()
    result['transfer_passed']=True
    result['status']='prepared'
except BaseException as error:
    result['status']='failed';result['transfer_passed']=False
    result['error_type']=type(error).__name__
    frames=[];tb=error.__traceback__
    while tb is not None:
        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
    result['failure_frames']=frames
finally:
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
    if base_before is not None and base_after is None:
        try:
            base_after=freeze('base-after-failure',OLD_SOURCE,BINDING['base_commit'],BINDING['base_tree'],True)
            result['base_after']=base_after
            result['old_source_unchanged']=base_after==base_before
        except BaseException as error:
            result['old_source_unchanged']=False
            result['base_after_error_type']=type(error).__name__
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
    result['input_descriptors_closed']=all(not row['acquired'] or row['closed']
                                            for row in result['input_descriptors'])
    if not result['input_descriptors_closed'] or result.get('old_source_unchanged') is not True:
        result['status']='failed';result['transfer_passed']=False
    if created_control:
        receipt=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
        assert len(receipt)<=1048576
        public_path=CONTROL/'stage-result.public.json'
        create(public_path,receipt);fsync_dir(CONTROL);fsync_dir(ROOT)
        result['receipt']={'path':str(public_path),'bytes':len(receipt),'sha256':digest(receipt)}
    result['publication_within_original_deadline']=time.monotonic()<UNTIL
    if not result['publication_within_original_deadline']:
        result['status']='failed';result['transfer_passed']=False
    summary={'status':result['status'],'source_commit':CANONICAL,'source_tree':TREE,
             'all_owned_stopped':result['all_owned_stopped'],
             'input_descriptors_closed':result['input_descriptors_closed'],
             'old_source_unchanged':result.get('old_source_unchanged',False),
             'compiler_started':False,'server_started':False,'controls_published':False,
             'within_original_deadline':result['publication_within_original_deadline'],
             'receipt':result.get('receipt')}
    sys.stdout.write(json.dumps(summary,sort_keys=True)+'\n');sys.stdout.flush()
sys.exit(0 if result['status']=='prepared' and time.monotonic()<UNTIL else 1)
