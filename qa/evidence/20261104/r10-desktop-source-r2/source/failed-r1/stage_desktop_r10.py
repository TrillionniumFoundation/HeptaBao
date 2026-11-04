#!/usr/bin/env python3
"""Fresh R10 desktop full-source materialization from the verified R8 dependency.

Source preparation only: fixed SSH public bundle, local-file Git, two fresh clones.
No application, compiler, server, HTTP request or public Git network operation.
"""
from pathlib import Path
import base64, hashlib, json, os, platform, re, shlex, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
SOURCES=BASE/'normal-r10-validation-source-controllers-r1'
CONTROL=BASE/'normal-r10-validation-source-control-r1'
SOURCE=BASE/'normal-r10-validation-source-r1'
INTERMEDIATE=CONTROL/'borrowed-intermediate-source'
OLD=BASE/'normal-r8-standby-oracle-source-r1'
OLD_OBJECTS=BASE/'pipelined-packed-frames-source-r1/.git/objects'
ORIGINAL=BASE/'normal-33cafa-full128-control-r2/launch_normal_33cafa_full128_r2.py'
ORIGINAL_SHA='c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e'
OLD_RESULT=BASE/'normal-r8-standby-oracle-live-r1/result.public.json'
OLD_RESULT_SHA='88477fe316686727aca2439ecd839beb2403a607b05ede1e1df63441aef2567b'
OLD_HEAD='384c957612186d64c5a530044af0ae62c568cc3d'
OLD_TREE='d5a0f91a4d47f7c8d5f34170ea167d10dc036e04'
OLD_REFS_SHA='88409147a6d950453f1675b8ab4c8adfd62361938352a65c9960a595f949f6e5'
OLD_ALTERNATES_SHA='dbb4a9708da32a75373f6d11b53fa04334c2706454ca1da17f3450d80df864e2'
CANONICAL='49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE='1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
PARENT='1d12abc45a83d4b32e7185d01a876eb93110b1e2'
PARENT_TREE='e1faeaa3ed49d26fb01a7617a8879cb693a12907'
ROOT_COMMIT='67d79b3b5442ed033d38929eab2010403463e56d'
ANCHOR='7a552330df821b358161628120a8b5d064f37367'
BOUNDARIES={ANCHOR,'55f27e4258ea3f71ab7872cd7a44e8cbd4da1f18'}
CANONICAL_REF='refs/heads/r10-canonical'
MACHINE_SHA='d90fa41f7e59edf2f2a732ea082cac83085a2a3695a503cd82b6b4eef9cab9f3'
SENDER_SHA='410ff7b90622f0cdc36ba397e3e5c0a5674748b1356b9bd9d6b727d4dc9cd392'
TINY_B64_SHA='f25e8087a8c8444ab773efb566602feed63b5d51c59bb60e85e99b53eee29484'
R9_BYTES=1886365
R9_SHA='49060b399899b9904aded82973589837062dace090fcb43102fa862a5ff7fb06'
R9_VERSION='66306:28228563:1886365:1793814029233278292:1793814029235278291'
R10_BYTES=1522
R10_SHA='543ad493d0b3e224f9620b5418e7eda260a000ccc1d8c3c0153bc49a963dad36'
R9_BUNDLE=CONTROL/'canonical-r9.bundle'
R10_BUNDLE=CONTROL/'canonical-r10.bundle'
UID=1000
SSH=['/usr/bin/ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
 '-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
 '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','UpdateHostKeys=no',
 '-o','ControlMaster=no','-o','ControlPath=none']
START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
remote_attempted=False
remote_verified=False
result={'schema':'heptabao.r10.desktop-full-source-stage.v1','status':'failed',
 'canonical_commit':CANONICAL,'canonical_tree':TREE,'source':str(SOURCE),
 'intermediate_source':str(INTERMEDIATE),'old_source':str(OLD),
 'expected_commit_count':3752,'sole_parent':PARENT,'overall_seconds':300,
 'git_command_seconds':90,'ssh_child_seconds':90,'remote_sender_seconds':90,
 'network_git_protocols_enabled':False,'compiler_started':False,'server_started':False,
 'runtime_qualification':False,'product_tests_executed':0,
 'old_source_independent_claimed':False,
 'preserved_readonly_failure_sha256':'6248bd1cb40489962398c55cebdf6158c3bb7371435810902098893d3c27f2b2',
 'readonly_prerequisite_pass_sha256':'623048c35ce31850f9b56c3d376cf4253453865bb468ea831e1965beaf423e01'}
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


def directory(path):
    assert path.resolve(strict=True)==path and path.is_dir() and path.stat().st_uid==UID
    assert path.stat().st_mode&0o022==0
    return path

def absent(path):
    assert not path.exists() and not path.is_symlink()

def freeze(name,path,head,tree,old=False):
    directory(path)
    _,actual_head=git(name+'-head',path,'rev-parse','--verify','HEAD')
    _,actual_tree=git(name+'-tree',path,'rev-parse','HEAD^{tree}')
    _,status=owned(name+'-status',path,'status','--porcelain=v1','--untracked-files=all')
    _,absolute=git(name+'-git-dir',path,'rev-parse','--absolute-git-dir')
    _,common=git(name+'-common-dir',path,'rev-parse','--git-common-dir')
    gitdir=directory(path/'.git')
    assert absolute==str(gitdir) and (path/common).resolve(strict=True)==gitdir
    _,shallow=git(name+'-shallow',path,'rev-parse','--is-shallow-repository')
    _,partial=owned(name+'-partial-config',path,'config','--local','--get-regexp',
       r'^(extensions[.]partialclone|remote[.].*[.]promisor|remote[.].*[.]partialclonefilter)$',allowed=(0,1))
    absent(gitdir/'info/grafts')
    locks={x:(gitdir/x).exists() or (gitdir/x).is_symlink()
           for x in ('index.lock','packed-refs.lock','shallow.lock','config.lock')}
    assert not any(locks.values())
    assert actual_head==head and actual_tree==tree and not status and shallow=='false' and not partial
    _,refs=owned(name+'-refs',path,'show-ref','--head')
    metadata={'commit':actual_head,'tree':actual_tree,'clean':True,'shallow':False,
      'git_directory':str(gitdir),'git_common_directory':str(gitdir),
      'no_partial_clone':True,'no_grafts':True,'locks':locks,
      'refs_sha256':digest(refs.strip()),'refs_bytes':len(refs)}
    alternate=gitdir/'objects/info/alternates'
    if old:
        raw,binding=stable(alternate,4096)
        assert raw==(str(OLD_OBJECTS)+'\n').encode() and binding['sha256']==OLD_ALTERNATES_SHA
        directory(OLD_OBJECTS)
        absent(OLD_OBJECTS/'info/alternates')
        assert metadata['refs_sha256']==OLD_REFS_SHA
        metadata['alternate']={'file':binding,'path':str(OLD_OBJECTS),
             'single_known_dependency_bounded_under_base':True}
        metadata['independent_object_store']=False
    else:
        absent(alternate)
        metadata['independent_object_store']=True
    return metadata

def old_fences():
    found={}
    for path,expected in ((ORIGINAL,ORIGINAL_SHA),(OLD_RESULT,OLD_RESULT_SHA)):
        raw,binding=stable(path)
        assert binding['sha256']==expected
        found[str(path)]=binding
    return found

def known_hosts_state(config):
    paths=shlex.split(config.get('userknownhostsfile',''))
    assert paths
    found={}
    for raw in paths:
        path=Path(raw)
        assert path.is_absolute() and path.is_relative_to(Path('/home/qian-qi/.ssh'))
        if path.exists():
            _raw,binding=stable(path,1048576)
            assert binding['identity'][4]&0o077==0
            found[str(path)]=binding
        else:
            absent(path);found[str(path)]={'absent':True}
    assert any('sha256' in binding for binding in found.values())
    return found

def inspect_ssh():
    _,raw=owned_argv('rog-effective-config',[*SSH,'-G','rog-ts'],90)
    config={}
    for line in raw.decode('utf-8').splitlines():
        key,sep,value=line.partition(' ')
        assert sep
        if key not in config:config[key]=value
    required={'host':'rog-ts','hostname':'192.168.0.10','user':'qian-qi','port':'22',
      'hostkeyalias':'hepta-node-rog','batchmode':'yes','connecttimeout':'10',
      'connectionattempts':'1','forwardagent':'no','clearallforwardings':'yes'}
    for key,value in required.items():assert config.get(key)==value
    assert config.get('stricthostkeychecking') in ('true','yes')
    assert config.get('updatehostkeys') in ('false','no')
    assert config.get('controlmaster') in ('false','no')
    assert config.get('controlpath') in (None,'none','null')
    assert config.get('permitlocalcommand') in (None,'no','false')
    assert config.get('proxycommand') in (None,'none')
    assert config.get('proxyjump') in (None,'none')
    keys=tuple(required)+('stricthostkeychecking','updatehostkeys','controlmaster','controlpath')
    return config,{'effective_config_sha256':digest(raw),'projection':{k:config.get(k) for k in keys},
                   'known_hosts':known_hosts_state(config)}

def bundle_header(raw,head,prerequisites):
    end=raw.find(b'\n\n',0,65536)
    assert end>0 and raw[end+2:end+6]==b'PACK'
    lines=raw[:end].split(b'\n')
    assert lines.pop(0)==b'# v2 git bundle'
    actual=[];heads=[]
    for line in lines:
        if line.startswith(b'-'):
            value,sep,_message=line[1:].partition(b' ')
            assert sep and re.fullmatch(rb'[0-9a-f]{40}',value)
            actual.append(value.decode())
        else:
            value,sep,name=line.partition(b' ')
            assert sep and re.fullmatch(rb'[0-9a-f]{40}',value)
            heads.append([value.decode(),name.decode('ascii')])
    assert len(actual)==len(set(actual)) and set(actual)==set(prerequisites)
    assert heads==[[head,'HEAD']]
    return {'version':2,'prerequisites':sorted(actual),'heads':heads,
            'header_bytes':end+2,'header_sha256':digest(raw[:end+2])}

def anchor_closure(label,path):
    _,raw=owned(label,path,'rev-list',ANCHOR)
    rows=raw.decode('ascii').splitlines()
    assert len(rows)==len(set(rows))==3735
    assert all(re.fullmatch(r'[0-9a-f]{40}',row) for row in rows)
    assert BOUNDARIES<=set(rows) and ROOT_COMMIT in rows
    return {'commit_count':len(rows),'prerequisites':sorted(BOUNDARIES),
            'root_present':True,'raw_sha256':digest(raw)}

def import_bundle(label,path,bundle,head,tree):
    owned(label+'-verify',path,'bundle','verify',str(bundle))
    _,heads=git(label+'-heads',path,'bundle','list-heads',str(bundle))
    assert heads==head+' HEAD'
    owned(label+'-fetch',path,'fetch','--no-tags','--no-recurse-submodules',
          '--no-write-fetch-head',str(bundle),'HEAD')
    _,kind=git(label+'-kind',path,'cat-file','-t',head);assert kind=='commit'
    _,actual_tree=git(label+'-tree',path,'rev-parse',head+'^{tree}');assert actual_tree==tree
    return {'commit':head,'tree':actual_tree,'only_local_file_fetch':True}

def independent_git_objects():
    gitdir=SOURCE/'.git'
    count=0;bytes_count=0
    def refuse_walk_error(error):
        raise error
    for root,dirs,files in os.walk(gitdir,topdown=True,onerror=refuse_walk_error,followlinks=False):
        remaining()
        parent=Path(root)
        directory(parent)
        for name in dirs:
            directory(parent/name)
        for name in files:
            remaining()
            path=parent/name
            s=path.lstat()
            assert stat.S_ISREG(s.st_mode) and s.st_uid==UID and s.st_nlink==1
            assert not path.is_symlink()
            count+=1;bytes_count+=s.st_size
    absent(gitdir/'objects/info/alternates')
    return {'regular_files':count,'total_bytes':bytes_count,
            'all_regular_files_single_link':True,'no_symlinks':True,'no_alternates':True}

def prove_canonical():
    _,kind=git('final-kind',SOURCE,'cat-file','-t',CANONICAL);assert kind=='commit'
    _,tree=git('final-tree',SOURCE,'rev-parse',CANONICAL+'^{tree}');assert tree==TREE
    _,parents=git('final-parents',SOURCE,'show','-s','--format=%P',CANONICAL);assert parents==PARENT
    owned('final-anchor',SOURCE,'merge-base','--is-ancestor',ANCHOR,CANONICAL)
    _,raw=owned('final-closure',SOURCE,'rev-list',CANONICAL)
    closure=raw.decode('ascii').splitlines()
    assert len(closure)==len(set(closure))==3752
    assert all(re.fullmatch(r'[0-9a-f]{40}',row) for row in closure)
    assert CANONICAL in closure and PARENT in closure and BOUNDARIES<=set(closure)
    _,roots=git('final-roots',SOURCE,'rev-list','--max-parents=0',CANONICAL)
    assert roots==ROOT_COMMIT
    owned('final-full-fsck',SOURCE,'fsck','--full','--strict','--no-reflogs','--no-dangling',CANONICAL)
    return {'commit':CANONICAL,'tree':tree,'sole_parent':parents,'root':roots,
            'commit_count':len(closure),'closure_raw_sha256':digest(raw),'full_fsck_passed':True}

try:
    assert (platform.system(),platform.machine(),os.getuid())==('Linux','x86_64',UID)
    directory(BASE);directory(SOURCES)
    assert stat.S_IMODE(SOURCES.stat().st_mode)==0o700
    assert Path(__file__).resolve(strict=True)==SOURCES/'stage_desktop_r10.py'
    controller_raw,controller_pin=stable(Path(__file__).resolve(strict=True),262144)
    sender_raw,sender_pin=stable(SOURCES/'source_sender_r10.py',262144)
    assert sender_pin['sha256']==SENDER_SHA
    compile(sender_raw,'source_sender_r10.py','exec',dont_inherit=True)
    tiny_text,tiny_pin=stable(SOURCES/'canonical-r10.bundle.base64',4096)
    assert tiny_pin['bytes']==2033 and tiny_pin['sha256']==TINY_B64_SHA
    assert tiny_text.endswith(b'\n') and b'\n' not in tiny_text[:-1]
    tiny_raw=base64.b64decode(tiny_text[:-1],validate=True)
    assert len(tiny_raw)==R10_BYTES and digest(tiny_raw)==R10_SHA
    machine=Path('/etc/machine-id').read_bytes()
    assert digest(machine)==MACHINE_SHA
    result['machine_id_sha256']=digest(machine)
    absent(CONTROL);absent(SOURCE)
    remaining()
    CONTROL.mkdir(mode=0o700);created_control=True
    (CONTROL/'empty-hooks').mkdir(mode=0o700)
    result['controller']=controller_pin
    result['sender']=sender_pin
    result['tiny_bundle_input']=tiny_pin
    public(CONTROL/'intent.public.json',{'schema':result['schema'],'canonical_commit':CANONICAL,
      'canonical_tree':TREE,'source':str(SOURCE),'intermediate':str(INTERMEDIATE),
      'old_source':str(OLD),'controller':controller_pin,'sender':sender_pin,
      'overall_seconds':300,'git_seconds':90,'ssh_seconds':90,
      'only_fixed_ssh_alias':'rog-ts','network_git_protocols_enabled':False,
      'two_stage_clone':True,'final_dissociate_required':True,
      'r9_bundle':{'bytes':R9_BYTES,'sha256':R9_SHA,'version':R9_VERSION},
      'r10_bundle':{'bytes':R10_BYTES,'sha256':R10_SHA}})
    result['old_before']=freeze('old-before',OLD,OLD_HEAD,OLD_TREE,old=True)
    result['old_fences_before']=old_fences()
    result['anchor_before']=anchor_closure('old-anchor-closure',OLD)
    config,result['ssh_before']=inspect_ssh()
    remote_command='/usr/bin/python3 -c '+shlex.quote(sender_raw.decode('ascii'))
    remote_attempted=True
    _,bundle_raw=owned_argv('receive-fixed-r9-bundle',[*SSH,'rog-ts',remote_command],90)
    command=commands[-1]
    prefix=command['label']
    stderr_raw,_stderr_pin=stable(CONTROL/(prefix+'.stderr'),262144)
    assert len(stderr_raw.splitlines())==1
    remote=json.loads(stderr_raw)
    assert remote['schema']=='heptabao.r10.canonical-source-bundle-sender.v1'
    assert remote['status']=='complete' and remote['all_owned_stopped'] is True
    assert remote['within_original_deadline'] is True and remote['request_seconds']==90
    assert remote['role']=='sender' and remote['source_version']==R9_VERSION
    assert remote['source_identity_before']==remote['source_identity_after']
    assert remote['source_before']==remote['source_after']
    assert remote['source_before']['commit']==CANONICAL and remote['source_before']['tree']==TREE
    assert remote['source_before']['commit_count']==3752 and remote['source_before']['clean'] is True
    assert len(remote['git_commands'])==20 and len(remote['cleanup'])==20
    assert all(row['direct_child_reaped'] and row['remaining']==[] for row in remote['cleanup'])
    assert remote['stream']=={'bytes':R9_BYTES,'sha256':R9_SHA}
    assert len(bundle_raw)==R9_BYTES and digest(bundle_raw)==R9_SHA
    remote_verified=True
    result['remote_sender']=remote
    result['remote_receipt_sha256']=digest(stderr_raw)
    result['r9_header']=bundle_header(bundle_raw,PARENT,BOUNDARIES)
    result['r10_header']=bundle_header(tiny_raw,CANONICAL,{PARENT})
    create(R9_BUNDLE,bundle_raw);create(R10_BUNDLE,tiny_raw);fsync_dir(CONTROL)
    result['r9_bundle']=stable(R9_BUNDLE)[1]
    result['r10_bundle']=stable(R10_BUNDLE)[1]
    absent(INTERMEDIATE)
    owned('clone-borrowed-intermediate',BASE,'clone','--no-hardlinks','--no-checkout',
          str(OLD),str(INTERMEDIATE))
    result['intermediate_anchor']=anchor_closure('intermediate-anchor-closure',INTERMEDIATE)
    assert result['intermediate_anchor']==result['anchor_before']
    result['r9_import']=import_bundle('import-r9',INTERMEDIATE,R9_BUNDLE,PARENT,PARENT_TREE)
    result['r10_import']=import_bundle('import-r10',INTERMEDIATE,R10_BUNDLE,CANONICAL,TREE)
    code,_=owned('new-canonical-ref-absent',INTERMEDIATE,'show-ref','--verify','--quiet',
                 CANONICAL_REF,allowed=(1,))
    assert code==1
    owned('new-canonical-ref',INTERMEDIATE,'update-ref',CANONICAL_REF,CANONICAL,'0'*40)
    owned('intermediate-head',INTERMEDIATE,'symbolic-ref','HEAD',CANONICAL_REF)
    _,actual_ref=git('intermediate-advertised-ref',INTERMEDIATE,'rev-parse',CANONICAL_REF)
    assert actual_ref==CANONICAL
    result['intermediate_canonical_advertised_ref']={'ref':CANONICAL_REF,'commit':actual_ref}
    absent(SOURCE)
    owned('clone-independent-final',BASE,'clone','--no-hardlinks','--dissociate',
          '--no-checkout','--branch','r10-canonical',str(INTERMEDIATE),str(SOURCE))
    owned('final-detached-checkout',SOURCE,'checkout','--detach',CANONICAL)
    result['source_after']=freeze('new-source',SOURCE,CANONICAL,TREE)
    result['canonical_proof']=prove_canonical()
    _,sparse=owned('final-sparse-config',SOURCE,'config','--local','--get-regexp',
       r'^(core[.]sparsecheckout|core[.]sparsecheckoutcone|extensions[.]worktreeconfig)$',allowed=(0,1))
    assert not sparse
    absent(SOURCE/'.git/info/sparse-checkout')
    _,tracked=owned('final-tree-paths',SOURCE,'ls-tree','-r','--name-only',CANONICAL)
    _,indexed=owned('final-index-paths',SOURCE,'ls-files')
    _,flags=owned('final-index-flags',SOURCE,'ls-files','-v')
    assert tracked==indexed and tracked
    assert all(line.startswith(b'H ') for line in flags.splitlines())
    assert len(flags.splitlines())==len(tracked.splitlines())
    result['full_checkout']={'tracked_entries':len(tracked.splitlines()),
        'tree_paths_sha256':digest(tracked),'index_paths_sha256':digest(indexed),
        'no_sparse_checkout':True,'no_skip_worktree_or_assume_unchanged':True}
    result['source_terminal']=freeze('new-terminal',SOURCE,CANONICAL,TREE)
    assert result['source_terminal']==result['source_after']
    result['independent_git_objects']=independent_git_objects()
    result['old_after']=freeze('old-after',OLD,OLD_HEAD,OLD_TREE,old=True)
    result['old_fences_after']=old_fences()
    assert result['old_before']==result['old_after']
    assert result['old_fences_before']==result['old_fences_after']
    result['known_hosts_after']=known_hosts_state(config)
    assert result['known_hosts_after']==result['ssh_before']['known_hosts']
    assert stable(R9_BUNDLE)[1]==result['r9_bundle'] and stable(R10_BUNDLE)[1]==result['r10_bundle']
    assert stable(Path(__file__).resolve(strict=True),262144)[1]==controller_pin
    assert stable(SOURCES/'source_sender_r10.py',262144)[1]==sender_pin
    assert stable(SOURCES/'canonical-r10.bundle.base64',4096)[1]==tiny_pin
    remaining()
    result['status']='prepared'
except BaseException as error:
    result['status']='failed';result['error_type']=type(error).__name__
    frames=[];tb=error.__traceback__
    while tb is not None:
        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
    result['failure_frames']=frames
finally:
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
    stop_errors={}
    for label,p in reversed(children):
        try:stop_active(p)
        except BaseException as error:stop_errors[label]=type(error).__name__
    try:current=process_snapshot();snapshot_error=None
    except BaseException as error:current=None;snapshot_error=type(error).__name__
    cleanup=[]
    for label,p in children:
        row={'label':label,'pid':p.pid,'exit_code':p.returncode,
             'direct_child_reaped':p.returncode is not None,
             'remaining':None if current is None else [x for x in current if x['pgid']==p.pid]}
        if label in stop_errors:row['cleanup_error_type']=stop_errors[label]
        if snapshot_error is not None:row['snapshot_error_type']=snapshot_error
        cleanup.append(row)
    result['commands']=commands;result['cleanup']=cleanup
    result['all_local_owned_stopped']=bool(cleanup) and all(
       row['direct_child_reaped'] and row['remaining']==[] and
       'cleanup_error_type' not in row and 'snapshot_error_type' not in row for row in cleanup)
    result['remote_cleanup_unknown']=remote_attempted and not remote_verified
    result['all_owned_stopped']=result['all_local_owned_stopped'] and not result['remote_cleanup_unknown']
    if pending_signal is not None or not result['all_owned_stopped']:result['status']='failed'
    result['deadline_before_receipt_passed']=time.monotonic()<UNTIL
    if not result['deadline_before_receipt_passed']:result['status']='failed'
    result['success_requires_authoritative_exit_zero']=True
    result['success_requires_terminal_publication_within_original_deadline']=True
    result['elapsed_seconds']=time.monotonic()-START;result['terminal_unix_ns']=time.time_ns()
    if created_control:
        public(CONTROL/'result.public.json',result);fsync_dir(BASE)
    within=time.monotonic()<UNTIL
    terminal_status=result['status'] if within else 'failed'
    terminal={'schema':result['schema'],'status':terminal_status,
      'receipt':str(CONTROL/'result.public.json') if created_control else None,
      'receipt_candidate_status':result['status'],'canonical_commit':CANONICAL,'canonical_tree':TREE,
      'all_owned_stopped':result['all_owned_stopped'],'remote_cleanup_unknown':result['remote_cleanup_unknown'],
      'publication_within_original_deadline':within,'elapsed_after_publication_seconds':time.monotonic()-START,
      'server_started':False,'compiler_started':False,'runtime_qualification':False}
    if not created_control:terminal['unpublished_failed_result']=result
    print(json.dumps(terminal,sort_keys=True),flush=True)
sys.exit(0 if terminal_status=='prepared' and time.monotonic()<UNTIL else 1)
