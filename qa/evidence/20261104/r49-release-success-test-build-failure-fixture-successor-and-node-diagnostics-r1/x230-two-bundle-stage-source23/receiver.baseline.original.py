#!/usr/bin/env python3
"""Receive fixed 4e808 public artifacts and one standalone full Git bundle.

No old X230 repository is used as a prerequisite. No binary, compiler, provider
request, acceptance suite or production service is started.
"""
from pathlib import Path
import hashlib, json, os, platform, re, select, signal, stat, subprocess, sys, time

os.umask(0o077)
BASE=Path('/home/qian')
ROOT=BASE/'heptabao-same-root-publication-normal-20261105-r1'
CONTROL=ROOT/'control'
ART=ROOT/'artifacts'
SOURCE=ROOT/'source'
CANONICAL='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
TREE='eba5e650bd080b8ad41ea52a2bc68867f541d255'
PARENT='1c66541993662f92cf717154e33717abedb2ea74'
ROOT_COMMIT='67d79b3b5442ed033d38929eab2010403463e56d'
CANONICAL_COUNT=3763
TRACKED_FILES=3914
MAX_BUNDLE=64*1024*1024
UID=1000
SYSTEM=('Linux','x86_64')
BINDING_READY=True
FILES=[
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifacts-r1/incoming/heptabao-server",
    "name": "heptabao-server",
    "bytes": 110219600,
    "sha256": "cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0",
    "source_mode": 320,
    "target_mode": 320,
    "version": "2050:7361480:110219600:1793892019496540722:1793892019496540722"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifacts-r1/incoming/native-build.public.json",
    "name": "native-build.public.json",
    "bytes": 786,
    "sha256": "3bfc21f48ce6dd831c8bde094b2f24f53ed0266e57e5fd55839b0a5977f5db5a",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361482:786:1793892021124514009:1793892021124514009"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifacts-r1/incoming/normal-release-result.public.json",
    "name": "result.public.json",
    "bytes": 3192,
    "sha256": "78d5eeb0235f62896ec57ca4d0243e31c56e861a4dde438ccd23eac3edafdd22",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361483:3192:1793892021131513894:1793892021131513894"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-carrier-r1/incoming/canonical-4e808-full.bundle",
    "name": "canonical-4e808-full.bundle",
    "bytes": 22320862,
    "sha256": "bb014971cb243db71e07d04b862fbba2436ceec09d2c1bafa707e4aa558bf5ac",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361612:22320862:1793898902432875221:1793898902432875221"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-source-carrier-r1/incoming/source-export.result.public.json",
    "name": "source-export.result.public.json",
    "bytes": 39692,
    "sha256": "47feb984dbda306b523071e09107ecade8bda10e712d74e5116a58d164eb027b",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361625:39692:1793898902726866721:1793898902726866721"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifacts-r1/incoming/normal-release-tests-result.public.json",
    "name": "normal61-result.public.json",
    "bytes": 57532,
    "sha256": "7830845172732432895c246d77c47266432a03c0788e15689ea74d15dff14475",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361495:57532:1793892021140513746:1793892021140513746"
  },
  {
    "path": "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifacts-r1/incoming/groups.json",
    "name": "groups.json",
    "bytes": 6249,
    "sha256": "0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1",
    "source_mode": 256,
    "target_mode": 256,
    "version": "2050:7361500:6249:1793892021148513615:1793892021148513615"
  }
]

START=time.monotonic()
UNTIL=START+300
children,commands=[],[]
deferred_logs=[]
protected=0
pending_signal=None
created_control=False
result={'schema':'heptabao.4e808.x230-standalone-source-receiver.v1','status':'failed',
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

def binding_ready():
 assert BINDING_READY is True,'actual_normal61_export_and_transport_file_bindings_unresolved'
 assert len(FILES)==7 and len({x['name'] for x in FILES})==7
 for item in FILES:
  assert type(item['bytes']) is int and item['bytes']>0
  assert isinstance(item['sha256'],str) and len(item['sha256'])==64
  assert all(c in '0123456789abcdef' for c in item['sha256'])
  assert isinstance(item['version'],str) and len(item['version'].split(':'))==5

def need(value,label):
 if not value:raise RuntimeError(label)

def verify_normal61(raw):
 n=json.loads(raw['normal61-result.public.json'])
 need(n.get('schema')=='heptabao.linux-normal-same-root-publication-exact-tests.v1'
      and n.get('source_commit')==CANONICAL and n.get('source_tree')==TREE
      and n.get('controller_sha256')=='93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be'
      and n.get('status')=='passed' and n.get('test_count')==44
      and n.get('selected_test_total')==61 and n.get('normal_default_features') is True
      and n.get('fixture_features')==[] and n.get('original_44_status')=='passed'
      and n.get('original_44_and_ingress_7_status')=='passed'
      and n.get('original_60_status')=='passed' and n.get('original_60_test_total')==60
      and n.get('additional_test_counts')=={'ingress_observer':7,'cold_h2':9,'same_root_publication':1}
      and n.get('source_unchanged') is True and n.get('binary_unchanged') is True
      and n.get('release_artifacts_unchanged') is True,'exact_normal61_qualification')
 for key,names in (
     ('ingress_observer_regression',["service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_is_affine_and_resumed_binding_never_arms","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root","service::native_v6_ha_install::tests::ingress_selection_tests::fresh_ingress_actual_failed_repair_closes_reselection_before_any_result","ha::native_v6_runtime::request_timing_tests::native_request_timing_failure_has_only_bounded_static_metadata","ha::native_v6_runtime::request_timing_tests::native_request_timing_sixty_four_buckets_preserve_existing_aggregates","ha::native_v6_runtime::request_timing_tests::native_request_timing_observes_deadlines_but_preserves_once_only_results","ha::native_v6_runtime::request_timing_tests::native_request_timing_phase_advance_is_distinct_from_operation_success"]),
     ('cold_h2_regression',["service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_once_and_owned_result_identity","service::native_v6_ha_install::read::cold_timing_tests::cold_native_ha_timing_preserves_nested_source_and_inner_results","service::native_v6_ha_install::tests::native_ha_install_batches_actual_readindex_cold_missing_and_corrupt_file","http::h2_transport::sync_worker_tests::h2_sync_worker_is_unentered_and_retains_outer_context","http::h2_transport::sync_worker_tests::h2_sync_worker_expired_deadline_never_calls_work","http::h2_transport::sync_worker_tests::h2_sync_worker_preserves_inner_result","http::h2_transport::sync_worker_tests::h2_sync_worker_joins_panicked_work_and_drops_capture","http::h2_transport::sync_worker_tests::h2_sync_worker_does_not_authorize_nested_runtime_context","http::h2_transport::sync_worker_tests::h2_sync_worker_cancelled_waiter_retains_blocking_capacity"])):
  group=n.get(key,{})
  need(group.get('status')=='passed' and group.get('test_count')==len(names)
       and group.get('actual_test_names')==names and group.get('clamped_to_original_outer_deadline') is True,
       'exact_separate_normal_regression')
 cleanup=n.get('cleanup')
 need(isinstance(cleanup,list) and cleanup and all(
      row.get('exit_code')==0 and row.get('direct_child_reaped') is True
      and row.get('remaining')==[] and not row.get('cleanup_error_type') for row in cleanup),
      'normal_all_children_terminal')
 need(n.get('groups_sha256')==digest(raw['groups.json'])=='0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1',
      'unchanged_original44_groups_whole_pin')
 need(n.get('native_build_receipt_sha256')==digest(raw['native-build.public.json']),
      'combined_normal61_native_receipt_exact')
 need(n.get('original_outer_seconds')==12000 and n.get('within_original_outer_before_receipt') is True
      and n.get('additional_group_caps_seconds')=={'ingress_observer':600,'cold_h2':600,'same_root_publication':600},
      'original_normal61_budgets_and_publication')
 same=n.get('same_root_publication_regression',{})
 need(same.get('schema')=='heptabao.normal-same-root-publication-regression.v1'
      and same.get('status')=='passed' and same.get('test_count')==1
      and same.get('actual_test_names')==['service::native_v6_ha_install::tests::same_root_republication_tests::native_ha_same_root_republication_advances_warm_and_cold_cursors']
      and same.get('original_44_7_9_denominators_unchanged') is True
      and same.get('clamped_to_original_outer_deadline') is True
      and same.get('new_total_group_cap_seconds')==600,
      'independent_same_root_publication_regression')
 result['normal61_qualification_verified']=True

def verify_receipts(raw):
    verify_normal61(raw)
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
    binding_ready()
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
    bundle=ART/'canonical-4e808-full.bundle'
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
