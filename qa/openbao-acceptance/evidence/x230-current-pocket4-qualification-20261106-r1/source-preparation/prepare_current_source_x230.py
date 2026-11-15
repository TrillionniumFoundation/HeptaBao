#!/usr/bin/env python3
"""Create one exact canonical checkout from the existing owned X230 checkout.

No Rust, product executable, listener or production service is started. Original
Git children use the unchanged 4b custody helper; old sources remain read only.
"""
from pathlib import Path
import hashlib,importlib.util,json,os,platform,stat,subprocess,sys,time
ROOT=Path('/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1')
BASE=Path('/home/qian/heptabao-same-root-publication-normal-20261105-r1/source')
SOURCE=ROOT/'source-4bde9'
OUT=ROOT/'source-preparation-r1'
CONTROL=ROOT/'control'
COMMIT='4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE='f08493a23f8ea0637073651231865ea9607b790e'
BASE_HEAD='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
BASE_TREE='eba5e650bd080b8ad41ea52a2bc68867f541d255'
PARENT='09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
PREREQUISITE='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
PREREQUISITE_TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
BUNDLE_SHA='9d7d937b2d324f73913f7f1fc144c6368ffa79593dad1dfede82e8033362f7b0'
CUSTODY_SHA='669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'
OWNED_SHA='0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'
QUALIFIER_SHA='448696002a72dbca1c9d2b070d826a34aac4ef0bc4ad7c3e77feab7a66fa7655'
TEST='crates/heptabao-server/src/service_native_jwt_tests.rs'
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','GIT_OPTIONAL_LOCKS':'0',
     'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
     'PYTHONDONTWRITEBYTECODE':'1'}
START=time.monotonic();END=START+300
REPORT={'schema':'heptabao.x230-current-canonical-source-preparation.v1','status':'failed',
        'source_commit':COMMIT,'source_tree':TREE,'source':str(SOURCE),'base_source':str(BASE),
        'steps':[],'source_budget_seconds':300,'no_hardlinks':False,
        'production_changed':False,'compiler_invocations':0,'product_binary_executions':0,
        'formal_x230_runtime_qualified':False,'automatic_retry':False,'deadline_renewed':False}

def need(ok,label):
    if not ok:raise RuntimeError(label)

def ident(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def pin(path,maximum=1024*1024,contents=False):
    need(path.is_absolute() and path.resolve(strict=True)==path,'literal_input_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and
            before.st_nlink==1 and not before.st_mode&0o022 and before.st_size<=maximum,'bounded_owned_input')
        parts=[];h=hashlib.sha256();n=0
        while True:
            need(time.monotonic()<END,'source_preparation_deadline')
            b=os.read(fd,65536)
            if not b:break
            n+=len(b);need(n<=before.st_size,'input_growth_refused');h.update(b)
            if contents:parts.append(b)
        need(n==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'input_changed')
        value={'path':str(path),'bytes':n,'sha256':h.hexdigest(),'identity':ident(before)}
        return (value,b''.join(parts)) if contents else value
    finally:os.close(fd)

def load_bound(name,path,digest):
    before,raw=pin(path,65536,True);need(before['sha256']==digest,'source_helper_hash')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;exec(compile(raw,str(path),'exec'),module.__dict__)
    need(pin(path,65536)==before,'source_helper_unchanged')
    return module,before

def run(label,args,cap=15):
    left=END-time.monotonic();need(left>0,'source_preparation_deadline')
    actual=min(cap,left);started=time.monotonic();code=None;timed=False
    stdout=OUT/(label+'.stdout');stderr=OUT/(label+'.stderr')
    try:
        with stdout.open('xb') as so,stderr.open('xb') as se:
            try:
                p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=ENV,
                    cwd=OUT,timeout=actual,start_new_session=True,check=False)
                code=p.returncode
            except subprocess.TimeoutExpired:
                timed=True;raise
            finally:
                so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
    finally:
        row={'label':label,'argv':args,'requested_cap_seconds':cap,'effective_cap_seconds':actual,
             'exit_code':code,'timed_out':timed,'elapsed_seconds':time.monotonic()-started,'attempts':1}
        if stdout.exists():row['stdout']=pin(stdout,2*1024*1024)
        if stderr.exists():row['stderr']=pin(stderr,2*1024*1024)
        REPORT['steps'].append(row)
    need(code==0 and not timed,label+'_failed')
    return stdout.read_bytes()

def git(label,path,*args,cap=15):
    return run(label,['/usr/bin/git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
                     '-C',str(path),*args],cap).decode().strip()

def freeze(label,path,commit,tree):
    info=path.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==1000 and
        not info.st_mode&0o022 and path.resolve(strict=True)==path,'owned_source_directory')
    need(git(label+'-head-tree',path,'rev-parse','HEAD','HEAD^{tree}').splitlines()==[commit,tree],label+'_identity')
    need(not git(label+'-clean',path,'status','--porcelain','--untracked-files=all'),label+'_clean')
    need(git(label+'-full',path,'rev-parse','--is-shallow-repository')=='false' and
         not os.path.lexists(path/'.git/objects/info/alternates'),'standalone_full_source')
    return {'head':commit,'tree':tree,'directory_identity':ident(info)[:5],
        'cargo_lock':pin(path/'Cargo.lock'),'workspace_manifest':pin(path/'Cargo.toml')}

def main():
    os.umask(0o077)
    need(platform.system()=='Linux' and platform.machine()=='x86_64' and
         platform.node()=='qian-ThinkPad-X230' and os.geteuid()==1000,'actual_x230_host')
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'isolated_interpreter')
    info=ROOT.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==1000 and
         stat.S_IMODE(info.st_mode)==0o700 and ROOT.resolve(strict=True)==ROOT,'new_owned_receiver_root')
    need(not os.path.lexists(OUT) and not os.path.lexists(SOURCE),'create_only_source_and_output')
    OUT.mkdir(mode=0o700)
    owner=None
    try:
        owned,owned_pin=load_bound('owned_process',CONTROL/'owned_process.py',OWNED_SHA)
        custody,custody_pin=load_bound('current_source_custody',CONTROL/'kv2_dr_process_custody.py',CUSTODY_SHA)
        qualifier,qualifier_pin=load_bound('current_source_qualifier',CONTROL/'x230_current_candidate_qualification.py',QUALIFIER_SHA)
        inputs={'owned':owned_pin,'custody':custody_pin,'qualifier':qualifier_pin,
                'bundle':pin(ROOT/'provenance/candidate.bundle')}
        need(inputs['bundle']['bytes']==377715 and inputs['bundle']['sha256']==BUNDLE_SHA,'exact_canonical_bundle')
        REPORT['inputs_before']=inputs
        with custody.activated() as owner:
            try:
                before=freeze('base-before',BASE,BASE_HEAD,BASE_TREE);REPORT['base_before']=before
                need(git('base-prerequisite',BASE,'rev-parse',PREREQUISITE+'^{tree}')==PREREQUISITE_TREE,'exact_bundle_prerequisite')
                git('base-fsck',BASE,'fsck','--full','--strict',cap=60)
                run('clone',['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',
                    'clone','--no-hardlinks','--no-local','--no-checkout',str(BASE),str(SOURCE)],90)
                git('bundle-verify',SOURCE,'bundle','verify',str(ROOT/'provenance/candidate.bundle'),cap=30)
                git('fetch-canonical',SOURCE,'fetch',str(ROOT/'provenance/candidate.bundle'),'HEAD',cap=30)
                need(git('fetched-head',SOURCE,'rev-parse','FETCH_HEAD')==COMMIT,'exact_bundle_head')
                git('checkout',SOURCE,'checkout','--detach',COMMIT,cap=30)
                git('candidate-fsck',SOURCE,'fsck','--full','--strict',cap=60)
                current=freeze('candidate',SOURCE,COMMIT,TREE)
                need(git('candidate-parent',SOURCE,'rev-parse','HEAD^')==PARENT,'exact_candidate_parent')
                need(git('candidate-test-diff',SOURCE,'diff','--name-only',PARENT,COMMIT).splitlines()==[TEST]
                     and pin(SOURCE/TEST)['sha256']=='1571d88838fb127509cdbe24a7e7b5402453ec4cb1dbb784d56753aa2f49e584','canonical_jwt_only_fix')
                objects=[p for p in (SOURCE/'.git/objects').rglob('*') if p.is_file()]
                need(objects and all(not p.is_symlink() and p.lstat().st_nlink==1 for p in objects),'independent_objects_no_hardlinks')
                snapshot=qualifier.source_snapshot(SOURCE)
                after=freeze('base-after',BASE,BASE_HEAD,BASE_TREE);need(after==before,'original_base_source_changed')
                for item in inputs.values():need(pin(Path(item['path']))==item,'source_preparation_input_changed')
                owner.assert_retired()
                REPORT.update(status='passed',base_after=after,candidate=current,source_dependency_snapshot=snapshot,
                    source_clean=True,no_hardlinks=True,original_base_preserved=True,inputs_unchanged=True)
            finally:REPORT['process_custody']=owner.finish()
        need(REPORT['process_custody']['passed_process_custody'] is True,'source_children_not_retired')
    except BaseException as error:
        REPORT['status']='failed';REPORT['failure']=str(error) if isinstance(error,RuntimeError) else type(error).__name__
        if owner is not None:REPORT['process_custody']=owner.finish()
    REPORT['elapsed_seconds']=time.monotonic()-START
    data=(json.dumps(REPORT,sort_keys=True,indent=2)+'\n').encode()
    with (OUT/'result.public.json').open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'status':REPORT['status'],'source':str(SOURCE),'source_commit':COMMIT,
          'result':str(OUT/'result.public.json'),'product_binary_executions':0}),flush=True)
    return 0 if REPORT['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
