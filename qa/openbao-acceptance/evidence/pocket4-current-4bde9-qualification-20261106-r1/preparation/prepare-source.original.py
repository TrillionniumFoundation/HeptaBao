"""Prepare canonical 4b on pocket4 only. No Rust build or Bao service execution."""
from pathlib import Path
import hashlib,json,os,stat,subprocess,sys,time,tomllib

os.umask(0o077)
ROOT=Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
BASE=Path('/home/alex/heptabao-replacement-unified-20261105-r5/source')
SOURCE=ROOT/'source-4bde9'
OUT=ROOT/'build-test-r1'
COMMIT='4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE='f08493a23f8ea0637073651231865ea9607b790e'
PARENT='09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
BASE_HEAD='1f188df0f2affebb92702222e9fe5dfb4712194c'
BASE_TREE='74bcb2b2af2fc9d349f007cd847fc2f16c08c01a'
PREREQUISITE='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c'
PREREQUISITE_TREE='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825'
BUNDLE_SHA='9d7d937b2d324f73913f7f1fc144c6368ffa79593dad1dfede82e8033362f7b0'
TEST='crates/heptabao-server/src/service_native_jwt_tests.rs'
CARGO_HOME=Path('/home/alex/.cargo')
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}
START=time.monotonic()
REPORT={'schema':'heptabao.pocket4-canonical-source-preparation.v1','status':'running',
        'source_commit':COMMIT,'source_tree':TREE,'source':str(SOURCE),'base_source':str(BASE),
        'steps':[],'no_hardlinks':False,'production_changed':False,'rust_build_executed':False,
        'formal_107_qualified':False,'full_replacement_qualified':False,'automatic_retry':False,
        'rog_unknown_preparation_replayed':False}

def need(ok,label):
    if not ok:raise RuntimeError(label)

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def pin(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1,'regular_unshared_file_required')
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':digest(path)}

def run(label,args,cap):
    stdout=OUT/(label+'.stdout');stderr=OUT/(label+'.stderr');started=time.monotonic()
    with stdout.open('xb') as so,stderr.open('xb') as se:
        process=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=ENV,timeout=cap,cwd=OUT)
        so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
    REPORT['steps'].append({'label':label,'argv':args,'original_cap_seconds':cap,
                            'exit_code':process.returncode,'seconds':round(time.monotonic()-started,6),
                            'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr)})
    need(process.returncode==0,label+'_failed')
    return stdout.read_text().strip()

def git(path,*args):
    return subprocess.check_output(['/usr/bin/git','-C',str(path),*args],env=ENV,stderr=subprocess.DEVNULL,timeout=15).decode().strip()

def base_state():
    return {'head':git(BASE,'rev-parse','HEAD'),'tree':git(BASE,'rev-parse','HEAD^{tree}'),
            'clean':not bool(git(BASE,'status','--porcelain','--untracked-files=all')),
            'cargo_lock':pin(BASE/'Cargo.lock'),'workspace_manifest':pin(BASE/'Cargo.toml')}

def registry_inventory():
    lock=tomllib.loads((SOURCE/'Cargo.lock').read_text())
    packages=lock['package']
    registries=[p for p in packages if p.get('source','').startswith('registry+')]
    git_packages=[p for p in packages if p.get('source','').startswith('git+')]
    cache=CARGO_HOME/'registry/cache'
    need(cache.is_dir() and not cache.is_symlink(),'existing_registry_cache_required')
    groups=[p for p in cache.iterdir() if p.is_dir() and not p.is_symlink()]
    matched=[];missing=[];mismatch=[]
    for package in registries:
        name=package['name']+'-'+package['version']+'.crate'
        files=[group/name for group in groups if (group/name).is_file() and not (group/name).is_symlink()]
        if not files:missing.append({'name':package['name'],'version':package['version']});continue
        if not any(digest(path)==package.get('checksum') for path in files):
            mismatch.append({'name':package['name'],'version':package['version']})
        else:matched.append({'name':package['name'],'version':package['version']})
    return {'cargo_lock':pin(SOURCE/'Cargo.lock'),'registry_packages':len(registries),
            'matching_archive_count':len(matched),'missing_archives':missing,'mismatched_archives':mismatch,
            'git_dependency_count':len(git_packages),'all_lock_registry_archives_verified':not missing and not mismatch,
            'all_lock_dependencies_offline_available':not missing and not mismatch and not git_packages,
            'registry_source_names_redacted':True,'cargo_or_rustc_executed':False,
            'missing_unused_target_packages_are_not_a_product_test_failure':True}

try:
    need(ROOT.resolve(strict=True)==ROOT and OUT.resolve(strict=True)==OUT,'owned_paths_required')
    need(stat.S_IMODE(ROOT.stat().st_mode)==0o700 and stat.S_IMODE(OUT.stat().st_mode)==0o700,'private_output_required')
    need(not os.path.lexists(SOURCE),'new_source_required')
    need(not (OUT/'result.public.json').exists() and not (OUT/'progress.public.json').exists(),'formal_attempt_not_started')
    before=base_state()
    need(before['head']==BASE_HEAD and before['tree']==BASE_TREE and before['clean'],'original_base_source_identity')
    need(git(BASE,'rev-parse',PREREQUISITE+'^{tree}')==PREREQUISITE_TREE,'bundle_prerequisite_required')
    REPORT['base_source_before']=before
    bundle=OUT/'candidate.bundle'
    need(bundle.stat().st_size==377715 and digest(bundle)==BUNDLE_SHA,'bundle_pin')
    run('prepare-clone',['/usr/bin/git','clone','--no-hardlinks','--no-local','--no-checkout',str(BASE),str(SOURCE)],180)
    run('prepare-bundle-verify',['/usr/bin/git','-C',str(SOURCE),'bundle','verify',str(bundle)],30)
    run('prepare-fetch',['/usr/bin/git','-C',str(SOURCE),'fetch',str(bundle),'HEAD'],30)
    need(git(SOURCE,'rev-parse','FETCH_HEAD')==COMMIT,'fetched_commit_mismatch')
    run('prepare-checkout',['/usr/bin/git','-C',str(SOURCE),'checkout','--detach',COMMIT],30)
    run('prepare-fsck',['/usr/bin/git','-C',str(SOURCE),'fsck','--full','--strict'],60)
    need(git(SOURCE,'rev-parse','HEAD')==COMMIT and git(SOURCE,'rev-parse','HEAD^{tree}')==TREE,'candidate_identity_mismatch')
    need(git(SOURCE,'rev-parse','HEAD^')==PARENT,'candidate_parent_mismatch')
    need(not git(SOURCE,'status','--porcelain','--untracked-files=all'),'candidate_source_dirty')
    need(digest(SOURCE/TEST)=='1571d88838fb127509cdbe24a7e7b5402453ec4cb1dbb784d56753aa2f49e584','canonical_jwt_test_pin')
    changed=git(SOURCE,'diff','--name-only',PARENT,COMMIT).splitlines()
    need(changed==[TEST],'canonical_test_only_parent_diff')
    objects=[path for path in (SOURCE/'.git/objects').rglob('*') if path.is_file()]
    need(objects and all(not path.is_symlink() and path.stat().st_nlink==1 for path in objects),'source_object_hardlink_refused')
    REPORT['no_hardlinks']=True
    REPORT['offline_registry']=registry_inventory()
    REPORT['base_source_after']=base_state()
    need(REPORT['base_source_after']==before,'original_base_source_changed')
    REPORT.update(status='passed',source_at_exact_published_commit=True,source_clean=True,source_parent=PARENT,
                  changed_test_file=TEST,changed_test_file_sha256=digest(SOURCE/TEST),
                  original_base_source_preserved=True,bundle=pin(bundle),
                  source_Cargo_lock=pin(SOURCE/'Cargo.lock'),source_workspace_manifest=pin(SOURCE/'Cargo.toml'))
except BaseException as error:
    REPORT['status']='failed'
    REPORT['failure']=str(error) if isinstance(error,RuntimeError) else type(error).__name__
finally:
    REPORT['elapsed_seconds']=round(time.monotonic()-START,6);REPORT['finished_at_unix']=time.time()
    REPORT['preparation_script_sha256']=digest(Path(__file__))
    result=OUT/'preparation.result.public.json'
    with result.open('x') as stream:
        json.dump(REPORT,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'status':REPORT['status'],'source_commit':COMMIT,'source_tree':TREE,
                      'rust_build_executed':False,'all_lock_dependencies_offline_available':REPORT.get('offline_registry',{}).get('all_lock_dependencies_offline_available'),
                      'result':str(result)}),flush=True)
sys.exit(0 if REPORT['status']=='passed' else 1)
