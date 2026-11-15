"""One read-only original cargo fmt check of prepared49d; no Rust build or product execution."""
from pathlib import Path
import hashlib, json, os, platform, stat, subprocess, sys, time, types
ROOT=Path('/home/alex/heptabao-kv2-ha-convergence-49d3b-authbus-20261107-r1')
OUT=ROOT/'build-test-r1'
SOURCE=ROOT/'source-49d3b'
BASE_ROOT=Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
BASE=BASE_ROOT/'source-4bde9'
WORK=OUT/'format-check-r1'
COMMIT='49d3bb88f548d7647c44cefe21e5e7ab75a77fe9'
TREE='ad35130626cbfa172dddfaffa1d09d081c7ff4dc'
TOOLCHAIN=Path('/home/alex/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
START=time.monotonic(); END=START+90
FDS=[]; PUBLIC={}; OWNER=None
REPORT={'schema':'heptabao.current-source-readonly-format-check.v1','status':'failed',
        'source_commit':COMMIT,'source_tree':TREE,'source':str(SOURCE),
        'original_format_cap_seconds':60,'inner_budget_seconds':90,
        'rust_compilation_executed':False,'rust_tests_executed':False,
        'product_executions':0,'source_modified':False,'automatic_retry':False,
        'formal107_qualified':False,'sourceprep_job_id':'1a1b41027d1-fc05-860f',
        'sourceprep_terminal_sha256':'8fe897b5496a0cb3ed59bedd5c81e01b48cf3674cafa21404c95db44b05ea69d',
        'sourceprep_stdout_sha256':'f9dd0fd4e8c9af968d569e76e3153899de2cdbe6f64612db1c61387ab44d48b4',
        'steps':[],'remoteClosureUnknown':False}
SELECTION_PIN = (142663, '869feff2d8672fe37a26a2fb671cdc853b3c9d7f889edfe76650eed8103f44e9')
HELPERS = {
    'owned_process': (28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
    'kv2_dr_process_custody': (26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
}
PRODUCT_PINS = {
    'crates/heptabao-server/src/state_records.rs': (18031, 'b419525a98f096c85681869b6037fb8356837fc5b8664ad3c09d9e2adc609e45'),
    'crates/heptabao-server/src/state_records/tests.rs': (33657, '2ce1ed3614bedf4531428df21dcdb3ccf938616a34f25cbdf867ef7b79a3c526'),
    'crates/heptabao-server/src/engines/kv2_native_paged.rs': (53318, '10b4865f78284c702f2e9136b0917f35ecd545e697433dd874a4fa6688e9da2c'),
    'crates/heptabao-server/src/engines/kv2_native_payload_validation_tests.rs': (14337, '35fa6c21b9d86fd66ab1216248614a01e19da453e12b73b1fcf6778c48e0dddb'),
}

class Refused(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refused(code)

def live():
    need(time.monotonic() < END - 10, 'original_preparation_deadline')

def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def file_pin(path, expected=None, *, contents=False, maximum=128 * 1024 * 1024):
    live()
    path = Path(path)
    before = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode)
         and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
         and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
         'bounded_owned_regular_public_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    row = {'fd': fd, 'attempts': 0, 'closed': False}; FDS.append(row)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'same_open_public_input')
        digest, size, raw = hashlib.sha256(), 0, bytearray()
        while True:
            live()
            part = os.read(fd, min(1048576, before.st_size + 1 - size))
            if not part:
                break
            size += len(part)
            need(size <= before.st_size, 'input_size_growth')
            digest.update(part)
            if contents:
                raw.extend(part)
        pin = (size, digest.hexdigest())
        need(size == before.st_size and identity(os.fstat(fd)) == identity(path.lstat()) == identity(before),
             'complete_public_input_unchanged')
        need(expected is None or pin == expected, 'exact_public_input_pin')
        PUBLIC.setdefault(path, (pin, identity(before)))
        return pin, bytes(raw)
    finally:
        row['attempts'] = 1
        os.close(fd); row['closed'] = True

def directory(path, private=False):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and not info.st_mode & 0o022
         and (not private or stat.S_IMODE(info.st_mode) == 0o700), 'owned_canonical_directory')
    return identity(info)[:5]

def run(label, args, cap, *, allow=(0,)):
    live()
    budget=min(cap, END-10-time.monotonic()); need(budget>0,'command_deadline')
    streams=[]
    try:
        for suffix in ('stdout','stderr'):
            stream=(WORK/(label+'.'+suffix)).open('xb')
            row={'fd':stream.fileno(),'attempts':0,'closed':False}
            FDS.append(row); streams.append((stream,row))
        began=time.monotonic()
        p=subprocess.run(args,cwd=SOURCE,env=ENV,stdin=subprocess.DEVNULL,
                         stdout=streams[0][0],stderr=streams[1][0],
                         timeout=budget,start_new_session=True)
        OWNER.assert_retired()
        for stream,_ in streams:
            stream.flush(); os.fsync(stream.fileno())
    finally:
        first=None
        for stream,row in reversed(streams):
            row['attempts']=1
            try: stream.close(); row['closed']=True
            except BaseException as error: first=first or error
        if first is not None: raise first
    so,raw=file_pin(WORK/(label+'.stdout'),contents=True,maximum=1048576)
    se,err=file_pin(WORK/(label+'.stderr'),contents=True,maximum=1048576)
    REPORT['steps'].append({'label':label,'argv':args,'cap_seconds':cap,
                           'effective_budget_seconds':budget,'exit_code':p.returncode,
                           'elapsed_seconds':time.monotonic()-began,
                           'stdout_bytes':so[0],'stdout_sha256':so[1],
                           'stderr_bytes':se[0],'stderr_sha256':se[1]})
    need(p.returncode in allow,label+'_failed')
    return p.returncode,raw.decode('utf-8','strict'),err.decode('utf-8','strict')

def source_state(phase):
    result={}
    for name,args in (('head',['rev-parse','HEAD']),('tree',['rev-parse','HEAD^{tree}']),
                      ('clean',['status','--porcelain','--untracked-files=all'])):
        _,value,_=run(phase+'-'+name,['/usr/bin/git','-C',str(SOURCE),*args],10)
        result[name]=value.strip()
    need(result=={'head':COMMIT,'tree':TREE,'clean':''},'exact_clean_current_source')
    return result

try:
    os.umask(0o077)
    need(platform.node()=='alex-G1628-04' and platform.system()=='Linux'
         and platform.machine()=='x86_64' and os.getuid()==1000,'exact_pocket4_account')
    dirs={p:directory(p,private=True) for p in (ROOT,OUT,SOURCE,BASE_ROOT,BASE)}
    need(not os.path.lexists(WORK),'new_readonly_format_output')
    WORK.mkdir(mode=0o700); dirs[WORK]=directory(WORK,private=True)
    _,raw=file_pin(OUT/'preparation.result.public.json',
                   (39109,'733fc3cd70c92e706dacc235036a9d04432e49fc86937e7187fcc05cdfe0efb8'),
                   contents=True,maximum=65536)
    prior=json.loads(raw)
    need(prior['status']=='passed' and prior['source_commit']==COMMIT
         and prior['source_tree']==TREE and prior['source_clean'] is True
         and prior['all_original_inputs_unchanged'] is True
         and prior['processCustody']['passed_process_custody'] is True
         and prior['remoteClosureUnknown'] is False,'prepared_current_source')
    _,raw=file_pin(BASE_ROOT/'build-test-r1/test-selection.public.json',SELECTION_PIN,
                   contents=True,maximum=524288)
    selection=json.loads(raw)
    ENV={key:os.environ[key] for key in ('HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR','TZ')
         if key in os.environ}
    ENV.update(selection['original_build']['env'])
    ENV.update(RUSTC=str(TOOLCHAIN/'rustc'),RUSTFMT=str(TOOLCHAIN/'rustfmt'),
               RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='',
               CARGO_BUILD_RUSTC_WRAPPER='',CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='',
               CARGO_NET_OFFLINE='true',GIT_OPTIONAL_LOCKS='0',GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    REPORT['format_only_offline_override']=True
    tools={'cargo':'ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24',
           'rustc':'3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2',
           'rustfmt':'5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'}
    for name,digest in tools.items():
        pin,_=file_pin(TOOLCHAIN/name); need(pin[1]==digest,'exact_original_toolchain')
    file_pin(TOOLCHAIN/'cargo-fmt')
    file_pin(Path('/usr/bin/git'),maximum=32*1024*1024)
    for name,pin in PRODUCT_PINS.items(): file_pin(SOURCE/name,pin)
    for name,key in (('Cargo.lock','pocket4_source_Cargo_lock'),
                     ('Cargo.toml','pocket4_source_workspace_manifest')):
        x=selection['old_retained_artifacts'][key]
        file_pin(SOURCE/name,(x['bytes'],x['sha256']))
    modules={}
    for name,pin in HELPERS.items():
        path=BASE/'qa/openbao-acceptance'/(name+'.py')
        _,raw=file_pin(path,pin,contents=True,maximum=65536)
        need(name not in sys.modules,'helper_not_preloaded')
        module=types.ModuleType(name); module.__file__=str(path);sys.modules[name]=module
        exec(compile(raw,str(path),'exec'),module.__dict__);modules[name]=module
    with modules['kv2_dr_process_custody'].activated() as owner:
        OWNER=owner
        before=source_state('before')
        rc,stdout,stderr=run('original-format-check',
            [str(TOOLCHAIN/'cargo'),'fmt','--all','--','--check'],60,allow=(0,1))
        REPORT.update(format_exit_code=rc,format_stdout=stdout,format_stderr=stderr)
        after=source_state('after'); need(before==after,'source_changed')
    REPORT['processCustody']=OWNER.assert_retired()
    for path,(pin,full9) in list(PUBLIC.items()):
        file_pin(path,pin); need(identity(path.lstat())==full9,'public_source_changed')
    need(all(directory(p,private=True)==i for p,i in dirs.items()),'directory_changed')
    REPORT.update(status='passed' if rc==0 else 'failed',
                  all_public_inputs_unchanged=True,source_clean_after=True)
    if rc: REPORT['failure']='original_cargo_fmt_check_failed'
except BaseException as error:
    REPORT['status']='failed'
    REPORT['failure']=str(error) if isinstance(error,Refused) else type(error).__name__
finally:
    if OWNER is not None:
        REPORT['processCustody']=OWNER.receipt()
        REPORT['remoteClosureUnknown']=not (OWNER.finished and all(
            r.get('original_wait_completed') is True and r.get('no_live_members_before_reap') is True
            for r in OWNER.rows))
        if not REPORT['processCustody']['passed_process_custody']: REPORT['status']='failed'
    for row in reversed(FDS):
        if row['attempts']==0:
            row['attempts']=1
            try: os.close(row['fd']);row['closed']=True
            except BaseException: REPORT['status']='failed'
    REPORT['allDescriptorsClosedOnce']=all(r['attempts']==1 and r['closed'] for r in FDS)
    REPORT['descriptorCount']=len(FDS); REPORT['elapsedSeconds']=time.monotonic()-START
    if not REPORT['allDescriptorsClosedOnce'] or REPORT['remoteClosureUnknown'] or time.monotonic()>=END:
        REPORT['status']='failed'
    print(json.dumps(REPORT,sort_keys=True),flush=True)
raise SystemExit(0 if REPORT['status']=='passed' else 1)
