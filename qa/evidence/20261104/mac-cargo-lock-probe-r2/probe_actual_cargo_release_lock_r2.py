from pathlib import Path
import fcntl,hashlib,json,os,platform,signal,stat,subprocess,time

BASE=Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT=BASE/'continuation-20261104-ha-cargo-lock-probe-61ff-r1'
TOOLCHAIN=Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin')
SECONDS=30.0
child=None
creating=False
pending_signal=None

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def write_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def write_json(path,value):
    write_new(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def interrupted(signum,frame):
    global pending_signal
    if creating:
        pending_signal=signum
        return
    raise RuntimeError('owned_probe_interrupted')

def start_owned(*args,**kwargs):
    global child,creating,pending_signal
    assert child is None or child.poll() is not None
    creating=True
    try:
        child=subprocess.Popen(*args,**kwargs)
    finally:
        creating=False
        if pending_signal is not None:raise RuntimeError('owned_probe_interrupted_during_spawn')
    return child

def stop_owned():
    if child is None:return None
    if child.poll() is None:
        assert os.getpgid(child.pid)==child.pid
        os.killpg(child.pid,signal.SIGTERM)
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            assert os.getpgid(child.pid)==child.pid
            os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
    else:child.wait()
    result=subprocess.run(['/bin/ps','-axo','pid=,pgid='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5)
    assert result.returncode==0
    remaining=[int(p[0]) for row in result.stdout.splitlines() if len(p:=row.split())==2 and int(p[1])==child.pid]
    return {'pid':child.pid,'wait_returncode':child.returncode,'remaining':remaining,'reaped':child.returncode is not None}

def main():
    os.umask(0o077)
    assert platform.system()=='Darwin' and platform.machine()=='arm64' and os.getuid()==501
    assert BASE.resolve(strict=True)==BASE and BASE.stat().st_uid==501
    assert not ROOT.exists() and not ROOT.is_symlink()
    ROOT.mkdir(mode=0o700)
    began=time.monotonic();until=began+SECONDS
    def remaining():
        left=until-time.monotonic()
        if left<=0:raise TimeoutError('original_probe_deadline')
        return left
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    result={'schema':'heptabao.actual-cargo-198-darwin-release-lock-probe.v1','status':'failed','budget_seconds':SECONDS,'source_cache_touched':False,'product_compiled_or_started':False,'exact_tag_handler_source_claimed':False}
    lock_fd=None;lock_held=False
    try:
        result['cargo']={'path':str(TOOLCHAIN/'cargo'),'sha256':sha(TOOLCHAIN/'cargo')}
        result['rustc']={'path':str(TOOLCHAIN/'rustc'),'sha256':sha(TOOLCHAIN/'rustc')}
        cargo_home=ROOT/'cargo-home';cargo_home.mkdir(mode=0o700)
        for parent in (ROOT,*ROOT.parents):
            for name in ('config','config.toml'):
                assert not (parent/'.cargo'/name).exists(), 'unexpected_inherited_cargo_config'
        environment={k:v for k,v in os.environ.items() if not k.startswith('CARGO_') and k not in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','RUSTDOCFLAGS','RUSTUP_TOOLCHAIN')}
        environment.update({'PATH':str(TOOLCHAIN)+':/usr/bin:/bin:/usr/sbin:/sbin','CARGO_HOME':str(cargo_home),'CARGO_TARGET_DIR':str(ROOT/'target'),'CARGO_TERM_COLOR':'never','RUSTC':str(TOOLCHAIN/'rustc'),'RUSTFLAGS':''})
        with (ROOT/'cargo-version.stdout').open('xb') as so,(ROOT/'cargo-version.stderr').open('xb') as se:
            p=start_owned([str(TOOLCHAIN/'cargo'),'-vV'],stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=environment,start_new_session=True)
            assert p.wait(timeout=remaining())==0
        version=(ROOT/'cargo-version.stdout').read_text()
        assert version.startswith('cargo 1.98.0 ')
        result['cargo_version']=version
        source=ROOT/'source';source.mkdir(mode=0o700);(source/'src').mkdir(mode=0o700)
        write_new(source/'Cargo.toml',b'[package]\nname = "heptabao-cargo-flock-probe"\nversion = "0.0.0"\nedition = "2021"\n[workspace]\n')
        write_new(source/'Cargo.lock',b'version = 4\n\n[[package]]\nname = "heptabao-cargo-flock-probe"\nversion = "0.0.0"\n')
        write_new(source/'src/main.rs',b'fn main() {}\n')
        target=ROOT/'target';target.mkdir(mode=0o700);release=target/'release';release.mkdir(mode=0o700)
        lock=release/'.cargo-lock';write_new(lock,b'')
        lock_fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW)
        st=os.fstat(lock_fd);assert stat.S_ISREG(st.st_mode) and st.st_uid==501 and st.st_nlink==1
        fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB);lock_held=True
        locked_at=time.monotonic_ns()
        args=[str(TOOLCHAIN/'cargo'),'build','--release','--locked','--offline','--manifest-path',str(source/'Cargo.toml'),'--message-format=json']
        with (ROOT/'cargo.stdout').open('xb') as so,(ROOT/'cargo.stderr').open('xb') as se:
            p=start_owned(args,cwd=source,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=environment,start_new_session=True)
            artifact=release/'heptabao-cargo-flock-probe'
            while True:
                remaining()
                stderr=(ROOT/'cargo.stderr').read_bytes()
                observed=(b'Blocking' in stderr and b'file lock on' in stderr and (b'build directory' in stderr or b'artifact directory' in stderr))
                if observed:break
                assert p.poll() is None, 'cargo_exited_before_build_directory_lock_observation'
                assert not artifact.exists(), 'cargo_artifact_appeared_while_flock_held'
                time.sleep(min(0.025,remaining()))
            assert p.poll() is None and not artifact.exists()
            result['blocked_same_child']={'pid':p.pid,'release_lock':str(lock),'existing_descriptor_mode':'O_RDONLY|O_NOFOLLOW','primitive':'flock LOCK_EX|LOCK_NB','lock_inode':st.st_ino,'lock_device':st.st_dev,'held_since_monotonic_ns':locked_at,'observed_at_monotonic_ns':time.monotonic_ns(),'artifact_absent':True,'stderr_sha256_at_observation':hashlib.sha256(stderr).hexdigest(),'diagnostic':stderr.decode('utf-8','strict').strip()}
            fcntl.flock(lock_fd,fcntl.LOCK_UN);lock_held=False
            result['released_at_monotonic_ns']=time.monotonic_ns()
            assert p.wait(timeout=remaining())==0
            so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
        events=[json.loads(line) for line in (ROOT/'cargo.stdout').read_text().splitlines()]
        assert any(e.get('reason')=='build-finished' and e.get('success') is True for e in events)
        actual=[e for e in events if e.get('reason')=='compiler-artifact' and e.get('executable')==str(artifact)]
        assert len(actual)==1 and actual[0]['fresh'] is False and actual[0]['profile']['test'] is False
        assert artifact.is_file()
        result.update(status='passed',same_child_pid=p.pid,completed_at_monotonic_ns=time.monotonic_ns(),artifact_sha256=sha(artifact),cargo_stdout_sha256=sha(ROOT/'cargo.stdout'),cargo_stderr_sha256=sha(ROOT/'cargo.stderr'),actual_cargo_artifact=actual[0])
        assert result['cargo']['sha256']==sha(TOOLCHAIN/'cargo') and result['rustc']['sha256']==sha(TOOLCHAIN/'rustc')
        remaining()
    except Exception as error:
        result['failure_class']=type(error).__name__
        result['failure_detail']=str(error) if isinstance(error,(AssertionError,RuntimeError,TimeoutError)) else None
    finally:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        if lock_fd is not None:
            if lock_held:fcntl.flock(lock_fd,fcntl.LOCK_UN)
            os.close(lock_fd)
        result['owned_child_cleanup']=stop_owned()
        if result['owned_child_cleanup'] is not None and result['owned_child_cleanup']['remaining']:
            result['status']='failed'
        result['elapsed_seconds']=time.monotonic()-began
        if result['elapsed_seconds']>SECONDS:
            result['status']='failed'
            result['failure_class']='OriginalTotalProbeDeadline'
        write_json(ROOT/'result.public.json',result)
        print(json.dumps({'status':result['status'],'result':str(ROOT/'result.public.json'),'result_sha256':sha(ROOT/'result.public.json'),'elapsed_seconds':result['elapsed_seconds'],'source_cache_touched':False,'product_compiled_or_started':False},sort_keys=True),flush=True)
    return 0 if result['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
