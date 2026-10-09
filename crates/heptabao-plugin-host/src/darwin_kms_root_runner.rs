//! Explicit operator-installed Darwin root KMS entry. Ordinary Mac plugin
//! manifests remain BeforeEntry. No caller copy may strip the root image mode.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use ring::digest::{Context, SHA256};
use rustix::fs::{Access, AtFlags, Mode, OFlags};
use zeroize::Zeroizing;
use super::{CommandSandboxRunner, PluginManifest, PluginOperation, SandboxFailure,
    SandboxRunner, SecretEnvironment, SecretValue, decode_response, encode_request};

const PROFILE: &str = "darwin-root-kms-v1";
const POLL: Duration = Duration::from_millis(2);
const ENVIRONMENT: [&str; 6] = ["HEPTABAO_KMS_DEPLOYMENT", "HEPTABAO_KMS_DEPLOYMENT_SHA256",
    "HEPTABAO_KMS_PROVIDER", "HEPTABAO_KMS_TEMP", "HEPTABAO_KMS_TIMEOUT_MS",
    "HEPTABAO_KMS_DEADLINE_MONOTONIC_NS"];

impl SandboxRunner for CommandSandboxRunner {
    fn admit(&self, manifest: &PluginManifest) -> Result<(), SandboxFailure> {
        RootBrokerPin::open(manifest).map(|_| ())
    }
    fn invoke(&self, manifest: &PluginManifest, operation: PluginOperation,
        request: &SecretValue, environment: &SecretEnvironment) -> Result<SecretValue,SandboxFailure> {
        if operation != PluginOperation::Read ||
            request.len() > manifest.limits().maximum_request_bytes ||
            environment.iter().count()!=ENVIRONMENT.len() ||
            environment.iter().any(|(n,_)| !ENVIRONMENT.contains(&n)) {
            return Err(SandboxFailure::BeforeEntry);
        }
        let stamp=environment.iter().find(|(n,_)| *n=="HEPTABAO_KMS_DEADLINE_MONOTONIC_NS")
            .and_then(|(_,v)| v.parse::<u64>().ok()).ok_or(SandboxFailure::BeforeEntry)?;
        let now=monotonic_ns()?;
        let remaining=stamp.checked_sub(now).filter(|v| *v>0)
            .ok_or(SandboxFailure::BeforeEntry)?;
        if remaining > manifest.limits().timeout_ms.saturating_mul(1_000_000) {
            return Err(SandboxFailure::BeforeEntry);
        }
        // The caller's original absolute timestamp, before pin hashing and IO.
        let deadline=Instant::now().checked_add(Duration::from_nanos(remaining))
            .ok_or(SandboxFailure::BeforeEntry)?;
        let pin=RootBrokerPin::open(manifest)?;
        if Instant::now()>=deadline { return Err(SandboxFailure::BeforeEntry); }
        let frame=encode_request(manifest.descriptor().protocol_version(),operation,request.expose())
            .map_err(|_| SandboxFailure::BeforeEntry)?;
        if !pin.unchanged() || Instant::now()>=deadline { return Err(SandboxFailure::BeforeEntry); }
        let mut command=Command::new(&pin.path);
        command.env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        for (name,value) in environment.iter() { command.env(name,value); }
        // Kernel setuid exec must actually yield EUID=0/RUID=caller. Go observes
        // it before IO and validates the external deployment/broker pin itself.
        let child=command.spawn().map_err(|_| SandboxFailure::BeforeEntry)?;
        let mut child=RootChild(Some(child));
        let original=child.0.as_mut().ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        let mut input=Some(original.stdin.take().ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?);
        let mut output=original.stdout.take().ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        nonblocking(input.as_ref().ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?)?;
        nonblocking(&output)?;
        let mut bytes=Zeroizing::new(Vec::new());
        let mut buffer=Zeroizing::new([0_u8;16384]);
        let maximum=manifest.limits().maximum_response_bytes.checked_add(8)
            .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        let mut written=0; let mut eof=false; let mut status=None;
        loop {
            if Instant::now()>=deadline { return Err(SandboxFailure::OutcomeUnknownAfterEntry); }
            if let Some(pipe)=input.as_mut() {
                match pipe.write(&frame[written..]) {
                    Ok(0)=>return Err(SandboxFailure::OutcomeUnknownAfterEntry),
                    Ok(n)=>written+=n, Err(e) if retryable(&e)=>{},
                    Err(_)=>return Err(SandboxFailure::OutcomeUnknownAfterEntry)
                }
                if written==frame.len() { input=None; }
            }
            if !eof {
                match output.read(&mut buffer[..]) {
                    Ok(0)=>eof=true,
                    Ok(n)=>{
                        if n>maximum.saturating_sub(bytes.len()) { return Err(SandboxFailure::OutcomeUnknownAfterEntry); }
                        bytes.extend_from_slice(&buffer[..n]);
                    },
                    Err(e) if retryable(&e)=>{},
                    Err(_)=>return Err(SandboxFailure::OutcomeUnknownAfterEntry)
                }
            }
            if status.is_none() {
                status=original.try_wait().map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)?;
            }
            if let Some(exit)=status {
                if !exit.success() { return Err(SandboxFailure::OutcomeUnknownAfterEntry); }
                if eof && input.is_none() {
                    if !pin.unchanged() { return Err(SandboxFailure::OutcomeUnknownAfterEntry); }
                    return decode_response(&bytes,manifest.limits().maximum_response_bytes)
                        .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry);
                }
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

struct RootChild(Option<Child>);
impl Drop for RootChild {
    fn drop(&mut self) {
        if let Some(mut child)=self.0.take() {
            // No numeric PID kill, group kill or fabricated task right. The
            // root broker owns the original absolute guard and traced provider.
            // A failed/expired outer call returns False immediately; detached
            // reap is the same actual Child, never a successful provider Wait.
            if !matches!(child.try_wait(),Ok(Some(_))) {
                let _=thread::Builder::new().name("heptabao-root-kms-reaper".into())
                    .spawn(move || { let _=child.wait(); });
            }
        }
    }
}
struct RootBrokerPin { path: PathBuf, file: File, ancestors: Vec<(File,PathBuf)>, identity: [i128;9], expected: [u8;32] }
fn identity(m:&std::fs::Metadata)->[i128;9] {
    [i128::from(m.dev()),i128::from(m.ino()),i128::from(m.mode()),i128::from(m.uid()),
        i128::from(m.gid()),i128::from(m.nlink()),i128::from(m.size()),
        i128::from(m.mtime())*1_000_000_000+i128::from(m.mtime_nsec()),
        i128::from(m.ctime())*1_000_000_000+i128::from(m.ctime_nsec())]
}
fn readonly_caller(fd:&impl AsFd,path:&str)->bool {
    rustix::fs::accessat(fd,path,Access::WRITE_OK,AtFlags::empty())==Err(rustix::io::Errno::ACCESS)
}
impl RootBrokerPin {
    fn open(m:&PluginManifest)->Result<Self,SandboxFailure> {
        let d=m.descriptor();let s=m.sandbox();
        if rustix::process::getuid().as_raw()==0 ||
            d.kind()!=heptabao_plugin_contracts::PluginKind::Kms ||
            d.protocol_version()!=1 || s.profile_id.as_str()!=PROFILE ||
            s.command.as_str()!=d.command().as_str() || s.command_sha256!=*d.checksum() ||
            m.operations().len()!=1 || !m.operations().contains(&PluginOperation::Read) ||
            m.environment_allowlist().len()!=ENVIRONMENT.len() ||
            m.environment_allowlist().iter().any(|n| !ENVIRONMENT.contains(&n.as_str())) {
            return Err(SandboxFailure::BeforeEntry);
        }
        let path=Path::new(d.command().as_str());
        if !d.command().as_str().starts_with("/Volumes/T5/") ||
            path.components().any(|c| matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir)) {
            return Err(SandboxFailure::BeforeEntry);
        }
        let mut ancestors=Vec::new();
        let mut prefix=PathBuf::from("/");
        for part in path.parent().ok_or(SandboxFailure::BeforeEntry)?.components() {
            if let std::path::Component::Normal(part)=part { prefix.push(part); }
            else if !matches!(part,std::path::Component::RootDir) { return Err(SandboxFailure::BeforeEntry); }
            let file=File::from(rustix::fs::open(&prefix,OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC,Mode::empty())
                .map_err(|_| SandboxFailure::BeforeEntry)?);
            let meta=file.metadata().map_err(|_| SandboxFailure::BeforeEntry)?;
            if !meta.is_dir() || meta.uid()!=0 || meta.mode()&0o2!=0 || !readonly_caller(&file,".") {
                return Err(SandboxFailure::BeforeEntry);
            }
            ancestors.push((file,prefix.clone()));
        }
        let file=File::from(rustix::fs::open(path,OFlags::RDONLY|OFlags::NOFOLLOW|OFlags::CLOEXEC|OFlags::NONBLOCK,Mode::empty())
            .map_err(|_| SandboxFailure::BeforeEntry)?);
        let meta=file.metadata().map_err(|_| SandboxFailure::BeforeEntry)?;
        if !meta.is_file() || meta.uid()!=0 || meta.nlink()!=1 || meta.mode()&0o7777!=0o4555 ||
            meta.len()>64*1024*1024 ||
            !readonly_caller(&rustix::fs::CWD,d.command().as_str()) {
            return Err(SandboxFailure::BeforeEntry);
        }
        let pin=Self{path:path.to_path_buf(),file,ancestors,identity:identity(&meta),expected:*d.checksum()};
        if !pin.unchanged() { return Err(SandboxFailure::BeforeEntry); }
        Ok(pin)
    }
    fn unchanged(&self)->bool {
        for (file,path) in &self.ancestors {
            let Ok(meta)=file.metadata() else {return false};
            let Ok(named)=std::fs::symlink_metadata(path) else {return false};
            if !named.is_dir() || meta.dev()!=named.dev() || meta.ino()!=named.ino() ||
                meta.uid()!=0 || meta.mode()&0o2!=0 || !readonly_caller(file,".") {return false}
        }
        let Ok(meta)=self.file.metadata() else {return false};
        let Ok(named)=std::fs::symlink_metadata(&self.path) else {return false};
        if identity(&meta)!=self.identity || identity(&named)!=self.identity ||
            !readonly_caller(&rustix::fs::CWD,self.path.to_str().unwrap_or("")) {return false}
        let mut hash=Context::new(&SHA256);let mut buffer=[0_u8;16384];let mut offset=0;
        use std::os::unix::fs::FileExt;
        loop {
            let Ok(n)=self.file.read_at(&mut buffer,offset) else {return false};
            if n==0 {break};hash.update(&buffer[..n]);offset+=n as u64;
        }
        hash.finish().as_ref()==self.expected
            && self.file.metadata().is_ok_and(|m|identity(&m)==self.identity)
    }
}
fn nonblocking(fd:&impl AsFd)->Result<(),SandboxFailure> {
    let flags=rustix::fs::fcntl_getfl(fd).map_err(|_|SandboxFailure::OutcomeUnknownAfterEntry)?;
    rustix::fs::fcntl_setfl(fd,flags|OFlags::NONBLOCK).map_err(|_|SandboxFailure::OutcomeUnknownAfterEntry)
}
fn retryable(e:&io::Error)->bool {matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)}
fn monotonic_ns()->Result<u64,SandboxFailure> {
    let t=rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(rustix::time::ClockId::Monotonic))
        .map_err(|_|SandboxFailure::BeforeEntry)?;
    if t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1_000_000_000 {return Err(SandboxFailure::BeforeEntry)}
    (t.tv_sec as u64).checked_mul(1_000_000_000).and_then(|v|v.checked_add(t.tv_nsec as u64))
        .ok_or(SandboxFailure::BeforeEntry)
}
