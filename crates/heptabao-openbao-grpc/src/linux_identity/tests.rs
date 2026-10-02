use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
struct Hook {
    calls: Arc<AtomicUsize>,
    change_at: usize,
    sealed: bool,
}
impl Hook {
    fn stable() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            change_at: usize::MAX,
            sealed: true,
        }
    }
}
impl AuthoritativeLifecycleHook for Hook {
    fn snapshot(&self) -> Result<HostLifecycle, BridgeError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HostLifecycle {
            sealed: self.sealed,
            configuration_generation: if call >= self.change_at { 2 } else { 1 },
        })
    }
}

struct Fixture {
    root: PathBuf,
    proc_root: PathBuf,
    executable: PathBuf,
    config: PathBuf,
    expected: OwnedPluginIdentity,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heptabao-proc-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let proc_root = root.join("proc");
        fs::create_dir(&proc_root)?;
        fs::create_dir(proc_root.join("101"))?;
        let executable = root.join("public-executable-fixture");
        let config = root.join("private-config-fixture");
        fs::write(&executable, b"PUBLIC_EXECUTABLE_FIXTURE")?;
        fs::write(&config, b"PUBLIC_CONFIG_FIXTURE")?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
        symlink(&executable, proc_root.join("101/exe"))?;
        let uid = fs::metadata(&root)?.uid();
        fs::write(proc_root.join("101/stat"), stat(101, 101, 200))?;
        fs::write(
            proc_root.join("101/status"),
            format!("Name:\tPRIVATE_COMM_NOT_EXPORTED\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )?;
        let exe = File::open(&executable)?;
        let cfg = File::open(&config)?;
        let em = stable_metadata(&exe)?;
        let cm = stable_metadata(&cfg)?;
        let expected = OwnedPluginIdentity {
            uid,
            pid: 101,
            session_id: 101,
            start_ticks: 200,
            executable_device: em.device,
            executable_inode: em.inode,
            executable_sha256: stable_hash(&exe, MAX_EXECUTABLE)?,
            config_device: cm.device,
            config_inode: cm.inode,
            config_sha256: stable_hash(&cfg, MAX_CONFIG)?,
            config_mode: 0o600,
        };
        Ok(Self {
            root,
            proc_root,
            executable,
            config,
            expected,
        })
    }
    fn probe(&self, hook: Hook) -> Result<LinuxIdentityProbe<Hook>, BridgeError> {
        LinuxIdentityProbe::capture_at(&self.proc_root, self.expected.clone(), &self.config, hook)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn stat(pid: u32, session: u32, ticks: u64) -> String {
    let mut fields = vec!["0".to_string(); 50];
    fields[0] = "S".into();
    fields[3] = session.to_string();
    fields[19] = ticks.to_string();
    // ')' and a newline in comm must not affect the numeric frame.
    format!("{pid} (PRIVATE)COMM\nNOT_EXPORTED) {}\n", fields.join(" "))
}

#[test]
fn held_identity_is_collected_and_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let probe = f.probe(Hook::stable())?;
    let (actual, lifecycle) = probe.observe()?;
    assert!(actual == f.expected, "OS identity changed");
    assert!(lifecycle.sealed && lifecycle.configuration_generation == 1);
    let debug = format!("{probe:?}");
    assert!(
        !debug.contains("PUBLIC_CONFIG")
            && !debug.contains("metadata-")
            && !debug.contains("PRIVATE_COMM")
    );
    Ok(())
}

#[test]
fn mutable_contents_mode_inode_and_symlink_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    for change in 0..8 {
        let f = Fixture::new()?;
        let probe = f.probe(Hook::stable())?;
        match change {
            0 => fs::write(&f.config, b"ALTERED_PUBLIC_CONFIG_FIXTURE")?,
            1 => fs::set_permissions(&f.config, fs::Permissions::from_mode(0o644))?,
            2 => {
                fs::rename(&f.config, f.root.join("old"))?;
                fs::write(&f.config, b"PUBLIC_CONFIG_FIXTURE")?;
                fs::set_permissions(&f.config, fs::Permissions::from_mode(0o600))?;
            }
            3 => {
                fs::rename(&f.config, f.root.join("old"))?;
                symlink(f.root.join("old"), &f.config)?;
            }
            4 => fs::write(&f.executable, b"ALTERED_PUBLIC_EXECUTABLE_FIXTURE")?,
            5 => {
                fs::remove_file(f.proc_root.join("101/exe"))?;
                fs::write(f.root.join("new-executable"), b"PUBLIC_EXECUTABLE_FIXTURE")?;
                symlink(f.root.join("new-executable"), f.proc_root.join("101/exe"))?;
            }
            6 => fs::hard_link(&f.config, f.root.join("alias"))?,
            _ => {
                fs::remove_file(&f.config)?;
                fs::create_dir(&f.config)?;
            }
        }
        assert!(probe.observe().is_err(), "changed OS identity admitted");
    }
    Ok(())
}

#[test]
fn process_reuse_uid_and_lifecycle_races_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    for change in 0..5 {
        let f = Fixture::new()?;
        let probe = f.probe(Hook::stable())?;
        match change {
            0 => fs::write(f.proc_root.join("101/stat"), stat(102, 101, 200))?,
            1 => fs::write(f.proc_root.join("101/stat"), stat(101, 102, 200))?,
            2 => fs::write(f.proc_root.join("101/stat"), stat(101, 101, 201))?,
            3 => {
                let wrong = u64::from(f.expected.uid) + 1;
                fs::write(
                    f.proc_root.join("101/status"),
                    format!("Uid:\t{wrong}\t{wrong}\t{wrong}\t{wrong}\n"),
                )?;
            }
            _ => fs::remove_file(f.proc_root.join("101/stat"))?,
        }
        assert!(probe.observe().is_err(), "changed process frame admitted");
    }
    let f = Fixture::new()?;
    let hook = Hook {
        change_at: 2,
        ..Hook::stable()
    };
    assert!(matches!(f.probe(hook), Err(BridgeError::LifecycleDenied)));
    assert!(matches!(
        f.probe(Hook {
            sealed: false,
            ..Hook::stable()
        }),
        Err(BridgeError::LifecycleDenied)
    ));
    let hook = Hook::stable();
    let probe = f.probe(hook.clone())?;
    let calls = hook.calls.load(Ordering::SeqCst);
    let changing = LinuxIdentityProbe {
        hook: Hook {
            change_at: calls + 1,
            ..hook
        },
        ..probe
    };
    assert!(changing.observe() == Err(BridgeError::LifecycleDenied));
    Ok(())
}

#[test]
fn proc_grammar_unknown_or_ambiguous_metadata_is_rejected() {
    assert!(parse_stat(stat(101, 101, 200).as_bytes()) == Ok((101, 101, 200)));
    for bad in [
        "1 (x) S 0 1",
        "0 (x) S",
        "01 (x) unknown",
        "1 x) S",
        "1 (x) Q",
    ] {
        assert!(parse_stat(bad.as_bytes()).is_err());
    }
    for bad in [
        "Uid:\t1\t1\t1\n",
        "Uid:\t1\t1\t2\t1\n",
        "Uid:\t1\t1\t1\t1\nUid:\t1\t1\t1\t1\n",
        "Uid:\ttrue\t1\t1\t1\n",
        "Pid:\t1\n",
        "Uid:\t01\t01\t01\t01\n",
    ] {
        assert!(parse_uids(bad.as_bytes()).is_err());
    }
    assert!(parse_uids(b"Name:\tPRIVATE\nUid:\t501\t501\t501\t501\n") == Ok(501));
}

#[test]
fn wrong_expected_digest_and_unbounded_files_deny_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let mut f = Fixture::new()?;
    f.expected.executable_sha256[0] ^= 1;
    assert!(matches!(
        f.probe(Hook::stable()),
        Err(BridgeError::IdentityChanged)
    ));
    let f = Fixture::new()?;
    assert!(stable_hash(&File::open(&f.config)?, 1).is_err());
    assert!(
        LinuxIdentityProbe::capture_at(
            &f.proc_root,
            f.expected.clone(),
            Path::new("relative"),
            Hook::stable()
        )
        .is_err()
    );
    #[cfg(not(target_os = "linux"))]
    assert!(matches!(
        LinuxIdentityProbe::capture(f.expected.clone(), &f.config, Hook::stable()),
        Err(BridgeError::ProcessObservationUnavailable)
    ));
    Ok(())
}

// This test is available for a separately authorized Linux scope. It reads only
// its own process metadata and a new owned 0600 fixture, without spawning.
#[cfg(target_os = "linux")]
#[test]
fn actual_proc_self_with_held_executable_and_private_config()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let pid = std::process::id();
    let uid = fs::metadata(format!("/proc/{pid}"))?.uid();
    let frame = process_frame(Path::new("/proc"), pid, uid)?;
    let exe = open_executable(Path::new("/proc"), pid)?;
    let cfg = open_config(&f.config)?;
    let em = stable_metadata(&exe)?;
    let cm = stable_metadata(&cfg)?;
    let expected = OwnedPluginIdentity {
        uid,
        pid,
        session_id: frame.session_id,
        start_ticks: frame.start_ticks,
        executable_device: em.device,
        executable_inode: em.inode,
        executable_sha256: stable_hash(&exe, MAX_EXECUTABLE)?,
        config_device: cm.device,
        config_inode: cm.inode,
        config_sha256: stable_hash(&cfg, MAX_CONFIG)?,
        config_mode: 0o600,
    };
    let probe = LinuxIdentityProbe::capture(expected.clone(), &f.config, Hook::stable())?;
    assert!(probe.observe()?.0 == expected);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn replaced_fifo_config_is_rejected_without_waiting_for_a_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let probe = f.probe(Hook::stable())?;
    fs::remove_file(&f.config)?;
    rustix::fs::mkfifoat(rustix::fs::CWD, &f.config, Mode::from_bits_truncate(0o600))?;
    assert!(probe.observe().is_err(), "nonregular config admitted");
    Ok(())
}
