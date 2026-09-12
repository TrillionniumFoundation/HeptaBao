use super::*;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

use heptabao_domain::{CanonicalPath, Id};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};

use crate::{PluginLimits, sha256};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    manifest: PluginManifest,
}

impl Fixture {
    fn new(provider: &str, plugin: &str, timeout_ms: u64) -> Result<Self, Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!(
            "heptabao-command-runner-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let provider_path = root.join("provider");
        let plugin_path = root.join("plugin");
        write_executable(&provider_path, provider)?;
        write_executable(&plugin_path, plugin)?;
        let plugin_id = Id::parse("fixture_plugin")?;
        let mut registry = PluginRegistry::default();
        registry.register(PluginDescriptor::new(
            plugin_id.clone(),
            PluginKind::Secrets,
            CanonicalPath::parse(plugin_path.to_string_lossy().into_owned())?,
            sha256(plugin.as_bytes()),
            1,
        )?)?;
        registry.enable(&plugin_id)?;
        let manifest = PluginManifest::new(
            registry.get(&plugin_id)?.clone(),
            crate::SandboxBinding::new(
                Id::parse("fixture_provider")?,
                CanonicalPath::parse(provider_path.to_string_lossy().into_owned())?,
                sha256(provider.as_bytes()),
                Id::parse("fixture_profile")?,
            )?,
            PluginLimits {
                maximum_request_bytes: 1024 * 1024,
                maximum_response_bytes: 1024 * 1024,
                timeout_ms,
            },
            BTreeSet::from([PluginOperation::Read]),
            BTreeSet::from(["DESCENDANT_PID_FILE".to_owned()]),
        )?;
        Ok(Self { root, manifest })
    }

    fn environment(&self) -> Result<SecretEnvironment, Box<dyn Error>> {
        let mut environment = SecretEnvironment::new();
        environment.insert(
            "DESCENDANT_PID_FILE",
            self.root
                .join("descendant.pid")
                .to_string_lossy()
                .into_owned(),
        )?;
        Ok(environment)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // An explicit test intentionally escapes the runner's process group.
        // It is our test-owned child; clean it up independently of assertions.
        if let Ok(value) = fs::read_to_string(self.root.join("descendant.pid"))
            && let Some(raw) = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<i32>().ok())
            && let Some(pid) = Pid::from_raw(raw)
        {
            let _ = rustix::process::kill_process(pid, Signal::KILL);
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_executable(path: &Path, source: &str) -> io::Result<()> {
    fs::write(path, source)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

const NOOP_PLUGIN: &str = "#!/bin/sh\nexit 0\n";
const EXEC_PROVIDER: &str = concat!(
    "#!/usr/bin/python3\n",
    "import os, sys\n",
    "plugin = sys.argv[sys.argv.index('--heptabao-plugin') + 1]\n",
    "assert plugin.startswith('/proc/') and '/fd/' in plugin\n",
    "os.execv(plugin, [plugin])\n",
);
const ECHO_PLUGIN: &str = concat!(
    "#!/usr/bin/python3\n",
    "import struct, sys\n",
    "data = sys.stdin.buffer.read()\n",
    "assert data[:4] == b'HBP1'\n",
    "payload = data[11:]\n",
    "sys.stdout.buffer.write(b'HBR1' + struct.pack('>I', len(payload)) + payload)\n",
);

#[test]
fn blocked_stdin_obeys_deadline_before_any_output() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(
        "#!/usr/bin/python3\nimport time\ntime.sleep(30)\n",
        NOOP_PLUGIN,
        150,
    )?;
    let request = SecretValue::new(vec![b'x'; 512 * 1024])?;
    let started = Instant::now();
    let result = CommandSandboxRunner.invoke(
        &fixture.manifest,
        PluginOperation::Read,
        &request,
        &fixture.environment()?,
    );
    assert_eq!(result.err(), Some(SandboxFailure::OutcomeUnknownAfterEntry));
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

fn descendant_fixture(parent_tail: &str, escape: &str) -> Result<Fixture, Box<dyn Error>> {
    Fixture::new(
        &format!(
            "#!/usr/bin/python3\nimport os, sys, time\n\
         sys.stdin.buffer.read()\npid = os.fork()\n\
         if pid == 0:\n    {escape}\n    with open(os.environ['DESCENDANT_PID_FILE'], 'w') as f: f.write(str(os.getpid()) + ' ' + os.readlink('/proc/self'))\n    time.sleep(30)\n    os._exit(0)\n\
         {parent_tail}\n",
        ),
        NOOP_PLUGIN,
        200,
    )
}

fn assert_descendant_timeout(fixture: &Fixture) -> Result<(), Box<dyn Error>> {
    let request = SecretValue::new(b"synthetic".to_vec())?;
    let started = Instant::now();
    let result = CommandSandboxRunner.invoke(
        &fixture.manifest,
        PluginOperation::Read,
        &request,
        &fixture.environment()?,
    );
    assert_eq!(result.err(), Some(SandboxFailure::OutcomeUnknownAfterEntry));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(fixture.root.join("descendant.pid").is_file());
    Ok(())
}

fn assert_descendant_was_stopped(fixture: &Fixture) -> Result<(), Box<dyn Error>> {
    let identity = fs::read_to_string(fixture.root.join("descendant.pid"))?;
    let visible_pid = identity
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("missing proc identity"))?;
    let status_path = PathBuf::from(format!("/proc/{visible_pid}/stat"));
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let active = match fs::read_to_string(&status_path) {
            Ok(stat) => !stat
                .rsplit_once(") ")
                .is_some_and(|(_, state)| state.starts_with('Z')),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if !active {
            return Ok(());
        }
        assert!(
            Instant::now() < deadline,
            "runner left a process-group descendant active"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn successful_parent_cannot_leave_stdout_join_blocked_on_descendant() -> Result<(), Box<dyn Error>>
{
    let fixture = descendant_fixture(
        "sys.stdout.buffer.write(b'HBR1\\x00\\x00\\x00\\x01x'); sys.stdout.buffer.flush()",
        "pass",
    )?;
    assert_descendant_timeout(&fixture)?;
    assert_descendant_was_stopped(&fixture)
}

#[test]
fn timed_out_parent_and_descendant_do_not_block_cleanup() -> Result<(), Box<dyn Error>> {
    let fixture = descendant_fixture("time.sleep(30)", "pass")?;
    assert_descendant_timeout(&fixture)?;
    assert_descendant_was_stopped(&fixture)
}

#[test]
fn escaped_descendant_cannot_extend_io_deadline() -> Result<(), Box<dyn Error>> {
    let fixture = descendant_fixture("sys.exit(0)", "os.setsid()")?;
    assert_descendant_timeout(&fixture)
}

#[test]
fn verified_snapshots_execute_after_both_original_paths_are_replaced() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(EXEC_PROVIDER, ECHO_PLUGIN, 2000)?;
    let executables = Executables::open(&fixture.manifest)
        .map_err(|_| io::Error::other("snapshot admission failed"))?;
    for name in ["provider", "plugin"] {
        fs::rename(
            fixture.root.join(name),
            fixture.root.join(format!("old-{name}")),
        )?;
        write_executable(&fixture.root.join(name), "#!/bin/sh\nexit 97\n")?;
    }
    let request = b"original-snapshot";
    let frame = encode_request(1, PluginOperation::Read, request)?;
    let response = executables
        .invoke(
            &fixture.manifest,
            PluginOperation::Read,
            &frame,
            &fixture.environment()?,
        )
        .map_err(|_| io::Error::other("descriptor execution failed"))?;
    assert_eq!(response.expose(), request);
    Ok(())
}

#[test]
fn verified_snapshots_survive_in_place_mutation_and_reject_writes() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EXEC_PROVIDER, ECHO_PLUGIN, 2000)?;
    let executables = Executables::open(&fixture.manifest)
        .map_err(|_| io::Error::other("snapshot admission failed"))?;
    for (name, image) in [
        ("provider", &executables.provider),
        ("plugin", &executables.plugin),
    ] {
        write_executable(&fixture.root.join(name), "#!/bin/sh\nexit 98\n")?;
        let opened = fs::OpenOptions::new()
            .write(true)
            .open(image.descriptor_path());
        if let Ok(mut opened) = opened {
            assert!(opened.write_all(b"corrupt").is_err());
            assert!(opened.set_len(0).is_err());
        }
    }
    let request = b"immutable-snapshot";
    let frame = encode_request(1, PluginOperation::Read, request)?;
    let response = executables
        .invoke(
            &fixture.manifest,
            PluginOperation::Read,
            &frame,
            &fixture.environment()?,
        )
        .map_err(|_| io::Error::other("immutable descriptor execution failed"))?;
    assert_eq!(response.expose(), request);
    Ok(())
}

#[test]
fn changed_checksum_or_symlink_path_fails_before_entry() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EXEC_PROVIDER, ECHO_PLUGIN, 2000)?;
    write_executable(&fixture.root.join("plugin"), NOOP_PLUGIN)?;
    assert_eq!(
        CommandSandboxRunner.admit(&fixture.manifest),
        Err(SandboxFailure::BeforeEntry)
    );
    fs::remove_file(fixture.root.join("plugin"))?;
    write_executable(&fixture.root.join("replacement"), ECHO_PLUGIN)?;
    symlink(
        fixture.root.join("replacement"),
        fixture.root.join("plugin"),
    )?;
    assert_eq!(
        CommandSandboxRunner.admit(&fixture.manifest),
        Err(SandboxFailure::BeforeEntry)
    );
    Ok(())
}

#[test]
fn full_duplex_io_does_not_deadlock_when_provider_writes_before_reading()
-> Result<(), Box<dyn Error>> {
    let provider = concat!(
        "#!/usr/bin/python3\nimport struct, sys\n",
        "payload = b'y' * (256 * 1024)\n",
        "sys.stdout.buffer.write(b'HBR1' + struct.pack('>I', len(payload)) + payload)\n",
        "sys.stdout.buffer.flush()\n",
        "data = sys.stdin.buffer.read()\n",
        "assert len(data) == 512 * 1024 + 11\n",
    );
    let fixture = Fixture::new(provider, NOOP_PLUGIN, 2000)?;
    let request = SecretValue::new(vec![b'x'; 512 * 1024])?;
    let response = CommandSandboxRunner
        .invoke(
            &fixture.manifest,
            PluginOperation::Read,
            &request,
            &fixture.environment()?,
        )
        .map_err(|_| io::Error::other("duplex invocation failed"))?;
    assert_eq!(response.expose(), vec![b'y'; 256 * 1024]);
    Ok(())
}

#[test]
fn oversized_stdout_fails_without_waiting_for_process_exit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(
        concat!(
            "#!/usr/bin/python3\nimport sys, time\n",
            "sys.stdout.buffer.write(b'x' * (1024 * 1024 + 9))\n",
            "sys.stdout.buffer.flush()\ntime.sleep(30)\n",
        ),
        NOOP_PLUGIN,
        2000,
    )?;
    let request = SecretValue::new(b"small".to_vec())?;
    let started = Instant::now();
    let result = CommandSandboxRunner.invoke(
        &fixture.manifest,
        PluginOperation::Read,
        &request,
        &fixture.environment()?,
    );
    assert_eq!(result.err(), Some(SandboxFailure::OutcomeUnknownAfterEntry));
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}
