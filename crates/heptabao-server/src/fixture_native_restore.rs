//! Opt-in Linux test instrumentation. No environment, HTTP or persisted switch.
//! The controller owns process termination; the child only waits once on fd 0.
use crate::state_record_root::StateIdentity;
use heptabao_raft_runtime::CommitReceipt;
use rustix::net::{AddressFamily, SocketType, sockopt};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

const MAX_PAYLOAD: usize = 510; // Two-byte length plus payload <= 512 bytes.
const GATE_ERROR: &str = "native restore fixture control failed";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    BeforeRootPublish,
    AfterRootCommitBeforeLocal,
}

/// Affine process-owned channel. Its contents never carry application secrets.
pub struct NativeRestoreFaultGate {
    stream: Option<UnixStream>,
    nonce: String,
    phase: Phase,
}

impl NativeRestoreFaultGate {
    /// Only the explicit instrumented executable calls this, before HA starts.
    /// Fixed fd 0 avoids unsafe arbitrary-number descriptor adoption.
    pub fn from_stdin(phase: &str, nonce: &str) -> Result<Self, String> {
        let phase = parse_phase(phase)?;
        validate_nonce(nonce)?;
        let fd = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| GATE_ERROR)?;
        if sockopt::socket_domain(&fd).map_err(|_| GATE_ERROR)? != AddressFamily::UNIX
            || sockopt::socket_type(&fd).map_err(|_| GATE_ERROR)? != SocketType::STREAM
        {
            return Err("fixture fd 0 must be an AF_UNIX stream socketpair".into());
        }
        let peer = sockopt::socket_peercred(&fd).map_err(|_| GATE_ERROR)?;
        if peer.uid != rustix::process::geteuid() || Some(peer.pid) != rustix::process::getppid() {
            return Err("fixture socket peer must be the same-user parent controller".into());
        }
        let stream = UnixStream::from(fd);
        if !stream.local_addr().map_err(|_| GATE_ERROR)?.is_unnamed()
            || !stream.peer_addr().map_err(|_| GATE_ERROR)?.is_unnamed()
        {
            return Err("fixture control requires an unnamed socketpair".into());
        }
        let stdin = std::io::stdin();
        let flags = rustix::io::fcntl_getfd(stdin.as_fd()).map_err(|_| GATE_ERROR)?;
        rustix::io::fcntl_setfd(stdin.as_fd(), flags | rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| GATE_ERROR)?;
        stream.set_nonblocking(false).map_err(|_| GATE_ERROR)?;
        Ok(Self {
            stream: Some(stream),
            nonce: nonce.to_owned(),
            phase,
        })
    }

    fn wait(&mut self, ready: &Ready) -> Result<(), &'static str> {
        let mut stream = self.stream.take().ok_or(GATE_ERROR)?;
        let result = (|| {
            let deadline = crate::request_deadline::current().ok_or(GATE_ERROR)?;
            let payload = serde_json::to_vec(ready).map_err(|_| GATE_ERROR)?;
            if payload.is_empty() || payload.len() > MAX_PAYLOAD {
                return Err(GATE_ERROR);
            }
            write_until(&mut stream, &(payload.len() as u16).to_be_bytes(), deadline)?;
            write_until(&mut stream, &payload, deadline)?;
            let mut length = [0_u8; 2];
            read_until(&mut stream, &mut length, deadline)?;
            let length = usize::from(u16::from_be_bytes(length));
            if !(1..=MAX_PAYLOAD).contains(&length) {
                return Err(GATE_ERROR);
            }
            let mut bytes = [0_u8; MAX_PAYLOAD];
            read_until(&mut stream, &mut bytes[..length], deadline)?;
            let release: Release =
                serde_json::from_slice(&bytes[..length]).map_err(|_| GATE_ERROR)?;
            if release.version != 1
                || release.phase != self.phase
                || release.nonce != self.nonce
                || release.action != "release"
            {
                return Err(GATE_ERROR);
            }
            remaining(deadline)?;
            Ok(())
        })();
        // Also shuts down the original inherited stdin descriptor. Never
        // close a borrowed stdio FD or leave a second usable gate behind.
        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    #[cfg(test)]
    pub(crate) fn test_pair(phase: Phase) -> std::io::Result<(Self, UnixStream)> {
        let (stream, controller) = UnixStream::pair()?;
        Ok((
            Self {
                stream: Some(stream),
                nonce: "a".repeat(64),
                phase,
            },
            controller,
        ))
    }
}

impl Drop for NativeRestoreFaultGate {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Parse only the exact suffix; ordinary builds never compile this function.
pub fn take_arguments(
    arguments: &mut Vec<String>,
) -> Result<Option<NativeRestoreFaultGate>, String> {
    if !arguments
        .iter()
        .any(|arg| arg.starts_with("--fixture-native-restore-"))
    {
        return Ok(None);
    }
    if arguments.len() != 10
        || arguments[0] != "--config"
        || arguments[2] != "--ha-config"
        || arguments[4] != "--fixture-native-restore-fd"
        || arguments[5] != "0"
        || arguments[6] != "--fixture-native-restore-phase"
        || arguments[8] != "--fixture-native-restore-nonce"
    {
        return Err(
            "invalid native restore fixture arguments; inherited fd must be 0 and HA is required"
                .into(),
        );
    }
    let gate = NativeRestoreFaultGate::from_stdin(&arguments[7], &arguments[9])?;
    arguments.truncate(4);
    Ok(Some(gate))
}

fn parse_phase(value: &str) -> Result<Phase, String> {
    match value {
        "before_root_publish" => Ok(Phase::BeforeRootPublish),
        "after_root_commit_before_local" => Ok(Phase::AfterRootCommitBeforeLocal),
        _ => Err("unknown native restore fixture phase".into()),
    }
}
fn validate_nonce(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("fixture nonce must be 32 bytes of lowercase hexadecimal".into());
    }
    Ok(())
}

#[derive(Serialize)]
struct Ready {
    version: u8,
    phase: Phase,
    nonce: String,
    pid: u32,
    old_root: String,
    new_root: String,
    local_generation: u64,
    leader_id: u64,
    stage_count: usize,
    stage_index: Option<u64>,
    commit_index: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    version: u8,
    phase: Phase,
    nonce: String,
    action: String,
}

/// Created only by authenticated native HA restore, never a normal write.
pub(crate) struct NativeRestoreFaultContext {
    gate: NativeRestoreFaultGate,
    old: StateIdentity,
    new: StateIdentity,
    generation: u64,
    stage_count: usize,
    last_stage: Option<CommitReceipt>,
    prepublication_error: Option<&'static str>,
}
impl NativeRestoreFaultContext {
    pub(crate) fn new(
        gate: NativeRestoreFaultGate,
        old: StateIdentity,
        new: StateIdentity,
        generation: u64,
    ) -> Self {
        Self {
            gate,
            old,
            new,
            generation,
            stage_count: 0,
            last_stage: None,
            prepublication_error: None,
        }
    }
    pub(crate) fn reject_before_publish(&mut self, message: &'static str) -> String {
        self.prepublication_error = Some(message);
        message.to_owned()
    }
    pub(crate) fn take_prepublication_error(&mut self) -> Option<&'static str> {
        self.prepublication_error.take()
    }
    pub(crate) fn before_publish(
        &mut self,
        old: StateIdentity,
        new: StateIdentity,
        leader: u64,
        count: usize,
        last: Option<CommitReceipt>,
    ) -> Result<(), String> {
        if old != self.old
            || new != self.new
            || old == new
            || last
                .as_ref()
                .is_some_and(|receipt| receipt.leader_id != leader)
            || (count == 0) != last.is_none()
        {
            return Err(self.reject_before_publish("fixture staged publication identity mismatch"));
        }
        self.stage_count = count;
        self.last_stage = last;
        if self.gate.phase == Phase::BeforeRootPublish {
            if count == 0 {
                return Err(
                    self.reject_before_publish("fixture P requires actual accepted Stage receipts")
                );
            }
            let ready = self.ready(leader, None);
            if let Err(error) = self.gate.wait(&ready) {
                return Err(self.reject_before_publish(error));
            }
        }
        Ok(())
    }
    pub(crate) fn after_commit(
        &mut self,
        receipt: &CommitReceipt,
        local_generation: u64,
    ) -> Result<(), &'static str> {
        if self.gate.phase != Phase::AfterRootCommitBeforeLocal {
            return Ok(());
        }
        if receipt.envelope_digest != self.new.digest()
            || local_generation != self.generation
            || self.last_stage.as_ref().is_some_and(|last| {
                last.leader_id != receipt.leader_id || last.log_index >= receipt.log_index
            })
        {
            return Err("fixture committed publication identity mismatch");
        }
        let ready = self.ready(receipt.leader_id, Some(receipt.log_index));
        self.gate.wait(&ready)
    }
    fn ready(&self, leader_id: u64, commit_index: Option<u64>) -> Ready {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        Ready {
            version: 1,
            phase: self.gate.phase,
            nonce: self.gate.nonce.clone(),
            pid: std::process::id(),
            old_root: hex(&self.old.digest()),
            new_root: hex(&self.new.digest()),
            local_generation: self.generation,
            leader_id,
            stage_count: self.stage_count,
            stage_index: self.last_stage.as_ref().map(|r| r.log_index),
            commit_index,
        }
    }
}

fn remaining(deadline: Instant) -> Result<std::time::Duration, &'static str> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(GATE_ERROR)?;
    if remaining.is_zero() {
        return Err(GATE_ERROR);
    }
    Ok(remaining)
}
fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), &'static str> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| GATE_ERROR)?;
        match stream.write(bytes) {
            Ok(0) => return Err(GATE_ERROR),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(GATE_ERROR),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), &'static str> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| GATE_ERROR)?;
        match stream.read(bytes) {
            Ok(0) => return Err(GATE_ERROR),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(GATE_ERROR),
        }
    }
    remaining(deadline)?;
    Ok(())
}

#[cfg(test)]
#[path = "fixture_native_restore_tests.rs"]
mod tests;
