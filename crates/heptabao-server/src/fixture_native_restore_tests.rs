use super::*;
use crate::request_deadline::RequestDeadlineScope;
use serde_json::{Value, json};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn receive_ready(
    stream: &mut UnixStream,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let count = usize::from(u16::from_be_bytes(length));
    if !(1..=MAX_PAYLOAD).contains(&count) {
        return Err("invalid ready length".into());
    }
    let mut bytes = [0_u8; MAX_PAYLOAD];
    stream.read_exact(&mut bytes[..count])?;
    Ok(serde_json::from_slice(&bytes[..count])?)
}

fn ready(phase: Phase) -> Ready {
    Ready {
        version: 1,
        phase,
        nonce: "a".repeat(64),
        pid: std::process::id(),
        old_root: "1".repeat(64),
        new_root: "2".repeat(64),
        local_generation: 7,
        leader_id: 1,
        stage_count: 2,
        stage_index: Some(10),
        commit_index: None,
    }
}

#[test]
fn fixture_protocol_requires_exact_bounded_release_and_is_one_shot() -> TestResult {
    for variant in ["valid", "unknown", "nonce", "phase", "oversize", "eof"] {
        let (mut gate, mut controller) =
            NativeRestoreFaultGate::test_pair(Phase::BeforeRootPublish)?;
        let worker = std::thread::spawn(
            move || -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
                let observed = receive_ready(&mut controller)?;
                let mut release = json!({"version":1,"phase":"before_root_publish","nonce":"a".repeat(64),"action":"release"});
                match variant {
                    "unknown" => release["unrecognized"] = json!(true),
                    "nonce" => release["nonce"] = json!("b".repeat(64)),
                    "phase" => release["phase"] = json!("after_root_commit_before_local"),
                    "oversize" => {
                        controller.write_all(&511_u16.to_be_bytes())?;
                        return Ok(observed);
                    }
                    "eof" => return Ok(observed),
                    _ => {}
                }
                let bytes = serde_json::to_vec(&release)?;
                controller.write_all(&(bytes.len() as u16).to_be_bytes())?;
                controller.write_all(&bytes)?;
                Ok(observed)
            },
        );
        let _scope = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(5));
        let result = gate.wait(&ready(Phase::BeforeRootPublish));
        assert_eq!(result.is_ok(), variant == "valid");
        assert!(gate.wait(&ready(Phase::BeforeRootPublish)).is_err());
        let observed = worker
            .join()
            .map_err(|_| "controller thread")?
            .map_err(|_| "controller exchange")?;
        assert_eq!(observed["stage_index"], 10);
        assert!(observed["commit_index"].is_null());
    }
    Ok(())
}

#[test]
fn fixture_never_invents_or_refreshes_a_missing_or_expired_request_deadline() -> TestResult {
    assert!(crate::request_deadline::current().is_none());
    for expired in [false, true] {
        let (mut gate, mut controller) =
            NativeRestoreFaultGate::test_pair(Phase::BeforeRootPublish)?;
        let _scope = expired.then(|| RequestDeadlineScope::enter(Instant::now()));
        assert!(gate.wait(&ready(Phase::BeforeRootPublish)).is_err());
        controller.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut byte = [0_u8; 1];
        assert_eq!(controller.read(&mut byte)?, 0);
    }
    Ok(())
}

#[test]
fn fixture_control_arguments_reject_other_descriptors_before_adoption() {
    for fd in ["1", "3", "-1", "0;exit"] {
        let mut args = [
            "--config",
            "/a",
            "--ha-config",
            "/b",
            "--fixture-native-restore-fd",
            fd,
            "--fixture-native-restore-phase",
            "before_root_publish",
            "--fixture-native-restore-nonce",
            &"a".repeat(64),
        ]
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
        assert!(take_arguments(&mut args).is_err());
    }
    assert!(parse_phase("after_unknown_publish").is_err());
    for nonce in ["", "a", &"A".repeat(64), &"g".repeat(64)] {
        assert!(validate_nonce(nonce).is_err());
    }
}
