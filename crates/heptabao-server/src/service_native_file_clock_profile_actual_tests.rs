//! The identical actual File test is included in the diagnostic baseline and
//! guarded variant. It records performance; no elapsed-time assertion grants
//! correctness or changes the original per-request 15-second budget.
use super::{ACTIVE, Phase, Scope};
use crate::service::*;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

#[test]
fn genuine_file_clock_profile_precise_get_cold_floor_and_payload_stable() -> TestResult {
    let directory = crate::service::tests::Root::new();
    let mut service = directory.service()?;
    service.configure_native_v6_candidate()?;
    let (key, root) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        crate::service::tests::bootstrap(&mut service)?
    };
    let key = Zeroizing::new(key);
    let root = Zeroizing::new(root);
    let payload = "bounded-real-file-clock-profile".repeat(128);
    for index in 0..64 {
        let response = request(
            &mut service,
            "POST",
            &format!("secret/data/clock-profile-{index:02}"),
            &root,
            json!({"data":{"ordinal":index,"payload":payload}}),
        );
        assert_eq!(response.status, 200);
    }
    let created = request(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["root"],"num_uses":0,"ttl":"1800s","no_default_policy":true,"no_parent":true}),
    );
    assert_eq!(created.status, 200);
    let activation = request(
        &mut service,
        "POST",
        "sys/internal/native-v6/activate",
        &root,
        json!({}),
    );
    assert_eq!(activation.status, 204);
    let source = service.state.as_ref().ok_or("actual native state")?;
    assert!(source.auth.has_token_api_precision_state());
    assert!(!source.engines.has_kubernetes_opaque_artifact_state());
    let source_auth = (*source.auth).clone();
    let before_floor = source_auth
        .terminal_token_clock_floor()
        .ok_or("original precise floor")?;
    let before_root = service.native_root.clone().ok_or("actual native root")?;
    assert_eq!(before_root.reader_floor.native_kv2_format, 2);
    let retained = service
        .durable
        .as_ref()
        .ok_or("actual durable owner")?
        .get("system", super::super::ACTIVE_SOURCE_ROOT_RESOURCE)?
        .ok_or("retained migration source")?;
    let observations = Arc::clone(&service.native_payload_observations);
    let payload_opens = observations.blocks_opened.load(Ordering::Relaxed);
    let mut last_floor = before_floor;
    for index in 0..32 {
        let sample = Scope::begin_enabled(true);
        let response = request(
            &mut service,
            "GET",
            &format!("secret/data/clock-profile-{index:02}"),
            &root,
            json!({"version":1}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert_eq!(response.body["data"]["data"]["ordinal"], index);
        assert!(response.body["data"]["data"]["payload"].as_str() == Some(payload.as_str()));
        let floor = service
            .state
            .as_ref()
            .ok_or("observed native state")?
            .auth
            .terminal_token_clock_floor()
            .ok_or("committed precise floor")?;
        assert!(
            floor > last_floor,
            "actual GET did not advance the durable floor"
        );
        last_floor = floor;
        ACTIVE.with(|active| -> TestResult {
            let slot = active.borrow();
            let observed = slot.as_ref().ok_or("actual File profile scope")?;
            assert!(observed.entered[Phase::Candidate as usize] > 0);
            assert!(observed.entered[Phase::RootPublication as usize] > 0);
            assert!(observed.entered[Phase::DurableReadback as usize] > 0);
            assert!(observed.entered[Phase::AuthGate as usize] > 0);
            assert!(observed.object_attempts > 0);
            assert_eq!(observed.object_attempts, observed.object_completions);
            Ok(())
        })?;
        sample.returned_ok();
    }
    assert!(observations.blocks_opened.load(Ordering::Relaxed) >= payload_opens + 32);
    let current = service.state.as_ref().ok_or("final native state")?;
    let mut expected_auth = source_auth;
    expected_auth.observe_token_api_time(AuthorityTime::Precise(last_floor))?;
    assert!(
        owner_store::serialize_owner(&current.auth)?.as_slice()
            == owner_store::serialize_owner(&expected_auth)?.as_slice()
    );
    let mut normalized = service.native_root.clone().ok_or("final native root")?;
    for (prior, owner) in before_root.owners.iter().zip(normalized.owners.iter_mut()) {
        if owner.domain == crate::state_record_root_v6::OwnerDomain::Auth {
            assert_eq!(prior.domain, owner.domain);
            *owner = prior.clone();
        }
    }
    assert!(
        normalized
            .encode()
            .map_err(|_| "normalized native root encoding failed")?
            .as_slice()
            == before_root
                .encode()
                .map_err(|_| "original native root encoding failed")?
                .as_slice()
    );
    let retained_after = service
        .durable
        .as_ref()
        .ok_or("final durable owner")?
        .get("system", super::super::ACTIVE_SOURCE_ROOT_RESOURCE)?
        .ok_or("retained migration source after GETs")?;
    assert!(retained.expose() == retained_after.expose());
    drop(service);

    let mut cold = directory.service()?;
    cold.configure_native_v6_candidate()?;
    let unsealed = request(
        &mut cold,
        "POST",
        "sys/unseal",
        "",
        json!({"key":key.as_str()}),
    );
    assert_eq!(unsealed.status, 200);
    assert_eq!(unsealed.body["sealed"], false);
    let cold_floor = cold
        .state
        .as_ref()
        .ok_or("actual cold native state")?
        .auth
        .terminal_token_clock_floor()
        .ok_or("cold precise floor")?;
    assert!(
        cold_floor >= last_floor,
        "cold reopen lost the committed observation floor"
    );
    let response = request(
        &mut cold,
        "GET",
        "secret/data/clock-profile-31",
        &root,
        json!({"version":1}),
    );
    assert_eq!(response.status, 200);
    assert!(response.body["data"]["data"]["payload"].as_str() == Some(payload.as_str()));
    Ok(())
}
