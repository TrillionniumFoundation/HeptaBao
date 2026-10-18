//! Native forwarding owner equivalence on real Service-published roots.
//! The positive paths use the three-node production TLS/Service pipeline.
//! Counterfeit root copies below test a hash boundary only: they are never
//! published, materialized, admitted as an Actor, or made into a peer receipt.
use super::*;
use crate::service::native_v6_ha_pipeline_tests::Pipeline;
use crate::state_record_root::StateIdentity;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Observed {
    root: RecordStateRootV6,
    identity: StateIdentity,
    full: [u8; 32],
    non_auth: [u8; 32],
    auth: [u8; 32],
    floor: Option<crate::auth::Timestamp>,
}

fn observed(pipeline: &Pipeline, leader: usize) -> TestResult<Observed> {
    pipeline.with_service(leader, |service| {
        let state = service
            .state
            .as_ref()
            .ok_or("native projection state absent")?
            .protected_state()
            .map_err(|_| "native projection protected owner unavailable")?;
        let root = service
            .native_root
            .as_ref()
            .ok_or("native projection selected root absent")?;
        assert!(service.record_root.is_none());
        Ok(Observed {
            root: root.clone(),
            identity: service
                .current_state_identity()
                .map_err(|_| "native projection current identity")?,
            full: service
                .forward_owner_projection()
                .map_err(|_| "native full owner projection")?,
            non_auth: service
                .forward_non_auth_owner_projection()
                .map_err(|_| "native non-Auth owner projection")?,
            auth: state.auth.forward_owner_projection_digest()?,
            floor: state.auth.terminal_token_clock_floor(),
        })
    })
}

fn call(
    pipeline: &Pipeline,
    leader: usize,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    status: u16,
) -> TestResult<Response> {
    let response = pipeline.call(leader, method, path, token, body)?;
    if response.status != status {
        // The pipeline reports only the fixed path/status/generic errors.
        return Err(format!(
            "native forwarding projection path={path}: expected HTTP {status}, observed {}",
            response.status
        )
        .into());
    }
    Ok(response)
}

fn projections(root: &RecordStateRootV6, auth: [u8; 32]) -> TestResult<([u8; 32], [u8; 32])> {
    Ok((
        Service::forward_native_owner_projection(root, Some(auth))
            .map_err(|_| "private full projection rejected")?,
        Service::forward_native_owner_projection(root, None)
            .map_err(|_| "private non-Auth projection rejected")?,
    ))
}

#[test]
fn native_forward_projection_real_precise_clock_auth_and_kv2_owner_boundaries() -> TestResult {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    call(
        &pipeline,
        leader,
        "POST",
        "sys/internal/native-v6/activate",
        pipeline.admin(),
        json!({}),
        204,
    )?;
    // This must be a real precise Token API issuance through native HA and its
    // mandatory terminal audit. A stale pre-floor HA proof must not be hidden
    // by manufacturing a credential, suppressing the floor or retrying here.
    let mut issued = call(
        &pipeline,
        leader,
        "POST",
        "auth/token/create",
        pipeline.admin(),
        json!({"policies":["default"],"ttl":"10m"}),
        200,
    )?;
    let Value::String(raw) = issued
        .body
        .pointer_mut("/auth/client_token")
        .ok_or("native projection precise token absent")?
        .take()
    else {
        return Err("native projection precise token type".into());
    };
    let token = Zeroizing::new(raw);
    assert!(!token.is_empty());
    erase_json(&mut issued.body);
    let before = observed(&pipeline, leader)?;
    assert!(before.floor.is_some());
    assert_ne!(before.full, before.non_auth, "the two scopes are distinct");

    let lookup = call(
        &pipeline,
        leader,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
        200,
    )?;
    assert!(lookup.body["data"]["id"].as_str() == Some(token.as_str()));
    let clock_only = observed(&pipeline, leader)?;
    assert!(clock_only.floor > before.floor);
    assert_ne!(clock_only.identity, before.identity);
    assert_eq!(clock_only.auth, before.auth);
    assert_eq!(clock_only.full, before.full);
    assert_eq!(clock_only.non_auth, before.non_auth);

    call(
        &pipeline,
        leader,
        "PUT",
        "sys/policies/acl/native-forward-projection",
        pipeline.admin(),
        json!({"policy":"path \"secret/data/pipeline/projection\" { capabilities = [\"read\"] }"}),
        204,
    )?;
    let auth_changed = observed(&pipeline, leader)?;
    assert_ne!(auth_changed.auth, clock_only.auth);
    assert_ne!(auth_changed.full, clock_only.full);
    assert_eq!(auth_changed.non_auth, clock_only.non_auth);

    call(
        &pipeline,
        leader,
        "POST",
        "secret/data/pipeline/projection",
        pipeline.admin(),
        json!({"options":{"cas":0},"data":{"value":"actual-native-KV2-owner"}}),
        200,
    )?;
    let kv_changed = observed(&pipeline, leader)?;
    assert_ne!(kv_changed.full, auth_changed.full);
    assert_ne!(kv_changed.non_auth, auth_changed.non_auth);
    assert_ne!(kv_changed.identity, auth_changed.identity);

    // These are authority-domain faults against one actual selected root, not
    // a duplicated list of implementation fields. All structurally valid
    // counterfeits must lose both equivalences. No live Service is modified.
    let expected = (kv_changed.full, kv_changed.non_auth);
    let mut foreign_owner = kv_changed.root.clone();
    foreign_owner
        .owners
        .iter_mut()
        .find(|role| role.domain == OwnerDomain::Namespaces)
        .ok_or("native namespace owner absent")?
        .owner
        .digest[0] ^= 1;
    let mut foreign_key = kv_changed.root.clone();
    foreign_key.object_address_key.0[0] ^= 1;
    for (domain, counterfeit) in [
        ("non-Auth ownership transplant", foreign_owner),
        ("object address-key transplant", foreign_key),
    ] {
        counterfeit.validate().map_err(|_| {
            format!("native projection fault must remain structurally valid: {domain}")
        })?;
        let changed = projections(&counterfeit, kv_changed.auth)?;
        assert_ne!(changed.0, expected.0, "{domain}");
        assert_ne!(changed.1, expected.1, "{domain}");
    }

    // Paged native graphs cannot acquire an older reader's interpretation.
    let mut unreadable = kv_changed.root.clone();
    assert_eq!(unreadable.reader_floor.native_kv2_format, 2);
    unreadable.reader_floor.native_kv2_format = 1;
    assert!(Service::forward_native_owner_projection(&unreadable, Some(kv_changed.auth)).is_err());
    assert!(Service::forward_native_owner_projection(&unreadable, None).is_err());

    // Equal owners and graph addresses still cannot hide changed number/JSON
    // semantics. Use two valid private compatibility roots with the same
    // supported schema, so the inequality cannot be explained by that field.
    let mut compatible = kv_changed.root.clone();
    compatible.state_schema = compatible
        .state_schema
        .max(crate::service::GLOBAL_LOSSLESS_JSON_STATE_SCHEMA);
    compatible.global_lossless_json_format = None;
    let old_semantics = projections(&compatible, kv_changed.auth)?;
    compatible.global_lossless_json_format = Some(1);
    let new_semantics = projections(&compatible, kv_changed.auth)?;
    assert_ne!(old_semantics.0, new_semantics.0);
    assert_ne!(old_semantics.1, new_semantics.1);

    // Precise renewal and its final empty revocation use the same original
    // Actor and pre-audit proof ordering as issuance/lookup. The observation
    // floor is an actual published monotonic successor, never a fresh clock.
    let before_renew = observed(&pipeline, leader)?;
    let renewed = call(
        &pipeline,
        leader,
        "POST",
        "auth/token/renew-self",
        &token,
        json!({"increment":"10m"}),
        200,
    )?;
    assert!(renewed.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    let after_renew = observed(&pipeline, leader)?;
    assert!(after_renew.floor > before_renew.floor);
    call(
        &pipeline,
        leader,
        "POST",
        "auth/token/revoke-self",
        &token,
        json!({}),
        204,
    )?;
    assert!(observed(&pipeline, leader)?.floor > after_renew.floor);
    let denied = call(
        &pipeline,
        leader,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
        403,
    )?;
    assert!(denied.body.get("auth").is_none() && denied.body.get("data").is_none());
    Ok(())
}
