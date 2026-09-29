//! Real Linux durable owner lifecycle, using disposable synthetic state only.
use super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::STANDARD;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn mldsa270_service_promotes_only_on_write_fences_legacy_and_reopens_signatures() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/mlfixture",
            &admin,
            json!({"type":"transit"})
        )
        .status,
        204
    );
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 61;
    legacy.validate_format().map_err(|_| "legacy validation")?;
    service.commit_state(&legacy).map_err(|_| "legacy commit")?;
    service.state = Some(legacy);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "sys/health", "", json!({})).status,
        200
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 61);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "mlfixture/keys/test",
            &admin,
            json!({"type":"mldsa-44"})
        )
        .status,
        200
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, 62);
    assert!(state.engines.has_mldsa_state());
    let mut future = state.clone();
    future.schema = CURRENT_STATE_SCHEMA + 1;
    assert!(future.validate_format().is_err());
    let mut disguised = state.clone();
    disguised.schema = 61;
    let denied = disguised
        .validate_format()
        .err()
        .ok_or("missing reader fence")?;
    assert_eq!(
        denied.body["errors"][0],
        "Transit ML-DSA keys require schema 62"
    );
    let input = STANDARD.encode(b"synthetic durable signature");
    let signed = call(
        &mut service,
        "POST",
        "mlfixture/sign/test",
        &admin,
        json!({"input":input}),
    );
    assert_eq!(signed.status, 200);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "mlfixture/keys/test/rotate",
            &admin,
            json!({})
        )
        .status,
        200
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    let verified = call(
        &mut service,
        "POST",
        "mlfixture/verify/test",
        &admin,
        json!({"input":input,"signature":signed.body["data"]["signature"]}),
    );
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["data"]["valid"], true);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "mlfixture/keys/test/config",
            &admin,
            json!({"min_decryption_version":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "mlfixture/verify/test",
            &admin,
            json!({"input":input,"signature":signed.body["data"]["signature"]})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "mlfixture/sign/test",
            "invalid",
            json!({"input":input})
        )
        .status,
        403
    );
    Ok(())
}
