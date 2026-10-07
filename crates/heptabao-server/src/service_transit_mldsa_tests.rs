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
    // The empty Transit mount is an ordinary, bounded historical writer input.
    super::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "legacy fixture commit")?;
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
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.engines.has_mldsa_state());
    let mut schema62 = state.clone();
    schema62.schema = 62;
    schema62
        .validate_format()
        .map_err(|_| "schema 62 ML-DSA validation")?;
    let mut future = state.clone();
    future.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
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
    let descriptor = call(
        &mut service,
        "GET",
        "mlfixture/keys/test",
        &admin,
        json!({}),
    );
    let public = STANDARD.decode(
        descriptor.body["data"]["keys"]["1"]["public_key"]
            .as_str()
            .ok_or("public")?,
    )?;
    let message = STANDARD.decode(&input)?;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut hash = sha3::Shake256::default();
    hash.update(&public);
    let mut tr = [0u8; 64];
    XofReader::read(&mut hash.finalize_xof(), &mut tr);
    let mut hash = sha3::Shake256::default();
    hash.update(&tr);
    hash.update(&[0, 0]);
    hash.update(&message);
    let mut mu = [0u8; 64];
    XofReader::read(&mut hash.finalize_xof(), &mut mu);
    let mu_signed = call(
        &mut service,
        "POST",
        "mlfixture/sign/test/mldsa-mu",
        &admin,
        json!({"input":STANDARD.encode(mu),"prehashed":true}),
    );
    assert_eq!(mu_signed.status, 200);
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
    let mu_verified = call(
        &mut service,
        "POST",
        "mlfixture/verify/test",
        &admin,
        json!({"input":input,"signature":mu_signed.body["data"]["signature"]}),
    );
    assert_eq!(mu_verified.status, 200);
    assert_eq!(mu_verified.body["data"]["valid"], true);
    let configured = call(
        &mut service,
        "POST",
        "mlfixture/keys/test/config",
        &admin,
        json!({"min_decryption_version":2}),
    );
    assert_eq!(configured.status, 200);
    assert_eq!(configured.body["data"]["type"], "mldsa-44");
    assert_eq!(configured.body["data"]["latest_version"], 2);
    assert_eq!(configured.body["data"]["min_decryption_version"], 2);
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

#[test]
fn asymmetric270_service_promotes_schema65_fences_disguised64_and_reopens_true_signatures()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/asymfixture",
            &admin,
            json!({"type":"transit"})
        )
        .status,
        204
    );
    let mut legacy = service.state.clone().ok_or("state")?;
    legacy.schema = 64;
    legacy
        .validate_format()
        .map_err(|_| "ordinary schema64 validation")?;
    // Create the old empty-mount input before introducing asymmetric key material.
    super::tests::commit_legacy_state_fixture(&mut service, &legacy)
        .map_err(|_| "schema64 fixture commit")?;
    service.state = Some(legacy);
    let input = STANDARD.encode(b"synthetic durable asymmetric signature");
    let mut signatures = Vec::new();
    for kind in [
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("asymfixture/keys/{kind}"),
                &admin,
                json!({"type":kind})
            )
            .status,
            200
        );
        let signed = call(
            &mut service,
            "POST",
            &format!("asymfixture/sign/{kind}"),
            &admin,
            json!({"input":input}),
        );
        assert_eq!(signed.status, 200);
        signatures.push((kind, signed.body["data"]["signature"].clone()));
    }
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, 65);
    assert!(state.engines.has_asymmetric_state());
    let mut disguised = state.clone();
    disguised.schema = 64;
    assert_eq!(
        disguised
            .validate_format()
            .err()
            .ok_or("missing schema fence")?
            .status,
        503
    );
    let mut future = state.clone();
    future.schema = MAX_SUPPORTED_STATE_SCHEMA + 1;
    assert_eq!(
        future
            .validate_format()
            .err()
            .ok_or("missing future schema fence")?
            .status,
        503
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
    for (kind, signature) in signatures {
        let verified = call(
            &mut service,
            "POST",
            &format!("asymfixture/verify/{kind}"),
            &admin,
            json!({"input":input,"signature":signature}),
        );
        assert_eq!(verified.status, 200);
        assert_eq!(verified.body["data"]["valid"], true);
    }
    Ok(())
}
