use super::tests::{Root, bootstrap, call};
use super::*;

// These auth format fixtures have no record-backed KV1 mounts. Decode their
// unchanged owner bytes as a legacy reader would, without retaining the v5
// runtime installed by current HTTP writes and masking the auth schema fence.
fn restore_legacy_engine_owner(state: &mut State) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !state.engines.has_record_kv1(),
        "legacy auth fixture cannot discard record-backed KV1 data"
    );
    let before = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture serialization")?;
    state.engines = serde_json::from_slice::<EngineState>(&before)?.into();
    assert!(state.engines.record_root().is_none());
    let after = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture reserialization")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "legacy engine owner bytes changed"
    );
    Ok(())
}

#[test]
fn approle_zero_token_limits_and_secret_issuance_each_require_schema_thirty_four()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let path = "auth/approle/role/schema";
    let positive =
        json!({"token_ttl":120,"token_max_ttl":600,"secret_id_ttl":0,"secret_id_num_uses":0});
    assert_eq!(
        call(&mut service, "POST", path, &admin, positive.clone()).status,
        204
    );
    let mut state = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 33;
    assert!(
        state.validate_format().is_ok(),
        "zero SecretID limits were already supported"
    );
    for body in [
        json!({"token_ttl":0,"token_max_ttl":600}),
        json!({"token_ttl":120,"token_max_ttl":0}),
    ] {
        assert_eq!(call(&mut service, "POST", path, &admin, body).status, 204);
        let mut state = service.state.clone().ok_or("state")?;
        restore_legacy_engine_owner(&mut state)?;
        state.schema = 33;
        assert_eq!(
            state.validate_format().err().ok_or("role fence")?.status,
            503
        );
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
    }
    assert_eq!(
        call(&mut service, "POST", path, &admin, positive).status,
        204
    );
    let mut state = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 33;
    assert!(state.validate_format().is_ok());
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("{path}/secret-id"),
            &admin,
            json!({})
        )
        .status,
        200
    );
    let mut state = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 33;
    assert_eq!(
        state
            .validate_format()
            .err()
            .ok_or("issuance fence")?
            .status,
        503
    );
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}
