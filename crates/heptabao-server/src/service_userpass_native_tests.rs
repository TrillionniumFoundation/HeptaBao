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
    // This format fixture models schema34 credentials, predating the
    // comparison-semantics marker. Do not let schema38 mask the schema35 gate.
    let mut auth = serde_json::to_value(&state.auth)?;
    for users in auth["users"].as_object_mut().ok_or("users")?.values_mut() {
        for user in users.as_object_mut().ok_or("user map")?.values_mut() {
            user.as_object_mut()
                .ok_or("user")?
                .remove("password_semantics");
            user.as_object_mut()
                .ok_or("user")?
                .remove("token_policies_configured");
            user.as_object_mut()
                .ok_or("user")?
                .remove("token_no_default_policy");
        }
    }
    for mounts in auth["mounted_users"]
        .as_object_mut()
        .ok_or("mounts")?
        .values_mut()
    {
        for users in mounts.as_object_mut().ok_or("mount map")?.values_mut() {
            for user in users.as_object_mut().ok_or("user map")?.values_mut() {
                user.as_object_mut()
                    .ok_or("user")?
                    .remove("password_semantics");
                user.as_object_mut()
                    .ok_or("user")?
                    .remove("token_policies_configured");
                user.as_object_mut()
                    .ok_or("user")?
                    .remove("token_no_default_policy");
            }
        }
    }
    state.auth = serde_json::from_value::<AuthState>(auth)?.into();
    Ok(())
}

#[test]
fn userpass_native_limits_policies_and_issuer_each_require_schema_thirty_five()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    let path = "auth/userpass/users/schema";
    let legacy = json!({"password":"synthetic-schema-password", "token_ttl":120,
        "token_max_ttl":600, "token_policies":["default"],
        "token_period":0,"token_explicit_max_ttl":0});
    for native in [
        json!({"token_ttl":0}),
        json!({"token_max_ttl":0}),
        json!({"token_period":120}),
        json!({"token_explicit_max_ttl":600}),
        json!({"token_policies":[]}),
    ] {
        assert_eq!(
            call(&mut service, "POST", path, &admin, legacy.clone()).status,
            204
        );
        let mut state = service.state.clone().ok_or("state")?;
        restore_legacy_engine_owner(&mut state)?;
        state.schema = 34;
        assert!(state.validate_format().is_ok());
        assert_eq!(call(&mut service, "POST", path, &admin, native).status, 204);
        let mut state = service.state.clone().ok_or("state")?;
        restore_legacy_engine_owner(&mut state)?;
        state.schema = 34;
        assert_eq!(state.validate_format().err().ok_or("fence")?.status, 503);
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
    }
    assert_eq!(call(&mut service, "POST", path, &admin, legacy).status, 204);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/userpass/login/schema",
            "",
            json!({"password":"synthetic-schema-password"})
        )
        .status,
        200
    );
    let mut state = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 34;
    assert_eq!(
        state.validate_format().err().ok_or("issuer fence")?.status,
        503
    );
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}
