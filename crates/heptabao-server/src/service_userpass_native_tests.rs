use super::tests::{Root, bootstrap, call};
use super::*;

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
        state.schema = 34;
        assert!(state.validate_format().is_ok());
        assert_eq!(call(&mut service, "POST", path, &admin, native).status, 204);
        let mut state = service.state.clone().ok_or("state")?;
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
    state.schema = 34;
    assert_eq!(
        state.validate_format().err().ok_or("issuer fence")?.status,
        503
    );
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}
