use super::tests::{Root, bootstrap, call};
use super::*;

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
