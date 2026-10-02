use super::*;
const PASSWORD: &str = "synthetic no default credential";
fn write(s: &mut AuthState, r: &Principal, b: Value) -> Result<AuthResponse, AuthError> {
    s.handle(Some(r), "", "POST", "auth/userpass/users/nd", &b, 100)?
        .ok_or_else(denied)
}
fn login(s: &mut AuthState) -> (String, AuthResponse) {
    let a = s
        .handle(
            None,
            "",
            "POST",
            "auth/userpass/login/nd",
            &json!({"password":PASSWORD}),
            100,
        )
        .unwrap()
        .unwrap();
    (
        a.body["auth"]["client_token"].as_str().unwrap().to_owned(),
        a,
    )
}
fn renew(s: &mut AuthState, r: &Principal, t: &str) -> Result<AuthResponse, AuthError> {
    s.handle(
        Some(r),
        "",
        "POST",
        "auth/token/renew",
        &json!({"token":t,"increment":120}),
        101,
    )?
    .ok_or_else(denied)
}

#[test]
fn userpass_nil_policy_requires_explicit_empty_for_empty_token_renewal() {
    let (mut s, _, r) = setup();
    write(
        &mut s,
        &r,
        json!({"password":PASSWORD,"token_no_default_policy":true}),
    )
    .unwrap();
    assert_eq!(s.users[""]["nd"].token_policies_configured, Some(false));
    let (t, a) = login(&mut s);
    assert_eq!(a.body["auth"]["policies"], json!([]));
    assert!(a.body["auth"].get("token_policies").is_none());
    let before = provider_renewal::state_revision(&s).unwrap();
    assert_eq!(renew(&mut s, &r, &t).err().unwrap().status, 500);
    assert_eq!(provider_renewal::state_revision(&s).unwrap(), before);
    let actor = s.authenticate(&t, 101).unwrap();
    assert_eq!(
        s.handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            101
        )
        .err()
        .unwrap()
        .status,
        403
    );
    for b in [
        json!({"token_policies":[]}),
        json!({"token_policies":null}),
        json!({"policies":[]}),
    ] {
        write(&mut s, &r, b).unwrap();
        assert_eq!(s.users[""]["nd"].token_policies_configured, Some(true));
        let a = renew(&mut s, &r, &t).unwrap();
        assert_eq!(a.status, 200);
        assert!(a.body["auth"].get("token_policies").is_none());
    }
}
#[test]
fn userpass_no_default_toggles_future_issuance_but_preserves_issued_policy_and_explicit_default() {
    let (mut s, _, r) = setup();
    write(
        &mut s,
        &r,
        json!({"password":PASSWORD,"token_no_default_policy":true,"token_policies":["named"]}),
    )
    .unwrap();
    let (t, _) = login(&mut s);
    for b in [
        json!({"token_ttl":60}),
        json!({"token_no_default_policy":false}),
        json!({"token_no_default_policy":true}),
        json!({"token_no_default_policy":null}),
    ] {
        write(&mut s, &r, b).unwrap();
        assert_eq!(
            renew(&mut s, &r, &t).unwrap().body["auth"]["token_policies"],
            json!(["named"])
        );
    }
    assert!(!s.users[""]["nd"].token_no_default_policy);
    let (_, a) = login(&mut s);
    assert_eq!(
        a.body["auth"]["token_policies"],
        json!(["default", "named"])
    );
    write(
        &mut s,
        &r,
        json!({"token_no_default_policy":true,"token_policies":["default","named"]}),
    )
    .unwrap();
    let (_, a) = login(&mut s);
    assert_eq!(
        a.body["auth"]["token_policies"],
        json!(["default", "named"])
    );
    write(&mut s, &r, json!({"token_policies":["other"]})).unwrap();
    let before = provider_renewal::state_revision(&s).unwrap();
    assert_eq!(renew(&mut s, &r, &t).err().unwrap().status, 500);
    assert_eq!(provider_renewal::state_revision(&s).unwrap(), before);
    write(&mut s, &r, json!({"token_policies":["named"]})).unwrap();
    assert_eq!(renew(&mut s, &r, &t).unwrap().status, 200);
}
#[test]
fn userpass_legacy_normalized_empty_is_not_guessed_nil_and_invalid_update_is_atomic() {
    let (mut s, _, r) = setup();
    write(&mut s, &r, json!({"password":PASSWORD})).unwrap();
    // Unit format fixture only: actual previous-binary upgrade is separate QA.
    s.users
        .get_mut("")
        .unwrap()
        .get_mut("nd")
        .unwrap()
        .token_policies_configured = None;
    let encoded = serde_json::to_vec(&s).unwrap();
    let mut s: AuthState = serde_json::from_slice(&encoded).unwrap();
    assert!(!s.has_userpass_no_default_policy());
    login(&mut s);
    assert_eq!(s.users[""]["nd"].token_policies_configured, None);
    write(&mut s, &r, json!({"token_no_default_policy":true})).unwrap();
    assert_eq!(s.users[""]["nd"].token_policies_configured, None);
    let (t, _) = login(&mut s);
    assert_eq!(renew(&mut s, &r, &t).unwrap().status, 200);
    let before = provider_renewal::state_revision(&s).unwrap();
    assert_eq!(
        write(
            &mut s,
            &r,
            json!({"password":"new value","token_no_default_policy":{}})
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&s).unwrap(), before);
    let mut invalid = s.clone();
    invalid
        .users
        .get_mut("")
        .unwrap()
        .get_mut("nd")
        .unwrap()
        .policies
        .insert("named".into());
    invalid
        .users
        .get_mut("")
        .unwrap()
        .get_mut("nd")
        .unwrap()
        .token_policies_configured = Some(false);
    assert!(invalid.validate_userpass_no_default_policy().is_err());
    mount_auth(&mut s, &r, "", "directory", "ldap");
    assert_eq!(
        s.handle(
            Some(&r),
            "",
            "POST",
            "auth/directory/users/nd",
            &json!({"password":PASSWORD,"token_no_default_policy":false}),
            100
        )
        .err()
        .unwrap()
        .status,
        400
    );
}
