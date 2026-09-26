use super::*;
const PASSWORD: &str = "synthetic source credential";
fn write(state: &mut AuthState, root: &Principal, body: Value) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(root),
            "",
            "POST",
            "auth/userpass/users/source",
            &body,
            100,
        )?
        .ok_or_else(denied)
}
fn login(
    state: &mut AuthState,
    password: &str,
    peer: Option<&str>,
) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/userpass/login/source",
            &json!({"password":password}),
            100,
            None,
            peer.map(|p| p.parse().unwrap()),
        )?
        .ok_or_else(denied)
}
fn get(state: &AuthState) -> &User {
    &state.users[""]["source"]
}

#[test]
fn userpass_cidr_alias_presence_partial_null_and_atomic_errors() {
    let (mut state, _, root) = setup();
    write(
        &mut state,
        &root,
        json!({"password":PASSWORD,"bound_cidrs":["127.0.0.1/32"]}),
    )
    .unwrap();
    assert_eq!(get(&state).token_bound_cidrs, ["127.0.0.1"]);
    assert_eq!(get(&state).bound_cidrs, ["127.0.0.1"]);
    write(&mut state, &root, json!({"token_ttl":60})).unwrap();
    assert_eq!(get(&state).bound_cidrs, ["127.0.0.1"]);
    write(
        &mut state,
        &root,
        json!({"bound_cidrs":["192.0.2.1"],"token_bound_cidrs":"::ffff:127.0.0.2/120"}),
    )
    .unwrap();
    assert_eq!(get(&state).token_bound_cidrs, ["127.0.0.2/24"]);
    assert_eq!(get(&state).bound_cidrs, get(&state).token_bound_cidrs);
    write(
        &mut state,
        &root,
        json!({"bound_cidrs":["192.0.2.1"],"token_bound_cidrs":null}),
    )
    .unwrap();
    assert!(get(&state).token_bound_cidrs.is_empty());
    assert!(get(&state).bound_cidrs.is_empty());
    write(&mut state, &root, json!({"bound_cidrs":["127.0.0.1"]})).unwrap();
    write(&mut state, &root, json!({"token_bound_cidrs":["::1/128"]})).unwrap();
    assert!(get(&state).bound_cidrs.is_empty());
    assert_eq!(get(&state).token_bound_cidrs, ["::1"]);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        write(
            &mut state,
            &root,
            json!({"password":"replacement","token_bound_cidrs":{"ip":"127.0.0.1"}})
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    assert!(login(&mut state, PASSWORD, Some("::1")).is_ok());
    assert_eq!(
        login(&mut state, "replacement", Some("::1"))
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn userpass_password_precedes_source_check_and_denial_is_not_a_mutation() {
    let (mut state, _, root) = setup();
    write(
        &mut state,
        &root,
        json!({"password":PASSWORD,"token_bound_cidrs":["127.0.0.1"]}),
    )
    .unwrap();
    for (password, peer, status) in [
        (PASSWORD, None, 403),
        (PASSWORD, Some("127.0.0.2"), 403),
        ("wrong", Some("127.0.0.2"), 400),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            login(&mut state, password, peer).err().unwrap().status,
            status
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    let response = login(&mut state, PASSWORD, Some("::ffff:127.0.0.1")).unwrap();
    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    assert_eq!(state.tokens[&hash(raw)].bound_cidrs, ["127.0.0.1"]);
    assert_eq!(
        state
            .authenticate_from(raw, 100, Some("127.0.0.2".parse().unwrap()))
            .err()
            .unwrap()
            .status,
        403
    );
}

#[test]
fn userpass_issued_cidr_survives_config_clear_and_root_manages_target_without_source_rebinding() {
    let (mut state, raw_root, root) = setup();
    write(&mut state,&root,json!({"password":PASSWORD,"token_bound_cidrs":["127.0.0.1"],"token_ttl":120,"token_max_ttl":600})).unwrap();
    let response = login(&mut state, PASSWORD, Some("127.0.0.1")).unwrap();
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let accessor = response.body["auth"]["accessor"]
        .as_str()
        .unwrap()
        .to_owned();
    write(&mut state, &root, json!({"token_bound_cidrs":[]})).unwrap();
    assert!(state.has_userpass_token_bound_cidrs());
    for (route, body) in [
        ("renew", json!({"token":raw,"increment":180})),
        (
            "renew-accessor",
            json!({"accessor":accessor,"increment":180}),
        ),
    ] {
        let actor = state
            .authenticate_from(&raw_root, 101, Some("127.0.0.2".parse().unwrap()))
            .unwrap();
        assert_eq!(
            state
                .handle_with_connection(
                    Some(&actor),
                    "",
                    "POST",
                    &format!("auth/token/{route}"),
                    &body,
                    101,
                    None,
                    Some("127.0.0.2".parse().unwrap())
                )
                .unwrap()
                .unwrap()
                .status,
            200
        );
    }
    assert_eq!(state.tokens[&hash(&raw)].bound_cidrs, ["127.0.0.1"]);
    let data = serde_json::to_vec(&state).unwrap();
    let mut reopened: AuthState = serde_json::from_slice(&data).unwrap();
    reopened.validate_userpass_token_bound_cidrs().unwrap();
    assert_eq!(
        reopened
            .authenticate_from(&raw, 101, Some("127.0.0.2".parse().unwrap()))
            .err()
            .unwrap()
            .status,
        403
    );
    assert!(login(&mut reopened, PASSWORD, Some("127.0.0.2")).is_ok());
}

#[test]
fn userpass_cidr_format_rejects_ambiguous_alias_and_bounded_ldap_owner() {
    let (mut state, _, root) = setup();
    write(
        &mut state,
        &root,
        json!({"password":PASSWORD,"token_bound_cidrs":["127.0.0.1"]}),
    )
    .unwrap();
    let mut wire = serde_json::to_value(&state).unwrap();
    wire["users"][""]["source"]["bound_cidrs"] = json!(["127.0.0.2"]);
    let invalid: AuthState = serde_json::from_value(wire).unwrap();
    assert!(invalid.validate_userpass_token_bound_cidrs().is_err());
    mount_auth(&mut state, &root, "", "directory", "ldap");
    assert_eq!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/directory/users/user",
                &json!({"password":PASSWORD,"token_bound_cidrs":[]}),
                100
            )
            .err()
            .unwrap()
            .status,
        400
    );
}
