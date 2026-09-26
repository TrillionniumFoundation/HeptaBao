#![allow(clippy::unwrap_used)]
use super::*;
fn setup() -> (AuthState, Principal) {
    let (state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate_read_only(&raw, 100).unwrap().unwrap();
    (state, root)
}
fn call(
    state: &mut AuthState,
    actor: Option<&Principal>,
    method: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(actor, "", method, path, &body, 100)?
        .ok_or_else(denied)
}
fn role(state: &mut AuthState, root: &Principal, body: Value) -> Result<AuthResponse, AuthError> {
    call(state, Some(root), "POST", "auth/approle/role/source", body)
}
fn field(
    state: &mut AuthState,
    root: &Principal,
    method: &str,
    legacy: bool,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    let suffix = if legacy {
        "bound-cidr-list"
    } else {
        "secret-id-bound-cidrs"
    };
    call(
        state,
        Some(root),
        method,
        &format!("auth/approle/role/source/{suffix}"),
        body,
    )
}
fn stored(state: &AuthState) -> &Role {
    &state.roles[""]["source"]
}
fn bytes(state: &AuthState) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(state).unwrap())
}
#[test]
fn approle_secret_source_presence_and_deprecated_alias_do_not_collapse_null() {
    let (mut state, root) = setup();
    role(&mut state, &root, json!({})).unwrap();
    let before = bytes(&state);
    assert!(!state.has_approle_secret_bound_cidrs());
    assert_eq!(
        field(&mut state, &root, "GET", false, json!({}))
            .unwrap()
            .body["data"]["secret_id_bound_cidrs"],
        Value::Null
    );
    let restored: AuthState = serde_json::from_slice(&before).unwrap();
    assert!(before.as_slice() == bytes(&restored).as_slice());
    assert!(before.as_slice() == bytes(&state).as_slice());
    role(
        &mut state,
        &root,
        json!({"bound_cidr_list":"127.0.0.1/32, ::1/128"}),
    )
    .unwrap();
    assert_eq!(
        stored(&state).secret_id_bound_cidrs,
        Some(vec!["127.0.0.1/32".into(), "::1/128".into()])
    );
    let legacy = field(&mut state, &root, "GET", true, json!({})).unwrap();
    assert_eq!(legacy.body["data"]["bound_cidr_list"], Value::Null);
    assert_eq!(
        legacy.body["warnings"],
        json!([
            "The \"bound_cidr_list\" field is deprecated and will be removed. Please use \"secret_id_bound_cidrs\" instead."
        ])
    );
    let before = bytes(&state);
    field(&mut state, &root, "DELETE", true, json!({})).unwrap();
    field(
        &mut state,
        &root,
        "POST",
        false,
        json!({"bound_cidr_list":["10.0.0.0/8"],"token_ttl":1}),
    )
    .unwrap();
    field(
        &mut state,
        &root,
        "POST",
        true,
        json!({"secret_id_bound_cidrs":["10.0.0.0/8"]}),
    )
    .unwrap();
    assert!(before.as_slice() == bytes(&state).as_slice());
    for empty in [Value::Null, json!([]), json!("")] {
        role(
            &mut state,
            &root,
            json!({"secret_id_bound_cidrs":empty,"bound_cidr_list":["10.0.0.0/8"]}),
        )
        .unwrap();
        assert_eq!(stored(&state).secret_id_bound_cidrs, Some(Vec::new()));
        assert!(state.has_approle_secret_bound_cidrs());
        let before = bytes(&state);
        assert_eq!(
            field(
                &mut state,
                &root,
                "POST",
                false,
                json!({"secret_id_bound_cidrs":empty})
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert!(before.as_slice() == bytes(&state).as_slice());
    }
    field(
        &mut state,
        &root,
        "POST",
        true,
        json!({"bound_cidr_list":["127.0.0.99/24"]}),
    )
    .unwrap();
    assert_eq!(
        stored(&state).secret_id_bound_cidrs,
        Some(vec!["127.0.0.99/24".into()])
    );
    field(&mut state, &root, "DELETE", false, json!({})).unwrap();
    assert!(stored(&state).secret_id_bound_cidrs.is_none());
}
#[test]
fn approle_secret_source_invalid_fields_constraints_and_missing_role_are_atomic() {
    let (mut state, root) = setup();
    let path = "auth/approle/role/source/secret-id-bound-cidrs";
    assert_eq!(
        call(&mut state, None, "GET", path, json!({}))
            .err()
            .unwrap()
            .status,
        403
    );
    let missing = field(&mut state, &root, "GET", false, json!({})).unwrap();
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, json!({"errors":[]}));
    assert_eq!(
        field(&mut state, &root, "POST", false, json!({}))
            .err()
            .unwrap()
            .status,
        404
    );
    assert_eq!(
        field(&mut state, &root, "DELETE", false, json!({}))
            .unwrap()
            .status,
        204
    );
    role(
        &mut state,
        &root,
        json!({"bind_secret_id":false,"secret_id_bound_cidrs":["127.0.0.1/32"]}),
    )
    .unwrap();
    let before = bytes(&state);
    for invalid in ["127.0.0.1", "127.0.0.1/33", "127.0.0.1:80"] {
        assert_eq!(
            role(
                &mut state,
                &root,
                json!({"secret_id_bound_cidrs":[invalid],"token_ttl":7})
            )
            .err()
            .unwrap()
            .status,
            500
        );
        assert_eq!(
            field(
                &mut state,
                &root,
                "POST",
                false,
                json!({"secret_id_bound_cidrs":[invalid]})
            )
            .err()
            .unwrap()
            .status,
            400
        );
    }
    assert_eq!(
        role(&mut state, &root, json!({"secret_id_bound_cidrs":{}}))
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(
        role(&mut state, &root, json!({"secret_id_bound_cidrs":[]}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        field(&mut state, &root, "DELETE", false, json!({}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        call(
            &mut state,
            Some(&root),
            "POST",
            "auth/approle/role/source/secret-id",
            json!({})
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert!(before.as_slice() == bytes(&state).as_slice());
    role(&mut state, &root, json!({"bind_secret_id":true})).unwrap();
    field(&mut state, &root, "DELETE", false, json!({})).unwrap();
}
#[test]
fn approle_secret_source_numeric_networks_match_real_peer_and_fail_closed_without_it() {
    let (mut state, root) = setup();
    role(&mut state, &root, json!({})).unwrap();
    for (network, allowed, denied_peer) in [
        ("127.0.0.99/24", "127.0.0.1", "127.0.1.1"),
        ("127.0.0.1/32", "::ffff:127.0.0.1", "::1"),
        ("::ffff:127.0.0.1/128", "127.0.0.1", "127.0.0.2"),
        ("2001:db8::123/64", "2001:db8::456", "2001:db9::1"),
        ("::/0", "2001:db8::1", "127.0.0.1"),
        ("::ffff:127.0.0.1/95", "::fffe:0:1", "127.0.0.1"),
    ] {
        role(
            &mut state,
            &root,
            json!({"secret_id_bound_cidrs":[network]}),
        )
        .unwrap();
        assert!(
            approle_secret_cidrs::check(stored(&state), Some(allowed.parse().unwrap())).is_ok()
        );
        assert_eq!(
            approle_secret_cidrs::check(stored(&state), Some(denied_peer.parse().unwrap()))
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            approle_secret_cidrs::check(stored(&state), None)
                .err()
                .unwrap()
                .status,
            500
        );
    }
    role(&mut state, &root, json!({"secret_id_bound_cidrs":[]})).unwrap();
    assert!(approle_secret_cidrs::check(stored(&state), None).is_ok());
    let mut restored: AuthState = serde_json::from_slice(&bytes(&state)).unwrap();
    restored.validate_approle_token_bound_cidrs().unwrap();
    restored
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("source")
        .unwrap()
        .secret_id_bound_cidrs = Some(vec!["127.0.0.1".into()]);
    assert!(restored.validate_approle_token_bound_cidrs().is_err());
}
#[test]
fn approle_source_denial_yields_only_checked_affine_consumption_without_installing_auth_candidate()
{
    let (mut state, root) = setup();
    role(
        &mut state,
        &root,
        json!({"secret_id_bound_cidrs":["127.0.0.1/32"],"secret_id_num_uses":2}),
    )
    .unwrap();
    let sid = call(
        &mut state,
        Some(&root),
        "POST",
        "auth/approle/role/source/secret-id",
        json!({}),
    )
    .unwrap();
    let body = json!({"role_id":stored(&state).role_id,"secret_id":sid.body["data"]["secret_id"]});
    let before = bytes(&state);
    let mut rejected = state
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/approle/login",
            &body,
            100,
            None,
            Some("127.0.0.2".parse().unwrap()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(rejected.status, 400);
    assert!(!rejected.mutated);
    assert!(rejected.login_identity.is_none());
    assert!(rejected.body.get("auth").is_none());
    assert!(before.as_slice() == bytes(&state).as_slice());
    let mut stale = state.clone();
    let mut other = stale
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/approle/login",
            &body,
            100,
            None,
            Some("127.0.0.2".parse().unwrap()),
        )
        .unwrap()
        .unwrap();
    rejected
        .approle_secret_consumption
        .take()
        .unwrap()
        .apply(&mut state)
        .unwrap();
    assert_eq!(
        stored(&state)
            .secret_ids
            .values()
            .next()
            .unwrap()
            .uses_remaining,
        Some(1)
    );
    let consumed = bytes(&state);
    assert_eq!(
        other
            .approle_secret_consumption
            .take()
            .unwrap()
            .apply(&mut state)
            .err()
            .unwrap()
            .status,
        409
    );
    assert!(consumed.as_slice() == bytes(&state).as_slice());
}

#[test]
fn approle_role_id_only_source_bound_login_and_existing_token_renewal_are_independent() {
    for kind in ["service", "batch"] {
        let (mut state, root) = setup();
        role(&mut state,&root,json!({"bind_secret_id":false,"secret_id_bound_cidrs":["127.0.0.1/32"],"token_type":kind})).unwrap();
        let body = json!({"role_id":stored(&state).role_id});
        let before = bytes(&state);
        let denied = state
            .handle_with_connection(
                None,
                "",
                "POST",
                "auth/approle/login",
                &body,
                100,
                None,
                Some("127.0.0.2".parse().unwrap()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(denied.status, 400);
        assert!(denied.approle_secret_consumption.is_none());
        assert!(before.as_slice() == bytes(&state).as_slice());
        let mut issued = state
            .handle_with_connection(
                None,
                "",
                "POST",
                "auth/approle/login",
                &body,
                100,
                None,
                Some("127.0.0.1".parse().unwrap()),
            )
            .unwrap()
            .unwrap();
        issued.login_identity.take();
        state
            .bind_issued_entity(&mut issued, "", "approle", "test-entity")
            .unwrap();
        state.finish_pending_batch(&mut issued, "", 100).unwrap();
        let raw = Zeroizing::new(
            issued.body["auth"]["client_token"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        role(
            &mut state,
            &root,
            json!({"secret_id_bound_cidrs":["10.0.0.0/8"]}),
        )
        .unwrap();
        let mut actor = state
            .authenticate_from(&raw, 100, Some("127.0.0.2".parse().unwrap()))
            .unwrap();
        actor.bind_identity_policies(BTreeSet::new());
        let renew = call(
            &mut state,
            Some(&actor),
            "POST",
            "auth/token/renew-self",
            json!({"increment":120}),
        );
        if kind == "service" {
            assert_eq!(renew.unwrap().status, 200);
        } else {
            assert_eq!(renew.err().unwrap().status, 400);
        }
        let mut restored: AuthState = serde_json::from_slice(&bytes(&state)).unwrap();
        restored.validate_approle_token_bound_cidrs().unwrap();
        assert!(
            restored
                .authenticate_from(&raw, 100, Some("127.0.0.2".parse().unwrap()))
                .is_ok()
        );
    }
}
