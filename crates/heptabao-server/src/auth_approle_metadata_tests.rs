#![allow(clippy::unwrap_used)]
use super::*;

fn setup() -> (AuthState, Principal) {
    let (state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate_read_only(&raw, 100).unwrap().unwrap();
    (state, root)
}
fn call(
    state: &mut AuthState,
    root: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", "POST", path, &body, 100)?
        .ok_or_else(denied)
}
fn saved(state: &AuthState) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(state).unwrap())
}
fn issue(state: &mut AuthState, root: &Principal, metadata: Value) -> AuthResponse {
    call(
        state,
        root,
        "auth/approle/role/example/secret-id",
        json!({"metadata":metadata}),
    )
    .unwrap()
}
fn login(state: &mut AuthState, issued: &AuthResponse) -> AuthResponse {
    let body = json!({"role_id":state.roles[""]["example"].role_id,"secret_id":issued.body["data"]["secret_id"]});
    let mut response = state
        .handle(None, "", "POST", "auth/approle/login", &body, 100)
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    state
        .bind_issued_entity(&mut response, "", "approle", "test-entity")
        .unwrap();
    state.finish_pending_batch(&mut response, "", 100).unwrap();
    response
}

#[test]
fn approle_metadata_parser_matches_observed_strings_and_upstream_base64_csv_order() {
    assert!(approle_metadata::parse(&json!({})).unwrap().is_none());
    for input in [Value::Null, json!(""), json!("{}"), json!("bnVsbA==")] {
        assert_eq!(
            approle_metadata::parse(&json!({"metadata":input})).unwrap(),
            Some(BTreeMap::new())
        );
    }
    assert_eq!(
        approle_metadata::parse(&json!({"metadata":r#"{"":null}"#})).unwrap(),
        Some(BTreeMap::from([("".into(), "".into())]))
    );
    for (input, expected) in [
        (r#"{"env":"first","env":"last"}"#, "last"),
        ("ENV=LAST,env=first,,", "last"),
        (" env = PROD ", "prod"),
        ("eyJlbnYiOiJQUk9EIn0=", "PROD"),
        ("ZW52PVBST0Q=", "prod"),
    ] {
        assert_eq!(
            approle_metadata::parse(&json!({"metadata":input}))
                .unwrap()
                .unwrap()["env"],
            expected
        );
    }
    for input in [
        json!({"env":"prod"}),
        json!([]),
        json!(12),
        json!(false),
        json!("null"),
        json!(r#"{"n":12}"#),
        json!(r#"{"n":null}"#),
        json!(r#"{"n":true}"#),
        json!(r#"{"n":[]}"#),
        json!(r#"{"n":{}}"#),
        json!("note=a=b"),
        json!("=prod"),
        json!("env="),
        json!("env"),
    ] {
        assert_eq!(
            approle_metadata::parse(&json!({"metadata":input}))
                .err()
                .unwrap()
                .status,
            400
        );
    }
}

#[test]
fn approle_metadata_invalid_inputs_do_not_create_or_replace_secret_ids() {
    for operation in ["secret-id", "custom-secret-id"] {
        let (mut state, root) = setup();
        call(&mut state, &root, "auth/approle/role/example", json!({})).unwrap();
        for metadata in [
            json!("bad"),
            json!({}),
            json!(format!(
                "k={}",
                "a".repeat(crate::login_metadata::MAX_BYTES)
            )),
            json!(r#"{"key":""}"#),
        ] {
            let before = saved(&state);
            let mut body = json!({"metadata":metadata});
            if operation == "custom-secret-id" {
                body["secret_id"] = json!("synthetic-id");
            }
            assert_eq!(
                call(
                    &mut state,
                    &root,
                    &format!("auth/approle/role/example/{operation}"),
                    body
                )
                .err()
                .unwrap()
                .status,
                400
            );
            assert!(before.as_slice() == saved(&state).as_slice());
        }
    }
}

#[test]
fn approle_metadata_legacy_bytes_and_empty_presence_are_distinct_without_read_migration() {
    let old = br#"{"accessor":"sa.legacy","expires_at":null,"uses_remaining":null}"#;
    let secret: SecretId = serde_json::from_slice(old).unwrap();
    assert!(serde_json::to_vec(&secret).unwrap().as_slice() == old);
    assert_eq!(
        approle_renewal::secret_id_info(&secret)["metadata"],
        json!({})
    );
    let provenance = br#"{"kind":"app_role","role_name":"example"}"#;
    let old_provenance: TokenAuthProvenance = serde_json::from_slice(provenance).unwrap();
    assert!(serde_json::to_vec(&old_provenance).unwrap().as_slice() == provenance);
    let (mut state, root) = setup();
    call(&mut state, &root, "auth/approle/role/example", json!({})).unwrap();
    assert!(!state.has_approle_metadata());
    issue(&mut state, &root, Value::Null);
    assert!(state.has_approle_metadata());
    state.validate_approle_metadata().unwrap();
    let bytes = saved(&state);
    let reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_approle_metadata().unwrap();
    assert!(bytes.as_slice() == saved(&reopened).as_slice());
}

#[test]
fn approle_metadata_raw_sid_and_service_or_batch_snapshot_are_separate() {
    for kind in ["service", "batch"] {
        let (mut state, root) = setup();
        call(
            &mut state,
            &root,
            "auth/approle/role/example",
            json!({"token_type":kind}),
        )
        .unwrap();
        let sid = issue(
            &mut state,
            &root,
            json!(r#"{"env":"one","role_name":"spoofed"}"#),
        );
        let response = login(&mut state, &sid);
        let expected = json!({"env":"one","role_name":"example"});
        assert_eq!(response.body["auth"]["metadata"], expected);
        assert_eq!(
            json!(response.login_identity.as_ref().unwrap().metadata),
            expected
        );
        let raw = Zeroizing::new(
            response.body["auth"]["client_token"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        let read = call(
            &mut state,
            &root,
            "auth/approle/role/example/secret-id/lookup",
            json!({"secret_id":sid.body["data"]["secret_id"]}),
        )
        .unwrap();
        assert_eq!(read.body["data"]["metadata"]["role_name"], "spoofed");
        let replacement = issue(&mut state, &root, json!(r#"{"env":"two"}"#));
        login(&mut state, &replacement);
        call(
            &mut state,
            &root,
            "auth/approle/role/example/secret-id/destroy",
            json!({"secret_id":sid.body["data"]["secret_id"]}),
        )
        .unwrap();
        let info = call(
            &mut state,
            &root,
            "auth/token/lookup",
            json!({"token":raw.as_str()}),
        )
        .unwrap();
        assert_eq!(info.body["data"]["meta"], expected);
        if kind == "service" {
            let renewed = state
                .renew_approle_token("", &hash(&raw), &json!({}), 100)
                .unwrap()
                .unwrap();
            assert_eq!(renewed.body["auth"]["metadata"], expected);
            // Old provenance keeps its known role projection without acquiring
            // the new persisted field when a lease is renewed.
            if let Some(TokenAuthProvenance::AppRole {
                issued_metadata, ..
            }) = &mut state.tokens.get_mut(&hash(&raw)).unwrap().auth_provenance
            {
                *issued_metadata = None;
            }
            let renewed = state
                .renew_approle_token("", &hash(&raw), &json!({}), 100)
                .unwrap()
                .unwrap();
            assert_eq!(
                renewed.body["auth"]["metadata"],
                json!({"role_name":"example"})
            );
            assert!(matches!(
                &state.tokens[&hash(&raw)].auth_provenance,
                Some(TokenAuthProvenance::AppRole {
                    issued_metadata: None,
                    ..
                })
            ));
        }
        state.validate_approle_metadata().unwrap();
    }
}

#[test]
fn approle_metadata_load_rejects_wrong_mount_or_snapshot_role_but_not_destroyed_sid() {
    let (mut state, root) = setup();
    call(&mut state, &root, "auth/approle/role/example", json!({})).unwrap();
    let sid = issue(&mut state, &root, json!("env=prod"));
    let response = login(&mut state, &sid);
    let id = hash(response.body["auth"]["client_token"].as_str().unwrap());
    state.roles.get_mut("").unwrap().clear();
    assert!(state.has_approle_metadata());
    state.validate_approle_metadata().unwrap();
    state.tokens.get_mut(&id).unwrap().auth_mount = Some("userpass".into());
    assert!(state.validate_approle_metadata().is_err());
    state.tokens.get_mut(&id).unwrap().auth_mount = Some("approle".into());
    if let Some(TokenAuthProvenance::AppRole {
        issued_metadata: Some(metadata),
        ..
    }) = &mut state.tokens.get_mut(&id).unwrap().auth_provenance
    {
        metadata.insert("role_name".into(), "other".into());
    }
    assert!(state.validate_approle_metadata().is_err());
    let (mut state, root) = setup();
    call(&mut state, &root, "auth/approle/role/example", json!({})).unwrap();
    issue(&mut state, &root, json!(""));
    state.auth_mounts.get_mut("").unwrap().remove("approle");
    assert!(state.validate_approle_metadata().is_err());
}

#[test]
fn approle_metadata_accepts_observed_extended_json_without_truncation() {
    let mut map: BTreeMap<String, String> =
        (0..65).map(|i| (format!("key-{i}"), "v".into())).collect();
    map.insert("".into(), "".into());
    map.insert("k".repeat(129), "v".repeat(1025));
    map.insert("control".into(), "名字\n\t".into());
    let encoded = serde_json::to_string(&map).unwrap();
    assert_eq!(
        approle_metadata::parse(&json!({"metadata":encoded})).unwrap(),
        Some(map)
    );
}

#[test]
fn approle_metadata_go_partial_type_errors_are_rejected_but_syntax_fallback_is_preserved() {
    for input in [
        r#"{"a=x":"good","b=y":42}"#,
        r#"{"a":"x=y","b":{"c":"d=e"}}"#,
        r#"{"a":"x=y","b":[]}"#,
        r#"{"b=y":42,"a=x":"good"}"#,
        r#"{"a=x":"good","b=y":null}"#,
        "a=synthetic-private-value,z",
    ] {
        let error = approle_metadata::parse(&json!({"metadata":input}))
            .err()
            .unwrap();
        assert_eq!(error.status, 400);
        assert_eq!(error.message, "invalid SecretID metadata");
    }
    let input = r#"{"a=x":"good","b=y":"#;
    let actual = approle_metadata::parse(&json!({"metadata":input}))
        .unwrap()
        .unwrap();
    assert_eq!(
        actual,
        BTreeMap::from([
            ("{\"a".into(), "x\":\"good\"".into()),
            ("\"b".into(), "y\":".into()),
        ])
    );
    // The fresh Identity alias rejects these punctuation-bearing keys later;
    // issuance must still retain the upstream parser's exact successful map.
}

#[test]
fn approle_metadata_partial_map_failure_is_atomic_for_random_and_custom_issuance() {
    for custom in [false, true] {
        let (mut state, root) = setup();
        call(&mut state, &root, "auth/approle/role/example", json!({})).unwrap();
        let before = saved(&state);
        let mut body = json!({"metadata":r#"{"a=x":"good","b=y":42}"#});
        let operation = if custom {
            body["secret_id"] = json!("synthetic-test-secret");
            "custom-secret-id"
        } else {
            "secret-id"
        };
        assert_eq!(
            call(
                &mut state,
                &root,
                &format!("auth/approle/role/example/{operation}"),
                body
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert!(before.as_slice() == saved(&state).as_slice());
    }
}

#[test]
fn approle_metadata_failed_base64_decode_does_not_replace_the_original_csv_input() {
    let csv = "YWJj=private-value";
    let actual = approle_metadata::parse(&json!({"metadata":csv}))
        .unwrap()
        .unwrap();
    assert_eq!(
        actual,
        BTreeMap::from([("ywjj".into(), "private-value".into())])
    );
}
