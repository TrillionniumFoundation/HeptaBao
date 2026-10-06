use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn auth_defaults270_fresh_root_and_namespace_only_token_reads_do_not_mutate() -> TestResult {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate_read_only(&raw, 100)?;
    for namespace in ["", "fresh"] {
        if !namespace.is_empty() {
            state.initialize_fresh_namespace_auth(namespace)?;
        }
        let before = serde_json::to_vec(&state)?;
        let response = state
            .handle(Some(&root), namespace, "GET", "sys/auth", &json!({}), 100)?
            .ok_or("missing auth catalog")?;
        assert_eq!(response.status, 200);
        let data = response.body["data"].as_object().ok_or("auth map")?;
        assert_eq!(
            data.keys().map(String::as_str).collect::<Vec<_>>(),
            ["token/"]
        );
        assert_eq!(data["token/"]["type"], "token");
        assert!(!response.mutated);
        assert_eq!(serde_json::to_vec(&state)?, before);
        assert!(!state.online_mount_enabled(namespace, "userpass", "userpass"));
        assert!(!state.online_mount_enabled(namespace, "approle", "approle"));
    }
    assert!(state.namespace_is_empty("fresh"));
    state.remove_fresh_namespace_auth_defaults("fresh");
    assert!(!state.auth_mounts.contains_key("fresh"));
    Ok(())
}

#[test]
fn auth_defaults270_implicit_and_saved_predecessor_catalogs_survive_reopen() -> TestResult {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    state.auth_mounts.remove("");
    let before = serde_json::to_vec(&state)?;
    let reopened: AuthState = serde_json::from_slice(&before)?;
    assert_eq!(serde_json::to_vec(&reopened)?, before);
    for historical in [&state, &reopened] {
        let keys = historical
            .effective_auth_mounts("")
            .into_keys()
            .collect::<Vec<_>>();
        assert_eq!(keys, ["approle", "token", "userpass"]);
    }
    state.auth_mounts.insert(
        "saved".into(),
        userpass_names::prior_native_default_auth_mounts(),
    );
    let saved = serde_json::to_vec(&state)?;
    let mut reopened: AuthState = serde_json::from_slice(&saved)?;
    reopened.initialize_fresh_namespace_auth("next")?;
    assert_eq!(
        reopened
            .effective_auth_mounts("saved")
            .into_keys()
            .collect::<Vec<_>>(),
        ["approle", "token", "userpass"]
    );
    assert_eq!(reopened.effective_auth_mounts("next").len(), 1);
    assert!(reopened.has_native_userpass_names(AuthScope {
        namespace: "saved",
        mount: "userpass"
    }));
    assert!(reopened.namespace_is_empty("saved"));
    reopened.remove_fresh_namespace_auth_defaults("saved");
    assert!(!reopened.auth_mounts.contains_key("saved"));
    assert!(reopened.authenticate_read_only(&raw, 100).is_ok());
    Ok(())
}

#[test]
fn auth_defaults270_changed_catalog_and_explicit_mount_are_not_erased() -> TestResult {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate_read_only(&raw, 100)?;
    state.initialize_fresh_namespace_auth("edited")?;
    state
        .auth_mounts
        .get_mut("edited")
        .ok_or("fresh namespace")?
        .get_mut("token")
        .ok_or("fresh token")?
        .description = "operator metadata".into();
    let before = serde_json::to_vec(&state)?;
    assert!(!state.namespace_is_empty("edited"));
    state.remove_fresh_namespace_auth_defaults("edited");
    assert_eq!(serde_json::to_vec(&state)?, before);
    let enabled = state
        .handle(
            Some(&root),
            "",
            "POST",
            "sys/auth/userpass",
            &json!({"type":"userpass"}),
            100,
        )?
        .ok_or("explicit auth enable")?;
    assert_eq!(enabled.status, 204);
    assert!(enabled.mutated);
    assert!(state.has_native_userpass_names(AuthScope {
        namespace: "",
        mount: "userpass"
    }));
    let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    assert_eq!(reopened.effective_auth_mounts("").len(), 2);
    assert!(reopened.online_mount_enabled("", "userpass", "userpass"));
    Ok(())
}
