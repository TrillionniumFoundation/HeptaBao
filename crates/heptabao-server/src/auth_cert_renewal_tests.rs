use super::*;

fn certificate_issuer() -> (AuthState, Principal, Vec<u8>, String) {
    let (mut state, _, root) = setup();
    mount_auth(&mut state, &root, "", "cert", "cert");
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/policies/acl/cert-issuer",
        json!({"policy": "path \"auth/token/create\" { capabilities = [\"update\", \"sudo\"] }"}),
        100,
    );
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/cert/certs/operator",
        json!({
            "certificate_sha256": certificate_sha256(&leaf),
            "token_policies": ["default", "cert-issuer"],
            "token_ttl": 300,
            "token_max_ttl": 600,
        }),
        100,
    );
    let login = state
        .handle_with_client_certificates(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({"name": "operator"}),
            101,
            Some(std::slice::from_ref(&leaf)),
        )
        .unwrap()
        .unwrap();
    let raw = login.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (state, root, leaf, raw)
}

#[test]
fn certificate_current_role_and_mount_maximum_count_from_issue_time() {
    for tune_mount in [false, true] {
        let (mut state, root, leaf, raw) = certificate_issuer();
        let actor = state.authenticate(&raw, 101).unwrap();
        let accessor = state.tokens[&actor.digest].accessor.clone();
        let (path, body) = if tune_mount {
            (
                "sys/auth/cert/tune",
                json!({"default_lease_ttl": 30, "max_lease_ttl": 60}),
            )
        } else {
            (
                "auth/cert/certs/operator",
                json!({
                    "certificate_sha256": certificate_sha256(&leaf),
                    "token_policies": ["default", "cert-issuer"],
                    "token_ttl": 30,
                    "token_max_ttl": 60,
                }),
            )
        };
        call(&mut state, &root, "", "POST", path, body, 120);

        // The original lease still has time remaining. Every renewal entry
        // point must nevertheless observe the newly shortened absolute max.
        assert_eq!(state.tokens[&actor.digest].expires_at, Some(401));
        for operation in ["renew-self", "renew", "renew-accessor"] {
            for (now, expected_ttl) in [
                (140, Some(21)),
                (160, Some(1)),
                (161, None),
                (162, None),
                (401, None),
            ] {
                let mut attempt = state.clone();
                let principal = if operation == "renew-self" {
                    &actor
                } else {
                    &root
                };
                let body = match operation {
                    "renew" => json!({"token": raw, "increment": 300}),
                    "renew-accessor" => json!({"accessor": accessor, "increment": 300}),
                    _ => json!({"increment": 300}),
                };
                let result = attempt.handle_with_client_certificates(
                    Some(principal),
                    "",
                    "POST",
                    &format!("auth/token/{operation}"),
                    &body,
                    now,
                    Some(std::slice::from_ref(&leaf)),
                );
                if let Some(ttl) = expected_ttl {
                    let response = result.unwrap().unwrap();
                    assert_eq!(response.body["auth"]["lease_duration"], ttl);
                    assert_eq!(attempt.tokens[&actor.digest].expires_at, Some(161));
                } else {
                    assert_eq!(
                        result.err().unwrap().status,
                        if now >= 401 { 403 } else { 500 }
                    );
                    assert_eq!(attempt.tokens[&actor.digest].expires_at, Some(401));
                }
            }
        }
    }
}

#[test]
fn certificate_raised_current_maximum_preserves_legacy_and_child_explicit_caps() {
    let (mut baseline, root, leaf, raw) = certificate_issuer();
    let actor = baseline.authenticate(&raw, 101).unwrap();
    assert!(baseline.tokens[&actor.digest].max_expires_at.is_none());
    call(
        &mut baseline,
        &root,
        "",
        "POST",
        "auth/cert/certs/operator",
        json!({"certificate_sha256": certificate_sha256(&leaf), "token_policies": ["default", "cert-issuer"],
            "token_ttl": 300, "token_max_ttl": 900}),
        120,
    );
    for body in [json!({}), json!({"increment": 0})] {
        let mut state = baseline.clone();
        let response = state
            .handle_with_client_certificates(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &body,
                150,
                Some(std::slice::from_ref(&leaf)),
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 300);
        assert_eq!(state.tokens[&actor.digest].expires_at, Some(450));
    }
    for legacy_cap in [false, true] {
        for mount_cap in [false, true] {
            let mut state = baseline.clone();
            if legacy_cap {
                // Old unmarked parentless cert fields can also belong to a
                // token-API orphan with a real explicit cap. Keep that cap.
                state.tokens.get_mut(&actor.digest).unwrap().max_expires_at = Some(701);
            }
            if mount_cap {
                call(
                    &mut state,
                    &root,
                    "",
                    "POST",
                    "sys/auth/cert/tune",
                    json!({"default_lease_ttl": 300, "max_lease_ttl": 700}),
                    120,
                );
            }
            let mut state: AuthState =
                serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
            let response = state
                .handle_with_client_certificates(
                    Some(&actor),
                    "",
                    "POST",
                    "auth/token/renew-self",
                    &json!({"increment": 1000}),
                    150,
                    Some(std::slice::from_ref(&leaf)),
                )
                .unwrap()
                .unwrap();
            let expected_expiry = if legacy_cap {
                701
            } else if mount_cap {
                801
            } else {
                1001
            };
            assert_eq!(
                state.tokens[&actor.digest].expires_at,
                Some(expected_expiry)
            );
            assert_eq!(
                response.body["auth"]["lease_duration"],
                expected_expiry - 150
            );
        }
    }
    for orphan in [false, true] {
        let mut state = baseline.clone();
        let child = token(
            &mut state,
            &actor,
            "",
            json!({"policies": ["default"], "ttl": 120, "explicit_max_ttl": 30, "no_parent": orphan}),
            121,
        );
        let child_actor = state.authenticate(&child, 130).unwrap();
        let response = call(
            &mut state,
            &child_actor,
            "",
            "POST",
            "auth/token/renew-self",
            json!({"increment": 1000}),
            130,
        );
        assert_eq!(response.body["auth"]["lease_duration"], 21);
        assert_eq!(state.tokens[&hash(&child)].max_expires_at, Some(151));
    }
}

#[test]
fn certificate_token_api_children_renew_without_certificate_or_current_parent_role() {
    for orphan in [false, true] {
        let (mut state, root, leaf, raw) = certificate_issuer();
        let issuer = state.authenticate(&raw, 101).unwrap();
        let child = call(
            &mut state,
            &issuer,
            "",
            "POST",
            "auth/token/create",
            json!({"policies": ["default"], "ttl": 120, "no_parent": orphan}),
            110,
        );
        let child_raw = child.body["auth"]["client_token"].as_str().unwrap();
        let child_id = hash(child_raw);
        let child_token = &state.tokens[&child_id];
        assert_eq!(
            child_token.auth_mount.as_deref(),
            if orphan { None } else { Some("cert") }
        );
        assert!(child_token.auth_cert_role.is_none());
        assert!(child_token.auth_cert_sha256.is_none());
        assert!(matches!(
            child_token.auth_provenance,
            Some(TokenAuthProvenance::TokenApi { .. })
        ));
        assert_eq!(child_token.parent.is_none(), orphan);
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "auth/cert/certs/operator",
            json!({}),
            115,
        );
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();

        let actor = state.authenticate(child_raw, 120).unwrap();
        let renewal = call(
            &mut state,
            &actor,
            "",
            "POST",
            "auth/token/renew-self",
            json!({"increment": 60}),
            120,
        );
        assert_eq!(renewal.body["auth"]["lease_duration"], 60);
        let parent_renewal = state.handle_with_client_certificates(
            Some(&issuer),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            120,
            Some(std::slice::from_ref(&leaf)),
        );
        assert_eq!(parent_renewal.err().unwrap().status, 403);

        // Parented children revoke with the certificate issuer. Orphans have
        // their own token-API lifetime and survive that issuer's unmount.
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "sys/auth/cert",
            json!({}),
            121,
        );
        assert_eq!(state.authenticate(child_raw, 121).is_ok(), orphan);
    }
}

#[test]
fn certificate_legacy_child_fields_do_not_override_known_token_api_origin() {
    for (marked, orphan) in [(true, false), (true, true), (false, false), (false, true)] {
        let (mut state, root, _, raw) = certificate_issuer();
        let issuer = state.authenticate(&raw, 101).unwrap();
        let parent = state.tokens[&issuer.digest].clone();
        let child = call(
            &mut state,
            &issuer,
            "",
            "POST",
            "auth/token/create",
            json!({"policies": ["default"], "ttl": 120, "no_parent": orphan}),
            110,
        );
        let child_raw = child.body["auth"]["client_token"].as_str().unwrap();
        let child_id = hash(child_raw);
        let child_token = state.tokens.get_mut(&child_id).unwrap();
        child_token.auth_mount = parent.auth_mount.clone();
        child_token.auth_cert_role = parent.auth_cert_role.clone();
        child_token.auth_cert_sha256 = parent.auth_cert_sha256.clone();
        if !marked {
            child_token.auth_provenance = None;
        }
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "auth/cert/certs/operator",
            json!({}),
            115,
        );
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let actor = state.authenticate(child_raw, 120).unwrap();
        let renewal = state.handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment": 60}),
            120,
        );
        if !marked && orphan {
            // An old parentless token without the issuer marker cannot be
            // distinguished from a direct certificate login. Fail closed.
            assert_eq!(renewal.err().unwrap().status, 403);
            assert_eq!(state.tokens[&child_id].expires_at, Some(230));
        } else {
            assert_eq!(renewal.unwrap().unwrap().body["auth"]["lease_duration"], 60);
        }
        call(
            &mut state,
            &root,
            "",
            "DELETE",
            "sys/auth/cert",
            json!({}),
            121,
        );
        assert_eq!(state.authenticate(child_raw, 121).is_ok(), marked && orphan);
    }
}

#[test]
fn token_api_orphan_unmount_independence_is_not_specific_to_certificate_auth() {
    let (mut state, _, root) = setup();
    let mut issuers = Vec::new();
    for (namespace, mount) in [("", "people"), ("", "people-other"), ("team", "people")] {
        mount_auth(&mut state, &root, namespace, mount, "userpass");
        call(
            &mut state,
            &root,
            namespace,
            "POST",
            "sys/policies/acl/issuer",
            json!({"policy": "path \"auth/token/create\" { capabilities = [\"update\", \"sudo\"] }"}),
            100,
        );
        call(
            &mut state,
            &root,
            namespace,
            "POST",
            &format!("auth/{mount}/users/alice"),
            json!({"password": "synthetic-userpass-password", "token_policies": ["issuer"], "token_ttl": 300}),
            100,
        );
        let login =
            userpass_login(&mut state, namespace, mount, "synthetic-userpass-password").unwrap();
        issuers.push(
            login.body["auth"]["client_token"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let actor = state.authenticate(&issuers[0], 101).unwrap();
    let child = token(
        &mut state,
        &actor,
        "",
        json!({"policies": ["default"], "ttl": 120}),
        110,
    );
    let orphan = token(
        &mut state,
        &actor,
        "",
        json!({"policies": ["default"], "ttl": 120, "no_parent": true}),
        110,
    );
    let historical_orphan = token(
        &mut state,
        &actor,
        "",
        json!({"policies": ["default"], "ttl": 120, "no_parent": true}),
        110,
    );
    assert!(state.tokens[&hash(&orphan)].auth_mount.is_none());
    state
        .tokens
        .get_mut(&hash(&historical_orphan))
        .unwrap()
        .auth_mount = Some("people".into());
    let mut state: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/people",
        json!({}),
        115,
    );
    assert!(state.authenticate(&issuers[0], 116).is_err());
    assert!(state.authenticate(&child, 116).is_err());
    // The same username on another mount or namespace is unrelated.
    assert!(state.authenticate(&issuers[1], 116).is_ok());
    assert!(state.authenticate(&issuers[2], 116).is_ok());
    for raw in [&orphan, &historical_orphan] {
        let actor = state.authenticate(raw, 116).unwrap();
        let renewal = call(
            &mut state,
            &actor,
            "",
            "POST",
            "auth/token/renew-self",
            json!({"increment": 60}),
            116,
        );
        assert_eq!(renewal.body["auth"]["lease_duration"], 60);
    }
}
