#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
fn config() -> Value {
    json!({"host":"RADIUS.EXAMPLE.TEST","secret":"synthetic-shared-secret","token_ttl":120,"token_max_ttl":600})
}
fn mount() -> (AuthState, String) {
    let (mut s, r) = AuthState::bootstrap(100).unwrap();
    write(&mut s, &r, "sys/auth/radius", json!({"type":"radius"}));
    (s, r)
}
fn fixture() -> (AuthState, String) {
    let (mut s, r) = mount();
    write(&mut s, &r, "auth/radius/config", config());
    (s, r)
}
fn write(s: &mut AuthState, r: &str, path: &str, body: Value) {
    let a = s.authenticate(r, 100).unwrap();
    assert_eq!(
        s.handle(Some(&a), "", "POST", path, &body, 100)
            .unwrap()
            .unwrap()
            .status,
        204
    );
}
fn read(s: &mut AuthState, r: &str, path: &str) -> Value {
    let a = s.authenticate(r, 100).unwrap();
    s.handle(Some(&a), "", "GET", path, &json!({}), 100)
        .unwrap()
        .unwrap()
        .body["data"]
        .clone()
}
fn login(s: &mut AuthState, name: &str) -> AuthResponse {
    let p = s
        .prepare_radius_login(
            "",
            "radius",
            "POST",
            &json!({"username":name,"password":"synthetic-user-password"}),
            100,
        )
        .unwrap();
    s.finish_radius_login(p, RadiusLoginObservation).unwrap()
}
fn bearer(r: &AuthResponse) -> String {
    r.body["auth"]["client_token"].as_str().unwrap().into()
}
fn renew(
    s: &mut AuthState,
    r: &str,
    raw: &str,
    via: &str,
    now: u64,
) -> (Principal, ProviderRenewalPlan) {
    assert!(["renew-self", "renew", "renew-accessor"].contains(&via));
    let a = s
        .authenticate(if via == "renew-self" { raw } else { r }, now)
        .unwrap();
    let body = match via {
        "renew" => json!({"token":raw,"increment":300}),
        "renew-accessor" => json!({"accessor":s.tokens[&hash(raw)].accessor,"increment":300}),
        _ => json!({"increment":300}),
    };
    let p = s
        .prepare_provider_renewal(
            Some(&a),
            "",
            "POST",
            &format!("auth/token/{via}"),
            &body,
            now,
        )
        .unwrap()
        .unwrap();
    (a, p)
}
fn accept(
    s: &mut AuthState,
    a: &Principal,
    p: ProviderRenewalPlan,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    s.finish_provider_renewal(
        p,
        a,
        ProviderRenewalObservation::Radius(RadiusRenewalObservation),
        now,
    )
}

#[test]
fn native_radius_config_defaults_partial_null_and_secret_redaction() {
    let (mut s, r) = fixture();
    let data = read(&mut s, &r, "auth/radius/config");
    assert_eq!(data["host"], "radius.example.test");
    assert_eq!(data["port"], 1812);
    assert_eq!(data["nas_port"], 10);
    assert_eq!(data["dial_timeout"], 10);
    assert_eq!(data["read_timeout"], 10);
    assert_eq!(data["unregistered_user_policies"], json!([]));
    assert!(data.get("secret").is_none());
    assert!(data.get("url").is_none());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"port":"1813","nas_port":-1,"nas_identifier":"test-nas","dial_timeout":"3s","read_timeout":3,"token_num_uses":4,"unregistered_user_policies":" Fallback ,fallback,other "}),
    );
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"port":null,"nas_port":null,"nas_identifier":null,"dial_timeout":null,"read_timeout":null,"token_num_uses":null}),
    );
    let data = read(&mut s, &r, "auth/radius/config");
    assert_eq!(data["port"], 0);
    assert_eq!(data["nas_port"], 0);
    assert_eq!(data["nas_identifier"], "");
    assert_eq!(data["dial_timeout"], 3);
    assert_eq!(data["read_timeout"], 3);
    assert_eq!(data["token_num_uses"], 0);
    assert_eq!(
        data["unregistered_user_policies"],
        json!([" Fallback ", "fallback", "other "])
    );
    for port in [-1, 65536, i64::MAX] {
        write(&mut s, &r, "auth/radius/config", json!({"port":port}));
        assert_eq!(read(&mut s, &r, "auth/radius/config")["port"], port);
        s.validate_online_auth().unwrap();
    }
    let a = s.authenticate(&r, 100).unwrap();
    for body in [
        json!({"host":null}),
        json!({"host":""}),
        json!({"secret":null}),
        json!({"secret":""}),
        json!({"read_timeout":61}),
        json!({"dial_timeout":-1}),
        json!({"unregistered_user_policies":" ROOT "}),
    ] {
        let before = state_revision(&s).unwrap();
        assert_eq!(
            s.handle(Some(&a), "", "POST", "auth/radius/config", &body, 100)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(state_revision(&s).unwrap(), before);
    }
    assert_eq!(
        s.handle(
            Some(&a),
            "",
            "DELETE",
            "auth/radius/config",
            &json!({}),
            100
        )
        .err()
        .unwrap()
        .status,
        405
    );
}

#[test]
fn native_radius_users_before_config_mark_profile_and_survive_empty_restart() {
    let (mut s, r) = mount();
    let a = s.authenticate(&r, 100).unwrap();
    assert_eq!(
        s.handle(Some(&a), "", "LIST", "auth/radius/users", &json!({}), 100)
            .err()
            .unwrap()
            .status,
        404
    );
    assert!(!s.has_native_radius_state());
    write(
        &mut s,
        &r,
        "auth/radius/users/alice",
        json!({"policies":["mapped"]}),
    );
    s.handle(
        Some(&a),
        "",
        "DELETE",
        "auth/radius/users/alice",
        &json!({}),
        100,
    )
    .unwrap();
    assert!(s.has_native_radius_state());
    s.validate_online_auth().unwrap();
    let encoded = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&encoded).unwrap();
    s.validate_online_auth().unwrap();
    assert!(s.has_native_radius_state());
    assert_eq!(
        s.handle(
            Some(&a),
            "",
            "POST",
            "auth/radius/config",
            &json!({"url":"radius://radius.example.test:1812"}),
            100
        )
        .err()
        .unwrap()
        .status,
        409
    );
    write(&mut s, &r, "auth/radius/config", config());
    assert!(
        login(&mut s, "alice").body["auth"]["renewable"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn native_radius_user_case_pagination_replace_and_fallback_shadowing() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_policies":["base"],"unregistered_user_policies":"fallback"}),
    );
    write(
        &mut s,
        &r,
        "auth/radius/users/alice",
        json!({"policies":" MAPPED, mapped "}),
    );
    write(
        &mut s,
        &r,
        "auth/radius/users/ALICE",
        json!({"policies":["upper"]}),
    );
    assert_eq!(
        read(&mut s, &r, "auth/radius/users/ALICE")["policies"],
        json!(["mapped"])
    );
    let a = s.authenticate(&r, 100).unwrap();
    for (body, expected) in [
        (json!({}), json!(["ALICE", "alice"])),
        (json!({"after":"ALICE","limit":1}), json!(["alice"])),
        (json!({"limit":-1}), json!(["ALICE", "alice"])),
    ] {
        let response = s
            .handle(Some(&a), "", "LIST", "auth/radius/users", &body, 100)
            .unwrap()
            .unwrap();
        assert_eq!(response.body["data"]["keys"], expected);
    }
    let auth = login(&mut s, "ALICE");
    assert_eq!(
        auth.body["auth"]["token_policies"],
        json!(["base", "default", "mapped"])
    );
    assert_eq!(
        auth.body["auth"]["metadata"],
        json!({"username":"ALICE","policies":"mapped"})
    );
    let raw = bearer(&auth);
    assert_eq!(
        token_info(&s.tokens[&hash(&raw)], 102)["meta"],
        json!({"username":"ALICE","policies":"mapped"})
    );
    assert_eq!(auth.login_identity.unwrap().alias, "ALICE");
    s.handle(
        Some(&a),
        "",
        "DELETE",
        "auth/radius/users/ALICE",
        &json!({}),
        100,
    )
    .unwrap();
    assert_eq!(
        read(&mut s, &r, "auth/radius/users/alice")["policies"],
        json!(["mapped"])
    );
    for body in [json!({}), json!({"policies":null}), json!({"policies":[]})] {
        write(&mut s, &r, "auth/radius/users/alice", body);
        let auth = login(&mut s, "alice");
        assert_eq!(
            auth.body["auth"]["token_policies"],
            json!(["base", "default"])
        );
        assert_eq!(auth.body["auth"]["metadata"]["policies"], "");
    }
    s.handle(
        Some(&a),
        "",
        "DELETE",
        "auth/radius/users/alice",
        &json!({}),
        100,
    )
    .unwrap();
    assert_eq!(
        login(&mut s, "alice").body["auth"]["token_policies"],
        json!(["base", "default", "fallback"])
    );
    assert_eq!(
        s.handle(
            Some(&a),
            "",
            "POST",
            "auth/radius/users/alice",
            &json!({"policies":["root"]}),
            100
        )
        .err()
        .unwrap()
        .status,
        400
    );
}

#[test]
fn native_radius_path_username_and_body_precedence_keep_provider_identity() {
    let (mut s, _) = fixture();
    for (body, expected) in [
        (json!({"password":"pw"}), "path-user"),
        (json!({"username":null,"password":"pw"}), "path-user"),
        (json!({"username":"","password":"pw"}), "path-user"),
        (json!({"username":123,"password":"pw"}), "123"),
        (json!({"username":false,"password":"pw"}), "0"),
        (json!({"username":true,"password":"pw"}), "1"),
        (json!({"username":"Body User","password":"pw"}), "Body User"),
    ] {
        let plan = s
            .prepare_radius_login_with_path("", "radius", Some("path-user"), "POST", &body, 100)
            .unwrap();
        assert_eq!(plan.username, expected);
        let auth = s.finish_radius_login(plan, RadiusLoginObservation).unwrap();
        assert_eq!(auth.body["auth"]["metadata"]["username"], expected);
        assert_eq!(auth.login_identity.unwrap().alias, expected);
    }
}

#[test]
fn native_radius_map_deletion_renews_only_when_current_fallback_matches() {
    for via in ["renew-self", "renew", "renew-accessor"] {
        let (mut s, r) = fixture();
        write(
            &mut s,
            &r,
            "auth/radius/users/alice",
            json!({"policies":["mapped"]}),
        );
        let raw = bearer(&login(&mut s, "alice"));
        let a = s.authenticate(&r, 110).unwrap();
        s.handle(
            Some(&a),
            "",
            "DELETE",
            "auth/radius/users/alice",
            &json!({}),
            110,
        )
        .unwrap();
        let (a, p) = renew(&mut s, &r, &raw, via, 110);
        let before = state_revision(&s).unwrap();
        assert_eq!(accept(&mut s, &a, p, 110).err().unwrap().status, 500);
        assert_eq!(state_revision(&s).unwrap(), before);
        write(
            &mut s,
            &r,
            "auth/radius/config",
            json!({"unregistered_user_policies":"mapped","secret":"rotated-secret"}),
        );
        let (a, p) = renew(&mut s, &r, &raw, via, 115);
        let response = accept(&mut s, &a, p, 115).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 300);
        assert_eq!(response.body["auth"]["metadata"]["policies"], "mapped");
        let a = s.authenticate(&r, 116).unwrap();
        assert_eq!(
            s.handle(
                Some(&a),
                "",
                "POST",
                "auth/token/renew",
                &json!({"token":raw}),
                116
            )
            .err()
            .unwrap()
            .status,
            503
        );
    }
}

#[test]
fn native_radius_raw_fallback_preserves_official_renewal_policy_mismatch() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"unregistered_user_policies":" Fallback ,fallback,other "}),
    );
    let auth = login(&mut s, "alice");
    let raw = bearer(&auth);
    assert_eq!(
        auth.body["auth"]["token_policies"],
        json!(["default", "fallback", "other"])
    );
    assert_eq!(
        auth.body["auth"]["metadata"]["policies"],
        " Fallback ,fallback,other "
    );
    let (a, p) = renew(&mut s, &r, &raw, "renew", 110);
    assert_eq!(accept(&mut s, &a, p, 110).err().unwrap().status, 500);
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"unregistered_user_policies":"fallback,other"}),
    );
    let (a, p) = renew(&mut s, &r, &raw, "renew", 115);
    assert_eq!(
        accept(&mut s, &a, p, 115).unwrap().body["auth"]["metadata"]["policies"],
        " Fallback ,fallback,other ",
        "renew preserves issued metadata snapshot"
    );
}

#[test]
fn native_radius_inflight_mapping_absence_config_and_mount_are_fenced() {
    for change in ["mapping", "secret", "mount"] {
        let (mut s, r) = fixture();
        let plan = s
            .prepare_radius_login(
                "",
                "radius",
                "POST",
                &json!({"username":"alice","password":"pw"}),
                100,
            )
            .unwrap();
        match change {
            "mapping" => write(
                &mut s,
                &r,
                "auth/radius/users/alice",
                json!({"policies":[]}),
            ),
            "secret" => write(
                &mut s,
                &r,
                "auth/radius/config",
                json!({"secret":"rotated"}),
            ),
            _ => {
                let a = s.authenticate(&r, 100).unwrap();
                s.handle(Some(&a), "", "DELETE", "sys/auth/radius", &json!({}), 100)
                    .unwrap();
                write(&mut s, &r, "sys/auth/radius", json!({"type":"radius"}));
                write(&mut s, &r, "auth/radius/config", config());
            }
        }
        let before = state_revision(&s).unwrap();
        assert_eq!(
            s.finish_radius_login(plan, RadiusLoginObservation)
                .err()
                .unwrap()
                .status,
            409
        );
        assert_eq!(state_revision(&s).unwrap(), before);
    }
    let (mut s, r) = fixture();
    let raw = bearer(&login(&mut s, "alice"));
    let (a, p) = renew(&mut s, &r, &raw, "renew", 110);
    write(
        &mut s,
        &r,
        "auth/radius/users/alice",
        json!({"policies":[]}),
    );
    let before = state_revision(&s).unwrap();
    assert_eq!(accept(&mut s, &a, p, 110).err().unwrap().status, 409);
    assert_eq!(state_revision(&s).unwrap(), before);
}

#[test]
fn native_radius_profile_boundaries_provenance_and_issued_cap_survive_restart() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "sys/policies/acl/issuer",
        json!({"policy":"path \"auth/token/create\" { capabilities = [\"update\"] }"}),
    );
    let a = s.authenticate(&r, 100).unwrap();
    assert_eq!(
        s.handle(
            Some(&a),
            "",
            "POST",
            "auth/radius/config",
            &json!({"url":"radius://radius.example.test:1812"}),
            100
        )
        .err()
        .unwrap()
        .status,
        409
    );
    assert_eq!(
        s.handle(
            Some(&a),
            "",
            "POST",
            "auth/radius/config",
            &json!({"url":"radius://radius.example.test:1812","host":"radius.example.test"}),
            100
        )
        .err()
        .unwrap()
        .status,
        400
    );
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_period":30,"token_explicit_max_ttl":90,"token_policies":["issuer"]}),
    );
    let raw = bearer(&login(&mut s, "alice"));
    let issued = s.tokens[&hash(&raw)].created_at;
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_period":60,"token_explicit_max_ttl":0}),
    );
    let data = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&data).unwrap();
    s.validate_online_auth().unwrap();
    assert_eq!(
        token_info(&s.tokens[&hash(&raw)], issued + 1)["meta"],
        json!({"username":"alice","policies":""})
    );
    let native_actor = s.authenticate(&raw, issued + 1).unwrap();
    let child = s
        .handle(
            Some(&native_actor),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"]}),
            issued + 1,
        )
        .unwrap()
        .unwrap();
    assert!(
        token_info(&s.tokens[&hash(&bearer(&child))], issued + 1)
            .get("meta")
            .is_none()
    );
    let child_token = &s.tokens[&hash(&bearer(&child))];
    assert_eq!(child_token.parent.as_deref(), Some(hash(&raw).as_str()));
    assert!(matches!(
        child_token.auth_provenance,
        Some(TokenAuthProvenance::TokenApi)
    ));
    let (a, p) = renew(&mut s, &r, &raw, "renew", issued + 20);
    assert_eq!(
        accept(&mut s, &a, p, issued + 20).unwrap().body["auth"]["lease_duration"],
        60
    );
    let (a, p) = renew(&mut s, &r, &raw, "renew", issued + 70);
    assert_eq!(
        accept(&mut s, &a, p, issued + 70).unwrap().body["auth"]["lease_duration"],
        20
    );
    assert_eq!(s.tokens[&hash(&raw)].period, 30);
    let (mut old, r) = mount();
    write(
        &mut old,
        &r,
        "auth/radius/config",
        json!({"url":"radius://radius.example.test:1812"}),
    );
    let token = bearer(&login(&mut old, "alice"));
    let a = old.authenticate(&r, 100).unwrap();
    assert_eq!(
        old.handle(
            Some(&a),
            "",
            "POST",
            "auth/radius/users/alice",
            &json!({}),
            100
        )
        .err()
        .unwrap()
        .status,
        409
    );
    old.handle(
        Some(&a),
        "",
        "DELETE",
        "auth/radius/config",
        &json!({}),
        100,
    )
    .unwrap();
    assert_eq!(
        old.handle(Some(&a), "", "POST", "auth/radius/config", &config(), 100)
            .err()
            .unwrap()
            .status,
        409
    );
    assert!(matches!(
        old.tokens[&hash(&token)].auth_provenance,
        Some(TokenAuthProvenance::Radius { .. })
    ));
}
