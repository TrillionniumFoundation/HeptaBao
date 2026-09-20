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

#[test]
fn native_radius_no_default_config_preserves_legacy_bytes_and_null_resets() {
    let (mut s, r) = fixture();
    let scope = AuthScope {
        namespace: "",
        mount: "radius",
    };
    let original = Zeroizing::new(serde_json::to_vec(s.radius_native_at(scope).unwrap()).unwrap());
    assert!(!String::from_utf8_lossy(&original).contains("token_no_default_policy"));
    let mut legacy_json: Value = serde_json::from_slice(&original).unwrap();
    legacy_json
        .as_object_mut()
        .unwrap()
        .remove("token_policies_configured");
    let legacy_bytes = Zeroizing::new(serde_json::to_vec(&legacy_json).unwrap());
    let legacy: RadiusNativeConfig = serde_json::from_slice(&legacy_bytes).unwrap();
    assert!(!legacy.token_no_default_policy);
    assert_eq!(legacy.token_policies_configured, None);
    assert_eq!(serde_json::to_value(&legacy).unwrap(), legacy_json);
    assert!(
        s.has_radius_no_default_policy(),
        "new config records nil provenance even before enabling the flag"
    );
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_no_default_policy": true}),
    );
    assert!(s.has_radius_no_default_policy());
    write(&mut s, &r, "auth/radius/config", json!({"token_ttl": 120}));
    assert_eq!(
        read(&mut s, &r, "auth/radius/config")["token_no_default_policy"],
        true
    );
    let saved = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&saved).unwrap();
    s.validate_online_auth().unwrap();
    assert!(s.has_radius_no_default_policy());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_no_default_policy": null}),
    );
    assert_eq!(
        read(&mut s, &r, "auth/radius/config")["token_no_default_policy"],
        false
    );
    assert_eq!(
        *original,
        serde_json::to_vec(s.radius_native_at(scope).unwrap()).unwrap()
    );
}

#[test]
fn native_radius_no_default_omits_empty_token_policies_without_adding_permissions() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_no_default_policy": true, "token_policies": []}),
    );
    let auth = login(&mut s, "alice");
    let raw = bearer(&auth);
    assert_eq!(auth.body["auth"]["policies"], json!([]));
    assert!(auth.body["auth"].get("token_policies").is_none());
    assert!(s.tokens[&hash(&raw)].policies.is_empty());
    let actor = s.authenticate(&raw, 110).unwrap();
    assert_eq!(
        s.prepare_provider_renewal(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            110
        )
        .err()
        .unwrap()
        .status,
        403
    );
    for via in ["renew", "renew-accessor"] {
        let (actor, plan) = renew(&mut s, &r, &raw, via, 115);
        let response = accept(&mut s, &actor, plan, 115).unwrap();
        assert_eq!(response.body["auth"]["policies"], json!([]));
        assert!(response.body["auth"].get("token_policies").is_none());
    }
    for fields in [
        json!({"token_policies":["default"]}),
        json!({"token_policies":[],"unregistered_user_policies":"default"}),
    ] {
        write(&mut s, &r, "auth/radius/config", fields);
        assert_eq!(
            login(&mut s, "alice").body["auth"]["token_policies"],
            json!(["default"])
        );
    }
}

#[test]
fn native_radius_no_default_toggle_preserves_issued_policies_on_all_renew_paths() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "sys/policies/acl/radius-renew",
        json!({"policy":"path \"auth/token/renew-self\" { capabilities = [\"update\"] }"}),
    );
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_policies":["radius-renew"]}),
    );
    let original = bearer(&login(&mut s, "alice"));
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_no_default_policy":true}),
    );
    let bare = bearer(&login(&mut s, "alice"));
    let saved = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&saved).unwrap();
    for fields in [
        json!({"token_no_default_policy":false}),
        json!({"token_no_default_policy":true,"token_policies":["default","radius-renew"]}),
        json!({"token_policies":["radius-renew"]}),
    ] {
        write(&mut s, &r, "auth/radius/config", fields);
        assert!(
            s.has_radius_no_default_policy(),
            "issued native policies retain schema fence after flag reset"
        );
        for (raw, expected) in [
            (&original, json!(["default", "radius-renew"])),
            (&bare, json!(["radius-renew"])),
        ] {
            for via in ["renew-self", "renew", "renew-accessor"] {
                let (actor, plan) = renew(&mut s, &r, raw, via, 115);
                assert_eq!(
                    accept(&mut s, &actor, plan, 115).unwrap().body["auth"]["token_policies"],
                    expected
                );
            }
        }
    }
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_policies":["different"]}),
    );
    let before = s.tokens[&hash(&bare)].expires_at;
    let (actor, plan) = renew(&mut s, &r, &bare, "renew", 115);
    assert_eq!(accept(&mut s, &actor, plan, 115).err().unwrap().status, 500);
    assert_eq!(s.tokens[&hash(&bare)].expires_at, before);
}

#[test]
fn native_radius_nil_empty_policy_distinction_and_legacy_normalization() {
    for empty in [json!([]), Value::Null] {
        let (mut s, r) = fixture();
        write(
            &mut s,
            &r,
            "auth/radius/config",
            json!({"token_no_default_policy":true}),
        );
        let raw = bearer(&login(&mut s, "alice"));
        let (actor, plan) = renew(&mut s, &r, &raw, "renew", 115);
        assert_eq!(accept(&mut s, &actor, plan, 115).err().unwrap().status, 500);
        write(
            &mut s,
            &r,
            "auth/radius/config",
            json!({"token_policies":empty}),
        );
        let (actor, plan) = renew(&mut s, &r, &raw, "renew", 115);
        assert_eq!(accept(&mut s, &actor, plan, 115).unwrap().status, 200);
    }
    let (mut s, r) = fixture();
    s.radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap()
        .native
        .as_mut()
        .unwrap()
        .token_policies_configured = None;
    assert!(!s.has_radius_no_default_policy());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_no_default_policy":true}),
    );
    let raw = bearer(&login(&mut s, "alice"));
    let saved = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&saved).unwrap();
    let (actor, plan) = renew(&mut s, &r, &raw, "renew", 115);
    assert_eq!(
        accept(&mut s, &actor, plan, 115).unwrap().status,
        200,
        "old normalized empty policies must not be guessed to have been nil"
    );
}

fn restore_enrolled_native_transport(s: &mut AuthState) {
    let mount = s
        .radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap();
    let mut stored = serde_json::to_value(mount.native.as_ref().unwrap()).unwrap();
    stored.as_object_mut().unwrap().remove("api_transport");
    mount.native = Some(Box::new(serde_json::from_value(stored).unwrap()));
    s.validate_online_auth().unwrap();
}

#[test]
fn native_radius_api_transport_legacy_serde_and_partial_updates_preserve_enrollment() {
    let (mut s, r) = fixture();
    assert!(s.has_radius_api_transport());
    restore_enrolled_native_transport(&mut s);
    let scope = AuthScope {
        namespace: "",
        mount: "radius",
    };
    let original = Zeroizing::new(serde_json::to_vec(s.radius_native_at(scope).unwrap()).unwrap());
    assert!(!s.radius_native_at(scope).unwrap().api_transport());
    assert!(!String::from_utf8_lossy(&original).contains("api_transport"));
    let legacy: RadiusNativeConfig = serde_json::from_slice(&original).unwrap();
    assert_eq!(*original, serde_json::to_vec(&legacy).unwrap());
    for body in [
        json!({"secret":"rotated-secret"}),
        json!({"token_ttl":60,"token_max_ttl":300}),
        json!({"token_policies":["default"],"token_no_default_policy":true}),
        json!({"nas_port":11,"nas_identifier":"nas","read_timeout":2}),
        json!({"unregistered_user_policies":"default"}),
    ] {
        write(&mut s, &r, "auth/radius/config", body);
        assert!(!s.has_radius_api_transport());
        assert!(!s.radius_native_at(scope).unwrap().api_transport());
    }
    let saved = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut s: AuthState = serde_json::from_slice(&saved).unwrap();
    s.validate_online_auth().unwrap();
    assert!(!s.has_radius_api_transport());
    assert!(
        read(&mut s, &r, "auth/radius/config")
            .get("api_transport")
            .is_none()
    );
    let actor = s.authenticate(&r, 100).unwrap();
    let before = state_revision(&s).unwrap();
    assert_eq!(
        s.handle(
            Some(&actor),
            "",
            "POST",
            "auth/radius/config",
            &json!({"api_transport":true}),
            100
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(state_revision(&s).unwrap(), before);
}

#[test]
fn native_radius_explicit_target_write_promotes_even_unchanged_target_and_survives_reopen() {
    for body in [json!({"host":"RADIUS.EXAMPLE.TEST"}), json!({"port":1812})] {
        let (mut s, r) = fixture();
        restore_enrolled_native_transport(&mut s);
        let raw = bearer(&login(&mut s, "alice"));
        let before = read(&mut s, &r, "auth/radius/config");
        write(&mut s, &r, "auth/radius/config", body);
        assert!(s.has_radius_api_transport());
        assert_eq!(read(&mut s, &r, "auth/radius/config"), before);
        let saved = Zeroizing::new(serde_json::to_vec(&s).unwrap());
        let mut s: AuthState = serde_json::from_slice(&saved).unwrap();
        s.validate_online_auth().unwrap();
        assert!(s.has_radius_api_transport());
        let (actor, plan) = renew(&mut s, &r, &raw, "renew", 110);
        accept(&mut s, &actor, plan, 110).unwrap();
        let actor = s.authenticate(&r, 110).unwrap();
        s.handle(
            Some(&actor),
            "",
            "DELETE",
            "sys/auth/radius",
            &json!({}),
            110,
        )
        .unwrap();
        assert!(!s.has_radius_api_transport());
        assert!(s.authenticate(&raw, 110).is_err());
    }
}

#[test]
fn native_radius_api_target_accepts_dns_and_bare_ips_but_rejects_url_ambiguity() {
    let (mut s, r) = fixture();
    for (host, stored, url) in [
        (
            "RADIUS.EXAMPLE.TEST",
            "radius.example.test",
            "radius://radius.example.test:1812",
        ),
        (
            "radius.example.test.",
            "radius.example.test.",
            "radius://radius.example.test.:1812",
        ),
        ("127.0.0.1", "127.0.0.1", "radius://127.0.0.1:1812"),
        ("2001:DB8::1", "2001:db8::1", "radius://[2001:db8::1]:1812"),
        ("::1", "::1", "radius://[::1]:1812"),
    ] {
        write(&mut s, &r, "auth/radius/config", json!({"host":host}));
        assert_eq!(read(&mut s, &r, "auth/radius/config")["host"], stored);
        assert_eq!(s.radius_mounts[""]["radius"].url, url);
        s.validate_online_auth().unwrap();
    }
    let actor = s.authenticate(&r, 100).unwrap();
    for host in [
        "",
        "radius://example.test",
        "example.test:1812",
        "[::1]",
        "fe80::1%lo0",
        "a/b",
        "a@b",
        " a",
        "a b",
        "a\nb",
        "é.test",
        "a..b",
        "-a.test",
        "a-.test",
    ] {
        let before = state_revision(&s).unwrap();
        assert_eq!(
            s.handle(
                Some(&actor),
                "",
                "POST",
                "auth/radius/config",
                &json!({"host":host}),
                100
            )
            .err()
            .unwrap()
            .status,
            400,
            "host {host:?}"
        );
        assert_eq!(state_revision(&s).unwrap(), before);
    }
    for port in [-1, 0, 65536, i64::MAX] {
        write(&mut s, &r, "auth/radius/config", json!({"port":port}));
        assert_eq!(read(&mut s, &r, "auth/radius/config")["port"], port);
        s.validate_online_auth().unwrap();
    }
}

#[test]
fn native_radius_transport_promotion_fences_inflight_login_and_all_renew_routes() {
    for via in ["renew-self", "renew", "renew-accessor"] {
        let (mut s, r) = fixture();
        restore_enrolled_native_transport(&mut s);
        let raw = bearer(&login(&mut s, "alice"));
        let login_plan = s
            .prepare_radius_login(
                "",
                "radius",
                "POST",
                &json!({"username":"alice","password":"pw"}),
                100,
            )
            .unwrap();
        assert!(!login_plan.config.native.as_ref().unwrap().api_transport());
        let (actor, renewal_plan) = renew(&mut s, &r, &raw, via, 110);
        write(
            &mut s,
            &r,
            "auth/radius/config",
            json!({"host":"radius.example.test"}),
        );
        let before = state_revision(&s).unwrap();
        assert_eq!(
            s.finish_radius_login(login_plan, RadiusLoginObservation)
                .err()
                .unwrap()
                .status,
            409
        );
        assert_eq!(state_revision(&s).unwrap(), before);
        assert_eq!(
            accept(&mut s, &actor, renewal_plan, 110)
                .err()
                .unwrap()
                .status,
            409
        );
        assert_eq!(state_revision(&s).unwrap(), before);
        let fresh = s
            .prepare_radius_login(
                "",
                "radius",
                "POST",
                &json!({"username":"alice","password":"pw"}),
                110,
            )
            .unwrap();
        assert!(fresh.config.native.as_ref().unwrap().api_transport());
        s.finish_radius_login(fresh, RadiusLoginObservation)
            .unwrap();
        let (actor, fresh) = renew(&mut s, &r, &raw, via, 110);
        accept(&mut s, &actor, fresh, 110).unwrap();
    }
}

fn cidr_login(
    s: &mut AuthState,
    peer: Option<std::net::IpAddr>,
) -> Result<AuthResponse, AuthError> {
    let plan = s.prepare_radius_login_from(
        "",
        "radius",
        None,
        "POST",
        &json!({"username":"alice","password":"pw"}),
        100,
        peer,
    )?;
    s.finish_radius_login(plan, RadiusLoginObservation)
}

#[test]
fn native_radius_cidr_login_and_token_admission_fail_before_use_consumption() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["127.0.0.1/32"],"token_num_uses":2}),
    );
    let good = Some("127.0.0.1".parse().unwrap());
    let bad_peer = Some("127.0.0.2".parse().unwrap());
    for peer in [None, bad_peer] {
        let before = state_revision(&s).unwrap();
        assert_eq!(cidr_login(&mut s, peer).err().unwrap().status, 403);
        assert_eq!(state_revision(&s).unwrap(), before);
    }
    let raw = bearer(&cidr_login(&mut s, good).unwrap());
    assert_eq!(s.tokens[&hash(&raw)].bound_cidrs, ["127.0.0.1"]);
    assert!(s.has_token_bound_cidrs());
    for peer in [None, bad_peer] {
        let before = state_revision(&s).unwrap();
        assert_eq!(
            s.authenticate_from(&raw, 101, peer).err().unwrap().status,
            403
        );
        assert_eq!(
            s.authenticate_read_only_from(&raw, 101, peer)
                .err()
                .unwrap()
                .status,
            403
        );
        assert_eq!(state_revision(&s).unwrap(), before);
        assert_eq!(s.tokens[&hash(&raw)].uses_remaining, Some(2));
    }
    let principal = s.authenticate_from(&raw, 101, good).unwrap();
    assert_eq!(s.tokens[&hash(&raw)].uses_remaining, Some(1));
    s.check_principal(&principal, "", 101).unwrap();
    // A held affine capability must not outlive a changed token constraint.
    s.tokens.get_mut(&hash(&raw)).unwrap().bound_cidrs = vec!["192.0.2.0/24".into()];
    assert_eq!(
        s.check_principal(&principal, "", 101).err().unwrap().status,
        403
    );
}

#[test]
fn native_radius_cidr_snapshot_survives_config_change_renewal_and_restart() {
    let (mut s, r) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["127.0.0.1/32"]}),
    );
    let raw = bearer(&cidr_login(&mut s, good).unwrap());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["192.0.2.0/24"]}),
    );
    assert_eq!(cidr_login(&mut s, good).err().unwrap().status, 403);
    for via in ["renew-self", "renew", "renew-accessor"] {
        let actor_peer = if via == "renew-self" {
            good
        } else {
            Some("127.0.0.2".parse().unwrap())
        };
        let actor = s
            .authenticate_from(if via == "renew-self" { &raw } else { &r }, 110, actor_peer)
            .unwrap();
        let body = match via {
            "renew" => json!({"token":raw,"increment":300}),
            "renew-accessor" => json!({"accessor":s.tokens[&hash(&raw)].accessor,"increment":300}),
            _ => json!({"increment":300}),
        };
        let plan = s
            .prepare_provider_renewal(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{via}"),
                &body,
                110,
            )
            .unwrap()
            .unwrap();
        accept(&mut s, &actor, plan, 110).unwrap();
        assert_eq!(
            token_info(&s.tokens[&hash(&raw)], 110)["bound_cidrs"],
            json!(["127.0.0.1"])
        );
    }
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":null}),
    );
    assert_eq!(
        read(&mut s, &r, "auth/radius/config")["token_bound_cidrs"],
        json!([])
    );
    assert!(
        s.has_token_bound_cidrs(),
        "issued tokens keep the schema fence after config clear"
    );
    let bytes = Zeroizing::new(serde_json::to_vec(&s).unwrap());
    let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_online_auth().unwrap();
    assert!(reopened.authenticate(&raw, 110).is_err());
    assert!(reopened.authenticate_from(&raw, 110, good).is_ok());
    let fresh = bearer(&cidr_login(&mut reopened, None).unwrap());
    assert!(reopened.authenticate(&fresh, 110).is_ok());
}

#[test]
fn native_radius_child_inherits_cidr_but_orphan_does_not() {
    let (mut s, r) = fixture();
    write(
        &mut s,
        &r,
        "sys/policies/acl/cidr-issuer",
        json!({"policy":
        "path \"auth/token/create\" { capabilities = [\"update\",\"sudo\"] } path \"auth/token/create-orphan\" { capabilities = [\"update\",\"sudo\"] }"}),
    );
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["127.0.0.1"],"token_policies":["cidr-issuer"]}),
    );
    let good = Some("127.0.0.1".parse().unwrap());
    let other = Some("127.0.0.2".parse().unwrap());
    let parent = bearer(&cidr_login(&mut s, good).unwrap());
    for (path, bound) in [
        ("auth/token/create", true),
        ("auth/token/create-orphan", false),
    ] {
        let principal = s.authenticate_from(&parent, 100, good).unwrap();
        let response = s
            .handle(
                Some(&principal),
                "",
                "POST",
                path,
                &json!({"policies":["default"]}),
                100,
            )
            .unwrap()
            .unwrap();
        let child = bearer(&response);
        assert_eq!(s.authenticate_from(&child, 101, other).is_err(), bound);
        assert_eq!(s.tokens[&hash(&child)].bound_cidrs.is_empty(), !bound);
        assert!(matches!(
            s.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        assert_eq!(
            token_info(&s.tokens[&hash(&child)], 101)
                .get("bound_cidrs")
                .is_some(),
            bound
        );
    }
}

#[test]
fn native_radius_cidr_config_change_fences_an_inflight_login() {
    let (mut s, r) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["127.0.0.1"]}),
    );
    let plan = s
        .prepare_radius_login_from(
            "",
            "radius",
            None,
            "POST",
            &json!({"username":"alice","password":"pw"}),
            100,
            good,
        )
        .unwrap();
    write(
        &mut s,
        &r,
        "auth/radius/config",
        json!({"token_bound_cidrs":["127.0.0.2"]}),
    );
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
