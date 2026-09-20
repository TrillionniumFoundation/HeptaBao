//! Durable Service tests inject only provider observations; the differential
//! fixture separately proves actual LDAPS Bind/Search and OpenBao responses.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::{LdapLoginObservation, LdapRenewalObservation, ProviderRenewalObservation};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn enroll(service: &mut Service) -> TestResult {
    let mut engines = EngineState::default();
    engines.handle("", "POST", "sys/mounts/pki", &json!({"type":"pki"}), 100)?;
    let certificate = engines
        .handle(
            "",
            "POST",
            "pki/root/generate/internal",
            &json!({"common_name":"directory.example.test","ttl":"48h"}),
            100,
        )?
        .ok_or("missing test CA")?;
    service.install_outbound_endpoints(vec![crate::outbound::EndpointConfig {
        origin: "ldaps://directory.example.test:636".into(),
        address: "127.0.0.1:636".parse()?,
        server_name: "directory.example.test".into(),
        ca_pem: certificate.body["data"]["certificate"]
            .as_str()
            .ok_or("missing CA")?
            .into(),
        path_prefix: "/".into(),
        shared_secret: String::new(),
    }])?;
    Ok(())
}

fn pending(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
    wrap_ttl_seconds: Option<u64>,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds,
        client_certificates: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(response) => {
            Err(format!("expected provider request, got {}", response.status).into())
        }
    }
}

fn groups(member: bool) -> BTreeSet<String> {
    if member {
        BTreeSet::from(["engineering".into()])
    } else {
        BTreeSet::new()
    }
}

fn accepted(service: &mut Service, plan: PendingExternalRequest, member: bool) -> Response {
    service.finish_external_request(
        plan,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::ProviderRenewal(
            ProviderRenewalObservation::Ldap(LdapRenewalObservation::observed(groups(member))),
        ))),
    )
}

struct Fixture {
    service: Service,
    key: String,
    root_token: String,
    token: String,
    entity: String,
    group: String,
}

fn fixture(root: &Root) -> TestResult<Fixture> {
    let mut service = root.service()?;
    enroll(&mut service)?;
    let (key, root_token) = bootstrap(&mut service)?;
    for (path, body) in [
        ("sys/auth/ldap", json!({"type":"ldap"})),
        ("auth/ldap/config", config()),
        (
            "auth/ldap/users/alice",
            json!({"password":"unused-local-verifier","token_ttl":120,"token_max_ttl":600}),
        ),
        (
            "sys/policies/acl/directory-only",
            json!({"policy":"path \"secret/data/*\" { capabilities = [\"read\"] }"}),
        ),
    ] {
        assert_eq!(
            call(&mut service, "POST", path, &root_token, body).status,
            204,
            "{path}"
        );
    }
    let mounts = call(&mut service, "GET", "sys/auth", &root_token, json!({}));
    let accessor = mounts.body["data"]["ldap/"]["accessor"]
        .as_str()
        .ok_or("missing mount accessor")?;
    let response = call(
        &mut service,
        "POST",
        "identity/group",
        &root_token,
        json!({"name":"directory-group","type":"external","policies":["directory-only"]}),
    );
    assert_eq!(response.status, 200);
    let group = response.body["data"]["id"]
        .as_str()
        .ok_or("missing group")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/group-alias",
            &root_token,
            json!({"name":"engineering","canonical_id":group,"mount_accessor":accessor})
        )
        .status,
        200
    );
    let login = pending(
        &mut service,
        "auth/ldap/login/alice",
        "",
        json!({"password":"synthetic-directory-password"}),
        100,
        None,
    )?;
    let response = service.finish_external_request(
        *login,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Ldap(
            LdapLoginObservation::observed(groups(true)),
        ))),
    );
    assert_eq!(response.status, 200);
    let token = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    let entity = response.body["auth"]["entity_id"]
        .as_str()
        .ok_or("missing entity")?
        .to_owned();
    assert_eq!(
        response.body["auth"]["identity_policies"],
        json!(["directory-only"])
    );
    Ok(Fixture {
        service,
        key,
        root_token,
        token,
        entity,
        group,
    })
}

fn config() -> Value {
    json!({"url":"ldaps://directory.example.test:636","bind_dn":"cn=admin,dc=example,dc=test","user_dn_template":"uid={{username}},ou=people,dc=example,dc=test","group_dn":"ou=groups,dc=example,dc=test"})
}

#[test]
fn ldap_renewal_persists_credentials_and_rejection_cannot_extend_or_refresh_groups() -> TestResult {
    let root = Root::new();
    let Fixture {
        mut service,
        key,
        root_token: _,
        token,
        entity: _,
        group: _,
    } = fixture(&root)?;
    let before = service.state_digest;
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        110,
        None,
    )?;
    let response = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Err(Response::error(
            400,
            "LDAP login failed during renewal",
        ))),
    );
    assert_eq!(response.status, 400);
    assert_eq!(service.state_digest, before);
    drop(service);
    let mut service = root.service()?;
    enroll(&mut service)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        120,
        None,
    )?;
    assert_eq!(accepted(&mut service, *request, true).status, 200);
    drop(service);
    let mut service = root.service()?;
    enroll(&mut service)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let info = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 130);
    assert_eq!(info.status, 200);
    assert!(
        info.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 200)
    );
    assert_eq!(
        info.body["data"]["identity_policies"],
        json!(["directory-only"])
    );
    let mut files = vec![root.path.clone()];
    while let Some(path) = files.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                files.push(entry?.path());
            }
        } else {
            assert!(
                !fs::read(path)?
                    .windows(b"synthetic-directory-password".len())
                    .any(|part| part == b"synthetic-directory-password")
            );
        }
    }
    Ok(())
}

#[test]
fn ldap_renewal_refreshes_identity_groups_and_echoes_only_supplied_bearers() -> TestResult {
    let root = Root::new();
    let Fixture {
        mut service,
        root_token,
        token,
        entity,
        group,
        ..
    } = fixture(&root)?;
    let lookup = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    let accessor = lookup.body["data"]["accessor"]
        .as_str()
        .ok_or("missing accessor")?;
    for (path, actor, body, member) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":300}),
            false,
        ),
        (
            "auth/token/renew",
            root_token.as_str(),
            json!({"token":token,"increment":301}),
            true,
        ),
        (
            "auth/token/renew-accessor",
            root_token.as_str(),
            json!({"accessor":accessor,"increment":302}),
            false,
        ),
    ] {
        let request = pending(&mut service, path, actor, body, 110, None)?;
        let response = accepted(&mut service, *request, member);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body["auth"]["identity_policies"],
            if member {
                json!(["directory-only"])
            } else {
                json!([])
            }
        );
        if path.ends_with("accessor") {
            assert!(response.body["auth"].get("client_token").is_none());
        } else {
            assert_eq!(response.body["auth"]["client_token"], token);
        }
        let read = call(
            &mut service,
            "GET",
            &format!("identity/group/id/{group}"),
            &root_token,
            json!({}),
        );
        assert_eq!(
            read.body["data"]["member_entity_ids"],
            if member { json!([entity]) } else { json!([]) }
        );
        let live = service
            .state
            .as_ref()
            .ok_or("missing state")?
            .engines
            .identity_projection("", &entity)?;
        assert_eq!(live.policies.contains("directory-only"), member);
    }
    Ok(())
}

#[test]
fn ldap_renewal_and_wrapper_publish_groups_and_ttl_in_one_transaction() -> TestResult {
    let root = Root::new();
    let Fixture {
        mut service,
        token,
        entity,
        ..
    } = fixture(&root)?;
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        110,
        Some(60),
    )?;
    let response = accepted(&mut service, *request, false);
    assert_eq!(response.status, 200);
    assert!(response.body["auth"].is_null());
    assert!(!response.body.to_string().contains(&token));
    let wrapper = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("missing wrapper")?;
    let unwrapped = service.handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 112);
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["auth"]["client_token"], token);
    assert_eq!(unwrapped.body["auth"]["identity_policies"], json!([]));
    assert!(
        service
            .state
            .as_ref()
            .ok_or("missing state")?
            .engines
            .identity_projection("", &entity)?
            .policies
            .is_empty()
    );
    let before_expiry = service
        .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115)
        .body["data"]["expire_time_unix"]
        .clone();
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":301}),
        115,
        Some(60),
    )?;
    // Admission independently advances the durable wrapping clock. The
    // provider transaction must leave that admitted state unchanged on failure.
    let before = service.state_digest;
    service.state_capacity = 1;
    let failed = accepted(&mut service, *request, true);
    assert_eq!(failed.status, 507);
    assert!(failed.body.get("auth").is_none());
    assert!(failed.body.get("wrap_info").is_none());
    assert_eq!(service.state_digest, before);
    let after_expiry = service
        .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115)
        .body["data"]["expire_time_unix"]
        .clone();
    assert_eq!(after_expiry, before_expiry);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("missing state")?
            .engines
            .identity_projection("", &entity)?
            .policies
            .is_empty()
    );
    Ok(())
}

#[test]
fn ldap_renewal_fences_inflight_authority_and_alias_changes() -> TestResult {
    for mutation in [
        "identity", "alias", "mapping", "config", "target", "actor", "sealed",
    ] {
        let root = Root::new();
        let Fixture {
            mut service,
            root_token,
            token,
            entity,
            ..
        } = fixture(&root)?;
        let request = pending(
            &mut service,
            "auth/token/renew",
            &root_token,
            json!({"token":token,"increment":300}),
            110,
            None,
        )?;
        let response = match mutation {
            "identity" => call(
                &mut service,
                "POST",
                &format!("identity/entity/id/{entity}"),
                &root_token,
                json!({"disabled":true}),
            ),
            "alias" => {
                let info = call(
                    &mut service,
                    "GET",
                    &format!("identity/entity/id/{entity}"),
                    &root_token,
                    json!({}),
                );
                let alias = info.body["data"]["aliases"][0]["id"]
                    .as_str()
                    .ok_or("missing alias")?;
                call(
                    &mut service,
                    "POST",
                    &format!("identity/entity-alias/id/{alias}"),
                    &root_token,
                    json!({"name":"renamed", "canonical_id":entity,"mount_accessor":info.body["data"]["aliases"][0]["mount_accessor"]}),
                )
            }
            "mapping" => call(
                &mut service,
                "POST",
                "auth/ldap/groups/engineering",
                &root_token,
                json!({"policies":["directory-only"]}),
            ),
            "config" => {
                let mut cfg = config();
                cfg["group_dn"] = json!("ou=changed,dc=example,dc=test");
                call(&mut service, "POST", "auth/ldap/config", &root_token, cfg)
            }
            "target" => call(
                &mut service,
                "POST",
                "auth/token/revoke",
                &root_token,
                json!({"token":token}),
            ),
            "actor" => call(
                &mut service,
                "POST",
                "auth/token/revoke-self",
                &root_token,
                json!({}),
            ),
            "sealed" => call(&mut service, "POST", "sys/seal", &root_token, json!({})),
            _ => return Err("unknown mutation".into()),
        };
        assert!(response.status < 300, "{mutation}");
        let before = service.state_digest;
        let failed = accepted(&mut service, *request, false);
        assert!(failed.status >= 400, "{mutation}");
        assert_eq!(service.state_digest, before, "{mutation}");
    }
    Ok(())
}

#[test]
fn ldap_schema_fence_and_auth_mount_disable_revoke_external_evidence() -> TestResult {
    let root = Root::new();
    let Fixture {
        mut service,
        root_token,
        entity,
        ..
    } = fixture(&root)?;
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.engines.has_external_group_membership());
    let mut downgraded = state.clone();
    downgraded.schema = 16;
    assert!(downgraded.validate_format().is_err());
    downgraded.auth = AuthState::bootstrap(100)?.0.into();
    assert!(
        downgraded.validate_format().is_err(),
        "external evidence independently needs schema 17"
    );
    downgraded.engines = EngineState::default().into();
    assert!(downgraded.validate_format().is_ok());
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/auth/ldap",
            &root_token,
            json!({})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("missing state")?;
    assert!(!state.engines.has_external_group_membership());
    assert!(
        state
            .engines
            .identity_projection("", &entity)?
            .policies
            .is_empty()
    );
    Ok(())
}

#[test]
fn ldap_login_observation_cannot_cross_mount_recreation_or_seal_activation() -> TestResult {
    for mutation in ["mount-recreated", "reactivated"] {
        let root = Root::new();
        let Fixture {
            mut service,
            key,
            root_token,
            ..
        } = fixture(&root)?;
        let login = pending(
            &mut service,
            "auth/ldap/login/alice",
            "",
            json!({"password":"synthetic-directory-password"}),
            110,
            None,
        )?;
        if mutation == "mount-recreated" {
            assert_eq!(
                call(
                    &mut service,
                    "DELETE",
                    "sys/auth/ldap",
                    &root_token,
                    json!({})
                )
                .status,
                204
            );
            for (path, body) in [
                ("sys/auth/ldap", json!({"type":"ldap"})),
                ("auth/ldap/config", config()),
                (
                    "auth/ldap/users/alice",
                    json!({"password":"unused-local-verifier","token_ttl":120,"token_max_ttl":600}),
                ),
            ] {
                assert_eq!(
                    call(&mut service, "POST", path, &root_token, body).status,
                    204
                );
            }
        } else {
            assert_eq!(
                call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
                204
            );
            enroll(&mut service)?;
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
        }
        let before = service.state_digest;
        let failed = service.finish_external_request(
            *login,
            ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Ldap(
                LdapLoginObservation::observed(groups(true)),
            ))),
        );
        assert_eq!(
            failed.status,
            if mutation == "mount-recreated" {
                409
            } else {
                503
            }
        );
        assert!(failed.body.get("auth").is_none());
        assert_eq!(service.state_digest, before);
    }
    Ok(())
}
