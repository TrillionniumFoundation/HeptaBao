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
    assert_eq!(response.status, 200, "{:?}", response.body.get("errors"));
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
            LdapLoginObservation::native("Case Person", groups(true)),
        ))),
    );
    assert_eq!(response.status, 200, "{:?}", response.body.get("errors"));
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
    json!({"url":"ldaps://directory.example.test:636","binddn":"cn=manager,dc=example,dc=test","bindpass":"synthetic-manager-secret","userdn":"ou=people,dc=example,dc=test","userattr":"uid","groupdn":"ou=groups,dc=example,dc=test","token_ttl":120,"token_max_ttl":600})
}

#[test]
fn opaque_identity_alias_requires_schema23_without_native_ldap_configuration() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/local",
            &root_token,
            json!({"type":"userpass"})
        )
        .status,
        204
    );
    let mounts = call(&mut service, "GET", "sys/auth", &root_token, json!({}));
    let accessor = mounts.body["data"]["local/"]["accessor"]
        .as_str()
        .ok_or("missing local mount accessor")?
        .to_owned();
    let created = call(
        &mut service,
        "POST",
        "identity/entity",
        &root_token,
        json!({"name":"person"}),
    );
    assert_eq!(created.status, 200);
    let entity = created.body["data"]["id"]
        .as_str()
        .ok_or("missing entity")?
        .to_owned();
    let created = call(
        &mut service,
        "POST",
        "identity/entity-alias",
        &root_token,
        json!({"name":"研发 / Case Person","canonical_id":entity,"mount_accessor":accessor}),
    );
    assert_eq!(created.status, 200);
    let state = service.state.as_ref().ok_or("missing state")?;
    assert!(!state.auth.has_native_ldap_state());
    assert!(state.engines.has_opaque_identity_aliases());
    let mut older = state.clone();
    older.schema = 22;
    assert!(older.validate_format().is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let found = call(
        &mut service,
        "POST",
        "identity/lookup/entity",
        &root_token,
        json!({"alias_name":"研发 / Case Person","alias_mount_accessor":accessor}),
    );
    assert_eq!(found.status, 200);
    assert_eq!(found.body["data"]["id"], entity);
    Ok(())
}

#[test]
fn native_ldap_service_restart_schema_and_all_renewal_entries() -> TestResult {
    let root = Root::new();
    let Fixture {
        mut service,
        key,
        root_token,
        token,
        entity,
        group,
    } = fixture(&root)?;
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let mut downgraded = state.clone();
    downgraded.schema = 22;
    assert!(downgraded.validate_format().is_err());
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/ldap/config",
            &root_token,
            json!({})
        )
        .body["data"]
            .get("bindpass"),
        None
    );
    let before = service.state_digest;
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        110,
        None,
    )?;
    let rejected = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Err(Response::error(
            400,
            "LDAP login failed during renewal",
        ))),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(service.state_digest, before);
    drop(service);
    let mut service = root.service()?;
    enroll(&mut service)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let lookup = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115);
    let accessor = lookup.body["data"]["accessor"]
        .as_str()
        .ok_or("missing token accessor")?;
    for (index, (path, caller, body)) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":300}),
        ),
        (
            "auth/token/renew",
            root_token.as_str(),
            json!({"token":token,"increment":300}),
        ),
        (
            "auth/token/renew-accessor",
            root_token.as_str(),
            json!({"accessor":accessor,"increment":300}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let request = pending(&mut service, path, caller, body, 120 + index as u64, None)?;
        let renewed = accepted(&mut service, *request, index != 1);
        assert_eq!(renewed.status, 200);
        if index < 2 {
            assert_eq!(renewed.body["auth"]["client_token"], token);
        } else {
            assert!(renewed.body["auth"].get("client_token").is_none());
        }
        assert_eq!(renewed.body["auth"]["metadata"]["username"], "alice");
        assert_eq!(renewed.body["auth"]["entity_id"], entity);
    }
    let read = call(
        &mut service,
        "GET",
        &format!("identity/group/id/{group}"),
        &root_token,
        json!({}),
    );
    assert_eq!(read.body["data"]["member_entity_ids"], json!([entity]));
    Ok(())
}

#[test]
fn native_ldap_wrapper_and_external_groups_share_one_commit() -> TestResult {
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
    let wrapped = accepted(&mut service, *request, false);
    assert_eq!(wrapped.status, 200);
    assert!(wrapped.body["auth"].is_null());
    assert!(!wrapped.body.to_string().contains(&token));
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("missing wrapper")?;
    let unwrapped = service.handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 112);
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["auth"]["client_token"], token);
    assert_eq!(unwrapped.body["auth"]["identity_policies"], json!([]));
    let expiry = service
        .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115)
        .body["data"]["expire_time_unix"]
        .clone();
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":400}),
        115,
        Some(60),
    )?;
    let before = service.state_digest;
    service.state_capacity = 1;
    let rejected = accepted(&mut service, *request, true);
    assert_eq!(rejected.status, 507);
    assert_eq!(service.state_digest, before);
    assert!(rejected.body.get("auth").is_none());
    assert!(rejected.body.get("wrap_info").is_none());
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115)
            .body["data"]["expire_time_unix"],
        expiry
    );
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
fn native_ldap_renewal_fences_absent_mapping_identity_and_live_actor() -> TestResult {
    for mutation in [
        "mapping-appeared",
        "alias-renamed",
        "identity-disabled",
        "actor-revoked",
        "config",
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
        let changed = match mutation {
            "mapping-appeared" => call(
                &mut service,
                "POST",
                "auth/ldap/users/alice",
                &root_token,
                json!({"policies":["new"]}),
            ),
            "identity-disabled" => call(
                &mut service,
                "POST",
                &format!("identity/entity/id/{entity}"),
                &root_token,
                json!({"disabled":true}),
            ),
            "alias-renamed" => {
                let read = call(
                    &mut service,
                    "GET",
                    &format!("identity/entity/id/{entity}"),
                    &root_token,
                    json!({}),
                );
                let alias = &read.body["data"]["aliases"][0];
                let id = alias["id"].as_str().ok_or("missing alias")?;
                call(
                    &mut service,
                    "POST",
                    &format!("identity/entity-alias/id/{id}"),
                    &root_token,
                    json!({"name":"renamed","canonical_id":entity,"mount_accessor":alias["mount_accessor"]}),
                )
            }
            "actor-revoked" => call(
                &mut service,
                "POST",
                "auth/token/revoke-self",
                &root_token,
                json!({}),
            ),
            "config" => call(
                &mut service,
                "POST",
                "auth/ldap/config",
                &root_token,
                json!({"token_period":30}),
            ),
            _ => return Err("unknown mutation".into()),
        };
        assert!(changed.status < 300, "{mutation}");
        let before = service.state_digest;
        let rejected = accepted(&mut service, *request, false);
        assert!(rejected.status >= 400, "{mutation}");
        assert_eq!(service.state_digest, before, "{mutation}");
    }
    Ok(())
}

#[test]
fn native_ldap_login_does_not_cross_missing_mapping_mount_or_activation_fences() -> TestResult {
    for mutation in ["mapping", "mount", "activation"] {
        let root = Root::new();
        let Fixture {
            mut service,
            root_token,
            key,
            ..
        } = fixture(&root)?;
        let request = pending(
            &mut service,
            "auth/ldap/login/new-user",
            "",
            json!({"password":"synthetic-user-secret"}),
            110,
            None,
        )?;
        match mutation {
            "mapping" => {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "auth/ldap/users/new-user",
                        &root_token,
                        json!({"policies":["directory-only"]})
                    )
                    .status,
                    204
                );
            }
            "mount" => {
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
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "sys/auth/ldap",
                        &root_token,
                        json!({"type":"ldap"})
                    )
                    .status,
                    204
                );
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "auth/ldap/config",
                        &root_token,
                        config()
                    )
                    .status,
                    204
                );
            }
            "activation" => {
                assert_eq!(
                    call(&mut service, "POST", "sys/seal", &root_token, json!({})).status,
                    204
                );
                assert_eq!(
                    call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                    200
                );
            }
            _ => return Err("unknown mutation".into()),
        }
        let before = service.state_digest;
        let rejected = service.finish_external_request(
            *request,
            ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Ldap(
                LdapLoginObservation::native("new-user", groups(true)),
            ))),
        );
        assert!(rejected.status >= 400, "{mutation}");
        assert_eq!(service.state_digest, before, "{mutation}");
    }
    Ok(())
}
