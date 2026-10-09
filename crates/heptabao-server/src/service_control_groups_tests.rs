//! Actual ordinary Service boundaries; every credential and payload is synthetic.
use super::*;
use crate::service::tests::{Root, bootstrap};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Login {
    token: Zeroizing<String>,
    entity: String,
}
struct Fixture {
    root: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    requester: Login,
    first: Login,
    second: Login,
    outsider: Login,
    group: String,
}
fn call(
    service: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Response {
    service.handle_at(method, path, "", token, body, now)
}
fn observed_call(
    service: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
    precise: bool,
) -> TestResult<Response> {
    if !precise {
        return Ok(call(service, token, method, path, body, now));
    }
    let clock = RequestClock::anchored(
        std::time::Duration::new(now, 125_000_000),
        std::time::Instant::now(),
    )?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    Ok(service.finish_synchronous_request(execution))
}
fn short_login(f: &mut Fixture, name: &str, policy: &str) -> TestResult<Login> {
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            &format!("auth/cg-login/users/{name}"),
            json!({"password":"synthetic-cg-password","token_policies":[policy],
        "token_no_default_policy":true,"token_ttl":"10s","token_max_ttl":"10s"}),
            100
        )
        .status,
        204
    );
    let response = call(
        &mut f.service,
        "",
        "POST",
        &format!("auth/cg-login/login/{name}"),
        json!({"password":"synthetic-cg-password"}),
        100,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["lease_duration"], 10);
    Ok(Login {
        token: Zeroizing::new(text(&response.body, "/auth/client_token")?),
        entity: text(&response.body, "/auth/entity_id")?,
    })
}
fn text(value: &Value, pointer: &str) -> TestResult<String> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing synthetic fixture field")?
        .to_owned())
}
fn requester_policy(ttl: &str, extra: &str) -> String {
    format!(
        r#"path "secret/data/cg/*" {{
      capabilities = ["create", "update", "read"] {extra}
      control_group = {{ ttl = "{ttl}" factor "review" {{
        controlled_capabilities = ["update"]
        identity {{ group_names = ["cg-team"] approvals = 2 self_authorization = false }}
      }} }}
    }}
    path "sys/control-group/request" {{ capabilities = ["update"] }}
    path "sys/control-group/authorize" {{ capabilities = ["update"] }}"#
    )
}
fn policy_write(service: &mut Service, admin: &str, name: &str, policy: &str) {
    assert_eq!(
        call(
            service,
            admin,
            "POST",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":policy}),
            100
        )
        .status,
        204
    );
}
fn login(service: &mut Service, admin: &str, name: &str, policy: &str) -> TestResult<Login> {
    assert_eq!(call(service, admin, "POST", &format!("auth/cg-login/users/{name}"),
        json!({"password":"synthetic-cg-password","token_policies":[policy],"token_no_default_policy":true}), 100).status, 204);
    let response = call(
        service,
        "",
        "POST",
        &format!("auth/cg-login/login/{name}"),
        json!({"password":"synthetic-cg-password"}),
        100,
    );
    assert_eq!(response.status, 200);
    Ok(Login {
        token: Zeroizing::new(text(&response.body, "/auth/client_token")?),
        entity: text(&response.body, "/auth/entity_id")?,
    })
}
fn setup() -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let key = Zeroizing::new(key);
    let admin = Zeroizing::new(admin);
    assert_eq!(
        call(
            &mut service,
            &admin,
            "POST",
            "sys/auth/cg-login",
            json!({"type":"userpass"}),
            100
        )
        .status,
        204
    );
    policy_write(
        &mut service,
        &admin,
        "cg-requester",
        &requester_policy("60s", ""),
    );
    policy_write(
        &mut service,
        &admin,
        "cg-approver",
        r#"path "sys/control-group/request" { capabilities = ["update"] }
        path "sys/control-group/authorize" { capabilities = ["update"] }
        path "sys/wrapping/unwrap" { capabilities = ["update"] }"#,
    );
    let requester = login(&mut service, &admin, "requester", "cg-requester")?;
    let first = login(&mut service, &admin, "first", "cg-approver")?;
    let second = login(&mut service, &admin, "second", "cg-approver")?;
    let outsider = login(&mut service, &admin, "outsider", "cg-approver")?;
    let group = call(
        &mut service,
        &admin,
        "POST",
        "identity/group",
        json!({"name":"cg-team","type":"internal","member_entity_ids":[requester.entity,first.entity,second.entity]}),
        100,
    );
    assert_eq!(group.status, 200);
    let group = text(&group.body, "/data/id")?;
    Ok(Fixture {
        root,
        service,
        key,
        admin,
        requester,
        first,
        second,
        outsider,
        group,
    })
}
fn create(f: &mut Fixture) {
    let created = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"before"}}),
        100,
    );
    assert_eq!(created.status, 200);
    assert_eq!(created.body["data"]["version"], 1);
    assert!(created.body.get("wrap_info").is_none());
}
fn pending(f: &mut Fixture) -> TestResult<(Zeroizing<String>, String)> {
    let response = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"after"}}),
        100,
    );
    assert_eq!(response.status, 200);
    assert!(response.body["data"].is_null());
    assert_eq!(response.body["wrap_info"]["ttl"], 60);
    Ok((
        Zeroizing::new(text(&response.body, "/wrap_info/token")?),
        text(&response.body, "/wrap_info/accessor")?,
    ))
}
fn read(f: &mut Fixture, version: u64, value: &str, now: u64) {
    let response = call(
        &mut f.service,
        &f.admin,
        "GET",
        "secret/data/cg/key",
        json!({}),
        now,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["metadata"]["version"], version);
    assert_eq!(response.body["data"]["data"]["value"], value);
}
fn review_request(f: &mut Fixture, accessor: &str) -> Response {
    call(
        &mut f.service,
        &f.first.token,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
        100,
    )
}
fn approve_two(f: &mut Fixture, accessor: &str) {
    for token in [&f.first.token, &f.second.token] {
        assert_eq!(
            call(
                &mut f.service,
                token,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":accessor}),
                100
            )
            .status,
            200
        );
    }
    let reviewed = review_request(f, accessor);
    assert_eq!(reviewed.status, 200);
    assert_eq!(reviewed.body["data"]["approved"], true);
}
#[test]
fn cg270_userpass_quorum_defers_update_and_preapproval_preserves_single_claim() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let (wrapper, accessor) = pending(&mut f)?;
    read(&mut f, 1, "before", 100);
    let initial = review_request(&mut f, &accessor);
    assert_eq!(initial.status, 200);
    let data = initial.body["data"].as_object().ok_or("review data")?;
    assert_eq!(data.len(), 6);
    assert_eq!(data["approved"], false);
    assert_eq!(data["authorizations"], json!([]));
    assert_eq!(data["request_operation"], "update");
    assert_eq!(data["request_path"], "secret/data/cg/key");
    assert_eq!(data["request_data"], json!({"data":{"value":"after"}}));
    assert_eq!(data["request_entity"]["ID"], f.requester.entity);
    assert_eq!(data["request_entity"]["namespace_id"], "root");
    assert_eq!(data["request_entity"].as_object().ok_or("entity")?.len(), 4);
    // A contradictory token parameter must not consume the unapproved owner.
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({"token":f.admin.as_str()}),
            100,
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.outsider.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        review_request(&mut f, &accessor).body["data"]["authorizations"],
        json!([])
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.requester.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            100
        )
        .status,
        500
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.first.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.first.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            100
        )
        .status,
        500
    );
    let once = review_request(&mut f, &accessor);
    assert_eq!(once.body["data"]["approved"], false);
    assert_eq!(
        once.body["data"]["authorizations"]
            .as_array()
            .ok_or("approvals")?
            .len(),
        1
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.second.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            100
        )
        .status,
        200
    );
    read(&mut f, 1, "before", 100);
    let executed = call(
        &mut f.service,
        &wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["version"], 2);
    read(&mut f, 2, "after", 100);
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    read(&mut f, 2, "after", 100);
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        CONTROL_GROUP_STATE_SCHEMA
    );
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"
        path "secret/metadata/cg" { capabilities = ["list"]
          control_group = { ttl = "60s" factor "review" {
            identity { group_names = ["cg-team"] approvals = 2 }
          } }
        }"#,
    );
    let wire = Zeroizing::new(format!(
        "GET /v1/secret/metadata/cg?list=true HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\n\r\n",
        f.requester.token.as_str(),
    ).into_bytes());
    let (method, path, namespace, token, body) = crate::http::parsed_api_request_for_test(&wire)?;
    assert_eq!(method, "LIST");
    assert_eq!(path, "secret/metadata/cg");
    assert_eq!(namespace, "");
    assert_eq!(body.0["__heptabao_kv_read_query"]["wire_method"], "GET");
    let deferred_list = call(&mut f.service, &token, &method, &path, body.0.clone(), 100);
    assert_eq!(deferred_list.status, 200);
    let list_token = Zeroizing::new(text(&deferred_list.body, "/wrap_info/token")?);
    let list_accessor = text(&deferred_list.body, "/wrap_info/accessor")?;
    let list_review = review_request(&mut f, &list_accessor);
    assert_eq!(list_review.status, 200);
    assert_eq!(list_review.body["data"]["request_operation"], "list");
    assert_eq!(list_review.body["data"]["request_data"], json!({}));
    approve_two(&mut f, &list_accessor);
    let listed = call(
        &mut f.service,
        &list_token,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["key"]));
    read(&mut f, 2, "after", 100);
    // Actual policy API install of the complete pinned example. This is
    // docs/source-only until a future real runtime control executes it.
    let mut d = setup()?;
    for (name, members) in [
        ("admin", vec![d.first.entity.clone()]),
        (
            "superuser",
            vec![d.second.entity.clone(), d.outsider.entity.clone()],
        ),
    ] {
        assert_eq!(
            call(
                &mut d.service,
                &d.admin,
                "POST",
                "identity/group",
                json!({"name":name,"type":"internal","member_entity_ids":members}),
                100
            )
            .status,
            200
        );
    }
    assert_eq!(
        call(
            &mut d.service,
            &d.admin,
            "POST",
            "sys/mounts/kv",
            json!({"type":"kv","options":{"version":"1"}}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut d.service,
            &d.admin,
            "POST",
            "kv/key",
            json!({"value":"before"}),
            100
        )
        .status,
        204
    );
    policy_write(
        &mut d.service,
        &d.admin,
        "cg-requester",
        r#"path "kv/*" {
    capabilities = ["create","update","delete","list","sudo"]
    control_group = {
        factor "admin" {
            controlled_capabilities = ["delete","list","sudo"]
            identity {
                group_names = ["admin"]
                approvals = 1
            }
        }
    }
}
path "kv/*" {
    capabilities = ["create"]
    control_group = {
        factor "superuser" {
            identity {
                group_names = ["superuser"]
                approvals = 2
            }
        }
    }
}
"#,
    );
    let wire = Zeroizing::new(
        format!(
            "GET /v1/kv/?list=true HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\n\r\n",
            d.requester.token.as_str()
        )
        .into_bytes(),
    );
    let (method, path, namespace, token, body) = crate::http::parsed_api_request_for_test(&wire)?;
    assert_eq!(method, "LIST");
    assert_eq!(path, "kv/");
    assert_eq!(namespace, "");
    let pending_list = call(&mut d.service, &token, &method, &path, body.0.clone(), 100);
    assert_eq!(pending_list.status, 200);
    assert!(pending_list.body["data"].is_null());
    let wrap = Zeroizing::new(text(&pending_list.body, "/wrap_info/token")?);
    let access = text(&pending_list.body, "/wrap_info/accessor")?;
    let initial = review_request(&mut d, &access);
    assert_eq!(initial.status, 200);
    assert_eq!(initial.body["data"]["request_operation"], "list");
    assert_eq!(initial.body["data"]["request_path"], "kv/");
    assert_eq!(initial.body["data"]["request_data"], json!({}));
    assert_eq!(initial.body["data"]["approved"], false);
    for (who, expected_approved, approvals) in [
        ("admin", false, 1),
        ("super-first", false, 2),
        ("super-second", true, 3),
    ] {
        let approver = match who {
            "admin" => &d.first.token,
            "super-first" => &d.second.token,
            "super-second" => &d.outsider.token,
            _ => return Err("unknown duplicate-stanza approver".into()),
        };
        assert_eq!(
            call(
                &mut d.service,
                approver,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":access}),
                100
            )
            .status,
            200
        );
        let reviewed = review_request(&mut d, &access);
        assert_eq!(reviewed.status, 200);
        assert_eq!(reviewed.body["data"]["approved"], expected_approved);
        assert_eq!(
            reviewed.body["data"]["authorizations"]
                .as_array()
                .ok_or("authorizations")?
                .len(),
            approvals
        );
        let unchanged = call(&mut d.service, &d.admin, "GET", "kv/key", json!({}), 100);
        assert_eq!(unchanged.status, 200);
        assert_eq!(unchanged.body["data"], json!({"value":"before"}));
        if !expected_approved {
            assert_eq!(
                call(
                    &mut d.service,
                    &wrap,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100
                )
                .status,
                400
            );
        }
    }
    let list = call(
        &mut d.service,
        &wrap,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["keys"], json!(["key"]));
    assert_eq!(
        call(
            &mut d.service,
            &wrap,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    // UPDATE selects superuser only: its omitted subset controls UPDATE
    // despite its own stanza granting create; admin excludes UPDATE.
    let update = call(
        &mut d.service,
        &d.requester.token,
        "POST",
        "kv/key",
        json!({"value":"after"}),
        100,
    );
    assert_eq!(update.status, 200);
    assert!(update.body["data"].is_null());
    let wrap = Zeroizing::new(text(&update.body, "/wrap_info/token")?);
    let access = text(&update.body, "/wrap_info/accessor")?;
    assert_eq!(
        call(
            &mut d.service,
            &d.first.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":access}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        review_request(&mut d, &access).body["data"]["authorizations"],
        json!([])
    );
    for (who, expected_approved) in [("first", false), ("second", true)] {
        let approver = if who == "first" {
            &d.second.token
        } else {
            &d.outsider.token
        };
        assert_eq!(
            call(
                &mut d.service,
                approver,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":access}),
                100
            )
            .status,
            200
        );
        assert_eq!(
            review_request(&mut d, &access).body["data"]["approved"],
            expected_approved
        );
        let unchanged = call(&mut d.service, &d.admin, "GET", "kv/key", json!({}), 100);
        assert_eq!(unchanged.status, 200);
        assert_eq!(unchanged.body["data"], json!({"value":"before"}));
    }
    assert_eq!(
        call(
            &mut d.service,
            &wrap,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut d.service,
            &wrap,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    let updated = call(&mut d.service, &d.admin, "GET", "kv/key", json!({}), 100);
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["data"], json!({"value":"after"}));
    Ok(())
}
#[test]
fn cg270_live_actor_policy_token_entity_and_group_revocation_prevent_effects() -> TestResult {
    for cause in [
        "policy",
        "token",
        "entity",
        "group",
        "approver-policy",
        "approver-token",
        "approver-entity",
    ] {
        let mut f = setup()?;
        create(&mut f);
        let (wrapper, accessor) = pending(&mut f)?;
        approve_two(&mut f, &accessor);
        match cause {
            "policy" => policy_write(
                &mut f.service,
                &f.admin,
                "cg-requester",
                r#"path "secret/data/cg/*" { capabilities = ["read"] }"#,
            ),
            "token" => assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    "auth/token/revoke",
                    json!({"token":f.requester.token.as_str()}),
                    100
                )
                .status,
                204
            ),
            "entity" => assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    &format!("identity/entity/id/{}", f.requester.entity),
                    json!({"disabled":true}),
                    100
                )
                .status,
                204
            ),
            "group" => assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    &format!("identity/group/id/{}", f.group),
                    json!({"member_entity_ids":[f.requester.entity,f.first.entity]}),
                    100
                )
                .status,
                204
            ),
            "approver-policy" => policy_write(
                &mut f.service,
                &f.admin,
                "cg-approver",
                r#"path "sys/control-group/request" { capabilities = ["update"] }"#,
            ),
            "approver-token" => assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    "auth/token/revoke",
                    json!({"token":f.first.token.as_str()}),
                    100,
                )
                .status,
                204
            ),
            "approver-entity" => assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    &format!("identity/entity/id/{}", f.first.entity),
                    json!({"disabled":true}),
                    100,
                )
                .status,
                204
            ),
            _ => return Err("unknown synthetic revocation".into()),
        }
        let rejected = call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100,
        );
        assert_eq!(
            rejected.status,
            if cause == "group" || cause.starts_with("approver-") {
                400
            } else {
                403
            }
        );
        read(&mut f, 1, "before", 100);
    }
    Ok(())
}
#[test]
fn cg270_group_recreation_and_secret_mount_incarnation_cannot_inherit_old_approval() -> TestResult {
    for cause in ["group", "mount"] {
        let mut f = setup()?;
        create(&mut f);
        let (wrapper, accessor) = pending(&mut f)?;
        approve_two(&mut f, &accessor);
        if cause == "group" {
            assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "DELETE",
                    &format!("identity/group/id/{}", f.group),
                    json!({}),
                    100
                )
                .status,
                204
            );
            let recreated = call(
                &mut f.service,
                &f.admin,
                "POST",
                "identity/group",
                json!({"name":"cg-team","member_entity_ids":[f.first.entity,f.second.entity]}),
                100,
            );
            assert_eq!(recreated.status, 200);
            assert!(text(&recreated.body, "/data/id")? != f.group);
            assert_eq!(
                call(
                    &mut f.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100
                )
                .status,
                400
            );
            read(&mut f, 1, "before", 100);
        } else {
            assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "DELETE",
                    "sys/mounts/secret",
                    json!({}),
                    100
                )
                .status,
                204
            );
            assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    "sys/mounts/secret",
                    json!({"type":"kv","options":{"version":"2"}}),
                    100
                )
                .status,
                204
            );
            assert_eq!(
                call(
                    &mut f.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100
                )
                .status,
                403
            );
            assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "GET",
                    "secret/data/cg/key",
                    json!({}),
                    100
                )
                .status,
                404
            );
        }
    }
    Ok(())
}
#[test]
fn cg270_encrypted_restart_expiry_and_irreversible118_reader_snapshot_floor() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let (wrapper, accessor) = pending(&mut f)?;
    let closed_state = f.service.state.as_ref().ok_or("state")?;
    assert_eq!(closed_state.schema, CONTROL_GROUP_STATE_SCHEMA);
    assert!(supported_reader_schema(116));
    assert!(!supported_reader_schema(CONTROL_GROUP_STATE_SCHEMA + 1));
    assert!(supported_reader_schema(118));
    let mut wrong = closed_state.clone();
    wrong.schema = 116;
    assert_eq!(
        wrong
            .validate_format()
            .err()
            .ok_or("format downgrade missing")?
            .status,
        503
    );
    assert_eq!(
        wrong
            .validate_publication_schema(Some(closed_state))
            .err()
            .ok_or("publication downgrade missing")?
            .status,
        503
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(closed_state, &wrong)
            .err()
            .ok_or("snapshot downgrade missing")?
            .status,
        400
    );
    drop(f.service);
    f.service = f.root.service()?;
    assert_eq!(
        call(
            &mut f.service,
            "",
            "POST",
            "sys/unseal",
            json!({"key":f.key.as_str()}),
            100
        )
        .status,
        200
    );
    approve_two(&mut f, &accessor);
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            160
        )
        .status,
        400
    );
    read(&mut f, 1, "before", 160);
    let current = f.service.state.as_ref().ok_or("state")?;
    assert_eq!(current.schema, 118);
    assert!(current.auth.has_control_group_state());
    drop(f.service);
    f.service = f.root.service()?;
    assert_eq!(
        call(
            &mut f.service,
            "",
            "POST",
            "sys/unseal",
            json!({"key":f.key.as_str()}),
            161
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            159
        )
        .status,
        400
    );
    read(&mut f, 1, "before", 161);
    // Shape-valid stale 118 snapshots/publications cannot roll back the
    // persistent approval floor, even after the owner has expired.
    let mut stale = serde_json::to_value(f.service.state.as_ref().ok_or("state")?)?;
    stale["auth"]["control_groups"]["clock"] = json!(100);
    let stale: State = serde_json::from_value(stale)?;
    let current = f.service.state.as_ref().ok_or("state")?;
    assert!(stale.validate_format().is_ok());
    assert_eq!(
        stale
            .validate_publication_schema(Some(current))
            .err()
            .ok_or("clock publication rollback")?
            .status,
        503
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(current, &stale)
            .err()
            .ok_or("clock snapshot rollback")?
            .status,
        400
    );
    let mut retired = serde_json::to_value(current)?;
    retired["auth"]["control_groups"] = json!({"floor":false,"clock":0,"requests":{}});
    retired["auth"]["policies"] = json!({});
    let retired: State = serde_json::from_value(retired)?;
    assert!(retired.validate_format().is_ok());
    assert_eq!(
        retired
            .validate_publication_schema(Some(current))
            .err()
            .ok_or("custody floor rollback")?
            .status,
        503
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(current, &retired)
            .err()
            .ok_or("custody snapshot rollback")?
            .status,
        400
    );

    for precise in [false, true] {
        for short_actor in [false, true] {
            let mut f = setup()?;
            create(&mut f);
            if short_actor {
                let login = short_login(&mut f, "requester", "cg-requester")?;
                assert_eq!(login.entity, f.requester.entity);
                f.requester = login;
            } else {
                let first = short_login(&mut f, "first", "cg-approver")?;
                let second = short_login(&mut f, "second", "cg-approver")?;
                assert_eq!(first.entity, f.first.entity);
                assert_eq!(second.entity, f.second.entity);
                f.first = first;
                f.second = second;
            }
            let (wrapper, accessor) = pending(&mut f)?;
            approve_two(&mut f, &accessor);
            let review = observed_call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/control-group/request",
                json!({"accessor":accessor}),
                111,
                precise,
            )?;
            assert_eq!(review.status, 200);
            assert_eq!(review.body["data"]["approved"], short_actor);
            assert_eq!(
                review.body["data"]["authorizations"]
                    .as_array()
                    .ok_or("live approvals")?
                    .len(),
                if short_actor { 2 } else { 0 }
            );
            let state = f.service.state.as_ref().ok_or("state")?;
            assert_eq!(state.auth.control_group_time(105), 111);
            let encoded = Zeroizing::new(serde_json::to_vec(&*state.auth)?);
            let auth: Value = serde_json::from_slice(&encoded)?;
            assert!(
                auth["token_api_observed_at"].is_null(),
                "this userpass fixture must not borrow a token API clock floor"
            );
            drop(f.service);
            f.service = f.root.service()?;
            assert_eq!(
                call(
                    &mut f.service,
                    "",
                    "POST",
                    "sys/unseal",
                    json!({"key":f.key.as_str()}),
                    105
                )
                .status,
                200
            );
            assert_eq!(
                f.service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .auth
                    .control_group_time(105),
                111
            );
            let denied = observed_call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                105,
                precise,
            )?;
            assert_eq!(denied.status, if short_actor { 403 } else { 400 });
            assert!(denied.body.get("wrap_info").is_none());
            assert_eq!(
                f.service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .auth
                    .control_group_request_count_for_test(),
                1
            );
            read(&mut f, 1, "before", 111);
            let review = observed_call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/control-group/request",
                json!({"accessor":accessor}),
                105,
                precise,
            )?;
            assert_eq!(review.status, 200);
            assert_eq!(review.body["data"]["approved"], short_actor);
            assert_eq!(
                observed_call(
                    &mut f.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    105,
                    precise
                )?
                .status,
                if short_actor { 403 } else { 400 }
            );
            read(&mut f, 1, "before", 111);
        }
    }

    // Strict logical-state admission rederives transport before storage write.
    let mut f = setup()?;
    create(&mut f);
    let (_wrapper, _) = pending(&mut f)?;
    for field in ["transport_path", "transport_body", "capability"] {
        let mut forged = serde_json::to_value(f.service.state.as_ref().ok_or("state")?)?;
        let owners = forged["auth"]["control_groups"]["requests"]
            .as_object_mut()
            .ok_or("requests")?;
        assert_eq!(owners.len(), 1);
        let owner = owners.values_mut().next().ok_or("owner")?;
        match field {
            "transport_path" => owner[field] = json!("secret/data/cg/different"),
            "transport_body" => owner[field] = json!({"data":{"value":"forged"}}),
            _ => owner[field] = json!("read"),
        }
        let mut forged: State = serde_json::from_value(forged)?;
        assert_eq!(
            forged
                .validate_format()
                .err()
                .ok_or("transport format")?
                .status,
            503
        );
        assert_eq!(
            forged
                .validate_publication_schema(f.service.state.as_ref())
                .err()
                .ok_or("transport publication")?
                .status,
            503
        );
        assert_eq!(
            f.service
                .commit_state(&mut forged)
                .err()
                .ok_or("transport commit")?
                .status,
            503
        );
        read(&mut f, 1, "before", 100);
    }
    // Original GET/list carrier remains request-local while a bare exact
    // registered KV1 root gains its canonical slash. A retired owner retains
    // its typed syntax basis without gaining a replacement mount's authority.
    for (marker, expected_method, expected_capability) in
        [("list", "LIST", "list"), ("scan", "SCAN", "scan")]
    {
        let mut f = setup()?;
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/mounts/cg-kv1",
                json!({"type":"kv","options":{"version":"1"}}),
                100
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "cg-kv1/key",
                json!({"value":"original"}),
                100
            )
            .status,
            204
        );
        policy_write(
            &mut f.service,
            &f.admin,
            "cg-requester",
            r#"
        path "cg-kv1/" { capabilities = ["list","scan"]
          control_group = { ttl = "60s" factor "review" {
            identity { group_names = ["cg-team"] approvals = 2 }
          } }
        }
        path "sys/control-group/request" { capabilities = ["update"] }
        path "sys/control-group/authorize" { capabilities = ["update"] }
    "#,
        );
        let wire = Zeroizing::new(
        format!(
            "GET /v1/cg-kv1?{marker}=true HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\n\r\n",
            f.requester.token.as_str()
        )
        .into_bytes(),
    );
        let (method, path, namespace, token, body) =
            crate::http::parsed_api_request_for_test(&wire)?;
        assert_eq!(method, expected_method);
        assert_eq!(path, "cg-kv1");
        assert_eq!(namespace, "");
        let pending = call(&mut f.service, &token, &method, &path, body.0.clone(), 100);
        assert_eq!(pending.status, 200);
        let wrapper = Zeroizing::new(text(&pending.body, "/wrap_info/token")?);
        let accessor = text(&pending.body, "/wrap_info/accessor")?;
        let review = review_request(&mut f, &accessor);
        assert_eq!(review.status, 200);
        assert_eq!(review.body["data"]["request_path"], "cg-kv1/");
        assert_eq!(review.body["data"]["request_data"], json!({}));
        assert_eq!(
            review.body["data"]["request_operation"],
            expected_capability
        );
        approve_two(&mut f, &accessor);
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "DELETE",
                "sys/mounts/cg-kv1",
                json!({}),
                100
            )
            .status,
            204
        );
        assert!(
            f.service
                .state
                .as_ref()
                .ok_or("state")?
                .validate_format()
                .is_ok()
        );
        assert_eq!(review_request(&mut f, &accessor).status, 403);
        drop(f.service);
        f.service = f.root.service()?;
        assert_eq!(
            call(
                &mut f.service,
                "",
                "POST",
                "sys/unseal",
                json!({"key":f.key.as_str()}),
                100
            )
            .status,
            200
        );
        assert!(
            f.service
                .state
                .as_ref()
                .ok_or("state")?
                .validate_format()
                .is_ok()
        );
        assert_eq!(review_request(&mut f, &accessor).status, 403);
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/mounts/cg-kv1",
                json!({"type":"kv","options":{"version":"1"}}),
                100
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "cg-kv1/key",
                json!({"value":"replacement"}),
                100
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                100
            )
            .status,
            403
        );
        let untouched = call(
            &mut f.service,
            &f.admin,
            "GET",
            "cg-kv1/key",
            json!({}),
            100,
        );
        assert_eq!(untouched.status, 200);
        assert_eq!(untouched.body["data"]["value"], "replacement");
        assert_eq!(
            f.service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .control_group_request_count_for_test(),
            1
        );
    }
    Ok(())
}
#[test]
fn cg270_denied_parameter_and_capability_never_create_deferred_request_or_write_kv() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        &requester_policy("60s", "required_parameters = [\"required\"]"),
    );
    let denied = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"after"}}),
        100,
    );
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("wrap_info").is_none());
    read(&mut f, 1, "before", 100);
    let control_count = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .control_group_request_count_for_test();
    assert_eq!(control_count, 0);
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"path "secret/data/cg/*" {
      capabilities = ["read"] control_group = { ttl = "60s" factor "review" {
        identity { group_names = ["cg-team"] approvals = 2 }
      } }
    }"#,
    );
    let denied = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"after"}}),
        100,
    );
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("wrap_info").is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_request_count_for_test(),
        0
    );
    read(&mut f, 1, "before", 100);
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        &format!(
            "{} path \"sys/workflows/execute/cg\" {{ capabilities = [\"update\"] }}",
            requester_policy("60s", ""),
        ),
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/workflows/manage/cg",
            json!({"steps":[{"name":"attempt","method":"POST","path":"secret/data/cg/key",
            "body":{"data":{"value":"workflow-bypass"}},"allow_failure":true}],"outputs":{}}),
            100
        )
        .status,
        200
    );
    let blocked = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/workflows/execute/cg",
        json!({}),
        100,
    );
    assert_eq!(blocked.status, 400);
    assert!(blocked.body.get("wrap_info").is_none());
    read(&mut f, 1, "before", 100);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_request_count_for_test(),
        0
    );
    let (wrapper, accessor) = pending(&mut f)?;
    approve_two(&mut f, &accessor);
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        200
    );
    read(&mut f, 2, "after", 100);
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/auth/cg-target",
            json!({"type":"userpass","description":"before"}),
            100
        )
        .status,
        204
    );
    let tune_policy = |caps: &str, controlled: &str| {
        format!(
            r#"
        path "sys/auth/cg-target/tune" {{ capabilities = [{caps}]
          control_group = {{ ttl = "60s" factor "sudo-review" {{
            {controlled}
            identity {{ group_names = ["cg-team"] approvals = 2 }}
          }} }}
        }}
        path "sys/control-group/request" {{ capabilities = ["update"] }}
        path "sys/control-group/authorize" {{ capabilities = ["update"] }}
    "#
        )
    };
    // Ordinary update is insufficient on this real update+sudo route.
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        &tune_policy("\"read\",\"update\"", ""),
    );
    let denied = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/auth/cg-target/tune",
        json!({"description":"after"}),
        100,
    );
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("wrap_info").is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_request_count_for_test(),
        0
    );
    let before = call(
        &mut f.service,
        &f.admin,
        "GET",
        "sys/auth/cg-target/tune",
        json!({}),
        100,
    );
    assert_eq!(before.status, 200);
    assert_eq!(before.body["data"]["description"], "before");
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        &tune_policy(
            "\"read\",\"update\",\"sudo\"",
            "controlled_capabilities = [\"sudo\"]",
        ),
    );
    let pending = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/auth/cg-target/tune",
        json!({"description":"after"}),
        100,
    );
    assert_eq!(pending.status, 200);
    assert!(pending.body["data"].is_null());
    let wrapper = Zeroizing::new(text(&pending.body, "/wrap_info/token")?);
    let accessor = text(&pending.body, "/wrap_info/accessor")?;
    let review = review_request(&mut f, &accessor);
    assert_eq!(review.status, 200);
    assert_eq!(review.body["data"]["request_operation"], "update");
    assert_eq!(
        review.body["data"]["request_path"],
        "sys/auth/cg-target/tune"
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "GET",
            "sys/auth/cg-target/tune",
            json!({}),
            100
        )
        .body["data"]["description"],
        "before"
    );
    // A system POST owner cannot relabel itself read or erase its sudo need.
    for field in ["capability", "requires_sudo"] {
        let mut forged = serde_json::to_value(f.service.state.as_ref().ok_or("state")?)?;
        let owners = forged["auth"]["control_groups"]["requests"]
            .as_object_mut()
            .ok_or("requests")?;
        let owner = owners.values_mut().next().ok_or("owner")?;
        owner[field] = if field == "capability" {
            json!("read")
        } else {
            json!(false)
        };
        let forged: State = serde_json::from_value(forged)?;
        assert_eq!(
            forged
                .validate_format()
                .err()
                .ok_or("system owner binding")?
                .status,
            503
        );
        assert_eq!(
            forged
                .validate_publication_schema(f.service.state.as_ref())
                .err()
                .ok_or("system publication")?
                .status,
            503
        );
    }
    approve_two(&mut f, &accessor);
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        204
    );
    let after = call(
        &mut f.service,
        &f.admin,
        "GET",
        "sys/auth/cg-target/tune",
        json!({}),
        100,
    );
    assert_eq!(after.status, 200);
    assert_eq!(after.body["data"]["description"], "after");
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "GET",
            "sys/auth/cg-target/tune",
            json!({}),
            100
        )
        .body["data"]["description"],
        "after"
    );
    Ok(())
}

// The deferred owner grants only the action already admitted by its requester.
// Batch request/approval custody remains unsupported and must never write data.
#[test]
fn cg270_last_use_request_authority_resumes_once_and_batch_requesters_fail_closed() -> TestResult {
    let mut f = setup()?;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "secret/data/cg/key",
            json!({"data":{"value":"before"}}),
            100
        )
        .status,
        200
    );
    assert_eq!(call(&mut f.service, &f.admin, "POST", "auth/cg-login/users/finite",
        json!({"password":"synthetic-cg-password","token_policies":["cg-requester"],"token_no_default_policy":true,"token_num_uses":1}), 100).status, 204);
    let finite_login = call(
        &mut f.service,
        "",
        "POST",
        "auth/cg-login/login/finite",
        json!({"password":"synthetic-cg-password"}),
        100,
    );
    assert_eq!(finite_login.status, 200);
    let finite = Login {
        token: Zeroizing::new(text(&finite_login.body, "/auth/client_token")?),
        entity: text(&finite_login.body, "/auth/entity_id")?,
    };
    assert_eq!(call(&mut f.service, &f.admin, "POST", &format!("identity/group/id/{}", f.group),
        json!({"member_entity_ids":[finite.entity,f.requester.entity,f.first.entity,f.second.entity]}), 100).status, 204);
    let deferred = call(
        &mut f.service,
        &finite.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"after"}}),
        100,
    );
    assert_eq!(deferred.status, 200);
    let wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let accessor = text(&deferred.body, "/wrap_info/accessor")?;
    assert_eq!(
        call(
            &mut f.service,
            &finite.token,
            "GET",
            "secret/data/cg/key",
            json!({}),
            100
        )
        .status,
        403
    );
    read(&mut f, 1, "before", 100);
    approve_two(&mut f, &accessor);
    let executed = call(
        &mut f.service,
        &wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(executed.status, 200);
    assert_eq!(executed.body["data"]["version"], 2);
    read(&mut f, 2, "after", 100);
    assert_eq!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );

    for (name, policy, requester) in [
        ("batch-requester", "cg-requester", true),
        ("batch-approver", "cg-approver", false),
    ] {
        assert_eq!(call(&mut f.service, &f.admin, "POST", &format!("auth/cg-login/users/{name}"),
            json!({"password":"synthetic-cg-password","token_policies":[policy],"token_no_default_policy":true,"token_type":"batch"}), 100).status, 204);
        let login = call(
            &mut f.service,
            "",
            "POST",
            &format!("auth/cg-login/login/{name}"),
            json!({"password":"synthetic-cg-password"}),
            100,
        );
        assert_eq!(login.status, 200);
        let token = Zeroizing::new(text(&login.body, "/auth/client_token")?);
        let batch_entity = text(&login.body, "/auth/entity_id")?;
        assert!(token.starts_with("hvb."));
        assert_eq!(call(&mut f.service, &f.admin, "POST", &format!("identity/group/id/{}", f.group),
            json!({"member_entity_ids":[batch_entity,f.requester.entity,f.first.entity,f.second.entity]}), 100).status, 204);
        if requester {
            let denied = call(
                &mut f.service,
                &token,
                "POST",
                "secret/data/cg/key",
                json!({"data":{"value":"batch-after"}}),
                100,
            );
            assert_eq!(denied.status, 403);
            assert!(denied.body.get("wrap_info").is_none());
            read(&mut f, 2, "after", 100);
        } else {
            let (wrapper, accessor) = pending(&mut f)?;
            assert_eq!(
                call(
                    &mut f.service,
                    &token,
                    "POST",
                    "sys/control-group/authorize",
                    json!({"accessor":accessor}),
                    100
                )
                .status,
                403
            );
            assert_eq!(
                review_request(&mut f, &accessor).body["data"]["authorizations"],
                json!([])
            );
            read(&mut f, 2, "after", 100);
            approve_two(&mut f, &accessor);
            assert_eq!(
                call(
                    &mut f.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100
                )
                .status,
                200
            );
            read(&mut f, 3, "after", 100);
        }
    }
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"
      path "auth/token/lookup-self" { capabilities = ["read"]
        control_group = { ttl = "60s" factor "review" {
          identity { group_names = ["cg-team"] approvals = 2 }
        } }
      }"#,
    );
    let unavailable = call(
        &mut f.service,
        &f.requester.token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    );
    assert_eq!(unavailable.status, 400);
    assert!(unavailable.body.get("wrap_info").is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_request_count_for_test(),
        0
    );
    Ok(())
}
