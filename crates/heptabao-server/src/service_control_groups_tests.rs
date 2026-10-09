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
fn batch_login(f: &mut Fixture, name: &str, policy: &str, ttl: &str) -> TestResult<Login> {
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            &format!("auth/cg-login/users/{name}"),
            json!({"password":"synthetic-cg-password","token_policies":[policy],
            "token_no_default_policy":true,"token_type":"batch","token_ttl":ttl,
            "token_max_ttl":ttl}),
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
    assert_eq!(response.body["auth"]["token_type"], "batch");
    let token = Zeroizing::new(text(&response.body, "/auth/client_token")?);
    assert!(token.starts_with("hvb."));
    Ok(Login {
        token,
        entity: text(&response.body, "/auth/entity_id")?,
    })
}
fn assert_raw_absent(f: &Fixture, raw: &str) -> TestResult {
    let encoded = Zeroizing::new(serde_json::to_vec(
        f.service.state.as_ref().ok_or("state")?,
    )?);
    assert!(
        !encoded
            .windows(raw.len())
            .any(|window| window == raw.as_bytes()),
        "CG persistent state must contain only issuer ciphertext, never the raw credential"
    );
    Ok(())
}
fn scoped_call(
    f: &mut Fixture,
    namespace: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Response {
    f.service
        .handle_at(method, path, namespace, token, body, now)
}
fn scoped_credentials(f: &mut Fixture, namespace: &str) -> TestResult<(Login, Login, Login)> {
    let admin = Zeroizing::new(f.admin.to_string());
    assert_eq!(
        scoped_call(
            f,
            namespace,
            &admin,
            "POST",
            "sys/auth/cg-login",
            json!({"type":"userpass"}),
            100
        )
        .status,
        204
    );
    let policy = r#"path "auth/token/lookup-self" {
      capabilities = ["read"] control_group = { ttl = "60s" factor "review" {
        identity { group_names = ["cg-team"] approvals = 2 }
      } }
    }"#;
    for (name, body) in [
        ("cg-requester", policy),
        (
            "cg-approver",
            r#"path "sys/control-group/request" { capabilities = ["update"] }
          path "sys/control-group/authorize" { capabilities = ["update"] }"#,
        ),
    ] {
        assert_eq!(
            scoped_call(
                f,
                namespace,
                &admin,
                "POST",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":body}),
                100
            )
            .status,
            204
        );
    }
    let mut logins = Vec::new();
    for (name, role, kind) in [
        ("requester", "cg-requester", "batch"),
        ("first", "cg-approver", "service"),
        ("second", "cg-approver", "service"),
    ] {
        assert_eq!(
            scoped_call(
                f,
                namespace,
                &admin,
                "POST",
                &format!("auth/cg-login/users/{name}"),
                json!({"password":"synthetic-cg-password","token_policies":[role],
                "token_no_default_policy":true,"token_type":kind,
                "token_ttl":"60s","token_max_ttl":"60s"}),
                100
            )
            .status,
            204
        );
        let response = scoped_call(
            f,
            namespace,
            "",
            "POST",
            &format!("auth/cg-login/login/{name}"),
            json!({"password":"synthetic-cg-password"}),
            100,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["token_type"], kind);
        logins.push(Login {
            token: Zeroizing::new(text(&response.body, "/auth/client_token")?),
            entity: text(&response.body, "/auth/entity_id")?,
        });
    }
    let second = logins.pop().ok_or("second")?;
    let first = logins.pop().ok_or("first")?;
    let requester = logins.pop().ok_or("requester")?;
    assert!(requester.token.starts_with("hvb."));
    assert_eq!(
        scoped_call(
            f,
            namespace,
            &admin,
            "POST",
            "identity/group",
            json!({"name":"cg-team","type":"internal","member_entity_ids":[
            requester.entity, first.entity, second.entity]}),
            100
        )
        .status,
        200
    );
    Ok((requester, first, second))
}
fn scoped_approvals(
    f: &mut Fixture,
    namespace: &str,
    accessor: &str,
    first: &Login,
    second: &Login,
) {
    for token in [&first.token, &second.token] {
        assert_eq!(
            scoped_call(
                f,
                namespace,
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
    let admin = Zeroizing::new(f.admin.to_string());
    let reviewed = scoped_call(
        f,
        namespace,
        &admin,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
        100,
    );
    assert_eq!(reviewed.status, 200);
    assert_eq!(reviewed.body["data"]["approved"], true);
}
fn restart(mut f: Fixture, now: u64) -> TestResult<Fixture> {
    drop(f.service);
    f.service = f.root.service()?;
    assert_eq!(
        call(
            &mut f.service,
            "",
            "POST",
            "sys/unseal",
            json!({"key":f.key.as_str()}),
            now
        )
        .status,
        200
    );
    Ok(f)
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
    assert!(!supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1));
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
// Batch request/approval and self echo use sealed issuer custody, never public authority.
#[test]
fn cg270_last_use_resumes_once_and_batch_self_echo_use_sealed_issuer_custody() -> TestResult {
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

    for origin in ["native", "parented"] {
        for requester in [true, false] {
            for cause in ["success", "policy", "entity", "expiry", "parent", "group"] {
                if cause == "group" && requester {
                    continue;
                }
                if origin == "native" && cause == "parent" {
                    continue;
                }
                let mut b = setup()?;
                create(&mut b);
                let role = if requester {
                    "cg-requester"
                } else {
                    "cg-approver"
                };
                let parent = Zeroizing::new(if requester {
                    b.requester.token.to_string()
                } else {
                    b.first.token.to_string()
                });
                let expected_entity = if requester {
                    b.requester.entity.clone()
                } else {
                    b.first.entity.clone()
                };
                let ttl = if cause == "expiry" { "10s" } else { "60s" };
                let batch = if origin == "native" {
                    batch_login(
                        &mut b,
                        if requester { "requester" } else { "first" },
                        role,
                        ttl,
                    )?
                } else {
                    let policy = if requester {
                        format!(
                            "{}\npath \"auth/token/create\" {{ capabilities = [\"update\"] }}",
                            requester_policy("60s", "")
                        )
                    } else {
                        r#"path "sys/control-group/request" { capabilities = ["update"] }
                        path "sys/control-group/authorize" { capabilities = ["update"] }
                        path "sys/wrapping/unwrap" { capabilities = ["update"] }
                        path "auth/token/create" { capabilities = ["update"] }"#
                            .into()
                    };
                    policy_write(&mut b.service, &b.admin, role, &policy);
                    let response = call(
                        &mut b.service,
                        &parent,
                        "POST",
                        "auth/token/create",
                        json!({"type":"batch","policies":[role],"no_default_policy":true,"ttl":ttl}),
                        100,
                    );
                    assert_eq!(response.status, 200);
                    assert_eq!(response.body["auth"]["token_type"], "batch");
                    let token = Zeroizing::new(text(&response.body, "/auth/client_token")?);
                    assert!(token.starts_with("hvb."));
                    Login {
                        token,
                        entity: text(&response.body, "/auth/entity_id")?,
                    }
                };
                assert_eq!(batch.entity, expected_entity);
                let raw = Zeroizing::new(batch.token.to_string());
                if requester {
                    b.requester = batch;
                } else {
                    b.first = batch;
                }
                let (wrapper, accessor) = pending(&mut b)?;
                read(&mut b, 1, "before", 100);
                assert_raw_absent(&b, &raw)?;
                assert_eq!(
                    call(
                        &mut b.service,
                        &wrapper,
                        "POST",
                        "sys/wrapping/unwrap",
                        json!({}),
                        100
                    )
                    .status,
                    400
                );
                approve_two(&mut b, &accessor);
                read(&mut b, 1, "before", 100);
                assert_raw_absent(&b, &raw)?;
                match cause {
                    "policy" => policy_write(
                        &mut b.service,
                        &b.admin,
                        role,
                        if requester {
                            r#"path "secret/data/cg/*" { capabilities = ["read"] }"#
                        } else {
                            r#"path "sys/control-group/request" { capabilities = ["update"] }"#
                        },
                    ),
                    "entity" => assert_eq!(
                        call(
                            &mut b.service,
                            &b.admin,
                            "POST",
                            &format!("identity/entity/id/{expected_entity}"),
                            json!({"disabled":true}),
                            100
                        )
                        .status,
                        204
                    ),
                    "parent" => assert_eq!(
                        call(
                            &mut b.service,
                            &b.admin,
                            "POST",
                            "auth/token/revoke",
                            json!({"token":parent.as_str()}),
                            100
                        )
                        .status,
                        204
                    ),
                    "group" => {
                        let remaining = [b.requester.entity.clone(), b.second.entity.clone()];
                        assert_eq!(
                            call(
                                &mut b.service,
                                &b.admin,
                                "POST",
                                &format!("identity/group/id/{}", b.group),
                                json!({"member_entity_ids":remaining}),
                                100
                            )
                            .status,
                            204
                        );
                        let reviewed = review_request(&mut b, &accessor);
                        assert_eq!(reviewed.status, 200);
                        assert_eq!(reviewed.body["data"]["approved"], false);
                    }
                    "expiry" => {
                        let reviewed = call(
                            &mut b.service,
                            &b.admin,
                            "POST",
                            "sys/control-group/request",
                            json!({"accessor":accessor}),
                            111,
                        );
                        assert_eq!(reviewed.status, 200);
                        assert_eq!(reviewed.body["data"]["approved"], requester);
                        assert_eq!(
                            b.service
                                .state
                                .as_ref()
                                .ok_or("state")?
                                .auth
                                .control_group_time(105),
                            111
                        );
                    }
                    "success" => {}
                    _ => return Err("unknown batch CG cause".into()),
                }
                b = restart(b, if cause == "expiry" { 105 } else { 100 })?;
                let executed = call(
                    &mut b.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    if cause == "expiry" { 105 } else { 100 },
                );
                if cause == "success" {
                    assert_eq!(executed.status, 200);
                    assert_eq!(executed.body["data"]["version"], 2);
                    read(&mut b, 2, "after", 100);
                    assert_eq!(
                        call(
                            &mut b.service,
                            &wrapper,
                            "POST",
                            "sys/wrapping/unwrap",
                            json!({}),
                            100
                        )
                        .status,
                        400
                    );
                    read(&mut b, 2, "after", 100);
                } else {
                    assert_eq!(executed.status, if requester { 403 } else { 400 });
                    assert!(executed.body.get("wrap_info").is_none());
                    read(
                        &mut b,
                        1,
                        "before",
                        if cause == "expiry" { 111 } else { 100 },
                    );
                }
            }
        }
    }

    // Current full-state loading/publication rejects both cipher edits and
    // swapping sealed batch authority between two distinct real CG owners.
    let mut b = setup()?;
    create(&mut b);
    b.requester = batch_login(&mut b, "requester", "cg-requester", "60s")?;
    let (wrapper, _) = pending(&mut b)?;
    let second = call(
        &mut b.service,
        &b.requester.token,
        "POST",
        "secret/data/cg/key",
        json!({"data":{"value":"different"}}),
        100,
    );
    assert_eq!(second.status, 200);
    assert!(second.body["wrap_info"].is_object());
    let original = Zeroizing::new(serde_json::to_vec(
        b.service.state.as_ref().ok_or("state")?,
    )?);
    for tamper in ["ciphertext", "transplant", "actor", "transport"] {
        let mut forged: Value = serde_json::from_slice(&original)?;
        let owners = forged["auth"]["control_groups"]["requests"]
            .as_object_mut()
            .ok_or("owners")?;
        assert_eq!(owners.len(), 2);
        let ids = owners.keys().cloned().collect::<Vec<_>>();
        let other = owners[&ids[1]]["credential"].clone();
        let owner = owners.get_mut(&ids[0]).ok_or("owner")?;
        match tamper {
            "ciphertext" => {
                let bytes = owner["credential"]["ciphertext"]
                    .as_array_mut()
                    .ok_or("ciphertext")?;
                let byte = bytes[0].as_u64().ok_or("byte")? as u8;
                bytes[0] = json!(byte ^ 1);
            }
            "transplant" => owner["credential"] = other,
            "actor" => owner["actor_digest"] = json!("f".repeat(43)),
            "transport" => owner["transport_body"] = json!({"data":{"value":"forged"}}),
            _ => return Err("unknown capsule tamper".into()),
        }
        let mut forged: State = serde_json::from_value(forged)?;
        assert_eq!(
            forged
                .validate_format()
                .err()
                .ok_or("capsule format")?
                .status,
            503
        );
        assert_eq!(
            forged
                .validate_publication_schema(b.service.state.as_ref())
                .err()
                .ok_or("capsule publication")?
                .status,
            503
        );
        assert_eq!(
            b.service
                .commit_state(&mut forged)
                .err()
                .ok_or("capsule commit")?
                .status,
            503
        );
        read(&mut b, 1, "before", 100);
    }
    // Admission runs through the full persistent State decoder, not a
    // standalone capsule parser or a public response-shaped authority.
    for malformed in ["unknown-field", "oversize"] {
        let mut forged: Value = serde_json::from_slice(&original)?;
        let owners = forged["auth"]["control_groups"]["requests"]
            .as_object_mut()
            .ok_or("owners")?;
        let credential = &mut owners.values_mut().next().ok_or("owner")?["credential"];
        if malformed == "unknown-field" {
            credential["unrecognized_custody"] = json!(true);
        } else {
            // Batch wire bound 16384 plus the real AEAD tag 16, then one byte.
            credential["ciphertext"] = json!(vec![0_u8; 16 * 1024 + 16 + 1]);
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&forged)?);
        assert!(serde_json::from_value::<State>(forged).is_err());
        assert!(serde_json::from_slice::<State>(&encoded).is_err());
        read(&mut b, 1, "before", 100);
    }
    assert_eq!(
        call(
            &mut b.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );

    for operation in ["lookup-self", "renew-self"] {
        for cause in ["success", "revoked", "policy"] {
            let mut e = setup()?;
            let policy = format!(
                r#"path "auth/token/{operation}" {{
              capabilities = ["read","update"] control_group = {{ ttl = "60s" factor "review" {{
                identity {{ group_names = ["cg-team"] approvals = 2 }}
              }} }}
            }}"#
            );
            policy_write(&mut e.service, &e.admin, "cg-requester", &policy);
            let before = call(
                &mut e.service,
                &e.admin,
                "POST",
                "auth/token/lookup",
                json!({"token":e.requester.token.as_str()}),
                100,
            );
            assert_eq!(before.status, 200);
            if operation == "renew-self" {
                for malformed in [json!({"increment":{}}), json!({"increment":"-1s"})] {
                    let rejected = call(
                        &mut e.service,
                        &e.requester.token,
                        "POST",
                        "auth/token/renew-self",
                        malformed,
                        100,
                    );
                    assert_eq!(rejected.status, 400);
                    assert!(rejected.body.get("wrap_info").is_none());
                    assert_eq!(
                        e.service
                            .state
                            .as_ref()
                            .ok_or("state")?
                            .auth
                            .control_group_request_count_for_test(),
                        0
                    );
                }
            }
            let body = if operation == "renew-self" {
                json!({"increment":"120s"})
            } else {
                json!({})
            };
            let deferred = call(
                &mut e.service,
                &e.requester.token,
                if operation == "lookup-self" {
                    "GET"
                } else {
                    "POST"
                },
                &format!("auth/token/{operation}"),
                body,
                100,
            );
            assert_eq!(deferred.status, 200);
            assert!(deferred.body["data"].is_null());
            let wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
            let accessor = text(&deferred.body, "/wrap_info/accessor")?;
            assert_raw_absent(&e, &e.requester.token)?;
            assert_eq!(
                call(
                    &mut e.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100
                )
                .status,
                400
            );
            let untouched = call(
                &mut e.service,
                &e.admin,
                "POST",
                "auth/token/lookup",
                json!({"token":e.requester.token.as_str()}),
                100,
            );
            assert_eq!(untouched.status, 200);
            assert_eq!(untouched.body["data"]["ttl"], before.body["data"]["ttl"]);
            approve_two(&mut e, &accessor);
            if cause == "revoked" {
                assert_eq!(
                    call(
                        &mut e.service,
                        &e.admin,
                        "POST",
                        "auth/token/revoke",
                        json!({"token":e.requester.token.as_str()}),
                        100
                    )
                    .status,
                    204
                );
            } else if cause == "policy" {
                policy_write(
                    &mut e.service,
                    &e.admin,
                    "cg-requester",
                    r#"path "auth/token/lookup-self" { capabilities = ["deny"] }"#,
                );
            }
            e = restart(e, 100)?;
            let response = call(
                &mut e.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                100,
            );
            if cause == "success" {
                assert_eq!(response.status, 200);
                if operation == "lookup-self" {
                    assert_eq!(response.body["data"]["id"], e.requester.token.as_str());
                } else {
                    assert_eq!(
                        response.body["auth"]["client_token"],
                        e.requester.token.as_str()
                    );
                    assert_eq!(response.body["auth"]["lease_duration"], 120);
                }
                assert_eq!(
                    call(
                        &mut e.service,
                        &wrapper,
                        "POST",
                        "sys/wrapping/unwrap",
                        json!({}),
                        100
                    )
                    .status,
                    400
                );
            } else {
                assert_eq!(response.status, 403);
                let encoded = Zeroizing::new(serde_json::to_vec(&response.body)?);
                assert!(
                    !encoded
                        .windows(e.requester.token.len())
                        .any(|window| window == e.requester.token.as_bytes())
                );
            }
        }
    }
    let mut e = setup()?;
    e.requester = batch_login(&mut e, "requester", "cg-requester", "60s")?;
    policy_write(
        &mut e.service,
        &e.admin,
        "cg-requester",
        r#"
      path "auth/token/lookup-self" { capabilities = ["read"]
        control_group = { ttl = "60s" factor "review" {
          identity { group_names = ["cg-team"] approvals = 2 }
        } }
      }
      path "auth/token/renew-self" { capabilities = ["update"]
        control_group = { ttl = "60s" factor "review" {
          identity { group_names = ["cg-team"] approvals = 2 }
        } }
      }"#,
    );
    let not_renewable = call(
        &mut e.service,
        &e.requester.token,
        "POST",
        "auth/token/renew-self",
        json!({"increment":"60s"}),
        100,
    );
    assert_eq!(not_renewable.status, 400);
    assert!(not_renewable.body.get("wrap_info").is_none());
    assert_eq!(
        e.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_request_count_for_test(),
        0
    );
    let deferred = call(
        &mut e.service,
        &e.requester.token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    );
    assert_eq!(deferred.status, 200);
    let wrap = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let access = text(&deferred.body, "/wrap_info/accessor")?;
    assert_raw_absent(&e, &e.requester.token)?;
    approve_two(&mut e, &access);
    e = restart(e, 100)?;
    let response = call(
        &mut e.service,
        &wrap,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["type"], "batch");
    assert_eq!(response.body["data"]["id"], e.requester.token.as_str());
    assert_eq!(
        call(
            &mut e.service,
            &wrap,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    // A short ordinary requester cannot be revived for self echo or renewal
    // by a coarse or precise clock rollback after a real observed expiry.
    for operation in ["lookup-self", "renew-self"] {
        for precise in [false, true] {
            let mut e = setup()?;
            let previous_entity = e.requester.entity.clone();
            e.requester = short_login(&mut e, "requester", "cg-requester")?;
            assert_eq!(e.requester.entity, previous_entity);
            policy_write(
                &mut e.service,
                &e.admin,
                "cg-requester",
                &format!(
                    r#"path "auth/token/{operation}" {{
                  capabilities = ["read","update"] control_group = {{ ttl = "60s" factor "review" {{
                    identity {{ group_names = ["cg-team"] approvals = 2 }}
                  }} }}
                }}"#
                ),
            );
            let before = call(
                &mut e.service,
                &e.admin,
                "POST",
                "auth/token/lookup",
                json!({"token":e.requester.token.as_str()}),
                100,
            );
            assert_eq!(before.status, 200);
            assert_eq!(before.body["data"]["ttl"], 10);
            let method = if operation == "lookup-self" {
                "GET"
            } else {
                "POST"
            };
            let body = if operation == "lookup-self" {
                json!({})
            } else {
                json!({"increment":"120s"})
            };
            let deferred = observed_call(
                &mut e.service,
                &e.requester.token,
                method,
                &format!("auth/token/{operation}"),
                body,
                100,
                precise,
            )?;
            assert_eq!(deferred.status, 200);
            assert!(deferred.body["data"].is_null());
            let wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
            let accessor = text(&deferred.body, "/wrap_info/accessor")?;
            assert_raw_absent(&e, &e.requester.token)?;
            assert_eq!(
                observed_call(
                    &mut e.service,
                    &wrapper,
                    "POST",
                    "sys/wrapping/unwrap",
                    json!({}),
                    100,
                    precise
                )?
                .status,
                400
            );
            let untouched = call(
                &mut e.service,
                &e.admin,
                "POST",
                "auth/token/lookup",
                json!({"token":e.requester.token.as_str()}),
                100,
            );
            assert_eq!(untouched.status, 200);
            assert_eq!(untouched.body["data"]["ttl"], 10);
            approve_two(&mut e, &accessor);
            let reviewed = observed_call(
                &mut e.service,
                &e.admin,
                "POST",
                "sys/control-group/request",
                json!({"accessor":accessor}),
                111,
                precise,
            )?;
            assert_eq!(reviewed.status, 200);
            assert_eq!(reviewed.body["data"]["approved"], true);
            assert_eq!(
                e.service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .auth
                    .control_group_time(105),
                111
            );
            e = restart(e, 105)?;
            let denied = observed_call(
                &mut e.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                105,
                precise,
            )?;
            assert_eq!(denied.status, 403);
            let encoded = Zeroizing::new(serde_json::to_vec(&denied.body)?);
            assert!(
                !encoded
                    .windows(e.requester.token.len())
                    .any(|window| window == e.requester.token.as_bytes())
            );
            assert_eq!(
                call(
                    &mut e.service,
                    &e.admin,
                    "POST",
                    "auth/token/lookup",
                    json!({"token":e.requester.token.as_str()}),
                    105
                )
                .status,
                403
            );
            assert_raw_absent(&e, &e.requester.token)?;
        }
    }

    // Real namespace publication owns a private batch requester capsule.
    // A sibling scope and a recreated namespace cannot inherit its approval.
    let mut n = setup()?;
    let admin = Zeroizing::new(n.admin.to_string());
    for path in ["cg-child", "cg-sibling"] {
        assert_eq!(
            call(
                &mut n.service,
                &admin,
                "POST",
                &format!("sys/namespaces/{path}"),
                json!({}),
                100
            )
            .status,
            200
        );
    }
    let first_namespace = call(
        &mut n.service,
        &admin,
        "GET",
        "sys/namespaces/cg-child",
        json!({}),
        100,
    );
    assert_eq!(first_namespace.status, 200);
    let first_id = text(&first_namespace.body, "/data/id")?;
    let (child, first, second) = scoped_credentials(&mut n, "cg-child")?;
    let deferred = scoped_call(
        &mut n,
        "cg-child",
        &child.token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    );
    assert_eq!(deferred.status, 200);
    assert!(deferred.body["data"].is_null());
    let old_wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let accessor = text(&deferred.body, "/wrap_info/accessor")?;
    assert_raw_absent(&n, &child.token)?;
    assert_eq!(
        scoped_call(
            &mut n,
            "cg-child",
            &old_wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    scoped_approvals(&mut n, "cg-child", &accessor, &first, &second);
    for scope in ["", "cg-sibling"] {
        assert_eq!(
            scoped_call(
                &mut n,
                scope,
                &child.token,
                "GET",
                "auth/token/lookup-self",
                json!({}),
                100
            )
            .status,
            403
        );
        assert_eq!(
            scoped_call(
                &mut n,
                scope,
                &old_wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                100
            )
            .status,
            403
        );
    }
    assert_eq!(
        call(
            &mut n.service,
            &admin,
            "DELETE",
            "sys/namespaces/cg-child",
            json!({}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut n.service,
            &admin,
            "POST",
            "sys/namespaces/cg-child",
            json!({}),
            100
        )
        .status,
        200
    );
    let next_namespace = call(
        &mut n.service,
        &admin,
        "GET",
        "sys/namespaces/cg-child",
        json!({}),
        100,
    );
    assert_eq!(next_namespace.status, 200);
    assert_ne!(text(&next_namespace.body, "/data/id")?, first_id);
    let (next, first, second) = scoped_credentials(&mut n, "cg-child")?;
    assert_ne!(next.entity, child.entity);
    n = restart(n, 100)?;
    assert_eq!(
        scoped_call(
            &mut n,
            "cg-child",
            &child.token,
            "GET",
            "auth/token/lookup-self",
            json!({}),
            100
        )
        .status,
        403
    );
    assert_eq!(
        scoped_call(
            &mut n,
            "cg-child",
            &old_wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        403
    );
    let fresh = scoped_call(
        &mut n,
        "cg-child",
        &next.token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
        100,
    );
    assert_eq!(fresh.status, 200);
    let fresh_wrapper = Zeroizing::new(text(&fresh.body, "/wrap_info/token")?);
    let fresh_accessor = text(&fresh.body, "/wrap_info/accessor")?;
    assert_ne!(fresh_accessor, accessor);
    scoped_approvals(&mut n, "cg-child", &fresh_accessor, &first, &second);
    let allowed = scoped_call(
        &mut n,
        "cg-child",
        &fresh_wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["data"]["id"], next.token.as_str());
    assert_eq!(allowed.body["data"]["type"], "batch");
    assert_eq!(
        scoped_call(
            &mut n,
            "cg-child",
            &fresh_wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        400
    );
    Ok(())
}

const CG_WORKFLOW_PROFILE: &str = r#"flow "controlled" {
  request "write" {
    operation = "update"
    path = "secret/data/cg/key"
    data = { data = { value = "after" } }
  }
}
output {
  data = {
    marker = "controlled-workflow-completed"
    wrapping = { eval_source = "response" eval_type = "interface{}"
      flow_name = "controlled" response_name = "write" field_selector = ["wrap_info"] }
  }
}"#;
fn profile_fixture() -> TestResult<Fixture> {
    let mut f = setup()?;
    let policy = requester_policy("60s", "")
        + r#"
    path "sys/workflows/execute/cg-wire" { capabilities = ["update"] }"#;
    policy_write(&mut f.service, &f.admin, "cg-requester", &policy);
    create(&mut f);
    let response = call(
        &mut f.service,
        &f.admin,
        "POST",
        "sys/workflows/manage/cg-wire",
        json!({"workflow":CG_WORKFLOW_PROFILE, "description":"synthetic-controlled-inner-request-wire",
            "cas":-1, "cas_required":false, "allow_unauthenticated":false}),
        100,
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["version"], 1);
    assert_eq!(response.body["data"]["workflow"], CG_WORKFLOW_PROFILE);
    assert_eq!(response.body["data"]["cas_required"], false);
    Ok(f)
}
fn profile_pending(f: &mut Fixture, precise: bool) -> TestResult<(Zeroizing<String>, String)> {
    let response = observed_call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/workflows/execute/cg-wire",
        json!({}),
        100,
        precise,
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["marker"],
        "controlled-workflow-completed"
    );
    assert_eq!(
        response.body["data"]["wrapping"]["creation_path"],
        "secret/data/cg/key"
    );
    assert_eq!(response.body["data"]["wrapping"]["ttl"], 60);
    assert!(response.body.get("wrap_info").is_none());
    read(f, 1, "before", 100);
    Ok((
        Zeroizing::new(text(&response.body, "/data/wrapping/token")?),
        text(&response.body, "/data/wrapping/accessor")?,
    ))
}

#[test]
fn cg270_hcl_workflow_inner_deferred_owner_survives_restart_and_executes_once() -> TestResult {
    for precise in [false, true] {
        let mut f = profile_fixture()?;
        let (wrapper, accessor) = profile_pending(&mut f, precise)?;
        let initial = review_request(&mut f, &accessor);
        assert_eq!(initial.status, 200);
        assert_eq!(initial.body["data"]["request_path"], "secret/data/cg/key");
        assert_eq!(
            initial.body["data"]["request_data"],
            json!({"data":{"value":"after"}})
        );
        assert_eq!(
            initial.body["data"]["request_entity"]["ID"],
            f.requester.entity
        );
        assert_eq!(initial.body["data"]["approved"], false);
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
            review_request(&mut f, &accessor).body["data"]["approved"],
            false
        );
        f = restart(f, 100)?;
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
        assert_eq!(
            review_request(&mut f, &accessor).body["data"]["approved"],
            true
        );
        let resumed = observed_call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100,
            precise,
        )?;
        assert_eq!(resumed.status, 200);
        assert_eq!(resumed.body["data"]["version"], 2);
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
    }
    Ok(())
}

#[test]
fn cg270_hcl_workflow_current_policy_and_approval_membership_veto_inner_effect() -> TestResult {
    for revoke_actor in [false, true] {
        let mut f = profile_fixture()?;
        let (wrapper, accessor) = profile_pending(&mut f, true)?;
        approve_two(&mut f, &accessor);
        if revoke_actor {
            policy_write(
                &mut f.service,
                &f.admin,
                "cg-requester",
                r#"path "sys/workflows/execute/cg-wire" { capabilities = ["update"] }
                path "secret/data/cg/*" { capabilities = ["deny"] }"#,
            );
        } else {
            assert_eq!(
                call(
                    &mut f.service,
                    &f.admin,
                    "POST",
                    &format!("identity/group/id/{}", f.group),
                    json!({"member_entity_ids":[f.requester.entity, f.first.entity]}),
                    100
                )
                .status,
                204
            );
        }
        f = restart(f, 100)?;
        let denied = call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100,
        );
        assert!(denied.status >= 400);
        read(&mut f, 1, "before", 100);
        assert_eq!(
            f.service.state.as_ref().ok_or("state")?.schema,
            WORKFLOW_PROFILE_STATE_SCHEMA
        );
    }
    Ok(())
}

#[test]
fn workflow121_profile_reader_publication_and_snapshot_floor_survives_retirement() -> TestResult {
    let mut f = profile_fixture()?;
    let active = f.service.state.as_ref().ok_or("state")?.clone();
    assert_eq!(active.schema, WORKFLOW_PROFILE_STATE_SCHEMA);
    assert!(active.validate_format().is_ok());
    let encoded = serde_json::to_value(&active)?;
    let decoded: State = serde_json::from_value(encoded.clone())?;
    assert!(decoded.validate_format().is_ok());
    for schema in [CONTROL_GROUP_STATE_SCHEMA, 119, 120] {
        let mut downgraded = decoded.clone();
        downgraded.schema = schema;
        assert!(downgraded.validate_format().is_err());
        assert!(
            downgraded
                .validate_publication_schema(Some(&active))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&active, &downgraded).is_err());
    }
    let mut unknown = encoded;
    unknown["namespaces"]["workflows"]["by_namespace"][""]["cg-wire"]["definition"]["profile"]["extra"] =
        json!(true);
    assert!(serde_json::from_value::<State>(unknown).is_err());
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "DELETE",
            "sys/workflows/manage/cg-wire",
            json!({}),
            100
        )
        .status,
        204
    );
    let retired = f.service.state.as_ref().ok_or("retired")?.clone();
    assert!(!retired.namespaces.workflows.has_profiles());
    assert_eq!(retired.schema, WORKFLOW_PROFILE_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), WORKFLOW_PROFILE_STATE_SCHEMA);
    let mut downgraded = retired.clone();
    downgraded.schema = CONTROL_GROUP_STATE_SCHEMA;
    assert!(
        downgraded
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &downgraded).is_err());
    assert!(supported_reader_schema(WORKFLOW_PROFILE_STATE_SCHEMA));
    assert!(!supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1));
    Ok(())
}

#[test]
fn cg270_hcl_workflow_inner_self_lookup_keeps_sealed_echo_and_live_actor_authority() -> TestResult {
    let mut f = setup()?;
    let policy = r#"path "auth/token/lookup-self" { capabilities = ["read"]
      control_group = { ttl = "60s" factor "review" { controlled_capabilities = ["read"]
        identity { group_names = ["cg-team"] approvals = 2 self_authorization = false } } } }
      path "sys/workflows/execute/self-wire" { capabilities = ["update"] }
      path "sys/control-group/request" { capabilities = ["update"] }"#;
    policy_write(&mut f.service, &f.admin, "cg-requester", policy);
    let document = r#"flow "self" { request "lookup" {
      operation = "read" path = "auth/token/lookup-self" } }
      output { data = { wrapping = { eval_source = "response" eval_type = "interface{}"
        flow_name = "self" response_name = "lookup" field_selector = ["wrap_info"] } } }"#;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/workflows/manage/self-wire",
            json!({"workflow":document, "cas":-1}),
            100
        )
        .status,
        200
    );
    let response = observed_call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/workflows/execute/self-wire",
        json!({}),
        100,
        true,
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["wrapping"]["creation_path"],
        "auth/token/lookup-self"
    );
    let wrapper = Zeroizing::new(text(&response.body, "/data/wrapping/token")?);
    let accessor = text(&response.body, "/data/wrapping/accessor")?;
    assert!(!serde_json::to_string(&f.service.state)?.contains(f.requester.token.as_str()));
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
    approve_two(&mut f, &accessor);
    f = restart(f, 100)?;
    let result = call(
        &mut f.service,
        &wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    assert_eq!(result.status, 200);
    assert_eq!(result.body["data"]["id"], f.requester.token.as_str());
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
    // A second owner cannot inherit the first approved claim after actor revocation.
    let second = call(
        &mut f.service,
        &f.requester.token,
        "POST",
        "sys/workflows/execute/self-wire",
        json!({}),
        100,
    );
    assert_eq!(second.status, 200);
    let wrapper = Zeroizing::new(text(&second.body, "/data/wrapping/token")?);
    let accessor = text(&second.body, "/data/wrapping/accessor")?;
    approve_two(&mut f, &accessor);
    assert_eq!(
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
    );
    assert!(
        call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status
            >= 400
    );
    Ok(())
}
fn fractional_call(
    service: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    at: crate::auth::Timestamp,
) -> TestResult<Response> {
    let encoded = Zeroizing::new(serde_json::to_vec(&body)?);
    let mut wire = Zeroizing::new(format!(
        "{method} /v1/{path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        encoded.len()).into_bytes());
    wire.extend_from_slice(&encoded);
    let clock = RequestClock::anchored(at.duration_since_epoch(), std::time::Instant::now())?;
    let (method, path, namespace, token, body) = crate::http::parsed_api_request_for_test(&wire)?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: &method,
            path: &path,
            namespace: &namespace,
            token: &token,
            body: body.0.clone(),
            now: at.seconds(),
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
fn fractional_approve(
    fixture: &mut Fixture,
    accessor: &str,
    at: crate::auth::Timestamp,
) -> TestResult {
    for token in [&fixture.first.token, &fixture.second.token] {
        let response = fractional_call(
            &mut fixture.service,
            token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
            at,
        )?;
        assert_eq!(response.status, 200);
    }
    Ok(())
}
#[test]
fn cg122_fractional_http_quorum_restart_exact_expiry_and_sticky_floor_veto_effects() -> TestResult {
    use crate::auth::Timestamp;
    for (raw, nanos, wire_ttl) in [
        ("1500ms", 1_500_000_000_u64, 1_u64),
        ("500ms", 500_000_000, 0),
    ] {
        let mut f = setup()?;
        create(&mut f);
        policy_write(
            &mut f.service,
            &f.admin,
            "cg-requester",
            &requester_policy(raw, ""),
        );
        let issued = Timestamp::checked(100, 125_000_000)?;
        let deferred = fractional_call(
            &mut f.service,
            &f.requester.token,
            "POST",
            "secret/data/cg/key",
            json!({"data":{"value":"after"}}),
            issued,
        )?;
        assert_eq!(deferred.status, 200);
        assert_eq!(deferred.body["wrap_info"]["ttl"], wire_ttl);
        assert!(deferred.body["data"].is_null());
        let wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
        let accessor = text(&deferred.body, "/wrap_info/accessor")?;
        let precision = f
            .service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_owners()
            .next()
            .ok_or("owner")?
            .precision
            .ok_or("precision")?;
        assert_eq!(precision.ttl.nanoseconds(), nanos);
        assert_eq!(
            precision.issued_at.checked_add(precision.ttl)?,
            precision.expires_at
        );
        assert_eq!(
            f.service.state.as_ref().ok_or("state")?.schema,
            CONTROL_GROUP_FRACTIONAL_STATE_SCHEMA
        );
        read(&mut f, 1, "before", 100);
        // Truncated ttl=0 is a projection, not an immediately dead capability.
        assert_eq!(
            fractional_call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                precision.issued_at
            )?
            .status,
            400
        );
        assert_eq!(
            f.service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .control_group_request_count_for_test(),
            1
        );
        fractional_approve(&mut f, &accessor, precision.issued_at)?;
        f = restart(f, 100)?;
        let resumed = fractional_call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            precision.issued_at,
        )?;
        assert_eq!(resumed.status, 200);
        assert_eq!(resumed.body["data"]["version"], 2);
        read(&mut f, 2, "after", 100);
        assert_eq!(
            fractional_call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                precision.issued_at
            )?
            .status,
            400
        );
        read(&mut f, 2, "after", 100);

        let deferred = fractional_call(
            &mut f.service,
            &f.requester.token,
            "POST",
            "secret/data/cg/key",
            json!({"data":{"value":"must-not-execute"}}),
            precision.issued_at,
        )?;
        assert_eq!(deferred.status, 200);
        let wrapper = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
        let accessor = text(&deferred.body, "/wrap_info/accessor")?;
        fractional_approve(&mut f, &accessor, precision.issued_at)?;
        let current = f.service.state.as_ref().ok_or("state")?.clone();
        let exact = current
            .auth
            .control_group_owners()
            .next()
            .ok_or("owner")?
            .precision
            .ok_or("precise deadline")?;
        let before = exact
            .issued_at
            .checked_add((nanos - 1).try_into()?)?;
        assert!(
            current
                .auth
                .control_group_target_observed(&wrapper, "", AuthorityTime::Precise(before))?
                .is_some()
        );
        assert!(
            current
                .auth
                .control_group_target_observed(
                    &wrapper,
                    "",
                    AuthorityTime::Precise(exact.expires_at)
                )
                .is_err()
        );

        // Full State decoder plus publication reject a forged precise deadline.
        let mut value = serde_json::to_value(&current)?;
        let owners = value["auth"]["control_groups"]["requests"]
            .as_object_mut()
            .ok_or("owners")?;
        let owner = owners.values_mut().next().ok_or("owner")?;
        owner["precision"]["ttl"] = json!(nanos + 1);
        let forged: State = serde_json::from_value(value)?;
        assert_eq!(forged.validate_format().err().ok_or("format")?.status, 503);
        assert_eq!(
            forged
                .validate_publication_schema(Some(&current))
                .err()
                .ok_or("publication")?
                .status,
            503
        );
        for schema in [CONTROL_GROUP_STATE_SCHEMA, WORKFLOW_PROFILE_STATE_SCHEMA] {
            let mut downgraded = current.clone();
            downgraded.schema = schema;
            assert!(downgraded.validate_format().is_err());
            assert!(
                downgraded
                    .validate_publication_schema(Some(&current))
                    .is_err()
            );
            assert!(Service::validate_snapshot_protected_floor(&current, &downgraded).is_err());
        }
        let expired = fractional_call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            exact.expires_at,
        )?;
        assert_eq!(expired.status, 400);
        read(&mut f, 2, "after", exact.expires_at.seconds());
        let retired = f.service.state.as_ref().ok_or("retired")?.clone();
        assert_eq!(retired.auth.control_group_request_count_for_test(), 0);
        assert_eq!(retired.schema, CONTROL_GROUP_FRACTIONAL_STATE_SCHEMA);
        assert_eq!(
            retired.writer_schema(),
            CONTROL_GROUP_FRACTIONAL_STATE_SCHEMA
        );
        assert!(current.validate_publication_schema(Some(&retired)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&retired, &current).is_err());
        f = restart(f, 100)?;
        // Reload and wall rollback cannot restore subsecond approval authority.
        assert_eq!(
            fractional_call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                exact.issued_at
            )?
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
        read(&mut f, 2, "after", exact.expires_at.seconds());
    }
    Ok(())
}

#[test]
fn cg_lossless_encrypted_pending_body_and_approval_context_survive_durable_restart() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let value = heptabao_domain::json::decode(br#"{"value":"after","big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#)?;
    let request = json!({"data":value});
    let pending = observed_call(&mut f.service,&f.requester.token,"POST","secret/data/cg/key",request.clone(),100,true)?;
    assert_eq!(pending.status,200);
    assert!(pending.body["data"].is_null());
    let wrapper = Zeroizing::new(text(&pending.body,"/wrap_info/token")?);
    let accessor = text(&pending.body,"/wrap_info/accessor")?;
    let before = review_request(&mut f,&accessor);
    assert_eq!(before.status,200);
    assert_eq!(before.body["data"]["request_data"],request);
    f = restart(f,100)?;
    let after = review_request(&mut f,&accessor);
    assert_eq!(after.status,200);
    assert_eq!(after.body["data"]["request_data"],request);
    assert_eq!(after.body["data"]["authorizations"],json!([]));
    approve_two(&mut f,&accessor);
    f = restart(f,100)?;
    assert_eq!(review_request(&mut f,&accessor).body["data"]["approved"],true);
    let executed = call(&mut f.service,&wrapper,"POST","sys/wrapping/unwrap",json!({}),100);
    assert_eq!(executed.status,200);
    assert_eq!(executed.body["data"]["version"],2);
    let read = call(&mut f.service,&f.admin,"GET","secret/data/cg/key",json!({}),100);
    assert_eq!(read.status,200);
    assert_eq!(read.body["data"]["data"],value);
    assert!(read.body["data"]["data"]["fake"].is_object());
    assert_eq!(call(&mut f.service,&wrapper,"POST","sys/wrapping/unwrap",json!({}),100).status,400);
    Ok(())
}
