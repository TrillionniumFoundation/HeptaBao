//! Actual configured File V6, normal Service requests, audited delivery and
//! cold reopen. Identity/CG objects are created only after native activation.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct TestRequest<'a> {
    token: &'a str,
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    body: Value,
    wrap_ttl_seconds: Option<u64>,
}

fn request(service: &mut Service, now: &mut u64, request: TestRequest<'_>) -> TestResult<Response> {
    *now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(*now), started)?;
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: request.method,
            path: request.path,
            namespace: request.namespace,
            token: request.token,
            body: request.body,
            now: *now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: request.wrap_ttl_seconds,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(response)
}

fn call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    request(
        service,
        now,
        TestRequest {
            token,
            method,
            path,
            namespace: "",
            body,
            wrap_ttl_seconds: None,
        },
    )
}

fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "native Identity status errors={:?}",
        response.body.get("errors")
    );
}

fn text(response: &Response, path: &str) -> TestResult<String> {
    response
        .body
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "required synthetic Identity response field absent".into())
}

fn credential(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    let value = Zeroizing::new(text(response, path)?);
    erase_json(&mut response.body);
    Ok(value)
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    now: u64,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let files = Root::new();
        let mut service = files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let mut now = 100;
        let mut initialized = call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        status(&initialized, 200);
        let key = Zeroizing::new(text(&initialized, "/keys/0")?);
        let admin = credential(&mut initialized, "/root_token")?;
        status(
            &call(
                &mut service,
                &mut now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":key.as_str()}),
            )?,
            200,
        );
        status(
            &call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                "sys/init/ack",
                json!({}),
            )?,
            204,
        );
        status(
            &call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                native_storage::ACTIVATE_PATH,
                json!({}),
            )?,
            204,
        );
        assert!(service.native_root.is_some() && service.record_root.is_none());
        Ok(Self {
            files,
            service,
            key,
            admin,
            now,
        })
    }

    fn admin(&mut self, method: &str, path: &str, body: Value) -> TestResult<Response> {
        call(
            &mut self.service,
            &mut self.now,
            &self.admin,
            method,
            path,
            body,
        )
    }

    fn actor(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        call(&mut self.service, &mut self.now, token, method, path, body)
    }

    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.files.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        status(
            &call(
                &mut self.service,
                &mut self.now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":self.key.as_str()}),
            )?,
            200,
        );
        assert!(self.service.native_root.is_some() && self.service.record_root.is_none());
        assert!(!self.service.recovery_required);
        Ok(self)
    }

    fn native_root(&self) -> TestResult<RecordStateRootV6> {
        self.service
            .native_root
            .clone()
            .ok_or_else(|| "native root absent".into())
    }

    fn assert_kv_unchanged(&self, before: &RecordStateRootV6) -> TestResult {
        let current = self
            .service
            .native_root
            .as_ref()
            .ok_or("native root absent")?;
        assert!(current.kv1 == before.kv1);
        assert!(current.kv2 == before.kv2);
        assert_eq!(
            current.reader_floor.native_kv2_format,
            before.reader_floor.native_kv2_format
        );
        Ok(())
    }

    fn policy(&mut self, name: &str, policy: &str) -> TestResult {
        status(
            &self.admin(
                "POST",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy}),
            )?,
            204,
        );
        Ok(())
    }

    fn token(&mut self, policy: &str, uses: u64) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin(
            "POST",
            "auth/token/create",
            json!({"policies":[policy],"no_default_policy":true,"num_uses":uses,"ttl":"1h"}),
        )?;
        status(&response, 200);
        credential(&mut response, "/auth/client_token")
    }

    fn mount_and_value(&mut self) -> TestResult {
        status(
            &self.admin(
                "POST",
                "sys/mounts/id-kv",
                json!({"type":"kv","options":{"version":"2"}}),
            )?,
            204,
        );
        status(
            &self.admin(
                "POST",
                "id-kv/data/key",
                json!({"options":{"cas":0},"data":{"value":"retained-native-value"}}),
            )?,
            200,
        );
        Ok(())
    }

    fn assert_value(&mut self) -> TestResult {
        let response = self.admin("GET", "id-kv/data/key", json!({}))?;
        status(&response, 200);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert_eq!(
            response.body["data"]["data"]["value"],
            "retained-native-value"
        );
        Ok(())
    }
}

#[test]
fn native_identity_formal_crud_lookup_list_and_cold_reopen_preserve_kv() -> TestResult {
    let mut f = Fixture::new()?;
    f.mount_and_value()?;
    let graph = f.native_root()?;
    let entity = f.admin(
        "POST",
        "identity/entity",
        json!({"name":"native-entity","metadata":{"phase":"created"}}),
    )?;
    status(&entity, 200);
    let entity = text(&entity, "/data/id")?;
    let group = f.admin(
        "POST",
        "identity/group",
        json!({"name":"native-group","type":"internal","member_entity_ids":[entity]}),
    )?;
    status(&group, 200);
    let group = text(&group, "/data/id")?;
    status(
        &f.admin(
            "PATCH",
            &format!("identity/entity/id/{entity}"),
            json!({"metadata":{"phase":"updated"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "PUT",
            &format!("identity/group/id/{group}"),
            json!({"metadata":{"owner":"native"},"member_entity_ids":[entity]}),
        )?,
        204,
    );
    for (path, name, id) in [
        ("identity/lookup/entity", "native-entity", entity.as_str()),
        ("identity/lookup/group", "native-group", group.as_str()),
    ] {
        let response = f.admin("POST", path, json!({"name":name}))?;
        status(&response, 200);
        assert_eq!(response.body["data"]["id"], id);
    }
    let listed = f.admin("LIST", "identity/entity/id", json!({}))?;
    status(&listed, 200);
    assert_eq!(listed.body["data"]["keys"], json!([entity]));
    let listed = f.admin("LIST", "identity/group/name", json!({}))?;
    status(&listed, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["native-group"]));
    f.assert_kv_unchanged(&graph)?;

    let mut f = f.restart()?;
    let read = f.admin("GET", &format!("identity/entity/id/{entity}"), json!({}))?;
    status(&read, 200);
    assert_eq!(read.body["data"]["metadata"], json!({"phase":"updated"}));
    let read = f.admin("GET", &format!("identity/group/id/{group}"), json!({}))?;
    status(&read, 200);
    assert_eq!(read.body["data"]["member_entity_ids"], json!([entity]));
    assert_eq!(read.body["data"]["metadata"], json!({"owner":"native"}));
    f.assert_kv_unchanged(&graph)?;
    f.assert_value()?;
    status(
        &f.admin("DELETE", &format!("identity/group/id/{group}"), json!({}))?,
        204,
    );
    status(
        &f.admin("DELETE", &format!("identity/entity/id/{entity}"), json!({}))?,
        204,
    );
    let mut f = f.restart()?;
    status(
        &f.admin("GET", &format!("identity/group/id/{group}"), json!({}))?,
        404,
    );
    status(
        &f.admin("GET", &format!("identity/entity/id/{entity}"), json!({}))?,
        404,
    );
    f.assert_kv_unchanged(&graph)?;
    f.assert_value()
}

#[test]
fn native_identity_delegated_acl_and_finite_actor_keep_original_authority() -> TestResult {
    let mut f = Fixture::new()?;
    let entity = f.admin("POST", "identity/entity", json!({"name":"readable"}))?;
    status(&entity, 200);
    let id = text(&entity, "/data/id")?;
    f.policy(
        "identity-reader",
        r#"path "identity/entity/*" { capabilities = ["read", "list"] }"#,
    )?;
    let finite = f.token("identity-reader", 1)?;
    let response = f.actor(
        &finite,
        "GET",
        &format!("identity/entity/id/{id}"),
        json!({}),
    )?;
    status(&response, 200);
    assert_eq!(response.body["data"]["id"], id);
    status(
        &f.actor(
            &finite,
            "GET",
            &format!("identity/entity/id/{id}"),
            json!({}),
        )?,
        403,
    );
    let reader = f.token("identity-reader", 0)?;
    let denied = f.actor(
        &reader,
        "POST",
        &format!("identity/entity/id/{id}"),
        json!({"disabled":true}),
    )?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    let observed = f.admin("GET", &format!("identity/entity/id/{id}"), json!({}))?;
    status(&observed, 200);
    assert_eq!(observed.body["data"]["disabled"], false);
    f.policy(
        "identity-lister",
        r#"path "identity/entity/id" {
        capabilities = ["list"] required_parameters = ["not-required-for-list"]
    }"#,
    )?;
    let lister = f.token("identity-lister", 0)?;
    // Service accepts the canonical output of the real HTTP parser. Keep the
    // GET query transport in this fixture instead of passing raw '?' to Service.
    let wire = Zeroizing::new(format!(
        "GET /v1/identity/entity/id?list=true HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: {}\r\n\r\n",
        lister.as_str(),
    ));
    let (method, path, namespace, token, mut body) =
        crate::http::parsed_api_request_for_test(wire.as_bytes())?;
    assert_eq!(method, "LIST");
    assert_eq!(path, "identity/entity/id");
    assert!(namespace.is_empty());
    let listed = f.actor(&token, &method, &path, std::mem::take(&mut body.0))?;
    status(&listed, 200);
    assert_eq!(listed.body["data"]["keys"], json!([id]));
    let mut f = f.restart()?;
    status(
        &f.actor(
            &finite,
            "GET",
            &format!("identity/entity/id/{id}"),
            json!({}),
        )?,
        403,
    );
    status(
        &f.actor(
            &reader,
            "GET",
            &format!("identity/entity/id/{id}"),
            json!({}),
        )?,
        200,
    );
    Ok(())
}

#[test]
fn native_identity_keeps_foreign_actor_wrapping_and_unowned_paths_closed() -> TestResult {
    let mut f = Fixture::new()?;
    f.mount_and_value()?;
    status(&f.admin("POST", "sys/namespaces/id-child", json!({}))?, 200);
    // Root administration now has a typed ordinary-child owner. Keep this
    // foreign-authority negative test with a real root-namespace-only token;
    // that token's path grant cannot become a child-namespace grant.
    f.policy(
        "identity-root-only",
        r#"path "identity/entity" { capabilities = ["create", "update"] }"#,
    )?;
    let root_only = f.token("identity-root-only", 0)?;
    let graph = f.native_root()?;
    let response = request(
        &mut f.service,
        &mut f.now,
        TestRequest {
            token: &f.admin,
            method: "POST",
            path: "identity/entity",
            namespace: "",
            body: json!({"name":"must-not-be-wrapped"}),
            wrap_ttl_seconds: Some(60),
        },
    )?;
    status(&response, 501);
    assert!(response.body.get("wrap_info").is_none());
    let response = request(
        &mut f.service,
        &mut f.now,
        TestRequest {
            token: &root_only,
            method: "POST",
            path: "identity/entity",
            namespace: "id-child",
            body: json!({"name":"foreign-must-not-appear"}),
            wrap_ttl_seconds: None,
        },
    )?;
    status(&response, 403);
    assert!(response.body.get("data").is_none());
    for path in [
        "identity/mfa/method/totp",
        "identity/oidc/config",
        "identity/entity/merge",
        "identity/entity-alias",
    ] {
        status(&f.admin("POST", path, json!({}))?, 501);
    }
    f.assert_kv_unchanged(&graph)?;
    let state = f.service.state.as_ref().ok_or("state absent")?;
    // Current child creation installs one custody-bound default policy. Only
    // that exact factory owner may be projected out of this private emptiness
    // check; foreign Identity requests must not introduce any other Auth owner.
    let binding = state
        .namespaces
        .custody_binding(&state.cluster_id, "id-child")
        .map_err(|_| "actual child namespace factory binding")?;
    let normalized = state
        .auth
        .without_namespace_factory_defaults(&std::collections::BTreeMap::from([(
            "id-child".to_owned(),
            binding,
        )]))
        .map_err(|_| "actual untouched child namespace factory")?;
    assert!(normalized.namespace_is_empty("id-child"));
    assert!(state.engines.namespace_is_empty("id-child"));
    f.assert_value()
}

#[test]
fn native_identity_actual_audit_keeps_exact_response_custody() -> TestResult {
    let mut f = Fixture::new()?;
    let response = f.admin(
        "POST",
        "identity/entity",
        json!({"name":"audited","metadata":{"secret":"synthetic-private-identity"}}),
    )?;
    status(&response, 200);
    let path = format!("identity/entity/id/{}", text(&response, "/data/id")?);
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let body = json!({});
    let response = f.service.handle_inner(RequestView {
        method: "GET",
        path: &path,
        namespace: "",
        token: &f.admin,
        body: &body,
        now: f.now,
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    status(&response, 200);
    assert!(f.service.pending_native_auth_delivery.is_some());
    let mut response = f.service.audit_completed_response_with_receipt(
        "native-identity-reply-binding",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 200);
    response.body["data"]["name"] = json!("changed-after-actual-audit");
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-identity-reply-binding");
    status(&response, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("auth").is_none());
    assert!(response.consistency_index.is_none());
    assert!(
        !response
            .body
            .to_string()
            .contains("synthetic-private-identity")
    );
    assert!(f.service.pending_native_auth_delivery.is_none());
    let mut f = f.restart()?;
    let response = f.admin("GET", &path, json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["name"], "audited");
    Ok(())
}

#[test]
fn native_identity_owner_cannot_drop_kv_graph_or_flip_native_format() -> TestResult {
    let mut f = Fixture::new()?;
    f.mount_and_value()?;
    let root = f.native_root()?;
    assert!(!root.kv2.is_empty());
    let mut missing_graph = root.clone();
    missing_graph.kv2.clear();
    assert!(auth_only_root_change(&root, &missing_graph, true).is_err());
    let mut changed_format = root.clone();
    changed_format.reader_floor.native_kv2_format = if root.reader_floor.native_kv2_format == 2 {
        1
    } else {
        2
    };
    assert!(auth_only_root_change(&root, &changed_format, true).is_err());
    assert!(auth_only_root_change(&changed_format, &root, true).is_err());
    f.assert_value()
}

struct Login {
    token: Zeroizing<String>,
    entity: String,
}

fn approle_login(f: &mut Fixture, name: &str, policy: &str) -> TestResult<Login> {
    let role = format!("auth/id-approle/role/{name}");
    status(
        &f.admin(
            "POST",
            &role,
            json!({"token_policies":[policy],"secret_id_num_uses":1,
        "token_no_default_policy":true,"token_ttl":"1h"}),
        )?,
        204,
    );
    let mut response = f.admin("GET", &format!("{role}/role-id"), json!({}))?;
    status(&response, 200);
    let role_id = credential(&mut response, "/data/role_id")?;
    let mut response = f.admin("POST", &format!("{role}/secret-id"), json!({}))?;
    status(&response, 200);
    let secret_id = credential(&mut response, "/data/secret_id")?;
    let mut response = f.actor(
        "",
        "POST",
        "auth/id-approle/login",
        json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
    )?;
    status(&response, 200);
    let entity = text(&response, "/auth/entity_id")?;
    let token = credential(&mut response, "/auth/client_token")?;
    Ok(Login { token, entity })
}

fn deferred(f: &mut Fixture, actor: &Login) -> TestResult<(Zeroizing<String>, String)> {
    let mut response = f.actor(&actor.token, "GET", "id-kv/data/key", json!({}))?;
    status(&response, 200);
    assert!(response.body["data"].is_null());
    let accessor = text(&response, "/wrap_info/accessor")?;
    let token = credential(&mut response, "/wrap_info/token")?;
    Ok((token, accessor))
}

fn approvals(f: &mut Fixture, first: &Login, second: &Login, accessor: &str) -> TestResult {
    for (actor, expected) in [(first, false), (second, true)] {
        let response = f.actor(
            &actor.token,
            "POST",
            "sys/control-group/authorize",
            json!({"accessor":accessor}),
        )?;
        status(&response, 200);
        assert_eq!(response.body["data"]["approved"], expected);
    }
    Ok(())
}

#[test]
fn native_identity_live_group_membership_controls_cg_after_cold_restart() -> TestResult {
    let mut f = Fixture::new()?;
    f.mount_and_value()?;
    status(
        &f.admin("POST", "sys/auth/id-approle", json!({"type":"approle"}))?,
        204,
    );
    f.policy(
        "id-cg-requester",
        r#"
      path "id-kv/data/key" { capabilities = ["read"]
        control_group = { ttl = "600s" factor "review" {
          controlled_capabilities = ["read"]
          identity { group_names = ["native-live-team"] approvals = 2 self_authorization = false }
        } }
      }
      path "sys/control-group/request" { capabilities = ["update"] }
      path "sys/control-group/authorize" { capabilities = ["update"] }
    "#,
    )?;
    f.policy(
        "id-cg-approver",
        r#"
      path "sys/control-group/request" { capabilities = ["update"] }
      path "sys/control-group/authorize" { capabilities = ["update"] }
      path "sys/wrapping/unwrap" { capabilities = ["update"] }
    "#,
    )?;
    let requester = approle_login(&mut f, "requester", "id-cg-requester")?;
    let first = approle_login(&mut f, "first", "id-cg-approver")?;
    let second = approle_login(&mut f, "second", "id-cg-approver")?;
    let graph = f.native_root()?;
    let response = f.admin(
        "POST",
        "identity/group",
        json!({"name":"native-live-team",
        "type":"internal","member_entity_ids":[first.entity,second.entity]}),
    )?;
    status(&response, 200);
    let group = text(&response, "/data/id")?;
    f.assert_kv_unchanged(&graph)?;

    let (token, accessor) = deferred(&mut f, &requester)?;
    approvals(&mut f, &first, &second, &accessor)?;
    let mut f = f.restart()?;
    let response = f.actor(&token, "POST", "sys/wrapping/unwrap", json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
    assert_eq!(
        response.body["data"]["data"]["value"],
        "retained-native-value"
    );
    status(
        &f.actor(&token, "POST", "sys/wrapping/unwrap", json!({}))?,
        400,
    );

    let (pending, accessor) = deferred(&mut f, &requester)?;
    approvals(&mut f, &first, &second, &accessor)?;
    status(
        &f.admin(
            "POST",
            &format!("identity/group/id/{group}"),
            json!({"member_entity_ids":[first.entity]}),
        )?,
        204,
    );
    let mut f = f.restart()?;
    let group = f.admin("GET", &format!("identity/group/id/{group}"), json!({}))?;
    status(&group, 200);
    assert_eq!(
        group.body["data"]["member_entity_ids"],
        json!([first.entity])
    );
    let denied = f.actor(&pending, "POST", "sys/wrapping/unwrap", json!({}))?;
    assert!(
        denied.status >= 400,
        "removed approver cannot retain live quorum"
    );
    assert!(denied.body.get("data").is_none());
    assert!(denied.body.get("auth").is_none());
    assert!(denied.body.get("wrap_info").is_none());
    f.assert_kv_unchanged(&graph)?;
    f.assert_value()
}
