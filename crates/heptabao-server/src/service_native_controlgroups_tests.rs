//! Real Service/File V6 ownership: no detached Auth fixture grants native admission.
use super::*;
use crate::configuration::NativeStorageProfile;
use std::time::{Duration, Instant};

enum Actor {
    Admin,
    Requester,
    First,
    Second,
}

struct NativeFixture {
    root: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    requester: Login,
    first: Login,
    second: Login,
    now: u64,
}

fn native_call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    *now += 1;
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let clock = RequestClock::anchored(Duration::from_secs(*now), Instant::now())?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now: *now,
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

const NATIVE_CG_HTTP_HEADERS: &str =
    "Accept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: Python-urllib/3.14\r\n";

fn native_wire_call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    extra_headers: &str,
) -> TestResult<Response> {
    *now += 1;
    let now = *now;
    let started = Instant::now();
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let clock = RequestClock::anchored(Duration::from_secs(now), started)?;
    let body = Zeroizing::new(serde_json::to_string(&body)?);
    let wire = Zeroizing::new(format!(
        "{method} /v1/{path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{NATIVE_CG_HTTP_HEADERS}{extra_headers}\r\n{}",
        body.len(),
        body.as_str(),
    ));
    Ok(crate::http::logical_data_wire_dispatch_fixture(
        wire.as_bytes(),
        |request| {
            assert!(
                crate::request_metadata::current(
                    request.method,
                    request.path,
                    request.namespace,
                    &request.body,
                )
                .is_ok_and(|data| data.is_some_and(|data| {
                    data.query.is_empty()
                        && data.profile.is_none()
                        && data.headers.contains_key("accept")
                        && data.headers.contains_key("accept-encoding")
                        && data.headers.contains_key("user-agent")
                        && data.headers.len() == 3 + usize::from(!extra_headers.is_empty())
                })),
                "actual HTTP parser must retain ordinary headers before Service admission",
            );
            let execution = service.begin_at_mode_precise(
                RequestDispatch {
                    method: request.method,
                    path: request.path,
                    namespace: request.namespace,
                    token: request.token,
                    body: request.body,
                    now,
                    allow_forward: true,
                    enforce_namespace: true,
                    wrap_ttl_seconds: request.wrap_ttl_seconds,
                    origin_peer: request.origin_peer,
                    client_certificates: request.client_certificates,
                },
                clock,
            );
            service.finish_synchronous_request(execution)
        },
    )?)
}

impl NativeFixture {
    fn request(
        &mut self,
        actor: Actor,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        let raw = match actor {
            Actor::Admin => &self.admin,
            Actor::Requester => &self.requester.token,
            Actor::First => &self.first.token,
            Actor::Second => &self.second.token,
        };
        native_call(&mut self.service, &mut self.now, raw, method, path, body)
    }

    fn unwrap(&mut self, raw: &str) -> TestResult<Response> {
        native_call(
            &mut self.service,
            &mut self.now,
            raw,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
        )
    }

    fn defer(&mut self, cas: u64) -> TestResult<(Zeroizing<String>, String)> {
        let response = self.request(
            Actor::Requester,
            "POST",
            "secret/data/cg/key",
            json!({"options":{"cas":cas},"data":{"value":"after"}}),
        )?;
        assert_eq!(response.status, 200, "native deferral status");
        assert!(response.body["data"].is_null());
        Ok((
            Zeroizing::new(text(&response.body, "/wrap_info/token")?),
            text(&response.body, "/wrap_info/accessor")?,
        ))
    }

    fn approve(&mut self, accessor: &str) -> TestResult {
        for (actor, approved) in [(Actor::First, false), (Actor::Second, true)] {
            let response = self.request(
                actor,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":accessor}),
            )?;
            assert_eq!(response.status, 200, "native approval status");
            assert_eq!(response.body["data"]["approved"], approved);
        }
        Ok(())
    }

    fn assert_value(&mut self, version: u64, value: &str) -> TestResult {
        let response = self.request(Actor::Admin, "GET", "secret/data/cg/key", json!({}))?;
        assert_eq!(response.status, 200, "native readback status");
        assert_eq!(response.body["data"]["metadata"]["version"], version);
        assert_eq!(response.body["data"]["data"]["value"], value);
        Ok(())
    }

    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.root.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        let response = native_call(
            &mut self.service,
            &mut self.now,
            "",
            "POST",
            "sys/unseal",
            json!({"key":self.key.as_str()}),
        )?;
        assert_eq!(response.status, 200, "native cold unseal status");
        assert!(self.service.native_root.is_some());
        assert!(self.service.record_root.is_none());
        Ok(self)
    }
}

impl NativeFixture {
    fn wire_request(
        &mut self,
        actor: Actor,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        let raw = match actor {
            Actor::Admin => &self.admin,
            Actor::Requester => &self.requester.token,
            Actor::First => &self.first.token,
            Actor::Second => &self.second.token,
        };
        native_wire_call(
            &mut self.service,
            &mut self.now,
            raw,
            method,
            path,
            body,
            "",
        )
    }

    fn wire_unwrap(&mut self, raw: &str) -> TestResult<Response> {
        native_wire_call(
            &mut self.service,
            &mut self.now,
            raw,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            "",
        )
    }

    fn wire_approve(&mut self, accessor: &str) -> TestResult {
        for (actor, approved) in [(Actor::First, false), (Actor::Second, true)] {
            let response = self.wire_request(
                actor,
                "POST",
                "sys/control-group/authorize",
                json!({"accessor":accessor}),
            )?;
            assert_eq!(response.status, 200, "wire native approval status");
            assert_eq!(response.body["data"]["approved"], approved);
        }
        Ok(())
    }
}

fn native_login(
    service: &mut Service,
    now: &mut u64,
    admin: &str,
    name: &str,
    policy: &str,
) -> TestResult<Login> {
    let role = format!("auth/cg-native/role/{name}");
    assert_eq!(
        native_call(
            service,
            now,
            admin,
            "POST",
            &role,
            json!({"token_policies":[policy],"secret_id_num_uses":1,
                "token_no_default_policy":true,"token_ttl":"1h"}),
        )?
        .status,
        204,
    );
    let role_id = native_call(
        service,
        now,
        admin,
        "GET",
        &format!("{role}/role-id"),
        json!({}),
    )?;
    assert_eq!(role_id.status, 200);
    let role_id = Zeroizing::new(text(&role_id.body, "/data/role_id")?);
    let secret_id = native_call(
        service,
        now,
        admin,
        "POST",
        &format!("{role}/secret-id"),
        json!({}),
    )?;
    assert_eq!(secret_id.status, 200);
    let secret_id = Zeroizing::new(text(&secret_id.body, "/data/secret_id")?);
    let response = native_call(
        service,
        now,
        "",
        "POST",
        "auth/cg-native/login",
        json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()}),
    )?;
    assert_eq!(response.status, 200, "actual AppRole login status");
    Ok(Login {
        token: Zeroizing::new(text(&response.body, "/auth/client_token")?),
        entity: text(&response.body, "/auth/entity_id")?,
    })
}

fn setup_native(create_only: bool) -> TestResult<NativeFixture> {
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let mut now = 100;
    let mut initialized = native_call(
        &mut service,
        &mut now,
        "",
        "POST",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    )?;
    assert_eq!(
        initialized.status, 200,
        "actual Shamir initialization status"
    );
    let key = Zeroizing::new(text(&initialized.body, "/keys/0")?);
    let admin = Zeroizing::new(text(&initialized.body, "/root_token")?);
    erase_json(&mut initialized.body);
    assert_eq!(
        native_call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/unseal",
            json!({"key":key.as_str()}),
        )?
        .status,
        200,
    );
    assert_eq!(
        native_call(
            &mut service,
            &mut now,
            &admin,
            "POST",
            "sys/init/ack",
            json!({})
        )?
        .status,
        204,
    );
    assert_eq!(
        native_call(
            &mut service,
            &mut now,
            &admin,
            "POST",
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"2"}}),
        )?
        .status,
        204,
    );
    assert_eq!(
        native_call(
            &mut service,
            &mut now,
            &admin,
            "POST",
            "sys/auth/cg-native",
            json!({"type":"approle"}),
        )?
        .status,
        204,
    );
    let requester_policy = if create_only {
        requester_policy("600s", "")
            .replace(
                "[\"create\", \"update\", \"read\"]",
                "[\"create\", \"read\"]",
            )
            .replace(
                "controlled_capabilities = [\"update\"]",
                "controlled_capabilities = [\"create\"]",
            )
    } else {
        requester_policy("600s", "")
    };
    for (name, policy) in [
        ("cg-requester", requester_policy.as_str()),
        (
            "cg-approver",
            r#"path "sys/control-group/request" { capabilities = ["update"] }
               path "sys/control-group/authorize" { capabilities = ["update"] }
               path "sys/wrapping/unwrap" { capabilities = ["update"] }"#,
        ),
    ] {
        assert_eq!(
            native_call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                &format!("sys/policies/acl/{name}"),
                json!({"policy":policy}),
            )?
            .status,
            204,
        );
    }
    let requester = native_login(&mut service, &mut now, &admin, "requester", "cg-requester")?;
    let first = native_login(&mut service, &mut now, &admin, "first", "cg-approver")?;
    let second = native_login(&mut service, &mut now, &admin, "second", "cg-approver")?;
    assert_eq!(
        native_call(
            &mut service,
            &mut now,
            &admin,
            "POST",
            "identity/group",
            json!({"name":"cg-team","type":"internal",
                "member_entity_ids":[requester.entity,first.entity,second.entity]}),
        )?
        .status,
        200,
    );
    if !create_only {
        assert_eq!(
            native_call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                "secret/data/cg/key",
                json!({"data":{"value":"before"}}),
            )?
            .status,
            200,
        );
    }
    let activation = native_call(
        &mut service,
        &mut now,
        &admin,
        "POST",
        native_storage::ACTIVATE_PATH,
        json!({}),
    )?;
    assert_eq!(
        activation.status, 204,
        "configured File V6 activation status"
    );
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    Ok(NativeFixture {
        root,
        service,
        key,
        admin,
        requester,
        first,
        second,
        now,
    })
}

#[test]
fn native_cg_atomic_claim_and_kv_survive_cold_reopen_without_replay() -> TestResult {
    let mut f = setup_native(false)?;
    let (raw, accessor) = f.defer(1)?;
    f.assert_value(1, "before")?;
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "unapproved request must stay deferred"
    );
    f.approve(&accessor)?;
    let mut f = f.restart()?;
    let resumed = f.unwrap(&raw)?;
    assert_eq!(resumed.status, 200, "native approved resume status");
    assert_eq!(resumed.body["data"]["version"], 2);
    f.assert_value(2, "after")?;
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "spent claim must not execute twice"
    );
    let mut f = f.restart()?;
    f.assert_value(2, "after")?;
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "cold spent claim must stay spent"
    );
    f.assert_value(2, "after")?;
    Ok(())
}

#[test]
fn native_cg_create_only_requester_keeps_original_capability_after_publication() -> TestResult {
    let mut f = setup_native(true)?;
    let (raw, accessor) = f.defer(0)?;
    f.approve(&accessor)?;
    let response = f.unwrap(&raw)?;
    assert_eq!(
        response.status,
        200,
        "create-only native controlled write status errors={:?}",
        response.body.get("errors")
    );
    f.assert_value(1, "after")?;
    let mut f = f.restart()?;
    f.assert_value(1, "after")?;
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "cold first-create claim must stay spent"
    );
    let denied = f.request(
        Actor::Requester,
        "POST",
        "secret/data/cg/key",
        json!({"options":{"cas":1},"data":{"value":"forbidden-update"}}),
    )?;
    assert_eq!(
        denied.status, 403,
        "create-only does not grant later update"
    );
    f.assert_value(1, "after")?;
    Ok(())
}

#[test]
fn native_cg_first_create_with_pending_claim_and_pristine_namespace_survives_cold() -> TestResult {
    let mut f = setup_native(true)?;
    let (raw, accessor) = f.defer(0)?;
    let created = f.request(Actor::Admin, "POST", "sys/namespaces/cg-empty", json!({}))?;
    assert_eq!(
        created.status,
        200,
        "namespace with pending CG errors={:?}",
        created.body.get("errors")
    );
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("native state")?
            .namespaces
            .incarnation("cg-empty"),
        Some(1),
    );
    f.approve(&accessor)?;
    let foreign = {
        f.now += 1;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let clock = RequestClock::anchored(Duration::from_secs(f.now), Instant::now())?;
        let execution = f.service.begin_at_mode_precise(
            RequestDispatch {
                method: "POST",
                path: "sys/wrapping/unwrap",
                namespace: "cg-empty",
                token: &f.admin,
                body: json!({"token":raw.as_str()}),
                now: f.now,
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: None,
                origin_peer: None,
                client_certificates: None,
            },
            clock,
        );
        f.service.finish_synchronous_request(execution)
    };
    assert!(
        foreign.status >= 400,
        "a child route must not consume the approved root claim"
    );
    let mut f = f.restart()?;
    let cold_incarnation = f
        .service
        .state
        .as_ref()
        .and_then(|state| state.namespaces.incarnation("cg-empty"));
    assert_eq!(cold_incarnation, Some(1), "cold namespace catalog identity");
    assert!(
        f.service.native_root.is_some()
            && f.service.record_root.is_none()
            && !f.service.recovery_required,
        "cold namespace must retain actual native custody",
    );
    let catalog = f.request(Actor::Admin, "GET", "sys/namespaces/cg-empty", json!({}))?;
    assert_eq!(
        catalog.status,
        200,
        "the actual namespace catalog must survive with the approved CG claim; errors={:?}",
        catalog.body.get("errors"),
    );
    let resumed = f.unwrap(&raw)?;
    assert_eq!(
        resumed.status,
        200,
        "first CG write with pristine child errors={:?}",
        resumed.body.get("errors")
    );
    f.assert_value(1, "after")?;
    let mut f = f.restart()?;
    f.assert_value(1, "after")?;
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("cold native state")?
            .namespaces
            .incarnation("cg-empty"),
        Some(1),
    );
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "cold mixed-owner claim cannot execute again"
    );
    Ok(())
}

#[test]
fn native_cg_domain_cas_rejection_consumes_claim_without_target_mutation() -> TestResult {
    let mut f = setup_native(false)?;
    let (raw, accessor) = f.defer(0)?;
    f.approve(&accessor)?;
    let prior = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let rejected = f.unwrap(&raw)?;
    assert_eq!(
        rejected.status, 400,
        "domain CAS rejection must remain its first outcome"
    );
    assert!(
        f.service.native_root.as_ref().ok_or("native root")?.kv2 == prior,
        "domain rejection changed the native KV2 graph",
    );
    f.assert_value(1, "before")?;
    let mut f = f.restart()?;
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "rejected completed claim is not replayable"
    );
    f.assert_value(1, "before")?;
    Ok(())
}

#[test]
fn native_cg_revoked_approver_and_expired_request_cannot_publish_target() -> TestResult {
    let mut f = setup_native(false)?;
    let (raw, accessor) = f.defer(1)?;
    f.approve(&accessor)?;
    let first = Zeroizing::new(f.first.token.to_string());
    assert_eq!(
        f.request(
            Actor::Admin,
            "POST",
            "auth/token/revoke",
            json!({"token":first.as_str()})
        )?
        .status,
        204,
    );
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "revoked approver cannot supply live quorum"
    );
    f.assert_value(1, "before")?;
    f.now += 601;
    assert!(
        f.unwrap(&raw)?.status >= 400,
        "expired deferred request cannot execute"
    );
    f.assert_value(1, "before")?;
    Ok(())
}

#[test]
fn native_cg_review_and_finite_external_unwrapper_preserve_claim_ownership() -> TestResult {
    let mut f = setup_native(false)?;
    let (raw, accessor) = f.defer(1)?;
    let review = f.request(
        Actor::First,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(review.status, 200, "native review status");
    assert_eq!(review.body["data"]["approved"], false);
    assert_eq!(review.body["data"]["request_path"], "secret/data/cg/key");
    assert_eq!(review.body["data"]["request_operation"], "update");
    assert_eq!(
        review.body["data"]["request_data"]["data"]["value"],
        "after"
    );
    assert_eq!(
        review.body["data"]["authorizations"]
            .as_array()
            .map(Vec::len),
        Some(0),
    );
    f.approve(&accessor)?;
    let review = f.request(
        Actor::First,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(review.status, 200, "native approved review status");
    assert_eq!(review.body["data"]["approved"], true);
    assert_eq!(
        review.body["data"]["authorizations"]
            .as_array()
            .map(Vec::len),
        Some(2),
    );

    // This caller has one ordinary service-token use and is distinct from the
    // one-use wrapping credential in body.token. Real token API admission must
    // join exactly its consumption with the claim and KV write.
    let created = f.request(
        Actor::Admin,
        "POST",
        "auth/token/create",
        json!({"policies":["cg-approver"],"no_default_policy":true,
            "num_uses":1,"ttl":"1h"}),
    )?;
    assert_eq!(
        created.status, 200,
        "finite external caller creation status"
    );
    let caller = Zeroizing::new(text(&created.body, "/auth/client_token")?);
    let response = native_call(
        &mut f.service,
        &mut f.now,
        &caller,
        "POST",
        "sys/wrapping/unwrap",
        json!({"token":raw.as_str()}),
    )?;
    assert_eq!(
        response.status,
        200,
        "finite external unwrap status errors={:?}",
        response.body.get("errors")
    );
    f.assert_value(2, "after")?;
    assert!(
        f.request(
            Actor::Admin,
            "POST",
            "sys/wrapping/unwrap",
            json!({"token":raw.as_str()}),
        )?
        .status
            >= 400,
        "another caller cannot replay the spent claim",
    );

    // Rejecting the already consumed caller must leave a different approved
    // claim available to a valid caller, including after a cold reopen.
    let (next_raw, next_accessor) = f.defer(2)?;
    f.approve(&next_accessor)?;
    let rejected = native_call(
        &mut f.service,
        &mut f.now,
        &caller,
        "POST",
        "sys/wrapping/unwrap",
        json!({"token":next_raw.as_str()}),
    )?;
    assert_eq!(
        rejected.status, 403,
        "external caller use must be exhausted"
    );
    f.assert_value(2, "after")?;
    let mut f = f.restart()?;
    let completed = f.request(
        Actor::Admin,
        "POST",
        "sys/wrapping/unwrap",
        json!({"token":next_raw.as_str()}),
    )?;
    assert_eq!(
        completed.status, 200,
        "admission rejection must preserve claim"
    );
    f.assert_value(3, "after")?;
    Ok(())
}

const NATIVE_READ_POLICY: &str = r#"
path "secret/data/cg/*" {
  capabilities = ["read"]
  control_group = { ttl = "600s" factor "review" {
    controlled_capabilities = ["read"]
    identity { group_names = ["cg-team"] approvals = 2 self_authorization = false }
  } }
}
path "sys/control-group/request" { capabilities = ["update"] }
path "sys/control-group/authorize" { capabilities = ["update"] }
"#;

impl NativeFixture {
    fn read_policy(&mut self, policy: &str) -> TestResult {
        let response = self.request(
            Actor::Admin,
            "POST",
            "sys/policies/acl/cg-requester",
            json!({"policy":policy}),
        )?;
        assert_eq!(
            response.status,
            204,
            "formal native read policy status errors={:?}",
            response.body.get("errors")
        );
        Ok(())
    }

    fn defer_read(&mut self) -> TestResult<(Zeroizing<String>, String)> {
        let response = self.request(Actor::Requester, "GET", "secret/data/cg/key", json!({}))?;
        assert_eq!(
            response.status,
            200,
            "native controlled read deferral errors={:?}",
            response.body.get("errors")
        );
        assert!(response.body["data"].is_null());
        assert!(response.body["auth"].is_null());
        assert_eq!(
            response.body["wrap_info"]["creation_path"],
            "secret/data/cg/key"
        );
        Ok((
            Zeroizing::new(text(&response.body, "/wrap_info/token")?),
            text(&response.body, "/wrap_info/accessor")?,
        ))
    }
}

#[test]
fn native_cg_read_latest_immutable_value_survives_cold_and_fresh_approval() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let (raw, accessor) = f.defer_read()?;
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "unapproved read must not execute"
    );
    f.approve(&accessor)?;
    let changed = f.request(
        Actor::Admin,
        "POST",
        "secret/data/cg/key",
        json!({"options":{"cas":1},"data":{"value":"after-approval"}}),
    )?;
    assert_eq!(changed.status, 200);
    assert_eq!(changed.body["data"]["version"], 2);
    let mut f = f.restart()?;
    let graphs = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let response = f.unwrap(&raw)?;
    assert_eq!(
        response.status,
        200,
        "native controlled read completion errors={:?}",
        response.body.get("errors")
    );
    assert_eq!(
        response.body["data"]["data"],
        json!({"value":"after-approval"})
    );
    assert_eq!(response.body["data"]["metadata"]["version"], 2);
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    f.assert_value(2, "after-approval")?;
    assert_eq!(f.unwrap(&raw)?.status, 400, "one read cannot replay");
    let mut f = f.restart()?;
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "spent read survives cold reopen"
    );
    let (next_raw, next_accessor) = f.defer_read()?;
    assert!(next_raw.as_str() != raw.as_str());
    assert!(next_accessor != accessor);
    assert_eq!(
        f.unwrap(&next_raw)?.status,
        400,
        "new read needs new approval"
    );
    f.approve(&next_accessor)?;
    let next = f.unwrap(&next_raw)?;
    assert_eq!(next.status, 200);
    assert_eq!(next.body["data"]["data"], json!({"value":"after-approval"}));
    assert_eq!(next.body["data"]["metadata"]["version"], 2);
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    assert_eq!(f.unwrap(&next_raw)?.status, 400);
    f.assert_value(2, "after-approval")?;
    Ok(())
}

#[test]
fn native_cg_read_current_acl_denial_preserves_unexecuted_claim() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let (raw, accessor) = f.defer_read()?;
    f.approve(&accessor)?;
    let graphs = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    f.read_policy(r#"path "secret/data/cg/*" { capabilities = ["update"] }"#)?;
    let denied = f.unwrap(&raw)?;
    assert_eq!(
        denied.status, 403,
        "stored approval cannot replace current read ACL"
    );
    assert!(denied.body["data"].is_null());
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_owners()
            .any(|owner| owner.request_accessor == accessor),
        "admission rejection consumed an unexecuted read claim"
    );
    let mut f = f.restart()?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let response = f.unwrap(&raw)?;
    assert_eq!(
        response.status, 200,
        "restored current ACL can use retained approval"
    );
    assert_eq!(response.body["data"]["data"], json!({"value":"before"}));
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    assert_eq!(f.unwrap(&raw)?.status, 400);
    Ok(())
}

#[test]
fn native_cg_read_domain_absence_spends_claim_without_graph_mutation() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let (raw, accessor) = f.defer_read()?;
    f.approve(&accessor)?;
    assert_eq!(
        f.request(Actor::Admin, "DELETE", "secret/data/cg/key", json!({}))?
            .status,
        204
    );
    let graphs = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let absent = f.unwrap(&raw)?;
    assert_eq!(
        absent.status, 404,
        "completed immutable read retains its domain outcome"
    );
    assert!(absent.body["data"]["data"].is_null());
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    let mut f = f.restart()?;
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "completed absence cannot execute twice"
    );
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    Ok(())
}

#[test]
fn native_cg_read_response_audit_failure_releases_no_value_and_spent_claim_survives_cold()
-> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let (raw, accessor) = f.defer_read()?;
    f.approve(&accessor)?;
    let owner = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .control_group_owners()
        .find(|owner| owner.request_accessor == accessor)
        .ok_or("approved read owner")?
        .clone();
    let graphs = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let sequence = f.service.audit_sequence;
    // Use the existing bounded audit I/O injection. Exactly one real ingress
    // request record fits; the mandatory response audit cannot append a byte.
    let unsigned = AuditUnsigned {
        schema: 2,
        sequence: sequence.checked_add(1).ok_or("audit sequence")?,
        previous: STANDARD.encode(f.service.audit_previous),
        time: f.now.checked_add(1).ok_or("request time")?,
        kind: "request".to_owned(),
        path_digest: f
            .service
            .request_fingerprint("POST", "sys/wrapping/unwrap", "", &raw),
        status: None,
    };
    let payload = serde_json::to_vec(&unsigned)?;
    let record = AuditRecord {
        event: unsigned,
        mac: STANDARD.encode(hmac::sign(&f.service.audit_key, &payload).as_ref()),
    };
    let request_bytes = u64::try_from(serde_json::to_vec(&record)?.len())?
        .checked_add(1)
        .ok_or("audit record size")?;
    f.service.audit_capacity = f
        .service
        .audit
        .metadata()?
        .len()
        .checked_add(request_bytes)
        .ok_or("audit capacity")?;
    let denied = f.unwrap(&raw)?;
    assert_eq!(
        denied.status, 503,
        "mandatory response audit must veto private read delivery"
    );
    assert!(denied.body["data"].is_null());
    assert!(denied.body["auth"].is_null());
    assert!(denied.body["wrap_info"].is_null());
    assert_eq!(
        f.service.audit_sequence,
        sequence + 1,
        "only real ingress was audited"
    );
    assert!(f.service.recovery_required);
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .native_cg_claim_is_spent(&owner)
    );
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    let mut f = f.restart()?;
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "withheld completed read stays one-use after cold reopen"
    );
    f.assert_value(1, "before")?;
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    Ok(())
}

#[test]
fn native_cg_read_approval_rejections_match_official_271_wire_errors() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let (raw, accessor) = f.defer_read()?;
    let self_denied = f.request(
        Actor::Requester,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(self_denied.status, 500);
    assert_eq!(
        self_denied.body["errors"],
        json!(["1 error occurred:\n\t* token owner cannot be approver\n\n"]),
    );
    let first = f.request(
        Actor::First,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["approved"], false);
    let duplicate_denied = f.request(
        Actor::First,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(duplicate_denied.status, 500);
    assert_eq!(
        duplicate_denied.body["errors"],
        json!(["1 error occurred:\n\t* approver has already authorized\n\n"]),
    );
    for denied in [&self_denied, &duplicate_denied] {
        assert!(denied.body["data"].is_null());
        assert!(denied.body["auth"].is_null());
        assert!(denied.body["wrap_info"].is_null());
    }
    let review = f.request(
        Actor::First,
        "POST",
        "sys/control-group/request",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(review.status, 200);
    assert_eq!(review.body["data"]["approved"], false);
    assert_eq!(
        review.body["data"]["authorizations"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "rejected self and duplicate approval cannot increase distinct quorum",
    );
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "one distinct approver is insufficient"
    );
    let second = f.request(
        Actor::Second,
        "POST",
        "sys/control-group/authorize",
        json!({"accessor":accessor}),
    )?;
    assert_eq!(second.status, 200);
    assert_eq!(second.body["data"]["approved"], true);
    let mut f = f.restart()?;
    let graphs = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let completed = f.unwrap(&raw)?;
    assert_eq!(completed.status, 200);
    assert_eq!(completed.body["data"]["data"], json!({"value":"before"}));
    assert_eq!(completed.body["data"]["metadata"]["version"], 1);
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graphs);
    assert_eq!(
        f.unwrap(&raw)?.status,
        400,
        "error compatibility cannot reopen the completed claim"
    );
    Ok(())
}

#[test]
fn native_cg_http_headers_read_approval_latest_value_and_spent_claim_survive_cold() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let mut deferred = f.wire_request(Actor::Requester, "GET", "secret/data/cg/key", json!({}))?;
    assert_eq!(
        deferred.status,
        200,
        "ordinary HTTP headers must admit the original controlled read; errors={:?}",
        deferred.body.get("errors"),
    );
    assert!(deferred.body["data"].is_null());
    assert!(deferred.body["auth"].is_null());
    assert_eq!(
        deferred.body["wrap_info"]["creation_path"],
        "secret/data/cg/key"
    );
    let raw = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let accessor = text(&deferred.body, "/wrap_info/accessor")?;
    erase_json(&mut deferred.body);
    let owner = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .control_group_owners()
        .find(|owner| owner.request_accessor == accessor)
        .ok_or("wire read owner")?;
    assert!(owner.logical_data.is_none());
    assert!(owner.credential.is_none());
    assert_eq!(
        f.wire_unwrap(&raw)?.status,
        400,
        "ordinary headers must not replace approval"
    );
    f.wire_approve(&accessor)?;
    let changed = f.wire_request(
        Actor::Admin,
        "POST",
        "secret/data/cg/key",
        json!({"options":{"cas":1},"data":{"value":"wire-after-approval"}}),
    )?;
    assert_eq!(changed.status, 200);
    assert_eq!(changed.body["data"]["version"], 2);
    let mut f = f.restart()?;
    let graph = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let completed = f.wire_unwrap(&raw)?;
    assert_eq!(completed.status, 200, "wire approved cold read status");
    assert_eq!(
        completed.body["data"]["data"],
        json!({"value":"wire-after-approval"})
    );
    assert_eq!(completed.body["data"]["metadata"]["version"], 2);
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graph);
    assert_eq!(f.wire_unwrap(&raw)?.status, 400, "wire read is single use");
    let mut f = f.restart()?;
    assert_eq!(
        f.wire_unwrap(&raw)?.status,
        400,
        "wire spent claim survives another cold reopen"
    );
    f.assert_value(2, "wire-after-approval")?;
    Ok(())
}

#[test]
fn native_cg_http_headers_write_retains_cas_approval_and_cold_single_use() -> TestResult {
    let mut f = setup_native(false)?;
    let mut deferred = f.wire_request(
        Actor::Requester,
        "POST",
        "secret/data/cg/key",
        json!({"options":{"cas":1},"data":{"value":"wire-write"}}),
    )?;
    assert_eq!(deferred.status, 200, "wire controlled write deferral");
    assert!(deferred.body["data"].is_null());
    assert!(deferred.body["auth"].is_null());
    let raw = Zeroizing::new(text(&deferred.body, "/wrap_info/token")?);
    let accessor = text(&deferred.body, "/wrap_info/accessor")?;
    erase_json(&mut deferred.body);
    assert_eq!(f.wire_unwrap(&raw)?.status, 400);
    f.assert_value(1, "before")?;
    f.wire_approve(&accessor)?;
    let mut f = f.restart()?;
    let completed = f.wire_unwrap(&raw)?;
    assert_eq!(completed.status, 200, "wire approved cold write");
    assert_eq!(completed.body["data"]["version"], 2);
    f.assert_value(2, "wire-write")?;
    assert_eq!(f.wire_unwrap(&raw)?.status, 400);
    let mut f = f.restart()?;
    assert_eq!(f.wire_unwrap(&raw)?.status, 400);
    f.assert_value(2, "wire-write")?;
    Ok(())
}

#[test]
fn native_cg_http_custom_logical_header_is_rejected_without_a_claim_or_kv_effect() -> TestResult {
    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let graph = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let count = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .control_group_owners()
        .count();
    let denied = native_wire_call(
        &mut f.service,
        &mut f.now,
        &f.requester.token,
        "GET",
        "secret/data/cg/key",
        json!({}),
        "X-Workflow-Input: custom-input\r\n",
    )?;
    assert_eq!(denied.status, 501);
    assert_eq!(
        denied.body["errors"],
        json!(["unsupported native controlled action"])
    );
    assert!(denied.body["data"].is_null());
    assert!(denied.body["auth"].is_null());
    assert!(denied.body["wrap_info"].is_null());
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graph);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .control_group_owners()
            .count(),
        count,
        "semantic metadata rejection cannot create a deferred claim",
    );
    let mut f = f.restart()?;
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graph);
    f.assert_value(1, "before")?;
    let admitted = f.wire_request(Actor::Requester, "GET", "secret/data/cg/key", json!({}))?;
    assert_eq!(admitted.status, 200, "ordinary metadata remains admissible");
    assert!(admitted.body["data"].is_null());
    assert!(admitted.body["wrap_info"]["token"].is_string());
    Ok(())
}

#[test]
fn native_cg_query_and_profile_data_keep_the_original_route_rejection() -> TestResult {
    use crate::request_metadata::{DataFrame, QueryProfile, Scope};

    let mut f = setup_native(false)?;
    f.read_policy(NATIVE_READ_POLICY)?;
    let graph = f
        .service
        .native_root
        .as_ref()
        .ok_or("native root")?
        .kv2
        .clone();
    let mut query = DataFrame::default();
    query
        .headers
        .insert("accept".to_owned(), vec!["application/json".to_owned()]);
    query
        .query
        .insert("version".to_owned(), vec!["1".to_owned()]);
    let document = "{}";
    let mut profile = DataFrame {
        local_redirect: None,
        headers: Default::default(),
        query: Default::default(),
        profile: Some(QueryProfile {
            namespace_id: "root".to_owned(),
            incarnation: 0,
            path: "cg-input".to_owned(),
            version: 1,
            document: document.to_owned(),
            digest: crate::crypto::digest(document.as_bytes()),
        }),
    };
    profile
        .headers
        .insert("accept".to_owned(), vec!["application/json".to_owned()]);
    for data in [query, profile] {
        data.validate()?;
        let body = json!({});
        let scope = Scope::enter(Some(data), "GET", "secret/data/cg/key", "", &body)?;
        let denied = f.request(Actor::Requester, "GET", "secret/data/cg/key", body)?;
        drop(scope);
        assert_eq!(denied.status, 400);
        assert_eq!(
            denied.body["errors"],
            json!(["workflow query data belongs to another route"])
        );
        assert!(denied.body["data"].is_null());
        assert!(denied.body["auth"].is_null());
        assert!(denied.body["wrap_info"].is_null());
        assert_eq!(
            f.service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .control_group_owners()
                .count(),
            0,
            "workflow metadata rejection cannot create a native claim",
        );
        assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graph);
    }
    let mut f = f.restart()?;
    assert!(f.service.native_root.as_ref().ok_or("native root")?.kv2 == graph);
    f.assert_value(1, "before")?;
    let admitted = f.wire_request(Actor::Requester, "GET", "secret/data/cg/key", json!({}))?;
    assert_eq!(admitted.status, 200);
    assert!(admitted.body["data"].is_null());
    assert!(admitted.body["wrap_info"]["token"].is_string());
    Ok(())
}

#[path = "service_native_controlgroups_271_semantics_tests.rs"]
mod compatibility_271_matrix;

#[path = "service_native_controlgroups_271_namespace_tests.rs"]
mod namespace_271_tests;
