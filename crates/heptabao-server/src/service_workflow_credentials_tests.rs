//! Credential steps exercise the real affine Service entry, not an auth mock.
use super::*;

const READ_PROFILE: &str = r#"input { field "string" "credential" { required = true } }
flow "read" { request "kv" {
 operation = "read" path = "secret/data/cg/key"
 token = { eval_source = "input" eval_type = "string" field_name = "credential" }
} }
output { data = { value = { eval_source = "response" eval_type = "string"
 flow_name = "read" response_name = "kv" field_selector = "data.data.value" } } }"#;

fn install(f: &mut Fixture, document: &str) {
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/workflows/manage/wf128",
            json!({"workflow":document}),
            100
        )
        .status,
        200
    );
}
fn execute(
    f: &mut Fixture,
    outer: &str,
    input: Value,
    now: u64,
    wall: Option<std::time::Duration>,
    origin: Option<std::net::IpAddr>,
    certificates: Option<Vec<Vec<u8>>>,
) -> TestResult<Response> {
    let request = RequestDispatch {
        method: "POST",
        path: "sys/workflows/execute/wf128",
        namespace: "",
        token: outer,
        body: input,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: origin,
        client_certificates: certificates,
    };
    let execution = match wall {
        Some(wall) => {
            let clock = RequestClock::anchored(wall, std::time::Instant::now())?;
            f.service.begin_at_mode_precise(request, clock)
        }
        None => f.service.begin_at_mode(request),
    };
    match execution {
        RequestExecution::Complete(response) => Ok(response),
        RequestExecution::External(_) => {
            Err("native workflow unexpectedly returned a provider plan".into())
        }
    }
}
fn reader(f: &mut Fixture, name: &str, uses: u64, cidrs: Value) -> TestResult<Login> {
    policy_write(
        &mut f.service,
        &f.admin,
        "wf128-reader",
        r#"path "secret/data/cg/key" { capabilities = ["read"] }"#,
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            &format!("auth/cg-login/users/{name}"),
            json!({"password":"synthetic-cg-password","token_policies":["wf128-reader"],
        "token_no_default_policy":true,"token_num_uses":uses,"token_ttl":"10s",
        "token_max_ttl":"10s","token_bound_cidrs":cidrs}),
            100
        )
        .status,
        204
    );
    let response = f.service.handle_at_mode(RequestDispatch {
        method: "POST",
        path: &format!("auth/cg-login/login/{name}"),
        namespace: "",
        token: "",
        body: json!({"password":"synthetic-cg-password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: Some("127.0.0.1".parse()?),
        client_certificates: None,
    });
    assert_eq!(response.status, 200);
    Ok(Login {
        token: Zeroizing::new(text(&response.body, "/auth/client_token")?),
        entity: text(&response.body, "/auth/entity_id")?,
    })
}

#[test]
fn workflow128_explicit_token_reauth_enforces_acl_finite_use_and_whole_program_preflight()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    install(&mut f, READ_PROFILE);
    let admin = Zeroizing::new(f.admin.to_string());
    let reader = reader(&mut f, "wf128-once", 1, json!([]))?;
    let input = json!({"credential":reader.token.as_str()});
    let allowed = execute(&mut f, &admin, input.clone(), 100, None, None, None)?;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["data"]["value"], "before");
    assert_raw_absent(&f, &reader.token)?;
    let denied = execute(&mut f, &admin, input, 100, None, None, None)?;
    assert_eq!(denied.status, 403);
    assert!(denied.body.get("auth").is_none());
    read(&mut f, 1, "before", 100);
    // An outer root cannot replace an explicitly supplied unprivileged actor.
    let outsider = Zeroizing::new(f.outsider.token.to_string());
    let denied = execute(
        &mut f,
        &admin,
        json!({"credential":outsider.as_str()}),
        100,
        None,
        None,
        None,
    )?;
    assert_eq!(denied.status, 403);
    read(&mut f, 1, "before", 100);
    // Independent token typing is checked for every step before the first write.
    let late = r#"input { field "map" "credential" { required = true } }
    flow "write" { request "early" { operation = "update" path = "secret/data/cg/key"
      data = { data = { value = "must-not-execute" } } }
      request "late" { operation = "read" path = "secret/data/cg/key"
        token = { eval_source = "input" eval_type = "map" field_name = "credential" } } }
    output { data = {} }"#;
    install(&mut f, late);
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"credential":{"not":"a bearer"}}),
            100,
            None,
            None,
            None
        )?
        .status,
        400
    );
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
    Ok(())
}

#[test]
fn workflow128_empty_userpass_login_chains_actual_entity_and_live_policy_without_outer_actor()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let login = reader(&mut f, "wf128-login", 0, json!([]))?;
    let document = r#"input { field "string" "password" { required = true } }
      flow "login" { request "native" { operation = "update" path = "auth/cg-login/login/wf128-login"
        token = "" data = { password = { eval_source = "input" eval_type = "string" field_name = "password" } } } }
      flow "read" { request "kv" { operation = "read" path = "secret/data/cg/key"
        token = { eval_source = "response" eval_type = "string" flow_name = "login"
          response_name = "native" field_selector = "auth.client_token" } } }
      output { data = {
        entity = { eval_source = "response" eval_type = "string" flow_name = "login"
          response_name = "native" field_selector = "auth.entity_id" }
        value = { eval_source = "response" eval_type = "string" flow_name = "read"
          response_name = "kv" field_selector = "data.data.value" }
      } }"#;
    install(&mut f, document);
    let admin = Zeroizing::new(f.admin.to_string());
    let allowed = execute(
        &mut f,
        &admin,
        json!({"password":"synthetic-cg-password"}),
        100,
        Some(std::time::Duration::new(100, 125_000_000)),
        None,
        None,
    )?;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["data"]["entity"], login.entity);
    assert_eq!(allowed.body["data"]["value"], "before");
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"password":"incorrect"}),
            100,
            None,
            None,
            None
        )?
        .status,
        400
    );
    read(&mut f, 1, "before", 100);
    policy_write(
        &mut f.service,
        &admin,
        "wf128-reader",
        r#"path "secret/data/cg/key" { capabilities = ["deny"] }"#,
    );
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"password":"synthetic-cg-password"}),
            100,
            None,
            None,
            None
        )?
        .status,
        403
    );
    // Disabling the actual projected entity rejects a fresh successful password,
    // before any returned token can be used by the second workflow step.
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "POST",
            &format!("identity/entity/id/{}", login.entity),
            json!({"disabled":true}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"password":"synthetic-cg-password"}),
            100,
            None,
            None,
            None
        )?
        .status,
        403
    );
    read(&mut f, 1, "before", 100);
    Ok(())
}

#[test]
fn workflow128_approle_login_consumes_one_secret_id_and_restores_lexical_ingress() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    policy_write(
        &mut f.service,
        &f.admin,
        "wf128-reader",
        r#"path "secret/data/cg/key" { capabilities = ["read"] }"#,
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/auth/wf128-role",
            json!({"type":"approle"}),
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
            "auth/wf128-role/role/native",
            json!({"token_policies":["wf128-reader"],
        "secret_id_num_uses":1,"token_ttl":60}),
            100
        )
        .status,
        204
    );
    let rid = call(
        &mut f.service,
        &f.admin,
        "GET",
        "auth/wf128-role/role/native/role-id",
        json!({}),
        100,
    );
    let sid = call(
        &mut f.service,
        &f.admin,
        "POST",
        "auth/wf128-role/role/native/secret-id",
        json!({}),
        100,
    );
    assert_eq!(rid.status, 200);
    assert_eq!(sid.status, 200);
    let role = Zeroizing::new(text(&rid.body, "/data/role_id")?);
    let secret = Zeroizing::new(text(&sid.body, "/data/secret_id")?);
    let document = r#"input {
      field "string" "role" { required = true }
      field "string" "secret" { required = true }
    }
    flow "login" { request "native" { operation = "update" path = "auth/wf128-role/login"
      token = "" data = {
        role_id = { eval_source = "input" eval_type = "string" field_name = "role" }
        secret_id = { eval_source = "input" eval_type = "string" field_name = "secret" }
      } } }
    flow "read" { request "kv" { operation = "read" path = "secret/data/cg/key"
      token = { eval_source = "response" eval_type = "string" flow_name = "login"
        response_name = "native" field_selector = "auth.client_token" } } }
    output { data = { value = { eval_source = "response" eval_type = "string"
      flow_name = "read" response_name = "kv" field_selector = "data.data.value" } } }"#;
    install(&mut f, document);
    let admin = Zeroizing::new(f.admin.to_string());
    let attempt = [0x28; 16];
    let _scope = crate::auth::IngressReplyScope::listener(&attempt);
    let allowed = execute(
        &mut f,
        &admin,
        json!({"role":role.as_str(),"secret":secret.as_str()}),
        100,
        Some(std::time::Duration::new(100, 125_000_000)),
        None,
        None,
    )?;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["data"]["value"], "before");
    let restored = crate::auth::current_ingress().ok_or("ingress was lost")?;
    assert_eq!(restored.attempt_id(), attempt);
    assert!(restored.wrapping_body().is_none());
    f = restart(f, 100)?;
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"role":role.as_str(),"secret":secret.as_str()}),
            100,
            None,
            None,
            None
        )?
        .status,
        400
    );
    read(&mut f, 1, "before", 100);
    assert_raw_absent(&f, &secret)?;
    assert!(f.service.pending_workflow_external_hold.is_none());
    Ok(())
}

#[test]
fn workflow128_cert_login_uses_original_verified_chain_and_role_constraints() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    policy_write(
        &mut f.service,
        &f.admin,
        "wf128-reader",
        r#"path "secret/data/cg/key" { capabilities = ["read"] }"#,
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/auth/wf128-cert",
            json!({"type":"cert"}),
            100
        )
        .status,
        204
    );
    let leaf = include_bytes!("../testdata/cert-selector.der").to_vec();
    let digest: String = crate::crypto::digest(&leaf)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "auth/wf128-cert/certs/native",
            json!({"certificate_sha256":digest,"allowed_common_names":["client.example.test"],
        "token_policies":["wf128-reader"],"token_ttl":"10s","token_max_ttl":"10s"}),
            100
        )
        .status,
        204
    );
    let document = r#"flow "login" { request "native" { operation = "update" path = "auth/wf128-cert/login"
      token = "" data = { name = "native" } } }
      flow "read" { request "kv" { operation = "read" path = "secret/data/cg/key"
        token = { eval_source = "response" eval_type = "string" flow_name = "login"
          response_name = "native" field_selector = "auth.client_token" } } }
      output { data = { value = { eval_source = "response" eval_type = "string"
        flow_name = "read" response_name = "kv" field_selector = "data.data.value" } } }"#;
    install(&mut f, document);
    let admin = Zeroizing::new(f.admin.to_string());
    let allowed = execute(
        &mut f,
        &admin,
        json!({}),
        100,
        None,
        Some("127.0.0.1".parse()?),
        Some(vec![leaf.clone()]),
    )?;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["data"]["value"], "before");
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({}),
            100,
            None,
            Some("127.0.0.1".parse()?),
            None
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "POST",
            "auth/wf128-cert/certs/native",
            json!({"allowed_common_names":["different.example.test"]}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({}),
            100,
            None,
            Some("127.0.0.1".parse()?),
            Some(vec![leaf.clone()])
        )?
        .status,
        403
    );
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "POST",
            "auth/wf128-cert/certs/native",
            json!({"allowed_common_names":["client.example.test"]}),
            100
        )
        .status,
        204
    );
    // The leaf digest and actual common-name constraints are both checked.
    let mut wrong = leaf;
    let last = wrong.last_mut().ok_or("certificate")?;
    *last ^= 1;
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({}),
            100,
            None,
            Some("127.0.0.1".parse()?),
            Some(vec![wrong])
        )?
        .status,
        403
    );
    read(&mut f, 1, "before", 100);
    Ok(())
}

#[test]
fn workflow128_explicit_requester_keeps_deferred_identity_and_once_only_approval_after_restart()
-> TestResult {
    for precise in [false, true] {
        let mut f = setup()?;
        create(&mut f);
        let document = r#"input { field "string" "credential" { required = true } }
          flow "controlled" { request "write" { operation = "update" path = "secret/data/cg/key"
            token = { eval_source = "input" eval_type = "string" field_name = "credential" }
            data = { data = { value = "after" } } } }
          output { data = { wrapping = { eval_source = "response" eval_type = "any"
            flow_name = "controlled" response_name = "write" field_selector = "wrap_info" } } }"#;
        install(&mut f, document);
        let admin = Zeroizing::new(f.admin.to_string());
        let requester = Zeroizing::new(f.requester.token.to_string());
        let pending = execute(
            &mut f,
            &admin,
            json!({"credential":requester.as_str()}),
            100,
            precise.then_some(std::time::Duration::new(100, 125_000_000)),
            None,
            None,
        )?;
        assert_eq!(pending.status, 200);
        let wrapper = Zeroizing::new(text(&pending.body, "/data/wrapping/token")?);
        let accessor = text(&pending.body, "/data/wrapping/accessor")?;
        let review = review_request(&mut f, &accessor);
        assert_eq!(review.status, 200);
        assert_eq!(
            review.body["data"]["request_entity"]["ID"],
            f.requester.entity
        );
        assert_eq!(
            review.body["data"]["request_data"],
            json!({"data":{"value":"after"}})
        );
        assert_eq!(review.body["data"]["approved"], false);
        read(&mut f, 1, "before", 100);
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
        f = restart(f, 100)?;
        approve_two(&mut f, &accessor);
        let resumed = call(
            &mut f.service,
            &wrapper,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100,
        );
        assert_eq!(resumed.status, 200);
        assert_eq!(resumed.body["data"]["version"], 2);
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
        // A separately deferred request is vetoed by its own current policy.
        let second = execute(
            &mut f,
            &admin,
            json!({"credential":requester.as_str()}),
            100,
            None,
            None,
            None,
        )?;
        assert_eq!(second.status, 200);
        let wrapper = Zeroizing::new(text(&second.body, "/data/wrapping/token")?);
        let accessor = text(&second.body, "/data/wrapping/accessor")?;
        approve_two(&mut f, &accessor);
        policy_write(
            &mut f.service,
            &admin,
            "cg-requester",
            r#"path "secret/data/cg/*" { capabilities = ["deny"] }"#,
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
        read(&mut f, 2, "after", 100);
        assert_raw_absent(&f, &requester)?;
    }
    Ok(())
}

#[test]
fn workflow128_original_clock_origin_namespace_and_closed_native_scope_are_not_replaced()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    install(&mut f, READ_PROFILE);
    let admin = Zeroizing::new(f.admin.to_string());
    let restricted = reader(&mut f, "wf128-origin", 0, json!(["127.0.0.1/32"]))?;
    let input = json!({"credential":restricted.token.as_str()});
    assert_eq!(
        execute(
            &mut f,
            &admin,
            input.clone(),
            100,
            None,
            Some("127.0.0.1".parse()?),
            None
        )?
        .status,
        200
    );
    assert_eq!(
        execute(
            &mut f,
            &admin,
            input.clone(),
            100,
            None,
            Some("127.0.0.2".parse()?),
            None
        )?
        .status,
        403
    );
    assert_eq!(
        execute(&mut f, &admin, input.clone(), 100, None, None, None)?.status,
        403
    );
    // The precise ingress is already past expiry while integer now still says100.
    assert_eq!(
        execute(
            &mut f,
            &admin,
            input,
            100,
            Some(std::time::Duration::new(111, 125_000_000)),
            Some("127.0.0.1".parse()?),
            None
        )?
        .status,
        403
    );
    read(&mut f, 1, "before", 111);
    // A child namespace bearer cannot acquire the outer root namespace's read ACL.
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "POST",
            "sys/namespaces/wf128-child",
            json!({}),
            111
        )
        .status,
        200
    );
    assert_eq!(
        f.service
            .handle_at(
                "POST",
                "sys/auth/cg-login",
                "wf128-child/",
                &admin,
                json!({"type":"userpass"}),
                111
            )
            .status,
        204
    );
    assert_eq!(
        f.service
            .handle_at(
                "POST",
                "sys/policies/acl/wf128-reader",
                "wf128-child/",
                &admin,
                json!({"policy":r#"path "secret/data/cg/key" { capabilities = ["read"] }"#}),
                111
            )
            .status,
        204
    );
    assert_eq!(f.service.handle_at("POST","auth/cg-login/users/native","wf128-child/",&admin,
        json!({"password":"synthetic-cg-password","token_policies":["wf128-reader"],"token_no_default_policy":true}),111).status,204);
    let child = f.service.handle_at(
        "POST",
        "auth/cg-login/login/native",
        "wf128-child/",
        "",
        json!({"password":"synthetic-cg-password"}),
        111,
    );
    assert_eq!(child.status, 200);
    let child_token = Zeroizing::new(text(&child.body, "/auth/client_token")?);
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"credential":child_token.as_str()}),
            111,
            None,
            None,
            None
        )?
        .status,
        403
    );
    // An explicit credential never dispatches arbitrary admin/provider effects.
    let excluded = r#"flow "closed" { request "admin" { operation = "update" path = "sys/mounts/wf128-external"
      token = { eval_source = "input" eval_type = "string" field_name = "credential" }
      data = { type = "database" } } } output { data = {} }"#;
    let excluded =
        String::from(r#"input { field "string" "credential" { required = true } }"#) + excluded;
    install(&mut f, &excluded);
    assert_eq!(
        execute(
            &mut f,
            &admin,
            json!({"credential":admin.as_str()}),
            111,
            None,
            None,
            None
        )?
        .status,
        400
    );
    assert!(f.service.pending_workflow_external_hold.is_none());
    assert_eq!(
        call(&mut f.service, &admin, "GET", "sys/mounts", json!({}), 111).body["data"]["wf128-external/"],
        Value::Null
    );
    read(&mut f, 1, "before", 111);
    Ok(())
}

#[test]
fn workflow128_active_and_retired_reader_floor_survives_actual_commit_and_reopen() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let previous = f.service.state.as_ref().ok_or("state")?.clone();
    assert!(!previous.namespaces.workflows.has_request_credentials());
    let original_workflows = serde_json::to_value(&previous.namespaces.workflows)?;
    assert!(supported_reader_schema(previous.schema));
    install(&mut f, READ_PROFILE);
    let current = f.service.state.as_ref().ok_or("state")?.clone();
    assert_eq!(current.schema, WORKFLOW_CREDENTIAL_STATE_SCHEMA);
    assert_eq!(current.writer_schema(), WORKFLOW_CREDENTIAL_STATE_SCHEMA);
    assert!(current.namespaces.workflows.has_request_credentials());
    current.validate_format().map_err(|_| "credential format")?;
    current
        .validate_publication_schema(Some(&previous))
        .map_err(|_| "credential publication")?;
    for schema in [
        WORKFLOW_PROFILE_STATE_SCHEMA,
        WORKFLOW_EXPRESSION_STATE_SCHEMA,
        TRANSIT_DERIVED_ED_STATE_SCHEMA,
    ] {
        let mut downgrade = current.clone();
        downgrade.schema = schema;
        assert!(downgrade.validate_format().is_err());
        assert!(
            downgrade
                .validate_publication_schema(Some(&current))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&current, &downgrade).is_err());
    }
    let admin = Zeroizing::new(f.admin.to_string());
    f = restart(f, 100)?;
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        WORKFLOW_CREDENTIAL_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "DELETE",
            "sys/workflows/manage/wf128",
            json!({}),
            100
        )
        .status,
        204
    );
    let retired = f.service.state.as_ref().ok_or("state")?.clone();
    assert!(!retired.namespaces.workflows.has_request_credentials());
    assert_eq!(retired.schema, WORKFLOW_CREDENTIAL_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), WORKFLOW_CREDENTIAL_STATE_SCHEMA);
    assert_eq!(
        serde_json::to_value(&retired.namespaces.workflows)?,
        original_workflows
    );
    let mut stale = retired.clone();
    stale.schema = TRANSIT_DERIVED_ED_STATE_SCHEMA;
    assert!(stale.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &stale).is_err());
    f = restart(f, 100)?;
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        WORKFLOW_CREDENTIAL_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut f.service,
            &admin,
            "GET",
            "sys/workflows/manage/wf128",
            json!({}),
            100
        )
        .status,
        404
    );
    Ok(())
}
