//! Original Service and HTTP-owned inputs; all credentials/payloads are synthetic.
use super::*;

const QUERY_PROFILE: &str = r#"input {
 field "string" "value" { required = true query = true }
}
flow "store" { request "kv" {
 operation = "update" path = "secret/data/cg/key"
 headers = { X-Review = ["workflow-header"] }
 data = { data = { value = { eval_source = "input" eval_type = "string" field_name = "value" } } }
} }
output { data = {
 value = { eval_source = "input" eval_type = "string" field_name = "value" }
 headers = { eval_source = "request" eval_type = "map" flow_name = "store" request_name = "kv" field_selector = "headers" }
} }"#;

fn install_logical(f: &mut Fixture, document: &str) {
    let response = call(
        &mut f.service,
        &f.admin,
        "POST",
        "sys/workflows/manage/wf131",
        json!({"workflow":document}),
        100,
    );
    assert_eq!(response.status, 200, "workflow install errors: {}",
        response.body.get("errors").unwrap_or(&Value::Null));
}
fn wire(
    f: &mut Fixture,
    token: &str,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    extra: &str,
) -> TestResult<Response> {
    let encoded = Zeroizing::new(serde_json::to_vec(&body)?);
    let head = Zeroizing::new(format!(
        "{method} /v1/{path} HTTP/1.1\r\nHost: fixture\r\n\
        X-Vault-Token: {token}\r\nX-Vault-Namespace: {namespace}\r\n\
        Content-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n",
        encoded.len()
    ));
    let mut bytes = Zeroizing::new(head.as_bytes().to_vec());
    bytes.extend_from_slice(&encoded);
    crate::http::logical_data_wire_fixture(&mut f.service, &bytes, 100)
        .map_err(|_| "actual logical HTTP ingress failed".into())
}
fn assert_logical_userpass_floor(state: &State) -> TestResult {
    assert!(state.auth.has_userpass_issuance_state());
    assert!(state.namespaces.workflows.has_logical_input_profiles()
        || state.auth.has_control_group_logical_data());
    assert_eq!(state.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert_eq!(state.writer_schema(), USERPASS_ISSUANCE_STATE_SCHEMA);
    state.validate_format().map_err(|_| "combined logical/Userpass format")?;
    Ok(())
}
fn logical_cg_record_key(encoded_auth: &Value, accessor: &str) -> TestResult<String> {
    let requests = encoded_auth.pointer("/control_groups/requests")
        .and_then(Value::as_object).ok_or("actual deferred request registry")?;
    // Public accessors identify a complete stored owner, but are not its map key.
    assert!(requests.get(accessor).is_none());
    let mut matches = requests.iter().filter(|(_, owner)| {
        owner.get("request_accessor").and_then(Value::as_str) == Some(accessor)
    });
    let (key, owner) = matches.next().ok_or("actual deferred request record")?;
    assert!(matches.next().is_none());
    assert!(owner.get("cluster_id").and_then(Value::as_str)
        .is_some_and(|cluster| !cluster.is_empty()));
    assert_ne!(key.as_str(), accessor);
    Ok(key.clone())
}
fn logical_policy(f: &mut Fixture, controlled: bool) {
    let group = if controlled {
        r#"control_group = { ttl = "60s" factor "review" {
       controlled_capabilities = ["update"]
       identity { group_names = ["cg-team"] approvals = 2 self_authorization = false }
    } }"#
    } else {
        ""
    };
    let policy = format!(
        r#"path "sys/workflows/execute/wf131" {{ capabilities = ["update"] {group} }}
      path "secret/data/cg/key" {{ capabilities = ["create","read","update"] }}
      path "sys/control-group/request" {{ capabilities = ["update"] }}
      path "sys/control-group/authorize" {{ capabilities = ["update"] }}"#
    );
    policy_write(&mut f.service, &f.admin, "cg-requester", &policy);
}

#[test]
fn workflow131_ten_public_fields_convert_before_any_effect_and_reject_unknown_shapes() -> TestResult
{
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let types = [
        ("duration_second", "dur", "int"),
        ("signed_duration_second", "signed", "int"),
        ("comma_string_slice", "strings", "[]string"),
        ("lower_case_string", "lower", "string"),
        ("name_string", "name", "string"),
        ("kv_pairs", "pairs", "map"),
        ("comma_int_slice", "ints", "any"),
        ("header", "headers", "map"),
        ("float", "float", "float64"),
        ("time", "time", "string"),
    ];
    let mut document = String::from("input {");
    for (ty, name, _) in types {
        document.push_str(&format!("field \"{ty}\" \"{name}\" {{ required = true }}"));
    }
    document.push_str(r#"} flow "store" { request "kv" { operation = "update"
        path = "secret/data/cg/key" data = { data = { value = "fields131" } } } } output { data = {"#);
    for (_, name, kind) in types {
        document.push_str(&format!(
            "{name} = {{ eval_source = \"input\" eval_type = \"{kind}\" field_name = \"{name}\" }}"
        ));
    }
    document.push_str("} }");
    install_logical(&mut f, &document);
    let input = json!({"dur":"1m","signed":"-10s","strings":"first, second",
        "lower":"ABC","name":"safe-name","pairs":{"key":"value"},"ints":"1,-2",
        "headers":{"X-Test":["one","two"]},"float":1.5,"time":"2026-10-10T12:34:56Z"});
    let token = Zeroizing::new(f.requester.token.to_string());
    let response = wire(
        &mut f,
        &token,
        "",
        "POST",
        "sys/workflows/execute/wf131",
        input.clone(),
        "",
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"],
        json!({"dur":60,"signed":-10,"strings":["first","second"],
       "lower":"abc","name":"safe-name","pairs":{"key":"value"},"ints":[1,-2],
       "headers":{"X-Test":["one","two"]},"float":1.5,"time":"2026-10-10T12:34:56Z"})
    );
    read(&mut f, 2, "fields131", 100);
    let mut version = 2;
    for (field, raw, expected) in [
        ("dur", json!("500ms"), json!(0)),
        ("dur", json!("-500ms"), json!(0)),
        ("signed", json!("-1500ms"), json!(-1)),
        ("strings", json!([1, true, null]), json!(["1", "1", ""])),
        ("lower", json!("İΣẞ"), json!("iσß")),
        ("name", json!("_a_"), json!("_a_")),
        ("pairs", json!("key=value"), json!({"key":"value"})),
        (
            "ints",
            json!("010,0x10,0b10,1,,2"),
            json!([8, 16, 2, 1, 0, 2]),
        ),
        (
            "headers",
            json!("eyJ4LXRlc3QiOiJ2In0="),
            json!({"X-Test":["v"]}),
        ),
        (
            "headers",
            json!({"x-test":"a\r\nb"}),
            json!({"X-Test":["a\r\nb"]}),
        ),
        ("float", json!("1.25"), json!(1.25)),
        ("float", json!("0x_1.8p+1"), json!(3)),
        ("float", json!("1_000.125"), json!(1000.125)),
        (
            "time",
            json!("2026-10-10T14:34:56.123456789+02:00"),
            json!("2026-10-10T12:34:56.123456789Z"),
        ),
    ] {
        let mut selected = input.clone();
        selected[field] = raw;
        let response = wire(
            &mut f,
            &token,
            "",
            "POST",
            "sys/workflows/execute/wf131",
            selected,
            "",
        )?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"][field], expected);
        version += 1;
        read(&mut f, version, "fields131", 100);
    }
    for (field, bad) in [
        ("dur", json!("-1500ms")),
        ("signed", json!("overflow")),
        ("strings", json!([{"unsupported":1}])),
        ("lower", json!({"unsupported":1})),
        ("name", json!("../unsafe/")),
        ("pairs", json!(["=value"])),
        ("ints", json!("1,NaN")),
        ("headers", json!({"X-Test":true})),
        ("float", json!("0x1")),
        ("float", json!("1__0")),
        ("time", json!("not-a-time")),
    ] {
        let mut invalid = input.clone();
        invalid[field] = bad;
        assert_eq!(
            wire(
                &mut f,
                &token,
                "",
                "POST",
                "sys/workflows/execute/wf131",
                invalid,
                ""
            )?
            .status,
            500
        );
        read(&mut f, version, "fields131", 100);
    }
    Ok(())
}

#[test]
fn workflow131_http_query_is_namespace_actor_and_parameter_acl_bound_without_header_auth()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    install_logical(&mut f, QUERY_PROFILE);
    let token = Zeroizing::new(f.requester.token.to_string());
    let ok = wire(
        &mut f,
        &token,
        "",
        "POST",
        "sys/workflows/execute/wf131?value=after",
        json!({"value":"after"}),
        "X-Client-Note: ingress\r\n",
    )?;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body["data"]["value"], "after");
    assert_eq!(
        ok.body["data"]["headers"],
        json!({"X-Review":["workflow-header"]})
    );
    read(&mut f, 2, "after", 100);
    for (target, body) in [
        ("sys/workflows/execute/wf131?value=a&value=b", json!({})),
        ("sys/workflows/execute/wf131?undeclared=bad", json!({})),
        (
            "sys/workflows/execute/wf131?value=a",
            json!({"value":{"invalid":"shape"}}),
        ),
        ("sys/workflows/execute/wf131", json!({})),
    ] {
        assert_eq!(
            wire(&mut f, &token, "", "POST", target, body, "")?.status,
            500
        );
        read(&mut f, 2, "after", 100);
    }
    assert_eq!(
        wire(
            &mut f,
            "",
            "",
            "POST",
            "sys/workflows/execute/wf131?value=blocked",
            json!({"value":"blocked"}),
            ""
        )?
        .status,
        403
    );
    assert_eq!(
        wire(
            &mut f,
            &token,
            "absent/",
            "POST",
            "sys/workflows/execute/wf131?value=blocked",
            json!({"value":"blocked"}),
            ""
        )?
        .status,
        404
    );
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"path "sys/workflows/execute/wf131" {
       capabilities = ["update"] denied_parameters = { value = ["blocked"] } }
       path "secret/data/cg/key" { capabilities = ["read","update"] }"#,
    );
    assert_eq!(
        wire(
            &mut f,
            &token,
            "",
            "POST",
            "sys/workflows/execute/wf131?value=blocked",
            json!({"value":"blocked"}),
            ""
        )?
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    // Raw denied values cannot be laundered by lower-case conversion.
    let lower_profile = QUERY_PROFILE.replace(
        r#"field "string" "value""#,
        r#"field "lower_case_string" "value""#,
    );
    install_logical(&mut f, &lower_profile);
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"path "sys/workflows/execute/wf131" {
       capabilities = ["update"] denied_parameters = { value = ["BLOCKED"] } }
       path "secret/data/cg/key" { capabilities = ["read","update"] }"#,
    );
    assert_eq!(
        wire(
            &mut f,
            &token,
            "",
            "POST",
            "sys/workflows/execute/wf131?value=BLOCKED",
            json!({"value":"BLOCKED"}),
            ""
        )?
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    // A token-shaped logical header is data, never a replacement Principal.
    let profile = QUERY_PROFILE.replace(
        r#"path = "secret/data/cg/key""#,
        r#"path = "sys/mounts" operation = "read""#,
    );
    // Keep a single operation declaration while retaining the real unauthorised route.
    let profile = profile.replace(
        r#"operation = "update" path = "sys/mounts" operation = "read""#,
        r#"operation = "read" path = "sys/mounts""#,
    );
    let profile = Zeroizing::new(profile.replace(
        r#"X-Review = ["workflow-header"]"#,
        &format!("X-Vault-Token = [\"{}\"]", f.admin.as_str()),
    ));
    install_logical(&mut f, &profile);
    assert_eq!(
        wire(
            &mut f,
            &token,
            "",
            "POST",
            "sys/workflows/execute/wf131?value=after",
            json!({"value":"after"}),
            ""
        )?
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    Ok(())
}

#[test]
fn workflow131_query_and_headers_are_sealed_deferred_reopened_and_dispatched_once() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, true);
    install_logical(&mut f, QUERY_PROFILE);
    let token = Zeroizing::new(f.requester.token.to_string());
    let pending = wire(
        &mut f,
        &token,
        "",
        "POST",
        "sys/workflows/execute/wf131?value=after",
        json!({"value":"after"}),
        "X-Client-Note: sealed\r\n",
    )?;
    assert_eq!(pending.status, 200);
    let wrapper = Zeroizing::new(text(&pending.body, "/wrap_info/token")?);
    let accessor = text(&pending.body, "/wrap_info/accessor")?;
    read(&mut f, 1, "before", 100);
    let current = f.service.state.as_ref().ok_or("state")?.clone();
    let owner = current
        .auth
        .control_group_owners()
        .find(|owner| owner.request_accessor == accessor)
        .ok_or("owner")?;
    assert_eq!(owner.transport_body, json!({"value":"after"}));
    assert_eq!(owner.body, json!({"value":"after"}));
    let frame = owner.logical_data.as_ref().ok_or("owned input")?;
    assert_eq!(frame.query.get("value"), Some(&vec![String::from("after")]));
    assert_eq!(
        frame.headers.get("x-client-note"),
        Some(&vec![String::from("sealed")])
    );
    assert_eq!(
        frame.profile.as_ref().ok_or("profile owner")?.namespace_id,
        "root"
    );
    assert_eq!(
        frame.profile.as_ref().ok_or("profile owner")?.incarnation,
        0
    );
    // Changing either public data field cannot reuse the sealed issuer capsule.
    for field in ["headers", "query"] {
        let mut encoded = serde_json::to_value(&current.auth)?;
        let record_key = logical_cg_record_key(&encoded, &accessor)?;
        encoded["control_groups"]["requests"][&record_key]["logical_data"][field] =
            if field == "headers" {
                json!({"x-client-note":["changed"]})
            } else {
                json!({"value":["changed"]})
            };
        let tainted: AuthState = serde_json::from_value(encoded)?;
        assert!(tainted.validate_control_group_state().is_err());
    }
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
    f = restart(f, 100)?;
    approve_two(&mut f, &accessor);
    // A new raw-parameter denial must precede one-use wrapper admission.
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"path "sys/workflows/execute/wf131" {
      capabilities = ["update"] denied_parameters = { value = ["after"] }
      control_group = { ttl = "60s" factor "review" { controlled_capabilities = ["update"]
        identity { group_names = ["cg-team"] approvals = 2 self_authorization = false } } } }
      path "secret/data/cg/key" { capabilities = ["create","read","update"] }"#,
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
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("deferred state")?
            .auth
            .control_group_owners()
            .any(|owner| owner.request_accessor == accessor)
    );
    read(&mut f, 1, "before", 100);
    logical_policy(&mut f, true);
    let executed = call(
        &mut f.service,
        &wrapper,
        "POST",
        "sys/wrapping/unwrap",
        json!({}),
        100,
    );
    // Reveal only a fixed static error category; never log the response body.
    let error_category = executed.body.get("errors")
        .and_then(Value::as_array).and_then(|errors| errors.first())
        .and_then(Value::as_str).map(|error| {
            if error.contains("control group policy has changed") { "control group policy" }
            else if error.contains("control group factors have changed") { "control group factors" }
            else if error.contains("control group operation ownership has changed") { "operation ownership" }
            else if error.contains("control group sudo ownership has changed") { "sudo ownership" }
            else if error.contains("workflow input definition ownership changed") { "workflow definition" }
            else if error.contains("request authority clock is already bound") { "clock already bound" }
            else if error.contains("control group authorization is not complete") { "approval incomplete" }
            else if error.contains("control group request is unavailable") { "request unavailable" }
            else if error.contains("namespace") { "namespace error" }
            else if error.contains("permission denied") { "permission denied" }
            else { "unclassified static error" }
        });
    assert_eq!(executed.status, 200, "fixed error category: {error_category:?}");
    assert_eq!(executed.body["data"]["value"], "after");
    assert_eq!(
        executed.body["data"]["headers"],
        json!({"X-Review":["workflow-header"]})
    );
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
    let next = wire(
        &mut f,
        &token,
        "",
        "POST",
        "sys/workflows/execute/wf131?value=stale",
        json!({"value":"stale"}),
        "",
    )?;
    assert_eq!(next.status, 200);
    let old = Zeroizing::new(text(&next.body, "/wrap_info/token")?);
    let old_accessor = text(&next.body, "/wrap_info/accessor")?;
    approve_two(&mut f, &old_accessor);
    install_logical(
        &mut f,
        &(String::from(QUERY_PROFILE) + "\n# replacement definition"),
    );
    assert_eq!(
        call(
            &mut f.service,
            &old,
            "POST",
            "sys/wrapping/unwrap",
            json!({}),
            100
        )
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    Ok(())
}

#[test]
fn workflow131_active_and_retired_definition_and_owner_floor_survive_commit_and_reopen()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let previous = f.service.state.as_ref().ok_or("state")?.clone();
    assert!(!previous.namespaces.workflows.has_logical_input_profiles());
    assert!(!previous.auth.has_control_group_logical_data());
    assert!(previous.auth.has_userpass_issuance_state());
    assert_eq!(previous.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert_eq!(previous.writer_schema(), USERPASS_ISSUANCE_STATE_SCHEMA);
    install_logical(&mut f, QUERY_PROFILE);
    let active = f.service.state.as_ref().ok_or("state")?.clone();
    assert_logical_userpass_floor(&active)?;
    assert_eq!(active.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert_eq!(active.writer_schema(), USERPASS_ISSUANCE_STATE_SCHEMA);
    active.validate_format().map_err(|_| "active format")?;
    active
        .validate_publication_schema(Some(&previous))
        .map_err(|_| "active publication")?;
    for schema in [
        WORKFLOW_INPUT_STATE_SCHEMA,
        WORKFLOW_CREDENTIAL_STATE_SCHEMA,
        WORKFLOW_EXPRESSION_STATE_SCHEMA,
    ] {
        let mut downgrade = active.clone();
        downgrade.schema = schema;
        assert!(downgrade.validate_format().is_err());
        assert!(
            downgrade
                .validate_publication_schema(Some(&active))
                .is_err()
        );
        assert!(Service::validate_snapshot_protected_floor(&active, &downgrade).is_err());
    }
    f = restart(f, 100)?;
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        USERPASS_ISSUANCE_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "DELETE",
            "sys/workflows/manage/wf131",
            json!({}),
            100
        )
        .status,
        204
    );
    let retired = f.service.state.as_ref().ok_or("state")?.clone();
    assert!(retired.auth.has_userpass_issuance_state());
    assert!(!retired.namespaces.workflows.has_logical_input_profiles());
    assert_eq!(retired.schema, USERPASS_ISSUANCE_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), USERPASS_ISSUANCE_STATE_SCHEMA);
    let mut downgrade = retired.clone();
    downgrade.schema = WORKFLOW_CREDENTIAL_STATE_SCHEMA;
    assert!(
        downgrade
            .validate_publication_schema(Some(&retired))
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&retired, &downgrade).is_err());
    f = restart(f, 100)?;
    assert_eq!(
        f.service.state.as_ref().ok_or("state")?.schema,
        USERPASS_ISSUANCE_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "GET",
            "sys/workflows/manage/wf131",
            json!({}),
            100
        )
        .status,
        404
    );
    // Independently create the real earlier reader shape without a native
    // Userpass issuance. This isolates 131 from the coexisting 132 floor above.
    let isolated_root = Root::new();
    let mut isolated = isolated_root.service()?;
    let (isolated_key, isolated_admin) = bootstrap(&mut isolated)?;
    let isolated_key = Zeroizing::new(isolated_key);
    let isolated_admin = Zeroizing::new(isolated_admin);
    let before = isolated.state.as_ref().ok_or("isolated initial state")?.clone();
    assert!(!before.auth.has_userpass_issuance_state());
    assert!(!before.namespaces.workflows.has_logical_input_profiles());
    assert!(!before.auth.has_control_group_logical_data());
    assert!(before.schema < WORKFLOW_INPUT_STATE_SCHEMA);
    assert_eq!(call(&mut isolated, &isolated_admin, "POST", "sys/workflows/manage/wf131",
        json!({"workflow":QUERY_PROFILE}), 100).status, 200);
    let active = isolated.state.as_ref().ok_or("isolated active")?.clone();
    assert!(active.namespaces.workflows.has_logical_input_profiles());
    assert!(!active.auth.has_userpass_issuance_state());
    assert_eq!(active.schema, WORKFLOW_INPUT_STATE_SCHEMA);
    assert_eq!(active.writer_schema(), WORKFLOW_INPUT_STATE_SCHEMA);
    active.validate_format().map_err(|_| "isolated active format")?;
    active.validate_publication_schema(Some(&before)).map_err(|_| "isolated publication")?;
    for schema in [WORKFLOW_CREDENTIAL_STATE_SCHEMA, WORKFLOW_EXPRESSION_STATE_SCHEMA] {
        let mut downgrade = active.clone();
        downgrade.schema = schema;
        assert!(downgrade.validate_format().is_err());
        assert!(downgrade.validate_publication_schema(Some(&active)).is_err());
        assert!(Service::validate_snapshot_protected_floor(&active, &downgrade).is_err());
    }
    drop(isolated);
    let mut isolated = isolated_root.service()?;
    assert_eq!(call(&mut isolated, "", "POST", "sys/unseal",
        json!({"key":isolated_key.as_str()}), 100).status, 200);
    let reopened = isolated.state.as_ref().ok_or("isolated reopen")?;
    assert_eq!(reopened.schema, WORKFLOW_INPUT_STATE_SCHEMA);
    assert!(reopened.namespaces.workflows.has_logical_input_profiles());
    assert!(!reopened.auth.has_userpass_issuance_state());
    assert_eq!(call(&mut isolated, &isolated_admin, "DELETE", "sys/workflows/manage/wf131",
        json!({}), 100).status, 204);
    let retired = isolated.state.as_ref().ok_or("isolated retired")?.clone();
    assert!(!retired.namespaces.workflows.has_logical_input_profiles());
    assert!(!retired.auth.has_control_group_logical_data());
    assert!(!retired.auth.has_userpass_issuance_state());
    assert_eq!(retired.schema, WORKFLOW_INPUT_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), WORKFLOW_INPUT_STATE_SCHEMA);
    retired.validate_format().map_err(|_| "isolated retired format")?;
    let mut downgrade = retired.clone();
    downgrade.schema = WORKFLOW_CREDENTIAL_STATE_SCHEMA;
    assert!(downgrade.validate_publication_schema(Some(&retired)).is_err());
    assert!(Service::validate_snapshot_protected_floor(&retired, &downgrade).is_err());
    drop(isolated);
    let mut isolated = isolated_root.service()?;
    assert_eq!(call(&mut isolated, "", "POST", "sys/unseal",
        json!({"key":isolated_key.as_str()}), 100).status, 200);
    assert_eq!(isolated.state.as_ref().ok_or("isolated retired reopen")?.schema,
        WORKFLOW_INPUT_STATE_SCHEMA);
    assert_eq!(call(&mut isolated, &isolated_admin, "GET", "sys/workflows/manage/wf131",
        json!({}), 100).status, 404);
    Ok(())
}

#[test]
fn workflow131_unmounted_hash_query_reaches_authenticated_actual_missing_route() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let admin = Zeroizing::new(f.admin.to_string());
    let requester = Zeroizing::new(f.requester.token.to_string());
    for path in [
        "unknown/byok-export/source/destination",
        "unknown/byok-export/source/destination?hash=SHA256",
    ] {
        assert_eq!(
            wire(&mut f, &admin, "", "GET", path, json!({}), "")?.status,
            404
        );
        assert_eq!(
            wire(&mut f, "", "", "GET", path, json!({}), "")?.status,
            403
        );
        assert_eq!(
            wire(&mut f, &requester, "", "GET", path, json!({}), "")?.status,
            403
        );
        read(&mut f, 1, "before", 100);
    }
    assert_eq!(
        wire(
            &mut f,
            &admin,
            "absent/",
            "GET",
            "unknown/byok-export/source/destination?hash=SHA256",
            json!({}),
            ""
        )?
        .status,
        404
    );
    read(&mut f, 1, "before", 100);
    Ok(())
}

#[test]
fn workflow131_data_scope_and_authenticated_forward_wire_preserve_headers_without_authority()
-> TestResult {
    use crate::request_metadata::{DataFrame, Scope};
    let body = json!({"input":"synthetic"});
    let method = "POST";
    let path = "sys/workflows/execute/wf131";
    assert!(crate::request_metadata::current(method, path, "", &body)?.is_none());
    let mut frame = DataFrame::default();
    frame
        .headers
        .insert("X-Logical".into(), vec!["one".into(), "two".into()]);
    let _scope = Scope::enter(Some(frame.clone()), method, path, "", &body)?;
    assert!(crate::request_metadata::current("GET", path, "", &body).is_err());
    assert!(crate::request_metadata::current(method, "sys/mounts", "", &body).is_err());
    assert!(crate::request_metadata::current(method, path, "other/", &body).is_err());
    assert!(
        crate::request_metadata::current(method, path, "", &json!({"input":"changed"})).is_err()
    );
    let context = crate::ha_forward::ForwardContext {
        method,
        path,
        namespace: "",
        token: "synthetic-only",
        body: &body,
        wrap_ttl_seconds: None,
        origin_peer: Some("127.0.0.1".parse()?),
        client_certificates: None,
        caller_deadline: None,
    };
    assert!(
        crate::ha_forward::encode_completed_index_request_for_cluster(
            "logical131",
            (1, 2),
            &context,
            None,
        ).is_err()
    );
    let encoded = Zeroizing::new(
        crate::ha_forward::encode_completed_index_request_for_cluster(
            "logical131",
            (1, 2),
            &context,
            Some([0x31; 32]),
        )?,
    );
    assert!(crate::ha_forward::decode_request_for_cluster(&encoded, "other-cluster").is_err());
    let mut decoded = crate::ha_forward::decode_request_for_cluster(&encoded, "logical131")?;
    assert_eq!((decoded.source, decoded.target), (1, 2));
    assert_eq!(decoded.completion_nonce, Some([0x31; 32]));
    assert_eq!(
        decoded
            .logical_data
            .as_ref()
            .ok_or("logical frame")?
            .headers,
        frame.headers
    );
    {
        let _received = Scope::enter(
            decoded.logical_data.take(),
            &decoded.method,
            &decoded.path,
            &decoded.namespace,
            &decoded.body,
        )?;
        assert_eq!(
            crate::request_metadata::current(method, path, "", &body)?
                .ok_or("received data")?
                .headers,
            frame.headers
        );
    }
    let mut oversized = frame.clone();
    oversized
        .headers
        .insert("X-Oversized".into(), vec!["x".repeat(16 * 1024 + 1)]);
    assert!(Scope::enter(Some(oversized), method, path, "", &body).is_err());
    let unknown = json!({"headers":{"X-Logical":["one"]},"principal":{"root":true}});
    assert!(serde_json::from_value::<DataFrame>(unknown).is_err());
    {
        let _nested = Scope::enter(None, "GET", "sys/mounts", "", &json!({}))?;
        assert!(crate::request_metadata::current("GET", "sys/mounts", "", &json!({}))?.is_none());
    }
    assert_eq!(
        crate::request_metadata::current(method, path, "", &body)?
            .ok_or("restored data")?
            .headers,
        frame.headers
    );
    Ok(())
}

#[test]
fn workflow131_static_http_headers_enter_each_inner_scope_without_inheriting_outer_data_or_acl()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    install_logical(
        &mut f,
        r#"flow "store" {
      request "write" { operation = "update" path = "secret/data/cg/key"
        data = { data = { value = "after" } }
      }
      request "read" { operation = "read" path = "secret/data/cg/key" }
    }
    output { data = { value = {
      eval_source = "response" eval_type = "string"
      flow_name = "store" response_name = "read"
      field_selector = ["data", "data", "value"]
    } } }"#,
    );
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .namespaces
            .workflows
            .has_logical_input_profiles()
    );
    let requester = Zeroizing::new(f.requester.token.to_string());
    let outer_headers = "User-Agent: synthetic-workflow-client\r\nX-Client-Note: outer-only\r\n";
    let response = wire(
        &mut f,
        &requester,
        "",
        "POST",
        "sys/workflows/execute/wf131",
        json!({}),
        outer_headers,
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["value"], json!("after"));
    read(&mut f, 2, "after", 100);
    assert!(
        crate::request_metadata::current("POST", "sys/workflows/execute/wf131", "", &json!({}))?
            .is_none()
    );

    // Header data cannot admit a missing bearer or bypass the inner API ACL.
    assert_eq!(
        wire(
            &mut f,
            "",
            "",
            "POST",
            "sys/workflows/execute/wf131",
            json!({}),
            outer_headers
        )?
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        r#"path "sys/workflows/execute/wf131" { capabilities = ["update"] }
           path "secret/data/cg/key" { capabilities = ["read"] }"#,
    );
    assert_eq!(
        wire(
            &mut f,
            &requester,
            "",
            "POST",
            "sys/workflows/execute/wf131",
            json!({}),
            outer_headers
        )?
        .status,
        403
    );
    read(&mut f, 2, "after", 100);
    assert!(
        crate::request_metadata::current("POST", "sys/workflows/execute/wf131", "", &json!({}))?
            .is_none()
    );
    Ok(())
}

#[test]
fn workflow131_public_sdk_query_coercions_and_string_slice_reach_the_original_program_before_effects()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let document = r#"input {
        field "duration_second" "dur" { required = true query = true }
        field "signed_duration_second" "signed" { required = true query = true }
        field "comma_string_slice" "list" { required = true query = true }
        field "string_slice" "plain" { required = true }
        field "lower_case_string" "lower" { required = true query = true }
        field "name_string" "name" { required = true query = true }
        field "kv_pairs" "pairs" { required = true query = true }
        field "comma_int_slice" "ints" { required = true query = true }
        field "header" "headers" { required = true query = true }
        field "float" "float" { required = true query = true }
        field "time" "time" { required = true query = true }
        field "int" "count" { required = true query = true }
        field "bool" "flag" { required = true query = true }
    } flow "store" { request "kv" {
        operation = "update" path = "secret/data/cg/key"
        data = { data = { value = "sdk131-query" } }
    } } output { data = {
        dur = { eval_source = "input" eval_type = "int" field_name = "dur" }
        signed = { eval_source = "input" eval_type = "int" field_name = "signed" }
        list = { eval_source = "input" eval_type = "[]string" field_name = "list" }
        plain = { eval_source = "input" eval_type = "[]string" field_name = "plain" }
        lower = { eval_source = "input" eval_type = "string" field_name = "lower" }
        name = { eval_source = "input" eval_type = "string" field_name = "name" }
        pairs = { eval_source = "input" eval_type = "map" field_name = "pairs" }
        ints = { eval_source = "input" eval_type = "any" field_name = "ints" }
        headers = { eval_source = "input" eval_type = "map" field_name = "headers" }
        float = { eval_source = "input" eval_type = "float64" field_name = "float" }
        time = { eval_source = "input" eval_type = "string" field_name = "time" }
        count = { eval_source = "input" eval_type = "int" field_name = "count" }
        flag = { eval_source = "input" eval_type = "bool" field_name = "flag" }
    } }"#;
    install_logical(&mut f, document);
    let target = "sys/workflows/execute/wf131?dur=500ms&signed=-1500ms&list=first%2C%20second%2C%2Cfirst&lower=%C4%B0%CE%A3%E1%BA%9E&name=_a_&pairs=key%3Dvalue&ints=010%2C0x10%2C0b10&headers=eyJ4LXRlc3QiOiJ2In0%3D&float=1.25&time=0&count=0x10&flag=TRUE";
    let token = Zeroizing::new(f.requester.token.to_string());
    let body = json!({"plain":[1,true,null,2.5],"dur":"500ms","signed":"-1500ms",
        "list":"first, second,,first","lower":"İΣẞ","name":"_a_","pairs":"key=value",
        "ints":"010,0x10,0b10","headers":"eyJ4LXRlc3QiOiJ2In0=",
        "float":"1.25","time":"0","count":16,"flag":true});
    let response = wire(&mut f, &token, "", "POST", target, body.clone(), "")?;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"],
        json!({
            "dur":0,"signed":-1,"list":["first","second","","first"],
            "plain":["1","1","","2.5"],"lower":"iσß","name":"_a_",
            "pairs":{"key":"value"},"ints":[8,16,2],"headers":{"X-Test":["v"]},
            "float":1.25,"time":"1970-01-01T00:00:00Z","count":16,"flag":true
        })
    );
    read(&mut f, 2, "sdk131-query", 100);
    for (field, invalid) in [
        ("dur", json!("-1500ms")),
        ("ints", json!("1, 2")),
        ("pairs", json!("=value")),
        ("time", json!("not-a-time")),
        ("flag", json!("not-a-bool")),
        ("count", json!("0xinvalid")),
    ] {
        let mut invalid_body = body.clone();
        invalid_body[field] = invalid;
        assert_eq!(wire(&mut f, &token, "", "POST", target,
            invalid_body, "")?.status, 500);
        read(&mut f, 2, "sdk131-query", 100);
    }
    assert_eq!(
        wire(
            &mut f,
            &token,
            "",
            "POST",
            target,
            { let mut invalid = body.clone(); invalid["plain"] = json!([{"x":1}]); invalid },
            ""
        )?
        .status,
        500
    );
    read(&mut f, 2, "sdk131-query", 100);
    assert_eq!(
        wire(&mut f, "", "", "POST", target, body.clone(), "")?.status,
        403
    );
    read(&mut f, 2, "sdk131-query", 100);
    assert_eq!(
        wire(&mut f, &token, "absent/", "POST", target, body.clone(), "")?.status,
        404
    );
    read(&mut f, 2, "sdk131-query", 100);

    // TypeHeader is logical JSON data: even CRLF does not become an HTTP line
    // or a new authenticated principal when merely returned by the program.
    let logical_headers = target.replace("headers=eyJ4LXRlc3QiOiJ2In0%3D",
        "headers=%7B%22x-test%22%3A%22a%5Cr%5Cnb%22%2C%22x-vault-token%22%3A%22synthetic-data%22%7D");
    let mut logical_body = body.clone();
    logical_body["headers"] = json!({"x-test":"a\r\nb","x-vault-token":"synthetic-data"});
    let response = wire(
        &mut f,
        &token,
        "",
        "POST",
        &logical_headers,
        logical_body,
        "",
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"]["headers"],
        json!({"X-Test":["a\r\nb"],"X-Vault-Token":["synthetic-data"]})
    );
    read(&mut f, 3, "sdk131-query", 100);
    assert_eq!(
        wire(&mut f, "", "", "POST", &logical_headers, body, "")?.status,
        403
    );
    read(&mut f, 3, "sdk131-query", 100);
    Ok(())
}

// No provider process is substituted: this fixture installs the real private
// runtime configuration, but its queue records only prepared Job fields.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn logical_sdk_reopen(mut f: Fixture) -> TestResult<Fixture> {
    drop(f.service);
    let plugin = f.root.path.join("header-plugins");
    let runtime = f.root.path.join("header-runtime");
    private_directory(&plugin)?;
    private_directory(&runtime)?;
    let mut service = f.root.service()?;
    service.install_sdk_backend(Some(sdk_backend::SdkBackendConfig {
        plugin_directory: plugin,
        companion: f.root.path.join("header-companion-not-started"),
        companion_sha256: "a".repeat(64),
        runtime_directory: runtime,
        timeout_ms: 5_000,
    }))?;
    let original_started = Instant::now();
    let clock = RequestClock::anchored(Duration::new(100, 125_000_000), original_started)?;
    let execution = service.begin_at_mode_precise(RequestDispatch {
        method: "POST", path: "sys/unseal", namespace: "", token: "",
        body: json!({"key":f.key.as_str()}), now: 100,
        allow_forward: true, enforce_namespace: true, wrap_ttl_seconds: None,
        origin_peer: None, client_certificates: None,
    }, clock);
    assert_eq!(service.finish_synchronous_request(execution).status, 200);
    f.service = service;
    Ok(f)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn workflow131_logical_header_resolver_cg_reopen_and_actual_sdk_job_keep_data_without_authority()
    -> TestResult
{
    let mut f = setup()?;
    f = logical_sdk_reopen(f)?;
    let mut candidate = f.service.state.clone().ok_or("actual state")?;
    let descriptor = candidate.engines.register_sdk_descriptor(crate::engines::sdk::Descriptor {
        name: "header_probe".into(), version: "v1.0.0".into(), command: "probe".into(),
        args: vec![], sha256: "a".repeat(64), generation: 1,
    })?;
    let created = candidate.engines.handle("", "POST", "sys/mounts/header-sdk",
        &json!({"type":"plugin","config":{"plugin_id":"header_probe"}}), 100)?
        .ok_or("actual SDK mount route")?;
    assert_eq!(created.status, 204);
    let sdk_owner = candidate.engines.bind_sdk_mount("", "header-sdk/", &descriptor)?;
    f.service.prepare_sdk_mount_record_root(&mut candidate)
        .map_err(|_| "actual SDK mount record-root preparation")?;
    candidate.schema = candidate.writer_schema();
    f.service.commit_state(&mut candidate).map_err(|_| "actual SDK mount publication")?;
    f.service.state = Some(candidate);
    policy_write(&mut f.service, &f.admin, "cg-requester", r#"
      path "sys/workflows/execute/wf131" { capabilities = ["update"] }
      path "header-sdk/store" { capabilities = ["update"]
        control_group = { ttl = "60s" factor "review" {
          controlled_capabilities = ["update"]
          identity { group_names = ["cg-team"] approvals = 2 self_authorization = false }
        } }
      }
      path "sys/control-group/request" { capabilities = ["update"] }
      path "sys/control-group/authorize" { capabilities = ["update"] }
    "#);
    let document = r#"input {
      field "header" "logical" { required = true }
      field "string" "value" { required = true }
    }
    flow "store" { request "sdk" {
      operation = "update" path = "header-sdk/store"
      headers = { eval_source = "input" eval_type = "map" field_name = "logical" }
      data = { value = { eval_source = "input" eval_type = "string" field_name = "value" } }
    } }
    output { data = { value = { eval_source = "input" eval_type = "string" field_name = "value" } } }"#;
    install_logical(&mut f, document);
    let started = Instant::now();
    let input = json!({"logical":{"":["empty-map-name"],"Bad Header":["line\r\nlogical\u{0}value"],
        "X-Vault-Token":["data-only"]},"value":"owned-header"});
    // This is the production resolver of the actually stored profile, not a
    // fabricated DataFrame. Profile SDK execution remains independently closed.
    let (method, path, body, frame) = f.service.state.as_ref().ok_or("stored state")?
        .namespaces.workflows.logical_first_step_fixture("", "wf131", &input, started)
        .map_err(|_| "actual stored Program resolution")?;
    assert_eq!(method, "POST");
    assert_eq!(path, "header-sdk/store");
    assert_eq!(body, json!({"value":"owned-header"}));
    let headers = frame.as_ref().ok_or("resolved logical headers")?.headers.clone();
    assert_eq!(headers.get(""), Some(&vec!["empty-map-name".to_owned()]));
    assert_eq!(headers.get("Bad Header"), Some(&vec!["line\r\nlogical\u{0}value".to_owned()]));
    assert_eq!(headers.get("X-Vault-Token"), Some(&vec!["data-only".to_owned()]));
    let (control, before_queue) = sdk_backend::model_revoke_queue();
    let host_key = f.service.sdk_host_key("", "header-sdk/", &sdk_owner);
    f.service.sdk_hosts.insert(host_key, control);
    // Data-only X-Vault-Token does not supply a client Principal.
    {
        let _data = crate::request_metadata::Scope::enter(frame.clone(), &method, &path, "", &body)?;
        assert_eq!(call(&mut f.service, "", &method, &path, body.clone(), 100).status, 403);
    }
    assert_eq!(before_queue.unexpected_invokes(), 0);
    assert!(!f.service.state.as_ref().ok_or("unauthenticated state")?.auth
        .control_group_owners().any(|owner| owner.path == path));
    let mut invalid_pair_input = input.clone();
    invalid_pair_input["logical"] = json!([":v"]);
    assert!(f.service.state.as_ref().ok_or("pair input state")?
        .namespaces.workflows.logical_first_step_fixture("", "wf131", &invalid_pair_input, started)
        .is_err());
    assert_eq!(before_queue.unexpected_invokes(), 0);
    let mut oversized_input = input.clone();
    oversized_input["logical"]["Bad Header"] = json!(["x".repeat(16 * 1024 + 1)]);
    assert!(f.service.state.as_ref().ok_or("bounded input state")?
        .namespaces.workflows.logical_first_step_fixture("", "wf131", &oversized_input, started)
        .is_err());
    assert_eq!(before_queue.unexpected_invokes(), 0);
    let pending_response = {
        let _data = crate::request_metadata::Scope::enter(frame, &method, &path, "", &body)?;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(60));
        let clock = RequestClock::anchored(Duration::new(100, 125_000_000), started)?;
        let execution = f.service.begin_at_mode_precise(RequestDispatch {
            method: &method, path: &path, namespace: "", token: &f.requester.token,
            body: body.clone(), now: 100, allow_forward: true, enforce_namespace: true,
            wrap_ttl_seconds: None, origin_peer: None, client_certificates: None,
        }, clock);
        match execution {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => return Err("CG dispatched SDK before approval".into()),
        }
    };
    assert_eq!(pending_response.status, 200);
    assert_eq!(before_queue.unexpected_invokes(), 0);
    let wrapper = Zeroizing::new(text(&pending_response.body, "/wrap_info/token")?);
    let accessor = text(&pending_response.body, "/wrap_info/accessor")?;
    let current = f.service.state.as_ref().ok_or("deferred state")?;
    assert_logical_userpass_floor(current)?;
    let owner = current.auth.control_group_owners()
        .find(|owner| owner.request_accessor == accessor).ok_or("actual deferred SDK owner")?;
    assert_eq!(owner.body, body);
    assert_eq!(owner.actor_entity_id, f.requester.entity);
    assert_eq!(owner.namespace_id, "root");
    assert_eq!(owner.namespace_incarnation, 0);
    assert_eq!(owner.logical_data.as_ref().ok_or("durable headers")?.headers, headers);
    assert_raw_absent(&f, &f.requester.token)?;
    let mut tampered = serde_json::to_value(&current.auth)?;
    let record_key = logical_cg_record_key(&tampered, &accessor)?;
    tampered["control_groups"]["requests"][&record_key]["logical_data"]["headers"]["Bad Header"] =
        json!(["changed"]);
    let changed: AuthState = serde_json::from_value(tampered)?;
    assert!(changed.validate_control_group_state().is_err());
    let mut empty_name_tampered = serde_json::to_value(&current.auth)?;
    let empty_record_key = logical_cg_record_key(&empty_name_tampered, &accessor)?;
    empty_name_tampered["control_groups"]["requests"][&empty_record_key]["logical_data"]["headers"][""] =
        json!(["changed-empty-key"]);
    let changed_empty: AuthState = serde_json::from_value(empty_name_tampered)?;
    assert!(changed_empty.validate_control_group_state().is_err());

    assert_eq!(call(&mut f.service, &wrapper, "POST", "sys/wrapping/unwrap", json!({}), 100).status, 400);
    assert_eq!(before_queue.unexpected_invokes(), 0);
    f = logical_sdk_reopen(f)?;
    let restored = f.service.state.as_ref().ok_or("encrypted reopen")?.auth
        .control_group_owners().find(|owner| owner.request_accessor == accessor)
        .ok_or("reopened original CG owner")?;
    assert_eq!(restored.logical_data.as_ref().ok_or("reopened headers")?.headers, headers);
    approve_two(&mut f, &accessor);
    let (control, after_queue) = sdk_backend::model_revoke_queue();
    f.service.sdk_hosts.insert(f.service.sdk_host_key("", "header-sdk/", &sdk_owner), control);
    let started = Instant::now();
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(60));
    let clock = RequestClock::anchored(Duration::new(100, 125_000_000), started)?;
    let execution = f.service.begin_at_mode_precise(RequestDispatch {
        method: "POST", path: "sys/wrapping/unwrap", namespace: "", token: &wrapper,
        body: json!({}), now: 100, allow_forward: true, enforce_namespace: true,
        wrap_ttl_seconds: None, origin_peer: None, client_certificates: None,
    }, clock);
    let RequestExecution::External(pending) = execution else {
        return Err("approved SDK request did not prepare its real affine Plan".into());
    };
    let ExternalEffectPlan::SdkBackend(plan) = &pending.effect else {
        return Err("approved request changed provider family".into());
    };
    let job = plan.logical_worker_job_fixture().map_err(|_| "actual production Job constructor")?;
    assert_eq!(job["operation"], "update");
    assert_eq!(job["path"], "store");
    assert_eq!(job["data"], body);
    assert_eq!(job["headers"], serde_json::to_value(&headers)?);
    assert_eq!(job["lease_present"], false);
    assert_eq!(job["auth_present"], false);
    assert_eq!(job["expected_auth_paths_present"], false);
    assert_eq!(job["original_deadline_preserved"], true);
    assert!(job.get("token").is_none());
    assert!(job.get("namespace").is_none());
    assert!(job.get("principal").is_none());
    assert_eq!(after_queue.unexpected_invokes(), 0);
    assert!(!f.service.state.as_ref().ok_or("claimed state")?.auth
        .control_group_owners().any(|owner| owner.request_accessor == accessor));
    // No typed model is called a started AutoMTLS provider or external workflow.
    drop(pending);
    Ok(())
}


#[test]
fn workflow131_actual_field_spelling_rejects_documented_alias_without_effect_and_keeps_json_acl() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let requester = Zeroizing::new(f.requester.token.to_string());
    let document = r#"input {
      field "comma_slice_string" "values" { required = true }
    }
    flow "store" {
      request "write" { operation = "update" path = "secret/data/cg/key"
        data = { data = {
          value = "observed131"
          values = { eval_source = "input" eval_type = "[]string" field_name = "values" }
        } }
      }
      request "read" { operation = "read" path = "secret/data/cg/key" }
    }
    output { data = {
      values = { eval_source = "response" eval_type = "[]string"
        flow_name = "store" response_name = "read"
        field_selector = ["data", "data", "values"]
      }
    } }"#;
    // Compiled OpenBao2.7 rejects its documented spelling before installing a profile.
    let rejected = call(&mut f.service, &f.admin, "POST", "sys/workflows/manage/wf131",
        json!({"workflow": document}), 100);
    assert_eq!(rejected.status, 400);
    assert_eq!(call(&mut f.service, &f.admin, "GET", "sys/workflows/manage/wf131",
        json!({}), 100).status, 404);
    read(&mut f, 1, "before", 100);
    install_logical(&mut f, &document.replace("comma_slice_string", "comma_string_slice"));
    let mut version = 1;
    for (input, expected) in [
        (json!({"values": " first, second "}), json!(["first", "second"])),
        (json!({"values": [1, true, null]}), json!(["1", "1", ""])),
    ] {
        let response = wire(&mut f, &requester, "", "POST",
            "sys/workflows/execute/wf131", input, "User-Agent: observed-fixture\r\n")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["values"], expected);
        version += 1;
        let stored = call(&mut f.service, &f.admin, "GET", "secret/data/cg/key", json!({}), 100);
        assert_eq!(stored.status, 200);
        assert_eq!(stored.body["data"]["metadata"]["version"], version);
        assert_eq!(stored.body["data"]["data"]["values"], expected);
    }
    for bad in [json!({}), json!({"values": [{"unsupported": 1}]})] {
        assert_eq!(wire(&mut f, &requester, "", "POST",
            "sys/workflows/execute/wf131", bad, "")?.status, 500);
        read(&mut f, version, "observed131", 100);
    }
    f = restart(f, 100)?;
    assert_logical_userpass_floor(f.service.state.as_ref().ok_or("state")?)?;
    let stored = call(&mut f.service, &f.admin, "GET", "secret/data/cg/key", json!({}), 100);
    assert_eq!(stored.status, 200);
    assert_eq!(stored.body["data"]["metadata"]["version"], version);
    assert_eq!(stored.body["data"]["data"]["values"], json!(["1", "1", ""]));
    assert_eq!(wire(&mut f, "", "", "POST",
        "sys/workflows/execute/wf131", json!({"values": "unearned"}), "")?.status, 403);
    read(&mut f, version, "observed131", 100);
    policy_write(&mut f.service, &f.admin, "cg-requester",
        r#"path "sys/workflows/execute/wf131" { capabilities = ["update"] }
           path "secret/data/cg/key" { capabilities = ["read"] }"#);
    assert_eq!(wire(&mut f, &requester, "", "POST",
        "sys/workflows/execute/wf131", json!({"values": "unearned"}), "")?.status, 403);
    read(&mut f, version, "observed131", 100);
    Ok(())
}

#[test]
fn workflow131_finite_float_public_sdk_bits_reach_actual_http_and_invalid_literals_preserve_engine_custody()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let document = r#"input { field "float" "float" { required = true query = true } }
        flow "store" { request "kv" { operation = "update" path = "secret/data/cg/key"
            data = { data = { value = "float131" } } } }
        output { data = {
            float = { eval_source = "input" eval_type = "float64" field_name = "float" }
        } }"#;
    install_logical(&mut f, document);
    let token = Zeroizing::new(f.requester.token.to_string());
    let mut version = 1;
    // Expected IEEE bits are from an independently built public SDK2.7
    // FieldData/GetOkErr + strconv consumer, not this parser's output.
    for (raw, expected_bits) in [
        ("0", 0x0000000000000000_u64),
        ("-0", 0x8000000000000000_u64),
        ("+0", 0x0000000000000000_u64),
        ("1", 0x3ff0000000000000_u64),
        ("1.", 0x3ff0000000000000_u64),
        (".5", 0x3fe0000000000000_u64),
        ("-.5", 0xbfe0000000000000_u64),
        ("001.25", 0x3ff4000000000000_u64),
        ("1e2", 0x4059000000000000_u64),
        ("1E-2", 0x3f847ae147ae147b_u64),
        ("1_000.125", 0x408f410000000000_u64),
        ("1.2_5", 0x3ff4000000000000_u64),
        ("1e1_0", 0x4202a05f20000000_u64),
        ("0x1p0", 0x3ff0000000000000_u64),
        ("0X.8p0", 0x3fe0000000000000_u64),
        ("0x_1p0", 0x3ff0000000000000_u64),
        ("0x1.8p+1", 0x4008000000000000_u64),
        ("-0x1p-1074", 0x8000000000000001_u64),
        ("0x1p-1075", 0x0000000000000000_u64),
        ("0x1.0000000000001p-1075", 0x0000000000000001_u64),
        ("0x1.fffffffffffffp1023", 0x7fefffffffffffff_u64),
        ("0x1.fffffffffffff7p1023", 0x7fefffffffffffff_u64),
        ("0x1.00000000000008p0", 0x3ff0000000000000_u64),
        ("0x1.00000000000018p0", 0x3ff0000000000002_u64),
        ("0x0.fffffffffffff8p-1022", 0x0010000000000000_u64),
        ("0x1p-1022", 0x0010000000000000_u64),
        ("0x1p-1023", 0x0008000000000000_u64),
        ("0x1p-2000", 0x0000000000000000_u64),
        ("-0x0p999999", 0x8000000000000000_u64),
        ("1e-400", 0x0000000000000000_u64),
        ("-1e-400", 0x8000000000000000_u64),
        ("1.7976931348623157e308", 0x7fefffffffffffff_u64),
        ("2.2250738585072014e-308", 0x0010000000000000_u64),
        ("4.9406564584124654e-324", 0x0000000000000001_u64),
        ("2.4703282292062327e-324", 0x0000000000000000_u64),
        ("2.4703282292062328e-324", 0x0000000000000001_u64),
        ("0x1.caf0a486_caf0a486caf0a486p-1023", 0x000e578524365785_u64),
        ("0x_1.c29ceda8c29ceda8c29ceda8p-445", 0x242c29ceda8c29cf_u64),
        ("-0x1.3b116d1a_3b116d1a3b116d1ap-275", 0xaec3b116d1a3b117_u64),
        ("0x1.bcb6875cbcb6875cbcb6875cp-193", 0x33ebcb6875cbcb68_u64),
        ("0x1.549494ee_549494ee549494eep57", 0x438549494ee54949_u64),
        ("-0x1.78fc025078fc025078fc0250p-589", 0x9b278fc025078fc0_u64),
        ("0x_1.68027002_6802700268027002p-427", 0x2546802700268027_u64),
        ("0x1.7f9cd2847f9cd2847f9cd284p95", 0x45e7f9cd2847f9cd_u64),
    ] {
        let response = wire(&mut f, &token, "", "POST",
            "sys/workflows/execute/wf131", json!({"float":raw}), "")?;
        assert_eq!(response.status, 200);
        let actual = response.body["data"]["float"].as_f64()
            .ok_or("public finite float output")?;
        assert_eq!(actual.to_bits(), expected_bits, "public SDK finite float bits");
        version += 1;
        read(&mut f, version, "float131", 100);
    }
    // URL query remains metadata; the actual JSON body reaches the consumer.
    for (query, raw, expected_bits) in [
        ("float=0x_1.8p%2B1", "0x_1.8p+1", 0x4008000000000000_u64),
        ("float=1_000.125", "1_000.125", 0x408f410000000000_u64),
    ] {
        let target = format!("sys/workflows/execute/wf131?{query}");
        let response = wire(&mut f, &token, "", "POST", &target, json!({"float":raw}), "")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["float"].as_f64()
            .ok_or("public query float output")?.to_bits(), expected_bits);
        version += 1;
        read(&mut f, version, "float131", 100);
    }
    for (raw, expected) in [
        ("1".repeat(129), 1.1111111111111112e128_f64),
        (format!("{}1", "0".repeat(4096)), 1.0_f64),
        (format!("0x{}1p0", "0".repeat(180)), 1.0_f64),
        (format!("1e{}1", "0".repeat(180)), 10.0_f64),
    ] {
        let response = wire(&mut f, &token, "", "PUT",
            "sys/workflows/execute/wf131?float=ignored", json!({"float":raw}), "")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["float"].as_f64()
            .ok_or("actual long finite float output")?.to_bits(), expected.to_bits());
        version += 1;
        read(&mut f, version, "float131", 100);
    }
    let before = Zeroizing::new(serde_json::to_vec(
        &f.service.state.as_ref().ok_or("actual float state")?.engines)
        .map_err(|_| "float engine custody serialization")?);
    // Syntax/range failures are rejected before the original KV consumer.
    // NaN/Inf remain a separately recorded compatibility gap, not SDK syntax errors.
    for raw in [
        "_1", "1_", "1__0", "1_.0", "1._0", ".", "+.", "1e", "1e+",
        "1e_2", "1e+_2", "0x1", "0x.p0", "0x_.8p0", "0x1_p0",
        "0x1p_0", "0x1p0_", "0x1p0x1", "0b1", "0o1", "1d2", "0xg.p0",
        " 1", "1 ", "1.7976931348623159e308", "0x1.fffffffffffff8p1023",
    ] {
        assert_eq!(wire(&mut f, &token, "", "POST",
            "sys/workflows/execute/wf131", json!({"float":raw}), "")?.status, 500);
        read(&mut f, version, "float131", 100);
        let after = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual unchanged float state")?.engines)
            .map_err(|_| "float unchanged engine serialization")?);
        assert!(before.as_slice() == after.as_slice());
    }
    Ok(())
}

#[test]
fn workflow131_explicit_null_seventeen_fields_and_raw_optional_defaults_reach_actual_http()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let token = Zeroizing::new(f.requester.token.to_string());
    let mut version = 1;
    for (kind, expected, status) in [
        ("string", json!(""), 200),
        ("int", json!(0), 200),
        ("int64", json!(0), 200),
        ("bool", json!(false), 200),
        ("map", Value::Null, 200),
        ("duration_second", json!(0), 200),
        ("signed_duration_second", json!(0), 200),
        ("slice", json!([]), 200),
        ("comma_string_slice", json!([]), 200),
        ("string_slice", json!([]), 200),
        ("lower_case_string", json!(""), 200),
        ("name_string", Value::Null, 500),
        ("kv_pairs", Value::Null, 200),
        ("comma_int_slice", json!([]), 200),
        ("header", json!({}), 200),
        ("float", json!(0), 200),
        ("time", json!("0001-01-01T00:00:00Z"), 200),
    ] {
        let document = format!(r#"input {{ field "{kind}" "value" {{ required = true query = true }} }}
            flow "store" {{ request "kv" {{ operation = "update"
                path = "secret/data/cg/key" data = {{ data = {{ value = "null131" }} }} }} }}
            output {{ data = {{ value = {{ eval_source = "input" eval_type = "any" field_name = "value" }} }} }}"#);
        install_logical(&mut f, &document);
        let before = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual null state")?.engines)
            .map_err(|_| "null engine custody")?);
        let response = wire(&mut f, &token, "", "POST",
            "sys/workflows/execute/wf131?value=ignored",
            json!({"value":null,"unknown":{"unused":"synthetic"}}), "")?;
        assert_eq!(response.status, status, "actual null FieldData consumer");
        if status == 200 {
            assert_eq!(response.body["data"]["value"], expected);
            version += 1;
            read(&mut f, version, "null131", 100);
        } else {
            let after = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual rejected null state")?.engines)
                .map_err(|_| "rejected null engine custody")?);
            assert!(before.as_slice() == after.as_slice());
            read(&mut f, version, "null131", 100);
        }
    }
    for (attrs, input, expected) in [
        ("", json!({}), json!(0)),
        ("required = false", json!({}), json!(0)),
        (r#"default = "not-a-float""#, json!({}), json!("not-a-float")),
        (r#"default = "NaN""#, json!({}), json!("NaN")),
        (r#"default = "+Inf""#, json!({}), json!("+Inf")),
        (r#"default = "7.5""#, json!({}), json!("7.5")),
        ("default = 7.5", json!({}), json!(7.5)),
        ("default = 7.5", json!({"value":null}), json!(0)),
    ] {
        let document = format!(r#"input {{ field "float" "value" {{ {attrs} }} }}
            flow "store" {{ request "kv" {{ operation = "update"
                path = "secret/data/cg/key" data = {{ data = {{ value = "default131" }} }} }} }}
            output {{ data = {{ value = {{ eval_source = "input" eval_type = "any" field_name = "value" }} }} }}"#);
        install_logical(&mut f, &document);
        let response = wire(&mut f, &token, "", "POST", "sys/workflows/execute/wf131",
            input, "")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["value"], expected);
        version += 1;
        read(&mut f, version, "default131", 100);
    }
    Ok(())
}

#[test]
fn workflow131_post_put_body_precedes_query_and_runtime_errors_leave_engines_unchanged()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let token = Zeroizing::new(f.requester.token.to_string());
    let document = r#"input { field "float" "value" { required = true query = true } }
      flow "store" { request "kv" { operation = "update"
        path = "secret/data/cg/key" data = { data = { value = "body131" } } } }
      output { data = {
        value = { eval_source = "input" eval_type = "any" field_name = "value" }
      } }"#;
    install_logical(&mut f, document);
    let mut version = 1;
    for method in ["POST", "PUT"] {
        let response = wire(&mut f, &token, "", method,
            "sys/workflows/execute/wf131?value=bad&value=ignored&unknown=extra",
            json!({"value":"2.5","unknown":"ignored"}), "")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["value"], json!(2.5));
        version += 1;
        read(&mut f, version, "body131", 100);
    }
    let admin = Zeroizing::new(f.admin.to_string());
    assert_eq!(wire(&mut f, &admin, "", "GET",
        "sys/workflows/execute/wf131?value=2.5", json!({}), "")?.status, 405);
    read(&mut f, version, "body131", 100);
    for input in [json!({}), Value::Null, json!({"unknown":"ignored"})] {
        let before = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual missing input state")?.engines)
            .map_err(|_| "missing input engine custody")?);
        assert_eq!(wire(&mut f, &token, "", "POST",
            "sys/workflows/execute/wf131?value=2.5", input, "")?.status, 500);
        let after = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual missing input state")?.engines)
            .map_err(|_| "missing input engine custody")?);
        assert!(before.as_slice() == after.as_slice());
        read(&mut f, version, "body131", 100);
    }
    for (kind, invalid) in [
        ("float", json!("not-a-float")),
        ("time", json!("not-a-time")),
        ("duration_second", json!("bad")),
        ("comma_int_slice", json!("1, 2")),
    ] {
        install_logical(&mut f, &document.replace(r#"field "float""#, &format!("field \"{kind}\"")));
        let before = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual invalid input state")?.engines)
            .map_err(|_| "invalid input engine custody")?);
        assert_eq!(wire(&mut f, &token, "", "POST", "sys/workflows/execute/wf131",
            json!({"value":invalid}), "")?.status, 500);
        let after = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual rejected input state")?.engines)
            .map_err(|_| "rejected input engine custody")?);
        assert!(before.as_slice() == after.as_slice());
        read(&mut f, version, "body131", 100);
    }
    // Definition errors remain installation errors, not runtime FieldData errors.
    for broken in [
        document.replace(r#"field "float""#, r#"field "unknown""#),
        document.replace("required = true query = true", "default = null"),
    ] {
        let old = call(&mut f.service, &f.admin, "GET", "sys/workflows/manage/wf131",
            json!({}), 100);
        assert_eq!(call(&mut f.service, &f.admin, "POST", "sys/workflows/manage/wf131",
            json!({"workflow":broken}), 100).status, 400);
        let unchanged = call(&mut f.service, &f.admin, "GET", "sys/workflows/manage/wf131",
            json!({}), 100);
        assert_eq!(unchanged.body, old.body);
        read(&mut f, version, "body131", 100);
    }
    Ok(())
}

#[test]
fn workflow131_real_public_weak_primitives_and_long_float_body_preserve_error_custody()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let token = Zeroizing::new(f.requester.token.to_string());
    let mut version = 1;
    // Exact synthetic inputs, outputs and effect/no-effect results from the
    // independently closed compiled OpenBao2.7 R23 HTTP consumer (77 cases).
    for (label, kind, input, expected, status) in [
        ("string-weak-0","string",json!(123),json!("123"),200),
        ("string-weak-1","string",json!(true),json!("1"),200),
        ("string-weak-2","string",json!(1.25),json!("1.25"),200),
        ("string-weak-3","string",json!([]),json!(null),500),
        ("string-weak-4","string",json!({}),json!(null),500),
        ("int-weak-0","int",json!(true),json!(1),200),
        ("int-weak-1","int",json!(1.75),json!(null),500),
        ("int-weak-2","int",json!("010"),json!(8),200),
        ("int-weak-3","int",json!("0x10"),json!(16),200),
        ("int-weak-4","int",json!(""),json!(0),200),
        ("int-weak-5","int",json!([]),json!(null),500),
        ("int-weak-6","int",json!(9223372036854775807_i64),json!(9223372036854775807_i64),200),
        ("int-weak-7","int",json!(18446744073709551615_u64),json!(null),500),
        ("int-weak-8","int",json!(1e+30),json!(null),500),
        ("int64-weak-0","int64",json!(true),json!(1),200),
        ("int64-weak-1","int64",json!(1.75),json!(null),500),
        ("int64-weak-2","int64",json!("010"),json!(8),200),
        ("int64-weak-3","int64",json!("0x10"),json!(16),200),
        ("int64-weak-4","int64",json!(""),json!(0),200),
        ("int64-weak-5","int64",json!([]),json!(null),500),
        ("int64-weak-6","int64",json!(9223372036854775807_i64),json!(9223372036854775807_i64),200),
        ("int64-weak-7","int64",json!(18446744073709551615_u64),json!(null),500),
        ("int64-weak-8","int64",json!(1e+30),json!(null),500),
        ("bool-weak-0","bool",json!(1),json!(true),200),
        ("bool-weak-1","bool",json!(0),json!(false),200),
        ("bool-weak-2","bool",json!(-2_i64),json!(null),500),
        ("bool-weak-3","bool",json!(1.75),json!(null),500),
        ("bool-weak-4","bool",json!("TRUE"),json!(true),200),
        ("bool-weak-5","bool",json!("1"),json!(true),200),
        ("bool-weak-6","bool",json!("0"),json!(false),200),
        ("bool-weak-7","bool",json!(""),json!(false),200),
        ("bool-weak-8","bool",json!("yes"),json!(null),500),
        ("bool-weak-9","bool",json!([]),json!(null),500),
        ("bool-weak-10","bool",json!({}),json!(null),500),
        ("map-weak-0","map",json!([]),json!({}),200),
        ("map-weak-1","map",json!([{}]),json!({}),200),
        ("map-weak-2","map",json!([{"a":1},{"b":2}]),json!({"a":1,"b":2}),200),
        ("map-weak-3","map",json!(""),json!(null),500),
        ("map-weak-4","map",json!("a"),json!(null),500),
        ("map-weak-5","map",json!(true),json!(null),500),
        ("map-weak-6","map",json!(1),json!(null),500),
        ("slice-weak-0","slice",json!("x"),json!(["x"]),200),
        ("slice-weak-1","slice",json!(true),json!([true]),200),
        ("slice-weak-2","slice",json!(12),json!([12]),200),
        ("slice-weak-3","slice",json!({}),json!([]),200),
        ("slice-weak-4","slice",json!([]),json!([]),200),
        ("slice-weak-5","slice",json!({"a":1}),json!([{"a":1}]),200),
        ("name_string-weak-0","name_string",json!(123),json!("123"),200),
        ("name_string-weak-1","name_string",json!(true),json!("1"),200),
        ("name_string-weak-2","name_string",json!(1.25),json!("1.25"),200),
        ("name_string-weak-3","name_string",json!("."),json!(null),500),
        ("name_string-weak-4","name_string",json!(" a "),json!(null),500),
        ("duration_second-weak-0","duration_second",json!(true),json!(null),500),
        ("duration_second-weak-1","duration_second",json!(1.75),json!(null),500),
        ("duration_second-weak-2","duration_second",json!("1.5"),json!(null),500),
        ("duration_second-weak-3","duration_second",json!("-500ms"),json!(0),200),
        ("signed_duration_second-weak-0","signed_duration_second",json!(true),json!(null),500),
        ("signed_duration_second-weak-1","signed_duration_second",json!(-1.75),json!(null),500),
        ("signed_duration_second-weak-2","signed_duration_second",json!("-1.5"),json!(null),500),
        ("signed_duration_second-weak-3","signed_duration_second",json!("-500ms"),json!(0),200),
        ("float-weak-0","float",json!(true),json!(1),200),
        ("float-weak-1","float",json!(false),json!(0),200),
        ("float-weak-2","float",json!(12),json!(12),200),
        ("time-weak-0","time",json!(true),json!(null),500),
        ("time-weak-1","time",json!(0),json!("1970-01-01T00:00:00Z"),200),
        ("time-weak-2","time",json!(1.5),json!(null),500),
        ("time-weak-3","time",json!(""),json!(null),500),
        ("time-weak-4","time",json!("0"),json!("1970-01-01T00:00:00Z"),200),
        ("time-weak-5","time",json!("1735689600"),json!("2025-01-01T00:00:00Z"),200),
        ("string_slice-weak-0","string_slice",json!(123),json!(["123"]),200),
        ("string_slice-weak-1","string_slice",json!(true),json!(["1"]),200),
        ("string_slice-weak-2","string_slice",json!({}),json!([]),200),
        ("string_slice-weak-3","string_slice",json!([1,true,null]),json!(["1","1",""]),200),
        ("kv_pairs-weak-0","kv_pairs",json!("a=b,c=d"),json!({"a":"b,c=d"}),200),
        ("kv_pairs-weak-1","kv_pairs",json!(["a=b","c=d"]),json!({"a":"b","c":"d"}),200),
        ("kv_pairs-weak-2","kv_pairs",json!({"a":1,"b":true}),json!({"a":"1","b":"1"}),200),
        ("float-32769-leading-zeroes","float",json!(format!("{}1", "0".repeat(32768))),json!(1),200),
    ] {
        let document = format!(r#"input {{ field "{kind}" "value" {{ required = true }} }}
            flow "store" {{ request "kv" {{ operation = "update"
                path = "secret/data/cg/key" data = {{ data = {{ value = "weak131" }} }} }} }}
            output {{ data = {{ value = {{ eval_source = "input" eval_type = "any"
                field_name = "value" }} }} }}"#);
        install_logical(&mut f, &document);
        let before = Zeroizing::new(serde_json::to_vec(
            &f.service.state.as_ref().ok_or("actual weak input state")?.engines)
            .map_err(|_| "weak input engine custody")?);
        let response = wire(&mut f, &token, "", "POST", "sys/workflows/execute/wf131",
            json!({"value":input}), "")?;
        assert_eq!(response.status, status, "public R23 FieldData status: {label}");
        if status == 200 {
            if kind == "float" {
                assert_eq!(response.body["data"]["value"].as_f64()
                    .ok_or("actual weak float output")?.to_bits(),
                    expected.as_f64().ok_or("actual R23 float expectation")?.to_bits(),
                    "public R23 float bits: {label}");
            } else {
                assert_eq!(response.body["data"]["value"], expected,
                    "public R23 FieldData value: {label}");
            }
            version += 1;
            read(&mut f, version, "weak131", 100);
        } else {
            let after = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual rejected weak input state")?.engines)
                .map_err(|_| "rejected weak input engine custody")?);
            assert!(before.as_slice() == after.as_slice(), "public R23 no effect: {label}");
            read(&mut f, version, if version == 1 { "before" } else { "weak131" }, 100);
        }
    }
    Ok(())
}

fn nonfinite_document(first: bool, request_kind: Option<&str>, output_kind:&str) -> String {
    let mut document=String::from(r#"input { field "float" "value" { required = true } }
flow "store" {"#);
    if first {
        document.push_str(r#"request "first" { operation = "update" path = "secret/data/cg/key"
            data = { data = { value = "stage-one" } } }"#);
    }
    if let Some(kind)=request_kind {
        document.push_str(&format!(r#"request "selected" {{ operation = "update"
            path = "secret/data/cg/key" data = {{ data = {{ value = {{
            eval_source = "input" eval_type = "{kind}" field_name = "value" }} }} }} }}"#));
    }
    document.push_str(&format!(r#"}} output {{ data = {{ value = {{ eval_source = "input"
        eval_type = "{output_kind}" field_name = "value" }} }} }}"#));
    document
}
fn nonfinite_raw(f:&mut Fixture, token:&str, input:Value, wrap:bool)
    -> TestResult<Zeroizing<Vec<u8>>> {
    let encoded=Zeroizing::new(serde_json::to_vec(&input)?);
    let ttl=if wrap {"X-Vault-Wrap-TTL: 60s\r\n"} else {""};
    let head=Zeroizing::new(format!("POST /v1/sys/workflows/execute/wf131 HTTP/1.1\r\n\
        Host: fixture\r\nX-Vault-Token: {token}\r\nContent-Type: application/json\r\n\
        Content-Length: {}\r\n{ttl}\r\n",encoded.len()));
    let mut request=Zeroizing::new(head.as_bytes().to_vec());
    request.extend_from_slice(&encoded);
    crate::http::workflow_output_wire_fixture(&mut f.service,&request,100)
        .map_err(|_|"actual complete output HTTP consumer failed".into())
}
fn nonfinite_response_body(bytes:&[u8]) -> TestResult<&[u8]> {
    let end=bytes.windows(4).position(|part|part==b"\r\n\r\n").ok_or("actual HTTP header terminator")?;
    Ok(&bytes[end+4..])
}

#[test]
fn workflow131_nonfinite_selected_request_serialization_preserves_only_prior_committed_effects()
-> TestResult {
    let mut f=setup()?;
    create(&mut f);
    let token=Zeroizing::new(f.admin.to_string());
    let mut version=1;
    for raw in ["NaN","+Inf","-Inf"] {
        install_logical(&mut f,&nonfinite_document(false,Some("float64"),"any"));
        let before=Zeroizing::new(serde_json::to_vec(&f.service.state.as_ref().ok_or("before")?.engines)?);
        let rejected=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
            json!({"value":raw}),"")?;
        assert_eq!(rejected.status,500);
        let after=Zeroizing::new(serde_json::to_vec(&f.service.state.as_ref().ok_or("after")?.engines)?);
        assert!(before.as_slice()==after.as_slice());
        let stored=call(&mut f.service,&token,"GET","secret/data/cg/key",json!({}),100);
        assert_eq!(stored.body["data"]["metadata"]["version"],version);

        install_logical(&mut f,&nonfinite_document(true,Some("float64"),"any"));
        let rejected=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
            json!({"value":raw}),"")?;
        assert_eq!(rejected.status,500);
        version+=1;
        read(&mut f,version,"stage-one",100);
        assert_logical_userpass_floor(f.service.state.as_ref().ok_or("actual state")?)?;
    }
    install_logical(&mut f,&nonfinite_document(true,Some("float64"),"any"));
    let finite=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
        json!({"value":1.25}),"")?;
    assert_eq!(finite.status,200);
    assert_eq!(finite.body["data"]["value"],1.25);
    version+=2;
    let stored=call(&mut f.service,&token,"GET","secret/data/cg/key",json!({}),100);
    assert_eq!(stored.body["data"]["metadata"]["version"],version);
    assert_eq!(stored.body["data"]["data"]["value"],1.25);
    // Missing optional defaults are original raw strings, not supplied Float conversion.
    let document=nonfinite_document(false,Some("any"),"any")
        .replace("required = true",r#"default = "NaN""#);
    install_logical(&mut f,&document);
    let default=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",json!({}),"")?;
    assert_eq!(default.status,200);
    assert_eq!(default.body["data"]["value"],"NaN");
    version+=1;
    read(&mut f,version,"NaN",100);
    Ok(())
}

#[test]
fn workflow131_real_float_runtime_casts_output_empty_wire_and_wrapping_fail_at_actual_stage()
-> TestResult {
    let mut f=setup()?;
    create(&mut f);
    let token=Zeroizing::new(f.admin.to_string());
    let mut version=1;
    for (raw,text) in [("NaN","NaN"),("+Inf","+Inf"),("-Inf","-Inf")] {
        for (kind,expected) in [
            ("string",json!(text)),("int",json!(i64::MIN)),("bool",json!(true)),
            ("[]string",json!([text])),
        ] {
            install_logical(&mut f,&nonfinite_document(true,None,kind));
            let reply=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
                json!({"value":raw}),"")?;
            assert_eq!(reply.status,200);
            assert_eq!(reply.body["data"]["value"],expected);
            version+=1;
            read(&mut f,version,"stage-one",100);
            install_logical(&mut f,&nonfinite_document(false,Some(kind),"any"));
            let reply=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
                json!({"value":raw}),"")?;
            assert_eq!(reply.status,200);
            let stored=call(&mut f.service,&token,"GET","secret/data/cg/key",json!({}),100);
            version+=1;
            assert_eq!(stored.body["data"]["metadata"]["version"],version);
            assert_eq!(stored.body["data"]["data"]["value"],expected);
        }
        for kind in ["any","float64"] {
            install_logical(&mut f,&nonfinite_document(true,None,kind));
            let raw_response=nonfinite_raw(&mut f,&token,json!({"value":raw}),false)?;
            assert!(raw_response.starts_with(b"HTTP/1.1 200 "));
            assert!(nonfinite_response_body(&raw_response)?.is_empty());
            version+=1;
            read(&mut f,version,"stage-one",100);
            let wrapped=nonfinite_raw(&mut f,&token,json!({"value":raw}),true)?;
            assert!(wrapped.starts_with(b"HTTP/1.1 500 "),
                "actual wrapped workflow status: {}",
                String::from_utf8_lossy(wrapped.split(|byte| *byte == b'\r').next().unwrap_or(&[])));
            let error:Value=serde_json::from_slice(nonfinite_response_body(&wrapped)?)?;
            assert_eq!(error["errors"],json!(["internal error"]));
            assert!(error.get("wrap_info").is_none());
            version+=1;
            read(&mut f,version,"stage-one",100);
        }
        install_logical(&mut f,&nonfinite_document(true,None,"int64"));
        let unsupported=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
            json!({"value":raw}),"")?;
        assert_eq!(unsupported.status,500);
        version+=1;
        read(&mut f,version,"stage-one",100);
        install_logical(&mut f,&nonfinite_document(false,Some("int64"),"any"));
        let before=Zeroizing::new(serde_json::to_vec(&f.service.state.as_ref().ok_or("before cast")?.engines)?);
        assert_eq!(wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
            json!({"value":raw}),"")?.status,500);
        assert!(before.as_slice()==serde_json::to_vec(&f.service.state.as_ref().ok_or("after cast")?.engines)?.as_slice());
    }
    install_logical(&mut f,&nonfinite_document(true,None,"float64"));
    let wrapped=nonfinite_raw(&mut f,&token,json!({"value":1.25}),true)?;
    assert!(wrapped.starts_with(b"HTTP/1.1 200 "));
    let wrapped_body:Value=serde_json::from_slice(nonfinite_response_body(&wrapped)?)?;
    let wrapper=Zeroizing::new(text(&wrapped_body,"/wrap_info/token")?);
    let unwrapped=call(&mut f.service,&wrapper,"POST","sys/wrapping/unwrap",json!({}),100);
    assert_eq!(unwrapped.status,200);
    assert_eq!(unwrapped.body["data"]["value"],1.25);
    version+=1;
    read(&mut f,version,"stage-one",100);
    // The admitted int64 type fails during output evaluation, even for finite input.
    install_logical(&mut f,&nonfinite_document(true,None,"int64"));
    assert_eq!(wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
        json!({"value":1.25}),"")?.status,500);
    version+=1;
    read(&mut f,version,"stage-one",100);
    Ok(())
}

#[test]
fn workflow131_true_nonfinite_input_reaches_maintained_cel_template_and_public_objects_cannot_mint_it()
-> TestResult {
    let mut f=setup()?;
    create(&mut f);
    let token=Zeroizing::new(f.admin.to_string());
    let document=r#"input { field "float" "value" { required = true } }
        flow "store" { request "first" { operation = "update" path = "secret/data/cg/key"
            data = { data = { value = "typed-runtime" } } } }
        output { data = {
            is_double = { eval_source = "cel" eval_type = "bool" expression = "type(input.value) == double" }
            is_nan = { eval_source = "cel" eval_type = "bool" expression = "input.value != input.value" }
            template_type = { eval_source = "template" eval_type = "string" template = "{{printf \"%T\" .input.value}}" }
            selected = { eval_source = "input" eval_type = "string" field_name = "value" }
        } }"#;
    install_logical(&mut f,document);
    let reply=wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
        json!({"value":"NaN"}),"")?;
    assert_eq!(reply.status,200);
    assert_eq!(reply.body["data"],json!({"is_double":true,"is_nan":true,
        "template_type":"float64","selected":"NaN"}));
    read(&mut f,2,"typed-runtime",100);
    for forged in [
        json!({"kind":"float64-bits","value":f64::NAN.to_bits()}),
        json!({"workflow_output_failure":true,"raw":[]}),
        json!({"data":{},"output_digest":[1,2,3]}),
    ] {
        let before=Zeroizing::new(serde_json::to_vec(&f.service.state.as_ref().ok_or("before forged")?.engines)?);
        assert_eq!(wire(&mut f,&token,"","POST","sys/workflows/execute/wf131",
            json!({"value":forged}),"")?.status,500);
        let after=Zeroizing::new(serde_json::to_vec(&f.service.state.as_ref().ok_or("after forged")?.engines)?);
        assert!(before.as_slice()==after.as_slice());
        read(&mut f,2,"typed-runtime",100);
    }
    Ok(())
}


#[test]
fn workflow131_hcl_numeric_defaults_use_real_legacy_tokens_and_install_errors_have_no_effect()
    -> TestResult
{
    let mut f = setup()?;
    create(&mut f);
    logical_policy(&mut f, false);
    let token = Zeroizing::new(f.requester.token.to_string());
    let mut version = 1;
    // Original compiled2.7 R35 and R36: 23 actual installation/execution rows.
    for (literal, expected) in [
        ("7.5", Some(7.5)),
        ("-0", Some(0.0)),
        ("-0.0", Some(0.0)),
        (".5", Some(0.5)),
        ("+1.5", None),
        ("1e2", Some(100.0)),
        ("1E+2", Some(100.0)),
        ("01", Some(1.0)),
        ("1e309", None),
        ("-1e309", None),
        ("null", None),
        ("7.5", Some(7.5)),
        ("-.5", None),
        ("010", Some(8.0)),
        ("08", None),
        ("09", None),
        ("-010", Some(-8.0)),
        ("0x10", Some(16.0)),
        ("1.", Some(1.0)),
        ("1.e2", Some(100.0)),
        ("1_0", None),
        (".5e2", None),
        ("0007", Some(7.0)),
    ] {
        let document = format!(r#"input {{ field "float" "value" {{ default = {literal} }} }}
          flow "store" {{ request "kv" {{ operation = "update"
            path = "secret/data/cg/key" data = {{ data = {{
              value = "grammar131"
              number = {{ eval_source = "input" eval_type = "any" field_name = "value" }}
            }} }} }} }}
          output {{ data = {{ value = {{
            eval_source = "input" eval_type = "any" field_name = "value"
          }} }} }}"#);
        if let Some(expected) = expected {
            install_logical(&mut f, &document);
            let (method, path, body, frame) = f.service.state.as_ref().ok_or("actual grammar state")?
                .namespaces.workflows.logical_first_step_fixture("", "wf131", &json!({}), Instant::now())
                .map_err(|_| "actual stored numeric Program resolution")?;
            assert_eq!(method, "POST");
            assert_eq!(path, "secret/data/cg/key");
            assert_eq!(body["data"]["value"], json!("grammar131"));
            assert_eq!(body["data"]["number"].as_f64(), Some(expected), "typed default {literal}");
            assert!(frame.is_none());
            let response = wire(&mut f, &token, "", "POST",
                "sys/workflows/execute/wf131", json!({}), "")?;
            assert_eq!(response.status, 200, "actual numeric default {literal}");
            assert!(response.body["data"]["value"].is_number());
            assert_eq!(response.body["data"]["value"].as_f64(), Some(expected));
            version += 1;
            read(&mut f, version, "grammar131", 100);
            let saved = call(&mut f.service, &f.admin, "GET",
                "secret/data/cg/key", json!({}), 100);
            assert_eq!(saved.status, 200);
            assert_eq!(saved.body["data"]["data"]["number"].as_f64(), Some(expected));
        } else {
            let before = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual rejected grammar state")?.engines)
                .map_err(|_| "grammar engine custody")?);
            let old = call(&mut f.service, &f.admin, "GET",
                "sys/workflows/manage/wf131", json!({}), 100);
            assert_eq!(call(&mut f.service, &f.admin, "POST",
                "sys/workflows/manage/wf131", json!({"workflow":document}), 100).status,
                400, "actual rejected default {literal}");
            let unchanged = call(&mut f.service, &f.admin, "GET",
                "sys/workflows/manage/wf131", json!({}), 100);
            assert_eq!(unchanged.status, old.status);
            assert_eq!(unchanged.body, old.body);
            let after = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual rejected grammar state")?.engines)
                .map_err(|_| "rejected grammar engine custody")?);
            assert!(before.as_slice() == after.as_slice());
            read(&mut f, version, "grammar131", 100);
        }
    }
    // R38 pins original response number tokens, exact signed-i64 and signbit.
    for (literal, expected_literal) in [
        ("7.5", Some("7.5")),
        ("-0", Some("0")),
        ("-0.0", Some("-0")),
        ("9223372036854775807", Some("9223372036854775807")),
        ("9223372036854775808", None),
        ("18446744073709551615", None),
        ("-9223372036854775808", Some("-9223372036854775808")),
        ("-9223372036854775809", None),
        ("-0x10", Some("-16")),
        ("0X10", Some("16")),
        ("0b10", None),
        ("0o10", None),
    ] {
        let document = format!(r#"input {{ field "float" "value" {{ default = {literal} }} }}
          flow "store" {{ request "kv" {{ operation = "update"
            path = "secret/data/cg/key" data = {{ data = {{ value = "grammar131" }} }} }} }}
          output {{ data = {{ value = {{
            eval_source = "input" eval_type = "any" field_name = "value"
          }} }} }}"#);
        if let Some(expected_literal) = expected_literal {
            install_logical(&mut f, &document);
            let raw = nonfinite_raw(&mut f, &token, json!({}), false)?;
            assert!(raw.starts_with(b"HTTP/1.1 200 "));
            let response = crate::auth::parse_strict_json(nonfinite_response_body(&raw)?)
                .map_err(|_| "actual HCL numeric original wire")?;
            let value = &response["data"]["value"];
            assert!(value.is_number());
            if literal == "-0.0" {
                assert_eq!(value.as_f64().ok_or("actual float zero")?.to_bits(),
                    (-0.0_f64).to_bits());
            } else {
                let expected = crate::auth::parse_strict_json(expected_literal.as_bytes())
                    .map_err(|_| "actual expected numeric token")?;
                if let Some(integer) = expected.as_i64() {
                    assert_eq!(value.as_i64(), Some(integer), "exact HCL int {literal}");
                } else {
                    assert_eq!(value.as_f64(), expected.as_f64());
                }
                if literal == "-0" {
                    assert_eq!(value.as_f64().ok_or("actual integer zero")?.to_bits(), 0.0_f64.to_bits());
                }
            }
            version += 1;
            read(&mut f, version, "grammar131", 100);
        } else {
            let before = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual integer-range state")?.engines)
                .map_err(|_| "integer-range engine custody")?);
            let old = call(&mut f.service, &f.admin, "GET",
                "sys/workflows/manage/wf131", json!({}), 100);
            assert_eq!(call(&mut f.service, &f.admin, "POST",
                "sys/workflows/manage/wf131", json!({"workflow":document}), 100).status, 400);
            let unchanged = call(&mut f.service, &f.admin, "GET",
                "sys/workflows/manage/wf131", json!({}), 100);
            assert_eq!(unchanged.body, old.body);
            let after = Zeroizing::new(serde_json::to_vec(
                &f.service.state.as_ref().ok_or("actual integer-range state")?.engines)
                .map_err(|_| "integer-range engine custody")?);
            assert!(before.as_slice() == after.as_slice());
            read(&mut f, version, "grammar131", 100);
        }
    }
    Ok(())
}
