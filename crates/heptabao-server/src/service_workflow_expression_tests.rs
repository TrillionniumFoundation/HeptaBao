//! Service controls exercise maintained consumers through normal ACL and durable dispatch.
use super::*;

const EXPRESSION125: &str = r#"input {
  field "int" "a" { required = true }
  field "string" "word" { default = "after" }
}
flow "write" {
  when = { eval_source = "cel" eval_type = "bool" expression = "input.a > 0" }
  request "save" {
    operation = "update" path = "secret/data/cg/key"
    data = { data = {
      value = { eval_source = "cel" eval_type = "string" expression = "input.word" }
      n = { eval_source = "cel" eval_type = "int" expression = "sum"
        variables = [{ name = "sum" expression = "input.a + 3" }] }
    } }
  }
  request "skipped" {
    when = { eval_source = "cel" eval_type = "bool" expression = "false" }
    operation = "update" path = "secret/data/cg/skipped" data = { data = { value = "forbidden" } }
  }
}
flow "read" { request "load" { operation = "read" path = "secret/data/cg/key" } }
output { data = {
  n = { eval_source = "cel" eval_type = "float64" expression = "responses.read.load.data.data.n" }
  numeric_type = { eval_source = "cel" eval_type = "bool" expression = "type(responses.read.load.data.data.n) == double" }
  path = { eval_source = "cel" eval_type = "string" expression = "requests.write.save.path" }
  text = { eval_source = "template" eval_type = "string" template = "{{.input.word}}" }
} }"#;

#[test]
fn workflow125_cel_and_template_use_actual_dispatch_and_validate_before_effects() -> TestResult {
    let mut f = setup()?;
    create(&mut f);
    assert_eq!(dynamic_profile123(&mut f, EXPRESSION125, -1).status, 200);
    let reply = call(
        &mut f.service,
        &f.admin,
        "POST",
        "sys/workflows/execute/cg-wire",
        json!({"a":2}),
        100,
    );
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.body["data"],
        json!({"n":5,"numeric_type":true,"path":"secret/data/cg/key","text":"after"})
    );
    let stored = call(
        &mut f.service,
        &f.admin,
        "GET",
        "secret/data/cg/key",
        json!({}),
        100,
    );
    assert_eq!(stored.status, 200);
    assert_eq!(stored.body["data"]["data"], json!({"value":"after","n":5}));
    assert_eq!(stored.body["data"]["metadata"]["version"], 2);
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "GET",
            "secret/data/cg/skipped",
            json!({}),
            100
        )
        .status,
        404
    );
    for input in [
        json!({}),
        json!({"a":"not-an-int"}),
        json!({"a":2,"word":true}),
    ] {
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/workflows/execute/cg-wire",
                input,
                100
            )
            .status,
            400
        );
        read(&mut f, 2, "after", 100);
    }
    for (cas, expression) in [(1, "1 / 0"), (2, "(")] {
        let document = EXPRESSION125.replace("input.a + 3", expression);
        assert_eq!(dynamic_profile123(&mut f, &document, cas).status, 200);
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "POST",
                "sys/workflows/execute/cg-wire",
                json!({"a":2}),
                100
            )
            .status,
            500
        );
        read(&mut f, 2, "after", 100);
        assert_eq!(
            call(
                &mut f.service,
                &f.admin,
                "GET",
                "secret/data/cg/skipped",
                json!({}),
                100
            )
            .status,
            404
        );
    }
    Ok(())
}

#[test]
fn workflow125_resolved_cel_controlled_body_restarts_once_and_keeps_live_authority() -> TestResult {
    let document = r#"input { field "int" "a" { required = true } }
    flow "controlled" { request "write" {
      operation = "update" path = "secret/data/cg/key"
      data = { data = {
        value = { eval_source = "cel" eval_type = "string" expression = "'after'" }
        n = { eval_source = "cel" eval_type = "int" expression = "input.a + 3" }
      } }
    } }
    output { data = { wrapping = { eval_source = "response" eval_type = "any"
      flow_name = "controlled" response_name = "write" field_selector = "wrap_info" } } }"#;
    for precise in [false, true] {
        let mut f = setup()?;
        create(&mut f);
        let policy = requester_policy("60s", "")
            + r#"path "sys/workflows/execute/cg-wire" { capabilities = ["update"] }"#;
        policy_write(&mut f.service, &f.admin, "cg-requester", &policy);
        assert_eq!(dynamic_profile123(&mut f, document, -1).status, 200);
        let pending = observed_call(
            &mut f.service,
            &f.requester.token,
            "POST",
            "sys/workflows/execute/cg-wire",
            json!({"a":2}),
            100,
            precise,
        )?;
        assert_eq!(pending.status, 200);
        let wrapper = Zeroizing::new(text(&pending.body, "/data/wrapping/token")?);
        let accessor = text(&pending.body, "/data/wrapping/accessor")?;
        let review = review_request(&mut f, &accessor);
        assert_eq!(review.status, 200);
        assert_eq!(
            review.body["data"]["request_data"],
            json!({"data":{"value":"after","n":5}})
        );
        assert_eq!(
            review.body["data"]["request_entity"]["ID"],
            f.requester.entity
        );
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
        approve_two(&mut f, &accessor);
        f = restart(f, 100)?;
        let replacement = document
            .replace("input.a + 3", "99")
            .replace("'after'", "'must-not-rewrite-owner'");
        assert_eq!(dynamic_profile123(&mut f, &replacement, 1).status, 200);
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
        let stored = call(
            &mut f.service,
            &f.admin,
            "GET",
            "secret/data/cg/key",
            json!({}),
            100,
        );
        assert_eq!(stored.body["data"]["data"], json!({"value":"after","n":5}));
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
        let pending = observed_call(
            &mut f.service,
            &f.requester.token,
            "POST",
            "sys/workflows/execute/cg-wire",
            json!({"a":2}),
            100,
            precise,
        )?;
        assert_eq!(pending.status, 200);
        let wrapper = Zeroizing::new(text(&pending.body, "/data/wrapping/token")?);
        let accessor = text(&pending.body, "/data/wrapping/accessor")?;
        approve_two(&mut f, &accessor);
        policy_write(
            &mut f.service,
            &f.admin,
            "cg-requester",
            r#"path "sys/workflows/execute/cg-wire" { capabilities = ["update"] }
            path "secret/data/cg/*" { capabilities = ["deny"] }"#,
        );
        f = restart(f, 100)?;
        assert_eq!(
            observed_call(
                &mut f.service,
                &wrapper,
                "POST",
                "sys/wrapping/unwrap",
                json!({}),
                100,
                precise
            )?
            .status,
            403
        );
        read(&mut f, 2, "after", 100);
        assert_raw_absent(&f, &f.requester.token)?;
    }
    Ok(())
}

#[test]
fn workflow125_active_and_retired_expression_floors_reject_old_publication_and_snapshot()
-> TestResult {
    let mut f = setup()?;
    create(&mut f);
    let old = f.service.state.as_ref().ok_or("old state")?.clone();
    assert!(!old.namespaces.workflows.has_expression_profiles());
    assert!(old.writer_schema() < WORKFLOW_EXPRESSION_STATE_SCHEMA);
    assert_eq!(dynamic_profile123(&mut f, EXPRESSION125, -1).status, 200);
    let active = f.service.state.as_ref().ok_or("active")?.clone();
    assert_eq!(active.schema, WORKFLOW_EXPRESSION_STATE_SCHEMA);
    assert_eq!(active.writer_schema(), WORKFLOW_EXPRESSION_STATE_SCHEMA);
    assert!(active.namespaces.workflows.has_expression_profiles());
    assert!(active.validate_format().is_ok());
    assert!(supported_reader_schema(WORKFLOW_EXPRESSION_STATE_SCHEMA));
    assert!(!supported_reader_schema(MAX_SUPPORTED_STATE_SCHEMA + 1));
    let raw = Zeroizing::new(serde_json::to_vec(&active)?);
    let decoded: State = serde_json::from_slice(&raw)?;
    assert!(decoded.validate_format().is_ok());
    assert!(decoded.namespaces.workflows.has_expression_profiles());
    for schema in [
        WORKFLOW_PROFILE_STATE_SCHEMA,
        WORKFLOW_DYNAMIC_STATE_SCHEMA,
        TRANSIT_ROTATION_PRECISION_STATE_SCHEMA,
    ] {
        let mut lower = decoded.clone();
        lower.schema = schema;
        assert_eq!(lower.validate_format().err().ok_or("reader")?.status, 503);
        assert_eq!(
            lower
                .validate_publication_schema(Some(&active))
                .err()
                .ok_or("publisher")?
                .status,
            503
        );
        assert_eq!(
            Service::validate_snapshot_protected_floor(&active, &lower)
                .err()
                .ok_or("snapshot")?
                .status,
            400
        );
    }
    f = restart(f, 100)?;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/workflows/execute/cg-wire",
            json!({"a":2}),
            100
        )
        .status,
        200
    );
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
    assert!(!retired.namespaces.workflows.has_expression_profiles());
    assert_eq!(retired.schema, WORKFLOW_EXPRESSION_STATE_SCHEMA);
    assert_eq!(retired.writer_schema(), WORKFLOW_EXPRESSION_STATE_SCHEMA);
    assert!(retired.validate_format().is_ok());
    let mut lower = retired.clone();
    lower.schema = TRANSIT_ROTATION_PRECISION_STATE_SCHEMA;
    assert_eq!(
        lower
            .validate_publication_schema(Some(&retired))
            .err()
            .ok_or("retired publisher")?
            .status,
        503
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(&retired, &lower)
            .err()
            .ok_or("retired snapshot")?
            .status,
        400
    );
    assert_eq!(
        Service::validate_snapshot_protected_floor(&retired, &old)
            .err()
            .ok_or("old snapshot")?
            .status,
        400
    );
    f = restart(f, 100)?;
    assert_eq!(
        f.service.state.as_ref().ok_or("retired reopen")?.schema,
        WORKFLOW_EXPRESSION_STATE_SCHEMA
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "GET",
            "sys/workflows/manage/cg-wire",
            json!({}),
            100
        )
        .status,
        404
    );
    Ok(())
}
