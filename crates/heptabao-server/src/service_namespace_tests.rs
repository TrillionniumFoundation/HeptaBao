use super::super::tests::{Root, bootstrap, call};
use super::*;
use serde_json::json;

#[test]
fn namespace_tree_metadata_restart_and_incarnation_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({"custom_metadata":{"owner":"platform","tier":"dev"}})
        )
        .status,
        204
    );
    let team = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(team.status, 200);
    assert_eq!(team.body["path"], "team/");
    assert_eq!(team.body["custom_metadata"]["owner"], "platform");
    let first_id = team.body["id"].as_str().ok_or("missing namespace id")?.to_owned();

    let list = call(
        &mut service,
        "LIST",
        "sys/namespaces",
        &token,
        json!({}),
    );
    assert_eq!(list.status, 200);
    assert_eq!(list.body["data"]["keys"], json!(["team/"]));
    assert_eq!(list.body["data"]["key_info"]["team/"]["id"], first_id);

    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"application"}}),
                100
            )
            .status,
        204
    );
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.status, 200);
    assert_eq!(child.body["path"], "child/");
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"owner":"payments","obsolete":"remove-me"}}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "PATCH",
                "sys/namespaces/child",
                "team",
                &token,
                json!({"custom_metadata":{"obsolete":null}}),
                100
            )
            .status,
        204
    );
    let scan = call(
        &mut service,
        "SCAN",
        "sys/namespaces",
        &token,
        json!({}),
    );
    assert_eq!(scan.status, 200);
    assert_eq!(scan.body["data"]["keys"], json!(["team/", "team/child/"]));
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );

    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let reopened = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body["id"], first_id);
    let child = service.handle_at(
        "GET",
        "sys/namespaces/child",
        "team",
        &token,
        json!({}),
        100,
    );
    assert_eq!(child.body["custom_metadata"]["owner"], "payments");
    assert!(child.body["custom_metadata"].get("obsolete").is_none());

    assert_eq!(
        service
            .handle_at(
                "DELETE",
                "sys/namespaces/child",
                "team",
                &token,
                json!({}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        204
    );
    let recreated = call(
        &mut service,
        "GET",
        "sys/namespaces/team",
        &token,
        json!({}),
    );
    assert_ne!(recreated.body["id"], first_id);
    Ok(())
}

#[test]
fn namespace_catalog_refuses_seal_and_nonempty_silent_delete()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/sealed",
            &token,
            json!({"seal":"seal \"shamir\" {}"})
        )
        .status,
        501
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "secret/data/item",
                "team",
                &token,
                json!({"data":{"value":"secret"}}),
                100
            )
            .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/namespaces/team",
            &token,
            json!({})
        )
        .status,
        409
    );
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let mut downgraded = state.clone();
    downgraded.schema = 8;
    assert!(downgraded.validate_format().is_err());
    Ok(())
}
