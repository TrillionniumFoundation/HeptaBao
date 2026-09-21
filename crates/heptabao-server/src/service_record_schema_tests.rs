//! Format gates run on the authenticated graph, not merely its root tag.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use crate::state_records::ObjectKind;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn artifacts(service: &Service) -> TestResult<Vec<[u8; 32]>> {
    ["state.hbs", "journal.hbj", "ledger.hbl"]
        .into_iter()
        .map(|name| {
            fs::read(service.data_dir.join(name))
                .map(|bytes| crypto::digest(&bytes))
                .map_err(Into::into)
        })
        .collect()
}

fn mount(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/mounts/records",
            token,
            json!({"type":"kv","options":{"version":"1"}})
        )
        .status,
        204
    );
}

#[test]
fn schema36_read_reopen_noop_and_rejection_do_not_upgrade_but_mutation_does() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    mount(&mut service, &token);
    // Referenced values retain the exact pre-packed shape. Merely reading them
    // must not repack the tree or raise the persisted reader requirement.
    let value = json!({"payload":"x".repeat(2048)});
    assert_eq!(
        call(&mut service, "PUT", "records/old", &token, value.clone()).status,
        204
    );
    let mut old = service.state.clone().ok_or("state")?;
    assert!(!old.engines.has_packed_kv1_records());
    old.schema = 36;
    let plan = service.prepare_record_plan(&old).map_err(|_| "old plan")?;
    service
        .commit_record_plan(&old, plan)
        .map_err(|_| "old publication")?;
    service.state = Some(old);
    let identity = service
        .current_state_identity()
        .map_err(|_| "old identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    drop(service);

    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 36);
    assert_eq!(
        call(&mut service, "GET", "records/old", &token, json!({})).body["data"],
        value
    );
    assert_eq!(
        call(&mut service, "PUT", "records/old", &token, value).status,
        204
    );
    assert_eq!(
        call(&mut service, "PUT", "records/rejected", &token, json!(7)).status,
        400
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 36);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        identity
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );

    assert_eq!(
        call(
            &mut service,
            "PUT",
            "records/new",
            &token,
            json!({"kept":true})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.engines.has_packed_kv1_records());
    let identity = service
        .current_state_identity()
        .map_err(|_| "new identity")?;
    let backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    assert!(service.prepare_snapshot_restore(&backup).is_ok());
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "reopen identity")?,
        identity
    );
    assert_eq!(
        call(&mut service, "GET", "records/new", &token, json!({})).body["data"]["kept"],
        true
    );
    Ok(())
}

#[test]
fn authenticated_deep_packed_graph_cannot_hide_under_schema36_on_any_load_path() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (key, token) = bootstrap(&mut service)?;
    mount(&mut service, &token);
    let mut next = service.state.clone().ok_or("state")?;
    // Byte-bounded pages force multiple Branch levels, independently of the
    // 256-entry ceiling. The public root itself therefore has an old kind.
    for number in 0..700 {
        next.engines.handle(
            "",
            "PUT",
            &format!("records/{number:04}-{}", "p".repeat(900)),
            &json!({"value":number}),
            100,
        )?;
    }
    assert!(next.engines.has_packed_kv1_records());
    let root = next.engines.record_root().ok_or("graph")?;
    assert!(root.height >= 3);
    assert_eq!(
        root.reference.as_ref().ok_or("root")?.kind,
        ObjectKind::Branch
    );
    let good = service
        .prepare_record_plan(&next)
        .map_err(|_| "good plan")?;
    service
        .commit_record_plan(&next, good)
        .map_err(|_| "good publication")?;
    service.state = Some(next.clone());
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut downgraded = next;
    downgraded.schema = 36;
    assert!(downgraded.validate_format().is_err());
    let bad = service
        .prepare_record_plan(&downgraded)
        .map_err(|_| "candidate identity")?;
    let bad_root = bad.root.clone();
    assert_eq!(
        service
            .commit_record_plan(&downgraded, bad)
            .err()
            .ok_or("gate")?
            .status,
        503
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    // This is the same authenticated loader used by HA follower materialization.
    assert!(
        Service::materialize_record_state(
            &bad_root,
            &DurableReader(service.durable.as_ref().ok_or("durable")?)
        )
        .is_err()
    );

    // Explicit test-only storage corruption: retain every valid authenticated
    // object, but re-label the root as an old schema. This must fail equally at
    // prepared restore and actual process-style seal/reopen, before publication.
    let bad = existing_plan(bad_root).map_err(|_| "bad envelope")?;
    Service::persist_record_batch(
        service.durable.as_mut().ok_or("durable")?,
        &bad,
        "schema-spoof-fixture",
    )?;
    let durable = service.durable.as_ref().ok_or("durable")?;
    let before = durable.export_backup()?;
    let generation = durable.generation();
    let files = artifacts(&service)?;
    assert_eq!(
        service
            .prepare_snapshot_restore(&before)
            .err()
            .ok_or("restore gate")?
            .status,
        400
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(artifacts(&service)?, files);
    drop(service);
    let mut service = directory.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        503
    );
    assert!(service.state.is_none());
    // Durable open authenticates/rebuilds the encrypted replay ledger before
    // application-schema admission. Its fresh AEAD nonce may change ledger.hbl;
    // rejection must leave the authoritative state and journal bytes unchanged.
    assert_eq!(artifacts(&service)?[..2], files[..2]);
    Ok(())
}
