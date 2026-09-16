use super::tests::{Root, bootstrap};
use super::*;

fn response_ok<T>(result: Result<T, Response>) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|response| {
        std::io::Error::other(format!(
            "service response {}: {}",
            response.status, response.body
        ))
        .into()
    })
}

#[test]
fn legacy_state_upgrades_to_manifest_on_next_local_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let _ = bootstrap(&mut service)?;
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    let legacy = durable
        .get("system", "state")?
        .ok_or("legacy state missing")?;
    assert!(state_store::decode_manifest(legacy.expose())?.is_none());

    let state = serde_json::to_vec(service.state.as_ref().ok_or("state missing")?)?;
    response_ok(service.persist_local(&state, "upgrade-state-format"))?;
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    let pointer = durable
        .get("system", "state")?
        .ok_or("state pointer missing")?;
    let manifest = state_store::decode_manifest(pointer.expose())?.ok_or("manifest missing")?;
    assert_eq!(manifest.state_schema(), CURRENT_STATE_SCHEMA);
    assert_eq!(manifest.slot(), 0);
    assert_eq!(
        response_ok(Service::load_state_bytes_from_durable(durable))?.as_slice(),
        state
    );
    Ok(())
}

#[test]
fn multi_chunk_state_round_trips_and_alternates_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let _ = bootstrap(&mut service)?;
    let first = vec![0x41_u8; state_store::STATE_CHUNK_BYTES + 31];
    response_ok(service.persist_local(&first, "large-state-one"))?;
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    let first_pointer = durable
        .get("system", "state")?
        .ok_or("first pointer missing")?;
    let first_manifest =
        state_store::decode_manifest(first_pointer.expose())?.ok_or("first manifest missing")?;
    assert_eq!(first_manifest.slot(), 0);
    assert_eq!(
        response_ok(Service::load_state_bytes_from_durable(durable))?.as_slice(),
        first
    );

    let second = vec![0x42_u8; state_store::STATE_CHUNK_BYTES + 47];
    response_ok(service.persist_local(&second, "large-state-two"))?;
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    let second_pointer = durable
        .get("system", "state")?
        .ok_or("second pointer missing")?;
    let second_manifest =
        state_store::decode_manifest(second_pointer.expose())?.ok_or("second manifest missing")?;
    assert_eq!(second_manifest.slot(), 1);
    assert_eq!(
        response_ok(Service::load_state_bytes_from_durable(durable))?.as_slice(),
        second
    );
    assert_eq!(
        durable.list("system", "state-chunks")?,
        vec!["0/".to_owned(), "1/".to_owned()]
    );
    Ok(())
}

#[test]
fn chunked_commit_preflights_all_required_replay_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let _ = bootstrap(&mut service)?;
    let bytes = vec![0x33_u8; state_store::STATE_CHUNK_BYTES + 1];
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    let pointer = durable
        .get("system", "state")?
        .ok_or("state pointer missing")?;
    let slot = state_store::next_slot(pointer.expose())?;
    let plan = state_store::StateWritePlan::new(&bytes, "slot-budget", CURRENT_STATE_SCHEMA, slot)?;
    assert_eq!(plan.required_operations(), 3);
    durable.preflight_new_identities(plan.required_operations())?;
    Ok(())
}
