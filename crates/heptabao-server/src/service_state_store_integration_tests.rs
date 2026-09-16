use super::state_store::{self, STATE_CHUNK_BYTES};
use super::tests::{Root, bootstrap, call};
use super::*;

fn current_manifest(
    service: &Service,
) -> Result<state_store::StateManifest, Box<dyn std::error::Error>> {
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    let record = durable
        .get("system", "state")?
        .ok_or("state record unavailable")?;
    state_store::decode_manifest(record.expose())?
        .ok_or_else(|| "state record is not a manifest".into())
}

#[test]
fn state_larger_than_legacy_limit_round_trips_through_manifest_chunks_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let payload = "x".repeat(900 * 1024);
    let response = call(
        &mut service,
        "PUT",
        "secret/data/large",
        &token,
        json!({"data":{"blob":payload}}),
    );
    assert_eq!(response.status, 200, "{}", response.body);

    let manifest = current_manifest(&service)?;
    assert!(manifest.chunk_count() >= 2);
    assert_eq!(manifest.state_schema(), CURRENT_STATE_SCHEMA);
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    assert_eq!(durable.retained_request_count(), 2);
    assert_eq!(durable.generation(), 2);
    for index in 0..manifest.chunk_count() {
        let resource = manifest.chunk_resource(index)?;
        let chunk = durable
            .get("system", &resource)?
            .ok_or("manifest referenced a missing chunk")?;
        if index + 1 < manifest.chunk_count() {
            assert_eq!(chunk.expose().len(), STATE_CHUNK_BYTES);
        }
    }

    drop(service);
    let mut service = root.service()?;
    let unseal = call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}));
    assert_eq!(unseal.status, 200, "{}", unseal.body);
    let read = call(&mut service, "GET", "secret/data/large", &token, json!({}));
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(
        read.body["data"]["data"]["blob"].as_str().map(str::len),
        Some(900 * 1024)
    );
    Ok(())
}

#[test]
fn legacy_raw_state_is_eagerly_migrated_to_manifest_in_one_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let state = service.state.as_ref().ok_or("state unavailable")?.clone();
    let bytes = serde_json::to_vec(&state)?;
    let durable = service
        .durable
        .as_mut()
        .ok_or("durable store unavailable")?;
    let raw = PutRequest::new(
        "legacy-migration-test",
        "system",
        "legacy-state-record",
        "state",
        crypto::digest(&bytes),
        Secret::new(bytes.clone())?,
    )?;
    durable.put(raw)?;
    let raw_generation = durable.generation();
    assert!(
        state_store::decode_manifest(
            durable
                .get("system", "state")?
                .ok_or("raw state missing")?
                .expose(),
        )?
        .is_none()
    );
    drop(service);

    let mut service = root.service()?;
    let unseal = call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}));
    assert_eq!(unseal.status, 200, "{}", unseal.body);
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    assert_eq!(durable.generation(), raw_generation + 1);
    assert_eq!(durable.retained_request_count(), 3);
    let manifest = current_manifest(&service)?;
    assert_eq!(manifest.slot(), 0);
    let health = call(&mut service, "GET", "sys/health", "", json!({}));
    assert_eq!(health.status, 200);
    let lookup = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(lookup.status, 200, "{}", lookup.body);
    Ok(())
}

#[test]
fn tampered_or_missing_manifest_chunk_fails_unseal_closed() -> Result<(), Box<dyn std::error::Error>>
{
    for missing in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, _) = bootstrap(&mut service)?;
        let manifest = current_manifest(&service)?;
        let resource = manifest.chunk_resource(0)?;
        let durable = service
            .durable
            .as_mut()
            .ok_or("durable store unavailable")?;
        let mutation = if missing {
            (resource, None)
        } else {
            (
                resource,
                Some(Secret::new(b"tampered-state-chunk".to_vec())?),
            )
        };
        durable.apply_batch(
            "state-corruption-test",
            "system",
            if missing {
                "missing-chunk"
            } else {
                "tampered-chunk"
            },
            [91; 32],
            vec![mutation],
        )?;
        drop(service);

        let mut service = root.service()?;
        let unseal = call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}));
        assert_eq!(unseal.status, 503, "missing={missing}: {}", unseal.body);
        assert!(service.state.is_none());
        assert!(service.durable.is_none());
    }
    Ok(())
}

#[test]
fn state_commits_alternate_slots_and_survive_restart() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(current_manifest(&service)?.slot(), 0);

    let first = call(
        &mut service,
        "PUT",
        "secret/data/first",
        &token,
        json!({"data":{"value":"one"}}),
    );
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(current_manifest(&service)?.slot(), 1);

    let second = call(
        &mut service,
        "PUT",
        "secret/data/second",
        &token,
        json!({"data":{"value":"two"}}),
    );
    assert_eq!(second.status, 200, "{}", second.body);
    assert_eq!(current_manifest(&service)?.slot(), 0);
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    assert_eq!(durable.generation(), 3);
    assert_eq!(durable.retained_request_count(), 3);
    drop(service);

    let mut service = root.service()?;
    let unseal = call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}));
    assert_eq!(unseal.status, 200, "{}", unseal.body);
    for (path, value) in [("secret/data/first", "one"), ("secret/data/second", "two")] {
        let read = call(&mut service, "GET", path, &token, json!({}));
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(read.body["data"]["data"]["value"], value);
    }
    Ok(())
}
