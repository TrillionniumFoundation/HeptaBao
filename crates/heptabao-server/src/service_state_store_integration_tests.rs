use super::owner_store::{self, STATE_STORAGE_FORMAT};
use super::tests::{Root, bootstrap, call};
use super::*;

fn current_manifest(
    service: &Service,
) -> Result<owner_store::OwnerStateManifest, Box<dyn std::error::Error>> {
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    let record = durable
        .get("system", "state")?
        .ok_or("state record unavailable")?;
    owner_store::decode_manifest(record.expose())?
        .ok_or_else(|| "state record is not an owner manifest".into())
}

// The retained V4 publication path is still used by lifecycle/provider owners
// before the ordinary-dispatch migration boundary. Exercise it explicitly;
// V5 HTTP publication and unchanged-owner reuse have separate Service tests.
fn legacy_owner_write(
    service: &mut Service,
    path: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    assert!(service.record_root.is_none());
    let mut state = service.state.clone().ok_or("state")?;
    let mut response = state
        .engines
        .handle("", "PUT", path, &body, 100)?
        .ok_or("engine route")?;
    service
        .commit_state(&state)
        .map_err(|_| "legacy owner commit")?;
    service.state = Some(state);
    Ok(Response {
        status: response.status,
        body: std::mem::take(&mut response.body),
    })
}

#[test]
fn large_engine_owner_round_trips_through_owner_chunks_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let payload = "x".repeat(900 * 1024);
    let response = legacy_owner_write(
        &mut service,
        "secret/data/large",
        json!({"data":{"blob":payload}}),
    )?;
    assert_eq!(response.status, 200, "{}", response.body);

    let manifest = current_manifest(&service)?;
    assert!(manifest.chunk_count("engines")? >= 2);
    assert_eq!(manifest.state_schema(), CURRENT_STATE_SCHEMA);
    assert_eq!(manifest.storage_format(), STATE_STORAGE_FORMAT);
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    assert_eq!(durable.retained_request_count(), 2);
    assert_eq!(durable.generation(), 2);
    for index in 0..manifest.chunk_count("engines")? {
        let resource = manifest.chunk_resource("engines", index)?;
        let chunk = durable
            .get("system", &resource)?
            .ok_or("manifest referenced a missing engine chunk")?;
        if index + 1 < manifest.chunk_count("engines")? {
            assert!((384 * 1024..=768 * 1024).contains(&chunk.expose().len()));
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
fn legacy_raw_state_is_eagerly_migrated_to_owner_manifest_in_one_generation()
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
        owner_store::decode_manifest(
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
    assert_eq!(manifest.storage_format(), STATE_STORAGE_FORMAT);
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
fn tampered_or_missing_owner_chunk_fails_unseal_closed() -> Result<(), Box<dyn std::error::Error>> {
    for missing in [false, true] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, _) = bootstrap(&mut service)?;
        let manifest = current_manifest(&service)?;
        let resource = manifest.chunk_resource("auth", 0)?;
        let durable = service
            .durable
            .as_mut()
            .ok_or("durable store unavailable")?;
        let mutation = if missing {
            (resource, None)
        } else {
            (
                resource,
                Some(Secret::new(b"tampered-owner-chunk".to_vec())?),
            )
        };
        durable.apply_batch(
            "state-corruption-test",
            "system",
            if missing {
                "missing-owner"
            } else {
                "tampered-owner"
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
fn owner_commits_reuse_unchanged_owners_retire_replaced_chunks_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let original = current_manifest(&service)?;
    assert_eq!(original.storage_format(), STATE_STORAGE_FORMAT);
    let original_all = original.unique_chunk_resources()?;
    let original_auth = (0..original.chunk_count("auth")?)
        .map(|index| original.chunk_resource("auth", index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;

    let first = legacy_owner_write(
        &mut service,
        "secret/data/first",
        json!({"data":{"value":"one"}}),
    )?;
    assert_eq!(first.status, 200, "{}", first.body);
    let after_first = current_manifest(&service)?;
    let after_first_auth = (0..after_first.chunk_count("auth")?)
        .map(|index| after_first.chunk_resource("auth", index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    assert_eq!(
        original_auth, after_first_auth,
        "KV mutation must not rewrite the unchanged auth owner"
    );

    let first_all = after_first.unique_chunk_resources()?;
    let second = legacy_owner_write(
        &mut service,
        "secret/data/second",
        json!({"data":{"value":"two"}}),
    )?;
    assert_eq!(second.status, 200, "{}", second.body);
    let final_manifest = current_manifest(&service)?;
    let final_all = final_manifest.unique_chunk_resources()?;
    let durable = service
        .durable
        .as_ref()
        .ok_or("durable store unavailable")?;
    for old in original_all.union(&first_all) {
        if !final_all.contains(old) {
            assert!(
                durable.get("system", old)?.is_none(),
                "retired owner chunk remains reachable"
            );
        }
    }
    for current in &final_all {
        assert!(
            durable.get("system", current)?.is_some(),
            "published owner chunk missing"
        );
    }
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

#[test]
fn large_unchanged_owner_bounds_v4_write_set_to_changed_owner()
-> Result<(), Box<dyn std::error::Error>> {
    // This is deliberately larger than the legacy 768 KiB value ceiling.  It
    // exercises the V4 owner plan directly so the assertion is about the
    // durable mutation set, rather than a small end-to-end happy path.
    let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
    let large_owner = |byte, size| vec![byte; size];
    let first = owner_store::OwnerWritePlan::new(
        logical,
        "owner-write-set-1",
        9,
        "cluster",
        0,
        vec![
            ("namespaces", large_owner(b'n', 512 * 1024)),
            ("auth", large_owner(b'a', 2 * 1024 * 1024)),
            ("engines", large_owner(b'e', 8 * 1024 * 1024)),
            ("database", large_owner(b'd', 2 * 1024 * 1024)),
            ("raft_admin", large_owner(b'r', 2 * 1024 * 1024)),
        ],
        None,
        Vec::new(),
    )?;
    let previous = owner_store::decode_manifest(&first.manifest_bytes)?
        .ok_or("initial owner manifest missing")?;
    let mut unchanged = std::collections::BTreeSet::new();
    for owner in ["namespaces", "engines", "database", "raft_admin"] {
        for index in 0..previous.chunk_count(owner)? {
            unchanged.insert(previous.chunk_resource(owner, index)?);
        }
    }
    let previous_auth = (0..previous.chunk_count("auth")?)
        .map(|index| previous.chunk_resource("auth", index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;

    // Only auth changes.  Use a byte pattern that cannot reuse the previous
    // auth chunks, so every new/retired physical mutation is attributable to
    // that owner and no hidden whole-state rewrite can satisfy the test.
    let second = owner_store::OwnerWritePlan::new_with_reuse(
        logical,
        "owner-write-set-2",
        9,
        "cluster",
        0,
        vec![
            ("namespaces", None),
            (
                "auth",
                Some(Zeroizing::new(large_owner(b'z', 2 * 1024 * 1024))),
            ),
            ("engines", None),
            ("database", None),
            ("raft_admin", None),
        ],
        Some(&previous),
        Vec::new(),
    )?;

    let added = second
        .chunks
        .iter()
        .map(|chunk| chunk.resource.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!added.is_empty());
    assert!(
        added
            .iter()
            .all(|resource| resource.starts_with("state-owners/auth/"))
    );
    assert!(
        second
            .deletes
            .iter()
            .all(|resource| previous_auth.contains(resource))
    );
    assert_eq!(second.deletes.len(), previous_auth.len());
    let reused = second
        .required_existing
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert!(unchanged.iter().all(|resource| reused.contains(resource)));
    assert!(
        reused
            .iter()
            .all(|resource| { unchanged.contains(*resource) || previous_auth.contains(*resource) })
    );

    let next = owner_store::decode_manifest(&second.manifest_bytes)?
        .ok_or("next owner manifest missing")?;
    let next_auth = (0..next.chunk_count("auth")?)
        .map(|index| next.chunk_resource("auth", index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    assert_eq!(next_auth.len(), added.len());
    assert_eq!(
        second.required_mutations(),
        second.chunks.len() + second.deletes.len() + 1,
        "owner publication mutation accounting must include only staged chunks, retired chunks and manifest"
    );
    assert!(
        second.required_mutations() <= previous_auth.len() + next_auth.len() + 1,
        "single-owner V4 mutation set exceeded the changed owner's old/new chunk bound"
    );
    Ok(())
}

#[test]
fn v3_state_chunks_are_retired_atomically_by_retained_v4_owner_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let state = service.state.as_ref().ok_or("state unavailable")?.clone();
    let bytes = serde_json::to_vec(&state)?;
    let old =
        state_store::StateWritePlan::new(&bytes, "synthetic-v3-downgrade", state.schema, None)?;
    let old_manifest =
        state_store::decode_manifest(&old.manifest_bytes)?.ok_or("v3 manifest missing")?;
    let old_resources = old_manifest.unique_chunk_resources()?;
    let owner_resources = current_manifest(&service)?.unique_chunk_resources()?;
    let durable = service
        .durable
        .as_mut()
        .ok_or("durable store unavailable")?;
    let mut mutations = old
        .chunks
        .into_iter()
        .map(|chunk| Ok((chunk.resource, Some(Secret::new(chunk.bytes)?))))
        .collect::<Result<Vec<_>, ServiceError>>()?;
    for resource in owner_resources {
        mutations.push((resource, None));
    }
    mutations.push(("state".to_owned(), Some(Secret::new(old.manifest_bytes)?)));
    durable.apply_batch(
        "synthetic-v3",
        "system",
        "install-v3",
        crypto::digest(&bytes),
        mutations,
    )?;
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let write = legacy_owner_write(
        &mut service,
        "secret/data/promote-v4",
        json!({"data":{"value":"v4"}}),
    )?;
    assert_eq!(write.status, 200, "{}", write.body);
    let durable = service.durable.as_ref().ok_or("durable missing")?;
    for old in old_resources {
        assert!(
            durable.get("system", &old)?.is_none(),
            "legacy V3 chunk survived V4 publication"
        );
    }
    assert_eq!(
        current_manifest(&service)?.storage_format(),
        STATE_STORAGE_FORMAT
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/promote-v4",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "v4"
    );
    Ok(())
}
