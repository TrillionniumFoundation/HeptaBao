//! Real source-session and authenticated registered-slot catalog. This lower
//! fixture grants no retained Raft roots, typed union or deletion permission.
use super::*;

fn inspect(owner: &mut Owner) -> Result<BTreeSet<String>, ServiceError> {
    let (session, conditions) = source(owner)?;
    owner.inspect_native_ha_local_resources(&session, &conditions, &mut gate)
}

#[test]
fn native_ha_local_catalog_actual_source_is_readonly_and_rejects_stale_foreign_or_incomplete_conditions()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-local-catalog-sources")?;
    add_object(&mut owner)?;
    let bytes = owner.backend.load()?;
    let blobs = blob_inventory(&root.0)?;
    assert_eq!(inspect(&mut owner)?, BTreeSet::from([OBJECT.to_owned()]));
    assert_eq!(owner.backend.load()?, bytes);
    assert_eq!(blob_inventory(&root.0)?, blobs);
    let (session, mut conditions) = source(&mut owner)?;
    let denied = owner.inspect_native_ha_local_resources(&session, &conditions, &mut || {
        Err(ServiceError::BarrierFailure)
    });
    assert!(matches!(denied, Err(ServiceError::BarrierFailure)));
    conditions.pop();
    assert!(matches!(
        owner.inspect_native_ha_local_resources(&session, &conditions, &mut gate),
        Err(ServiceError::InvalidResource)
    ));
    drop(session);
    let (stale, conditions) = source(&mut owner)?;
    owner.put(PutRequest::new(
        "intent-fixture",
        "system",
        "advance-local-catalog",
        "outside-native-selectors",
        [5; 32],
        Secret::new(b"new exact generation".to_vec())?,
    )?)?;
    let advanced = owner.backend.load()?;
    assert!(matches!(
        owner.inspect_native_ha_local_resources(&stale, &conditions, &mut gate),
        Err(ServiceError::PublicationConditionConflict)
    ));
    drop(stale);
    let (_other_root, mut other) = fixture("ha-local-catalog-other")?;
    add_object(&mut other)?;
    let (foreign, conditions) = source(&mut other)?;
    assert!(matches!(
        owner.inspect_native_ha_local_resources(&foreign, &conditions, &mut gate),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert_eq!(owner.backend.load()?, advanced);
    assert_eq!(blob_inventory(&root.0)?, blobs);
    assert_eq!(inspect(&mut owner)?, BTreeSet::from([OBJECT.to_owned()]));
    assert_eq!(owner.backend.load()?, advanced);
    Ok(())
}

#[test]
fn native_ha_local_catalog_unknown_selector_duplicate_locator_and_foreign_store_hold_without_mutation()
-> TestResult {
    let _serial = serial_test();
    for case in 0..3 {
        let (root, mut owner) = fixture(&format!("ha-local-catalog-malformed-{case}"))?;
        add_object(&mut owner)?;
        if case == 0 {
            owner.put(PutRequest::new(
                "intent-fixture",
                "system",
                "unknown-side-selector",
                "state-native-v6/unrecognized-historical-root",
                [5; 32],
                Secret::new(b"authenticated but unclassified selector".to_vec())?,
            )?)?;
        } else if case == 1 {
            let same = owner.get("system", OBJECT)?.ok_or("registered slot")?;
            let alias = OBJECT.replace("/kv2/", "/kv1/");
            owner.put(PutRequest::new(
                "intent-fixture",
                "system",
                "duplicate-slot-locator",
                &alias,
                [5; 32],
                same,
            )?)?;
        }
        let before = owner.backend.load()?;
        let blobs = blob_inventory(&root.0)?;
        let result = if case == 2 {
            let current = owner.get("system", "state")?.ok_or("root")?;
            let session =
                owner.immutable_source_session("system", "state", current.expose(), [0x79; 16])?;
            let (_, conditions) = source(&mut owner)?;
            owner.inspect_native_ha_local_resources(&session, &conditions, &mut gate)
        } else {
            inspect(&mut owner)
        };
        assert!(matches!(
            result,
            Err(ServiceError::UnsupportedProfile | ServiceError::CorruptState)
        ));
        assert_eq!(owner.backend.load()?, before);
        assert_eq!(blob_inventory(&root.0)?, blobs);
        assert_eq!(registered_bytes(&mut owner)?, OBJECT_BYTES);
    }
    Ok(())
}
