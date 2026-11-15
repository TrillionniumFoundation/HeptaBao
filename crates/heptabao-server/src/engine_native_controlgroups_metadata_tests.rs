//! The native CG format witness must not absorb unrelated opaque metadata.
use super::*;
use crate::state_records::{AddressKey, ObjectId, StagedObject};
use std::collections::BTreeMap;
use std::sync::Arc;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Objects(BTreeMap<ObjectId, Arc<StagedObject>>);

impl RecordReader for Objects {
    fn read_object(
        &self,
        reference: &ObjectRef,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, RecordError> {
        let object = self.0.get(&reference.id).ok_or(RecordError::Missing)?;
        if object.reference() != reference {
            return Err(RecordError::Corrupt);
        }
        Ok(Zeroizing::new(object.bytes().to_vec()))
    }
}

// Build an actual empty paged graph and run its first precise data mutation.
// No fabricated graph owner or pre-existing business record grants the witness.
fn first_precise_write() -> TestResult<(EngineState, EngineState)> {
    let mut source = EngineState::initialized_empty();
    let mounted = source
        .handle(
            "",
            "POST",
            "sys/mounts/secret",
            &json!({"type":"kv","options":{"version":"2"}}),
            100,
        )?
        .ok_or("KV2 mount response")?;
    assert_eq!(mounted.status, 204);
    let parent = AddressKey::from_bytes([91; 32]);
    let mut objects = Objects(BTreeMap::new());
    let (_, graphs) = source.project_v6_native_paged(&parent, &|| Ok(()), |_, object| {
        objects.0.insert(object.reference().id, Arc::clone(object));
        Ok(())
    })?;
    assert_eq!(graphs.len(), 1);
    let graph = &graphs[0];
    let view = NativeReadView::open_paged(
        &parent,
        graph.scope.borrowed(),
        graph.root.clone(),
        &objects,
    )?;
    assert!(!view.has_lossless_state());
    source
        .namespaces
        .get_mut("")
        .ok_or("root namespace")?
        .mounts
        .get_mut("secret/")
        .ok_or("KV2 mount")?
        .backend = Backend::Kv2Native(view);
    assert_eq!(source.kv2_lossless_format, None);
    let mut candidate = source.clone();
    let response = candidate.dispatch_native_paged(
        "",
        "POST",
        "secret/data/cg/key",
        &json!({"options":{"cas":0},"data":{"value":"first"}}),
        crate::auth::Timestamp::checked(101, 17)?,
        |_, reference| objects.read_object(reference),
    )?;
    assert_eq!(response.status, 200);
    assert_eq!(candidate.kv2_lossless_format, Some(1));
    assert_eq!(
        source.native_cg_metadata_transition(&candidate, "secret/data/cg/key", &|| true),
        Some(true),
        "the actual first precise mutation must produce the bounded witness",
    );
    Ok((source, candidate))
}

#[test]
fn native_cg_metadata_transition_rejects_other_engine_metadata_drift() -> TestResult {
    let (source, candidate) = first_precise_write()?;
    let mut changed = candidate.clone();
    changed.lease_clock = 1;
    assert_eq!(
        source.native_cg_metadata_transition(&changed, "secret/data/cg/key", &|| true),
        None,
        "a valid format promotion must not carry another engine clock",
    );
    let mut changed = candidate.clone();
    changed
        .namespaces
        .get_mut("")
        .ok_or("root namespace")?
        .mounts
        .get_mut("secret/")
        .ok_or("KV2 mount")?
        .description
        .push_str(" unauthorized drift");
    assert_eq!(
        source.native_cg_metadata_transition(&changed, "secret/data/cg/key", &|| true),
        None,
        "unchanged mount binding must not hide opaque mount metadata drift",
    );
    let mut changed = candidate.clone();
    changed.ensure_empty_namespace("unrelated/");
    assert_eq!(
        source.native_cg_metadata_transition(&changed, "secret/data/cg/key", &|| true),
        None,
        "a valid format promotion must not create another namespace owner",
    );
    assert_eq!(
        source.native_cg_metadata_transition(&candidate, "secret/data/cg/key", &|| false),
        None,
        "the proof cannot outlive its original deadline",
    );
    Ok(())
}

#[test]
fn native_cg_metadata_transition_rejects_format_regression_and_unwitnessed_upgrade() -> TestResult {
    let (source, candidate) = first_precise_write()?;
    let mut reversed = candidate.clone();
    reversed.kv2_lossless_format = None;
    assert_eq!(
        candidate.native_cg_metadata_transition(&reversed, "secret/data/cg/key", &|| true),
        None,
        "a persisted precise format marker must never be removed",
    );
    let mut changed = candidate.clone();
    changed.kv2_lossless_format = Some(2);
    for prior in [&source, &candidate] {
        assert_eq!(
            prior.native_cg_metadata_transition(&changed, "secret/data/cg/key", &|| true),
            None,
            "only the exact supported format can be promoted",
        );
    }
    let mut unwitnessed = source.clone();
    unwitnessed.kv2_lossless_format = Some(1);
    assert_eq!(
        source.native_cg_metadata_transition(&unwitnessed, "secret/data/cg/key", &|| true),
        None,
        "setting the flag without a real precise target mutation is insufficient",
    );
    assert_eq!(
        candidate.native_cg_metadata_transition(&candidate, "secret/data/cg/key", &|| true),
        Some(false),
        "an unchanged existing precise marker does not grant engine mutation",
    );
    Ok(())
}
