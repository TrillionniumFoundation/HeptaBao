use super::*;
use crate::records::RecordCommand;
use crate::state_machine::{ApplicationRequest, RecordRequest};

pub(crate) fn block(id: u8) -> SealedRecordObject {
    SealedRecordObject::new(
        RecordObjectRef {
            id: [id; 32],
            kind: RecordObjectKind::Block,
            encoded_bytes: 29,
            record_count: 0,
            payload_bytes: 4,
        },
        vec![],
        vec![id; 62],
    )
    .expect("bounded synthetic sealed block")
}
pub(crate) fn owner(id: u8) -> SealedRecordObject {
    SealedRecordObject::new(
        RecordObjectRef {
            id: [id; 32],
            kind: RecordObjectKind::OwnerChunk,
            encoded_bytes: 29,
            record_count: 0,
            payload_bytes: 4,
        },
        vec![],
        vec![id; 62],
    )
    .expect("owner")
}
fn value(id: u8, block: &SealedRecordObject) -> SealedRecordObject {
    SealedRecordObject::new(
        RecordObjectRef {
            id: [id; 32],
            kind: RecordObjectKind::Value,
            encoded_bytes: 80,
            record_count: 1,
            payload_bytes: 4,
        },
        vec![block.reference().clone()],
        vec![id; 113],
    )
    .expect("value")
}
pub(crate) fn root(
    base: RecordRootBase,
    id: u8,
    refs: Vec<RecordObjectRef>,
) -> PublishedRecordRoot {
    PublishedRecordRoot::new(
        base,
        ReplicatedEnvelope::new("root", [id; 32], vec![id; 100]).expect("envelope"),
        refs,
    )
    .expect("published root")
}
fn apply(state: &mut StateMachine, command: RecordCommand) -> Result<(), RecordRejection> {
    state
        .apply(&ApplicationRequest::records(1, command).expect("bounded command"))
        .result()
}
fn bytes(state: &StateMachine) -> Vec<u8> {
    serde_json::to_vec(state).expect("state encoding")
}

#[test]
fn stage_child_first_exact_immutability_and_no_partial_publication() {
    let mut state = StateMachine::default();
    let b = block(1);
    let v = value(2, &b);
    assert_eq!(
        apply(&mut state, RecordCommand::Stage { object: v.clone() }),
        Err(RecordRejection::MissingDependency)
    );
    assert!(state.records_v5.is_none());
    apply(&mut state, RecordCommand::Stage { object: b.clone() }).expect("stage child");
    let before = bytes(&state);
    apply(&mut state, RecordCommand::Stage { object: b.clone() }).expect("idempotent stage");
    assert_eq!(bytes(&state), before);
    let changed = SealedRecordObject::new(b.reference().clone(), vec![], vec![9; 62])
        .expect("different valid ciphertext");
    assert_eq!(
        apply(&mut state, RecordCommand::Stage { object: changed }),
        Err(RecordRejection::ImmutableConflict)
    );
    assert_eq!(bytes(&state), before);
    apply(&mut state, RecordCommand::Stage { object: v }).expect("stage parent");
    assert!(
        state
            .records_v5
            .as_ref()
            .expect("records")
            .published()
            .is_none()
    );
    let missing = owner(4);
    let publish = root(RecordRootBase::Empty, 5, vec![missing.reference().clone()]);
    let before = bytes(&state);
    assert_eq!(
        apply(&mut state, RecordCommand::Publish { root: publish }),
        Err(RecordRejection::MissingDependency)
    );
    assert_eq!(bytes(&state), before);
}

#[test]
fn publish_cas_fences_legacy_and_prune_protects_current_root() {
    let mut state = StateMachine::default();
    let a = owner(1);
    let b = owner(2);
    for object in [&a, &b] {
        apply(
            &mut state,
            RecordCommand::Stage {
                object: object.clone(),
            },
        )
        .expect("stage");
    }
    let first = root(RecordRootBase::Empty, 3, vec![a.reference().clone()]);
    apply(
        &mut state,
        RecordCommand::Publish {
            root: first.clone(),
        },
    )
    .expect("first publish");
    apply(&mut state, RecordCommand::Publish { root: first }).expect("retry exact publication");
    let before = bytes(&state);
    assert_eq!(
        apply(
            &mut state,
            RecordCommand::Publish {
                root: root(RecordRootBase::Empty, 4, vec![b.reference().clone()])
            }
        ),
        Err(RecordRejection::StaleRoot)
    );
    assert_eq!(bytes(&state), before);
    assert_eq!(
        state
            .apply(
                &openraft_memstore::ClientRequest {
                    client: crate::records::PRODUCTION_CLIENT.into(),
                    serial: 1,
                    status: "bypass".into()
                }
                .into()
            )
            .result(),
        Err(RecordRejection::LegacyFenced)
    );
    assert_eq!(bytes(&state), before);
    assert_eq!(
        apply(
            &mut state,
            RecordCommand::Prune {
                expected_root: [3; 32],
                ids: vec![a.reference().id]
            }
        ),
        Err(RecordRejection::Reachable)
    );
    assert_eq!(bytes(&state), before);
    assert_eq!(
        apply(
            &mut state,
            RecordCommand::Prune {
                expected_root: [0; 32],
                ids: vec![b.reference().id]
            }
        ),
        Err(RecordRejection::StaleRoot)
    );
    apply(
        &mut state,
        RecordCommand::Publish {
            root: root(
                RecordRootBase::RecordsV5([3; 32]),
                4,
                vec![b.reference().clone()],
            ),
        },
    )
    .expect("CAS update");
    apply(
        &mut state,
        RecordCommand::Prune {
            expected_root: [4; 32],
            ids: vec![a.reference().id],
        },
    )
    .expect("prune retired root");
    assert!(
        state
            .records_v5
            .as_ref()
            .expect("records")
            .object(a.reference())
            .expect("lookup")
            .is_none()
    );
    assert!(
        state
            .records_v5
            .as_ref()
            .expect("records")
            .object(b.reference())
            .expect("lookup")
            .is_some()
    );
}

#[test]
fn unpublished_gc_is_parent_first_and_zero_cas_cannot_cross_publication() {
    let mut state = StateMachine::default();
    let b = block(1);
    let v = value(2, &b);
    // A real legacy manifest can coexist with failed migration staging.
    let legacy = ReplicatedEnvelope::new("legacy", [8; 32], vec![1]).expect("legacy envelope");
    state
        .apply(
            &openraft_memstore::ClientRequest {
                client: crate::records::PRODUCTION_CLIENT.into(),
                serial: 1,
                status: legacy.encoded_status(),
            }
            .into(),
        )
        .result()
        .expect("legacy");
    for object in [&b, &v] {
        apply(
            &mut state,
            RecordCommand::Stage {
                object: object.clone(),
            },
        )
        .expect("stage");
    }
    assert_eq!(
        state
            .records_v5
            .as_ref()
            .expect("records")
            .prunable(256)
            .expect("candidates"),
        vec![v.reference().id]
    );
    assert_eq!(
        apply(
            &mut state,
            RecordCommand::Prune {
                expected_root: [0; 32],
                ids: vec![b.reference().id]
            }
        ),
        Err(RecordRejection::ReferencedByStaged)
    );
    apply(
        &mut state,
        RecordCommand::Prune {
            expected_root: [0; 32],
            ids: vec![v.reference().id],
        },
    )
    .expect("parent first");
    apply(
        &mut state,
        RecordCommand::Prune {
            expected_root: [0; 32],
            ids: vec![b.reference().id],
        },
    )
    .expect("then child");
    apply(
        &mut state,
        RecordCommand::Publish {
            root: root(RecordRootBase::Legacy([8; 32]), 9, vec![]),
        },
    )
    .expect("migrate exact legacy root");
    assert_eq!(
        apply(
            &mut state,
            RecordCommand::Prune {
                expected_root: [0; 32],
                ids: vec![[10; 32]]
            }
        ),
        Err(RecordRejection::StaleRoot)
    );
}

#[test]
fn typed_wire_fences_old_decoders_and_preserves_legacy_shapes() {
    let legacy = openraft_memstore::ClientRequest {
        client: "legacy".into(),
        serial: 3,
        status: "value".into(),
    };
    let old = serde_json::to_vec(&legacy).expect("old request");
    let own: ApplicationRequest = serde_json::from_slice(&old).expect("new reads old");
    assert_eq!(serde_json::to_vec(&own).expect("same encoding"), old);
    let typed = ApplicationRequest::records(4, RecordCommand::Stage { object: owner(1) })
        .expect("typed request");
    let wire = serde_json::to_vec(&typed).expect("wire");
    assert!(serde_json::from_slice::<openraft_memstore::ClientRequest>(&wire).is_err());
    let mut state = StateMachine::default();
    state.apply(&own).result().expect("legacy state");
    let old_snapshot = state.snapshot_bytes().expect("old snapshot");
    assert!(
        serde_json::from_slice::<openraft_memstore::MemStoreStateMachine>(&old_snapshot).is_ok()
    );
    state.apply(&typed).result().expect("stage");
    let new_snapshot = state.snapshot_bytes().expect("new snapshot");
    assert!(
        serde_json::from_slice::<openraft_memstore::MemStoreStateMachine>(&new_snapshot).is_err()
    );
    assert_eq!(
        StateMachine::from_snapshot(&new_snapshot)
            .expect("new restore")
            .snapshot_bytes()
            .expect("encode"),
        new_snapshot
    );
    assert!(
        StateMachine::from_snapshot(&bytes(&state)).is_err(),
        "typed state without version wrapper must fail"
    );
}

#[test]
fn malformed_graph_base64_and_aggregate_are_rejected_on_restore() {
    let mut state = StateMachine::default();
    let b = block(1);
    let v = value(2, &b);
    for object in [&b, &v] {
        apply(
            &mut state,
            RecordCommand::Stage {
                object: object.clone(),
            },
        )
        .expect("stage");
    }
    let original: serde_json::Value =
        serde_json::from_slice(&state.snapshot_bytes().expect("snapshot")).expect("json");
    let id = |id: u8| format!("{id:02x}").repeat(32);
    for kind in 0..4 {
        let mut damaged = original.clone();
        let objects = &mut damaged["state"]["records_v5"]["objects"];
        match kind {
            0 => {
                objects.as_object_mut().expect("map").remove(&id(1));
            }
            1 => objects[id(1)]["sealed"] = serde_json::json!("AQ=="),
            2 => objects[id(2)]["reference"]["payload_bytes"] = serde_json::json!(8),
            _ => objects[id(2)]["children"][0]["encoded_bytes"] = serde_json::json!(30),
        }
        assert!(
            StateMachine::from_snapshot(&serde_json::to_vec(&damaged).expect("damaged")).is_err()
        );
    }
}

#[test]
fn semantic_invalid_command_does_not_change_state_and_encoded_budget_counts_legacy() {
    let mut state = StateMachine::default();
    let invalid = ApplicationRequest::RecordsV5(RecordRequest {
        serial: 0,
        records_v5: RecordCommand::Stage { object: owner(1) },
    });
    let before = bytes(&state);
    assert_eq!(
        state.apply(&invalid).result(),
        Err(RecordRejection::Invalid)
    );
    assert_eq!(bytes(&state), before);
    state
        .client_status
        .insert("old-chunks".into(), "x".repeat(47 * 1024 * 1024));
    let before = bytes(&state);
    assert_eq!(
        apply(&mut state, RecordCommand::Stage { object: owner(1) }),
        Err(RecordRejection::Budget)
    );
    assert_eq!(bytes(&state), before);
    assert!(state.records_v5.is_none());
}

#[test]
fn cached_usage_and_bounded_inventory_track_only_actual_changes() {
    let mut state = StateMachine::default();
    let initial = state.record_usage().expect("initial");
    let a = owner(1);
    let b = owner(2);
    for object in [&a, &b] {
        apply(
            &mut state,
            RecordCommand::Stage {
                object: object.clone(),
            },
        )
        .expect("stage");
    }
    let usage = state.record_usage().expect("usage");
    assert_eq!(usage.object_count, 2);
    assert!(usage.encoded_bytes > initial.encoded_bytes);
    apply(&mut state, RecordCommand::Stage { object: a.clone() }).expect("retry");
    assert_eq!(state.record_usage().expect("same usage"), usage);
    let records = state.records_v5.as_ref().expect("records");
    assert_eq!(
        records.inventory(None, 1).expect("page"),
        vec![a.reference().clone()]
    );
    assert_eq!(
        records.inventory(Some(a.reference().id), 1).expect("after"),
        vec![b.reference().clone()]
    );
    assert!(records.inventory(None, 257).is_err());
    apply(
        &mut state,
        RecordCommand::Prune {
            expected_root: [0; 32],
            ids: vec![a.reference().id, b.reference().id],
        },
    )
    .expect("remove");
    assert_eq!(state.record_usage().expect("empty").object_count, 0);
}

#[test]
fn object_shape_and_ciphertext_bounds_keep_real_proposals_within_transport_capacity() {
    let reference = RecordObjectRef {
        id: [1; 32],
        kind: RecordObjectKind::Block,
        encoded_bytes: 256 * 1024 + 25,
        record_count: 0,
        payload_bytes: 256 * 1024,
    };
    let block = SealedRecordObject::new(
        reference.clone(),
        vec![],
        vec![1; reference.encoded_bytes as usize + 33],
    )
    .expect("largest production block");
    let request =
        ApplicationRequest::records(1, RecordCommand::Stage { object: block }).expect("proposal");
    assert!(
        serde_json::to_vec(&request)
            .expect("encoded proposal")
            .len()
            < 512 * 1024
    );
    assert!(
        SealedRecordObject::new(
            reference.clone(),
            vec![],
            vec![1; reference.encoded_bytes as usize + 257]
        )
        .is_err()
    );
    let mut bad = reference;
    bad.record_count = 1;
    assert!(SealedRecordObject::new(bad, vec![], vec![1]).is_err());
    let b = owner(2);
    let invalid_value = RecordObjectRef {
        id: [3; 32],
        kind: RecordObjectKind::Value,
        encoded_bytes: 80,
        record_count: 1,
        payload_bytes: 4,
    };
    assert!(
        SealedRecordObject::new(invalid_value, vec![b.reference().clone()], vec![1]).is_err(),
        "value cannot reference owner chunks"
    );
}
