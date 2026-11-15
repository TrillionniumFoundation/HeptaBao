use super::*;
use std::cell::Cell;

fn fixture(key_byte: u8, data: Value) -> CodecResult<(NativeReadView, GraphObjects)> {
    let key = AddressKey::from_bytes([key_byte; 32]);
    let scope = NativeScope {
        namespace: "",
        mount: "secret/",
        incarnation: 7,
    };
    let mut owner = Kv2::default();
    owner
        .handle_precise(
            "POST",
            "data/history",
            &json!({"data": data}),
            Timestamp::whole(100).map_err(|_| RecordError::Invalid)?,
        )
        .map_err(|_| RecordError::Invalid)?;
    owner.lossless_format = Some(1);
    let graph = NativeCellGraph::encode_paged(&owner, &key, scope, &|| Ok(()))?;
    let mut source = GraphObjects::default();
    graph.visit_objects(
        |object| {
            source.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        },
        &|| Ok(()),
    )?;
    let view = NativeReadView::open_paged(&key, scope, graph.root(), &source)?;
    Ok((view, source))
}

struct ObservedReader<'a> {
    source: &'a GraphObjects,
    calls: Cell<usize>,
    corrupt: bool,
    revoke_after_read: Option<&'a Cell<bool>>,
}
impl RecordReader for ObservedReader<'_> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        let mut bytes = self.source.read_object(reference)?;
        if self.corrupt {
            let byte = bytes
                .get_mut(OBJECT_HEADER_BYTES)
                .ok_or(RecordError::Missing)?;
            *byte ^= 1;
        }
        if let Some(revoked) = self.revoke_after_read {
            revoked.set(true);
        }
        Ok(bytes)
    }
}

#[test]
fn payload_validation_memo_hits_still_read_every_actual_block_and_reject_corruption()
-> CodecResult<()> {
    let (view, source) = fixture(61, json!({"body": "x".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    let actual = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: None,
    };
    view.verify_paged_payloads_with_memo(&actual, &|| Ok(()), Some(&memo))?;
    let first_reads = actual.calls.get();
    assert!(first_reads > 1);
    assert_eq!(memo.borrow().hits, 0);
    assert_eq!(memo.borrow().needs_lossless.len(), 1);
    view.verify_paged_payloads_with_memo(&actual, &|| Ok(()), Some(&memo))?;
    assert_eq!(actual.calls.get(), 2 * first_reads);
    assert_eq!(memo.borrow().hits, 1);

    let corrupt = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: true,
        revoke_after_read: None,
    };
    assert!(
        view.verify_paged_payloads_with_memo(&corrupt, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(corrupt.calls.get(), 1);
    assert_eq!(memo.borrow().hits, 1);
    assert!(
        view.verify_paged_payloads_with_memo(&GraphObjects::default(), &|| Ok(()), Some(&memo),)
            .is_err()
    );
    Ok(())
}

#[test]
fn payload_validation_memo_cannot_cover_original_gate_loss_or_format_change() -> CodecResult<()> {
    let (view, source) = fixture(62, json!({"body": "y".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    let revoked = Cell::new(false);
    let actual = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: Some(&revoked),
    };
    assert!(
        view.verify_paged_payloads_with_memo(
            &actual,
            &|| if revoked.get() {
                Err(RecordError::Invalid)
            } else {
                Ok(())
            },
            Some(&memo),
        )
        .is_err()
    );
    assert_eq!(actual.calls.get(), 1);
    assert_eq!(memo.borrow().hits, 0);

    let mut changed = view.clone();
    changed.graph.as_mut().ok_or(RecordError::Missing)?.format = "other-graph-format".into();
    assert!(
        changed
            .verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    let mut changed = view.clone();
    changed
        .graph
        .as_mut()
        .and_then(|graph| graph.paged.as_mut())
        .and_then(|paged| paged.descriptors.values_mut().next())
        .and_then(|versions| versions.values_mut().next())
        .ok_or(RecordError::Missing)?
        .format = "other-payload-format".into();
    assert!(
        changed
            .verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(memo.borrow().hits, 0);
    Ok(())
}

#[test]
fn payload_validation_memo_binds_scoped_key_and_rechecks_current_lossless_floor() -> CodecResult<()>
{
    let data: Value = serde_json::from_str(r#"{"n":1.0000000000000000000000000000000000001}"#)
        .map_err(|_| RecordError::Corrupt)?;
    assert!(lossless::needs_lossless_number_format(&data));
    let (mut view, source) = fixture(63, data.clone())?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    let (other_key, other_source) = fixture(64, data)?;
    other_key.verify_paged_payloads_with_memo(&other_source, &|| Ok(()), Some(&memo))?;
    assert_eq!(memo.borrow().needs_lossless.len(), 2);
    assert_eq!(memo.borrow().hits, 0);
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    assert_eq!(memo.borrow().hits, 1);
    view.owner.lossless_format = None;
    assert!(
        view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(memo.borrow().hits, 2);
    Ok(())
}

// Exercise the same hostile readers and authority changes at the earlier
// detached transition boundary, where the plan now first learns semantics.
#[test]
fn payload_validation_transition_memo_hits_still_read_every_actual_block_and_reject_corruption()
-> CodecResult<()> {
    let (view, source) = fixture(61, json!({"body": "x".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    let actual = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: None,
    };
    view.verify_paged_transition_with_memo(None, &actual, &|| Ok(()), Some(&memo))?;
    let first_reads = actual.calls.get();
    assert!(first_reads > 1);
    assert_eq!(memo.borrow().hits, 0);
    assert_eq!(memo.borrow().needs_lossless.len(), 1);
    view.verify_paged_transition_with_memo(None, &actual, &|| Ok(()), Some(&memo))?;
    assert_eq!(actual.calls.get(), 2 * first_reads);
    assert_eq!(memo.borrow().hits, 1);

    let corrupt = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: true,
        revoke_after_read: None,
    };
    assert!(
        view.verify_paged_transition_with_memo(None, &corrupt, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(corrupt.calls.get(), 1);
    assert_eq!(memo.borrow().hits, 1);
    assert!(
        view.verify_paged_transition_with_memo(
            None,
            &GraphObjects::default(),
            &|| Ok(()),
            Some(&memo),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn payload_validation_transition_memo_cannot_cover_original_gate_loss_or_format_change()
-> CodecResult<()> {
    let (view, source) = fixture(62, json!({"body": "y".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))?;
    let revoked = Cell::new(false);
    let actual = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: Some(&revoked),
    };
    assert!(
        view.verify_paged_transition_with_memo(
            None,
            &actual,
            &|| if revoked.get() {
                Err(RecordError::Invalid)
            } else {
                Ok(())
            },
            Some(&memo),
        )
        .is_err()
    );
    assert_eq!(actual.calls.get(), 1);
    assert_eq!(memo.borrow().hits, 0);

    let mut changed = view.clone();
    changed.graph.as_mut().ok_or(RecordError::Missing)?.format = "other-graph-format".into();
    assert!(
        changed
            .verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    let mut changed = view.clone();
    changed
        .graph
        .as_mut()
        .and_then(|graph| graph.paged.as_mut())
        .and_then(|paged| paged.descriptors.values_mut().next())
        .and_then(|versions| versions.values_mut().next())
        .ok_or(RecordError::Missing)?
        .format = "other-payload-format".into();
    assert!(
        changed
            .verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(memo.borrow().hits, 0);
    Ok(())
}

#[test]
fn payload_validation_transition_memo_binds_scoped_key_and_rechecks_current_lossless_floor()
-> CodecResult<()> {
    let data: Value = serde_json::from_str(r#"{"n":1.0000000000000000000000000000000000001}"#)
        .map_err(|_| RecordError::Corrupt)?;
    assert!(lossless::needs_lossless_number_format(&data));
    let (mut view, source) = fixture(63, data.clone())?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))?;
    let (other_key, other_source) = fixture(64, data)?;
    other_key.verify_paged_transition_with_memo(None, &other_source, &|| Ok(()), Some(&memo))?;
    assert_eq!(memo.borrow().needs_lossless.len(), 2);
    assert_eq!(memo.borrow().hits, 0);
    view.verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))?;
    assert_eq!(memo.borrow().hits, 1);
    view.owner.lossless_format = None;
    assert!(
        view.verify_paged_transition_with_memo(None, &source, &|| Ok(()), Some(&memo))
            .is_err()
    );
    assert_eq!(memo.borrow().hits, 2);
    Ok(())
}

fn first_payload_descriptor(
    view: &NativeReadView,
) -> CodecResult<(&AddressKey, &PayloadDescriptor)> {
    let graph = view.graph.as_ref().ok_or(RecordError::Missing)?;
    let descriptor = graph
        .paged
        .as_ref()
        .and_then(|paged| paged.descriptors.get("history"))
        .and_then(|versions| versions.get(&1))
        .ok_or(RecordError::Missing)?;
    Ok((&graph.key, descriptor))
}

#[test]
fn payload_validation_streamed_hit_rejects_other_fully_keyed_blocks_by_complete_payload_mac()
-> CodecResult<()> {
    let (view, source) = fixture(65, json!({"body": "x".repeat(600_000)}))?;
    let (other_view, other_source) = fixture(65, json!({"body": "y".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    let (key, original) = first_payload_descriptor(&view)?;
    let (_, other) = first_payload_descriptor(&other_view)?;
    assert_eq!(original.logical_bytes, other.logical_bytes);
    let mut substituted = original.clone();
    substituted.blocks = other.blocks.clone();
    // Every replacement block has a valid keyed ObjectRef under this key.
    // The memo key is unchanged, so only the fresh whole-payload MAC can
    // establish that these actual bytes do not match the prior semantics.
    substituted.validate(key, "history", 1)?;
    let actual = ObservedReader {
        source: &other_source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: None,
    };
    assert!(matches!(
        substituted.verify_semantics(key, "history", 1, &actual, &|| Ok(()), &memo),
        Err(RecordError::Corrupt)
    ));
    assert_eq!(actual.calls.get(), substituted.blocks.len());
    assert_eq!(memo.borrow().test_observations(), (1, 0));
    Ok(())
}

#[test]
fn payload_validation_stream_rejects_descriptor_length_mismatch_with_warm_memo() -> CodecResult<()>
{
    let (view, source) = fixture(66, json!({"body": "z".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    let (key, original) = first_payload_descriptor(&view)?;
    let mut changed = original.clone();
    changed.logical_bytes -= 1;
    let actual = ObservedReader {
        source: &source,
        calls: Cell::new(0),
        corrupt: false,
        revoke_after_read: None,
    };
    assert!(matches!(
        changed.verify_semantics(key, "history", 1, &actual, &|| Ok(()), &memo),
        Err(RecordError::Corrupt)
    ));
    assert_eq!(actual.calls.get(), 0);
    assert_eq!(memo.borrow().test_observations(), (1, 0));
    Ok(())
}

#[test]
fn payload_validation_streamed_hit_rejects_memo_entry_replaced_during_actual_read()
-> CodecResult<()> {
    struct ReplacingReader<'a> {
        source: &'a GraphObjects,
        memo: &'a RefCell<PagedPayloadValidationMemo>,
        calls: Cell<usize>,
    }
    impl RecordReader for ReplacingReader<'_> {
        fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
            self.calls.set(self.calls.get() + 1);
            let actual = self.source.read_object(reference)?;
            self.memo
                .try_borrow_mut()
                .map_err(|_| RecordError::Invalid)?
                .needs_lossless
                .clear();
            Ok(actual)
        }
    }
    let (view, source) = fixture(67, json!({"body": "q".repeat(600_000)}))?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    view.verify_paged_payloads_with_memo(&source, &|| Ok(()), Some(&memo))?;
    let (key, descriptor) = first_payload_descriptor(&view)?;
    let actual = ReplacingReader {
        source: &source,
        memo: &memo,
        calls: Cell::new(0),
    };
    assert!(matches!(
        descriptor.verify_semantics(key, "history", 1, &actual, &|| Ok(()), &memo),
        Err(RecordError::Invalid)
    ));
    assert_eq!(actual.calls.get(), descriptor.blocks.len());
    assert_eq!(memo.borrow().test_observations(), (0, 0));
    Ok(())
}
