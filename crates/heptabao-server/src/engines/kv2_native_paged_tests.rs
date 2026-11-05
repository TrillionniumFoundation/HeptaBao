use super::*;
use std::cell::Cell;

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "",
        mount: "secret/",
        incarnation: 7,
    }
}
fn time() -> CodecResult<Timestamp> {
    Timestamp::whole(100).map_err(|_| RecordError::Invalid)
}
fn owner() -> CodecResult<Kv2> {
    let mut owner = Kv2::default();
    owner
        .handle_precise("POST", "config", &json!({"max_versions":4}), time()?)
        .map_err(|_| RecordError::Invalid)?;
    for number in 1..=3 {
        owner
            .handle_precise(
                "POST",
                "data/history",
                &json!({"data":{"n":number,"body":"x".repeat(600_000)},"options":{"cas":number-1}}),
                time()?,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    Ok(owner)
}
fn objects(graph: &NativeCellGraph) -> CodecResult<GraphObjects> {
    let mut source = GraphObjects::default();
    graph.visit_objects(
        |object| {
            source.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        },
        &|| Ok(()),
    )?;
    Ok(source)
}
struct Counting<'a> {
    source: &'a GraphObjects,
    payloads: BTreeSet<ObjectId>,
    blocks: Cell<usize>,
}
fn payload_ids(graph: &NativeCellGraph) -> BTreeSet<ObjectId> {
    graph
        .0
        .paged
        .as_ref()
        .map(|p| {
            p.descriptors
                .values()
                .flat_map(BTreeMap::values)
                .flat_map(|d| d.blocks.iter().map(|r| r.id))
                .collect()
        })
        .unwrap_or_default()
}
impl RecordReader for Counting<'_> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        if self.payloads.contains(&reference.id) {
            self.blocks.set(self.blocks.get() + 1);
        }
        self.source.read_object(reference)
    }
}

#[test]
fn paged_cold_metadata_retains_no_payload_and_point_read_opens_only_one_version() -> CodecResult<()>
{
    let key = AddressKey::from_bytes([19; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    assert_eq!(graph.graph_format(), PAGED_NATIVE_FORMAT);
    assert!(graph.logical_payload_bytes()? > 1_800_000);
    assert!(
        graph
            .root()
            .reference
            .as_ref()
            .ok_or(RecordError::Missing)?
            .payload_bytes
            < 32_000
    );
    let source = objects(&graph)?;
    let counted = Counting {
        source: &source,
        payloads: payload_ids(&graph),
        blocks: Cell::new(0),
    };
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &counted)?;
    assert_eq!(counted.blocks.get(), 0);
    assert!(
        view.owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none())
    );
    let response = view
        .read_with_source(
            "GET",
            "data/history",
            &json!({"version":1}),
            time()?,
            &counted,
        )
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["data"]["n"], 1);
    assert_eq!(counted.blocks.get(), 3);
    assert!(
        view.owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none())
    );
    view.verify_paged_payloads(&counted, &|| Ok(()))?;
    assert_eq!(counted.blocks.get(), 12);
    Ok(())
}

#[test]
fn paged_actual_cas_delete_destroy_and_new_blocks_preserve_unselected_history() -> CodecResult<()> {
    let key = AddressKey::from_bytes([21; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    let mut source = objects(&graph)?;
    let mut view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    assert!(
        view.mutate(
            "POST",
            "data/history",
            &json!({"data":{"v":"no"},"options":{"cas":2}}),
            time()?
        )
        .is_err()
    );
    view.mutate("POST", "destroy/history", &json!({"versions":[2]}), time()?)
        .map_err(|_| RecordError::Corrupt)?;
    view.mutate(
        "POST",
        "data/history",
        &json!({"data":{"v":"new"},"options":{"cas":3}}),
        time()?,
    )
    .map_err(|_| RecordError::Corrupt)?;
    view.validate_paged_candidate()?;
    let next = view.encode_paged(&key, scope(), &|| Ok(()))?;
    let mut new_blocks = 0;
    next.visit_objects(
        |object| {
            if next
                .0
                .paged
                .as_ref()
                .is_some_and(|p| p.new_blocks.contains_key(&object.reference().id))
            {
                new_blocks += 1;
            }
            source.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        },
        &|| Ok(()),
    )?;
    assert_eq!(new_blocks, 1);
    let cold = NativeReadView::open_paged(&key, scope(), next.root(), &source)?;
    cold.verify_paged_payloads(&source, &|| Ok(()))?;
    assert_eq!(
        cold.read_with_source(
            "GET",
            "data/history",
            &json!({"version":1}),
            time()?,
            &source
        )
        .map_err(|_| RecordError::Corrupt)?
        .body["data"]["data"]["n"],
        1
    );
    assert_eq!(
        cold.read_with_source(
            "GET",
            "data/history",
            &json!({"version":2}),
            time()?,
            &source
        )
        .map_err(|_| RecordError::Corrupt)?
        .status,
        404
    );
    assert_eq!(
        cold.read_with_source("GET", "data/history", &json!({}), time()?, &source)
            .map_err(|_| RecordError::Corrupt)?
            .body["data"]["data"]["v"],
        "new"
    );
    Ok(())
}

#[test]
fn paged_patch_hydrates_current_only_and_rejects_wrong_chunk_or_descriptor() -> CodecResult<()> {
    let key = AddressKey::from_bytes([23; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let counted = Counting {
        source: &source,
        payloads: payload_ids(&graph),
        blocks: Cell::new(0),
    };
    let mut view = NativeReadView::open_paged(&key, scope(), graph.root(), &counted)?;
    view.hydrate_current_for_patch("data/history", &counted)
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(counted.blocks.get(), 3);
    view.mutate(
        "PATCH",
        "data/history",
        &json!({"data":{"n":9},"options":{"cas":3}}),
        time()?,
    )
    .map_err(|_| RecordError::Corrupt)?;
    view.clear_hydrated_payloads()
        .map_err(|_| RecordError::Corrupt)?;
    assert!(
        view.owner
            .entries
            .get("history")
            .ok_or(RecordError::Missing)?
            .versions
            .get(&3)
            .ok_or(RecordError::Missing)?
            .data
            .is_none()
    );
    assert!(
        view.owner
            .entries
            .get("history")
            .ok_or(RecordError::Missing)?
            .versions
            .get(&4)
            .ok_or(RecordError::Missing)?
            .data
            .is_some()
    );
    let next = view.encode_paged(&key, scope(), &|| Ok(()))?;
    assert!(next.logical_payload_bytes()? > graph.logical_payload_bytes()?);
    let native = view.graph.as_ref().ok_or(RecordError::Corrupt)?;
    let original = native
        .paged
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .descriptors
        .get("history")
        .and_then(|values| values.get(&1))
        .ok_or(RecordError::Missing)?;
    let mut bad = original.clone();
    bad.version = 2;
    assert!(bad.validate(&native.key, "history", 1).is_err());
    let mut altered = original.clone();
    altered.digest[0] ^= 1;
    assert!(
        altered
            .read(&native.key, "history", 1, &source, &|| Ok(()))
            .is_err()
    );
    let other_key = AddressKey::from_bytes([24; 32]);
    assert!(
        original
            .read(&other_key, "history", 1, &source, &|| Ok(()))
            .is_err()
    );
    Ok(())
}

fn transition_fixture() -> CodecResult<(NativeReadView, NativeReadView, GraphObjects)> {
    let key = AddressKey::from_bytes([25; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    let mut source = objects(&graph)?;
    let prior = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    // Model the caller's prior full cold admission; this helper cannot mint it.
    prior.verify_paged_payloads(&source, &|| Ok(()))?;
    let mut next = prior.clone();
    next.mutate(
        "POST",
        "data/history",
        &json!({"data":{"n":4,"body":"z".repeat(700_000)},"options":{"cas":3}}),
        time()?,
    )
    .map_err(|_| RecordError::Corrupt)?;
    let next = next.encode_paged(&key, scope(), &|| Ok(()))?;
    let staged = GraphObjects(
        next.0
            .paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .new_blocks
            .clone(),
    );
    source.0.extend(objects(&next)?.0);
    let candidate = NativeReadView::open_paged(&key, scope(), next.root(), &source)?;
    Ok((prior, candidate, staged))
}

#[test]
fn paged_cloned_snapshots_isolate_both_writers_and_keep_actual_source_checks() -> CodecResult<()> {
    let key = AddressKey::from_bytes([79; 32]);
    let initial = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    let mut source = objects(&initial)?;
    let snapshot = NativeReadView::open_paged(&key, scope(), initial.root(), &source)?;
    let mut append = snapshot.clone();
    let mut destroy = snapshot.clone();
    append
        .mutate(
            "POST",
            "data/history",
            &json!({"data":{"n":4,"branch":"append"},"options":{"cas":3}}),
            time()?,
        )
        .map_err(|_| RecordError::Corrupt)?;
    destroy
        .mutate("POST", "destroy/history", &json!({"versions":[1]}), time()?)
        .map_err(|_| RecordError::Corrupt)?;
    let appended = append.encode_paged(&key, scope(), &|| Ok(()))?;
    let destroyed = destroy.encode_paged(&key, scope(), &|| Ok(()))?;
    source.0.extend(objects(&appended)?.0);
    source.0.extend(objects(&destroyed)?.0);
    let appended = NativeReadView::open_paged(&key, scope(), appended.root(), &source)?;
    let destroyed = NativeReadView::open_paged(&key, scope(), destroyed.root(), &source)?;

    assert!(snapshot.matches_authenticated_root(&key, scope(), &initial.root(), &|| Ok(()))?);
    for view in [&snapshot, &appended] {
        let read = view
            .read_with_source(
                "GET",
                "data/history",
                &json!({"version":1}),
                time()?,
                &source,
            )
            .map_err(|_| RecordError::Corrupt)?;
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["data"]["n"], 1);
    }
    let deleted = destroyed
        .read_with_source(
            "GET",
            "data/history",
            &json!({"version":1}),
            time()?,
            &source,
        )
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(deleted.status, 404);
    assert!(deleted.body["data"]["metadata"]["destroyed"] == true);
    assert_eq!(snapshot.owner.entries["history"].current_version, 3);
    assert_eq!(appended.owner.entries["history"].current_version, 4);
    assert_eq!(destroyed.owner.entries["history"].current_version, 3);

    // Shared decoded data never replaces the actual selected payload source.
    let missing = *payload_ids(&initial)
        .iter()
        .next()
        .ok_or(RecordError::Missing)?;
    source.0.remove(&missing).ok_or(RecordError::Missing)?;
    assert!(snapshot.verify_paged_payloads(&source, &|| Ok(())).is_err());
    assert!(appended.verify_paged_payloads(&source, &|| Ok(())).is_err());
    Ok(())
}

fn view_payload_ids(view: &NativeReadView) -> CodecResult<BTreeSet<ObjectId>> {
    Ok(view
        .graph
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .paged
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .descriptors
        .values()
        .flat_map(BTreeMap::values)
        .flat_map(|descriptor| descriptor.blocks.iter().map(|reference| reference.id))
        .collect())
}

#[test]
fn paged_transition_reuses_old_closure_without_old_reads_and_verifies_new_blocks() -> CodecResult<()>
{
    let (prior, candidate, staged) = transition_fixture()?;
    let empty = GraphObjects::default();
    let old_counted = Counting {
        source: &empty,
        payloads: view_payload_ids(&prior)?,
        blocks: Cell::new(0),
    };
    prior.verify_paged_transition(Some(&prior), &old_counted, &|| Ok(()))?;
    assert_eq!(old_counted.blocks.get(), 0);
    let counted = Counting {
        source: &staged,
        payloads: view_payload_ids(&candidate)?,
        blocks: Cell::new(0),
    };
    candidate.verify_paged_transition(Some(&prior), &counted, &|| Ok(()))?;
    assert_eq!(counted.blocks.get(), 3);
    assert!(
        candidate
            .verify_paged_transition(None, &staged, &|| Ok(()))
            .is_err()
    );
    assert!(
        candidate
            .owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none())
    );
    Ok(())
}

#[test]
fn paged_transition_missing_new_block_rejects_without_prior_fallback() -> CodecResult<()> {
    let (prior, candidate, mut staged) = transition_fixture()?;
    let first = candidate
        .graph
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .paged
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .descriptors
        .get("history")
        .and_then(|versions| versions.get(&4))
        .and_then(|descriptor| descriptor.blocks.first())
        .ok_or(RecordError::Missing)?
        .id;
    assert!(staged.0.remove(&first).is_some());
    assert!(
        candidate
            .verify_paged_transition(Some(&prior), &staged, &|| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn paged_transition_changed_staged_block_rejects_typed_address_mismatch() -> CodecResult<()> {
    let (prior, candidate, mut staged) = transition_fixture()?;
    let graph = candidate.graph.as_ref().ok_or(RecordError::Corrupt)?;
    let reference = graph
        .paged
        .as_ref()
        .ok_or(RecordError::Corrupt)?
        .descriptors
        .get("history")
        .and_then(|versions| versions.get(&4))
        .and_then(|descriptor| descriptor.blocks.first())
        .ok_or(RecordError::Missing)?;
    let replacement =
        StagedObject::payload_block(&graph.key, &vec![b'q'; reference.payload_bytes as usize])?;
    // The source returns a valid same-domain block at the requested slot, but
    // its authenticated typed address differs from the candidate descriptor.
    staged.0.insert(reference.id, replacement);
    assert!(
        candidate
            .verify_paged_transition(Some(&prior), &staged, &|| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn paged_transition_changed_old_digest_never_inherits_prior_closure() -> CodecResult<()> {
    let (prior, mut candidate, staged) = transition_fixture()?;
    let descriptor = candidate
        .graph
        .as_mut()
        .ok_or(RecordError::Corrupt)?
        .paged
        .as_mut()
        .ok_or(RecordError::Corrupt)?
        .descriptors
        .get_mut("history")
        .and_then(|versions| versions.get_mut(&1))
        .ok_or(RecordError::Missing)?;
    descriptor.digest[0] ^= 1;
    assert!(
        candidate
            .verify_paged_transition(Some(&prior), &staged, &|| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn paged_transition_prior_scope_or_graph_key_mismatch_rejects_before_payload_read()
-> CodecResult<()> {
    let (prior, _, _) = transition_fixture()?;
    for (parent, incarnation) in [([26; 32], 7), ([25; 32], 8)] {
        let parent = AddressKey::from_bytes(parent);
        let different = NativeScope {
            incarnation,
            ..scope()
        };
        let graph = NativeCellGraph::encode_paged(&owner()?, &parent, different, &|| Ok(()))?;
        let source = objects(&graph)?;
        let candidate = NativeReadView::open_paged(
            &parent,
            NativeScope {
                incarnation,
                ..scope()
            },
            graph.root(),
            &source,
        )?;
        let empty = GraphObjects::default();
        let counted = Counting {
            source: &empty,
            payloads: view_payload_ids(&candidate)?,
            blocks: Cell::new(0),
        };
        assert!(
            candidate
                .verify_paged_transition(Some(&prior), &counted, &|| Ok(()))
                .is_err()
        );
        assert_eq!(counted.blocks.get(), 0);
    }
    Ok(())
}

#[test]
fn paged_transition_initial_admission_reads_entire_staged_closure_and_retains_checks()
-> CodecResult<()> {
    let key = AddressKey::from_bytes([27; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let candidate = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let counted = Counting {
        source: &source,
        payloads: view_payload_ids(&candidate)?,
        blocks: Cell::new(0),
    };
    candidate.verify_paged_transition(None, &counted, &|| Ok(()))?;
    assert_eq!(counted.blocks.get(), 9);
    counted.blocks.set(0);
    assert!(
        candidate
            .verify_paged_transition(None, &counted, &|| Err(RecordError::Invalid))
            .is_err()
    );
    assert_eq!(counted.blocks.get(), 0);
    Ok(())
}

#[test]
fn paged_transition_reused_closure_cannot_drop_prior_lossless_floor() -> CodecResult<()> {
    let key = AddressKey::from_bytes([28; 32]);
    let mut original = owner()?;
    original.lossless_format = Some(1);
    let graph = NativeCellGraph::encode_paged(&original, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let prior = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    prior.verify_paged_payloads(&source, &|| Ok(()))?;
    let mut candidate = prior.clone();
    // A prior admitted format flag is sticky when its payloads are inherited;
    // metadata-only candidate validation cannot inspect their numeric grammar.
    candidate.owner.lossless_format = None;
    assert!(
        candidate
            .verify_paged_transition(Some(&prior), &GraphObjects::default(), &|| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn precise_history_clock_same_second_delete_destroy_and_cold_reopen_boundaries() -> CodecResult<()>
{
    // Build actual paged records through the existing KV mutation and cold-open
    // paths. These explicit clocks exercise read semantics without any sleeps.
    let key = AddressKey::from_bytes([29; 32]);
    let mut original = owner()?;
    let deletion = Timestamp::checked(100, 418_352_420).map_err(|_| RecordError::Invalid)?;
    original
        .handle_precise("POST", "delete/history", &json!({"versions":[2]}), deletion)
        .map_err(|_| RecordError::Invalid)?;
    original
        .handle_precise(
            "POST",
            "destroy/history",
            &json!({"versions":[1]}),
            deletion,
        )
        .map_err(|_| RecordError::Invalid)?;
    let graph = NativeCellGraph::encode_paged(&original, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let counted = Counting {
        source: &source,
        payloads: payload_ids(&graph),
        blocks: Cell::new(0),
    };
    let cold = NativeReadView::open_paged(&key, scope(), graph.root(), &counted)?;
    assert_eq!(counted.blocks.get(), 0);
    for (wall, expected_deleted_status) in [
        (std::time::Duration::new(100, 0), 200),
        (std::time::Duration::new(100, 418_352_419), 200),
        (std::time::Duration::new(100, 418_352_420), 404),
        (std::time::Duration::new(100, 418_352_421), 404),
        (std::time::Duration::new(100, 883_013_756), 404),
        (std::time::Duration::new(101, 0), 404),
    ] {
        // The same conversion as the repaired HA fixture retains nanoseconds.
        // The deliberately whole-second row is a positive reproduction control.
        let now = Timestamp::from_wall(wall).map_err(|_| RecordError::Invalid)?;
        counted.blocks.set(0);
        let soft_deleted = cold
            .read_with_source("GET", "data/history", &json!({"version":2}), now, &counted)
            .map_err(|_| RecordError::Corrupt)?;
        assert_eq!(
            soft_deleted.status, expected_deleted_status,
            "soft deletion must use the complete supplied timestamp at {wall:?}",
        );
        if expected_deleted_status == 200 {
            assert_eq!(soft_deleted.body["data"]["data"]["n"], 2);
            assert!(counted.blocks.get() > 0);
        } else {
            assert_eq!(counted.blocks.get(), 0, "deleted data must not be opened");
        }
        counted.blocks.set(0);
        let destroyed = cold
            .read_with_source("GET", "data/history", &json!({"version":1}), now, &counted)
            .map_err(|_| RecordError::Corrupt)?;
        assert_eq!(destroyed.status, 404, "destroy is independent of read time");
        assert_eq!(counted.blocks.get(), 0, "destroyed data must not be opened");
        counted.blocks.set(0);
        let retained = cold
            .read_with_source("GET", "data/history", &json!({"version":3}), now, &counted)
            .map_err(|_| RecordError::Corrupt)?;
        assert_eq!(retained.status, 200);
        assert_eq!(retained.body["data"]["data"]["n"], 3);
        assert!(counted.blocks.get() > 0);
    }
    assert!(
        cold.owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none()),
        "point reads must leave the cold metadata owner without retained payloads",
    );
    Ok(())
}

#[test]
fn paged_transition_memo_keeps_prior_custody_and_fresh_changed_reads() -> CodecResult<()> {
    let (prior, candidate, staged) = transition_fixture()?;
    let memo = RefCell::new(PagedPayloadValidationMemo::default());
    let counted = Counting {
        source: &staged,
        payloads: view_payload_ids(&candidate)?,
        blocks: Cell::new(0),
    };
    candidate.verify_paged_transition_with_memo(Some(&prior), &counted, &|| Ok(()), Some(&memo))?;
    assert_eq!(counted.blocks.get(), 3);
    assert_eq!(memo.borrow().test_observations(), (1, 0));
    candidate.verify_paged_transition_with_memo(Some(&prior), &counted, &|| Ok(()), Some(&memo))?;
    assert_eq!(
        counted.blocks.get(),
        6,
        "a hit still reads every changed block"
    );
    assert_eq!(memo.borrow().test_observations(), (1, 1));
    assert!(
        candidate
            .verify_paged_transition_with_memo(
                Some(&prior),
                &GraphObjects::default(),
                &|| Ok(()),
                Some(&memo)
            )
            .is_err(),
        "a warm semantic fact cannot replace the actual staged source"
    );
    assert!(
        candidate
            .verify_paged_transition_with_memo(None, &staged, &|| Ok(()), Some(&memo))
            .is_err(),
        "a warm semantic fact cannot create the missing admitted prior closure"
    );
    assert_eq!(memo.borrow().test_observations(), (1, 1));
    Ok(())
}
