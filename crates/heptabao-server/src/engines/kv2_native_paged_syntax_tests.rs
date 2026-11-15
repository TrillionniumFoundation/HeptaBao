use super::*;
use std::cell::{Cell, RefCell};

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "",
        mount: "syntax/",
        incarnation: 17,
    }
}
fn owner() -> CodecResult<Kv2> {
    let mut owner = Kv2::default();
    let at = Timestamp::checked(100, 113).map_err(|_| RecordError::Invalid)?;
    for n in 1..=2 {
        owner
            .handle_precise(
                "POST",
                "data/path",
                &json!({"data":{"n":n},"options":{"cas":n-1}}),
                at,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    Ok(owner)
}
fn fixture(
    owner: &Kv2,
    key: &AddressKey,
) -> CodecResult<(NativeCellGraph, GraphObjects, NativeReadView)> {
    let graph = NativeCellGraph::encode_paged(owner, key, scope(), &|| Ok(()))?;
    let mut objects = GraphObjects::default();
    graph.visit_objects(
        |o| {
            objects.0.insert(o.reference().id, Arc::clone(o));
            Ok(())
        },
        &|| Ok(()),
    )?;
    let view = NativeReadView::open_paged(key, scope(), graph.root(), &objects)?;
    Ok((graph, objects, view))
}
struct Reads<'a> {
    source: &'a GraphObjects,
    ids: RefCell<Vec<ObjectId>>,
}
impl RecordReader for Reads<'_> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        self.ids.borrow_mut().push(reference.id);
        self.source.read_object(reference)
    }
}

#[test]
fn same_syntax_still_reads_every_object_and_runs_every_original_gate() -> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    let (graph, source, original) = fixture(&owner()?, &key)?;
    let hint = original
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let baseline = Reads {
        source: &source,
        ids: RefCell::new(Vec::new()),
    };
    let counted = Reads {
        source: &source,
        ids: RefCell::new(Vec::new()),
    };
    let calls_a = Cell::new(0);
    let calls_b = Cell::new(0);
    let plain =
        NativeReadView::open_paged_checked(&key, scope(), graph.root(), &baseline, &|| {
            calls_a.set(calls_a.get() + 1);
            Ok(())
        })?;
    let reused = NativeReadView::open_paged_with_syntax(
        &key,
        scope(),
        graph.root(),
        &counted,
        &|| {
            calls_b.set(calls_b.get() + 1);
            Ok(())
        },
        Some(&hint),
    )?;
    assert!(!baseline.ids.borrow().is_empty());
    assert_eq!(*baseline.ids.borrow(), *counted.ids.borrow());
    assert_eq!(calls_a.get(), calls_b.get());
    assert_eq!(
        serialize(&plain.owner, MAX_GRAPH_BYTES)?,
        serialize(&reused.owner, MAX_GRAPH_BYTES)?
    );
    let metadata = metadata_key(&hint.scope, &hint.key, "path")?;
    assert!(Arc::ptr_eq(
        &reused.owner.entries["path"].0,
        &hint.paths[&metadata].metadata.0
    ));
    assert!(!Arc::ptr_eq(
        &plain.owner.entries["path"].0,
        &hint.paths[&metadata].metadata.0
    ));
    Ok(())
}

#[test]
fn changed_authenticated_cells_use_original_decode_and_incomplete_bytes_are_refused()
-> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    let (_, _, original) = fixture(&owner()?, &key)?;
    let hint = original
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let mut changed = owner()?;
    changed
        .entries
        .get_mut("path")
        .ok_or(RecordError::Missing)?
        .custom_metadata = Some(BTreeMap::from([("new".into(), "fresh-data".into())]));
    let (graph, source, _) = fixture(&changed, &key)?;
    let reopened = NativeReadView::open_paged_with_syntax(
        &key,
        scope(),
        graph.root(),
        &source,
        &|| Ok(()),
        Some(&hint),
    )?;
    assert_eq!(
        reopened.owner.entries["path"].custom_metadata,
        changed.entries["path"].custom_metadata
    );
    let record = metadata_key(&hint.scope, &hint.key, "path")?;
    let bytes = hint.index.get(&record).ok_or(RecordError::Missing)?;
    assert!(hint.path(&record, &bytes[..bytes.len() - 1]).is_none());
    assert!(canonical::<PathCell>(&bytes[..bytes.len() - 1], MAX_METADATA_BYTES).is_err());
    // Same metadata bytes can accompany different authenticated payload descriptors.
    let mut different_payload = Kv2::default();
    let at = Timestamp::checked(100, 113).map_err(|_| RecordError::Invalid)?;
    for n in 1..=2 {
        different_payload
            .handle_precise(
                "POST",
                "data/path",
                &json!({"data":{"n":n+100},"options":{"cas":n-1}}),
                at,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    let (graph, source, _) = fixture(&different_payload, &key)?;
    let fresh = NativeReadView::open_paged_with_syntax(
        &key,
        scope(),
        graph.root(),
        &source,
        &|| Ok(()),
        Some(&hint),
    )?;
    assert!(Arc::ptr_eq(
        &fresh.owner.entries["path"].0,
        &hint.paths[&record].metadata.0
    ));
    let value = fresh
        .read_with_source("GET", "data/path", &json!({"version":1}), at, &source)
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(value.body["data"]["data"]["n"], 101);
    Ok(())
}

#[test]
fn edited_pending_and_nonserialized_default_edges_cannot_capture_a_false_pair() -> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    for field in [
        "config",
        "metadata-clock",
        "precision",
        "descriptor",
        "pending",
    ] {
        let (_, _, mut view) = fixture(&owner()?, &key)?;
        match field {
            "config" => view.owner.config.cas_required = true,
            "metadata-clock" => {
                view.owner
                    .entries
                    .get_mut("path")
                    .ok_or(RecordError::Missing)?
                    .current_metadata_version += 1
            }
            "precision" => {
                view.owner
                    .entries
                    .get_mut("path")
                    .ok_or(RecordError::Missing)?
                    .precision
                    .created_at = None
            }
            "descriptor" => {
                view.graph
                    .as_mut()
                    .ok_or(RecordError::Missing)?
                    .paged
                    .as_mut()
                    .ok_or(RecordError::Missing)?
                    .descriptors
                    .get_mut("path")
                    .ok_or(RecordError::Missing)?
                    .get_mut(&1)
                    .ok_or(RecordError::Missing)?
                    .logical_bytes += 1
            }
            "pending" => {
                view.pending
                    .capture(&view.owner, "metadata/path")
                    .map_err(|_| RecordError::Invalid)?;
            }
            _ => return Err(RecordError::Invalid),
        }
        assert!(
            view.capture_paged_syntax_hint(&|| Ok(()))?.is_none(),
            "{field}"
        );
    }
    // Option<SharedJson>::None and Some(JSON null) both serialize as null.
    // Canonical bytes alone cannot admit an in-memory payload-bearing cell.
    let (_, source, mut view) = fixture(&owner()?, &key)?;
    let baseline = serialize(&view.owner, MAX_GRAPH_BYTES)?;
    let mut hint = view
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let null: SharedJson = serde_json::from_slice(b"null").map_err(|_| RecordError::Corrupt)?;
    view.owner
        .entries
        .get_mut("path")
        .ok_or(RecordError::Missing)?
        .versions
        .get_mut(&1)
        .ok_or(RecordError::Missing)?
        .data = Some(null.clone());
    assert_eq!(baseline, serialize(&view.owner, MAX_GRAPH_BYTES)?);
    assert!(view.capture_paged_syntax_hint(&|| Ok(()))?.is_none());
    let record = metadata_key(&hint.scope, &hint.key, "path")?;
    hint.paths
        .get_mut(&record)
        .ok_or(RecordError::Missing)?
        .metadata
        .versions
        .get_mut(&1)
        .ok_or(RecordError::Missing)?
        .data = Some(null);
    assert!(
        crate::secret_serde::matches_bytes(
            &hint.paths[&record],
            hint.index.get(&record).ok_or(RecordError::Missing)?,
            MAX_METADATA_BYTES
        )
        .map_err(|_| RecordError::Corrupt)?
    );
    let root = view
        .graph
        .as_ref()
        .ok_or(RecordError::Missing)?
        .index
        .root();
    assert!(
        NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            root,
            &source,
            &|| Ok(()),
            Some(&hint)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn retained_syntax_cannot_hide_missing_source_wrong_key_scope_or_expired_gate() -> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    let (graph, mut source, original) = fixture(&owner()?, &key)?;
    let hint = original
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    assert!(
        NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            graph.root(),
            &source,
            &|| Err(RecordError::Invalid),
            Some(&hint)
        )
        .is_err()
    );
    assert!(
        NativeReadView::open_paged_with_syntax(
            &AddressKey::from_bytes([86; 32]),
            scope(),
            graph.root(),
            &source,
            &|| Ok(()),
            Some(&hint)
        )
        .is_err()
    );
    let wrong = NativeScope {
        mount: "wrong/",
        ..scope()
    };
    assert!(
        NativeReadView::open_paged_with_syntax(
            &key,
            wrong,
            graph.root(),
            &source,
            &|| Ok(()),
            Some(&hint)
        )
        .is_err()
    );
    let root_id = graph.root().reference.ok_or(RecordError::Missing)?.id;
    source.0.remove(&root_id);
    assert!(
        NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            graph.root(),
            &source,
            &|| Ok(()),
            Some(&hint)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn syntax_and_two_decoded_views_keep_bidirectional_copy_on_write_isolation() -> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    let (graph, source, mut original) = fixture(&owner()?, &key)?;
    let hint = original
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let mut first = NativeReadView::open_paged_with_syntax(
        &key,
        scope(),
        graph.root(),
        &source,
        &|| Ok(()),
        Some(&hint),
    )?;
    let second = NativeReadView::open_paged_with_syntax(
        &key,
        scope(),
        graph.root(),
        &source,
        &|| Ok(()),
        Some(&hint),
    )?;
    original
        .owner
        .entries
        .get_mut("path")
        .ok_or(RecordError::Missing)?
        .current_metadata_version = 91;
    first
        .owner
        .entries
        .get_mut("path")
        .ok_or(RecordError::Missing)?
        .current_metadata_version = 92;
    let record = metadata_key(&hint.scope, &hint.key, "path")?;
    assert_eq!(hint.paths[&record].metadata.current_metadata_version, 0);
    assert_eq!(second.owner.entries["path"].current_metadata_version, 0);
    assert_eq!(original.owner.entries["path"].current_metadata_version, 91);
    Ok(())
}

fn typed_bounds_fixture_cell() -> CodecResult<PathCell<Entry>> {
    let key = AddressKey::from_bytes([85; 32]);
    let (_, _, view) = fixture(&owner()?, &key)?;
    let hint = view
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let record = metadata_key(&hint.scope, &hint.key, "path")?;
    let cell: PathCell = canonical(
        hint.index.get(&record).ok_or(RecordError::Missing)?,
        MAX_METADATA_BYTES,
    )?;
    Ok(PathCell {
        format: cell.format.clone(),
        scope: cell.scope.clone(),
        path: cell.path.clone(),
        metadata: Entry::from(cell.metadata.clone()),
        payload_versions: cell.payload_versions.clone(),
    })
}

#[test]
fn canonical_typed_bounds_match_raw_preflight_limits_and_errors() -> CodecResult<()> {
    for field in [
        "versions",
        "precision",
        "payload-versions",
        "custom-metadata",
    ] {
        let maximum = if field == "custom-metadata" {
            64
        } else {
            MAX_RETAINED_VERSIONS
        };
        for count in [0, maximum, maximum + 1] {
            let mut cell = typed_bounds_fixture_cell()?;
            match field {
                "versions" => {
                    let template = cell
                        .metadata
                        .versions
                        .values()
                        .next()
                        .cloned()
                        .ok_or(RecordError::Missing)?;
                    cell.metadata.versions = (1..=count).map(|n| (n, template.clone())).collect();
                }
                "precision" => {
                    cell.metadata.precision.versions = (1..=count)
                        .map(|n| (n, VersionPrecision::default()))
                        .collect()
                }
                "payload-versions" => cell.payload_versions = (1..=count).collect(),
                "custom-metadata" => {
                    cell.metadata.custom_metadata = Some(
                        (0..count)
                            .map(|n| (format!("key{n}"), "synthetic".into()))
                            .collect(),
                    )
                }
                _ => return Err(RecordError::Invalid),
            }
            // Test bounds only; normal metadata/key/descriptor/owner semantic
            // validation remains a separate mandatory production step.
            let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
            let raw = preflight_paged_path(&bytes);
            let typed = preflight_paged_typed_path(&bytes, &cell);
            assert_eq!(raw, typed, "{field}/{count}");
            assert_eq!(
                typed,
                if count > maximum {
                    Err(RecordError::Corrupt)
                } else {
                    Ok(())
                }
            );
        }
    }
    let mut cell = typed_bounds_fixture_cell()?;
    for metadata in [None, Some(BTreeMap::new())] {
        cell.metadata.custom_metadata = metadata;
        let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
        assert_eq!(
            preflight_paged_path(&bytes),
            preflight_paged_typed_path(&bytes, &cell)
        );
    }
    Ok(())
}

fn authenticated_replaced_record(
    graph: &NativeCellGraph,
    source: &GraphObjects,
    record: Kv1Key,
    bytes: &[u8],
) -> CodecResult<(Kv1Root, GraphObjects)> {
    let next = graph.0.index.edit(record, Some(bytes))?.next;
    let mut objects = GraphObjects::default();
    for (id, object) in &source.0 {
        objects.0.insert(*id, Arc::clone(object));
    }
    next.visit_objects(|object| {
        objects.0.insert(object.reference().id, Arc::clone(object));
        Ok(())
    })?;
    Ok((next.root(), objects))
}

#[test]
fn fresh_authenticated_noncanonical_and_mismatched_cells_cannot_use_typed_bounds() -> CodecResult<()>
{
    let key = AddressKey::from_bytes([85; 32]);
    let (graph, source, view) = fixture(&owner()?, &key)?;
    let hint = view
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    let record = metadata_key(&hint.scope, &hint.key, "path")?;
    let original = hint.index.get(&record).ok_or(RecordError::Missing)?;
    let text = std::str::from_utf8(original).map_err(|_| RecordError::Corrupt)?;
    let mut rows: Vec<(&str, Vec<u8>, bool)> = Vec::new();
    rows.push(("empty", Vec::new(), false));
    rows.push((
        "noncanonical-whitespace",
        [b" ".as_slice(), original].concat(),
        false,
    ));
    rows.push((
        "unknown-field",
        format!("{},\"unrecognized\":true}}", &text[..text.len() - 1]).into_bytes(),
        false,
    ));
    assert!(text.contains("\"payload_versions\":[1,2]"));
    rows.push((
        "duplicate-payload-set",
        text.replacen(
            "\"payload_versions\":[1,2]",
            "\"payload_versions\":[1,2,2]",
            1,
        )
        .into_bytes(),
        false,
    ));
    let mut changed = typed_bounds_fixture_cell()?;
    let version = serialize(
        changed
            .metadata
            .versions
            .get(&1)
            .ok_or(RecordError::Missing)?,
        MAX_METADATA_BYTES,
    )?;
    let needle = format!(
        "\"1\":{}",
        std::str::from_utf8(&version).map_err(|_| RecordError::Corrupt)?
    );
    assert!(text.contains(&needle));
    rows.push((
        "duplicate-version-map-key",
        text.replacen(&needle, &format!("{needle},{needle}"), 1)
            .into_bytes(),
        false,
    ));
    changed.metadata.precision = EntryPrecision::default();
    rows.push((
        "canonical-default-precision-omission",
        serialize(&changed, MAX_METADATA_BYTES)?.to_vec(),
        true,
    ));
    changed = typed_bounds_fixture_cell()?;
    changed.metadata.custom_metadata = Some(BTreeMap::from([("fresh".into(), "synthetic".into())]));
    rows.push((
        "changed-canonical-metadata",
        serialize(&changed, MAX_METADATA_BYTES)?.to_vec(),
        true,
    ));
    changed = typed_bounds_fixture_cell()?;
    changed.payload_versions.clear();
    rows.push((
        "empty-payload-set-keeps-original-unconsumed-record-rejection",
        serialize(&changed, MAX_METADATA_BYTES)?.to_vec(),
        false,
    ));
    let mut nested = Value::Null;
    for _ in 0..150 {
        nested = Value::Array(vec![nested]);
    }
    let mut deep: Value = serde_json::from_slice(original).map_err(|_| RecordError::Corrupt)?;
    deep["metadata"]["versions"]["1"]["data"] = json!({"nested":nested});
    rows.push((
        "excessive-depth",
        serialize(&deep, MAX_METADATA_BYTES)?.to_vec(),
        false,
    ));
    for size in [MAX_METADATA_BYTES, MAX_METADATA_BYTES + 1] {
        let mut padded = vec![b' '; size - original.len()];
        padded.extend_from_slice(original);
        assert_eq!(
            preflight_paged_path(&padded),
            if size > MAX_METADATA_BYTES {
                Err(RecordError::TooLarge)
            } else {
                Ok(())
            }
        );
        rows.push((
            if size > MAX_METADATA_BYTES {
                "4mib-plus-one"
            } else {
                "4mib-noncanonical"
            },
            padded,
            false,
        ));
    }
    for (label, bytes, expected_success) in rows {
        assert!(hint.path(&record, &bytes).is_none(), "{label}");
        let (root, objects) =
            authenticated_replaced_record(&graph, &source, record.clone(), &bytes)?;
        let a = Reads {
            source: &objects,
            ids: RefCell::new(Vec::new()),
        };
        let b = Reads {
            source: &objects,
            ids: RefCell::new(Vec::new()),
        };
        let gates_a = Cell::new(0);
        let gates_b = Cell::new(0);
        let plain = NativeReadView::open_paged_checked(&key, scope(), root.clone(), &a, &|| {
            gates_a.set(gates_a.get() + 1);
            Ok(())
        });
        let cached = NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            root,
            &b,
            &|| {
                gates_b.set(gates_b.get() + 1);
                Ok(())
            },
            Some(&hint),
        );
        assert_eq!(
            plain.as_ref().map(|_| ()).map_err(|e| *e),
            cached.as_ref().map(|_| ()).map_err(|e| *e),
            "{label}"
        );
        assert_eq!(plain.is_ok(), expected_success, "{label}");
        assert_eq!(*a.ids.borrow(), *b.ids.borrow(), "{label}");
        assert_eq!(gates_a.get(), gates_b.get(), "{label}");
        if let (Ok(a), Ok(b)) = (plain, cached) {
            assert_eq!(
                serialize(&a.owner, MAX_GRAPH_BYTES)?,
                serialize(&b.owner, MAX_GRAPH_BYTES)?,
                "{label}"
            );
        }
    }
    // Unconsumed aggregate membership is checked even when every known path
    // hits the existing exact-canonical representation.
    let extra = hint.scope.key("opaque-extra")?;
    let (root, objects) = authenticated_replaced_record(&graph, &source, extra, b"synthetic")?;
    assert!(
        NativeReadView::open_paged_checked(&key, scope(), root.clone(), &objects, &|| Ok(()))
            .is_err()
    );
    assert!(
        NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            root,
            &objects,
            &|| Ok(()),
            Some(&hint)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn unchanged_aggregate_record_and_path_limits_apply_with_exact_syntax_hint() -> CodecResult<()> {
    let key = AddressKey::from_bytes([85; 32]);
    let (graph, source, view) = fixture(&owner()?, &key)?;
    let hint = view
        .capture_paged_syntax_hint(&|| Ok(()))?
        .ok_or(RecordError::Invalid)?;
    for (prefix, total, expected) in [
        ("opaque", MAX_RECORDS, RecordError::Corrupt),
        ("opaque", MAX_RECORDS + 1, RecordError::Corrupt),
        ("metadata/fake", MAX_PATHS, RecordError::Corrupt),
        ("metadata/fake", MAX_PATHS + 1, RecordError::TooLarge),
    ] {
        let mut records = BTreeMap::new();
        graph.0.index.visit_keys(|record| {
            records.insert(
                record.clone(),
                Zeroizing::new(
                    graph
                        .0
                        .index
                        .get(record)
                        .ok_or(RecordError::Missing)?
                        .to_vec(),
                ),
            );
            Ok(())
        })?;
        let existing = if prefix == "opaque" { records.len() } else { 1 };
        for n in existing..total {
            records.insert(
                hint.scope.key(&format!("{prefix}/{n:020}"))?,
                Zeroizing::new(Vec::new()),
            );
        }
        let index = Kv1Index::from_records_checked(Arc::clone(&graph.0.key), records, &|| Ok(()))?;
        let mut objects = GraphObjects::default();
        for (id, object) in &source.0 {
            objects.0.insert(*id, Arc::clone(object));
        }
        index.visit_objects(|object| {
            objects.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        })?;
        let a = Reads {
            source: &objects,
            ids: RefCell::new(Vec::new()),
        };
        let b = Reads {
            source: &objects,
            ids: RefCell::new(Vec::new()),
        };
        let ga = Cell::new(0);
        let gb = Cell::new(0);
        let plain = NativeReadView::open_paged_checked(&key, scope(), index.root(), &a, &|| {
            ga.set(ga.get() + 1);
            Ok(())
        });
        let cached = NativeReadView::open_paged_with_syntax(
            &key,
            scope(),
            index.root(),
            &b,
            &|| {
                gb.set(gb.get() + 1);
                Ok(())
            },
            Some(&hint),
        );
        assert_eq!(plain.as_ref().err(), Some(&expected), "{prefix}/{total}");
        assert_eq!(cached.as_ref().err(), Some(&expected), "{prefix}/{total}");
        assert_eq!(*a.ids.borrow(), *b.ids.borrow(), "{prefix}/{total}");
        assert_eq!(ga.get(), gb.get(), "{prefix}/{total}");
    }
    Ok(())
}
