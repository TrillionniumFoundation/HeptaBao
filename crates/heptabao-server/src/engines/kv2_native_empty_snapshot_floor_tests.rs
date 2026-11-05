//! Actual codec graphs exercise proof refusal; none grants Service authority.
use super::*;

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

fn destroyed_history_without_payload() -> CodecResult<Kv2> {
    let mut value = Kv2::default();
    value
        .handle_precise(
            "POST",
            "data/history",
            &json!({"data":{"value":"synthetic"}}),
            time()?,
        )
        .map_err(|_| RecordError::Invalid)?;
    value
        .handle_precise("POST", "destroy/history", &json!({"versions":[1]}), time()?)
        .map_err(|_| RecordError::Invalid)?;
    Ok(value)
}

#[test]
fn native_empty_snapshot_rejects_destroyed_history_with_no_payload() -> CodecResult<()> {
    let key = AddressKey::from_bytes([131; 32]);
    let graph = NativeCellGraph::encode_paged(
        &destroyed_history_without_payload()?,
        &key,
        scope(),
        &|| Ok(()),
    )?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    assert_eq!(view.counts(), (1, 1, 0));
    assert_eq!(view.logical_payload_bytes()?, 0);
    // A destroyed record is still authenticated metadata/history. A zero
    // logical payload count cannot permit preserving a newer marker over it.
    assert!(!matches!(
        view.is_authenticated_empty_for_marker(&key, scope(), &graph.root(), &|| Ok(())),
        Ok(true)
    ));
    Ok(())
}

#[test]
fn native_empty_snapshot_rejects_zero_counts_with_pending_metadata_deletion() -> CodecResult<()> {
    let key = AddressKey::from_bytes([132; 32]);
    let graph = NativeCellGraph::encode_paged(
        &destroyed_history_without_payload()?,
        &key,
        scope(),
        &|| Ok(()),
    )?;
    let source = objects(&graph)?;
    let mut view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let response = view
        .mutate("DELETE", "metadata/history", &json!({}), time()?)
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(response.status, 204);
    assert!(response.mutated);
    assert_eq!(view.counts(), (0, 0, 0));
    assert!(view.pending.paths().any(|path| path == "history"));
    assert_eq!(
        view.graph
            .as_ref()
            .ok_or(RecordError::Missing)?
            .index
            .root(),
        graph.root()
    );
    // The old cache still contains historical metadata, even though the
    // candidate owner is empty. Also reject the prospective encoded root:
    // matches_authenticated_root alone could match that detached candidate.
    assert!(!matches!(
        view.is_authenticated_empty_for_marker(&key, scope(), &graph.root(), &|| Ok(())),
        Ok(true)
    ));
    let detached = view.encode_paged(&key, scope(), &|| Ok(()))?;
    assert_ne!(detached.root(), graph.root());
    assert!(!matches!(
        view.is_authenticated_empty_for_marker(&key, scope(), &detached.root(), &|| Ok(())),
        Ok(true)
    ));
    Ok(())
}

#[test]
fn native_empty_snapshot_binds_actual_config_scope_key_root_and_format() -> CodecResult<()> {
    let key = AddressKey::from_bytes([133; 32]);
    let mut empty = Kv2::default();
    empty
        .handle_precise("POST", "config", &json!({"max_versions":4}), time()?)
        .map_err(|_| RecordError::Invalid)?;
    let graph = NativeCellGraph::encode_paged(&empty, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    assert_eq!(view.counts(), (0, 0, 0));
    assert!(view.is_authenticated_empty_for_marker(&key, scope(), &graph.root(), &|| Ok(()))?);
    assert!(
        view.is_authenticated_empty_for_marker(&key, scope(), &graph.root(), &|| Err(
            RecordError::Invalid
        ))
        .is_err()
    );
    for wrong in [
        NativeScope {
            namespace: "sibling",
            mount: "secret/",
            incarnation: 7,
        },
        NativeScope {
            namespace: "",
            mount: "other/",
            incarnation: 7,
        },
        NativeScope {
            namespace: "",
            mount: "secret/",
            incarnation: 8,
        },
    ] {
        assert!(!matches!(
            view.is_authenticated_empty_for_marker(&key, wrong, &graph.root(), &|| Ok(())),
            Ok(true)
        ));
    }
    let other = NativeCellGraph::encode_paged(&Kv2::default(), &key, scope(), &|| Ok(()))?;
    assert_ne!(other.root(), graph.root());
    assert!(!matches!(
        view.is_authenticated_empty_for_marker(&key, scope(), &other.root(), &|| Ok(())),
        Ok(true)
    ));
    let wrong_key = AddressKey::from_bytes([134; 32]);
    assert!(!matches!(
        view.is_authenticated_empty_for_marker(&wrong_key, scope(), &graph.root(), &|| Ok(())),
        Ok(true)
    ));
    let legacy = NativeCellGraph::encode(&empty, &key, scope(), &|| Ok(()))?;
    let legacy_source = objects(&legacy)?;
    let legacy_view = NativeReadView::open(&key, scope(), legacy.root(), &legacy_source)?;
    assert!(!matches!(
        legacy_view.is_authenticated_empty_for_marker(&key, scope(), &legacy.root(), &|| Ok(())),
        Ok(true)
    ));
    Ok(())
}
