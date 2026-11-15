use super::*;
use crate::state_record_root_v6::{Kv2GraphRef, MountScope};
use std::cell::Cell;

fn from() -> NativeScope<'static> {
    NativeScope {
        namespace: "",
        mount: "before/",
        incarnation: 2,
    }
}
fn to() -> NativeScope<'static> {
    NativeScope {
        namespace: "team",
        mount: "after/",
        incarnation: 7,
    }
}
fn at() -> CodecResult<Timestamp> {
    Timestamp::whole(100).map_err(|_| RecordError::Invalid)
}
fn owner() -> CodecResult<Kv2> {
    let mut owner = Kv2::default();
    for (method, path, body) in [
        (
            "POST",
            "config",
            json!({"max_versions":8,"cas_required":true}),
        ),
        (
            "POST",
            "data/history",
            json!({"data":{"version":1,"payload":"a".repeat(300_000)},"options":{"cas":0}}),
        ),
        (
            "POST",
            "data/history",
            json!({"data":{"version":2,"payload":"b".repeat(300_000)},"options":{"cas":1}}),
        ),
        (
            "POST",
            "data/history",
            json!({"data":{"version":3,"payload":"c".repeat(300_000)},"options":{"cas":2}}),
        ),
        (
            "POST",
            "metadata/history",
            json!({"custom_metadata":{"owner":"unchanged"}}),
        ),
        ("POST", "delete/history", json!({"versions":[1]})),
        ("POST", "destroy/history", json!({"versions":[2]})),
    ] {
        owner
            .handle_precise(method, path, &body, at()?)
            .map_err(|_| RecordError::Invalid)?;
    }
    Ok(owner)
}
fn objects(graph: &NativeCellGraph) -> CodecResult<GraphObjects> {
    let mut result = GraphObjects::default();
    graph.visit_objects(
        |object| {
            result.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        },
        &|| Ok(()),
    )?;
    Ok(result)
}
fn fingerprint(source: &GraphObjects) -> BTreeMap<ObjectId, [u8; 32]> {
    source
        .0
        .iter()
        .map(|(id, object)| (*id, crate::crypto::digest(object.bytes())))
        .collect()
}
fn receipt_source(
    candidate: &NativeReadView,
    receipt: &NativeKv2GraphImport,
    key: &AddressKey,
) -> CodecResult<GraphObjects> {
    let graph = candidate.encode_paged(key, to(), &|| Ok(()))?;
    let root = Kv2GraphRef {
        scope: MountScope {
            namespace: to().namespace.into(),
            mount: to().mount.into(),
            incarnation: to().incarnation,
        },
        graph_format: PAGED_NATIVE_FORMAT.into(),
        root: graph.root(),
        logical_payload_bytes: graph.logical_payload_bytes()?,
    };
    let mut result = GraphObjects::default();
    receipt.visit_for(&[root], &|| Ok(()), |_, object| {
        result.0.insert(object.reference().id, Arc::clone(object));
        Ok(())
    })?;
    Ok(result)
}

#[test]
fn native_remount_graph_paged_exact_history_and_fresh_staged_closure() -> CodecResult<()> {
    let key = AddressKey::from_bytes([71; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, from(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let before = fingerprint(&source);
    let view = NativeReadView::open_paged(&key, from(), graph.root(), &source)?;
    let (candidate, receipt) =
        view.prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &|| Ok(()))?;
    assert_eq!(candidate.counts(), view.counts());
    assert_eq!(
        serialize(&candidate.owner, MAX_GRAPH_BYTES)?.as_slice(),
        serialize(&view.owner, MAX_GRAPH_BYTES)?.as_slice()
    );
    let receipt = receipt.ok_or(RecordError::Missing)?;
    let staged = receipt_source(&candidate, &receipt, &key)?;
    candidate.verify_paged_transition(None, &staged, &|| Ok(()))?;
    let encoded = candidate.encode_paged(&key, to(), &|| Ok(()))?;
    assert_ne!(encoded.root(), graph.root());
    let cold = NativeReadView::open_paged(&key, to(), encoded.root(), &staged)?;
    cold.verify_paged_payloads(&staged, &|| Ok(()))?;
    let response = cold
        .read_with_source("GET", "data/history", &json!({"version":3}), at()?, &staged)
        .map_err(|_| RecordError::Corrupt)?;
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["data"]["version"], 3);
    assert!(cold.owner.entries["history"].versions[&2].destroyed);
    assert!(
        cold.owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none())
    );
    assert_eq!(fingerprint(&source), before);
    view.verify_paged_payloads(&source, &|| Ok(()))?;
    Ok(())
}

#[test]
fn native_remount_graph_rejects_key_scope_root_and_pending_metadata() -> CodecResult<()> {
    let key = AddressKey::from_bytes([72; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, from(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, from(), graph.root(), &source)?;
    assert!(
        view.prepare_graph_readdress(
            &AddressKey::from_bytes([73; 32]),
            from(),
            &graph.root(),
            to(),
            &source,
            &|| Ok(())
        )
        .is_err()
    );
    assert!(
        view.prepare_graph_readdress(&key, to(), &graph.root(), from(), &source, &|| Ok(()))
            .is_err()
    );
    let wrong = Kv1Index::empty(AddressKey::from_bytes([74; 32])).root();
    assert!(
        view.prepare_graph_readdress(&key, from(), &wrong, to(), &source, &|| Ok(()))
            .is_err()
    );
    assert!(
        view.prepare_graph_readdress(&key, from(), &graph.root(), from(), &source, &|| Ok(()))
            .is_err()
    );
    let mut pending = view.clone();
    pending
        .mutate(
            "POST",
            "metadata/history",
            &json!({"custom_metadata":{"changed":"pending"}}),
            at()?,
        )
        .map_err(|_| RecordError::Invalid)?;
    assert!(
        pending
            .prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &|| Ok(()))
            .is_err()
    );
    let mut detached = view.clone();
    detached.owner.entries.clear();
    assert!(
        detached
            .prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &|| Ok(()))
            .is_err()
    );
    let mut config = view.clone();
    config
        .mutate("POST", "config", &json!({"max_versions":9}), at()?)
        .map_err(|_| RecordError::Invalid)?;
    assert!(
        config
            .prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &|| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn native_remount_graph_reopens_actual_payload_and_rejects_missing_or_changed_source()
-> CodecResult<()> {
    let key = AddressKey::from_bytes([75; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, from(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, from(), graph.root(), &source)?;
    let selected = graph
        .0
        .paged
        .as_ref()
        .ok_or(RecordError::Missing)?
        .descriptors["history"][&3]
        .blocks[0]
        .id;
    struct Fault<'a> {
        source: &'a GraphObjects,
        selected: ObjectId,
        missing: bool,
        seen: Cell<bool>,
    }
    impl RecordReader for Fault<'_> {
        fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
            if reference.id != self.selected {
                return self.source.read_object(reference);
            }
            self.seen.set(true);
            if self.missing {
                return Err(RecordError::Missing);
            }
            let mut bytes = self.source.read_object(reference)?;
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            Ok(bytes)
        }
    }
    for missing in [true, false] {
        let fault = Fault {
            source: &source,
            selected,
            missing,
            seen: Cell::new(false),
        };
        assert!(
            view.prepare_graph_readdress(&key, from(), &graph.root(), to(), &fault, &|| Ok(()))
                .is_err()
        );
        assert!(
            fault.seen.get(),
            "failure must reach the actual retained payload"
        );
    }
    view.verify_paged_payloads(&source, &|| Ok(()))?;
    Ok(())
}

#[test]
fn native_remount_graph_original_budget_rejects_during_read_without_changing_source()
-> CodecResult<()> {
    let key = AddressKey::from_bytes([76; 32]);
    let graph = NativeCellGraph::encode_paged(&owner()?, &key, from(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let before = fingerprint(&source);
    let view = NativeReadView::open_paged(&key, from(), graph.root(), &source)?;
    let calls = Cell::new(0_usize);
    let gate = || {
        let count = calls.get() + 1;
        calls.set(count);
        if count > 10 {
            Err(RecordError::Invalid)
        } else {
            Ok(())
        }
    };
    assert!(
        view.prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &gate)
            .is_err()
    );
    assert_eq!(calls.get(), 11);
    assert_eq!(fingerprint(&source), before);
    view.verify_paged_payloads(&source, &|| Ok(()))?;
    Ok(())
}

#[test]
fn native_remount_graph_legacy_format_is_preserved_without_paged_fallback() -> CodecResult<()> {
    let key = AddressKey::from_bytes([77; 32]);
    let graph = NativeCellGraph::encode(&owner()?, &key, from(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open(&key, from(), graph.root(), &source)?;
    let (candidate, receipt) =
        view.prepare_graph_readdress(&key, from(), &graph.root(), to(), &source, &|| Ok(()))?;
    assert!(receipt.is_none());
    assert!(!candidate.is_paged());
    let encoded = candidate.encode(&key, to(), &|| Ok(()))?;
    assert_eq!(encoded.graph_format(), NATIVE_FORMAT);
    let staged = objects(&encoded)?;
    let cold = NativeReadView::open(&key, to(), encoded.root(), &staged)?;
    assert_eq!(
        serialize(&cold.owner, MAX_GRAPH_BYTES)?.as_slice(),
        serialize(&view.owner, MAX_GRAPH_BYTES)?.as_slice()
    );
    Ok(())
}
