//! Detached native import proof boundaries. Synthetic closed bundles only.
use super::*;
use crate::state_records::ObjectKind;
use std::cell::RefCell;
use std::collections::BTreeSet;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn scope() -> NativeScope<'static> {
    NativeScope { namespace: "", mount: "secret/", incarnation: 11 }
}

fn bundle() -> TestResult<Zeroizing<Vec<u8>>> {
    let value = crate::engines::decode_lossless_json(
        br#"{"big":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"}}"#
    )?;
    let body = json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"item":{
            "created_time":"1970-01-01T00:01:30.000000113Z",
            "updated_time":"1970-01-01T00:01:35.000000113Z",
            "current_version":5,"current_metadata_version":7,"oldest_version":3,
            "max_versions":3,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"7200.5s","custom_metadata":{"owner":"exact-import"},
            "versions":{
                "3":{"created_time":"1970-01-01T00:01:33.000000113Z","deletion_time":"","destroyed":true,"data":null},
                "4":{"created_time":"1970-01-01T00:01:34.000000113Z","deletion_time":"1970-01-01T00:01:36.000000113Z",
                     "source_deletion_time":"1970-01-01T02:01:34.500000113Z","destroyed":false,"data":{"old":true}},
                "5":{"created_time":"1970-01-01T00:01:35.000000113Z","deletion_time":"","destroyed":false,"data":value}
            }
        }}
    });
    Ok(crate::secret_serde::to_vec(&body, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "fixture encoding")?)
}

fn empty_view(parent: &AddressKey) -> TestResult<NativeReadView> {
    let owner = NativeReadView {
        owner: DetachedOwner(Kv2::default()),
        graph: None,
        pending: mutation::PendingPaths::default(),
    };
    let graph = owner.encode_paged(parent, scope(), &|| Ok(()))?;
    let mut source = GraphObjects::default();
    graph.visit_objects(|object| {
        source.0.insert(object.reference().id, Arc::clone(object));
        Ok(())
    }, &|| Ok(()))?;
    Ok(NativeReadView::open_paged(parent, scope(), graph.root(), &source)?)
}

fn root_reference(import: &NativeKv2GraphImport) -> Kv2GraphRef {
    Kv2GraphRef {
        scope: import.scope.clone(),
        root: import.root.clone(),
        graph_format: PAGED_NATIVE_FORMAT.into(),
        logical_payload_bytes: import.logical_bytes,
    }
}

fn import_source(import: &NativeKv2GraphImport) -> TestResult<GraphObjects> {
    let mut source = GraphObjects::default();
    import.visit_for(&[root_reference(import)], &|| Ok(()), |_, object| {
        source.0.insert(object.reference().id, Arc::clone(object));
        Ok(())
    })?;
    Ok(source)
}

struct RecordingReader<'a> {
    source: &'a GraphObjects,
    reads: RefCell<BTreeSet<ObjectId>>,
}

impl RecordReader for RecordingReader<'_> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        self.reads.borrow_mut().insert(reference.id);
        self.source.read_object(reference)
    }
}

#[test]
fn native_kv2_graph_import_codec_keeps_exact_history_and_no_payload_owner() -> TestResult {
    let parent = AddressKey::from_bytes([41;32]);
    let before = empty_view(&parent)?;
    let bytes = bundle()?;
    let expected = Kv2::from_lossless_import_json(&bytes)?;
    let (view, import) = before.prepare_lossless_graph_import(
        &bytes, &parent, scope(), &|| Ok(()),
    )?;
    assert!(view.owner.entries.values().flat_map(|entry| entry.versions.values())
        .all(|version| version.data.is_none()));
    assert!(crate::secret_serde::to_vec(&view, crate::MAX_APPLICATION_STATE_BYTES).is_err());
    assert!(import.objects.values().any(|object| object.reference().kind == ObjectKind::Block));
    let source = import_source(&import)?;
    let cold = NativeReadView::open_paged(&parent, scope(), import.root.clone(), &source)?;
    cold.verify_paged_transition(Some(&before), &source, &|| Ok(()))?;
    let at = Timestamp::whole(100)?;
    for (path, query) in [
        ("config", json!({})), ("metadata/item", json!({})),
        ("data/item", json!({"version":3})), ("data/item", json!({"version":4})),
        ("data/item", json!({"version":5})),
    ] {
        let actual = cold.read_with_source("GET", path, &query, at, &source)?;
        let expected = expected.handle_read_precise("GET", path, &query, at)?;
        assert_eq!(actual.status, expected.status);
        assert_eq!(actual.body, expected.body);
    }
    let metadata = cold.read("GET", "metadata/item", &json!({}), at)?;
    assert_eq!(metadata.body["data"]["current_metadata_version"],7);
    assert_eq!(metadata.body["data"]["oldest_version"],3);
    let data = cold.read_with_source("GET", "data/item", &json!({"version":5}), at, &source)?;
    assert_eq!(data.body["data"]["data"]["big"].as_number().ok_or("big")?.to_string(),
        "184467440737095516160001");
    assert_eq!(data.body["data"]["data"]["decimal"].as_number().ok_or("decimal")?.to_string(),
        "0.12345678901234567890123456789");
    assert!(data.body["data"]["data"]["fake"].is_object());
    Ok(())
}

#[test]
fn native_kv2_graph_import_codec_binds_scope_root_and_complete_payload_closure() -> TestResult {
    let parent = AddressKey::from_bytes([42;32]);
    let before = empty_view(&parent)?;
    let (view, import) = before.prepare_lossless_graph_import(
        &bundle()?, &parent, scope(), &|| Ok(()),
    )?;
    let mut seen = 0;
    let mut wrong = root_reference(&import);
    wrong.scope.incarnation += 1;
    assert!(import.visit_for(&[wrong], &|| Ok(()), |_,_| { seen += 1; Ok(()) }).is_err());
    assert_eq!(seen,0);
    let mut wrong = root_reference(&import);
    wrong.logical_payload_bytes += 1;
    assert!(import.visit_for(&[wrong], &|| Ok(()), |_,_| { seen += 1; Ok(()) }).is_err());
    assert_eq!(seen,0);
    assert!(import.visit_for(&[root_reference(&import)], &|| Err(RecordError::Invalid),
        |_,_| { seen += 1; Ok(()) }).is_err());
    assert_eq!(seen,0);
    let source = import_source(&import)?;
    view.verify_paged_transition(Some(&before), &source, &|| Ok(()))?;
    // Block is also the type of large metadata values. Select payload objects
    // through the actual point reader, including the soft-deleted version at a
    // time before its deletion. Hash ordering and object kind cannot identify
    // payload closure.
    for (version, now) in [(4, Timestamp::whole(95)?), (5, Timestamp::whole(100)?)] {
        let recorder = RecordingReader {
            source: &source,
            reads: RefCell::new(BTreeSet::new()),
        };
        let query = json!({"version":version});
        let response = view.read_with_source("GET", "data/item", &query, now, &recorder)?;
        assert_eq!(response.status, 200);
        let payloads = recorder.reads.into_inner();
        assert!(!payloads.is_empty());
        for missing in payloads {
            let mut incomplete = import_source(&import)?;
            assert!(incomplete.0.remove(&missing).is_some());
            // A metadata-only open authenticates the descriptor, not its
            // payload. The fresh import cannot inherit the missing payload
            // from the prior empty destination, for either a cached or a cold
            // view. The same real point read must reject it too.
            let cold = NativeReadView::open_paged(
                &parent, scope(), import.root.clone(), &incomplete,
            )?;
            assert!(view.verify_paged_transition(
                Some(&before), &incomplete, &|| Ok(()),
            ).is_err());
            assert!(cold.verify_paged_transition(
                Some(&before), &incomplete, &|| Ok(()),
            ).is_err());
            assert!(cold.read_with_source(
                "GET", "data/item", &query, now, &incomplete,
            ).is_err());
        }
    }
    // Cold graph opening, rather than the incremental payload verifier, owns
    // the metadata-root closure check. Remove that exact reference separately.
    let root_id = import.root.reference.as_ref().ok_or("metadata root")?.id;
    let mut missing_metadata = import_source(&import)?;
    assert!(missing_metadata.0.remove(&root_id).is_some());
    assert!(NativeReadView::open_paged(
        &parent, scope(), import.root.clone(), &missing_metadata,
    ).is_err());
    assert!(before.prepare_lossless_graph_import(&bundle()?,
        &AddressKey::from_bytes([43;32]),scope(),&|| Ok(())).is_err());
    Ok(())
}

#[test]
fn native_kv2_graph_import_codec_rejects_replay_nonpristine_and_incomplete_history() -> TestResult {
    let parent = AddressKey::from_bytes([44;32]);
    let mut before = empty_view(&parent)?;
    let bytes = bundle()?;
    let (view, _) = before.prepare_lossless_graph_import(&bytes,&parent,scope(),&|| Ok(()))?;
    assert_eq!(view.prepare_lossless_graph_import(&bytes,&parent,scope(),&|| Ok(()))
        .err().ok_or("replay rejection")?.status,409);
    let mut malformed = crate::engines::decode_lossless_json(&bytes)?;
    malformed["entries"]["item"]["versions"].as_object_mut()
        .ok_or("versions")?.remove("4");
    let malformed = crate::secret_serde::to_vec(&malformed,crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| "encoding")?;
    assert_eq!(before.prepare_lossless_graph_import(&malformed,&parent,scope(),&|| Ok(()))
        .err().ok_or("incomplete rejection")?.status,400);
    assert_eq!(before.counts(),(0,0,0));
    before.mutate("POST","config",&json!({"cas_required":true}),Timestamp::whole(100)?)?;
    assert_eq!(before.prepare_lossless_graph_import(&bytes,&parent,scope(),&|| Ok(()))
        .err().ok_or("nonpristine rejection")?.status,409);
    Ok(())
}
