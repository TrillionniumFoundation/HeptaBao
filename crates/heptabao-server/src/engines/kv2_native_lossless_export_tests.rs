use super::*;
use std::cell::Cell;

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "",
        mount: "secret/",
        incarnation: 7,
    }
}

fn exact_owner() -> CodecResult<Kv2> {
    let data = lossless::decode_lossless_json(
        br#"{"integer":9007199254740993,"decimal":0.123456789012345678901234567890,"private":{"$serde_json::private::Number":"001"}}"#,
    ).map_err(|_| RecordError::Invalid)?;
    let input = json!({
        "schema":lossless::IMPORT_SCHEMA,
        "config":{"max_versions":4,"cas_required":true,"metadata_cas_required":true,"delete_version_after":"0.000000113s"},
        "entries":{"history":{
            "created_time":"1970-01-01T00:01:40.000000113Z",
            "updated_time":"1970-01-01T00:01:43.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":4,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:41.000000113Z","deletion_time":"1970-01-01T00:03:20.000000113Z","destroyed":false,"source_deletion_time":"1970-01-01T00:04:20.000000113Z","data":data},
                "2":{"created_time":"1970-01-01T00:01:42.000000113Z","deletion_time":"","destroyed":true,"source_deletion_time":"1970-01-01T00:04:21.000000113Z","data":null},
                "3":{"created_time":"1970-01-01T00:01:43.000000113Z","deletion_time":"","destroyed":false,"source_deletion_time":"","data":data}
            }
        }}
    });
    let bytes = serialize(&input, 16 * 1024 * 1024)?;
    Kv2::from_lossless_import_json(&bytes).map_err(|_| RecordError::Invalid)
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

fn exported(view: &NativeReadView, reader: &impl RecordReader) -> CodecResult<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    view.write_lossless_export(&mut *bytes, reader, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    check_export_syntax(&mut bytes.as_slice(), bytes.len() as u64, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    Ok(bytes)
}

#[test]
fn lossless_export_exact_history_roundtrips_the_same_authenticated_root() -> CodecResult<()> {
    let key = AddressKey::from_bytes([73; 32]);
    let graph = NativeCellGraph::encode_paged(&exact_owner()?, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let bytes = exported(&view, &source)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| RecordError::Corrupt)?;
    assert!(text.contains("9007199254740993"));
    assert!(text.contains("0.123456789012345678901234567890"));
    assert!(text.contains("\"custom_metadata\":{}"));
    assert!(text.contains("1970-01-01T00:04:21.000000113Z"));
    let checked = lossless::native_large::NativeLargeBundle::checked(bytes, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let restored =
        Kv2::from_native_large_import(&checked, &|| Ok(())).map_err(|_| RecordError::Corrupt)?;
    let restored = NativeCellGraph::encode_paged(&restored, &key, scope(), &|| Ok(()))?;
    assert_eq!(graph.root(), restored.root());
    assert!(
        view.owner
            .entries
            .values()
            .flat_map(|entry| entry.versions.values())
            .all(|version| version.data.is_none())
    );
    Ok(())
}

#[test]
fn wire_duration_api_reads_preserve_native_lossless_bytes_and_root() -> CodecResult<()> {
    let mut owner = exact_owner()?;
    owner.config.delete_version_after = 86_400;
    let entry = owner
        .entries
        .get_mut("history")
        .ok_or(RecordError::Missing)?;
    entry.config.delete_version_after = 7_200;
    entry.config.delete_version_after_nanos = 500_000_000;
    let key = AddressKey::from_bytes([79; 32]);
    let graph = NativeCellGraph::encode_paged(&owner, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let before = exported(&view, &source)?;
    for (path, expected) in [
        ("config", "24h0m0.000000113s"),
        ("metadata/history", "2h0m0.5s"),
    ] {
        let response = view
            .owner
            .handle_read("GET", path, &json!({}), 101)
            .map_err(|_| RecordError::Corrupt)?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["delete_version_after"], expected);
    }
    assert_eq!(exported(&view, &source)?.as_slice(), before.as_slice());
    let projection: Value =
        lossless::decode_lossless_json(&before).map_err(|_| RecordError::Corrupt)?;
    assert_eq!(
        projection["config"]["delete_version_after"],
        "86400.000000113s"
    );
    assert_eq!(
        projection["entries"]["history"]["delete_version_after"],
        "7200.5s"
    );
    let checked = lossless::native_large::NativeLargeBundle::checked(before, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let restored =
        Kv2::from_native_large_import(&checked, &|| Ok(())).map_err(|_| RecordError::Corrupt)?;
    let restored = NativeCellGraph::encode_paged(&restored, &key, scope(), &|| Ok(()))?;
    assert_eq!(graph.root(), restored.root());
    Ok(())
}

struct ChangingReader<'a> {
    source: &'a GraphObjects,
    payloads: BTreeSet<ObjectId>,
    corrupt: Cell<bool>,
    revoked: Cell<bool>,
    revoke_on_payload: bool,
}
impl RecordReader for ChangingReader<'_> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        let mut bytes = self.source.read_object(reference)?;
        if self.payloads.contains(&reference.id) {
            if self.corrupt.get() {
                *bytes.first_mut().ok_or(RecordError::Corrupt)? ^= 1;
            }
            if self.revoke_on_payload {
                self.revoked.set(true);
            }
        }
        Ok(bytes)
    }
}

#[test]
fn lossless_export_reopens_actual_blocks_and_rejects_revoked_gate_or_format() -> CodecResult<()> {
    let key = AddressKey::from_bytes([74; 32]);
    let graph = NativeCellGraph::encode_paged(&exact_owner()?, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let payloads = graph
        .0
        .paged
        .as_ref()
        .ok_or(RecordError::Missing)?
        .descriptors
        .values()
        .flat_map(BTreeMap::values)
        .flat_map(|value| value.blocks.iter().map(|reference| reference.id))
        .collect();
    let mut reader = ChangingReader {
        source: &source,
        payloads,
        corrupt: Cell::new(false),
        revoked: Cell::new(false),
        revoke_on_payload: false,
    };
    let mut view = NativeReadView::open_paged(&key, scope(), graph.root(), &reader)?;
    assert!(!exported(&view, &reader)?.is_empty());
    reader.corrupt.set(true);
    assert!(
        exported(&view, &reader).is_err(),
        "success cannot cache source authority"
    );
    reader.corrupt.set(false);
    reader.revoke_on_payload = true;
    let mut output = Zeroizing::new(Vec::new());
    assert!(
        view.write_lossless_export(&mut *output, &reader, &|| {
            if reader.revoked.get() {
                Err(RecordError::Invalid)
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    reader.revoke_on_payload = false;
    reader.revoked.set(false);
    view.owner.lossless_format = None;
    assert!(
        exported(&view, &reader).is_err(),
        "a precise owner cannot lose its current format floor"
    );
    Ok(())
}

#[test]
fn lossless_export_refuses_sparse_history_without_fabricating_a_bundle() -> CodecResult<()> {
    let mut owner = Kv2::default();
    for number in 1..=3 {
        owner
            .handle(
                "POST",
                "data/history",
                &json!({"data":{"value":number}}),
                100,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    owner
        .entries
        .get_mut("history")
        .ok_or(RecordError::Missing)?
        .versions
        .remove(&2);
    let key = AddressKey::from_bytes([75; 32]);
    let graph = NativeCellGraph::encode_paged(&owner, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let failure = view.write_lossless_export(&mut *bytes, &source, &|| Ok(()));
    assert!(failure.is_err_and(|error| error.status == 409));
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn lossless_export_keeps_original_byte_depth_and_transport_profile_bounds() {
    let mut sink = io::sink();
    let mut output = BoundedOutput {
        writer: &mut sink,
        written: MAX_BYTES - 1,
        exhausted: false,
    };
    assert!(output.write_all(b"{}").is_err());
    assert!(output.exhausted);
    let nested = format!("{}null{}", "[".repeat(130), "]".repeat(130));
    assert!(check_export_syntax(&mut nested.as_bytes(), nested.len() as u64, &|| Ok(())).is_err());
    assert!(check_export_syntax(&mut b"{}".as_slice(), MAX_BYTES + 1, &|| Ok(())).is_err());
    assert!(check_export_syntax(&mut b"{}extra".as_slice(), 2, &|| Ok(())).is_err());
}

#[test]
fn lossless_export_34mib_history_remains_streamed_and_reimportable() -> CodecResult<()> {
    let mut owner = Kv2::default();
    owner
        .handle("POST", "config", &json!({"max_versions":20}), 100)
        .map_err(|_| RecordError::Invalid)?;
    for number in 1..=19 {
        owner
            .handle(
                "POST",
                "data/history",
                &json!({"data":{"version":number,"body":"x".repeat(2 * 1024 * 1024)}}),
                100 + number,
            )
            .map_err(|_| RecordError::Invalid)?;
    }
    owner
        .handle("POST", "destroy/history", &json!({"versions":[2,6]}), 200)
        .map_err(|_| RecordError::Invalid)?;
    owner
        .handle("POST", "delete/history", &json!({"versions":[1]}), 201)
        .map_err(|_| RecordError::Invalid)?;
    owner.lossless_format = Some(1);
    let key = AddressKey::from_bytes([76; 32]);
    let graph = NativeCellGraph::encode_paged(&owner, &key, scope(), &|| Ok(()))?;
    let source = objects(&graph)?;
    let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
    let bytes = exported(&view, &source)?;
    assert!(bytes.len() > 34 * 1024 * 1024);
    let checked = lossless::native_large::NativeLargeBundle::checked(bytes, &|| Ok(()))
        .map_err(|_| RecordError::Corrupt)?;
    let restored =
        Kv2::from_native_large_import(&checked, &|| Ok(())).map_err(|_| RecordError::Corrupt)?;
    let next = NativeCellGraph::encode_paged(&restored, &key, scope(), &|| Ok(()))?;
    assert_eq!(graph.root(), next.root());
    Ok(())
}

#[test]
fn lossless_export_native_schedule_and_missing_source_survive_paged_reopen() -> CodecResult<()> {
    let mut owner = Kv2::default();
    for (method, path, body, now) in [
        (
            "POST",
            "metadata/future",
            json!({"delete_version_after":"86400s"}),
            90,
        ),
        (
            "POST",
            "data/future",
            json!({"data":{"scheduled":true}}),
            100,
        ),
        (
            "POST",
            "data/unscheduled",
            json!({"data":{"scheduled":false}}),
            100,
        ),
        (
            "POST",
            "metadata/unscheduled",
            json!({"delete_version_after":"30s"}),
            101,
        ),
        ("POST", "delete/unscheduled", json!({"versions":[1]}), 102),
        ("POST", "undelete/unscheduled", json!({"versions":[1]}), 103),
    ] {
        owner
            .handle(method, path, &body, now)
            .map_err(|_| RecordError::Invalid)?;
    }
    let key = AddressKey::from_bytes([77; 32]);
    for (operation, now, expected_deletion) in [
        ("", 100, 86500),
        ("delete/future", 110, 110),
        ("undelete/future", 111, 86511),
    ] {
        if !operation.is_empty() {
            owner
                .handle("POST", operation, &json!({"versions":[1]}), now)
                .map_err(|_| RecordError::Invalid)?;
        }
        let graph = NativeCellGraph::encode_paged(&owner, &key, scope(), &|| Ok(()))?;
        let source = objects(&graph)?;
        let view = NativeReadView::open_paged(&key, scope(), graph.root(), &source)?;
        let bytes = exported(&view, &source)?;
        let value = lossless::decode_lossless_json(&bytes).map_err(|_| RecordError::Corrupt)?;
        let future = &value["entries"]["future"];
        assert_eq!(future["custom_metadata"], Value::Null);
        assert_eq!(
            future["versions"]["1"]["source_deletion_time"],
            timestamp(86500)
        );
        assert_eq!(
            future["versions"]["1"]["deletion_time"],
            timestamp(expected_deletion)
        );
        assert_eq!(future["versions"]["1"]["destroyed"], false);
        let unscheduled = &value["entries"]["unscheduled"]["versions"]["1"];
        assert_eq!(unscheduled["source_deletion_time"], "");
        assert_eq!(unscheduled["deletion_time"], timestamp(133));
        let checked = lossless::native_large::NativeLargeBundle::checked(bytes, &|| Ok(()))
            .map_err(|_| RecordError::Corrupt)?;
        let restored = Kv2::from_native_large_import(&checked, &|| Ok(()))
            .map_err(|_| RecordError::Corrupt)?;
        let next = NativeCellGraph::encode_paged(&restored, &key, scope(), &|| Ok(()))?;
        assert_eq!(graph.root(), next.root());
    }
    Ok(())
}
