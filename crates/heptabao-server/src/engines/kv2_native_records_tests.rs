//! Actual KV2 owners and logical APIs, detached from production root admission.
use super::*;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn scope() -> NativeScope<'static> {
    NativeScope {
        namespace: "team-a",
        mount: "secret/",
        incarnation: 7,
    }
}
fn base() -> Arc<AddressKey> {
    AddressKey::from_bytes([61; 32])
}
fn at(seconds: u64, nanos: u32) -> TestResult<Timestamp> {
    Ok(Timestamp::checked(seconds, nanos)?)
}
fn reopened(owner: &Kv2) -> TestResult<(NativeGraph, DetachedOwner)> {
    let graph = NativeGraph::encode(owner, &base(), scope())?;
    let objects = GraphObjects::from_index(&graph.index)?;
    let open = NativeGraph::open(&base(), scope(), graph.index.root(), &objects)?;
    let restored = open.decode()?;
    assert_eq!(
        serialize(owner, MAX_GRAPH_BYTES)?,
        serialize(&restored, MAX_GRAPH_BYTES)?
    );
    Ok((open, restored))
}
fn compare_read(
    left: &Kv2,
    right: &Kv2,
    method: &str,
    path: &str,
    body: &Value,
    now: Timestamp,
) -> TestResult {
    match (
        left.handle_read_precise(method, path, body, now),
        right.handle_read_precise(method, path, body, now),
    ) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.status, b.status);
            assert_eq!(a.body, b.body);
            assert_eq!(a.mutated, b.mutated);
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.status, b.status);
            assert_eq!(a.message, b.message);
        }
        _ => return Err("native reconstruction changed logical outcome".into()),
    }
    Ok(())
}
fn compare_write(
    left: &mut Kv2,
    right: &mut Kv2,
    method: &str,
    path: &str,
    body: &Value,
    now: Timestamp,
) -> TestResult {
    match (
        left.handle_precise(method, path, body, now),
        right.handle_precise(method, path, body, now),
    ) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.status, b.status);
            assert_eq!(a.body, b.body);
            assert_eq!(a.mutated, b.mutated);
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.status, b.status);
            assert_eq!(a.message, b.message);
        }
        _ => return Err("native reconstruction changed mutation outcome".into()),
    }
    assert_eq!(
        serialize(left, MAX_GRAPH_BYTES)?,
        serialize(right, MAX_GRAPH_BYTES)?
    );
    Ok(())
}

#[test]
fn actual_retained_payloads_over_32_mib_roundtrip_and_match_logical_operations() -> TestResult {
    let mut owner = Kv2::default();
    owner.handle_precise("POST", "config", &json!({"max_versions":80}), at(1000, 1)?)?;
    let lossless = lossless::decode_lossless_json(
        br#"{"huge":1234567890123456789012345678901234567890,"exponent":1.234567890123456789e-999,"$serde_json::private::Number":"user object","nested":[true,null,{"n":-0.00}]}"#,
    )?;
    for version in 1..=80 {
        // Every block contains distinct version/chunk markers. Repeated filler
        // alone would deduplicate below 32 MiB of independent stored objects.
        let mut blob = String::with_capacity(448 * 1024);
        for chunk in 0..112 {
            let marker = format!("version-{version:05}/chunk-{chunk:05}/");
            blob.push_str(&marker);
            blob.extend(std::iter::repeat_n(
                char::from(b'a' + (version % 26) as u8),
                4096 - marker.len(),
            ));
        }
        let body = json!({"data":{
            "blob":blob,
            "ordinal":version,"structured":lossless,
        }});
        owner.handle_precise(
            "POST",
            "data/folder/item",
            &body,
            at(1000 + version, version as u32)?,
        )?;
    }
    owner.handle_precise("POST", "metadata/folder/item", &json!({
        "cas_required":true,"metadata_cas_required":true,"custom_metadata":{"owner":"qianqi","purpose":"native foundation"}
    }), at(1100, 7)?)?;
    owner.handle_precise(
        "POST",
        "delete/folder/item",
        &json!({"versions":[7,8]}),
        at(1101, 999_999_999)?,
    )?;
    owner.handle_precise(
        "POST",
        "destroy/folder/item",
        &json!({"versions":[9]}),
        at(1102, 3)?,
    )?;
    owner.handle_precise(
        "POST",
        "metadata/metadata-only",
        &json!({"custom_metadata":{}}),
        at(1103, 11)?,
    )?;
    let bytes = serialize(&owner, MAX_GRAPH_BYTES)?;
    assert!(bytes.len() > 32 * 1024 * 1024);
    let receipt = verify_native_owner_records(&bytes, &[61; 32], scope())?;
    eprintln!(
        "stage-a-only owner_bytes={} unique_object_bytes={} graph_objects={} retained_versions={} payload_records={} replacement_authority=false",
        bytes.len(),
        receipt.encoded_graph_bytes,
        receipt.graph_objects,
        receipt.retained_versions,
        receipt.payload_records
    );
    assert!(receipt.encoded_graph_bytes > 32 * 1024 * 1024);
    assert!(receipt.graph_objects > 200);
    assert_eq!(receipt.retained_versions, 80);
    assert_eq!(receipt.payload_records, 79);
    assert!(!receipt.production_writer_admitted);
    assert!(!receipt.migration_admitted);
    assert!(!receipt.replacement_authority);
    let (_, mut restored) = reopened(&owner)?;
    for version in 1..=80 {
        compare_read(
            &owner,
            &restored,
            "GET",
            "data/folder/item",
            &json!({"version":version}),
            at(1200, 0)?,
        )?;
    }
    for (method, path) in [
        ("GET", "config"),
        ("GET", "metadata/folder/item"),
        ("GET", "metadata/metadata-only"),
        ("GET", "subkeys/folder/item"),
        ("LIST", "metadata"),
        ("SCAN", "metadata"),
    ] {
        compare_read(&owner, &restored, method, path, &json!({}), at(1200, 0)?)?;
    }
    compare_write(
        &mut owner,
        &mut restored,
        "POST",
        "data/folder/item",
        &json!({"data":{"denied":true},"options":{"cas":79}}),
        at(1201, 13)?,
    )?;
    compare_write(
        &mut owner,
        &mut restored,
        "POST",
        "metadata/folder/item",
        &json!({"metadata_cas":0,"custom_metadata":{"denied":"yes"}}),
        at(1201, 13)?,
    )?;
    compare_write(
        &mut owner,
        &mut restored,
        "POST",
        "undelete/folder/item",
        &json!({"versions":[7,9]}),
        at(1202, 17)?,
    )?;
    compare_write(
        &mut owner,
        &mut restored,
        "PATCH",
        "data/folder/item",
        &json!({"data":{"patched":true},"options":{"cas":80}}),
        at(1203, 19)?,
    )?;
    assert_eq!(
        restored
            .entries
            .get("folder/item")
            .ok_or("item")?
            .current_version,
        81
    );
    assert_eq!(
        restored
            .handle_read_precise(
                "GET",
                "data/folder/item",
                &json!({"version":7}),
                at(1203, 20)?
            )?
            .status,
        200
    );
    assert_eq!(
        restored
            .handle_read_precise(
                "GET",
                "data/folder/item",
                &json!({"version":9}),
                at(1203, 20)?
            )?
            .status,
        404
    );
    compare_write(
        &mut owner,
        &mut restored,
        "DELETE",
        "metadata/folder/item",
        &json!({}),
        at(1204, 23)?,
    )?;
    Ok(())
}

#[test]
fn ten_thousand_versions_and_sparse_history_keep_actual_runtime_retention() -> TestResult {
    let data = SharedJson::from(SecretJson(json!({"retained":true,"nested":{"n":123}})));
    let mut entry = EntryState {
        config: Config {
            max_versions: 10_000,
            ..Config::default()
        },
        current_version: 10_000,
        current_metadata_version: 0,
        oldest_version: 0,
        created_at: 100,
        updated_at: 101,
        custom_metadata: Some(BTreeMap::from([("owner".into(), "history".into())])),
        versions: BTreeMap::new(),
        precision: EntryPrecision::default(),
    };
    for number in 1..=10_000 {
        entry.versions.insert(
            number,
            Version {
                created_at: 100,
                deletion_at: None,
                destroyed: false,
                data: Some(data.clone()),
            },
        );
    }
    let mut owner = Kv2 {
        entries: BTreeMap::from([("retained".into(), Entry::from(entry))]),
        ..Kv2::default()
    };
    let (_, mut restored) = reopened(&owner)?;
    assert_eq!(
        restored
            .entries
            .get("retained")
            .ok_or("retained")?
            .versions
            .len(),
        10_000
    );
    compare_write(
        &mut owner,
        &mut restored,
        "POST",
        "data/retained",
        &json!({"data":{"next":true}}),
        at(102, 37)?,
    )?;
    let retained = restored.entries.get("retained").ok_or("retained")?;
    assert_eq!(retained.versions.len(), 10_000);
    assert_eq!(retained.oldest_version, 2);
    assert!(!retained.versions.contains_key(&1));
    // Sparse histories use the same EntryState and precise metadata, rather
    // than the QA shard contract's contiguous artificial version array.
    owner
        .entries
        .get_mut("retained")
        .ok_or("retained")?
        .versions
        .retain(|number, _| matches!(number, 2 | 5000 | 10_001));
    owner
        .entries
        .get_mut("retained")
        .ok_or("retained")?
        .precision
        .versions
        .retain(|number, _| *number == 10_001);
    let (_, sparse) = reopened(&owner)?;
    assert_eq!(
        sparse
            .entries
            .get("retained")
            .ok_or("retained")?
            .versions
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![2, 5000, 10_001]
    );
    for number in [1, 2, 3, 5000, 10_000, 10_001] {
        compare_read(
            &owner,
            &sparse,
            "GET",
            "data/retained",
            &json!({"version":number}),
            at(103, 0)?,
        )?;
    }
    compare_read(
        &owner,
        &sparse,
        "GET",
        "metadata/retained",
        &json!({}),
        at(103, 0)?,
    )?;
    Ok(())
}

#[test]
fn scheduled_soft_deletion_source_deadline_and_precision_survive_native_records() -> TestResult {
    let mut owner = Kv2::default();
    owner.handle_precise(
        "POST",
        "data/scheduled",
        &json!({"data":{"value":"retained"}}),
        at(100, 7)?,
    )?;
    let entry = owner.entries.get_mut("scheduled").ok_or("scheduled")?;
    entry.config.delete_version_after = 7200;
    entry.config.delete_version_after_nanos = 500_000_000;
    entry.versions.get_mut(&1).ok_or("version")?.deletion_at = Some(120);
    entry
        .precision
        .versions
        .get_mut(&1)
        .ok_or("precision")?
        .deletion_at = Some(at(120, 500_000_001)?);
    entry
        .precision
        .versions
        .get_mut(&1)
        .ok_or("precision")?
        .source_deletion_at = Some(at(7300, 500_000_007)?);
    let (_, mut restored) = reopened(&owner)?;
    for nanos in [500_000_000, 500_000_001] {
        compare_read(
            &owner,
            &restored,
            "GET",
            "data/scheduled",
            &json!({}),
            at(120, nanos)?,
        )?;
    }
    compare_write(
        &mut owner,
        &mut restored,
        "POST",
        "undelete/scheduled",
        &json!({"versions":[1]}),
        at(121, 99)?,
    )?;
    compare_read(
        &owner,
        &restored,
        "GET",
        "metadata/scheduled",
        &json!({}),
        at(121, 100)?,
    )?;
    let (_, reopened) = reopened(&restored)?;
    compare_read(
        &restored,
        &reopened,
        "GET",
        "data/scheduled",
        &json!({}),
        at(7321, 500_000_098)?,
    )?;
    compare_read(
        &restored,
        &reopened,
        "GET",
        "data/scheduled",
        &json!({}),
        at(7321, 500_000_099)?,
    )?;
    Ok(())
}

fn small_owner() -> TestResult<Kv2> {
    let mut owner = Kv2::default();
    owner.handle_precise(
        "POST",
        "data/item",
        &json!({"data":{"secret":"payload"}}),
        at(10, 7)?,
    )?;
    Ok(owner)
}
fn replace(graph: &mut NativeGraph, key: Kv1Key, bytes: Option<&[u8]>) -> TestResult {
    graph.index = graph.index.edit(key, bytes)?.next;
    Ok(())
}
fn assert_open_error(graph: &NativeGraph, expected: RecordError) -> TestResult {
    let objects = GraphObjects::from_index(&graph.index)?;
    match NativeGraph::open(&base(), scope(), graph.index.root(), &objects) {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => return Err("hostile native graph was accepted".into()),
    }
    Ok(())
}

#[test]
fn native_graph_rejects_missing_payload_orphan_noncanonical_and_inline_data() -> TestResult {
    let owner = small_owner()?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let pinned = NativeGraph {
        scope: graph.scope.clone(),
        key: Arc::clone(&graph.key),
        index: graph.index.clone(),
        format: graph.format.clone(),
        paged: graph.paged.clone(),
    };
    let payload = payload_key(&graph.scope, &graph.key, "item", 1)?;
    replace(&mut graph, payload, None)?;
    assert_open_error(&graph, RecordError::Missing)?;
    assert_eq!(
        serialize(&pinned.decode()?, MAX_GRAPH_BYTES)?,
        serialize(&owner, MAX_GRAPH_BYTES)?
    );
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let config = graph.scope.key("config")?;
    replace(&mut graph, config, None)?;
    assert_open_error(&graph, RecordError::Missing)?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let orphan = payload_key(&graph.scope, &graph.key, "item", 2)?;
    replace(&mut graph, orphan, Some(br#"{"orphan":true}"#))?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let payload = payload_key(&graph.scope, &graph.key, "item", 1)?;
    replace(&mut graph, payload, Some(br#"{ "secret":"payload"}"#))?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let record = metadata_key(&graph.scope, &graph.key, "item")?;
    let mut cell: PathCell = canonical(
        graph.index.get(&record).ok_or("metadata")?,
        MAX_METADATA_BYTES,
    )?;
    cell.metadata.versions.get_mut(&1).ok_or("version")?.data =
        Some(SharedJson::from(SecretJson(json!({"inline":"forbidden"}))));
    let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
    replace(&mut graph, record, Some(&bytes))?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let record = metadata_key(&graph.scope, &graph.key, "item")?;
    let mut cell: PathCell = canonical(
        graph.index.get(&record).ok_or("metadata")?,
        MAX_METADATA_BYTES,
    )?;
    cell.metadata.versions.clear();
    cell.metadata.precision.versions.clear();
    cell.payload_versions.clear();
    let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
    replace(&mut graph, record, Some(&bytes))?;
    let payload = payload_key(&graph.scope, &graph.key, "item", 1)?;
    replace(&mut graph, payload, None)?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    Ok(())
}

#[test]
fn native_graph_binds_secret_parent_scope_and_canonical_path_identity() -> TestResult {
    let owner = small_owner()?;
    let graph = NativeGraph::encode(&owner, &base(), scope())?;
    let other = NativeGraph::encode(&owner, &AddressKey::from_bytes([62; 32]), scope())?;
    assert_ne!(graph.index.root(), other.index.root());
    let objects = GraphObjects::from_index(&graph.index)?;
    for wrong in [
        NativeScope {
            namespace: "team-b",
            ..scope()
        },
        NativeScope {
            mount: "other/",
            ..scope()
        },
        NativeScope {
            incarnation: 8,
            ..scope()
        },
    ] {
        assert!(NativeGraph::open(&base(), wrong, graph.index.root(), &objects).is_err());
    }
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let record = metadata_key(&graph.scope, &graph.key, "item")?;
    let mut cell: PathCell = canonical(
        graph.index.get(&record).ok_or("metadata")?,
        MAX_METADATA_BYTES,
    )?;
    cell.scope.namespace = "team-b".into();
    let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
    replace(&mut graph, record, Some(&bytes))?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    let mut graph = NativeGraph::encode(&owner, &base(), scope())?;
    let record = metadata_key(&graph.scope, &graph.key, "item")?;
    let mut cell: PathCell = canonical(
        graph.index.get(&record).ok_or("metadata")?,
        MAX_METADATA_BYTES,
    )?;
    cell.path = "other".into();
    let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
    replace(&mut graph, record, Some(&bytes))?;
    assert_open_error(&graph, RecordError::Corrupt)?;
    Ok(())
}

#[test]
fn keyed_object_reopening_rejects_missing_and_changed_objects() -> TestResult {
    let graph = NativeGraph::encode(&small_owner()?, &base(), scope())?;
    let mut objects = GraphObjects::from_index(&graph.index)?;
    let root = graph.index.root();
    let root_id = root.reference.as_ref().ok_or("root")?.id;
    objects.0.remove(&root_id);
    assert!(matches!(
        NativeGraph::open(&base(), scope(), root.clone(), &objects),
        Err(RecordError::Missing)
    ));
    struct Changed<'a>(&'a GraphObjects);
    impl RecordReader for Changed<'_> {
        fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
            let mut bytes = self.0.read_object(reference)?;
            let last = bytes.last_mut().ok_or(RecordError::Corrupt)?;
            *last ^= 1;
            Ok(bytes)
        }
    }
    let objects = GraphObjects::from_index(&graph.index)?;
    assert!(matches!(
        NativeGraph::open(&base(), scope(), root, &Changed(&objects)),
        Err(RecordError::Corrupt)
    ));
    Ok(())
}

#[test]
fn native_verifier_preflights_scope_container_and_aggregate_bounds() -> TestResult {
    assert_eq!(
        verify_native_owner_records(
            b"unparsed",
            &[61; 32],
            NativeScope {
                mount: "",
                ..scope()
            }
        )
        .err(),
        Some(FoundationError::Invalid)
    );
    let owner = small_owner()?;
    let bytes = serialize(&owner, MAX_GRAPH_BYTES)?;
    let mut padded = Zeroizing::new(bytes.to_vec());
    padded.push(b' ');
    assert_eq!(
        verify_native_owner_records(&padded, &[61; 32], scope()).err(),
        Some(FoundationError::Corrupt)
    );
    let oversized = Zeroizing::new(vec![b' '; MAX_GRAPH_BYTES + 1]);
    assert_eq!(
        verify_native_owner_records(&oversized, &[61; 32], scope()).err(),
        Some(FoundationError::TooLarge)
    );
    let mut many = String::from("{\"entries\":{");
    for n in 0..=MAX_PATHS {
        if n > 0 {
            many.push(',');
        }
        many.push_str(&format!("\"path-{n}\":null"));
    }
    many.push_str("}}");
    assert!(preflight_owner(many.as_bytes()).is_err());
    many.zeroize();
    let mut versions = String::from("{\"versions\":{");
    for n in 1..=MAX_RETAINED_VERSIONS + 1 {
        if n > 1 {
            versions.push(',');
        }
        versions.push_str(&format!("\"{n}\":null"));
    }
    versions.push_str("}}");
    let raw: &serde_json::value::RawValue = serde_json::from_str(&versions)?;
    assert!(preflight_entry(raw).is_err());
    versions.zeroize();
    let version_map = (1..=10_000)
        .map(|n| format!("\"{n}\":null"))
        .collect::<Vec<_>>()
        .join(",");
    let entry = format!("{{\"versions\":{{{version_map}}}}}");
    let entries = (0..10)
        .map(|n| format!("\"path-{n}\":{entry}"))
        .collect::<Vec<_>>()
        .join(",");
    let aggregate = format!("{{\"entries\":{{{entries}}}}}");
    assert_eq!(
        preflight_owner(aggregate.as_bytes()),
        Err(RecordError::TooLarge)
    );
    let mut invalid = owner;
    invalid
        .entries
        .get_mut("item")
        .ok_or("item")?
        .precision
        .versions
        .insert(
            2,
            VersionPrecision {
                created_at: Some(at(10, 3)?),
                ..VersionPrecision::default()
            },
        );
    assert!(matches!(
        NativeGraph::encode(&invalid, &base(), scope()),
        Err(RecordError::Corrupt)
    ));
    Ok(())
}

#[test]
fn native_record_keys_preserve_full_runtime_path_scope_limits() -> TestResult {
    let path = "p".repeat(1024);
    let namespace = "n".repeat(1024);
    let mount = "m".repeat(1024);
    let scope = NativeScope {
        namespace: &namespace,
        mount: &mount,
        incarnation: u64::MAX,
    };
    let mut owner = Kv2::default();
    owner.handle_precise(
        "POST",
        &format!("data/{path}"),
        &json!({"data":{"full":"path"}}),
        at(10, 1)?,
    )?;
    let graph = NativeGraph::encode(&owner, &base(), scope)?;
    let objects = GraphObjects::from_index(&graph.index)?;
    let restored = NativeGraph::open(&base(), scope, graph.index.root(), &objects)?.decode()?;
    compare_read(
        &owner,
        &restored,
        "GET",
        &format!("data/{path}"),
        &json!({}),
        at(11, 0)?,
    )?;
    let oversized_mount = "m".repeat(1025);
    assert_eq!(
        verify_native_owner_records(
            b"unparsed",
            &[61; 32],
            NativeScope {
                mount: &oversized_mount,
                ..scope
            }
        )
        .err(),
        Some(FoundationError::Invalid)
    );
    Ok(())
}

#[test]
fn native_raw_owner_and_payloads_preserve_exact_user_transport_tag_objects() -> TestResult {
    for raw in [
        br#"{"$serde_json::private::Number":"7"}"#.as_slice(),
        br#"{"\u0024serde_json::private::Number":"7"}"#,
        br#"{"$serde_json::private::Number":"not a number"}"#,
        br#"{"$serde_json::private::RawValue":"[1]"}"#,
        br#"{"$serde_json::private::RawValue":"not JSON"}"#,
        br#"{"number":184467440737095516160001,"decimal":0.12345678901234567890123456789,"fake":{"$serde_json::private::Number":"7"},"bad":{"$serde_json::private::Number":"bad"},"raw":{"$serde_json::private::RawValue":"[1]"}}"#,
    ] {
        let payload=lossless::decode_lossless_json(raw)?;
        assert!(payload.is_object());
        let mut owner=Kv2::default();
        owner.handle("POST","data/tags",&json!({"data":payload}),10)?;
        owner.validate_lossless_state()?;
        let bytes=serialize(&owner,MAX_GRAPH_BYTES)?;
        let actual:Kv2=serde_json::from_slice(&bytes)?;
        actual.validate_lossless_state()?;
        let receipt=verify_native_owner_records(&bytes,&[61;32],scope())?;
        assert_eq!(receipt.payload_records,1);
        let (_,restored)=reopened(&actual)?;
        let response=restored.handle_read("GET","data/tags",&json!({}),11)?;
        assert_eq!(response.body["data"]["data"],payload);
        assert!(response.body["data"]["data"].is_object());
        if let Some(fake)=payload.get("fake") {
            assert!(fake.is_object());
            assert_eq!(response.body["data"]["data"]["fake"],*fake);
            assert!(response.body["data"]["data"]["bad"].is_object());
            assert!(response.body["data"]["data"]["raw"].is_object());
            assert!(response.body["data"]["data"]["number"].is_number());
        }
    }
    Ok(())
}

#[test]
fn native_owner_rejects_missing_sticky_format_and_invalid_precision_like_actual_kv2() -> TestResult
{
    for payload in [
        lossless::decode_lossless_json(br#"{"$serde_json::private::Number":"7"}"#)?,
        lossless::decode_lossless_json(br#"{"big":184467440737095516160001}"#)?,
    ] {
        let mut owner = Kv2::default();
        owner.handle("POST", "data/item", &json!({"data":payload}), 10)?;
        owner.validate_lossless_state()?;
        assert_eq!(owner.lossless_format, Some(1));
        owner.lossless_format = None;
        assert!(owner.validate_lossless_state().is_err());
        let bytes = serialize(&owner, MAX_GRAPH_BYTES)?;
        assert_eq!(
            verify_native_owner_records(&bytes, &[61; 32], scope()).err(),
            Some(FoundationError::Corrupt)
        );
    }
    for inconsistent in [at(11, 7)?, at(10, 0)?] {
        let mut owner = small_owner()?;
        owner
            .entries
            .get_mut("item")
            .ok_or("item")?
            .precision
            .created_at = Some(inconsistent);
        assert!(owner.validate_lossless_state().is_err());
        let bytes = serialize(&owner, MAX_GRAPH_BYTES)?;
        assert_eq!(
            verify_native_owner_records(&bytes, &[61; 32], scope()).err(),
            Some(FoundationError::Corrupt)
        );
    }
    let mut owner = small_owner()?;
    owner
        .entries
        .get_mut("item")
        .ok_or("item")?
        .precision
        .versions
        .get_mut(&1)
        .ok_or("precision")?
        .deletion_at = Some(at(12, 1)?);
    assert!(owner.validate_lossless_state().is_err());
    let bytes = serialize(&owner, MAX_GRAPH_BYTES)?;
    assert_eq!(
        verify_native_owner_records(&bytes, &[61; 32], scope()).err(),
        Some(FoundationError::Corrupt)
    );
    Ok(())
}
