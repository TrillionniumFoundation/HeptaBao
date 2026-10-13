//! Real root roles, actual protected owners and native graph logical reads.
use super::*;
use crate::state_record_root::{OpaqueOwnerRef, RecordStateRoot, StateIdentity};
use crate::state_record_root_v6::{AddressMaterial, OwnerDomain, ReaderFloor, RoleOwner};
use crate::state_records::{Kv1Root, StagedObject};
use crate::v6_read_validation::{EncodedDomain, EncodedObject, ReadIdentity};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct Source(BTreeMap<(ObjectDomain, ObjectId), Zeroizing<Vec<u8>>>);
impl ObjectSource for Source {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.0
            .get(&(domain.clone(), reference.id))
            .cloned()
            .ok_or(RecordError::Missing)
    }
    fn object_count(&self) -> Option<usize> {
        Some(self.0.len())
    }
}
impl Source {
    fn stage(&mut self, domain: ObjectDomain, object: &StagedObject) {
        self.0.insert(
            (domain, object.reference().id),
            Zeroizing::new(object.bytes().to_vec()),
        );
    }
    fn encoded(&self) -> Vec<EncodedObject<'_>> {
        self.0
            .iter()
            .map(|((domain, id), bytes)| EncodedObject {
                domain: match domain {
                    ObjectDomain::Owner(role) => EncodedDomain::Owner(*role),
                    ObjectDomain::Kv1 => EncodedDomain::Kv1,
                    ObjectDomain::Kv2(scope) => EncodedDomain::Kv2(scope.borrowed()),
                },
                id: *id.bytes(),
                bytes,
            })
            .collect()
    }
}
struct Fixture {
    root: RecordStateRootV6,
    source: Source,
    logical: EngineState,
}
impl Fixture {
    fn context(&self) -> TestResult<ReadContext<'_>> {
        let StateIdentity::RecordsV6(identity) = self.root.identity().map_err(|_| "identity")?
        else {
            return Err("identity kind".into());
        };
        Ok(ReadContext {
            expected_identity: ReadIdentity::RecordsV6(identity),
            cluster_id: &self.root.cluster_id,
            replay_epoch: self.root.replay_epoch,
            minimum_state_schema: self.root.state_schema,
            maximum_state_schema: 132,
            reader_format: 6,
        })
    }
}
fn fixture(large: bool) -> TestResult<Fixture> {
    let mut logical = EngineState::default();
    logical
        .handle(
            "",
            "POST",
            "sys/mounts/raw",
            &json!({"type":"kv","options":{"version":"1"}}),
            100,
        )?
        .ok_or("KV1 mount")?;
    logical
        .handle(
            "",
            "PUT",
            "raw/item",
            &json!({"nested":[false,null,{"value":"native KV1 closure"}]}),
            100,
        )?
        .ok_or("KV1 write")?;
    logical
        .handle(
            "",
            "POST",
            "secret/config",
            &json!({"max_versions":100}),
            100,
        )?
        .ok_or("config")?;
    for version in 1..=if large { 16 } else { 2 } {
        let data = if large {
            let mut blob = String::with_capacity(2560 * 1024);
            for chunk in 0..640 {
                let marker = format!("v{version:04}/chunk{chunk:04}/");
                blob.push_str(&marker);
                blob.extend(std::iter::repeat_n('x', 4096 - marker.len()));
            }
            json!({"blob":blob,"version":version,"nested":[true,null,{"integer":version}]})
        } else {
            json!({"version":version,"nested":{"number":3}})
        };
        logical
            .handle(
                "",
                "POST",
                "secret/data/item",
                &json!({"data":data}),
                100 + version,
            )?
            .ok_or("write")?;
    }
    let mut root = RecordStateRootV6 {
        storage_format: crate::state_record_root_v6::STORAGE_FORMAT.into(),
        state_schema: 65,
        reader_floor: ReaderFloor {
            record_format: 6,
            minimum_state_schema: 65,
            native_kv2_format: 1,
        },
        global_lossless_json_format: None,
        cluster_id: "v6-reader-fixture".into(),
        replay_epoch: 7,
        owners: OwnerDomain::ALL.map(|domain| RoleOwner {
            domain,
            owner: OpaqueOwnerRef {
                name: domain.name().into(),
                total_bytes: 0,
                chunks: Vec::new(),
                digest: [0; 32],
            },
        }),
        kv1: Kv1Root::default(),
        kv2: Vec::new(),
        object_address_key: AddressMaterial([71; 32]),
    };
    let recorded = logical.migrate_kv1_records(root.kv1_key().map_err(|_| "key")?)?;
    root.kv1 = recorded.record_root().ok_or("kv1 root")?;
    let mut source = Source::default();
    recorded.visit_record_objects(|object| {
        source.stage(ObjectDomain::Kv1, object);
        Ok(())
    })?;
    let parent = root.kv2_parent_key().map_err(|_| "key")?;
    let native = crate::engines::kv2_native_records::reader_fixture(&recorded, &parent)?;
    root.kv2 = native.roots;
    for (scope, object) in native.objects {
        source.stage(ObjectDomain::Kv2(scope), &object);
    }
    let engine = EngineMetadata {
        format: ENGINE_FORMAT.into(),
        opaque: native.opaque,
        kv2_scopes: root.kv2.iter().map(|graph| graph.scope.clone()).collect(),
    };
    let (auth, token) = AuthState::bootstrap(100)?;
    let _token = Zeroizing::new(token);
    let owners = [
        owner_store::serialize_owner(&namespaces::NamespaceRegistry::default())?,
        owner_store::serialize_owner(&auth)?,
        owner_store::serialize_owner(&engine)?,
        owner_store::serialize_owner(&database::DatabaseState::default())?,
        owner_store::serialize_owner(&raft_admin::RaftAdminState::default())?,
    ];
    for (index, bytes) in owners.iter().enumerate() {
        let domain = OwnerDomain::ALL[index];
        let key = root.owner_key(domain).map_err(|_| "key")?;
        let mut refs = Vec::new();
        for chunk in bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
            let object = StagedObject::owner_chunk(&key, chunk)?;
            source.stage(ObjectDomain::Owner(domain), &object);
            refs.push(object.reference().clone());
        }
        root.owners[index].owner = OpaqueOwnerRef {
            name: domain.name().into(),
            total_bytes: bytes.len() as u64,
            chunks: refs,
            digest: root.owner_digest(domain, bytes).map_err(|_| "digest")?,
        };
    }
    root.validate().map_err(|_| "root")?;
    Ok(Fixture {
        root,
        source,
        logical,
    })
}

#[test]
fn v6_full_root_reads_real_40_mib_kv2_history_with_exact_logical_responses() -> TestResult {
    let fixture = fixture(true)?;
    let state = materialize(&fixture.root, fixture.context()?, &fixture.source)?;
    let actual_kv1 = state.protected.engines.handle_immutable_kv_read(
        "",
        "GET",
        "raw/item",
        &json!({}),
        1000,
    )?;
    let expected_kv1 =
        fixture
            .logical
            .handle_immutable_kv_read("", "GET", "raw/item", &json!({}), 1000)?;
    assert_eq!(actual_kv1.status, expected_kv1.status);
    assert_eq!(actual_kv1.body, expected_kv1.body);
    let scope = fixture.root.kv2.first().ok_or("scope")?.scope.clone();
    let view = state.native.get(&scope).ok_or("view")?;
    for version in [1, 6, 7, 16] {
        let actual = view.read(
            "GET",
            "data/item",
            &json!({"version":version}),
            crate::auth::Timestamp::whole(1000)?,
        )?;
        let mut source = fixture.logical.clone();
        let expected = source
            .handle(
                "",
                "GET",
                "secret/data/item",
                &json!({"version":version}),
                1000,
            )?
            .ok_or("read")?;
        assert_eq!(actual.status, expected.status);
        assert_eq!(actual.body, expected.body);
    }
    for (method, path) in [
        ("GET", "metadata/item"),
        ("GET", "config"),
        ("GET", "subkeys/item"),
        ("LIST", "metadata"),
        ("SCAN", "metadata"),
    ] {
        let actual = view.read(
            method,
            path,
            &json!({}),
            crate::auth::Timestamp::whole(1000)?,
        )?;
        let mut source = fixture.logical.clone();
        let expected = source
            .handle("", method, &format!("secret/{path}"), &json!({}), 1000)?
            .ok_or("read")?;
        assert_eq!(actual.body, expected.body);
    }
    let receipt = crate::v6_read_validation::inspect_v6_records(
        &fixture.root.encode().map_err(|_| "encode")?,
        fixture.context()?,
        &fixture.source.encoded(),
    )?;
    assert_eq!(receipt.retained_versions, 16);
    assert!(receipt.encoded_bytes_read > 40 * 1024 * 1024);
    assert!(!receipt.service_reader_admitted);
    assert!(!receipt.production_writer_admitted);
    assert!(!receipt.migration_admitted);
    eprintln!(
        "stage-b-only versions={} objects={} encoded_bytes={} service_reader_admitted=false",
        receipt.retained_versions, receipt.objects_read, receipt.encoded_bytes_read
    );
    Ok(())
}

#[test]
fn v6_frontier_and_reader_floor_reject_before_any_object_read() -> TestResult {
    let fixture = fixture(false)?;
    struct NoRead;
    impl ObjectSource for NoRead {
        fn read(&self, _: &ObjectDomain, _: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
            Err(RecordError::Missing)
        }
    }
    let good = fixture.context()?;
    for bad in [
        ReadContext {
            cluster_id: "wrong",
            ..good
        },
        ReadContext {
            replay_epoch: 6,
            ..good
        },
        ReadContext {
            expected_identity: ReadIdentity::RecordsV5(
                fixture.root.identity().map_err(|_| "id")?.digest(),
            ),
            ..good
        },
        ReadContext {
            expected_identity: ReadIdentity::RecordsV6([0; 32]),
            ..good
        },
    ] {
        assert!(matches!(
            materialize(&fixture.root, bad, &NoRead),
            Err(ReadError::Authentication)
        ));
    }
    for bad in [
        ReadContext {
            reader_format: 5,
            ..good
        },
        ReadContext {
            maximum_state_schema: 64,
            ..good
        },
        ReadContext {
            minimum_state_schema: 66,
            ..good
        },
    ] {
        assert!(matches!(
            materialize(&fixture.root, bad, &NoRead),
            Err(ReadError::ReaderFloor)
        ));
    }
    Ok(())
}

#[test]
fn v6_canonical_closed_shape_and_service_default_are_distinct_from_v5() -> TestResult {
    let fixture = fixture(false)?;
    let bytes = fixture.root.encode().map_err(|_| "encode")?;
    assert!(RecordStateRoot::decode(&bytes).is_err());
    let decoded = RecordStateRootV6::decode(&bytes).map_err(|_| "decode")?;
    assert_eq!(decoded.encode().map_err(|_| "encode")?, bytes);
    assert_eq!(
        records::decode_root(&bytes).err().ok_or("closed")?.status,
        503
    );
    for length in [0, 1, bytes.len() - 1] {
        assert!(RecordStateRootV6::decode(&bytes[..length]).is_err());
    }
    let mut padded = bytes.to_vec();
    padded.push(b' ');
    assert!(RecordStateRootV6::decode(&padded).is_err());
    let mut value: Value = serde_json::from_slice(&bytes)?;
    value.as_object_mut().ok_or("object")?.remove("kv2");
    assert!(RecordStateRootV6::decode(&serde_json::to_vec(&value)?).is_err());
    value = serde_json::from_slice(&bytes)?;
    value["unknown"] = json!(true);
    assert!(RecordStateRootV6::decode(&serde_json::to_vec(&value)?).is_err());
    value = serde_json::from_slice(&bytes)?;
    value["storage_format"] = json!(crate::state_record_root::STORAGE_FORMAT);
    assert!(RecordStateRoot::decode(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn v6_rejects_missing_wrong_domain_and_tampered_graph_objects() -> TestResult {
    let mut fixture = fixture(false)?;
    let scope = fixture.root.kv2[0].scope.clone();
    let id = fixture.root.kv2[0]
        .root
        .reference
        .as_ref()
        .ok_or("root")?
        .id;
    let original = fixture
        .source
        .0
        .remove(&(ObjectDomain::Kv2(scope.clone()), id))
        .ok_or("object")?;
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Missing)
    ));
    fixture
        .source
        .0
        .insert((ObjectDomain::Kv1, id), original.clone());
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Missing)
    ));
    fixture.source.0.remove(&(ObjectDomain::Kv1, id));
    let mut corrupted = original;
    *corrupted.last_mut().ok_or("bytes")? ^= 1;
    fixture
        .source
        .0
        .insert((ObjectDomain::Kv2(scope), id), corrupted);
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Authentication)
    ));
    Ok(())
}

#[test]
fn v6_nonempty_kv1_graph_cannot_be_missing_or_reused_in_a_native_kv2_domain() -> TestResult {
    let mut fixture = fixture(false)?;
    let id = fixture.root.kv1.reference.as_ref().ok_or("KV1 root")?.id;
    let original = fixture
        .source
        .0
        .remove(&(ObjectDomain::Kv1, id))
        .ok_or("KV1 object")?;
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Missing)
    ));
    fixture.source.0.insert(
        (ObjectDomain::Kv2(fixture.root.kv2[0].scope.clone()), id),
        original,
    );
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Missing)
    ));
    Ok(())
}

#[test]
fn v6_roles_floor_mount_incarnation_and_missing_graph_fail_closed() -> TestResult {
    let fixture = fixture(false)?;
    let mut root = fixture.root.clone();
    root.owners[0].domain = OwnerDomain::Auth;
    assert!(root.validate().is_err());
    let mut root = fixture.root.clone();
    root.reader_floor.record_format = 5;
    assert!(root.validate().is_err());
    let mut root = fixture.root.clone();
    root.reader_floor.minimum_state_schema = 66;
    assert!(root.validate().is_err());
    let mut root = fixture.root.clone();
    root.kv2[0].root = Kv1Root::default();
    assert!(root.validate().is_err());
    let mut root = fixture.root.clone();
    root.kv2[0].scope.incarnation += 1;
    let StateIdentity::RecordsV6(id) = root.identity().map_err(|_| "id")? else {
        return Err("id kind".into());
    };
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(id),
        ..fixture.context()?
    };
    assert!(matches!(
        materialize(&root, context, &fixture.source),
        Err(ReadError::Invalid) | Err(ReadError::State)
    ));
    let mut root = fixture.root.clone();
    root.kv2.clear();
    let StateIdentity::RecordsV6(id) = root.identity().map_err(|_| "id")? else {
        return Err("id kind".into());
    };
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(id),
        ..fixture.context()?
    };
    assert!(matches!(
        materialize(&root, context, &fixture.source),
        Err(ReadError::Invalid) | Err(ReadError::State)
    ));
    Ok(())
}

#[test]
fn v5_golden_encoding_identity_and_dispatch_are_exactly_preserved() -> TestResult {
    let bytes = include_bytes!("testdata/state-v5-canonical-golden.json");
    let root = RecordStateRoot::decode(bytes).map_err(|_| "v5 decode")?;
    assert_eq!(root.encode().map_err(|_| "v5 encode")?.as_slice(), bytes);
    assert_eq!(
        root.identity().map_err(|_| "v5 identity")?,
        StateIdentity::RecordsV5([
            195, 86, 182, 67, 108, 217, 164, 63, 46, 213, 46, 107, 25, 88, 229, 207, 150, 165, 251,
            85, 176, 255, 226, 235, 16, 166, 126, 110, 192, 140, 66, 139,
        ])
    );
    let identity = root.identity().map_err(|_| "identity")?;
    let serialized = serde_json::to_vec(&identity)?;
    assert!(std::str::from_utf8(&serialized)?.starts_with("{\"kind\":\"records_v5\",\"digest\":"));
    assert_eq!(
        serde_json::from_slice::<StateIdentity>(&serialized)?,
        identity
    );
    assert_ne!(identity, StateIdentity::RecordsV6(identity.digest()));
    assert!(
        records::decode_root(bytes)
            .map_err(|_| "v5 dispatch")?
            .is_some()
    );
    assert!(RecordStateRootV6::decode(bytes).is_err());
    let future = std::str::from_utf8(bytes)?
        .replace("heptabao-state-records-v5", "heptabao-state-records-v7");
    assert_eq!(
        records::decode_root(future.as_bytes())
            .err()
            .ok_or("future rejected")?
            .status,
        503
    );
    Ok(())
}

#[test]
fn v6_public_object_frame_rejects_duplicate_and_orphan_rows() -> TestResult {
    let fixture = fixture(false)?;
    let bytes = fixture.root.encode().map_err(|_| "encode")?;
    let mut input = fixture.source.encoded();
    let extra = input.first().ok_or("object")?.bytes;
    let first = input.first().ok_or("object")?;
    input.push(EncodedObject {
        domain: first.domain,
        id: first.id,
        bytes: first.bytes,
    });
    assert_eq!(
        crate::v6_read_validation::inspect_v6_records(&bytes, fixture.context()?, &input).err(),
        Some(ReadError::Invalid)
    );
    let mut input = fixture.source.encoded();
    input.push(EncodedObject {
        domain: EncodedDomain::Owner(OwnerDomain::Auth),
        id: [0; 32],
        bytes: extra,
    });
    assert_eq!(
        crate::v6_read_validation::inspect_v6_records(&bytes, fixture.context()?, &input).err(),
        Some(ReadError::Invalid)
    );
    Ok(())
}

#[test]
fn v6_owner_object_references_cannot_be_reused_across_protected_roles() -> TestResult {
    let mut fixture = fixture(false)?;
    let auth = fixture.root.owners[1].owner.clone();
    let reference = auth.chunks.first().ok_or("auth")?.clone();
    let bytes = fixture
        .source
        .read(&ObjectDomain::Owner(OwnerDomain::Auth), &reference)?;
    fixture.root.owners[0].owner.total_bytes = auth.total_bytes;
    fixture.root.owners[0].owner.chunks = auth.chunks;
    fixture.root.owners[0].owner.digest = fixture
        .root
        .owner_digest(OwnerDomain::Namespaces, &bytes)
        .map_err(|_| "digest")?;
    fixture.source.0.insert(
        (ObjectDomain::Owner(OwnerDomain::Namespaces), reference.id),
        bytes,
    );
    assert!(matches!(
        materialize(&fixture.root, fixture.context()?, &fixture.source),
        Err(ReadError::Authentication)
    ));
    Ok(())
}

#[test]
fn v6_metadata_cannot_use_legacy_implicit_root_namespace_defaults() -> TestResult {
    let fixture = fixture(false)?;
    let scopes: Vec<_> = fixture
        .root
        .kv2
        .iter()
        .map(|graph| graph.scope.clone())
        .collect();
    assert!(
        EngineState::default()
            .validate_v6_kv2_placeholders(&scopes)
            .is_err()
    );
    assert!(
        fixture
            .logical
            .validate_v6_kv2_placeholders(&scopes)
            .is_err()
    );
    Ok(())
}

#[test]
fn v6_borrowed_metadata_preflight_rejects_opaque_payloads_and_unbounded_scopes() -> TestResult {
    let fixture = fixture(false)?;
    let metadata = owner_bytes(
        &fixture.root,
        2,
        &fixture.source,
        &RefCell::new(Usage::default()),
    )?;
    preflight_metadata(&metadata)?;
    let opaque = owner_store::serialize_owner(&fixture.logical)?;
    assert!(crate::engines::kv2_native_records::preflight_v6_kv2_metadata(&opaque).is_err());
    let mut value: Value = serde_json::from_slice(&metadata)?;
    let scope = value["kv2_scopes"][0].clone();
    value["kv2_scopes"] =
        Value::Array(vec![scope; crate::state_record_root_v6::MAX_KV2_MOUNTS + 1]);
    let encoded = crate::secret_serde::to_vec(&value, MAX_STATE_BYTES).map_err(|_| "metadata")?;
    assert!(preflight_metadata(&encoded).is_err());
    let root_bytes = fixture.root.encode().map_err(|_| "root")?;
    let mut input = fixture.source.encoded();
    let bytes = input.first().ok_or("object")?.bytes;
    input.push(EncodedObject {
        domain: EncodedDomain::Kv2(crate::engines::kv2_native_records::NativeScope {
            namespace: "unowned",
            mount: "secret/",
            incarnation: 1,
        }),
        id: [1; 32],
        bytes,
    });
    assert_eq!(
        crate::v6_read_validation::inspect_v6_records(&root_bytes, fixture.context()?, &input)
            .err(),
        Some(ReadError::Invalid)
    );
    Ok(())
}

#[test]
fn v6_declared_graph_payload_and_record_budgets_fail_before_frame_copies() -> TestResult {
    let fixture = fixture(false)?;
    for kv1 in [true, false] {
        for count in [true, false] {
            let mut root = fixture.root.clone();
            if kv1 {
                root.kv1 = root.kv2[0].root.clone();
            }
            let graph = if kv1 {
                &mut root.kv1
            } else {
                &mut root.kv2[0].root
            };
            let reference = graph.reference.as_mut().ok_or("root")?;
            if count {
                reference.record_count = if kv1 { 1_048_577 } else { 100_001 };
            } else {
                reference.payload_bytes = crate::state_records::MAX_GRAPH_BYTES as u64 + 1;
            }
            assert_eq!(
                root.validate().err(),
                Some(crate::state_record_root::RootError::TooLarge)
            );
            let encoded =
                crate::secret_serde::to_vec(&root, crate::state_record_root::MAX_ROOT_BYTES)
                    .map_err(|_| "root")?;
            assert_eq!(
                crate::v6_read_validation::inspect_v6_records(&encoded, fixture.context()?, &[])
                    .err(),
                Some(ReadError::TooLarge)
            );
        }
    }
    Ok(())
}
