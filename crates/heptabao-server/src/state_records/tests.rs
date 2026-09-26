#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;

#[derive(Default)]
struct MemoryObjects(BTreeMap<ObjectId, Zeroizing<Vec<u8>>>);
impl RecordReader for MemoryObjects {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>> {
        self.0
            .get(&reference.id)
            .cloned()
            .ok_or(RecordError::Missing)
    }
}
impl MemoryObjects {
    fn stage(&mut self, objects: &[Arc<StagedObject>]) {
        for object in objects {
            if let Some(previous) = self
                .0
                .insert(object.reference.id, Zeroizing::new(object.bytes().to_vec()))
            {
                assert_eq!(
                    previous.as_slice(),
                    object.bytes(),
                    "immutable address must never be replaced with different bytes"
                );
            }
        }
    }
}
fn address() -> Arc<AddressKey> {
    AddressKey::from_bytes([71; 32])
}
fn key(path: &str) -> Kv1Key {
    Kv1Key::new("root", "secret/", 1, path).expect("key")
}
fn scope() -> Kv1Scope {
    Kv1Scope::new("root", "secret/", 1).expect("scope")
}
fn put(index: &mut Kv1Index, store: &mut MemoryObjects, key: Kv1Key, value: &[u8]) {
    let edit = index.edit(key, Some(value)).expect("put");
    store.stage(&edit.objects);
    *index = edit.next;
}

#[test]
fn byte_bounded_splits_form_multiple_levels_and_reopen_in_tuple_order() {
    let address = address();
    let mut index = Kv1Index::empty(address.clone());
    let mut store = MemoryObjects::default();
    let namespace = "n".repeat(128);
    let mount = "m".repeat(128);
    let suffix = "p".repeat(945);
    // 700 distinct long keys force byte-based splits, including branch splits,
    // well before the independent 256-entry count bound.
    for n in (0..700).map(|n| (n * 251) % 700) {
        let path = format!("{n:04}-{suffix}");
        put(
            &mut index,
            &mut store,
            Kv1Key::new(&namespace, &mount, 1, &path).unwrap(),
            format!("value-{n}").as_bytes(),
        );
    }
    assert!(index.height >= 3);
    let root = index.root();
    let reopen = Kv1Index::open(address, root.clone(), &store).expect("all objects validated");
    assert_eq!(reopen.root(), root);
    let scope = Kv1Scope::new(&namespace, &mount, 1).unwrap();
    let mut cursor = None;
    let mut all = Vec::new();
    loop {
        let page = reopen
            .scan(&scope, "", cursor.as_deref(), 37, true)
            .unwrap();
        all.extend(page.keys);
        cursor = page.next_after;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(all.len(), 700);
    assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
    for n in 0..700 {
        let key = Kv1Key::new(&namespace, &mount, 1, &format!("{n:04}-{suffix}")).unwrap();
        assert_eq!(reopen.get(&key), Some(format!("value-{n}").as_bytes()));
    }
    index
        .visit_objects(|object| {
            object
                .reference
                .verify(&index.address_key, object.bytes())?;
            if matches!(
                object.reference.kind,
                ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf
            ) {
                assert!(object.bytes().len() <= PAGE_BYTES);
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn point_update_is_only_value_and_path_and_old_reader_survives_deleted_disk_objects() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for n in 0..1200 {
        put(
            &mut index,
            &mut store,
            key(&format!("key-{n:04}")),
            &vec![(n % 251) as u8; 4096],
        );
    }
    let pin = index.clone();
    let before = index.root();
    let edited = index.edit(key("key-0500"), Some(b"replacement")).unwrap();
    assert!(edited.changed);
    assert_eq!(pin.root(), before);
    assert_eq!(
        edited
            .objects
            .iter()
            .filter(|o| matches!(
                o.reference.kind,
                ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf
            ))
            .count(),
        index.height as usize
    );
    // The replacement is inline: only its packed leaf and ancestor path change.
    assert_eq!(edited.objects.len(), index.height as usize);
    assert!(
        edited
            .objects
            .iter()
            .map(|o| o.bytes().len())
            .sum::<usize>()
            <= index.height as usize * PAGE_BYTES + BLOCK_BYTES + HEADER_BYTES + REF_BYTES + 27
    );
    store.stage(&edited.objects);
    let reopened = Kv1Index::open(address(), edited.next.root(), &store).unwrap();
    assert_eq!(
        reopened.get(&key("key-0500")),
        Some(b"replacement".as_slice())
    );
    store.0.clear(); // Existing pins own data, not only IDs requiring lazy reads.
    assert_eq!(
        pin.get(&key("key-0500")),
        Some(vec![(500 % 251) as u8; 4096].as_slice())
    );
    assert_eq!(edited.next.get(&key("key-0501")), pin.get(&key("key-0501")));
    assert!(matches!(
        Kv1Index::open(address(), before, &store),
        Err(RecordError::Missing)
    ));
}

#[test]
fn shallow_cursor_skips_entire_subtrees_and_scope_incarnation_never_bleeds() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for path in [
        "a",
        "a/child",
        "a/deep/leaf",
        "a0",
        "b/一",
        "b/😀",
        "b/ё",
        "c",
    ] {
        let bytes = if path == "a/deep/leaf" {
            vec![b'x'; INLINE_VALUE_BYTES + 1]
        } else {
            b"{}".to_vec()
        };
        put(&mut index, &mut store, key(path), &bytes);
    }
    put(
        &mut index,
        &mut store,
        Kv1Key::new("root", "secret/", 2, "resurrected").unwrap(),
        b"{}",
    );
    put(
        &mut index,
        &mut store,
        Kv1Key::new("other", "secret/", 1, "foreign").unwrap(),
        b"{}",
    );
    assert_eq!(
        index.scan(&scope(), "", None, 4096, false).unwrap().keys,
        ["a", "a/", "a0", "b/", "c"]
    );
    let first = index.scan(&scope(), "", None, 2, false).unwrap();
    assert_eq!(first.keys, ["a", "a/"]);
    assert_eq!(first.next_after.as_deref(), Some("a/"));
    assert_eq!(
        index
            .scan(&scope(), "", first.next_after.as_deref(), 2, false)
            .unwrap()
            .keys,
        ["a0", "b/"]
    );
    assert_eq!(
        index.scan(&scope(), "b", None, 10, true).unwrap().keys,
        ["ё", "一", "😀"]
    );
    assert_eq!(
        index.scan(&scope(), "a", None, 10, false).unwrap().keys,
        ["child", "deep/"]
    );
    assert!(index.scan(&scope(), "", None, 0, false).is_err());
}

#[test]
fn delete_collapses_root_noops_keep_identity_and_export_excludes_temporary_pages() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for n in 0..600 {
        put(&mut index, &mut store, key(&format!("{n:04}")), b"same");
    }
    let pin = index.clone();
    let noop = index.edit(key("0001"), Some(b"same")).unwrap();
    assert!(!noop.changed);
    assert!(noop.objects.is_empty());
    assert_eq!(noop.next.root(), index.root());
    let missing = index.edit(key("absent"), None).unwrap();
    assert!(!missing.changed);
    for n in 0..600 {
        let edit = index.edit(key(&format!("{n:04}")), None).unwrap();
        let mut reachable = BTreeSet::new();
        edit.next
            .visit_objects(|o| {
                reachable.insert(o.reference.id);
                Ok(())
            })
            .unwrap();
        assert!(
            edit.objects
                .iter()
                .all(|o| reachable.contains(&o.reference.id))
        );
        store.stage(&edit.objects);
        index = edit.next;
        if n % 97 == 0 {
            let reopened = Kv1Index::open(address(), index.root(), &store).unwrap();
            assert!(reopened.get(&key(&format!("{n:04}"))).is_none());
            assert_eq!(reopened.get(&key("0599")), Some(b"same".as_slice()));
        }
    }
    assert_eq!(index.root(), Kv1Root::default());
    assert!(
        Kv1Index::open(address(), index.root(), &store)
            .unwrap()
            .get(&key("0001"))
            .is_none()
    );
    assert_eq!(pin.get(&key("0001")), Some(b"same".as_slice()));
}

#[test]
fn full_export_is_child_first_and_value_blocks_reassemble_at_boundaries() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for (n, size) in [
        0,
        1,
        BLOCK_BYTES - 1,
        BLOCK_BYTES,
        BLOCK_BYTES + 1,
        3 * BLOCK_BYTES + 7,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = (0..size).map(|i| (i % 239) as u8).collect::<Vec<_>>();
        put(&mut index, &mut store, key(&format!("block-{n}")), &bytes);
    }
    let mut exported = MemoryObjects::default();
    index
        .visit_objects(|object| {
            assert!(
                object
                    .children()
                    .iter()
                    .all(|child| exported.0.contains_key(&child.id))
            );
            exported
                .0
                .insert(object.reference.id, Zeroizing::new(object.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    let reopened = Kv1Index::open(address(), index.root(), &exported).unwrap();
    assert_eq!(
        reopened.get(&key("block-5")).unwrap().len(),
        3 * BLOCK_BYTES + 7
    );
    assert_eq!(reopened.get(&key("block-0")), Some(b"".as_slice()));
    assert!(matches!(
        index.edit(key("too-big"), Some(&vec![0; MAX_VALUE_BYTES + 1])),
        Err(RecordError::TooLarge)
    ));
}

#[test]
fn authentication_aggregate_counts_and_missing_objects_fail_closed() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    put(&mut index, &mut store, key("low-entropy"), b"true");
    assert!(matches!(
        Kv1Index::open(AddressKey::from_bytes([72; 32]), index.root(), &store),
        Err(RecordError::Corrupt)
    ));
    let root = index.root();
    let reference = root.reference.as_ref().unwrap();
    let mut raw = store.0[&reference.id].clone();
    raw[HEADER_BYTES] ^= 1;
    store.0.insert(reference.id, raw);
    assert!(matches!(
        Kv1Index::open(address(), root.clone(), &store),
        Err(RecordError::Corrupt)
    ));
    // Authenticate an internally inconsistent aggregate, as if a buggy writer
    // generated it. Cryptographic integrity alone must not authorize the graph.
    let mut root = index.root();
    let reference = root.reference.as_mut().unwrap();
    let mut raw = index.root.as_ref().unwrap().object.bytes.clone();
    raw[9..17].copy_from_slice(&2_u64.to_be_bytes());
    reference.record_count = 2;
    reference.id = ObjectId(address().digest(b"object", &raw).unwrap());
    store.0.insert(reference.id, raw);
    assert!(matches!(
        Kv1Index::open(address(), root, &store),
        Err(RecordError::Corrupt)
    ));
    let owner = StagedObject::owner_chunk(&address(), b"private-owner-state").unwrap();
    assert_eq!(
        owner
            .reference()
            .owner_chunk_payload(&address(), owner.bytes())
            .unwrap(),
        b"private-owner-state"
    );
    assert_eq!(owner.reference().kind, ObjectKind::OwnerChunk);
    assert!(!owner.reference().resource().contains("private"));
    assert_ne!(
        owner.reference().id,
        StagedObject::owner_chunk(&AddressKey::from_bytes([72; 32]), b"private-owner-state")
            .unwrap()
            .reference()
            .id
    );
}

#[test]
fn failed_candidate_does_not_publish_new_root_and_staging_alone_is_invisible() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    put(&mut index, &mut store, key("selected"), b"original");
    let published = index.root();
    let edit = index.edit(key("selected"), Some(b"unpublished")).unwrap();
    store.stage(&edit.objects);
    drop(edit);
    let reopened = Kv1Index::open(address(), published, &store).unwrap();
    assert_eq!(reopened.get(&key("selected")), Some(b"original".as_slice()));
    assert_eq!(index.get(&key("selected")), Some(b"original".as_slice()));
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Fixed schema-36 bytes, computed from the documented binary layout and HMAC
// domain. This fixture does not call the current encoder to create its input.
fn legacy_small_values() -> (Kv1Index, MemoryObjects) {
    const BLOCK: &str = "48424b56314f303101000000000000000000000000000000027b7d";
    const VALUE: &str = "48424b56314f303102000000000000000100000000000000020001a62b4344e157cf9f5b70b1e2c3fa97e2900c163a48e645df36f5f0a3b8fafd70010000001b00000000000000000000000000000002";
    const LEAF: &str = "48424b56314f3031030000000000000002000000000000000400020004726f6f7400077365637265742f0000000000000001000161fd3df7db93b8a2efda45febcbd07f48fe7fc67935172f2a2a34d98f2d3f550470200000050000000000000000100000000000000020004726f6f7400077365637265742f0000000000000001000162fd3df7db93b8a2efda45febcbd07f48fe7fc67935172f2a2a34d98f2d3f55047020000005000000000000000010000000000000002";
    let mut store = MemoryObjects::default();
    for (digest, bytes) in [
        (
            "a62b4344e157cf9f5b70b1e2c3fa97e2900c163a48e645df36f5f0a3b8fafd70",
            BLOCK,
        ),
        (
            "fd3df7db93b8a2efda45febcbd07f48fe7fc67935172f2a2a34d98f2d3f55047",
            VALUE,
        ),
        (
            "1b832d3b60bc8d61858866ee8a2b6533434bafec26e8114913924c3cc398e034",
            LEAF,
        ),
    ] {
        store.0.insert(
            ObjectId::from_bytes(unhex(digest).try_into().unwrap()),
            Zeroizing::new(unhex(bytes)),
        );
    }
    let root = Kv1Root {
        reference: Some(ObjectRef {
            id: ObjectId::from_bytes(
                unhex("1b832d3b60bc8d61858866ee8a2b6533434bafec26e8114913924c3cc398e034")
                    .try_into()
                    .unwrap(),
            ),
            kind: ObjectKind::Leaf,
            encoded_bytes: 185,
            record_count: 2,
            payload_bytes: 4,
        }),
        height: 1,
    };
    (Kv1Index::open(address(), root, &store).unwrap(), store)
}

#[test]
fn fixed_legacy_bytes_reopen_without_conversion_and_changed_page_preserves_references() {
    let (legacy, mut store) = legacy_small_values();
    let root = legacy.root();
    assert!(!legacy.has_packed_leaves());
    assert_eq!(legacy.get(&key("a")), Some(b"{}".as_slice()));
    let mut exported = MemoryObjects::default();
    legacy
        .visit_objects(|object| {
            exported.stage(std::slice::from_ref(object));
            Ok(())
        })
        .unwrap();
    assert_eq!(exported.0, store.0);
    let noop = legacy.edit(key("a"), Some(b"{}")).unwrap();
    assert!(!noop.changed);
    assert!(noop.objects.is_empty());
    assert_eq!(noop.next.root(), root);
    let edit = legacy.edit(key("a"), Some(b"{\"v\":1}")).unwrap();
    assert_eq!(edit.objects.len(), 1);
    let page = &edit.objects[0];
    assert_eq!(page.reference.kind, ObjectKind::PackedLeaf);
    assert_eq!(page.children.len(), 1);
    assert_eq!(
        page.children[0].id,
        ObjectId::from_bytes(
            unhex("fd3df7db93b8a2efda45febcbd07f48fe7fc67935172f2a2a34d98f2d3f55047")
                .try_into()
                .unwrap()
        )
    );
    store.stage(&edit.objects);
    let reopened = Kv1Index::open(address(), edit.next.root(), &store).unwrap();
    assert!(reopened.has_packed_leaves());
    assert_eq!(reopened.get(&key("b")), Some(b"{}".as_slice()));
    assert_eq!(legacy.root(), root);
    assert_eq!(legacy.get(&key("a")), Some(b"{}".as_slice()));
    // Removing the last inline entry returns to the old Leaf encoding and
    // keeps the surviving referenced value untouched.
    let deleted = reopened.edit(key("a"), None).unwrap();
    assert_eq!(deleted.objects.len(), 1);
    assert_eq!(deleted.objects[0].reference.kind, ObjectKind::Leaf);
    assert!(!deleted.next.has_packed_leaves());
    assert_eq!(deleted.next.get(&key("b")), Some(b"{}".as_slice()));
}

#[test]
fn packed_leaf_has_fixed_binary_encoding_and_hmac_and_no_external_value_objects() {
    let edit = Kv1Index::empty(address())
        .edit(key("a"), Some(b"{}"))
        .unwrap();
    assert_eq!(edit.objects.len(), 1);
    let page = &edit.objects[0];
    assert_eq!(
        page.bytes(),
        unhex(
            "48424b56314f3031060000000000000001000000000000000200010004726f6f7400077365637265742f00000000000000010001610000027b7d"
        )
    );
    assert_eq!(
        page.reference.id.bytes().as_slice(),
        unhex("5c82157ab844808b0a61f47b1f680402fc6f2caa8bf512728b70a9861656e665")
    );
    assert!(page.children.is_empty());
    assert_eq!(page.reference.record_count, 1);
    assert_eq!(page.reference.payload_bytes, 2);
}

#[test]
fn inline_threshold_empty_bytes_and_mixed_reference_edges_roundtrip() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for (path, len) in [("empty", 0), ("inline", 1024), ("external", 1025)] {
        put(&mut index, &mut store, key(path), &vec![b'x'; len]);
    }
    let page = index.root.as_ref().unwrap();
    assert_eq!(page.object.reference.kind, ObjectKind::PackedLeaf);
    assert_eq!(page.object.children.len(), 1);
    assert_eq!(page.object.reference.record_count, 3);
    assert_eq!(page.object.reference.payload_bytes, 2049);
    let mut count = 0;
    index
        .visit_objects(|_| {
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 3); // one Block, one Value, one PackedLeaf
    let pin = index.clone();
    let reopened = Kv1Index::open(address(), index.root(), &store).unwrap();
    assert_eq!(reopened.get(&key("empty")), Some(b"".as_slice()));
    assert_eq!(reopened.get(&key("inline")).unwrap().len(), 1024);
    assert_eq!(reopened.get(&key("external")).unwrap().len(), 1025);
    store.0.clear();
    assert_eq!(pin.get(&key("inline")).unwrap(), &[b'x'; 1024]);

    let (legacy, mut store) = legacy_small_values();
    let appended = legacy.edit(key("c"), Some(b"inline")).unwrap();
    assert_eq!(appended.objects.len(), 1);
    assert_eq!(appended.objects[0].children.len(), 2);
    assert_eq!(
        appended.objects[0].children[0],
        appended.objects[0].children[1]
    );
    store.stage(&appended.objects);
    let reopened = Kv1Index::open(address(), appended.next.root(), &store).unwrap();
    let mut kinds = Vec::new();
    reopened
        .visit_objects(|o| {
            kinds.push(o.reference.kind);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        kinds,
        [ObjectKind::Block, ObjectKind::Value, ObjectKind::PackedLeaf]
    );
    assert_eq!(reopened.root().reference.unwrap().payload_bytes, 10);
}

#[test]
fn dense_inline_values_split_by_page_bytes_and_export_only_reachable_pages() {
    let mut index = Kv1Index::empty(address());
    let mut store = MemoryObjects::default();
    for number in 0..800 {
        let value = format!("{number:08}{}", "x".repeat(592));
        put(
            &mut index,
            &mut store,
            key(&format!("item-{number:04}")),
            value.as_bytes(),
        );
    }
    assert!(index.height > 1);
    let mut exported = MemoryObjects::default();
    let mut bytes = 0;
    index
        .visit_objects(|object| {
            assert!(matches!(
                object.reference.kind,
                ObjectKind::PackedLeaf | ObjectKind::Branch
            ));
            assert!(object.bytes().len() <= PAGE_BYTES);
            assert!(
                object
                    .children
                    .iter()
                    .all(|child| exported.0.contains_key(&child.id))
            );
            bytes += object.bytes().len();
            exported.stage(std::slice::from_ref(object));
            Ok(())
        })
        .unwrap();
    assert!(exported.0.len() < 64);
    // Actual encoded immutable bytes, not an allocation or latency claim.
    assert!(bytes < 800 * 650 + 2 * PAGE_BYTES);
    assert_eq!(index.root().reference.as_ref().unwrap().record_count, 800);
    assert_eq!(
        index.root().reference.as_ref().unwrap().payload_bytes,
        800 * 600
    );
    let reopened = Kv1Index::open(address(), index.root(), &exported).unwrap();
    assert_eq!(
        reopened
            .scan(&scope(), "", None, 4096, true)
            .unwrap()
            .keys
            .len(),
        800
    );
    for number in [0, 127, 399, 799] {
        assert_eq!(
            reopened.get(&key(&format!("item-{number:04}"))).unwrap(),
            format!("{number:08}{}", "x".repeat(592)).as_bytes()
        );
    }
}

#[test]
fn regular_and_packed_leaf_siblings_share_height_and_cursor_but_branch_cannot_be_leaf() {
    let (legacy, mut store) = legacy_small_values();
    let mut objects = Vec::new();
    let packed_value = codec::value(&address(), b"z-value", &mut objects).unwrap();
    let packed = codec::page(
        &address(),
        PageData::Leaf(vec![(key("z"), packed_value)]),
        &mut objects,
    )
    .unwrap();
    let branch = codec::page(
        &address(),
        PageData::Branch(vec![legacy.root.clone().unwrap(), packed]),
        &mut objects,
    )
    .unwrap();
    store.stage(&objects);
    let mixed = Kv1Index::open(
        address(),
        Kv1Root {
            reference: Some(branch.object.reference.clone()),
            height: 2,
        },
        &store,
    )
    .unwrap();
    assert!(mixed.has_packed_leaves());
    assert_eq!(
        mixed.scan(&scope(), "", Some("a"), 10, true).unwrap().keys,
        ["b", "z"]
    );
    assert_eq!(mixed.get(&key("b")), Some(b"{}".as_slice()));
    assert_eq!(mixed.get(&key("z")), Some(b"z-value".as_slice()));
    let edit = mixed.edit(key("z"), None).unwrap();
    assert_eq!(edit.next.root(), legacy.root());
    assert!(!edit.next.has_packed_leaves());
    assert!(edit.objects.is_empty());
    let smaller_value = codec::value(&address(), b"x", &mut objects).unwrap();
    let smaller = codec::page(
        &address(),
        PageData::Leaf(vec![(key("0"), smaller_value)]),
        &mut objects,
    )
    .unwrap();
    assert!(matches!(
        codec::page(
            &address(),
            PageData::Branch(vec![smaller, branch]),
            &mut objects
        ),
        Err(RecordError::Corrupt)
    ));
}

fn reopen_authenticated_page(bytes: Vec<u8>, height: u8) -> Result<Kv1Index> {
    let reference = ObjectRef {
        id: ObjectId(address().digest(b"object", &bytes).unwrap()),
        kind: ObjectKind::PackedLeaf,
        encoded_bytes: bytes.len() as u32,
        record_count: u64::from_be_bytes(bytes[9..17].try_into().unwrap()),
        payload_bytes: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
    };
    let mut store = MemoryObjects::default();
    store.0.insert(reference.id, Zeroizing::new(bytes));
    Kv1Index::open(
        address(),
        Kv1Root {
            reference: Some(reference),
            height,
        },
        &store,
    )
}

#[test]
fn authenticated_packed_page_rejects_invalid_tags_lengths_counts_order_and_height() {
    let edit = Kv1Index::empty(address())
        .edit(key("a"), Some(b"{}"))
        .unwrap();
    let golden = edit.objects[0].bytes().to_vec();
    assert!(reopen_authenticated_page(golden.clone(), 1).is_ok());
    assert!(matches!(
        reopen_authenticated_page(golden.clone(), 2),
        Err(RecordError::Corrupt)
    ));
    // Fixed key ends at byte 53 in the independent golden fixture above.
    let mut bad = golden.clone();
    bad[53] = 2;
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut bad = golden.clone();
    bad[54..56].copy_from_slice(&1025_u16.to_be_bytes());
    bad.resize(56 + 1025, b'x');
    bad[17..25].copy_from_slice(&1025_u64.to_be_bytes());
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut bad = golden.clone();
    bad[17..25].copy_from_slice(&3_u64.to_be_bytes());
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut bad = golden.clone();
    bad[9..17].copy_from_slice(&2_u64.to_be_bytes());
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut bad = golden.clone();
    bad.push(0);
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut bad = golden.clone();
    bad[25..27].copy_from_slice(&0_u16.to_be_bytes());
    assert!(matches!(
        reopen_authenticated_page(bad, 1),
        Err(RecordError::Corrupt)
    ));
    let mut duplicate = golden.clone();
    duplicate.extend_from_slice(&golden[27..]);
    duplicate[9..17].copy_from_slice(&2_u64.to_be_bytes());
    duplicate[17..25].copy_from_slice(&4_u64.to_be_bytes());
    duplicate[25..27].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        reopen_authenticated_page(duplicate, 1),
        Err(RecordError::Corrupt)
    ));
    // A packed page with only external references is not canonical: it must
    // remain the byte-identical legacy Leaf representation.
    let (legacy, _) = legacy_small_values();
    let old = legacy.root.as_ref().unwrap().object.bytes();
    let mut no_inline = old[..27].to_vec();
    no_inline[8] = 6;
    for entry in old[27..].as_chunks::<79>().0 {
        no_inline.extend_from_slice(&entry[..26]);
        no_inline.push(1);
        no_inline.extend_from_slice(&entry[26..]);
    }
    assert!(matches!(
        reopen_authenticated_page(no_inline, 1),
        Err(RecordError::Corrupt)
    ));
}
