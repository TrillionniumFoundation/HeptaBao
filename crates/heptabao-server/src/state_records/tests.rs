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
            if matches!(object.reference.kind, ObjectKind::Leaf | ObjectKind::Branch) {
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
            .filter(|o| matches!(o.reference.kind, ObjectKind::Leaf | ObjectKind::Branch))
            .count(),
        index.height as usize
    );
    assert_eq!(edited.objects.len(), index.height as usize + 2);
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
        put(&mut index, &mut store, key(path), b"{}");
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
