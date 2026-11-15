#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use std::cell::Cell;

#[derive(Default)]
struct Objects(BTreeMap<ObjectId, Zeroizing<Vec<u8>>>);
impl RecordReader for Objects {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>> {
        self.0
            .get(&reference.id)
            .cloned()
            .ok_or(RecordError::Missing)
    }
}
fn key(n: usize) -> Kv1Key {
    Kv1Key::new("root", "secret/", 7, &format!("{n:05}-{}", "p".repeat(940))).unwrap()
}
fn fixture() -> BTreeMap<Kv1Key, Zeroizing<Vec<u8>>> {
    (0..1400)
        .map(|n| {
            let length = [0, 1, 1023, 1024, 1025, 4096, BLOCK_BYTES + 31][n % 7];
            (key(n), Zeroizing::new(vec![(n % 251) as u8; length]))
        })
        .collect()
}
fn store(index: &Kv1Index) -> Objects {
    let mut store = Objects::default();
    index
        .visit_objects(|object| {
            object
                .reference
                .verify(&index.address_key, object.bytes())?;
            if matches!(
                object.reference.kind,
                ObjectKind::Leaf | ObjectKind::PackedLeaf | ObjectKind::Branch
            ) {
                assert!(object.bytes().len() <= PAGE_BYTES);
            }
            store
                .0
                .insert(object.reference.id, Zeroizing::new(object.bytes().to_vec()));
            Ok(())
        })
        .unwrap();
    store
}

#[test]
fn bulk_index_mixed_values_reopen_and_incremental_edits_preserve_reader_pin() {
    let address = AddressKey::from_bytes([19; 32]);
    let records = fixture();
    let mut incremental = Kv1Index::empty(Arc::clone(&address));
    for (key, bytes) in &records {
        incremental = incremental.edit(key.clone(), Some(bytes)).unwrap().next;
    }
    let bulk = Kv1Index::from_records_checked(Arc::clone(&address), records, &|| Ok(())).unwrap();
    assert!(bulk.height >= 3);
    let mut objects = store(&bulk);
    let reopened = Kv1Index::open(Arc::clone(&address), bulk.root(), &objects).unwrap();
    for n in 0..1400 {
        assert_eq!(reopened.get(&key(n)), incremental.get(&key(n)));
    }
    let pin = reopened.clone();
    let edit = reopened
        .edit(key(350), Some(b"changed-after-import"))
        .unwrap();
    for object in &edit.objects {
        objects
            .0
            .insert(object.reference.id, Zeroizing::new(object.bytes().to_vec()));
    }
    let next = Kv1Index::open(address, edit.next.root(), &objects).unwrap();
    assert_eq!(
        next.get(&key(350)),
        Some(b"changed-after-import".as_slice())
    );
    assert_eq!(pin.get(&key(350)), incremental.get(&key(350)));
    let removed = next.edit(key(1), None).unwrap().next;
    assert!(removed.get(&key(1)).is_none());
    assert_eq!(pin.get(&key(1)), incremental.get(&key(1)));
}

#[test]
fn bulk_index_cold_reader_rejects_missing_corrupt_and_wrong_key_objects() {
    let address = AddressKey::from_bytes([21; 32]);
    let mut records = BTreeMap::new();
    records.insert(key(1), Zeroizing::new(vec![17; BLOCK_BYTES + 19]));
    records.insert(key(2), Zeroizing::new(b"inline".to_vec()));
    let index = Kv1Index::from_records_checked(Arc::clone(&address), records, &|| Ok(())).unwrap();
    let root = index.root();
    let mut objects = store(&index);
    assert!(matches!(
        Kv1Index::open(AddressKey::from_bytes([22; 32]), root.clone(), &objects),
        Err(RecordError::Corrupt)
    ));
    let id = root.reference.as_ref().unwrap().id;
    objects.0.get_mut(&id).unwrap()[HEADER_BYTES] ^= 1;
    assert!(matches!(
        Kv1Index::open(Arc::clone(&address), root.clone(), &objects),
        Err(RecordError::Corrupt)
    ));
    objects.0.remove(&id);
    assert!(matches!(
        Kv1Index::open(address, root, &objects),
        Err(RecordError::Missing)
    ));
}

#[test]
fn bulk_index_cancellation_returns_no_partial_graph_or_changed_prior_root() {
    let address = AddressKey::from_bytes([23; 32]);
    let prior = Kv1Index::empty(Arc::clone(&address))
        .edit(key(0), Some(b"prior"))
        .unwrap()
        .next;
    let root = prior.root();
    let checks = Cell::new(0);
    let check = || {
        checks.set(checks.get() + 1);
        if checks.get() >= 23 {
            Err(RecordError::Invalid)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        Kv1Index::from_records_checked(address, fixture(), &check),
        Err(RecordError::Invalid)
    ));
    assert_eq!(prior.root(), root);
    assert_eq!(prior.get(&key(0)), Some(b"prior".as_slice()));
    assert_eq!(checks.get(), 23);
}

#[test]
fn bulk_index_empty_and_singleton_are_canonical_and_check_original_gate() {
    let address = AddressKey::from_bytes([24; 32]);
    let empty =
        Kv1Index::from_records_checked(Arc::clone(&address), BTreeMap::new(), &|| Ok(())).unwrap();
    assert_eq!(empty.root().height, 0);
    assert!(empty.root().reference.is_none());
    assert!(matches!(
        Kv1Index::from_records_checked(Arc::clone(&address), BTreeMap::new(), &|| Err(
            RecordError::Invalid
        )),
        Err(RecordError::Invalid)
    ));
    let records = BTreeMap::from([(key(1), Zeroizing::new(b"single".to_vec()))]);
    let single = Kv1Index::from_records_checked(Arc::clone(&address), records, &|| Ok(())).unwrap();
    assert_eq!(single.root().height, 1);
    let cold = Kv1Index::open(address, single.root(), &store(&single)).unwrap();
    assert_eq!(cold.get(&key(1)), Some(b"single".as_slice()));
}
