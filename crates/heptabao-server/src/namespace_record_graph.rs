//! Typed private namespace graph. Its header is part of the independently
//! encrypted namespace asset parcel; only opaque authenticated cells enter the
//! root-owned publication graph. No plaintext path or record is copied there.
use crate::namespace_custody::Key;
use crate::state_records::{Kv1Index, Kv1Root, ObjectRef, RecordError, RecordReader};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Graph {
    version: u32,
    namespace: String,
    root: Kv1Root,
}

pub(crate) type Cells = BTreeMap<String, Zeroizing<Vec<u8>>>;

fn cell_name(reference: &ObjectRef) -> String {
    reference
        .id
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Graph {
    pub(crate) fn protect(
        namespace: &str,
        key: &Key,
        index: &Kv1Index,
    ) -> Result<(Self, Cells), RecordError> {
        Self::protect_reusing(namespace, key, index, |_| Err(RecordError::Missing))
    }

    pub(crate) fn protect_reusing(
        namespace: &str,
        key: &Key,
        index: &Kv1Index,
        read_previous: impl Fn(&str) -> Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<(Self, Cells), RecordError> {
        if namespace.is_empty() || !key.owns_namespace(namespace) {
            return Err(RecordError::Invalid);
        }
        index.visit_keys(|record| {
            if record.namespace() != namespace {
                return Err(RecordError::Corrupt);
            }
            Ok(())
        })?;
        let address_key = key
            .record_address_key(namespace)
            .map_err(|_| RecordError::Corrupt)?;
        let mut cells = BTreeMap::new();
        index.visit_objects(|object| {
            object.reference().verify(&address_key, object.bytes())?;
            let protected = match read_previous(&cell_name(object.reference())) {
                Ok(ciphertext) => {
                    let bytes = key
                        .open_record_object(namespace, object.reference().id.bytes(), &ciphertext)
                        .map_err(|_| RecordError::Corrupt)?;
                    if bytes.as_slice() != object.bytes() {
                        return Err(RecordError::Corrupt);
                    }
                    ciphertext
                }
                Err(RecordError::Missing) => key
                    .protect_record_object(namespace, object.reference().id.bytes(), object.bytes())
                    .map_err(|_| RecordError::Corrupt)?,
                Err(error) => return Err(error),
            };
            if cells
                .insert(cell_name(object.reference()), protected)
                .is_some()
            {
                return Err(RecordError::Corrupt);
            }
            Ok(())
        })?;
        Ok((
            Self {
                version: 1,
                namespace: namespace.to_owned(),
                root: index.root(),
            },
            cells,
        ))
    }

    pub(crate) fn open(
        &self,
        actual: &str,
        key: &Key,
        read_cell: impl Fn(&str) -> Result<Zeroizing<Vec<u8>>, RecordError>,
    ) -> Result<Kv1Index, RecordError> {
        if self.version != 1
            || actual.is_empty()
            || self.namespace != actual
            || !key.owns_namespace(actual)
        {
            return Err(RecordError::Corrupt);
        }
        struct Reader<'a, F> {
            namespace: &'a str,
            key: &'a Key,
            read_cell: F,
        }
        impl<F: Fn(&str) -> Result<Zeroizing<Vec<u8>>, RecordError>> RecordReader for Reader<'_, F> {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                let name = cell_name(reference);
                let ciphertext = (self.read_cell)(&name)?;
                self.key
                    .open_record_object(self.namespace, reference.id.bytes(), &ciphertext)
                    .map_err(|_| RecordError::Corrupt)
            }
        }
        let address_key = key
            .record_address_key(actual)
            .map_err(|_| RecordError::Corrupt)?;
        let index = Kv1Index::open(
            address_key,
            self.root.clone(),
            &Reader {
                namespace: actual,
                key,
                read_cell,
            },
        )?;
        index.visit_keys(|record| {
            if record.namespace() != actual {
                return Err(RecordError::Corrupt);
            }
            Ok(())
        })?;
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_custody::{Binding, Descriptor, Progress, Submission};
    use crate::state_records::{AddressKey, Kv1Key};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn key(namespace: &str) -> TestResult<Key> {
        let binding = Binding::new(
            "record-custody-cluster".into(),
            namespace.into(),
            "public-custody-id".into(),
            1,
        )?;
        let created = Descriptor::create(binding.clone(), 1, 1, b"{}")?;
        let mut progress = Progress::new(binding, &created.descriptor)?;
        match progress.submit(&created.descriptor, &created.shares[0])? {
            Submission::Unlocked { key, .. } => Ok(key),
            Submission::Pending => Err("threshold did not authenticate".into()),
        }
    }

    #[test]
    fn namespace_record_graph_excludes_plaintext_and_authenticates_actual_owner() -> TestResult {
        let owner = key("custody")?;
        let original = Kv1Index::empty(AddressKey::from_bytes([77; 32]));
        let secret_key = Kv1Key::new("custody", "records/", 1, "private-record-path")?;
        let root_key = Kv1Key::new("", "records/", 1, "root-control")?;
        let value = b"namespace-record-marker-plaintext";
        let original = original
            .edit(secret_key.clone(), Some(value))?
            .next
            .edit(root_key.clone(), Some(b"root-value"))?
            .next;
        let (retained, private) =
            original.partition_namespace("custody", owner.record_address_key("custody")?)?;
        assert!(
            retained.get(&secret_key).is_none()
                && retained.get(&root_key) == Some(b"root-value".as_slice()),
            "partition retains only the unrelated root control"
        );
        let (graph, cells) = Graph::protect("custody", &owner, &private)?;
        assert!(
            cells
                .values()
                .all(|bytes| !bytes.windows(value.len()).any(|window| window == value)),
            "opaque cells contain no plaintext record"
        );
        let restored = graph.open("custody", &owner, |name| {
            cells.get(name).cloned().ok_or(RecordError::Missing)
        })?;
        let joined = retained.merge_namespace("custody", &restored)?;
        assert!(
            joined.get(&secret_key) == Some(value.as_slice())
                && joined.get(&root_key) == Some(b"root-value".as_slice()),
            "logical values restore exactly"
        );
        assert!(
            retained.merge_namespace("other", &restored).is_err()
                && joined.merge_namespace("custody", &restored).is_err(),
            "wrong namespace and collisions fail before merge"
        );
        let wrong = key("custody")?;
        assert!(
            graph
                .open("custody", &wrong, |name| cells
                    .get(name)
                    .cloned()
                    .ok_or(RecordError::Missing))
                .is_err(),
            "another actual independent key cannot read the graph"
        );
        assert!(
            graph
                .open("other", &owner, |name| cells
                    .get(name)
                    .cloned()
                    .ok_or(RecordError::Missing))
                .is_err(),
            "graph header is namespace bound"
        );
        assert!(
            graph
                .open("custody", &owner, |_| Err(RecordError::Missing))
                .is_err(),
            "missing ciphertext fails without fallback"
        );
        let mut corrupt = cells.clone();
        let cell = corrupt.values_mut().next().ok_or("cell")?;
        let last = cell.last_mut().ok_or("ciphertext")?;
        *last ^= 1;
        assert!(
            graph
                .open("custody", &owner, |name| corrupt
                    .get(name)
                    .cloned()
                    .ok_or(RecordError::Missing))
                .is_err(),
            "ciphertext tampering fails authenticated opening"
        );
        Ok(())
    }

    #[test]
    fn namespace_record_graph_exceeds_owner_bound_using_bounded_cipher_objects() -> TestResult {
        let owner = key("custody")?;
        let mut private = Kv1Index::empty(owner.record_address_key("custody")?);
        for number in 0..17_u8 {
            let key = Kv1Key::new("custody", "records/", 1, &format!("large-{number}"))?;
            let value = Zeroizing::new(vec![number + 64; 1024 * 1024]);
            private = private.edit(key, Some(&value))?.next;
        }
        let (graph, cells) = Graph::protect("custody", &owner, &private)?;
        let header = serde_json::to_vec(&graph)?;
        assert!(
            header.len() < 4096
                && cells
                    .values()
                    .all(|bytes| bytes.len() <= crate::state_records::BLOCK_BYTES + 25 + 32),
            "large namespace records do not flatten into an application owner"
        );
        let restored = graph.open("custody", &owner, |name| {
            cells.get(name).cloned().ok_or(RecordError::Missing)
        })?;
        for number in 0..17_u8 {
            let key = Kv1Key::new("custody", "records/", 1, &format!("large-{number}"))?;
            let value = restored.get(&key).ok_or("large record")?;
            assert!(
                value.len() == 1024 * 1024 && value.iter().all(|byte| *byte == number + 64),
                "every large record reopens exactly"
            );
        }
        Ok(())
    }
}
