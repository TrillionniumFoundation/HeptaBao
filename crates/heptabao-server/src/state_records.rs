//! Immutable KV1 record graph. Persistence and root publication belong to Service.
//!
//! An index clone owns a fully materialized immutable graph; it is a real read
//! pin, not a root identifier whose disk objects may disappear during a read.
//! Object bytes are private plaintext until the caller encrypts them. A content
//! address is a keyed digest, never a public hash of a low-entropy secret.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

mod codec;
#[cfg(test)]
mod tests;
mod tree;

pub(crate) const BLOCK_BYTES: usize = 256 * 1024;
pub(crate) const PAGE_BYTES: usize = 32 * 1024;
pub(crate) const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHILDREN: usize = 256;
const MAX_HEIGHT: u8 = 16;
pub(crate) const MAX_GRAPH_BYTES: usize = 64 * 1024 * 1024;
const MAX_OBJECTS: usize = 1_048_576;
const HEADER_BYTES: usize = 25;
const REF_BYTES: usize = 53;
const MAGIC: &[u8; 8] = b"HBKV1O01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordError {
    Invalid,
    Corrupt,
    Missing,
    TooLarge,
}
impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid record operation",
            Self::Corrupt => "invalid record graph",
            Self::Missing => "record object is missing",
            Self::TooLarge => "record graph resource bound exceeded",
        })
    }
}
impl std::error::Error for RecordError {}
type Result<T> = std::result::Result<T, RecordError>;

pub(crate) struct AddressKey(Zeroizing<[u8; 32]>);
impl AddressKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Arc<Self> {
        Arc::new(Self(Zeroizing::new(bytes)))
    }
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
    pub(crate) fn digest(&self, domain: &[u8], bytes: &[u8]) -> Result<[u8; 32]> {
        let mut mac = self.mac(domain)?;
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }
    fn mac(&self, domain: &[u8]) -> Result<Hmac<Sha256>> {
        if domain.len() > 128 {
            return Err(RecordError::Invalid);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.expose()).map_err(|_| RecordError::Invalid)?;
        mac.update(b"HeptaBao/v5/keyed-object-address\0");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain);
        Ok(mac)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub(crate) struct ObjectId([u8; 32]);
impl ObjectId {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum ObjectKind {
    Block = 1,
    Value = 2,
    Leaf = 3,
    Branch = 4,
    OwnerChunk = 5,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObjectRef {
    pub(crate) id: ObjectId,
    pub(crate) kind: ObjectKind,
    pub(crate) encoded_bytes: u32,
    pub(crate) record_count: u64,
    pub(crate) payload_bytes: u64,
}
impl ObjectRef {
    pub(crate) fn resource(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(81);
        name.push_str("state-records/v5/");
        for byte in self.id.0 {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        name
    }
    pub(crate) fn owner_chunk_payload<'a>(
        &self,
        key: &AddressKey,
        bytes: &'a [u8],
    ) -> Result<&'a [u8]> {
        self.verify(key, bytes)?;
        if self.kind != ObjectKind::OwnerChunk {
            return Err(RecordError::Corrupt);
        }
        Ok(&bytes[HEADER_BYTES..])
    }
    pub(crate) fn verify(&self, key: &AddressKey, bytes: &[u8]) -> Result<()> {
        codec::verify_object(self, key, bytes)
    }
}

pub(crate) struct StagedObject {
    reference: ObjectRef,
    children: Vec<ObjectRef>,
    bytes: Zeroizing<Vec<u8>>,
}
impl StagedObject {
    pub(crate) fn reference(&self) -> &ObjectRef {
        &self.reference
    }
    pub(crate) fn children(&self) -> &[ObjectRef] {
        &self.children
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn owner_chunk(key: &AddressKey, bytes: &[u8]) -> Result<Arc<Self>> {
        codec::block(key, ObjectKind::OwnerChunk, bytes)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Kv1Key {
    namespace: String,
    mount: String,
    incarnation: u64,
    path: String,
}
impl Drop for Kv1Key {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
        self.path.zeroize();
    }
}
impl Kv1Key {
    pub(crate) fn new(namespace: &str, mount: &str, incarnation: u64, path: &str) -> Result<Self> {
        let scope = Kv1Scope::new(namespace, mount, incarnation)?;
        if path.is_empty() || path.len() > 1024 || path.contains('\0') {
            return Err(RecordError::Invalid);
        }
        Ok(Self::probe(&scope, path))
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn mount(&self) -> &str {
        &self.mount
    }
    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }
    fn probe(scope: &Kv1Scope, path: &str) -> Self {
        Self {
            namespace: scope.namespace.clone(),
            mount: scope.mount.clone(),
            incarnation: scope.incarnation,
            path: path.into(),
        }
    }
    fn in_scope(&self, scope: &Kv1Scope) -> bool {
        self.namespace == scope.namespace
            && self.mount == scope.mount
            && self.incarnation == scope.incarnation
    }
}
#[derive(Clone)]
pub(crate) struct Kv1Scope {
    namespace: String,
    mount: String,
    incarnation: u64,
}
impl Drop for Kv1Scope {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
    }
}
impl Kv1Scope {
    pub(crate) fn new(namespace: &str, mount: &str, incarnation: u64) -> Result<Self> {
        if namespace.len() > 1024
            || mount.is_empty()
            || mount.len() > 1024
            || incarnation == 0
            || namespace.contains('\0')
            || mount.contains('\0')
        {
            return Err(RecordError::Invalid);
        }
        Ok(Self {
            namespace: namespace.into(),
            mount: mount.into(),
            incarnation,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Kv1Root {
    pub(crate) reference: Option<ObjectRef>,
    pub(crate) height: u8,
}

pub(crate) trait RecordReader {
    /// Return decrypted bytes for exactly the requested object, without fallback.
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>>;
}

struct StoredValue {
    object: Arc<StagedObject>,
    blocks: Vec<Arc<StagedObject>>,
    encoded: Zeroizing<Vec<u8>>,
}
struct Page {
    object: Arc<StagedObject>,
    data: PageData,
    graph_bytes: usize,
    object_count: usize,
}
enum PageData {
    Leaf(Vec<(Kv1Key, Arc<StoredValue>)>),
    Branch(Vec<Arc<Page>>),
}
impl Page {
    fn checked(object: Arc<StagedObject>, data: PageData) -> Result<Self> {
        let mut graph_bytes = object.bytes.len();
        let mut object_count: usize = 1;
        let mut include = |bytes: usize, count: usize| -> Result<()> {
            graph_bytes = graph_bytes
                .checked_add(bytes)
                .ok_or(RecordError::TooLarge)?;
            object_count = object_count
                .checked_add(count)
                .ok_or(RecordError::TooLarge)?;
            if graph_bytes > MAX_GRAPH_BYTES || object_count > MAX_OBJECTS {
                return Err(RecordError::TooLarge);
            }
            Ok(())
        };
        match &data {
            PageData::Leaf(entries) => {
                for (_, value) in entries {
                    include(value.object.bytes.len(), 1)?;
                    for block in &value.blocks {
                        include(block.bytes.len(), 1)?;
                    }
                }
            }
            PageData::Branch(children) => {
                for child in children {
                    include(child.graph_bytes, child.object_count)?;
                }
            }
        }
        Ok(Self {
            object,
            data,
            graph_bytes,
            object_count,
        })
    }
    fn first(&self) -> &Kv1Key {
        match &self.data {
            PageData::Leaf(entries) => &entries[0].0,
            PageData::Branch(children) => children[0].first(),
        }
    }
    fn last(&self) -> &Kv1Key {
        match &self.data {
            PageData::Leaf(entries) => &entries[entries.len() - 1].0,
            PageData::Branch(children) => children[children.len() - 1].last(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Kv1Index {
    address_key: Arc<AddressKey>,
    root: Option<Arc<Page>>,
    height: u8,
}
pub(crate) struct Kv1Edit {
    pub(crate) next: Kv1Index,
    pub(crate) objects: Vec<Arc<StagedObject>>,
    pub(crate) changed: bool,
}
pub(crate) struct KeyPage {
    pub(crate) keys: Vec<String>,
    pub(crate) next_after: Option<String>,
}

impl Kv1Index {
    pub(crate) fn empty(address_key: Arc<AddressKey>) -> Self {
        Self {
            address_key,
            root: None,
            height: 0,
        }
    }
    pub(crate) fn root(&self) -> Kv1Root {
        Kv1Root {
            reference: self.root.as_ref().map(|page| page.object.reference.clone()),
            height: self.height,
        }
    }
    pub(crate) fn get(&self, key: &Kv1Key) -> Option<&[u8]> {
        tree::get(self.root.as_deref()?, key).map(|v| v.encoded.as_slice())
    }
    pub(crate) fn open(
        address_key: Arc<AddressKey>,
        root: Kv1Root,
        reader: &impl RecordReader,
    ) -> Result<Self> {
        codec::open(address_key, root, reader)
    }
    pub(crate) fn edit(&self, key: Kv1Key, value: Option<&[u8]>) -> Result<Kv1Edit> {
        tree::edit(self, key, value)
    }
    pub(crate) fn scan(
        &self,
        scope: &Kv1Scope,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        recursive: bool,
    ) -> Result<KeyPage> {
        tree::scan(self, scope, prefix, after, limit, recursive)
    }
    pub(crate) fn visit_keys(&self, mut visitor: impl FnMut(&Kv1Key) -> Result<()>) -> Result<()> {
        if let Some(root) = &self.root {
            tree::visit_keys(root, &mut visitor)?;
        }
        Ok(())
    }
    pub(crate) fn visit_objects(
        &self,
        mut visitor: impl FnMut(&Arc<StagedObject>) -> Result<()>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        if let Some(root) = &self.root {
            tree::visit(root, &mut seen, &mut visitor)?;
        }
        Ok(())
    }
}
