//! Read-only V6 root/closure inspection under an independent expected frontier.
//! No result authorizes Service, custody, HA membership, migration or a writer.
pub use crate::engines::kv2_native_records::NativeScope;
use crate::state_record_root::StateIdentity;
pub use crate::state_record_root_v6::OwnerDomain;
use crate::state_record_root_v6::{MountScope, ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectId, ObjectRef, RecordError};
use serde::Serialize;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAX_OBJECTS: usize = 150_000;
const MAX_INPUT_BYTES: usize =
    crate::MAX_APPLICATION_STATE_BYTES + 2 * crate::state_records::MAX_GRAPH_BYTES + 16 * 1024;

#[derive(Clone, Copy)]
pub enum ReadIdentity {
    Legacy([u8; 32]),
    RecordsV5([u8; 32]),
    RecordsV6([u8; 32]),
}
impl ReadIdentity {
    pub(crate) fn typed(self) -> StateIdentity {
        match self {
            Self::Legacy(id) => StateIdentity::Legacy(id),
            Self::RecordsV5(id) => StateIdentity::RecordsV5(id),
            Self::RecordsV6(id) => StateIdentity::RecordsV6(id),
        }
    }
}

/// Supplied expected state and local reader capability, never a custody grant.
#[derive(Clone, Copy)]
pub struct ReadContext<'a> {
    pub expected_identity: ReadIdentity,
    pub cluster_id: &'a str,
    pub replay_epoch: u64,
    pub minimum_state_schema: u32,
    pub maximum_state_schema: u32,
    pub reader_format: u32,
}

#[derive(Clone, Copy)]
pub enum EncodedDomain<'a> {
    Owner(OwnerDomain),
    Kv1,
    Kv2(NativeScope<'a>),
}
pub struct EncodedObject<'a> {
    pub domain: EncodedDomain<'a>,
    pub id: [u8; 32],
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    Invalid,
    TooLarge,
    Authentication,
    Missing,
    ReaderFloor,
    State,
}
impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid V6 root or object shape",
            Self::TooLarge => "V6 reader bound exceeded",
            Self::Authentication => "V6 expected identity or object authentication failed",
            Self::Missing => "V6 object closure is incomplete",
            Self::ReaderFloor => "V6 reader floor or state frontier is not admitted",
            Self::State => "V6 protected owner state rejected",
        })
    }
}
impl std::error::Error for ReadError {}
impl From<crate::state_record_root::RootError> for ReadError {
    fn from(error: crate::state_record_root::RootError) -> Self {
        match error {
            crate::state_record_root::RootError::TooLarge => Self::TooLarge,
            crate::state_record_root::RootError::Authentication => Self::Authentication,
            _ => Self::Invalid,
        }
    }
}
impl From<RecordError> for ReadError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Missing => Self::Missing,
            RecordError::TooLarge => Self::TooLarge,
            _ => Self::Authentication,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReadReceipt {
    pub storage_format: &'static str,
    pub graph_roots: usize,
    pub kv2_mounts: usize,
    pub paths: usize,
    pub retained_versions: usize,
    pub payload_records: usize,
    pub objects_read: usize,
    pub encoded_bytes_read: usize,
    pub service_reader_admitted: bool,
    pub namespace_custody_qualified: bool,
    pub membership_reader_fence_qualified: bool,
    pub production_writer_admitted: bool,
    pub migration_admitted: bool,
    pub replacement_authority: bool,
}

pub(crate) trait ObjectSource {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError>;
    fn object_count(&self) -> Option<usize> {
        None
    }
}
struct Objects<'a>(BTreeMap<(ObjectDomain, ObjectId), &'a [u8]>);
impl ObjectSource for Objects<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.0
            .get(&(domain.clone(), reference.id))
            .map(|bytes| Zeroizing::new(bytes.to_vec()))
            .ok_or(RecordError::Missing)
    }
    fn object_count(&self) -> Option<usize> {
        Some(self.0.len())
    }
}
impl<'a> Objects<'a> {
    fn new(root: &RecordStateRootV6, input: &[EncodedObject<'a>]) -> Result<Self, ReadError> {
        if input.len() > MAX_OBJECTS {
            return Err(ReadError::TooLarge);
        }
        let mut sum = 0_usize;
        // Preflight borrowed scopes and bytes before owning keys or maps.
        for object in input {
            if object.bytes.len() < 25
                || object.bytes.len() > crate::state_records::BLOCK_BYTES + 25
                || &object.bytes[..8] != b"HBKV1O01"
            {
                return Err(ReadError::Invalid);
            }
            sum = sum
                .checked_add(object.bytes.len())
                .filter(|total| *total <= MAX_INPUT_BYTES)
                .ok_or(ReadError::TooLarge)?;
            if let EncodedDomain::Kv2(scope) = object.domain {
                crate::state_records::Kv1Key::new(
                    scope.namespace,
                    scope.mount,
                    scope.incarnation,
                    "scope",
                )
                .map_err(|_| ReadError::Invalid)?;
                if !root.kv2.iter().any(|graph| {
                    graph.scope.namespace == scope.namespace
                        && graph.scope.mount == scope.mount
                        && graph.scope.incarnation == scope.incarnation
                }) {
                    return Err(ReadError::Invalid);
                }
            } else if matches!(object.domain, EncodedDomain::Kv1) && root.kv1.reference.is_none() {
                return Err(ReadError::Invalid);
            }
        }
        let mut map = BTreeMap::new();
        for object in input {
            let domain = match object.domain {
                EncodedDomain::Owner(role) => ObjectDomain::Owner(role),
                EncodedDomain::Kv1 => ObjectDomain::Kv1,
                EncodedDomain::Kv2(scope) => ObjectDomain::Kv2(MountScope {
                    namespace: scope.namespace.into(),
                    mount: scope.mount.into(),
                    incarnation: scope.incarnation,
                }),
            };
            if map
                .insert((domain, ObjectId::from_bytes(object.id)), object.bytes)
                .is_some()
            {
                return Err(ReadError::Invalid);
            }
        }
        Ok(Self(map))
    }
}

/// Validate a canonical V6 root and authenticate its full role-separated
/// owner/KV1/KV2 closure against the supplied expected frontier. It never opens
/// storage, admits a Service reader, or supplies committed membership custody.
pub fn inspect_v6_records(
    root_bytes: &[u8],
    context: ReadContext<'_>,
    objects: &[EncodedObject<'_>],
) -> Result<ReadReceipt, ReadError> {
    let root = RecordStateRootV6::decode(root_bytes)?;
    crate::service::v6_records::validate_frontier(&root, context)?;
    let objects = Objects::new(&root, objects)?;
    crate::service::v6_records::inspect(&root, context, &objects)
}
