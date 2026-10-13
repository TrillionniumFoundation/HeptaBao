//! Actual-key, operation-scoped native KV2 custody. Retained pins contain
//! encrypted objects only and cannot activate Service or manufacture a deadline.
use crate::engines::kv2_native_records::{NativeCellGraph, NativeReadView, NativeScope};
use crate::namespace_custody::{Binding, InheritedParent, Key};
use crate::state_record_root_v6::MountScope;
use crate::state_records::{Kv1Root, ObjectId, ObjectRef, RecordError, RecordReader, StagedObject};
use crate::v6_record_resources::{CipherDomain, CipherObject, CipherReference};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    Deadline,
    Unavailable,
    Invalid,
    Missing,
    TooLarge,
    Authentication,
    Storage,
}
impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deadline => "original V6 request deadline unavailable or expired",
            Self::Unavailable => "actual V6 custody owner unavailable or retired",
            Self::Invalid => "invalid V6 custody closure",
            Self::Missing => "missing V6 ciphertext",
            Self::TooLarge => "V6 custody bound exceeded",
            Self::Authentication => "V6 custody authentication failed",
            Self::Storage => "V6 retained storage failed",
        })
    }
}
impl std::error::Error for CustodyError {}
impl From<RecordError> for CustodyError {
    fn from(e: RecordError) -> Self {
        match e {
            RecordError::Missing => Self::Missing,
            RecordError::TooLarge => Self::TooLarge,
            RecordError::Invalid => Self::Invalid,
            RecordError::Corrupt => Self::Authentication,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OriginalDeadline(Instant);
impl OriginalDeadline {
    pub(crate) fn capture() -> Result<Self, CustodyError> {
        let deadline = Self(crate::request_deadline::current().ok_or(CustodyError::Deadline)?);
        deadline.check()?;
        Ok(deadline)
    }
    pub(crate) fn instant(self) -> Instant {
        self.0
    }
    pub(crate) fn check(self) -> Result<(), CustodyError> {
        let current = crate::request_deadline::current().ok_or(CustodyError::Deadline)?;
        if Instant::now() >= current.min(self.0) {
            Err(CustodyError::Deadline)
        } else {
            Ok(())
        }
    }
    fn record_check(self) -> Result<(), RecordError> {
        self.check().map_err(|_| RecordError::Invalid)
    }
}

/// Authenticated normal namespace owner facts, never a key/capability grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFrontier {
    pub binding: Binding,
    pub key_epoch: u64,
    pub seal_frontier: u64,
    pub inherited_parent: Option<InheritedParent>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeHeader {
    format: String,
    cluster: String,
    replay_epoch: u64,
    scope: MountScope,
    custody: NamespaceFrontier,
    root: Kv1Root,
}

/// An encrypted native graph pin. There are deliberately no NamespaceKey,
/// AddressKey, decoded Kv2 or plaintext namespace/header fields in this type.
pub struct NativeCipherPin {
    pub(crate) header: CipherReference,
    pub(crate) objects: Arc<BTreeMap<String, Arc<CipherObject>>>,
}
impl NativeCipherPin {
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
    pub fn ciphertext_bytes(&self) -> usize {
        self.objects.values().map(|o| o.ciphertext().len()).sum()
    }
    pub fn references(&self) -> impl Iterator<Item = &CipherReference> {
        self.objects.values().map(|object| &object.reference)
    }
    pub(crate) fn project_namespace(
        owner: &NativeReadView,
        key: &Key,
        frontier: NamespaceFrontier,
        cluster: &str,
        replay_epoch: u64,
        scope: NativeScope<'_>,
        deadline: OriginalDeadline,
    ) -> Result<Self, CustodyError> {
        deadline.check()?;
        if !key.matches_v6_frontier(&frontier) || !key.owns_namespace(scope.namespace) {
            return Err(CustodyError::Unavailable);
        }
        let parent = key.v6_parent_key(cluster, replay_epoch, scope.namespace)?;
        let domain = key.v6_domain(cluster, replay_epoch, scope)?;
        let graph = owner
            .encode(&parent, scope, &|| deadline.record_check())
            .map_err(|error| deadline.check().err().unwrap_or_else(|| error.into()))?;
        let mut objects = BTreeMap::new();
        let mut total = 0_usize;
        graph
            .visit_objects(
                |object| {
                    let reference = CipherReference::new(domain, object.reference());
                    let bytes = key.protect_v6_object(
                        cluster,
                        replay_epoch,
                        scope,
                        &reference,
                        object.bytes(),
                    )?;
                    total = total
                        .checked_add(bytes.len())
                        .filter(|size| *size <= crate::state_records::MAX_GRAPH_BYTES)
                        .ok_or(RecordError::TooLarge)?;
                    if objects
                        .insert(
                            reference.resource(),
                            Arc::new(CipherObject { reference, bytes }),
                        )
                        .is_some()
                    {
                        return Err(RecordError::Corrupt);
                    }
                    Ok(())
                },
                &|| deadline.record_check(),
            )
            .map_err(|error| deadline.check().err().unwrap_or_else(|| error.into()))?;
        let header = NativeHeader {
            format: "heptabao-namespace-native-kv2-v6".into(),
            cluster: cluster.into(),
            replay_epoch,
            scope: MountScope {
                namespace: scope.namespace.into(),
                mount: scope.mount.into(),
                incarnation: scope.incarnation,
            },
            custody: frontier,
            root: graph.root(),
        };
        let bytes = crate::secret_serde::to_vec(&header, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| CustodyError::TooLarge)?;
        deadline.check()?;
        let header = StagedObject::owner_chunk(&parent, &bytes)?;
        let reference = CipherReference::new(domain, header.reference());
        let bytes =
            key.protect_v6_object(cluster, replay_epoch, scope, &reference, header.bytes())?;
        let header = reference.clone();
        total
            .checked_add(bytes.len())
            .filter(|size| *size <= crate::state_records::MAX_GRAPH_BYTES)
            .ok_or(CustodyError::TooLarge)?;
        if objects
            .insert(
                reference.resource(),
                Arc::new(CipherObject { reference, bytes }),
            )
            .is_some()
        {
            return Err(CustodyError::Authentication);
        }
        deadline.check()?;
        Ok(Self {
            header,
            objects: Arc::new(objects),
        })
    }
    fn open_namespace(
        &self,
        key: &Key,
        frontier: &NamespaceFrontier,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
        deadline: OriginalDeadline,
    ) -> Result<NativeReadView, CustodyError> {
        deadline.check()?;
        let domain = key.v6_domain(cluster, epoch, scope)?;
        if self.header.domain != domain || !key.matches_v6_frontier(&frontier) {
            return Err(CustodyError::Unavailable);
        }
        let object = self
            .objects
            .get(&self.header.resource())
            .ok_or(CustodyError::Missing)?;
        if object.reference != self.header {
            return Err(CustodyError::Authentication);
        }
        object.validate()?;
        let plain = key.open_v6_object(cluster, epoch, scope, &self.header, object.ciphertext())?;
        deadline.check()?;
        let parent = key.v6_parent_key(cluster, epoch, scope.namespace)?;
        let plain_ref = self.header.plain_reference()?;
        let bytes = plain_ref.owner_chunk_payload(&parent, &plain)?;
        if bytes.len() > crate::state_record_root::MAX_ROOT_BYTES {
            return Err(CustodyError::TooLarge);
        }
        let header: NativeHeader =
            serde_json::from_slice(bytes).map_err(|_| CustodyError::Invalid)?;
        if crate::secret_serde::to_vec(&header, crate::state_record_root::MAX_ROOT_BYTES)
            .map_err(|_| CustodyError::Invalid)?
            .as_slice()
            != bytes
            || header.format != "heptabao-namespace-native-kv2-v6"
            || header.cluster != cluster
            || header.replay_epoch != epoch
            || &header.custody != frontier
            || header.scope.borrowed().namespace != scope.namespace
            || header.scope.borrowed().mount != scope.mount
            || header.scope.incarnation != scope.incarnation
        {
            return Err(CustodyError::Authentication);
        }
        let root = header
            .root
            .reference
            .as_ref()
            .ok_or(CustodyError::Invalid)?;
        if root.payload_bytes > crate::state_records::MAX_GRAPH_BYTES as u64
            || root.record_count > 100_000
        {
            return Err(CustodyError::TooLarge);
        }
        struct Reader<'a> {
            pin: &'a NativeCipherPin,
            key: &'a Key,
            domain: CipherDomain,
            cluster: &'a str,
            epoch: u64,
            scope: NativeScope<'a>,
            deadline: OriginalDeadline,
            seen: std::cell::RefCell<BTreeSet<ObjectId>>,
        }
        impl RecordReader for Reader<'_> {
            fn read_object(
                &self,
                reference: &ObjectRef,
            ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
                self.deadline.record_check()?;
                let wanted = CipherReference::new(self.domain, reference);
                let object = self
                    .pin
                    .objects
                    .get(&wanted.resource())
                    .ok_or(RecordError::Missing)?;
                if object.reference != wanted {
                    return Err(RecordError::Corrupt);
                }
                object.validate()?;
                let result = self.key.open_v6_object(
                    self.cluster,
                    self.epoch,
                    self.scope,
                    &wanted,
                    object.ciphertext(),
                )?;
                self.deadline.record_check()?;
                self.seen.borrow_mut().insert(reference.id);
                Ok(result)
            }
        }
        let reader = Reader {
            pin: self,
            key,
            domain,
            cluster,
            epoch,
            scope,
            deadline,
            seen: std::cell::RefCell::new(BTreeSet::new()),
        };
        let view =
            NativeCellGraph::open_view(&parent, scope, header.root.clone(), &reader, &|| {
                deadline.record_check()
            })
            .map_err(|error| deadline.check().err().unwrap_or_else(|| error.into()))?;
        deadline.check()?;
        if reader.seen.borrow().len() + 1 != self.objects.len() {
            return Err(CustodyError::Invalid);
        }
        Ok(view)
    }
    pub(crate) fn inspect_namespace(
        &self,
        key: &Key,
        frontier: &NamespaceFrontier,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
        deadline: OriginalDeadline,
        inspect: impl FnOnce(&NativeReadView) -> Result<(), CustodyError>,
    ) -> Result<NativeCustodyReceipt, CustodyError> {
        let view = self.open_namespace(key, frontier, cluster, epoch, scope, deadline)?;
        inspect(&view)?;
        deadline.check()?;
        let (paths, retained_versions, payload_records) = view.counts();
        Ok(NativeCustodyReceipt {
            paths,
            retained_versions,
            payload_records,
            objects: self.object_count(),
            ciphertext_bytes: self.ciphertext_bytes(),
            service_reader_admitted: false,
            namespace_custody_admitted: false,
            membership_fence_admitted: false,
            production_writer_admitted: false,
            migration_admitted: false,
            replacement_authority: false,
        })
    }

    /// Authenticate the complete old ciphertext closure before invoking the
    /// real KV2 mutation. The returned candidate is detached encrypted data,
    /// never an installed owner or a published root. Its caller must retain
    /// the original key/lease callback until after publication admission.
    pub(crate) fn mutate_namespace(
        &self,
        key: &Key,
        frontier: &NamespaceFrontier,
        cluster: &str,
        epoch: u64,
        scope: NativeScope<'_>,
        deadline: OriginalDeadline,
        method: &str,
        path: &str,
        body: &serde_json::Value,
        now: crate::auth::Timestamp,
        check_owner: &impl Fn() -> Result<(), CustodyError>,
    ) -> Result<NativeMutation, MutationError> {
        let check = || -> Result<(), CustodyError> {
            deadline.check()?;
            check_owner()?;
            deadline.check()
        };
        check()?;
        if !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(CustodyError::Invalid.into());
        }
        let mut view = self.open_namespace(key, frontier, cluster, epoch, scope, deadline)?;
        check()?;
        let response = view.mutate(method, path, body, now);
        // A failed or late mutation must never escape its original custody.
        check()?;
        let response = response.map_err(MutationError::Engine)?;
        let candidate = if response.mutated {
            let candidate = Self::project_namespace(
                &view,
                key,
                frontier.clone(),
                cluster,
                epoch,
                scope,
                deadline,
            )?;
            check()?;
            Some(candidate)
        } else {
            None
        };
        check()?;
        Ok(NativeMutation {
            expected_source: self.header.clone(),
            response,
            candidate,
        })
    }
}

pub(crate) enum MutationError {
    Custody(CustodyError),
    Engine(crate::engines::EngineError),
}
impl From<CustodyError> for MutationError {
    fn from(error: CustodyError) -> Self {
        Self::Custody(error)
    }
}
impl std::fmt::Debug for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custody(error) => f.debug_tuple("Custody").field(error).finish(),
            Self::Engine(error) => f
                .debug_struct("Engine")
                .field("status", &error.status)
                .finish_non_exhaustive(),
        }
    }
}
impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custody(error) => error.fmt(f),
            Self::Engine(error) => write!(
                f,
                "native KV2 mutation rejected with status {}",
                error.status
            ),
        }
    }
}
impl std::error::Error for MutationError {}

/// The response has the normal EngineResponse zeroizing destructor. No decoded
/// owner, namespace key, address key or plaintext pin can leave the operation.
pub(crate) struct NativeMutation {
    /// Required publication CAS base; namespace seal/key frontiers alone do not
    /// distinguish successive data mutations. This is still no publish permit.
    pub(crate) expected_source: CipherReference,
    pub(crate) response: crate::engines::EngineResponse,
    pub(crate) candidate: Option<NativeCipherPin>,
}

#[derive(Debug, Serialize)]
pub struct NativeCustodyReceipt {
    pub paths: usize,
    pub retained_versions: usize,
    pub payload_records: usize,
    pub objects: usize,
    pub ciphertext_bytes: usize,
    pub service_reader_admitted: bool,
    pub namespace_custody_admitted: bool,
    pub membership_fence_admitted: bool,
    pub production_writer_admitted: bool,
    pub migration_admitted: bool,
    pub replacement_authority: bool,
}

#[cfg(test)]
#[path = "v6_native_mutation_tests.rs"]
mod mutation_tests;
