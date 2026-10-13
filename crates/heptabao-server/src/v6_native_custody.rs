//! Actual-key, operation-scoped native KV2 custody. Retained pins contain
//! encrypted objects only and cannot activate Service or manufacture a deadline.
#[cfg(test)]
use crate::engines::kv2_native_records::{NativeCellGraph, NativeReadView, NativeScope};
#[cfg(test)]
use crate::namespace_custody::Key;
use crate::namespace_custody::{Binding, InheritedParent};
#[cfg(test)]
use crate::state_record_root_v6::MountScope;
use crate::state_records::RecordError;
#[cfg(test)]
use crate::state_records::{Kv1Root, ObjectId, ObjectRef, RecordReader, StagedObject};
#[cfg(test)]
use crate::v6_record_resources::CipherDomain;
use crate::v6_record_resources::{CipherObject, CipherReference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::Arc;
#[cfg(any(test, feature = "fixture-native-v6-service"))]
use std::time::Instant;
#[cfg(test)]
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

#[cfg(any(test, feature = "fixture-native-v6-service"))]
#[derive(Clone, Copy)]
pub(crate) struct OriginalDeadline(Instant);
#[cfg(any(test, feature = "fixture-native-v6-service"))]
impl OriginalDeadline {
    pub(crate) fn capture() -> Result<Self, CustodyError> {
        let deadline = Self(crate::request_deadline::current().ok_or(CustodyError::Deadline)?);
        deadline.check()?;
        Ok(deadline)
    }
    #[cfg(feature = "fixture-native-v6-service")]
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
    #[cfg(test)]
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

#[cfg(test)]
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
    #[cfg(test)]
    pub(crate) header: CipherReference,
    pub(crate) objects: Arc<BTreeMap<String, Arc<CipherObject>>>,
}
#[cfg(test)]
pub(crate) struct NamespaceContext<'a> {
    key: &'a Key,
    frontier: &'a NamespaceFrontier,
    cluster: &'a str,
    epoch: u64,
    scope: NativeScope<'a>,
    deadline: OriginalDeadline,
}
#[cfg(test)]
pub(crate) struct MutationRequest<'a> {
    method: &'a str,
    path: &'a str,
    body: &'a serde_json::Value,
    now: crate::auth::Timestamp,
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
    #[cfg(test)]
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
        if self.header.domain != domain || !key.matches_v6_frontier(frontier) {
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
    #[cfg(test)]
    pub(crate) fn inspect_namespace(
        &self,
        context: NamespaceContext<'_>,
        inspect: impl FnOnce(&NativeReadView) -> Result<(), CustodyError>,
    ) -> Result<NativeCustodyReceipt, CustodyError> {
        let NamespaceContext {
            key,
            frontier,
            cluster,
            epoch,
            scope,
            deadline,
        } = context;
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
    #[cfg(test)]
    pub(crate) fn mutate_namespace(
        &self,
        context: NamespaceContext<'_>,
        request: MutationRequest<'_>,
        check_owner: &impl Fn() -> Result<(), CustodyError>,
    ) -> Result<NativeMutation, MutationError> {
        let NamespaceContext {
            key,
            frontier,
            cluster,
            epoch,
            scope,
            deadline,
        } = context;
        let MutationRequest {
            method,
            path,
            body,
            now,
        } = request;
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

#[cfg(test)]
pub(crate) enum MutationError {
    Custody(CustodyError),
    Engine(crate::engines::EngineError),
}
#[cfg(test)]
impl From<CustodyError> for MutationError {
    fn from(error: CustodyError) -> Self {
        Self::Custody(error)
    }
}
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
impl std::error::Error for MutationError {}

/// The response has the normal EngineResponse zeroizing destructor. No decoded
/// owner, namespace key, address key or plaintext pin can leave the operation.
#[cfg(test)]
pub(crate) struct NativeMutation {
    /// Required publication CAS base; namespace seal/key frontiers alone do not
    /// distinguish successive data mutations. This is still no publish permit.
    pub(crate) expected_source: CipherReference,
    pub(crate) response: crate::engines::EngineResponse,
    pub(crate) candidate: Option<NativeCipherPin>,
}

/// Data-only CAS evidence obtained from a separately authenticated, durable
/// publication cursor. A content-addressed header alone is insufficient:
/// publishing A -> B -> A can return the same root reference (ABA).
///
/// No constructor, successful preflight, or result here grants storage writes,
/// Service installation, migration, namespace membership, or response delivery.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePublicationFence {
    generation: std::num::NonZeroU64,
    header: CipherReference,
}
#[cfg(test)]
impl NativePublicationFence {
    /// The caller MUST authenticate this generation against its actual
    /// persistent root/linearized HA frontier; this helper cannot do so.
    pub(crate) fn observed(
        generation: u64,
        published: &NativeCipherPin,
    ) -> Result<Self, CustodyError> {
        let generation = std::num::NonZeroU64::new(generation).ok_or(CustodyError::Invalid)?;
        Ok(Self {
            generation,
            header: published.header.clone(),
        })
    }

    /// A stronger precommit *observation*: reauthenticate every reachable
    /// encrypted candidate object using the original namespace key and exact
    /// HA epoch. The bare generation/header preflight cannot detect missing
    /// non-root pages or post-projection ciphertext corruption. Even this
    /// authenticated check is NOT a durable Service publication: the actual
    /// writer must repeat the owner and generation CAS atomically with storage.
    pub(crate) fn authenticated_preflight(
        &self,
        actual: &Self,
        prepared: &NativeMutation,
        context: NamespaceContext<'_>,
        check_owner: &impl Fn() -> Result<(), CustodyError>,
    ) -> Result<Option<Self>, CustodyError> {
        let NamespaceContext {
            key,
            frontier,
            cluster,
            epoch,
            scope,
            deadline,
        } = context;
        let next = self.preflight(actual, prepared, deadline, check_owner)?;
        if let Some(pin) = prepared.candidate.as_ref() {
            // open_namespace proves the header MAC, all object AEAD tags,
            // scoped graph structure, and complete object consumption.
            let _authenticated =
                pin.open_namespace(key, frontier, cluster, epoch, scope, deadline)?;
            check_owner()?;
            deadline.check()?;
        }
        Ok(next)
    }

    /// Non-publishing defence-in-depth against an authenticated root change
    /// *during* expensive candidate AEAD verification. Only the durable/HA
    /// authority owner may implement `current`; a caller-supplied generation
    /// with no authenticated publication cursor has no production authority.
    ///
    /// Two observations do NOT grant a compare-and-swap or publish right.
    /// A production publisher must repeat the generation + custody + deadline
    /// checks *inside* the same linearized, crash-safe storage transaction.
    pub(crate) fn authenticated_preflight_against_live_cursor(
        &self,
        prepared: &NativeMutation,
        context: NamespaceContext<'_>,
        check_owner: &impl Fn() -> Result<(), CustodyError>,
        current: &impl Fn() -> Result<Self, CustodyError>,
    ) -> Result<Option<Self>, CustodyError> {
        let NamespaceContext {
            key,
            frontier,
            cluster,
            epoch,
            scope,
            deadline,
        } = context;
        deadline.check()?;
        let before = current()?;
        deadline.check()?;
        let next = self.authenticated_preflight(
            &before,
            prepared,
            NamespaceContext {
                key,
                frontier,
                cluster,
                epoch,
                scope,
                deadline,
            },
            check_owner,
        )?;
        // A->B->A may restore the original content-addressed encrypted root,
        // so compare the independently committed generation as well.
        let after = current()?;
        if after != before {
            return Err(CustodyError::Unavailable);
        }
        // The second snapshot may itself have revoked the namespace owner.
        check_owner()?;
        deadline.check()?;
        Ok(next)
    }

    /// Pure, non-publishing admission preflight, not a commit or reply grant.
    /// The outer writer must independently recheck the actual durable
    /// generation, authenticated ciphertext closure, namespace owner, quorum,
    /// and original deadline inside its one atomic publication transaction.
    pub(crate) fn preflight(
        &self,
        actual: &Self,
        prepared: &NativeMutation,
        deadline: OriginalDeadline,
        check_owner: &impl Fn() -> Result<(), CustodyError>,
    ) -> Result<Option<Self>, CustodyError> {
        deadline.check()?;
        check_owner()?;
        deadline.check()?;
        if self != actual || prepared.expected_source != actual.header {
            return Err(CustodyError::Unavailable);
        }
        if !prepared.response.mutated {
            if prepared.candidate.is_some() {
                return Err(CustodyError::Invalid);
            }
            check_owner()?;
            deadline.check()?;
            return Ok(None);
        }
        let pin = prepared.candidate.as_ref().ok_or(CustodyError::Invalid)?;
        if pin.header.domain != actual.header.domain
            || pin
                .objects
                .get(&pin.header.resource())
                .is_none_or(|object| object.reference != pin.header)
        {
            return Err(CustodyError::Authentication);
        }
        let generation = self
            .generation
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or(CustodyError::Invalid)?;
        check_owner()?;
        deadline.check()?;
        Ok(Some(Self {
            generation,
            header: pin.header.clone(),
        }))
    }
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
