//! Typed Service graph <-> shared-key HA ciphertext closure adapter.
//!
//! No HTTP route or publication guard is opened here. Every operation consumes
//! the already captured original deadline and caller's original Actor/source
//! gate. A fresh ReadIndex witness must surround receiving/installation in the
//! coordinator; an old typed read cannot replace that consensus observation.
use super::*;
use crate::engines::kv2_native_records::{NativeReadView, PagedPayloadValidationMemo};
use crate::ha_state::ClusterStateCodec;
use crate::ha_state::native_v6::{
    CodecResult, NativeV6CipherBuilder, NativeV6CipherClosure, NativeV6CipherRead,
    NativeV6CodecError,
};
use crate::state_record_root_v6::{MountScope, ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectRef, RecordError};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};
use heptabao_raft_runtime::{
    LocalV6BlobStage, LocalV6ClosureReceipt, NativeV6CommitIntent, NativeV6PeerEnrollment,
    NativeV6PublishedRoot, RecordObjectRef,
};
use std::cell::RefCell;

#[path = "service_native_v6_retained_resources.rs"]
mod retained_resources;
pub(crate) use retained_resources::{
    NativeV6TypedRetainedResources, mark_native_v6_retained_roots,
};

/// The actual shared codec and local ciphertext store borrowed for one call.
/// This pair carries no proof, cached admission or renewed request deadline.
pub(super) struct NativeV6ObjectStorage<'a> {
    pub(super) codec: &'a ClusterStateCodec,
    pub(super) store: &'a LocalV6BlobStage,
}

struct OriginalGate<'a> {
    deadline: OriginalDeadline,
    actor: &'a mut dyn FnMut() -> CodecResult<()>,
}
impl OriginalGate<'_> {
    fn check(&mut self) -> CodecResult<()> {
        self.deadline
            .check()
            .map_err(|_| NativeV6CodecError::Gate)?;
        (self.actor)()?;
        self.deadline.check().map_err(|_| NativeV6CodecError::Gate)
    }
}

fn check(gate: &RefCell<OriginalGate<'_>>) -> CodecResult<()> {
    gate.try_borrow_mut()
        .map_err(|_| NativeV6CodecError::Gate)?
        .check()
}

fn record_error(error: NativeV6CodecError) -> RecordError {
    match error {
        NativeV6CodecError::Gate => RecordError::Invalid,
        NativeV6CodecError::TooLarge => RecordError::TooLarge,
        _ => RecordError::Corrupt,
    }
}

struct RecordingSource<'a, 'gate> {
    plan: &'a v6_records::NativeRootMigrationPlan,
    fallback: Option<&'a dyn ObjectSource>,
    reuse: Option<&'a NativeV6CipherRead>,
    builder: RefCell<NativeV6CipherBuilder<'a>>,
    gate: &'a RefCell<OriginalGate<'gate>>,
}
impl ObjectSource for RecordingSource<'_, '_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        check(self.gate).map_err(record_error)?;
        let bytes = if let Some(object) = self.plan.objects.get(&(domain.clone(), reference.id)) {
            if object.reference() != reference {
                return Err(RecordError::Corrupt);
            }
            Zeroizing::new(object.bytes().to_vec())
        } else {
            // The fallback is the actual root/generation-bound NativeSource.
            // Do not hold the Actor RefCell borrow while its independent
            // barrier/session checks run through the same original request.
            self.fallback
                .ok_or(RecordError::Missing)?
                .read(domain, reference)?
        };
        check(self.gate).map_err(record_error)?;
        self.builder
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?
            .stage_object(domain, reference, &bytes, self.reuse, &mut || {
                check(self.gate)
            })
            .map_err(record_error)?;
        check(self.gate).map_err(record_error)?;
        Ok(bytes)
    }
    fn object_count(&self) -> Option<usize> {
        // Initial migration cannot silently ignore a staged owner/object.
        // Incremental plans also read the admitted original durable closure;
        // only objects reached by the real reader enter the new directory.
        self.fallback.is_none().then_some(self.plan.objects.len())
    }
}

struct CipherSource<'a, 'gate> {
    codec: &'a ClusterStateCodec,
    store: &'a LocalV6BlobStage,
    closure: &'a NativeV6CipherRead,
    gate: &'a RefCell<OriginalGate<'gate>>,
}
impl ObjectSource for CipherSource<'_, '_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.closure
            .read_object(self.codec, self.store, domain, reference, &mut || {
                check(self.gate)
            })
            .map_err(record_error)
    }
    fn object_count(&self) -> Option<usize> {
        Some(self.closure.object_count())
    }
}

/// Only the complete actual V6 typed materializer can create this Service
/// preparation. It still grants no consensus, fsync quorum or response ACK.
pub(crate) struct PreparedNativeV6HaObjects {
    closure: NativeV6CipherClosure,
    deadline: OriginalDeadline,
}

/// One sealed proposal under the original request budget. It is intentionally
/// neither Clone nor Deserialize. Unknown publication requires reconciliation,
/// never automatic resubmission with a newly minted request clock.
pub(crate) struct NativeV6HaProposal {
    closure: NativeV6CipherClosure,
    intent: NativeV6CommitIntent,
    sealed: Vec<u8>,
    deadline: OriginalDeadline,
}

/// Detached protected owners/native views after the selected committed closure
/// passed the real typed reader. Installing it still requires local Shamir
/// custody, local root conditions and the caller's fresh consensus witness.
pub(super) struct ReceivedNativeV6HaObjects {
    closure: NativeV6CipherRead,
    protected: State,
    native: BTreeMap<MountScope, NativeReadView>,
    deadline: OriginalDeadline,
}

/// A bounded object borrowed only while the selected complete typed closure's
/// visitor is running. Private fields and no constructor/Clone/serde prevent a
/// ciphertext manifest or a caller's plaintext from minting this typed input.
/// The embedded check retains the visitor's same original Actor and deadline.
pub(super) struct VerifiedNativeV6Object<'a> {
    root: &'a RecordStateRootV6,
    root_bytes: &'a [u8],
    domain: &'a ObjectDomain,
    reference: &'a ObjectRef,
    plaintext: &'a [u8],
    original: &'a dyn Fn() -> CodecResult<()>,
}

impl VerifiedNativeV6Object<'_> {
    pub(super) fn root(&self) -> &RecordStateRootV6 {
        self.root
    }
    pub(super) fn root_bytes(&self) -> &[u8] {
        self.root_bytes
    }
    pub(super) fn domain(&self) -> &ObjectDomain {
        self.domain
    }
    pub(super) fn reference(&self) -> &ObjectRef {
        self.reference
    }
    pub(super) fn plaintext(&self) -> &[u8] {
        self.plaintext
    }
    pub(super) fn check_original(&self) -> CodecResult<()> {
        (self.original)()
    }
    pub(super) fn shares_visitor_with(&self, other: &Self) -> bool {
        std::ptr::eq(self.root, other.root)
            && std::ptr::eq(self.root_bytes, other.root_bytes)
            && std::ptr::eq(self.original, other.original)
    }
}

pub(super) fn prepare_native_v6_ha_objects(
    plan: &v6_records::NativeRootMigrationPlan,
    codec: &ClusterStateCodec,
    enrollment: &NativeV6PeerEnrollment,
    store: &LocalV6BlobStage,
    fallback: Option<&dyn ObjectSource>,
    reuse: Option<&NativeV6CipherRead>,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
) -> CodecResult<PreparedNativeV6HaObjects> {
    prepare_native_v6_ha_objects_with_payload_validation(
        plan,
        NativeV6ObjectStorage { codec, store },
        enrollment,
        fallback,
        reuse,
        original_actor,
        None,
    )
}

// The optional memo changes only repeated deterministic payload decoding.
// RecordingSource still reads, authenticates and stages each actual object
// under every original gate, producing a fresh epoch-bound cipher closure.
pub(super) fn prepare_native_v6_ha_objects_with_payload_validation(
    plan: &v6_records::NativeRootMigrationPlan,
    storage: NativeV6ObjectStorage<'_>,
    enrollment: &NativeV6PeerEnrollment,
    fallback: Option<&dyn ObjectSource>,
    reuse: Option<&NativeV6CipherRead>,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
    payload_validation: Option<&RefCell<PagedPayloadValidationMemo>>,
) -> CodecResult<PreparedNativeV6HaObjects> {
    let NativeV6ObjectStorage { codec, store } = storage;
    let gate = RefCell::new(OriginalGate {
        deadline: plan.deadline,
        actor: original_actor,
    });
    check(&gate)?;
    if plan
        .root
        .encode()
        .map_err(|_| NativeV6CodecError::Directory)?
        .as_slice()
        != plan.bytes.as_slice()
    {
        return Err(NativeV6CodecError::Directory);
    }
    let identity = plan
        .root
        .identity()
        .map_err(|_| NativeV6CodecError::Directory)?
        .digest();
    let context = ReadContext {
        expected_identity: ReadIdentity::RecordsV6(identity),
        cluster_id: &plan.root.cluster_id,
        replay_epoch: plan.root.replay_epoch,
        minimum_state_schema: plan.root.state_schema,
        maximum_state_schema: plan.root.state_schema,
        reader_format: crate::state_record_root_v6::READER_FORMAT,
    };
    let source = RecordingSource {
        plan,
        fallback,
        reuse,
        builder: RefCell::new(codec.native_v6_builder(&plan.root, enrollment, store)?),
        gate: &gate,
    };
    // Full owner, metadata, retained-history and every paged-payload block are
    // authenticated by their actual role/scoped ObjectRef key. The recording
    // source never asserts that a caller-provided list is a complete closure.
    #[cfg(feature = "private-ha-forward-diagnostic")]
    let started = {
        use std::io::Write as _;
        let started = std::time::Instant::now();
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-PRIVATE-PREPARE-STAGE event=start phase=typed_materialize planned_objects={}",
            plan.objects.len()
        );
        started
    };
    let result = match payload_validation {
        Some(memo) => v6_records::materialize_for_service_with_payload_validation(
            &plan.root, context, &source, memo,
        ),
        None => v6_records::materialize_for_service(&plan.root, context, &source),
    };
    #[cfg(feature = "private-ha-forward-diagnostic")]
    {
        use std::io::Write as _;
        let elapsed = started.elapsed().as_micros();
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-PRIVATE-PREPARE-STAGE event=end phase=typed_materialize planned_objects={} elapsed_us={} completed={}",
            plan.objects.len(),
            elapsed,
            result.is_ok()
        );
    }
    check(&gate)?;
    let (protected, native) = result.map_err(|_| NativeV6CodecError::Directory)?;
    drop((protected, native));
    if source.builder.borrow().object_count() == 0 {
        return Err(NativeV6CodecError::Directory);
    }
    let closure = source.builder.into_inner().finish(&mut || check(&gate))?;
    check(&gate)?;
    Ok(PreparedNativeV6HaObjects {
        closure,
        deadline: plan.deadline,
    })
}

impl PreparedNativeV6HaObjects {
    pub(crate) fn root_digest(&self) -> [u8; 32] {
        self.closure.root_digest()
    }
    pub(crate) fn local_closure(&self) -> LocalV6ClosureReceipt {
        self.closure.local_closure()
    }
    #[cfg(test)]
    pub(crate) fn references(&self) -> &[RecordObjectRef] {
        self.closure.references()
    }
    pub(crate) fn original_deadline(&self) -> OriginalDeadline {
        self.deadline
    }

    pub(crate) fn into_proposal(
        self,
        codec: &ClusterStateCodec,
        enrollment: &NativeV6PeerEnrollment,
        intent: NativeV6CommitIntent,
        original_actor: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<NativeV6HaProposal> {
        let gate = RefCell::new(OriginalGate {
            deadline: self.deadline,
            actor: original_actor,
        });
        check(&gate)?;
        let sealed = self
            .closure
            .seal_root(codec, enrollment, &intent, &mut || check(&gate))?;
        check(&gate)?;
        Ok(NativeV6HaProposal {
            closure: self.closure,
            intent,
            sealed,
            deadline: self.deadline,
        })
    }
}

impl NativeV6HaProposal {
    pub(crate) fn intent(&self) -> NativeV6CommitIntent {
        self.intent
    }
    pub(crate) fn sealed_root(&self) -> &[u8] {
        &self.sealed
    }
    pub(crate) fn references(&self) -> &[RecordObjectRef] {
        self.closure.references()
    }
    pub(crate) fn original_deadline(&self) -> OriginalDeadline {
        self.deadline
    }
    pub(crate) fn root(&self) -> &RecordStateRootV6 {
        self.closure.root()
    }
}

pub(super) fn open_native_v6_ha_objects(
    codec: &ClusterStateCodec,
    enrollment: &NativeV6PeerEnrollment,
    published: &NativeV6PublishedRoot,
    store: &LocalV6BlobStage,
    context: ReadContext<'_>,
    deadline: OriginalDeadline,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
) -> CodecResult<ReceivedNativeV6HaObjects> {
    open_native_v6_ha_objects_inner(
        NativeV6ObjectStorage { codec, store },
        enrollment,
        published,
        context,
        deadline,
        original_actor,
        None,
    )
}

pub(super) fn open_native_v6_ha_objects_with_payload_validation(
    storage: NativeV6ObjectStorage<'_>,
    enrollment: &NativeV6PeerEnrollment,
    published: &NativeV6PublishedRoot,
    context: ReadContext<'_>,
    deadline: OriginalDeadline,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
    payload_validation: &RefCell<PagedPayloadValidationMemo>,
) -> CodecResult<ReceivedNativeV6HaObjects> {
    open_native_v6_ha_objects_inner(
        storage,
        enrollment,
        published,
        context,
        deadline,
        original_actor,
        Some(payload_validation),
    )
}

fn open_native_v6_ha_objects_inner(
    storage: NativeV6ObjectStorage<'_>,
    enrollment: &NativeV6PeerEnrollment,
    published: &NativeV6PublishedRoot,
    context: ReadContext<'_>,
    deadline: OriginalDeadline,
    original_actor: &mut impl FnMut() -> CodecResult<()>,
    payload_validation: Option<&RefCell<PagedPayloadValidationMemo>>,
) -> CodecResult<ReceivedNativeV6HaObjects> {
    let NativeV6ObjectStorage { codec, store } = storage;
    let gate = RefCell::new(OriginalGate {
        deadline,
        actor: original_actor,
    });
    check(&gate)?;
    let closure =
        codec.open_native_v6_committed_read(enrollment, published, store, &mut || check(&gate))?;
    let source = CipherSource {
        codec,
        store,
        closure: &closure,
        gate: &gate,
    };
    let result = match payload_validation {
        Some(memo) => v6_records::materialize_for_service_with_payload_validation(
            closure.root(),
            context,
            &source,
            memo,
        ),
        None => v6_records::materialize_for_service(closure.root(), context, &source),
    };
    check(&gate)?;
    let (protected, native) = result.map_err(|_| NativeV6CodecError::Directory)?;
    check(&gate)?;
    Ok(ReceivedNativeV6HaObjects {
        closure,
        protected,
        native,
        deadline,
    })
}

impl ReceivedNativeV6HaObjects {
    pub(super) fn root(&self) -> &RecordStateRootV6 {
        self.closure.root()
    }
    pub(super) fn root_bytes(&self) -> &[u8] {
        self.closure.root_bytes()
    }
    #[cfg(test)]
    pub(super) fn cipher_closure(&self) -> &NativeV6CipherRead {
        &self.closure
    }

    /// Reauthenticate each bounded object before handing its plaintext to the
    /// target node's existing local-barrier stager. No plaintext is retained by
    /// this visitor, and it never writes a locator or active root itself.
    pub(super) fn visit_verified_objects(
        &self,
        codec: &ClusterStateCodec,
        store: &LocalV6BlobStage,
        original_actor: &mut impl FnMut() -> CodecResult<()>,
        visit: &mut impl FnMut(&VerifiedNativeV6Object<'_>) -> CodecResult<()>,
    ) -> CodecResult<()> {
        let gate = RefCell::new(OriginalGate {
            deadline: self.deadline,
            actor: original_actor,
        });
        check(&gate)?;
        let original = || check(&gate);
        self.closure.visit_objects(
            codec,
            store,
            &mut || check(&gate),
            &mut |domain, reference, plaintext| {
                let object = VerifiedNativeV6Object {
                    root: self.closure.root(),
                    root_bytes: self.closure.root_bytes(),
                    domain,
                    reference,
                    plaintext,
                    original: &original,
                };
                object.check_original()?;
                visit(&object)?;
                object.check_original()
            },
        )?;
        check(&gate)
    }

    /// Production installation may hold one bounded group while its new
    /// ciphertext files reach a common durability barrier. Typed capabilities
    /// are still private temporary borrows of this fully verified closure;
    /// neither their plaintext nor their original gate escapes this callback.
    pub(super) fn visit_verified_object_batches(
        &self,
        codec: &ClusterStateCodec,
        store: &LocalV6BlobStage,
        original_actor: &mut impl FnMut() -> CodecResult<()>,
        visit: &mut impl FnMut(&[VerifiedNativeV6Object<'_>]) -> CodecResult<()>,
    ) -> CodecResult<()> {
        let gate = RefCell::new(OriginalGate {
            deadline: self.deadline,
            actor: original_actor,
        });
        check(&gate)?;
        let original = || check(&gate);
        // Installation rewraps each object with the local HBA1 barrier, whose
        // exact overhead is 32 bytes. Reserve that overhead for all 32 possible
        // members before reading any batch, so plaintext plus all local seal
        // overhead stays within four MiB even for many tiny objects. The
        // durable owner independently verifies the sum of actual exact lengths.
        let maximum_plaintext_bytes =
            heptabao_durable_service::ImmutableSourceSession::MAX_BATCH_CIPHERTEXT_BYTES
                - 32 * heptabao_filesystem_guard::MAX_IMMUTABLE_BATCH_OBJECTS;
        self.closure.visit_object_batches(
            codec,
            store,
            maximum_plaintext_bytes,
            &mut || check(&gate),
            &mut |batch| {
                let objects: Vec<_> = batch
                    .iter()
                    .map(|(domain, reference, plaintext)| VerifiedNativeV6Object {
                        root: self.closure.root(),
                        root_bytes: self.closure.root_bytes(),
                        domain,
                        reference,
                        plaintext: plaintext.as_slice(),
                        original: &original,
                    })
                    .collect();
                for object in &objects {
                    object.check_original()?;
                }
                visit(&objects)?;
                for object in &objects {
                    object.check_original()?;
                }
                check(&gate)
            },
        )?;
        check(&gate)
    }

    pub(super) fn into_detached_parts(
        self,
        original_actor: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<(
        State,
        BTreeMap<MountScope, NativeReadView>,
        NativeV6CipherRead,
    )> {
        let gate = RefCell::new(OriginalGate {
            deadline: self.deadline,
            actor: original_actor,
        });
        check(&gate)?;
        Ok((self.protected, self.native, self.closure))
    }
}

#[cfg(test)]
#[path = "service_native_v6_ha_objects_tests.rs"]
mod tests;
