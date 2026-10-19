//! Explicit native HA custody over this running process's real Raft instance.
//! A read handle grants neither an Actor nor a local publication or response.
use super::*;
use crate::v6_native_custody::OriginalDeadline;
use heptabao_ha_service::{
    AuthenticatedPeerFrame, HaError, NativeV6ClosureReceiver, NativeV6CommittedRootSource,
    is_native_v6_closure_frame, is_native_v6_root_pull_frame, recover_native_v6_committed_closure,
};
use heptabao_raft_runtime::{
    LocalV6BlobStage, NativeV6CommittedRootRead, NativeV6PeerEnrollment, NativeV6PublishedRoot,
};
use std::sync::OnceLock;

#[path = "ha_native_v6_archive_repair.rs"]
mod archive_repair;
pub(crate) use archive_repair::NativeV6ArchiveRootAnchor;

#[path = "ha_native_v6_publication.rs"]
mod publication;
pub(crate) use publication::NativeHaPublicationError;

#[path = "ha_native_v6_epoch_restore.rs"]
mod epoch_restore;

#[cfg(test)]
#[path = "ha_native_v6_install_test_support.rs"]
pub(super) mod install_test_support;

pub(super) struct NativeV6Runtime {
    identity: Arc<()>,
    root: PathBuf,
    storage: OnceLock<Arc<LocalV6BlobStage>>,
    receiver: OnceLock<Arc<NativeV6ClosureReceiver>>,
    root_source: OnceLock<Arc<NativeV6CommittedRootSource>>,
    configured_pins: BTreeMap<u64, [u8; 32]>,
    pub(super) transport: MutualTlsPeerTransport,
    eligible: bool,
}

impl NativeV6Runtime {
    pub(super) fn configured(
        config: &HaProcessConfig,
        client: Arc<ClientConfig>,
        local_leaf: [u8; 32],
    ) -> Result<Self, String> {
        let parsed = parse_peers(config)?;
        let configured_pins = parsed
            .iter()
            .map(|peer| (peer.id, peer.certificate_sha256))
            .collect();
        // Self is an actual TLS destination. It never becomes an implicit vote.
        let endpoints = parsed
            .iter()
            .map(|peer| (peer.node.clone(), peer.endpoint.clone()))
            .collect();
        let transport = MutualTlsPeerTransport::new(
            endpoints,
            client,
            Duration::from_millis(config.forward_timeout_ms),
        )
        .map_err(|error| error.to_string())?;
        let eligible = !config.allow_legacy_peer_v1
            && !config.outbound_legacy_peer_v1()
            && parsed.len() >= 3
            && parsed
                .iter()
                .all(|peer| peer.certificate_sha256_next.is_none())
            && parsed
                .iter()
                .any(|peer| peer.id == config.node_id && peer.certificate_sha256 == local_leaf);
        Ok(Self {
            identity: Arc::new(()),
            root: config.raft_dir.join("native-v6-ciphertext"),
            storage: OnceLock::new(),
            receiver: OnceLock::new(),
            root_source: OnceLock::new(),
            configured_pins,
            transport,
            eligible,
        })
    }

    fn enabled(&self) -> bool {
        self.eligible && self.storage.get().is_some()
    }

    pub(super) fn enable(&self) -> Result<(), String> {
        if !self.eligible || self.storage.get().is_some() {
            return Err("native HA requires an explicit fresh eligibility installation".into());
        }
        // The immutable store retains the no-symlink descriptor and exclusive
        // writer lock; subsequent reads and writes never reopen by pathname.
        let parent = self
            .root
            .parent()
            .ok_or("native HA storage parent absent")?;
        let directory = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(parent)
            .map_err(|_| "native HA storage parent custody unavailable")?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&self.root) {
            Ok(()) => {
                directory
                    .sync_all()
                    .map_err(|_| "native HA storage parent fsync unavailable")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("native HA ciphertext store creation unavailable".into()),
        }
        let storage = LocalV6BlobStage::open_existing(&self.root)
            .map_err(|_| "native HA ciphertext custody unavailable")?;
        self.storage
            .set(Arc::new(storage))
            .map_err(|_| "native HA eligibility was concurrently installed".to_owned())
    }

    fn validate_enrollment(
        &self,
        codec: &ClusterStateCodec,
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<(), String> {
        self.validate_enrollment_binding(codec.native_v6_cluster_digest(), enrollment)
    }

    fn validate_enrollment_binding(
        &self,
        cluster_digest: [u8; 32],
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<(), String> {
        if !self.enabled()
            || enrollment.cluster_digest() != cluster_digest
            || enrollment.pins() != &self.configured_pins
        {
            return Err("native HA committed enrollment differs from configured custody".into());
        }
        Ok(())
    }

    /// Only the shared listener's actual TLS handle can reach native ingress.
    /// Initial pins come from an actual committed enrollment, never the wire.
    /// Each receiver/source subsequently obtains its own fresh applied proof.
    pub(super) fn handle_authenticated(
        &self,
        frame: AuthenticatedPeerFrame,
        node: &Arc<ProcessRaftNode>,
        handle: &tokio::runtime::Handle,
        cluster_digest: [u8; 32],
    ) -> Result<Vec<u8>, HaError> {
        if !self.enabled() || Instant::now() >= frame.deadline() || !frame.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let push = is_native_v6_closure_frame(frame.payload());
        let pull = is_native_v6_root_pull_frame(frame.payload());
        if !push && !pull {
            return Err(HaError::InvalidFrame);
        }
        if push && self.receiver.get().is_none() || pull && self.root_source.get().is_none() {
            let (witness, enrollment, _) = handle
                .block_on(node.native_v6_application_read_witness(frame.deadline()))
                .map_err(|_| HaError::OutcomeUnknown)?;
            let enrollment = enrollment.ok_or(HaError::InvalidMembership)?;
            self.validate_enrollment_binding(cluster_digest, &enrollment)
                .map_err(|_| HaError::InvalidMembership)?;
            let storage = self.storage.get().ok_or(HaError::Transport)?;
            if push {
                let receiver = NativeV6ClosureReceiver::new(
                    node.clone(),
                    handle.clone(),
                    storage.clone(),
                    &enrollment,
                )?;
                // A concurrent initializer may win. Both came from actual
                // committed enrollment; the retained receiver rechecks it.
                let _ = self.receiver.set(Arc::new(receiver));
            } else {
                let source = NativeV6CommittedRootSource::new(
                    node.clone(),
                    handle.clone(),
                    storage.clone(),
                    &enrollment,
                )?;
                let _ = self.root_source.set(Arc::new(source));
            }
            handle
                .block_on(heptabao_raft_runtime::with_read_index_deadline(
                    frame.deadline(),
                    node.verify_application_read_witness(&witness),
                ))
                .map_err(|_| HaError::OutcomeUnknown)?;
        }
        if push {
            self.receiver
                .get()
                .ok_or(HaError::Transport)?
                .handle_authenticated(frame)
        } else {
            self.root_source
                .get()
                .ok_or(HaError::Transport)?
                .handle_authenticated(frame)
        }
    }
}

/// Only this process's actual committed-root observation constructs the handle.
/// Keeping the instance identity alive prevents pointer reuse after a reopen.
pub(crate) struct CommittedNativeV6Read {
    instance: Arc<()>,
    selected: NativeV6CommittedRootRead,
    deadline: OriginalDeadline,
}
impl CommittedNativeV6Read {
    pub(crate) fn enrollment(&self) -> &NativeV6PeerEnrollment {
        self.selected.enrollment()
    }
    pub(crate) fn published(&self) -> &NativeV6PublishedRoot {
        self.selected.root()
    }
    pub(crate) fn deadline(&self) -> OriginalDeadline {
        self.deadline
    }
    /// Only the owning HaProcess may reduce its verified native selection to
    /// the original applied witness; no replacement observation is minted.
    pub(super) fn into_application_witness(self) -> heptabao_raft_runtime::ApplicationReadWitness {
        self.selected.into_application_witness()
    }
}

impl HaProcess {
    pub(super) fn ensure_native_v6_application_identity(
        &self,
        expected: crate::state_record_root::StateIdentity,
    ) -> Result<(), String> {
        let deadline = OriginalDeadline::capture().map_err(|error| error.to_string())?;
        let read = self
            .native_v6_committed_read(deadline)?
            .ok_or("native HA application root absent")?;
        if !matches!(
            expected,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ) || expected.digest() != read.published().root_digest()
        {
            return Err("native HA local identity is not the committed root".into());
        }
        self.with_native_v6_source(&read, |codec, store| {
            let closure = codec
                .open_native_v6_committed_closure(
                    read.enrollment(),
                    read.published(),
                    store,
                    &mut || {
                        self.verify_native_v6_committed_read(&read)
                            .map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Gate)
                    },
                )
                .map_err(|_| "native HA authenticated closure unavailable")?;
            if closure
                .root()
                .identity()
                .map_err(|_| "native HA root identity invalid")?
                != expected
            {
                return Err("native HA root identity differs".to_owned());
            }
            self.verify_native_v6_committed_read(&read)
        })?
    }

    /// Startup eligibility only. HTTP root activation separately authenticates
    /// the current Actor, exact migration source and original request deadline.
    pub fn enable_native_v6_candidate(&mut self) -> Result<(), String> {
        if self.node.is_none() {
            return Err("HA process is shut down".into());
        }
        if self
            .listener
            .as_ref()
            .is_none_or(|listener| !listener.native_capacity_installed)
        {
            return Err(
                "native HA requires explicit candidate startup with reserved peer workers".into(),
            );
        }
        if self.native_v6_enabled() {
            return Ok(());
        }
        self.native_v6
            .as_ref()
            .ok_or("native HA runtime absent")?
            .enable()
    }

    pub(crate) fn native_v6_enabled(&self) -> bool {
        self.node.is_some()
            && self
                .native_v6
                .as_ref()
                .is_some_and(|runtime| runtime.enabled())
    }

    /// Fixture-only readiness observation, without fetching or repairing any
    /// shared ciphertext. Returned data grants no Service/local-install/Actor
    /// authority; the actual cold unseal still owes complete graph validation.
    #[cfg(test)]
    pub(crate) fn observe_native_v6_root_without_materialization_for_test(
        &self,
        deadline: OriginalDeadline,
    ) -> Result<Option<(u64, NativeV6PublishedRoot)>, String> {
        deadline.check().map_err(|error| error.to_string())?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA was not explicitly enabled")?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let selected = self
            .runtime
            .block_on(node.native_v6_committed_root_read(deadline.instant()))
            .map_err(|error| error.to_string())?;
        let Some(selected) = selected else {
            deadline.check().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        native.validate_enrollment(&self.codec, selected.enrollment())?;
        self.runtime
            .block_on(heptabao_raft_runtime::with_read_index_deadline(
                deadline.instant(),
                node.verify_native_v6_committed_root_read(&selected),
            ))
            .map_err(|error| error.to_string())?;
        deadline.check().map_err(|error| error.to_string())?;
        Ok(Some((
            selected.enrollment().epoch(),
            selected.root().clone(),
        )))
    }

    pub(crate) fn native_v6_committed_read(
        &self,
        deadline: OriginalDeadline,
    ) -> Result<Option<CommittedNativeV6Read>, String> {
        deadline.check().map_err(|error| error.to_string())?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA was not explicitly enabled")?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let selected = self
            .runtime
            .block_on(node.native_v6_committed_root_read(deadline.instant()))
            .map_err(|error| error.to_string())?;
        let Some(selected) = selected else {
            deadline.check().map_err(|error| error.to_string())?;
            return Ok(None);
        };
        native.validate_enrollment(&self.codec, selected.enrollment())?;
        // The selected process handle is consumed. A missing/new leader must
        // pull the exact committed closure from actual pinned voters. Repair
        // writes only immutable local ciphertext, never a Raft command or ACK.
        let storage = native
            .storage
            .get()
            .ok_or("native HA ciphertext store unavailable")?;
        let recovered = recover_native_v6_committed_closure(
            node,
            self.runtime.handle(),
            &native.transport,
            &self.peers,
            storage,
            selected,
        )
        .map_err(|error| error.to_string())?;
        let (selected, _) = recovered.into_parts();
        let read = CommittedNativeV6Read {
            instance: native.identity.clone(),
            selected,
            deadline,
        };
        self.verify_native_v6_committed_read(&read)?;
        Ok(Some(read))
    }

    pub(crate) fn verify_native_v6_committed_read(
        &self,
        read: &CommittedNativeV6Read,
    ) -> Result<(), String> {
        read.deadline.check().map_err(|error| error.to_string())?;
        let native = self.native_v6.as_ref().ok_or("native HA runtime absent")?;
        if !Arc::ptr_eq(&read.instance, &native.identity) {
            return Err("native HA read belongs to a different process instance".into());
        }
        native.validate_enrollment(&self.codec, read.enrollment())?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        self.runtime
            .block_on(heptabao_raft_runtime::with_read_index_deadline(
                read.deadline.instant(),
                node.verify_native_v6_committed_root_read(&read.selected),
            ))
            .map_err(|error| {
                // Failure observation only. Keep the same opaque witness,
                // original operation/read bounds and original error result.
                #[cfg(feature = "private-ha-forward-diagnostic")]
                {
                    use std::io::Write as _;
                    let observed = std::time::Instant::now();
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "HBHA-PRIVATE-READ-WITNESS-FAIL operation_expired={} read_index_expired={} generation={}",
                        observed >= read.deadline.instant(),
                        observed >= read.selected.read_index_deadline(),
                        read.selected.application_generation(),
                    );
                }
                error.to_string()
            })?;
        read.deadline.check().map_err(|error| error.to_string())
    }

    /// The caller keeps the same HaProcess borrow for gates inside the closure.
    /// There is deliberately no fallible post-callback wrapper: that could hide
    /// a local publication's precise unknown/superseded result.
    pub(crate) fn with_native_v6_source<T>(
        &self,
        read: &CommittedNativeV6Read,
        f: impl FnOnce(&ClusterStateCodec, &LocalV6BlobStage) -> T,
    ) -> Result<T, String> {
        self.verify_native_v6_committed_read(read)?;
        let store = self
            .native_v6
            .as_ref()
            .and_then(|native| native.storage.get())
            .ok_or("native HA ciphertext store unavailable")?;
        Ok(f(&self.codec, store))
    }
}
