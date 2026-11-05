//! Explicit normal-server admission for the bounded root V6 storage profile.
//! Configuration binds a runtime owner; it never supplies a key, actor, cursor
//! or time budget. The existing native transaction owns all physical effects.
use super::*;
use crate::configuration::NativeStorageProfile;

pub(super) const ACTIVATE_PATH: &str = "sys/storage/native-v6/activate";

#[path = "service_native_file_gc.rs"]
pub(super) mod file_gc;

#[cfg(feature = "native-v6-ha")]
#[path = "service_native_ha_gc.rs"]
pub(super) mod ha_gc;

impl Service {
    /// Read-only startup eligibility for an already provisioned Shamir seed.
    /// This never initializes a cohort or authenticates its encrypted state.
    /// Normal unseal, peer identity, ReadIndex and native graph admission must
    /// still establish their own authority after the real runtime is opened.
    #[cfg(unix)]
    pub(crate) fn validate_native_v6_raft_seed(data_dir: &Path) -> Result<(), String> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::os::unix::fs::MetadataExt;
        let parent = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(data_dir)
            .map_err(|_| "native V6 Raft requires an existing private Shamir file seed")?;
        let held = parent
            .metadata()
            .map_err(|_| "native V6 Raft seed is unavailable")?;
        if held.mode() & 0o077 != 0 {
            return Err("native V6 Raft seed directory must be private".into());
        }
        let seal = load_seal_metadata(data_dir)?
            .ok_or("native V6 Raft requires a provisioned Shamir seal; fresh HA initialization is not admitted")?;
        if seal.is_wrapper() || seal.share_format != "shamir-v1" {
            return Err("native V6 Raft requires the actual Shamir seal, without Wrapper or legacy key substitution".into());
        }
        if load_durable_profile(data_dir)?.is_some()
            || postgres_pending_exists(data_dir)?
            || initialization_recovery_pending(data_dir)?
        {
            return Err("native V6 Raft requires acknowledged file initialization without a pending or provider-owned state".into());
        }
        let file = File::from(
            openat(
                &parent,
                "state.hbs",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| "native V6 Raft requires an existing sealed file checkpoint")?,
        );
        check_private_file(&file)
            .map_err(|_| "native V6 Raft checkpoint must be a private regular file")?;
        if file
            .metadata()
            .map_err(|_| "native V6 Raft checkpoint is unavailable")?
            .len()
            == 0
        {
            return Err("native V6 Raft checkpoint is empty".into());
        }
        let current = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(data_dir)
            .and_then(|directory| directory.metadata().map_err(Into::into))
            .map_err(|_| "native V6 Raft seed directory changed during admission")?;
        if held.dev() != current.dev() || held.ino() != current.ino() {
            return Err("native V6 Raft seed directory changed during admission".into());
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn validate_native_v6_raft_seed(_data_dir: &Path) -> Result<(), String> {
        Err("native V6 Raft requires supported descriptor-bound file custody".into())
    }

    /// Called once by ordinary HTTP startup after backend/provider installation
    /// and before accepting requests. Initialization and unseal remain explicit.
    pub(crate) fn configure_native_v6_storage(
        &mut self,
        profile: NativeStorageProfile,
    ) -> Result<(), String> {
        if self.native_storage_profile.is_some()
            || self.native_candidate_profile.is_some()
            || self.state.is_some()
            || self.durable.is_some()
            || self.barrier_key.is_some()
            || self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some()
            || self
                .seal
                .as_ref()
                .is_some_and(|seal| seal.is_wrapper() || seal.share_format != "shamir-v1")
            || self.initialized() && self.seal.is_none()
        {
            return Err(
                "native V6 storage must bind a sealed Shamir file owner once at startup".into(),
            );
        }
        match profile {
            NativeStorageProfile::File => {
                self.native_candidate_profile = Some(
                    native_v6_reader::NativeCandidateProfile::capture(self).map_err(
                        |_| "native V6 file storage requires standalone sealed file custody",
                    )?,
                );
            }
            NativeStorageProfile::Raft => {
                #[cfg(feature = "native-v6-ha")]
                {
                    let ha = self.ha.as_ref().ok_or("native V6 Raft owner is absent")?;
                    if !ha
                        .lock()
                        .map_err(|_| "native V6 Raft owner is unavailable")?
                        .native_v6_enabled()
                    {
                        return Err("native V6 Raft storage requires its startup-owned workers and ciphertext custody".into());
                    }
                    Self::validate_native_v6_raft_seed(&self.data_dir)?;
                }
                #[cfg(not(feature = "native-v6-ha"))]
                return Err("native V6 Raft support is absent from this binary".into());
            }
        }
        self.native_storage_profile = Some(profile);
        Ok(())
    }

    /// Reject unsupported live owners before activation or restore can commit.
    /// This does not remove state or turn a successful migration into a claim
    /// that every secret engine and authentication backend is native-ready.
    pub(super) fn require_native_storage_state(&self, state: &State) -> Result<(), Response> {
        if self.native_storage_profile.is_none() {
            return Ok(());
        }
        if self.rekey.is_some()
            || initialization_recovery_pending(&self.data_dir)
                .map_err(|_| Response::error(503, "initialization recovery state is unavailable"))?
        {
            return Err(Response::error(
                409,
                "finish initialization acknowledgement and rekey before native V6 activation or restore",
            ));
        }
        if !state.raft_admin.is_default() {
            return Err(Response::error(
                409,
                "native V6 storage requires default Raft administration; retain the V5 owner until its management policy is migrated",
            ));
        }
        if !state.database.is_empty()
            || namespaces::native_plain::profile(state).is_err()
            || !native_controlgroups::supported_state(state)
        {
            return Err(Response::error(
                409,
                "native V6 root storage supports KV, local Transit, local token/AppRole/certificate authentication and root token cubbyhole; unsupported live owners require separate migration",
            ));
        }
        Ok(())
    }

    pub(super) fn activate_configured_native_v6_route(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        if self.native_storage_profile.is_none() {
            return Response::error(
                409,
                "native V6 activation requires an explicitly configured storage profile",
            );
        }
        self.activate_native_v6_route(admitted, principal, request)
    }
}

/// The authenticated native root can only enter through a bound native owner.
/// A missing/mismatched profile never falls back to a V5 JSON state decoder.
pub(super) fn reject_unconfigured_native_root(
    durable: &DurableService<AeadBarrier>,
) -> Result<(), Response> {
    let bytes = durable
        .get("system", "state")
        .map_err(|_| Response::error(503, "storage format is unavailable"))?
        .ok_or_else(|| Response::error(503, "storage root is absent"))?;
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        storage_format: Option<String>,
    }
    let probe: Probe = serde_json::from_slice(bytes.expose())
        .map_err(|_| Response::error(503, "storage format is invalid"))?;
    if probe.storage_format.as_deref() == Some(crate::state_record_root_v6::STORAGE_FORMAT) {
        return Err(Response::error(
            503,
            "native V6 root requires its configured native storage owner; V5 fallback is forbidden",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "service_native_storage_tests.rs"]
mod tests;
