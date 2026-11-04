//! Persist observed private time at the existing terminal writer boundary.
//! This is observation state, never a new actor/provider publication grant.
use super::*;

#[cfg(all(unix, feature = "native-v6-storage"))]
#[path = "service_token_precision_offline.rs"]
pub(super) mod offline;

// An affine receipt for this one terminal observation-only write. Fields and
// construction stay private to the writer; it cannot authorize a provider effect.
pub(super) struct TerminalClockReceipt {
    before: (
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    ),
    after: (
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    ),
}
impl TerminalClockReceipt {
    pub(super) fn advance(
        self,
        checkpoint: &mut Option<(
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        )>,
    ) {
        if checkpoint
            .as_ref()
            .is_some_and(|prior| *prior == self.before)
        {
            *checkpoint = Some(self.after);
        }
    }

    #[cfg(feature = "native-v6-storage")]
    pub(super) fn advance_native_cg(
        self,
        checkpoint: &mut Option<(
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        )>,
    ) -> Result<(), Response> {
        if checkpoint.as_ref() != Some(&self.before) {
            return Err(Response::error(
                503,
                "native CG terminal observation changed original checkpoint",
            ));
        }
        *checkpoint = Some(self.after);
        Ok(())
    }

    /// Snapshot keeps archive A immutable. This receipt binds only this
    /// operation's terminal observation B to the exact exported checkpoint A;
    /// it neither relabels archive bytes as B nor provides current-read custody.
    /// A new actual B proof must separately prove the direct A -> B root CAS.
    #[cfg(feature = "native-v6-ha")]
    pub(super) fn bind_native_snapshot(
        self,
        exported: (
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        ),
    ) -> Result<
        (
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        ),
        Response,
    > {
        if exported != self.before
            || !matches!(
                self.before.0,
                crate::state_record_root::StateIdentity::RecordsV6(_)
            )
            || !matches!(
                self.after.0,
                crate::state_record_root::StateIdentity::RecordsV6(_)
            )
            || self.before == self.after
        {
            return Err(Response::error(
                503,
                "snapshot terminal observation differs from archive source",
            ));
        }
        Ok(self.after)
    }

    /// Consume this actual observation-only publication exactly once. Native
    /// Auth must not replace an unrelated post-operation checkpoint with the
    /// receipt's newer frontier, even if both roots happen to share an Auth
    /// projection. This conveys no Actor or consensus-read authority.
    #[cfg(feature = "native-v6-storage")]
    pub(super) fn advance_native_auth(
        self,
        checkpoint: &mut Option<(
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        )>,
    ) -> Result<(), Response> {
        if checkpoint.as_ref() != Some(&self.before) {
            return Err(Response::error(
                503,
                "native authentication terminal observation changed its original checkpoint",
            ));
        }
        *checkpoint = Some(self.after);
        Ok(())
    }

    /// An ordinary KV output wrapper consumes the same actual terminal write,
    /// while retaining its KV Actor. This grants no Auth/resource authority.
    #[cfg(feature = "native-v6-storage")]
    pub(super) fn advance_native_response_wrapping(
        self,
        checkpoint: &mut Option<(
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        )>,
    ) -> Result<(), Response> {
        if checkpoint.as_ref() != Some(&self.before) {
            return Err(Response::error(
                503,
                "native response wrapping terminal checkpoint changed",
            ));
        }
        *checkpoint = Some(self.after);
        Ok(())
    }
}

impl Service {
    pub(super) fn persist_terminal_token_clock(
        &mut self,
        token_clock: Option<RequestClock>,
        now: u64,
    ) -> Result<(), Response> {
        self.persist_terminal_token_clock_with_receipt(token_clock, now, false)
            .map(drop)
    }

    pub(super) fn persist_terminal_token_clock_with_receipt(
        &mut self,
        token_clock: Option<RequestClock>,
        now: u64,
        retain_receipt: bool,
    ) -> Result<Option<TerminalClockReceipt>, Response> {
        let Some(state) = self.state.as_ref() else {
            return Ok(None);
        };
        // Historical stores do not acquire an extra write or private floor.
        let precise_token = state.has_token_api_precision_state();
        let opaque_artifact = state.engines.has_kubernetes_opaque_artifact_state();
        #[cfg(feature = "native-v6-storage")]
        let native_control_groups =
            self.native_root.is_some() && state.auth.has_control_group_state();
        #[cfg(not(feature = "native-v6-storage"))]
        let native_control_groups = false;
        if !precise_token && !opaque_artifact && !native_control_groups {
            return Ok(None);
        }
        if self.recovery_required || (precise_token && !state.auth.has_token_api_precision_state())
        {
            return Err(Response::error(
                503,
                "Token API observation authority is unavailable",
            ));
        }
        let clock = token_clock
            .ok_or_else(|| Response::error(503, "trusted token clock is required"))?
            .with_seconds_floor(now.max(state.engines.lease_clock()))
            .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?;
        let at = clock
            .observed_at()
            .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?;
        #[cfg(feature = "native-v6-storage")]
        let file_clock_profile = super::native_v6_writer::file_clock_profile::Scope::begin(
            self.native_root.is_some() && self.ha.is_none(),
        );
        #[cfg(feature = "native-v6-storage")]
        let candidate_sample = super::native_v6_writer::file_clock_profile::Span::begin(
            super::native_v6_writer::file_clock_profile::Phase::Candidate,
        );
        let mut candidate = state.clone();
        let time = candidate
            .engines
            .kubernetes_artifact_time(AuthorityTime::Precise(at))
            .map_err(|error| Response::error(503, &error.message))?;
        let time = candidate.auth.token_api_observed_time(time);
        let mut changed = candidate
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        changed |= candidate
            .engines
            .observe_kubernetes_artifact_time(time)
            .map_err(|error| Response::error(503, &error.message))?;
        if native_control_groups {
            changed |= candidate
                .auth
                .advance_control_group_observed(time)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        #[cfg(feature = "native-v6-storage")]
        drop(candidate_sample);
        if !changed {
            #[cfg(feature = "native-v6-storage")]
            file_clock_profile.returned_ok();
            return Ok(None);
        }
        candidate.schema = candidate.writer_schema();
        // Existing State/RecordPlan publication validates the same current
        // owner and floor. No ReadIndex, audit or provider deadline is renewed.
        #[cfg(all(unix, feature = "native-v6-storage"))]
        let offline_retention = offline::requested(self) && !retain_receipt;
        #[cfg(not(all(unix, feature = "native-v6-storage")))]
        let offline_retention = false;
        let before = if retain_receipt || offline_retention {
            Some((
                self.current_state_identity()?,
                self.external_effect_generation()?,
            ))
        } else {
            None
        };
        #[cfg(feature = "native-v6-storage")]
        let publication = if self.native_root.is_some() {
            self.commit_native_terminal_clock_floor(
                &mut candidate,
                clock,
                AuthorityTime::Precise(at),
            )
        } else {
            self.commit_state(&mut candidate)
        };
        #[cfg(not(feature = "native-v6-storage"))]
        let publication = self.commit_state(&mut candidate);
        if let Err(cause) = publication {
            let message = cause.body["errors"]
                .as_array()
                .and_then(|errors| errors.first())
                .and_then(Value::as_str)
                .unwrap_or("");
            let kind = match message {
                "HA record publication failed; no response released" => {
                    "record_publication_failure"
                }
                "server is sealed" => "sealed",
                "invalid replay epoch transition" => "replay_epoch",
                "record state failed authenticated validation" => "record_authentication",
                _ => "other",
            };
            eprintln!(
                "HBHA-DIAG-TERMINAL-FLOOR kind={kind} status={} error_sha={} state_loaded={} recovery_required={} barrier_loaded={} record_root={} activation={}",
                cause.status,
                hex(&crypto::digest(message.as_bytes())),
                self.state.is_some(),
                self.recovery_required,
                self.barrier_key.is_some(),
                self.record_root.is_some(),
                self.ha_activation.is_some()
            );
            return Err(Response::error(
                503,
                "Token API observation floor was not committed",
            ));
        }
        self.state = Some(candidate);
        let result = before
            .map(|before| {
                Ok(TerminalClockReceipt {
                    before,
                    after: (
                        self.current_state_identity()?,
                        self.external_effect_generation()?,
                    ),
                })
            })
            .transpose();
        #[cfg(all(unix, feature = "native-v6-storage"))]
        let result = match result {
            Ok(Some(receipt)) if offline_retention => {
                offline::record(self, receipt);
                Ok(None)
            }
            other => other,
        };
        #[cfg(feature = "native-v6-storage")]
        if result.is_ok() {
            file_clock_profile.returned_ok();
        }
        result
    }
}
