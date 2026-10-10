//! One host-owned MFA queue tick, using the actual Service writer and commit.
//! The minimum eligible age is inferred, not an exact upstream TTL claim.
//! No HTTP actor, issued bearer or private first-factor grant is reconstructed.
use super::*;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

const TICK: Duration = Duration::from_secs(5);

impl Service {
    pub(in crate::service) fn maintain_mfa_challenges_with_clock(
        &mut self,
        clock: RequestClock,
    ) -> Result<bool, &'static str> {
        let deadline = clock
            .started()
            .checked_add(crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET)
            .ok_or("MFA janitor original deadline unavailable")?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        if Instant::now() >= deadline {
            return Err("MFA janitor original read deadline elapsed");
        }
        if self.private_shutdown_requested || self.state.is_none() {
            return Ok(false);
        }
        if self.recovery_required || self.audit_failed {
            return Err("MFA janitor requires recovery");
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| "MFA janitor HA lock unavailable")?;
            let local = ha
                .local_id()
                .map_err(|_| "MFA janitor HA identity unavailable")?;
            if ha.leader().map_err(|_| "MFA janitor leader unavailable")? != Some(local) {
                return Ok(false);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "MFA janitor original ReadIndex unavailable")?;
        }
        if Instant::now() >= deadline {
            return Err("MFA janitor original read deadline elapsed");
        }
        let Some(current) = &self.state else {
            return Ok(false);
        };
        // Refresh only from the SAME captured native clock after ReadIndex.
        let time = AuthorityTime::Precise(
            clock
                .observed_at()
                .map_err(|_| "MFA janitor original captured clock unavailable")?,
        );
        let mut next = current.clone();
        let prepared: Option<crate::auth::mfa::MfaJanitorHead> = next
            .auth
            .prepare_mfa_janitor_observed(time)
            .map_err(|_| "MFA janitor head custody unavailable")?;
        let Some(head) = prepared else {
            return Ok(false);
        };
        if let Some(expected) = head.ciphertext_owner() {
            let actual = next.sdk_namespace_ciphertext_owner(expected.binding.namespace())
                .map_err(|_| "MFA janitor actual capsule unavailable")?;
            if actual != *expected { return Err("MFA janitor actual capsule changed"); }
        }
        let binding = match head.closed_binding(&next.cluster_id)
            .map_err(|_| "MFA janitor original closed namespace binding unavailable")? {
            Some(binding) => binding,
            None => Self::mfa_native_binding(&next.namespaces, &next.cluster_id, head.namespace())
                .map_err(|_| "MFA janitor actual namespace binding unavailable")?,
        };
        next.auth
            .finish_mfa_janitor_observed(head, binding, time)
            .map_err(|_| "MFA janitor original head finalize rejected")?;
        if Instant::now() >= deadline {
            return Err("MFA janitor original admission deadline elapsed");
        }
        let fingerprint = self.request_fingerprint("INTERNAL", "mfa/janitor", "", "");
        self.audit_event("mfa-janitor-request", &fingerprint, time.seconds(), None)
            .map_err(|_| "MFA janitor request audit unavailable")?;
        next.schema = next.writer_schema();
        let result = self.commit_state(&mut next);
        if result.is_ok() {
            self.state = Some(next);
        }
        let status = if result.is_ok() { 204 } else { 503 };
        if self
            .audit_event(
                "mfa-janitor-response",
                &fingerprint,
                time.seconds(),
                Some(status),
            )
            .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Err("MFA janitor result audit unavailable; recovery required");
        }
        result.map_err(|_| "MFA janitor original commit failed")?;
        Ok(true)
    }
}

/// The HTTP host owns this single join handle. Weak ownership cannot keep the
/// Service alive. Stop wakes the original receiver; Drop joins that same thread.
pub(crate) struct MfaJanitorWorker {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}
impl Drop for MfaJanitorWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take()
            && join.join().is_err()
        {
            eprintln!("heptabao-mfa-janitor: original worker panicked");
        }
    }
}
pub(crate) fn start_mfa_janitor_worker(
    service: &Arc<Mutex<Service>>,
) -> Result<MfaJanitorWorker, String> {
    let service = Arc::downgrade(service);
    let (stop, receiver) = mpsc::channel();
    let join = thread::Builder::new()
        .name("heptabao-mfa-janitor".into())
        .spawn(move || {
            // A slow or missed attempt starts another wait; there is no catchup.
            while let Err(mpsc::RecvTimeoutError::Timeout) = receiver.recv_timeout(TICK) {
                let Some(service) = service.upgrade() else {
                    break;
                };
                let started = Instant::now();
                let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    continue;
                };
                let Ok(clock) = RequestClock::anchored(wall, started) else {
                    continue;
                };
                let deadline = started + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET;
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
                let Ok(mut writer) = service.try_lock() else {
                    continue;
                };
                if Instant::now() >= deadline {
                    continue;
                }
                if writer.maintain_mfa_challenges_with_clock(clock).is_err() {
                    eprintln!("heptabao-mfa-janitor: original retirement remains pending");
                }
            }
        })
        .map_err(|_| "cannot start MFA janitor worker".to_owned())?;
    Ok(MfaJanitorWorker {
        stop,
        join: Some(join),
    })
}

// Called only after actual key/MAC/assets restoration has completed. Generic
// verification restores never consume receipts or create a publication.
impl Service {
    pub(in crate::service) fn complete_mfa_namespace_retirements(&mut self) -> Result<(), Response> {
        let result = (|| -> Result<(), Response> {
            let Some(current) = self.state.as_ref() else { return Ok(()); };
            let mut next = current.clone();
            let count = next.auth.consume_authenticated_mfa_terminal_receipts()
                .map_err(|error| Response::error(503, &error.message))?;
            if count == 0 { return Ok(()); }
            let deadline = crate::request_deadline::current()
                .ok_or_else(|| Response::error(503, "MFA restored cleanup has no original request deadline"))?;
            if Instant::now() >= deadline {
                return Err(Response::error(503, "MFA restored cleanup original deadline elapsed"));
            }
            let at = next.auth.mfa_terminal_receipt_clock()
                .ok_or_else(|| Response::error(503, "MFA original terminal observation absent"))?;
            let fingerprint = self.request_fingerprint("INTERNAL", "mfa/restored-terminal", "", "");
            self.audit_event("mfa-restored-terminal-request", &fingerprint, at.seconds(), None)
                .map_err(|_| Response::error(503, "MFA restored cleanup request audit unavailable"))?;
            next.schema = next.writer_schema();
            self.commit_state(&mut next)?;
            self.state = Some(next);
            self.audit_event("mfa-restored-terminal-response", &fingerprint, at.seconds(), Some(204))
                .map_err(|_| Response::error(503, "MFA restored cleanup response audit unavailable"))?;
            if Instant::now() >= deadline {
                return Err(Response::error(503, "MFA restored cleanup original deadline elapsed"));
            }
            Ok(())
        })();
        if result.is_err() {
            // This drops all loaded namespace keys and the local barrier, not
            // just a public response. No challenge can mint after an unknown commit.
            self.fence_recovery_delivery();
        }
        result
    }
}
