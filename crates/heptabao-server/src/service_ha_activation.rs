//! Process-local application activation, serialized by the Service writer.
//! Metrics identify the term; only the authenticated application gate publishes
//! the event. Neither a diagnostic request nor an election observation is a clock.
use super::*;
use heptabao_raft_runtime::LocalLeaderObservation;
use std::{sync::mpsc, thread::JoinHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ActivationKey {
    local_id: u64,
    term: u64,
}
impl ActivationKey {
    pub(super) fn from_observation(observation: LocalLeaderObservation) -> Option<Self> {
        (observation.local_is_leader && observation.leader == Some(observation.local_id)).then_some(
            Self {
                local_id: observation.local_id,
                term: observation.term,
            },
        )
    }
}

pub(super) struct LeaderActivation {
    key: ActivationKey,
    // A failed/out-of-range host clock does not become a fabricated timestamp.
    // Keep the completed event without a time; later probes cannot retimestamp it.
    time: Option<String>,
}
impl LeaderActivation {
    pub(super) fn matches(&self, key: ActivationKey) -> bool {
        self.key == key
    }
    pub(super) fn active_time(&self, key: ActivationKey) -> Option<&str> {
        (self.key == key).then_some(self.time.as_deref()).flatten()
    }
}

fn activation_time(time: SystemTime) -> Option<String> {
    let elapsed = time.duration_since(UNIX_EPOCH).ok()?;
    let mut formatted = database::unix_rfc3339(elapsed.as_secs()).ok()?;
    let nanos = elapsed.subsec_nanos();
    if nanos != 0 {
        formatted.pop();
        formatted.push('.');
        formatted.push_str(format!("{nanos:09}").trim_end_matches('0'));
        formatted.push('Z');
    }
    Some(formatted)
}

fn publish(
    slot: &mut Option<LeaderActivation>,
    before: Option<ActivationKey>,
    after: Option<ActivationKey>,
    application_ready: bool,
    clock: impl FnOnce() -> SystemTime,
) {
    let Some(key) = before.filter(|key| Some(*key) == after && application_ready) else {
        *slot = None;
        return;
    };
    if slot
        .as_ref()
        .is_some_and(|activation| activation.key == key)
    {
        return;
    }
    *slot = Some(LeaderActivation {
        key,
        time: activation_time(clock()),
    });
}

impl Service {
    pub(super) fn ha_activation_permitted(&self) -> bool {
        self.state.is_some()
            && self.barrier_key.is_some()
            && !self.recovery_required
            && !self.audit_failed
            && self
                .durable
                .as_ref()
                .is_some_and(|durable| !durable.recovery_required())
    }

    pub(super) fn local_activation_key(&self) -> Option<ActivationKey> {
        if !self.ha_activation_permitted() {
            return None;
        }
        let process = self.ha.as_ref()?.lock_for_request().ok()?;
        process.bootstrap_ready().then_some(())?;
        ActivationKey::from_observation(process.leader_status().ok()?)
    }

    pub(super) fn record_ha_activation(
        &mut self,
        before: Option<ActivationKey>,
        after: Option<ActivationKey>,
        application_ready: bool,
    ) {
        let permitted = self.ha_activation_permitted();
        publish(
            &mut self.ha_activation,
            before,
            after,
            application_ready && permitted,
            SystemTime::now,
        );
    }

    pub(super) fn publish_ha_activation_after_sync(&mut self, before: Option<ActivationKey>) {
        let Some(process) = self.ha.as_ref().cloned() else {
            self.ha_activation = None;
            return;
        };
        let after = self.local_activation_key();
        if before.is_none() || before != after {
            self.ha_activation = None;
            return;
        }
        // An existing event is stable across further reads and durable mutations.
        // The synchronization which just succeeded has its own ReadIndex gate.
        if self
            .ha_activation
            .as_ref()
            .is_some_and(|activation| Some(activation.key) == after)
        {
            return;
        }
        let identity = self.current_state_identity().ok();
        let verified = process.lock_for_request().ok().and_then(|process| {
            if !process.bootstrap_ready()
                || ActivationKey::from_observation(process.leader_status().ok()?) != before
            {
                return None;
            }
            process.ensure_application_identity(identity?).ok()?;
            ActivationKey::from_observation(process.leader_status().ok()?)
        });
        self.record_ha_activation(before, verified, verified == before);
    }

    fn maintain_ha_activation(&mut self) {
        let current = self.local_activation_key();
        if self
            .ha_activation
            .as_ref()
            .is_some_and(|activation| Some(activation.key) != current)
        {
            self.ha_activation = None;
        }
        if current.is_none() {
            self.ha_activation = None;
            return;
        }
        if self.ha_activation.is_some() {
            return;
        }
        // Election alone cannot admit local state. This read-only catch-up cannot
        // create the first application anchor; unseal/request admission owns it.
        let _ = self.sync_from_ha_with_anchor(false);
    }
}

/// Always runs for HA, including deployments which disable expiry maintenance.
/// One bounded pass, no queued work. Drop wakes and joins the host-owned thread.
pub(crate) struct HaActivationWorker {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}
impl Drop for HaActivationWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
pub(crate) fn start_ha_activation_worker(
    service: &Arc<Mutex<Service>>,
) -> Result<Option<HaActivationWorker>, String> {
    if service
        .lock()
        .map_err(|_| "HA activation writer is unavailable")?
        .ha
        .is_none()
    {
        return Ok(None);
    }
    let service = Arc::downgrade(service);
    let (stop, receiver) = mpsc::channel();
    let join = std::thread::Builder::new()
        .name("heptabao-ha-activation".into())
        .spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) =
                receiver.recv_timeout(Duration::from_millis(100))
            {
                let Some(service) = service.upgrade() else {
                    break;
                };
                let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                    std::time::Instant::now()
                        + crate::request_deadline::IDLE_MAINTENANCE_READ_BUDGET,
                );
                if let Ok(mut writer) = service.try_lock() {
                    writer.maintain_ha_activation();
                }
            }
        })
        .map_err(|_| "cannot start HA activation worker")?;
    Ok(Some(HaActivationWorker {
        stop,
        join: Some(join),
    }))
}

#[cfg(test)]
#[path = "service_ha_activation_tests.rs"]
mod tests;
