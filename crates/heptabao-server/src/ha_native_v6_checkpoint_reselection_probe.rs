//! Test-only scheduling of one real checkpoint after one real staged intent.
//! No clock, generation, root, intent receipt or read authority is supplied.
//! This module is absent from production builds. Its caller owns the ordinary
//! Service pipeline, original request clock and unchanged fifteen-second bound.
use super::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

struct Staged {
    intent: NativeV6CommitIntent,
    receipt: CommitReceipt,
}

struct Observed {
    source: PublicationSource,
    enrollment: NativeV6PeerEnrollment,
    term: u64,
    deadline: OriginalDeadline,
    before_generation: u64,
    after_generation: u64,
    snapshot_index: u64,
    staged_index: u64,
    old_witness_refused: bool,
    original_read_until: Instant,
}

struct ProbeState {
    cluster: String,
    node_id: u64,
    staged: Option<Staged>,
    observed: Option<Observed>,
    checkpoint_started: bool,
    stage_calls: usize,
    root_calls: usize,
    reselection_calls: usize,
    reselection_bound_preserved: bool,
    read_until: Instant,
}

thread_local! {
    static OWNED_PROBE: RefCell<Option<ProbeState>> = const { RefCell::new(None) };
}

/// An affine, thread-local test scheduling lease. It grants no product action.
pub(crate) struct NativeCheckpointReselectionProbe {
    cluster: String,
    node_id: u64,
    _thread: PhantomData<Rc<()>>,
}

#[derive(Debug)]
pub(crate) struct NativeCheckpointReselectionEvidence {
    pub(crate) stage_calls: usize,
    pub(crate) before_generation: u64,
    pub(crate) after_generation: u64,
    pub(crate) snapshot_index: u64,
    pub(crate) staged_index: u64,
    pub(crate) old_witness_refused: bool,
    pub(crate) fresh_exact_intent_admitted: bool,
    pub(crate) root_calls: usize,
    pub(crate) reselection_calls: usize,
    pub(crate) published_index: u64,
    pub(crate) source_and_membership_unchanged: bool,
    pub(crate) original_deadline_live: bool,
    pub(crate) original_read_bound_preserved: bool,
}

impl Drop for NativeCheckpointReselectionProbe {
    fn drop(&mut self) {
        OWNED_PROBE.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut()
                && slot.as_ref().is_some_and(|state| {
                    state.cluster == self.cluster && state.node_id == self.node_id
                })
            {
                *slot = None;
            }
        });
    }
}

impl HaProcess {
    pub(crate) fn arm_native_checkpoint_reselection_probe(
        &self,
    ) -> Result<NativeCheckpointReselectionProbe, String> {
        let node = self.node.as_ref().ok_or("owned checkpoint node absent")?;
        if !self.native_v6_enabled() {
            return Err("owned checkpoint native runtime absent".into());
        }
        let operation = OriginalDeadline::capture().map_err(|error| error.to_string())?;
        // This is established BEFORE any work in the terminal writer. It is
        // no later than any subsequent original eight-second ReadIndex bound.
        // Fresh proof selection below cannot move this absolute endpoint.
        let read_until = operation
            .instant()
            .min(Instant::now() + Duration::from_secs(8));
        OWNED_PROBE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| "owned checkpoint probe already borrowed")?;
            if slot.is_some() {
                return Err("owned checkpoint probe already armed".into());
            }
            *slot = Some(ProbeState {
                cluster: self.cluster_id.clone(),
                node_id: node.id(),
                staged: None,
                observed: None,
                checkpoint_started: false,
                stage_calls: 0,
                root_calls: 0,
                reselection_calls: 0,
                reselection_bound_preserved: false,
                read_until,
            });
            Ok(NativeCheckpointReselectionProbe {
                cluster: self.cluster_id.clone(),
                node_id: node.id(),
                _thread: PhantomData,
            })
        })
    }

    /// Verify the actual single successor after the production coordinator
    /// completed. This does not publish, repair, retry or grant an Actor.
    pub(crate) fn finish_native_checkpoint_reselection_probe(
        &self,
        probe: NativeCheckpointReselectionProbe,
    ) -> Result<NativeCheckpointReselectionEvidence, String> {
        let node = self.node.as_ref().ok_or("owned checkpoint node absent")?;
        let state = OWNED_PROBE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| "owned checkpoint probe borrowed")?;
            if slot.as_ref().is_none_or(|state| {
                state.cluster != probe.cluster
                    || state.node_id != probe.node_id
                    || state.cluster != self.cluster_id
                    || state.node_id != node.id()
            }) {
                return Err("owned checkpoint probe identity changed");
            }
            slot.take().ok_or("owned checkpoint probe absent")
        })?;
        let staged = state.staged.ok_or("owned checkpoint exact Stage absent")?;
        let observed = state.observed.ok_or("owned checkpoint was not observed")?;
        observed
            .deadline
            .check()
            .map_err(|error| error.to_string())?;
        if state.stage_calls != 1
            || state.root_calls != 1
            || state.reselection_calls != 1
            || !state.reselection_bound_preserved
            || !observed.old_witness_refused
            || Instant::now() >= state.read_until
        {
            return Err("owned checkpoint did not complete exactly one bounded publication".into());
        }
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(state.read_until);
        let bounded = OriginalDeadline::capture().map_err(|error| error.to_string())?;
        let read = self
            .native_v6_committed_read(bounded)?
            .ok_or("owned checkpoint actual native successor absent")?;
        self.verify_native_v6_committed_read(&read)?;
        let published = read.published();
        let role = node
            .local_leader_observation()
            .map_err(|error| error.to_string())?;
        if published.intent() != staged.intent
            || published.intent_log_id().index != staged.receipt.log_index
            || published.intent_log_id().committed_leader_id().node_id != staged.receipt.leader_id
            || published.publication_log_id().index != staged.receipt.log_index + 1
            || published.generation() != observed.source.prior_generation() + 1
            || published.intent().expected_previous_commit_index
                != observed.source.previous_commit_index()
            || read.enrollment() != &observed.enrollment
            || role.term != observed.term
            || role.leader != Some(node.id())
            || !role.local_is_leader
            || Instant::now() >= state.read_until
        {
            return Err("owned checkpoint actual successor or original source differs".into());
        }
        Ok(NativeCheckpointReselectionEvidence {
            stage_calls: state.stage_calls,
            root_calls: state.root_calls,
            reselection_calls: state.reselection_calls,
            before_generation: observed.before_generation,
            after_generation: observed.after_generation,
            snapshot_index: observed.snapshot_index,
            staged_index: observed.staged_index,
            published_index: published.publication_log_id().index,
            old_witness_refused: observed.old_witness_refused,
            fresh_exact_intent_admitted: true,
            source_and_membership_unchanged: true,
            original_deadline_live: true,
            original_read_bound_preserved: state.reselection_bound_preserved,
        })
    }
}

pub(super) fn record_actual_stage(
    process: &HaProcess,
    intent: &NativeV6CommitIntent,
    receipt: &CommitReceipt,
) -> Result<(), String> {
    OWNED_PROBE.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "owned checkpoint Stage observation borrowed")?;
        let Some(state) = slot
            .as_mut()
            .filter(|state| state.cluster == process.cluster_id)
        else {
            return Ok(());
        };
        if process
            .node
            .as_ref()
            .is_none_or(|node| state.node_id != node.id())
        {
            return Err("owned checkpoint Stage node changed".into());
        }
        state.stage_calls += 1;
        if state.stage_calls != 1 || state.staged.is_some() {
            return Err("owned checkpoint observed repeated Stage".into());
        }
        state.staged = Some(Staged {
            intent: *intent,
            receipt: receipt.clone(),
        });
        Ok(())
    })
}

pub(super) async fn at_source_verification(
    process: &HaProcess,
    node: &ProcessRaftNode,
    witness: &heptabao_raft_runtime::ApplicationReadWitness,
    source: &PublicationSource,
    enrollment: Option<&NativeV6PeerEnrollment>,
    term: u64,
    deadline: OriginalDeadline,
) -> Result<(), String> {
    let selected = OWNED_PROBE.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "owned checkpoint source observation borrowed")?;
        let Some(state) = slot
            .as_mut()
            .filter(|state| state.cluster == process.cluster_id && state.node_id == node.id())
        else {
            return Ok(None);
        };
        if state.checkpoint_started {
            return Ok(None);
        }
        let Some(staged) = state.staged.as_ref() else {
            return Ok(None);
        };
        state.checkpoint_started = true;
        Ok::<_, String>(Some((
            staged.intent,
            staged.receipt.clone(),
            state.read_until,
        )))
    })?;
    let Some((intent, receipt, read_until)) = selected else {
        return Ok(());
    };
    Box::pin(tokio::time::timeout_at(
        tokio::time::Instant::from_std(read_until),
        async {
            let enrollment = enrollment.ok_or("owned checkpoint enrollment absent")?;
            let PublicationSource::V6(root) = source else {
                return Err("owned checkpoint requires an already active native root".into());
            };
            if root.root_digest() != intent.prior_root_digest
                || root.generation() != intent.prior_generation
                || root.publication_log_id().index != intent.expected_previous_commit_index
                || witness.completed_prefix().index() != receipt.log_index
                || intent.expected_previous_commit_index.checked_add(1) != Some(receipt.log_index)
            {
                return Err("owned checkpoint exact post-Stage source differs".into());
            }
            node.verify_application_read_witness(witness)
                .await
                .map_err(|error| error.to_string())?;
            let before_generation = node.application_state_generation().await;
            let snapshot = with_read_index_deadline(read_until, node.snapshot_observed())
                .await
                .map_err(|error| error.to_string())?;
            let after_generation = node.application_state_generation().await;
            let (_, fresh_enrollment, fresh_root) = node
                .native_v6_application_read_witness(read_until)
                .await
                .map_err(|error| error.to_string())?;
            let old_witness_refused = matches!(
                node.verify_application_read_witness(witness).await,
                Err(RemoteRaftError::Consensus(ref reason))
                    if reason == "ReadIndex application witness is not current"
            );
            if snapshot.requested_index != receipt.log_index
                || snapshot.persisted_index != receipt.log_index
                || snapshot.byte_count == 0
                || after_generation <= before_generation
                || fresh_enrollment.as_ref() != Some(enrollment)
                || fresh_root.as_ref() != Some(root.as_ref())
                || !old_witness_refused
            {
                return Err(
                    "owned checkpoint changed more than persisted snapshot generation".into(),
                );
            }
            deadline.check().map_err(|error| error.to_string())?;
            if Instant::now() >= read_until {
                return Err("owned checkpoint exceeded original read bound".into());
            }
            OWNED_PROBE.with(|slot| {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| "owned checkpoint result observation borrowed")?;
                let state = slot
                    .as_mut()
                    .ok_or("owned checkpoint result owner absent")?;
                if state.cluster != process.cluster_id
                    || state.node_id != node.id()
                    || state.observed.is_some()
                {
                    return Err("owned checkpoint result owner changed".into());
                }
                state.observed = Some(Observed {
                    source: source.clone(),
                    enrollment: enrollment.clone(),
                    term,
                    deadline,
                    before_generation,
                    after_generation,
                    snapshot_index: snapshot.persisted_index,
                    staged_index: receipt.log_index,
                    old_witness_refused,
                    original_read_until: witness.deadline(),
                });
                Ok(())
            })
        },
    ))
    .await
    .map_err(|_| "owned checkpoint schedule original read bound expired".to_owned())?
    // The caller now performs its original strict check, which still refuses.
    // The production branch, not this scheduling probe, chooses any fresh read.
}

pub(super) fn record_reselection(
    process: &HaProcess,
    selected_until: Instant,
    fresh_until: Instant,
) -> Result<(), String> {
    OWNED_PROBE.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "owned reselection probe borrowed")?;
        let Some(state) = slot
            .as_mut()
            .filter(|state| state.cluster == process.cluster_id)
        else {
            return Ok(());
        };
        let observed = state
            .observed
            .as_ref()
            .ok_or("owned checkpoint observation absent")?;
        if process
            .node
            .as_ref()
            .is_none_or(|node| state.node_id != node.id())
            || selected_until > observed.original_read_until
            || fresh_until > selected_until
            || Instant::now() >= fresh_until
        {
            return Err("owned checkpoint reselection changed its original bound".into());
        }
        state.reselection_calls += 1;
        state.reselection_bound_preserved = true;
        if state.reselection_calls != 1 {
            return Err("owned checkpoint repeated fresh selection".into());
        }
        Ok(())
    })
}

pub(super) fn record_root_call(process: &HaProcess) -> Result<(), String> {
    OWNED_PROBE.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "owned root call probe borrowed")?;
        let Some(state) = slot
            .as_mut()
            .filter(|state| state.cluster == process.cluster_id)
        else {
            return Ok(());
        };
        if process
            .node
            .as_ref()
            .is_none_or(|node| state.node_id != node.id())
        {
            return Err("owned checkpoint root call node changed".into());
        }
        state.root_calls += 1;
        if state.root_calls != 1 || state.reselection_calls != 1 {
            return Err("owned checkpoint root call order or count changed".into());
        }
        Ok(())
    })
}
