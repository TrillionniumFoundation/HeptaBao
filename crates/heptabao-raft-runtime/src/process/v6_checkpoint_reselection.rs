//! A single fresh read after a proved, locally generated checkpoint window.
//! The old strict witness stays invalid. Only a private same-process store
//! transition can select this read; caller-supplied generation/root hints,
//! imported snapshots and reopens cannot. This module never stages or writes.
use super::*;

fn unavailable() -> RemoteRaftError {
    RemoteRaftError::Consensus("native checkpoint reselection is unavailable".into())
}

impl ProcessRaftNode {
    /// Reselect once after a strict witness has been retired ONLY by local
    /// generated checkpoints. The fresh proof has the old witness's deadline,
    /// leader, term, full applied prefix and live store identity. The caller
    /// must reauthenticate its complete source/intent and verify the NEW proof.
    /// No stale witness becomes valid, even when this independent read succeeds.
    pub async fn native_v6_read_after_generated_checkpoint(
        &self,
        selected: &ApplicationReadWitness,
        deadline: std::time::Instant,
    ) -> Result<
        (
            ApplicationReadWitness,
            Option<crate::NativeV6PeerEnrollment>,
            Option<crate::NativeV6PublishedRoot>,
        ),
        RemoteRaftError,
    > {
        let deadline = deadline.min(selected.deadline());
        crate::with_read_index_deadline(deadline, async {
            let deadline = crate::process::read_deadline::current().unwrap_or(deadline);
            let until = tokio::time::Instant::from_std(deadline);
            if !self.state_machine.same_instance(&selected.store)
                || tokio::time::Instant::now() >= until
                || !crate::process::follower_read::bound(
                    &self.raft,
                    selected.leader,
                    selected.term,
                    selected.leader == self.id,
                )
            {
                return Err(unavailable());
            }
            let generated = tokio::time::timeout_at(
                until,
                self.state_machine.generated_checkpoint_transition_since(
                    selected.generation,
                    selected.applied_log,
                ),
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
            // This invokes the actual quorum protocol. The private transition
            // fact is merely a reason to try ONE independent bounded read.
            let (fresh, enrollment, root) =
                self.native_v6_application_read_witness(deadline).await?;
            if !fresh.store.same_instance(&selected.store)
                || fresh.generation != generated
                || fresh.applied_log != selected.applied_log
                || fresh.leader != selected.leader
                || fresh.term != selected.term
                || fresh.deadline > selected.deadline
                || fresh.deadline > until
                || tokio::time::Instant::now() >= until
            {
                return Err(unavailable());
            }
            // An apply/install/another checkpoint during that read fails this
            // one attempt; no loop masks it or supplies a new time budget.
            let still_generated = tokio::time::timeout_at(
                until,
                self.state_machine.generated_checkpoint_transition_since(
                    selected.generation,
                    selected.applied_log,
                ),
            )
            .await
            .map_err(|_| unavailable())?;
            if still_generated != Some(fresh.generation) {
                return Err(unavailable());
            }
            self.verify_application_read_witness(&fresh).await?;
            Ok((fresh, enrollment, root))
        })
        .await
    }
}

#[cfg(test)]
#[path = "v6_checkpoint_reselection_tests.rs"]
mod tests;
