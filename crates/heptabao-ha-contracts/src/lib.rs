#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! HA term, membership and writer-fence contracts without a Raft implementation.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Follower,
    Leader,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterFence {
    pub term: u64,
    pub leader_id: Id,
    pub generation: u64,
}

#[derive(Debug)]
pub struct HaState {
    local_node: Id,
    role: NodeRole,
    term: u64,
    leader_id: Option<Id>,
    voters: BTreeSet<Id>,
    learners: BTreeSet<Id>,
    generation: u64,
}

impl HaState {
    pub fn new(local_node: Id, voters: BTreeSet<Id>) -> Result<Self, HaError> {
        if voters.is_empty() || !voters.contains(&local_node) {
            return Err(HaError::InvalidMembership);
        }
        Ok(Self {
            local_node,
            role: NodeRole::Follower,
            term: 0,
            leader_id: None,
            voters,
            learners: BTreeSet::new(),
            generation: 0,
        })
    }

    pub fn role(&self) -> NodeRole {
        self.role
    }

    pub fn term(&self) -> u64 {
        self.term
    }

    pub fn local_node(&self) -> &Id {
        &self.local_node
    }

    pub fn voters(&self) -> &BTreeSet<Id> {
        &self.voters
    }

    pub fn observe_higher_term(&mut self, term: u64) -> Result<(), HaError> {
        if term <= self.term {
            return Err(HaError::StaleTerm);
        }
        self.term = term;
        self.role = NodeRole::Follower;
        self.leader_id = None;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    pub fn grant_leadership(&mut self, leader_id: Id, term: u64) -> Result<WriterFence, HaError> {
        if term == 0 || term < self.term {
            return Err(HaError::StaleTerm);
        }
        if !self.voters.contains(&leader_id) {
            return Err(HaError::NotVoter);
        }
        self.term = term;
        self.leader_id = Some(leader_id.clone());
        self.role = if leader_id == self.local_node {
            NodeRole::Leader
        } else {
            NodeRole::Follower
        };
        self.generation = self.generation.saturating_add(1);
        Ok(WriterFence {
            term,
            leader_id,
            generation: self.generation,
        })
    }

    pub fn validate_writer(&self, fence: &WriterFence) -> Result<(), HaError> {
        if self.role != NodeRole::Leader
            || fence.term != self.term
            || fence.generation != self.generation
            || self.leader_id.as_ref() != Some(&fence.leader_id)
            || &fence.leader_id != self.local_node()
        {
            return Err(HaError::StaleFence);
        }
        Ok(())
    }

    pub fn add_learner(&mut self, node_id: Id) -> Result<(), HaError> {
        if self.voters.contains(&node_id) || !self.learners.insert(node_id) {
            return Err(HaError::DuplicateMember);
        }
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    pub fn promote(&mut self, node_id: &Id) -> Result<(), HaError> {
        if !self.learners.remove(node_id) {
            return Err(HaError::MissingLearner);
        }
        self.voters.insert(node_id.clone());
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    pub fn remove_voter(&mut self, node_id: &Id) -> Result<(), HaError> {
        if self.voters.len() == 1 {
            return Err(HaError::LastVoter);
        }
        if !self.voters.remove(node_id) {
            return Err(HaError::NotVoter);
        }
        if node_id == &self.local_node {
            self.role = NodeRole::Removed;
        }
        if self.leader_id.as_ref() == Some(node_id) {
            self.leader_id = None;
        }
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HaError {
    InvalidMembership,
    StaleTerm,
    NotVoter,
    StaleFence,
    DuplicateMember,
    MissingLearner,
    LastVoter,
}

impl fmt::Display for HaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMembership => "HA membership is invalid",
            Self::StaleTerm => "HA term is stale",
            Self::NotVoter => "node is not a voter",
            Self::StaleFence => "writer fence is stale",
            Self::DuplicateMember => "node already belongs to the cluster",
            Self::MissingLearner => "node is not a learner",
            Self::LastVoter => "last voter cannot be removed",
        })
    }
}

impl Error for HaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_writer_fence_is_rejected_after_term_change() -> Result<(), Box<dyn Error>> {
        let local = Id::parse("node_a")?;
        let mut voters = BTreeSet::new();
        voters.insert(local.clone());
        let mut state = HaState::new(local.clone(), voters)?;
        let fence = state.grant_leadership(local, 1)?;
        state.observe_higher_term(2)?;
        assert_eq!(Err(HaError::StaleFence), state.validate_writer(&fence));
        Ok(())
    }

    #[test]
    fn learner_promotion_and_last_voter_guard_are_explicit() -> Result<(), Box<dyn Error>> {
        let local = Id::parse("node_a")?;
        let peer = Id::parse("node_b")?;
        let mut voters = BTreeSet::new();
        voters.insert(local.clone());
        let mut state = HaState::new(local.clone(), voters)?;
        assert_eq!(Err(HaError::LastVoter), state.remove_voter(&local));
        state.add_learner(peer.clone())?;
        state.promote(&peer)?;
        state.remove_voter(&peer)?;
        assert_eq!(1, state.voters().len());
        Ok(())
    }
}
