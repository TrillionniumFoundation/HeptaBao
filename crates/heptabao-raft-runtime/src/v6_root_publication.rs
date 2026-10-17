//! Raft-ordered V6 root CAS metadata. Ciphertext closures stay in the external
//! immutable store. This is a trusted application-writer primitive, not an HTTP
//! permission or a claim that local observations constitute quorum durability.
use crate::{NativeV6CommitIntent, RecordRejection, ReplicatedEnvelope, TypeConfig};
use openraft::alias::{LogIdOf, StoredMembershipOf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_ROOT_CIPHERTEXT_BYTES: usize = 64 * 1024 + 256;
const MAX_VOTERS: usize = 256;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EnrollmentCommand {
    pub(crate) cluster_digest: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) membership_log: LogIdOf<TypeConfig>,
    #[serde(with = "enrolled_pins_wire")]
    pub(crate) pins: BTreeMap<u64, [u8; 32]>,
}

// ApplicationRequest is an untagged enum. Its Serde content buffer cannot
// coerce JSON object string keys back to u64 as a direct JSON map reader can.
// Use a canonical bounded sequence on the actual log and snapshot wire, while
// retaining the typed voter map at the trusted configuration API boundary.
mod enrolled_pins_wire {
    use super::{BTreeMap, MAX_VOTERS};
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(
        pins: &BTreeMap<u64, [u8; 32]>, serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(pins.len()))?;
        for pair in pins { sequence.serialize_element(&pair)?; }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<u64, [u8; 32]>, D::Error> {
        struct Pins;
        impl<'de> Visitor<'de> for Pins {
            type Value = BTreeMap<u64, [u8; 32]>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("3..256 strictly ordered voter and leaf-pin pairs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut pins = BTreeMap::new();
                let mut previous = 0;
                while let Some((node, pin)) = sequence.next_element::<(u64, [u8; 32])>()? {
                    if pins.len() == MAX_VOTERS || node <= previous || pin == [0; 32] {
                        return Err(A::Error::custom("invalid canonical enrolled voter pins"));
                    }
                    previous = node;
                    pins.insert(node, pin);
                }
                if pins.len() < 3 {
                    return Err(A::Error::custom("native enrollment requires three or more voters"));
                }
                Ok(pins)
            }
        }
        deserializer.deserialize_seq(Pins)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6EnrollmentState {
    pub(crate) command: NativeV6EnrollmentCommand,
    pub(crate) log: LogIdOf<TypeConfig>,
}

/// The configured voter-to-TLS-leaf binding actually committed by Raft. It is
/// not self-enrollment, a peer fsync receipt or a signature certificate. Only
/// the trusted configuration owner may call `enroll_native_v6_peers`.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV6PeerEnrollment(pub(crate) NativeV6EnrollmentState);
impl NativeV6PeerEnrollment {
    pub fn digest(&self) -> [u8; 32] { self.0.digest() }
    pub fn cluster_digest(&self) -> [u8; 32] { self.0.command.cluster_digest }
    pub fn epoch(&self) -> u64 { self.0.command.epoch }
    pub fn pins(&self) -> &BTreeMap<u64, [u8; 32]> { &self.0.command.pins }
    pub fn membership_log_id(&self) -> LogIdOf<TypeConfig> { self.0.command.membership_log }
    pub fn enrollment_log_id(&self) -> LogIdOf<TypeConfig> { self.0.log }
}
impl fmt::Debug for NativeV6PeerEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6PeerEnrollment")
            .field("voters", &self.0.command.pins.len())
            .field("log_index", &self.0.log.index)
            .finish_non_exhaustive()
    }
}

pub(crate) fn valid_log(log: LogIdOf<TypeConfig>) -> bool {
    log.index > 0 && log.committed_leader_id().node_id > 0
        && log.committed_leader_id().term > 0
}

fn valid_membership_log(log: LogIdOf<TypeConfig>) -> bool {
    // Pinned OpenRaft 0.10.0-alpha.34 initializes the real membership at
    // (term = 0, initializing node, index = 0), before its first election.
    // This exception applies only to the actual StoredMembership binding;
    // application sources, intents, enrollment and root publication still
    // require an elected leader's nonzero term and application log index.
    valid_log(log)
        || (log.index == 0
            && log.committed_leader_id().term == 0
            && log.committed_leader_id().node_id > 0)
}

pub(crate) fn membership_binding(
    membership: &StoredMembershipOf<TypeConfig>,
) -> Result<(LogIdOf<TypeConfig>, BTreeSet<u64>), RecordRejection> {
    let log = (*membership.log_id()).ok_or(RecordRejection::Invalid)?;
    let voters: BTreeSet<_> = membership.voter_ids().collect();
    if !valid_membership_log(log) || membership.get_joint_config().len() != 1
        || !(3..=MAX_VOTERS).contains(&voters.len()) || voters.contains(&0)
    {
        return Err(RecordRejection::Invalid);
    }
    Ok((log, voters))
}

impl NativeV6EnrollmentCommand {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        let distinct: BTreeSet<_> = self.pins.values().copied().collect();
        if self.cluster_digest == [0; 32] || self.epoch == 0
            || !valid_membership_log(self.membership_log)
            || !(3..=MAX_VOTERS).contains(&self.pins.len())
            || self.pins.contains_key(&0) || self.pins.values().any(|pin| *pin == [0; 32])
            || distinct.len() != self.pins.len()
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
    pub(crate) fn matches_membership(
        &self, membership: &StoredMembershipOf<TypeConfig>,
    ) -> Result<(), RecordRejection> {
        self.validate()?;
        let (log, voters) = membership_binding(membership)?;
        if self.membership_log != log || self.pins.keys().copied().collect::<BTreeSet<_>>() != voters {
            return Err(RecordRejection::StaleRoot);
        }
        Ok(())
    }
}

fn hash_log(hash: &mut Sha256, log: LogIdOf<TypeConfig>) {
    let leader = log.committed_leader_id();
    hash.update(leader.term.to_be_bytes());
    hash.update(leader.node_id.to_be_bytes());
    hash.update(log.index.to_be_bytes());
}
impl NativeV6EnrollmentState {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.command.validate()?;
        if !valid_log(self.log) || self.log.index <= self.command.membership_log.index {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"heptabao.raft.native-v6.peer-enrollment.v1\0");
        hash.update(self.command.cluster_digest);
        hash.update(self.command.epoch.to_be_bytes());
        hash_log(&mut hash, self.command.membership_log);
        hash_log(&mut hash, self.log);
        hash.update((self.command.pins.len() as u64).to_be_bytes());
        for (node, pin) in &self.command.pins {
            hash.update(node.to_be_bytes());
            hash.update(pin);
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6RootCommand {
    pub(crate) intent: NativeV6CommitIntent,
    pub(crate) intent_log: LogIdOf<TypeConfig>,
    pub(crate) enrollment_digest: [u8; 32],
    #[serde(with = "crate::records::root_envelope")]
    pub(crate) envelope: ReplicatedEnvelope,
}
impl NativeV6RootCommand {
    pub(crate) fn operation_id(intent: &NativeV6CommitIntent) -> String {
        let mut id = String::from("native-v6-");
        crate::append_hex(&mut id, &intent.operation_digest);
        id
    }
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.intent.encode()?;
        if !valid_log(self.intent_log)
            || self.intent_log.index <= self.intent.expected_previous_commit_index
            || self.enrollment_digest == [0; 32]
            || self.envelope.digest() != self.intent.proposed_root_digest
            || self.envelope.operation_id() != Self::operation_id(&self.intent)
            || !(25..=MAX_ROOT_CIPHERTEXT_BYTES).contains(&self.envelope.sealed().len())
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6RootState {
    pub(crate) command: NativeV6RootCommand,
    pub(crate) publication_log: LogIdOf<TypeConfig>,
    // Kept even after subsequent publications, so a cold reader can identify
    // the actual committed V5 migration source, rather than inventing genesis.
    pub(crate) migration_source_digest: [u8; 32],
    pub(crate) migration_source_log: LogIdOf<TypeConfig>,
}
impl NativeV6RootState {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.command.validate()?;
        if !valid_log(self.publication_log) || !valid_log(self.migration_source_log)
            || self.migration_source_digest == [0; 32]
            || self.migration_source_log.index >= self.command.intent_log.index
            || self.publication_log.index <= self.command.intent_log.index
            || (self.command.intent.prior_generation == 0
                && (self.command.intent.prior_root_digest != self.migration_source_digest
                    || self.command.intent.expected_previous_commit_index != self.migration_source_log.index))
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}

/// A root returned from the actual Raft state machine. No public constructor
/// or Deserialize implementation can manufacture one from a caller manifest.
/// It can be stale: use a fresh quorum witness before granting a business read.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV6PublishedRoot(pub(crate) NativeV6RootState);
impl NativeV6PublishedRoot {
    pub fn intent(&self) -> NativeV6CommitIntent { self.0.command.intent }
    pub fn intent_log_id(&self) -> LogIdOf<TypeConfig> { self.0.command.intent_log }
    pub fn publication_log_id(&self) -> LogIdOf<TypeConfig> { self.0.publication_log }
    pub fn enrollment_digest(&self) -> [u8; 32] { self.0.command.enrollment_digest }
    pub fn sealed_root(&self) -> &[u8] { self.0.command.envelope.sealed() }
    pub fn root_digest(&self) -> [u8; 32] { self.0.command.intent.proposed_root_digest }
    pub fn generation(&self) -> u64 { self.0.command.intent.proposed_generation }
    pub fn migration_source(&self) -> ([u8; 32], LogIdOf<TypeConfig>) {
        (self.0.migration_source_digest, self.0.migration_source_log)
    }
}
impl fmt::Debug for NativeV6PublishedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6PublishedRoot")
            .field("generation", &self.generation())
            .field("log_index", &self.0.publication_log.index)
            .field("objects", &self.0.command.intent.object_count)
            .finish_non_exhaustive()
    }
}

impl crate::StateMachine {
    pub(crate) fn validate_native_v6_state(&self) -> Result<(), RecordRejection> {
        let last = self.last_applied_log.map(|log| log.index).unwrap_or(0);
        if self.v5_root_log.is_some_and(|log| !valid_log(log) || log.index > last)
            || (self.v5_root_log.is_some()
                && self.records_v5.as_ref().and_then(crate::records::RecordState::published_digest).is_none())
        {
            return Err(RecordRejection::Invalid);
        }
        if let Some(enrollment) = &self.v6_enrollment {
            enrollment.validate()?;
            if enrollment.log.index > last || self.records_v5.is_none() {
                return Err(RecordRejection::Invalid);
            }
        }
        if let Some(root) = &self.v6_root {
            root.validate()?;
            let enrollment = self.v6_enrollment.as_ref().ok_or(RecordRejection::Invalid)?;
            let intent = &root.command.intent;
            let object = crate::SealedRecordObject::new_native_v6_commit_intent(*intent)
                .map_err(|_| RecordRejection::Invalid)?;
            if root.publication_log.index > last
                || enrollment.log.index >= root.publication_log.index
                || enrollment.digest() != root.command.enrollment_digest
                || enrollment.command.cluster_digest != intent.cluster_digest
                || enrollment.command.epoch != intent.epoch
                || self.v5_root_log != Some(root.migration_source_log)
                || self.records_v5.as_ref().and_then(crate::records::RecordState::published_digest)
                    != Some(root.migration_source_digest)
                || self.v6_intent_log_id(&object.reference().id) != Some(root.command.intent_log)
                || self.records_v5.as_ref().ok_or(RecordRejection::Invalid)?
                    .object(object.reference())? != Some(object)
            {
                return Err(RecordRejection::Invalid);
            }
        }
        Ok(())
    }

    pub(crate) fn apply_native_v6_command(
        &mut self, request: &crate::ApplicationRequest,
    ) -> Option<Result<(), RecordRejection>> {
        use crate::records::RecordCommand;
        match request {
            crate::ApplicationRequest::RecordsV5(data) => match &data.records_v5 {
                RecordCommand::EnrollNativeV6 { enrollment } => Some(request.validate_size()
                    .and_then(|()| self.apply_native_v6_enrollment(enrollment))),
                RecordCommand::PublishNativeV6 { root } => Some(request.validate_size()
                    .and_then(|()| self.apply_native_v6_root(root))),
                RecordCommand::Stage { object } if self.v6_root.is_some()
                    && object.reference().kind == crate::RecordObjectKind::NativeV6CommitIntent => None,
                _ if self.v6_root.is_some() => Some(Err(RecordRejection::LegacyFenced)),
                _ => None,
            },
            _ if self.v6_root.is_some() => Some(Err(RecordRejection::LegacyFenced)),
            _ => None,
        }
    }

    fn apply_native_v6_enrollment(
        &mut self, command: &NativeV6EnrollmentCommand,
    ) -> Result<(), RecordRejection> {
        command.matches_membership(&self.last_membership)?;
        let log = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        if self.v6_root.is_some() || self.records_v5.as_ref()
            .and_then(crate::records::RecordState::published_digest).is_none()
        {
            return Err(RecordRejection::LegacyFenced);
        }
        if let Some(existing) = &self.v6_enrollment {
            return if existing.command == *command { Ok(()) }
                else { Err(RecordRejection::ImmutableConflict) };
        }
        let candidate = NativeV6EnrollmentState { command: command.clone(), log };
        candidate.validate()?;
        self.v6_enrollment = Some(candidate);
        Ok(())
    }

    fn apply_native_v6_root(&mut self, command: &NativeV6RootCommand) -> Result<(), RecordRejection> {
        command.validate()?;
        let log = self.last_applied_log.ok_or(RecordRejection::Invalid)?;
        let enrollment = self.v6_enrollment.as_ref().ok_or(RecordRejection::MissingDependency)?;
        enrollment.command.matches_membership(&self.last_membership)?;
        let intent = command.intent;
        if command.enrollment_digest != enrollment.digest()
            || intent.cluster_digest != enrollment.command.cluster_digest
            || intent.epoch != enrollment.command.epoch
        {
            return Err(RecordRejection::StaleRoot);
        }
        let object = crate::SealedRecordObject::new_native_v6_commit_intent(intent)
            .map_err(|_| RecordRejection::Invalid)?;
        if self.v6_intent_log_id(&object.reference().id) != Some(command.intent_log)
            || self.records_v5.as_ref().ok_or(RecordRejection::MissingDependency)?
                .object(object.reference())? != Some(object)
        {
            return Err(RecordRejection::MissingDependency);
        }
        let source_digest = self.records_v5.as_ref()
            .and_then(crate::records::RecordState::published_digest)
            .ok_or(RecordRejection::MissingDependency)?;
        let source_log = self.v5_root_log.ok_or(RecordRejection::MissingDependency)?;
        let (prior_digest, prior_generation, prior_log) = match &self.v6_root {
            Some(root) => (root.command.intent.proposed_root_digest,
                root.command.intent.proposed_generation, root.publication_log),
            None => (source_digest, 0, source_log),
        };
        if intent.prior_root_digest != prior_digest || intent.prior_generation != prior_generation
            || intent.expected_previous_commit_index != prior_log.index
        {
            return Err(RecordRejection::StaleRoot);
        }
        let candidate = NativeV6RootState {
            command: command.clone(), publication_log: log,
            migration_source_digest: source_digest, migration_source_log: source_log,
        };
        candidate.validate()?;
        self.v6_root = Some(candidate);
        Ok(())
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::records::RecordCommand;
    use crate::state_machine::RecordRequest;
    use crate::ApplicationRequest;
    use openraft::alias::EntryOf;

    fn log(term: u64, index: u64) -> LogIdOf<TypeConfig> {
        openraft::LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId { term, node_id: 1 },
            index,
        }
    }

    fn enrollment() -> NativeV6EnrollmentCommand {
        NativeV6EnrollmentCommand {
            cluster_digest: [1; 32], epoch: 7, membership_log: log(0, 0),
            pins: BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]),
        }
    }

    #[test]
    fn native_v6_commands_roundtrip_through_actual_untagged_raft_log_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let enrollment = enrollment();
        let committed = NativeV6EnrollmentState { command: enrollment.clone(), log: log(1, 2) };
        let intent = NativeV6CommitIntent {
            cluster_digest: [1; 32], epoch: 7, operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32], object_count: 3, ciphertext_bytes: 192,
            prior_root_digest: [4; 32], proposed_root_digest: [5; 32],
            prior_generation: 0, proposed_generation: 1, expected_previous_commit_index: 1,
        };
        let root = NativeV6RootCommand {
            intent, intent_log: log(1, 3), enrollment_digest: committed.digest(),
            envelope: ReplicatedEnvelope::new(
                NativeV6RootCommand::operation_id(&intent), intent.proposed_root_digest, vec![0x55; 64],
            )?,
        };
        for command in [
            RecordCommand::EnrollNativeV6 { enrollment: enrollment.clone() },
            RecordCommand::PublishNativeV6 { root },
        ] {
            let request = ApplicationRequest::RecordsV5(RecordRequest { serial: 7, records_v5: command });
            // Both paths use the untagged application decoder, not just the
            // enrollment struct's direct JSON map deserializer.
            let value = serde_json::to_value(&request)?;
            let replay: ApplicationRequest = serde_json::from_value(value.clone())?;
            assert_eq!(serde_json::to_value(&replay)?, value);
            let entry = EntryOf::<TypeConfig> {
                log_id: log(1, 4), payload: openraft::EntryPayload::Normal(request),
            };
            let encoded = serde_json::to_vec(&entry)?;
            let decoded: EntryOf<TypeConfig> = serde_json::from_slice(&encoded)?;
            assert_eq!(serde_json::to_vec(&decoded)?, encoded);
        }
        let encoded = serde_json::to_vec(&committed)?;
        let decoded: NativeV6EnrollmentState = serde_json::from_slice(&encoded)?;
        assert!(decoded == committed);
        assert_eq!(decoded.digest(), committed.digest());
        Ok(())
    }

    #[test]
    fn native_v6_enrollment_log_pins_reject_noncanonical_and_unbounded_sequences()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = ApplicationRequest::RecordsV5(RecordRequest {
            serial: 7, records_v5: RecordCommand::EnrollNativeV6 { enrollment: enrollment() },
        });
        let value = serde_json::to_value(&request)?;
        let pairs = value["records_v5"]["EnrollNativeV6"]["enrollment"]["pins"]
            .as_array().ok_or("canonical pins must be a sequence")?.clone();
        let mut reversed = pairs.clone(); reversed.reverse();
        let mut repeated = pairs.clone(); repeated[2] = repeated[1].clone();
        let pin = [11_u8; 32];
        let too_many = (1..=MAX_VOTERS + 1).map(|node| serde_json::json!([node, pin]))
            .collect::<Vec<_>>();
        for pins in [
            serde_json::Value::Array(reversed),
            serde_json::Value::Array(repeated),
            serde_json::Value::Array(too_many),
            serde_json::Value::Array(pairs[..2].to_vec()),
            serde_json::to_value(enrollment().pins)?,
        ] {
            let mut invalid = value.clone();
            invalid["records_v5"]["EnrollNativeV6"]["enrollment"]["pins"] = pins;
            let bytes = serde_json::to_vec(&invalid)?;
            assert!(serde_json::from_slice::<ApplicationRequest>(&bytes).is_err());
        }
        Ok(())
    }
}
