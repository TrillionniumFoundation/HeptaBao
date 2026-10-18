//! Own Raft application type. Legacy JSON fields remain byte-shape compatible;
//! typed record commands deliberately have no legacy client/status fields.
use crate::ReplicatedEnvelope;
use crate::records::{
    LegacyChunkRef, LegacyStatusIdentity, MAX_RECORD_COMMAND_BYTES, PRODUCTION_CLIENT,
    RecordCommand, RecordRejection, RecordRootBase, RecordState, status_entry_size,
};
use openraft::alias::{LogIdOf, StoredMembershipOf};
use serde::{Deserialize, Serialize};
#[cfg(feature = "experimental-v6-raft-objects")]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicationRequest {
    RecordsV5(RecordRequest),
    Legacy(LegacyRequest),
}

#[cfg(all(test, not(feature = "experimental-v6-raft-objects")))]
mod native_format_refusal_tests {
    use super::*;

    #[test]
    fn default_build_rejects_native_fields_and_v4_without_discarding_the_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = StateMachine {
            records_v5: Some(RecordState::default()),
            ..Default::default()
        };
        let old = state.snapshot_bytes()?;
        assert!(
            StateMachine::from_snapshot(&old).is_ok(),
            "ordinary V5 snapshots remain readable"
        );
        let mut bytes: serde_json::Value = serde_json::from_slice(&old)?;
        bytes["format_version"] = serde_json::json!(4);
        assert!(StateMachine::from_snapshot(&serde_json::to_vec(&bytes)?).is_err());
        for field in ["v6_root", "v6_enrollment"] {
            let mut bytes: serde_json::Value = serde_json::from_slice(&old)?;
            bytes["state"][field] = serde_json::json!({"must_not_be_ignored":true});
            assert!(StateMachine::from_snapshot(&serde_json::to_vec(&bytes)?).is_err());
            let raw: StateMachine = serde_json::from_value(bytes["state"].clone())?;
            assert!(
                raw.validate().is_err(),
                "direct bundle decoding cannot ignore native state either"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRequest {
    pub client: String,
    pub serial: u64,
    pub status: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRequest {
    pub(crate) serial: u64,
    pub(crate) records_v5: RecordCommand,
}
impl From<openraft_memstore::ClientRequest> for ApplicationRequest {
    fn from(value: openraft_memstore::ClientRequest) -> Self {
        Self::Legacy(LegacyRequest {
            client: value.client,
            serial: value.serial,
            status: value.status,
        })
    }
}
impl fmt::Debug for ApplicationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Legacy(_) => "Legacy([REDACTED])",
            Self::RecordsV5(_) => "RecordsV5([REDACTED])",
        })
    }
}
impl fmt::Display for ApplicationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicationResponse {
    Legacy(openraft_memstore::ClientResponse),
    Records(RecordResponse),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordResponse {
    pub accepted: bool,
    pub rejection: Option<RecordRejection>,
}
impl fmt::Debug for ApplicationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Legacy(_) => "LegacyResponse([REDACTED])",
            Self::Records(_) => "RecordResponse([REDACTED])",
        })
    }
}
impl ApplicationResponse {
    pub(crate) fn rejected(reason: RecordRejection) -> Self {
        Self::Records(RecordResponse {
            accepted: false,
            rejection: Some(reason),
        })
    }
    pub(crate) fn blank() -> Self {
        Self::Legacy(openraft_memstore::ClientResponse(None))
    }
    pub(crate) fn result(&self) -> Result<(), RecordRejection> {
        match self {
            Self::Legacy(_) => Ok(()),
            Self::Records(r) if r.accepted && r.rejection.is_none() => Ok(()),
            Self::Records(r) => Err(r.rejection.unwrap_or(RecordRejection::Invalid)),
        }
    }
}
openraft::declare_raft_types!(
    pub TypeConfig:
        D=ApplicationRequest,
        R=ApplicationResponse,
        Node=(),
        LeaderId=openraft::impls::leader_id_adv::LeaderId<Self::Term,Self::NodeId>,
);

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct StateMachine {
    pub last_applied_log: Option<LogIdOf<TypeConfig>>,
    pub last_membership: StoredMembershipOf<TypeConfig>,
    pub client_status: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) records_v5: Option<RecordState>,
    /// Only the original *applied* Raft log may create this identity.
    /// Retained in the authenticated-by-Raft local snapshot state; this is not
    /// a quorum certificate, root CAS, read grant or client acknowledgment.
    #[cfg(feature = "experimental-v6-raft-objects")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) v6_intent_log_provenance: BTreeMap<String, LogIdOf<TypeConfig>>,
    #[cfg(feature = "experimental-v6-raft-objects")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) v5_root_log: Option<LogIdOf<TypeConfig>>,
    #[cfg(feature = "experimental-v6-raft-objects")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) v6_enrollment: Option<crate::v6_root_publication::NativeV6EnrollmentState>,
    #[cfg(feature = "experimental-v6-raft-objects")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) v6_root: Option<crate::v6_root_publication::NativeV6RootState>,
    // Old/default builds must not silently discard an enrolled or published
    // V6 state even if an input falsely labels its enclosing format as V3.
    #[cfg(not(feature = "experimental-v6-raft-objects"))]
    #[serde(default, skip_serializing, rename = "v6_enrollment")]
    unsupported_v6_enrollment: Option<serde::de::IgnoredAny>,
    #[cfg(not(feature = "experimental-v6-raft-objects"))]
    #[serde(default, skip_serializing, rename = "v6_root")]
    unsupported_v6_root: Option<serde::de::IgnoredAny>,
    #[serde(skip)]
    legacy_json_bytes: Option<usize>,
}
impl fmt::Debug for StateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateMachine")
            .field("clients", &self.client_status.len())
            .field("records_v5", &self.records_v5.is_some())
            .finish_non_exhaustive()
    }
}
impl ApplicationRequest {
    pub(crate) fn records(serial: u64, command: RecordCommand) -> Result<Self, RecordRejection> {
        let request = Self::RecordsV5(RecordRequest {
            serial,
            records_v5: command,
        });
        request.validate_size()?;
        Ok(request)
    }
    pub(crate) fn validate_size(&self) -> Result<(), RecordRejection> {
        let Self::RecordsV5(request) = self else {
            return Ok(());
        };
        if request.serial == 0
            || serde_json::to_vec(self)
                .map_err(|_| RecordRejection::Invalid)?
                .len()
                > MAX_RECORD_COMMAND_BYTES
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}
fn retired_legacy_client(client: &str) -> bool {
    if client == PRODUCTION_CLIENT {
        return true;
    }
    let Some(suffix) = client.strip_prefix("heptabao-production-ha-chunk:") else {
        return false;
    };
    let Some((index, slot)) = suffix.split_once(':') else {
        return false;
    };
    index.len() == 3
        && index.bytes().all(|b| b.is_ascii_digit())
        && index.parse::<u16>().is_ok_and(|n| n <= 127)
        && matches!(slot, "0" | "1")
}
impl StateMachine {
    pub(crate) fn legacy_size(&self) -> Result<usize, RecordRejection> {
        self.client_status
            .iter()
            .try_fold(2_usize, |sum, (client, status)| {
                sum.checked_add(status_entry_size(client, status)?)
                    .ok_or(RecordRejection::Budget)
            })
    }
    pub(crate) fn base(&self) -> Result<RecordRootBase, RecordRejection> {
        if let Some(digest) = self
            .records_v5
            .as_ref()
            .and_then(RecordState::published_digest)
        {
            return Ok(RecordRootBase::RecordsV5(digest));
        }
        self.client_status
            .get(PRODUCTION_CLIENT)
            .map(|status| {
                ReplicatedEnvelope::decode_status(status)
                    .map(|e| RecordRootBase::Legacy(e.digest()))
                    .map_err(|_| RecordRejection::Invalid)
            })
            .unwrap_or(Ok(RecordRootBase::Empty))
    }
    pub(crate) fn record_usage(&mut self) -> Result<crate::records::RecordUsage, RecordRejection> {
        let legacy = match self.legacy_json_bytes {
            Some(n) => n,
            None => self.legacy_size()?,
        };
        self.legacy_json_bytes = Some(legacy);
        match &mut self.records_v5 {
            Some(records) => records.usage(legacy),
            None => crate::records::RecordState::default().usage(legacy),
        }
    }
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        #[cfg(not(feature = "experimental-v6-raft-objects"))]
        if self.unsupported_v6_enrollment.is_some() || self.unsupported_v6_root.is_some() {
            return Err(RecordRejection::Invalid);
        }
        #[cfg(feature = "experimental-v6-raft-objects")]
        {
            self.validate_native_v6_state()?;
            if self.v6_intent_log_provenance.len() > 4096 {
                return Err(RecordRejection::Budget);
            }
            for (id, log) in &self.v6_intent_log_provenance {
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || log.index == 0
                    || log.committed_leader_id().node_id == 0
                    || self
                        .last_applied_log
                        .is_none_or(|last| log.index > last.index)
                    || !self
                        .records_v5
                        .as_ref()
                        .ok_or(RecordRejection::Invalid)?
                        .has_valid_v6_intent(id)?
                {
                    return Err(RecordRejection::Invalid);
                }
            }
        }
        if let Some(records) = &self.records_v5 {
            let metadata = serde_json::to_vec(&(&self.last_applied_log, &self.last_membership))
                .map_err(|_| RecordRejection::Invalid)?;
            if metadata.len() > 1024 * 1024 - 1024 {
                return Err(RecordRejection::Budget);
            }
            if let Some(expected) = records.prepared_identity() {
                let status = self
                    .client_status
                    .get(PRODUCTION_CLIENT)
                    .ok_or(RecordRejection::Invalid)?;
                if LegacyStatusIdentity::inspect(status)?.1 != expected {
                    return Err(RecordRejection::StaleRoot);
                }
            }
            records.validate(self.legacy_size()?)?;
        }
        Ok(())
    }
    /// Read-only original applied log identity, not a grant of quorum.
    #[cfg(feature = "experimental-v6-raft-objects")]
    pub(crate) fn v6_intent_log_id(&self, digest: &[u8; 32]) -> Option<LogIdOf<TypeConfig>> {
        let mut key = String::with_capacity(64);
        crate::append_hex(&mut key, digest);
        self.v6_intent_log_provenance.get(&key).copied()
    }

    fn retain_legacy_chunks(
        &mut self,
        expected: LegacyStatusIdentity,
        active: &[LegacyChunkRef],
    ) -> Result<(), RecordRejection> {
        expected.validate()?;
        if self
            .records_v5
            .as_ref()
            .and_then(RecordState::published_digest)
            .is_some()
        {
            return Err(RecordRejection::LegacyFenced);
        }
        let status = self
            .client_status
            .get(PRODUCTION_CLIENT)
            .ok_or(RecordRejection::StaleRoot)?;
        let (legacy_envelope, observed) = LegacyStatusIdentity::inspect(status)?;
        if observed != expected {
            return Err(RecordRejection::StaleRoot);
        }
        // Empty retention is valid only for the historical HBSR1 inline
        // whole-state format, which has no physical chunk clients. Chunked
        // formats must still name every authenticated active slot.
        if active.len() > 128
            || (active.is_empty() && !legacy_envelope.sealed().starts_with(b"HBSR1"))
        {
            return Err(RecordRejection::Invalid);
        }
        let mut indexes = std::collections::BTreeSet::new();
        let mut retained = std::collections::BTreeSet::new();
        for reference in active {
            reference.identity.validate()?;
            if reference.index > 127 || reference.slot > 1 || !indexes.insert(reference.index) {
                return Err(RecordRejection::Invalid);
            }
            let client = format!(
                "heptabao-production-ha-chunk:{:03}:{}",
                reference.index, reference.slot
            );
            let status = self
                .client_status
                .get(&client)
                .ok_or(RecordRejection::MissingDependency)?;
            if LegacyStatusIdentity::inspect(status)?.1 != reference.identity {
                return Err(RecordRejection::ImmutableConflict);
            }
            retained.insert(client);
        }
        // The application proposer has authenticated the inline HBSR1 state or
        // HBSM4 manifest and complete reference set under its serialized leader
        // writer. Runtime has no replication key.
        // Freeze production legacy writes atomically with cleanup; a later old
        // writer cannot replace a kept slot or publish now-deleted staged slots.
        let keep = |client: &String| {
            client == PRODUCTION_CLIENT
                || !retired_legacy_client(client)
                || retained.contains(client)
        };
        let remaining = self
            .client_status
            .iter()
            .filter(|(client, _)| keep(client))
            .try_fold(2_usize, |sum, (client, status)| {
                sum.checked_add(status_entry_size(client, status)?)
                    .ok_or(RecordRejection::Budget)
            })?;
        if let Some(records) = &mut self.records_v5 {
            records.prepare_legacy_migration(expected, remaining)?;
        } else {
            let mut records = RecordState::default();
            records.prepare_legacy_migration(expected, remaining)?;
            self.records_v5 = Some(records);
        }
        // No fallible work after mutation. Root and all selected statuses retain
        // their exact encoded bytes; only recognized unreferenced slots leave.
        self.client_status.retain(|client, _| keep(client));
        self.legacy_json_bytes = Some(remaining);
        Ok(())
    }

    pub(crate) fn apply(&mut self, request: &ApplicationRequest) -> ApplicationResponse {
        #[cfg(feature = "experimental-v6-raft-objects")]
        if let Some(result) = self.apply_native_v6_command(request) {
            return match result {
                Ok(()) => ApplicationResponse::Records(RecordResponse {
                    accepted: true,
                    rejection: None,
                }),
                Err(error) => ApplicationResponse::rejected(error),
            };
        }
        #[cfg(feature = "experimental-v6-raft-objects")]
        let v6_applied_provenance = match request {
            ApplicationRequest::RecordsV5(data) => match &data.records_v5 {
                RecordCommand::Stage { object }
                    if object.reference().kind == crate::RecordObjectKind::NativeV6CommitIntent =>
                {
                    let Some(log) = self.last_applied_log else {
                        return ApplicationResponse::rejected(RecordRejection::Invalid);
                    };
                    let Ok(intent) = crate::NativeV6CommitIntent::decode(object.sealed()) else {
                        return ApplicationResponse::rejected(RecordRejection::Invalid);
                    };
                    if intent.expected_previous_commit_index >= log.index {
                        return ApplicationResponse::rejected(RecordRejection::Invalid);
                    }
                    let mut key = String::with_capacity(64);
                    crate::append_hex(&mut key, &object.reference().id);
                    if !self.v6_intent_log_provenance.contains_key(&key)
                        && self.v6_intent_log_provenance.len() >= 4096
                    {
                        return ApplicationResponse::rejected(RecordRejection::Budget);
                    }
                    Some((key, log))
                }
                RecordCommand::Prune { ids, .. } => {
                    for id in ids {
                        let mut key = String::with_capacity(64);
                        crate::append_hex(&mut key, id);
                        if self.v6_intent_log_provenance.contains_key(&key) {
                            return ApplicationResponse::rejected(
                                RecordRejection::ReferencedByStaged,
                            );
                        }
                    }
                    None
                }
                _ => None,
            },
            _ => None,
        };
        let result = match request {
            ApplicationRequest::Legacy(data) => {
                if retired_legacy_client(&data.client)
                    && self
                        .records_v5
                        .as_ref()
                        .and_then(RecordState::prepared_identity)
                        .is_some()
                {
                    return ApplicationResponse::rejected(RecordRejection::LegacyFenced);
                }
                if self.records_v5.is_some() {
                    let previous = match self.legacy_json_bytes {
                        Some(n) => Ok(n),
                        None => self.legacy_size(),
                    };
                    let proposed = previous.and_then(|n| {
                        let prior = self
                            .client_status
                            .get(&data.client)
                            .map(|s| status_entry_size(&data.client, s))
                            .transpose()?
                            .unwrap_or(0);
                        n.checked_sub(prior)
                            .and_then(|n| {
                                n.checked_add(status_entry_size(&data.client, &data.status).ok()?)
                            })
                            .ok_or(RecordRejection::Budget)
                    });
                    match proposed.and_then(|bytes| {
                        self.records_v5
                            .as_mut()
                            .ok_or(RecordRejection::Invalid)?
                            .permits_legacy(bytes)?;
                        Ok(bytes)
                    }) {
                        Ok(bytes) => self.legacy_json_bytes = Some(bytes),
                        Err(reason) => return ApplicationResponse::rejected(reason),
                    }
                } else {
                    self.legacy_json_bytes = None;
                }
                let previous = self
                    .client_status
                    .insert(data.client.clone(), data.status.clone());
                return ApplicationResponse::Legacy(openraft_memstore::ClientResponse(previous));
            }
            ApplicationRequest::RecordsV5(data) => {
                // Must precede build_cache: the old two-slot map can exceed the
                // typed staging budget and still be a valid legacy artifact.
                if let RecordCommand::RetainLegacyChunks {
                    expected_manifest,
                    active,
                } = &data.records_v5
                {
                    return match request
                        .validate_size()
                        .and_then(|()| self.retain_legacy_chunks(*expected_manifest, active))
                    {
                        Ok(()) => ApplicationResponse::Records(RecordResponse {
                            accepted: true,
                            rejection: None,
                        }),
                        Err(reason) => ApplicationResponse::rejected(reason),
                    };
                }
                let operation = || -> Result<(usize, RecordRootBase), RecordRejection> {
                    request.validate_size()?;
                    let base = self.base()?;
                    let reclaim = matches!(data.records_v5, RecordCommand::Publish { .. })
                        && !matches!(base, RecordRootBase::RecordsV5(_));
                    let legacy = if reclaim {
                        self.client_status
                            .iter()
                            .filter(|(client, _)| !retired_legacy_client(client))
                            .try_fold(2_usize, |sum, (client, status)| {
                                sum.checked_add(status_entry_size(client, status)?)
                                    .ok_or(RecordRejection::Budget)
                            })?
                    } else {
                        match self.legacy_json_bytes {
                            Some(n) => n,
                            None => self.legacy_size()?,
                        }
                    };
                    Ok((legacy, base))
                };
                match operation() {
                    Err(error) => Err(error),
                    Ok((legacy, base)) => if let Some(records) = self.records_v5.as_mut() {
                        records.apply(&data.records_v5, base, legacy)
                    } else {
                        let mut records = RecordState::default();
                        match records.apply(&data.records_v5, base, legacy) {
                            Ok(()) => {
                                self.records_v5 = Some(records);
                                Ok(())
                            }
                            Err(error) => Err(error),
                        }
                    }
                    .inspect(|()| {
                        if matches!(data.records_v5, RecordCommand::Publish { .. })
                            && !matches!(base, RecordRootBase::RecordsV5(_))
                        {
                            self.client_status
                                .retain(|client, _| !retired_legacy_client(client));
                        }
                        self.legacy_json_bytes = Some(legacy);
                    }),
                }
            }
        };
        match result {
            Ok(()) => {
                #[cfg(feature = "experimental-v6-raft-objects")]
                if matches!(request, ApplicationRequest::RecordsV5(data)
                    if matches!(data.records_v5, RecordCommand::Publish { .. }))
                {
                    // Actual successful application entry, including an explicit
                    // unchanged-root refresh after an upgrade from old snapshots.
                    self.v5_root_log = self.last_applied_log;
                }
                #[cfg(feature = "experimental-v6-raft-objects")]
                if let Some((key, log)) = v6_applied_provenance {
                    // Immutable first-apply identity survives duplicate Stage.
                    self.v6_intent_log_provenance.entry(key).or_insert(log);
                }
                ApplicationResponse::Records(RecordResponse {
                    accepted: true,
                    rejection: None,
                })
            }
            Err(reason) => ApplicationResponse::rejected(reason),
        }
    }
    pub(crate) fn records_format_version(&self) -> Option<u16> {
        #[cfg(feature = "experimental-v6-raft-objects")]
        if self.v6_enrollment.is_some() || self.v6_root.is_some() {
            return Some(4);
        }
        self.records_v5.as_ref().map(|_| 3)
    }
    pub(crate) fn native_v6_is_published(&self) -> bool {
        #[cfg(feature = "experimental-v6-raft-objects")]
        {
            self.v6_root.is_some()
        }
        #[cfg(not(feature = "experimental-v6-raft-objects"))]
        {
            false
        }
    }
    pub(crate) fn snapshot_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        if let Some(format_version) = self.records_format_version() {
            #[derive(Serialize)]
            struct Wire<'a> {
                format_version: u16,
                state: &'a StateMachine,
            }
            serde_json::to_vec(&Wire {
                format_version,
                state: self,
            })
        } else {
            serde_json::to_vec(self)
        }
    }
    pub(crate) fn from_snapshot(bytes: &[u8]) -> Result<Self, std::io::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            format_version: u16,
            state: StateMachine,
        }
        #[derive(Deserialize)]
        struct Header {
            format_version: Option<u16>,
        }
        // Ignored state fields are streamed during this header probe; avoid a
        // second full JSON Value tree containing all ciphertext strings.
        let header: Header = serde_json::from_slice(bytes)
            .map_err(|_| std::io::Error::other("invalid state snapshot"))?;
        let state = if header.format_version.is_some() {
            let wire: Wire = serde_json::from_slice(bytes)
                .map_err(|_| std::io::Error::other("invalid typed snapshot"))?;
            if wire.state.records_format_version() != Some(wire.format_version) {
                return Err(std::io::Error::other("invalid records snapshot version"));
            }
            wire.state
        } else {
            let state: Self = serde_json::from_slice(bytes)
                .map_err(|_| std::io::Error::other("invalid legacy snapshot"))?;
            if state.records_v5.is_some() {
                return Err(std::io::Error::other(
                    "records snapshot lacks version fence",
                ));
            }
            state
        };
        state
            .validate()
            .map_err(|_| std::io::Error::other("invalid snapshot object graph"))?;
        Ok(state)
    }
}
