//! Sticky retention of the two actual sealed roots owned by each committed
//! epoch transition. Activation has a distinct wire command; a mixed old
//! member cannot apply the same old command with different capture semantics.
use crate::v6_retention::{NativeV6RetentionSource, RETENTION_PROTOCOL};
use crate::{RecordRejection, StateMachine};
use serde::{Deserialize, Serialize};

pub(crate) const RETAINED_ROOT_PROTOCOL: u8 = 1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeV6RetainedRootActivation {
    protocol: u8,
    pub(crate) source: NativeV6RetentionSource,
}

impl NativeV6RetainedRootActivation {
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        self.source.validate()?;
        if self.protocol != RETAINED_ROOT_PROTOCOL {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], RecordRejection> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"HeptaBao/native-v6/retained-root-activation/v1\0");
        hash.update(serde_json::to_vec(self).map_err(|_| RecordRejection::Invalid)?);
        Ok(hash.finalize().into())
    }
}

impl StateMachine {
    pub(crate) fn validate_native_v6_retained_roots(&self) -> Result<(), RecordRejection> {
        if self
            .v6_retained_root_protocol
            .is_some_and(|value| value != RETAINED_ROOT_PROTOCOL)
            || (self.v6_retained_root_protocol.is_some()
                && (self.v6_root.is_none()
                    || self.v6_retention_protocol != Some(RETENTION_PROTOCOL)))
        {
            return Err(RecordRejection::Invalid);
        }
        if let Some(root) = &self.v6_root {
            let activated = self.v6_retained_root_protocol == Some(RETAINED_ROOT_PROTOCOL);
            // Both directions matter: missing provenance under the new floor
            // and provenance falsely wrapped in an old floor are rejected.
            if root
                .restore_lineage
                .iter()
                .any(|step| step.retained_roots.is_some() != activated)
            {
                return Err(RecordRejection::MissingDependency);
            }
            for step in &root.restore_lineage {
                if let Some(roots) = &step.retained_roots {
                    for retained in [&roots.source, &roots.target] {
                        // The partial source tuple cannot substitute for the
                        // full original staged intent. Cold decode must reject
                        // a changed closure/operation before any GC catalog.
                        let object =
                            crate::SealedRecordObject::new_native_v6_commit_intent(retained.intent)
                                .map_err(|_| RecordRejection::Invalid)?;
                        if self.v6_intent_log_id(&object.reference().id)
                            != Some(retained.intent_log)
                            || self
                                .records_v5
                                .as_ref()
                                .ok_or(RecordRejection::MissingDependency)?
                                .object(object.reference())?
                                != Some(object)
                        {
                            return Err(RecordRejection::MissingDependency);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_native_v6_retained_root_activation(
        &self,
    ) -> Result<NativeV6RetainedRootActivation, RecordRejection> {
        self.validate()?;
        if self.v6_retention_protocol != Some(RETENTION_PROTOCOL)
            || self.v6_pending_epoch_restore.is_some()
        {
            return Err(RecordRejection::MissingDependency);
        }
        let root = self
            .v6_root
            .as_ref()
            .ok_or(RecordRejection::MissingDependency)?;
        if self.v6_retained_root_protocol.is_none() && !root.restore_lineage.is_empty() {
            // A legacy transition's missing source/target envelope cannot be
            // recreated from its tuple or a caller-supplied decoded root.
            return Err(RecordRejection::MissingDependency);
        }
        let command = NativeV6RetainedRootActivation {
            protocol: RETAINED_ROOT_PROTOCOL,
            source: NativeV6RetentionSource::from_state(self)?,
        };
        command.validate()?;
        Ok(command)
    }

    pub(crate) fn apply_native_v6_retained_root_activation(
        &mut self,
        command: &NativeV6RetainedRootActivation,
    ) -> Result<(), RecordRejection> {
        command.validate()?;
        if self.prepare_native_v6_retained_root_activation()? != *command {
            return Err(RecordRejection::StaleRoot);
        }
        if self
            .last_applied_log
            .is_none_or(|log| log.index <= command.source.publication_log.index)
        {
            return Err(RecordRejection::Invalid);
        }
        let mut candidate = self.clone();
        candidate.v6_retained_root_protocol = Some(RETAINED_ROOT_PROTOCOL);
        candidate.validate()?;
        // The new command, sticky floor and all future capture semantics are
        // atomic. No side file, lazy backfill or post-commit flag is involved.
        *self = candidate;
        Ok(())
    }
}
