//! Exact old enum and format-decision bodies, renamed for local component
//! tests. records.rs SHA ccb8bca2f70c618d07bcec9beda80582d4843c3a1f168be71128e4a09db6ecd7;
//! state_machine.rs SHA a10af5f3d137f8f3791711f9b6d5baedc5dc8de91677d22e1363721349fdaf9f.
//! These are not an executed old server. The snapshot test uses the current
//! StateMachine data type solely to exercise the unchanged old format check;
//! old wire fields would impose additional refusals, never grant new rights.
use crate::StateMachine;
use crate::records::{
    LegacyChunkRef, LegacyStatusIdentity, PublishedRecordRoot, RecordObjectId, SealedRecordObject,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
enum OldRecordCommand {
    #[cfg(feature = "native-v6-raft-objects")]
    EnrollNativeV6 {
        enrollment: crate::v6_root_publication::NativeV6EnrollmentCommand,
    },
    #[cfg(feature = "native-v6-raft-objects")]
    PublishNativeV6 {
        root: crate::v6_root_publication::NativeV6RootCommand,
    },
    #[cfg(feature = "native-v6-raft-objects")]
    BeginNativeV6EpochRestore {
        pending: crate::v6_epoch_restore::NativeV6EpochRestoreCommand,
    },
    #[cfg(feature = "native-v6-raft-objects")]
    CancelNativeV6EpochRestore {
        pending: Box<crate::v6_epoch_restore::NativeV6PendingEpochRestore>,
    },
    #[cfg(feature = "native-v6-raft-objects")]
    PublishNativeV6EpochRestore {
        publication: Box<crate::v6_epoch_restore::NativeV6EpochRestorePublication>,
    },
    #[cfg(feature = "native-v6-raft-objects")]
    RetireNativeV6Intents {
        retirement: crate::v6_retention::NativeV6IntentRetirementCommand,
    },
    RetainLegacyChunks {
        expected_manifest: LegacyStatusIdentity,
        active: Vec<LegacyChunkRef>,
    },
    Stage {
        object: SealedRecordObject,
    },
    Publish {
        root: PublishedRecordRoot,
    },
    Prune {
        expected_root: [u8; 32],
        ids: Vec<RecordObjectId>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldRecordRequest {
    serial: u64,
    records_v5: OldRecordCommand,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OldApplicationRequest {
    RecordsV5(Box<OldRecordRequest>),
    Legacy(crate::state_machine::LegacyRequest),
}

pub(super) fn decode_application(bytes: &[u8]) -> Result<(), serde_json::Error> {
    let decoded: OldApplicationRequest = serde_json::from_slice(bytes)?;
    let _ = serde_json::to_vec(&decoded)?;
    Ok(())
}

fn old_records_format_version(state: &StateMachine) -> Option<u16> {
    #[cfg(feature = "native-v6-raft-objects")]
    if state.v6_retention_protocol.is_some() {
        return Some(6);
    }
    #[cfg(feature = "native-v6-raft-objects")]
    if state.v6_epoch_protocol.is_some() {
        return Some(5);
    }
    #[cfg(feature = "native-v6-raft-objects")]
    if state.v6_enrollment.is_some() || state.v6_root.is_some() {
        return Some(4);
    }
    state.records_v5.as_ref().map(|_| 3)
}

pub(super) fn from_snapshot(bytes: &[u8]) -> Result<StateMachine, std::io::Error> {
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
        if old_records_format_version(&wire.state) != Some(wire.format_version) {
            return Err(std::io::Error::other("invalid records snapshot version"));
        }
        wire.state
    } else {
        let state: StateMachine = serde_json::from_slice(bytes)
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
