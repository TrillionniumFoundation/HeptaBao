//! Actual Apply and format components using the existing synthetic-envelope
//! state fixture. These do not claim AEAD, TLS, Service or old server execution.
use super::*;
use crate::v6_retained_roots::NativeV6RetainedRootActivation;

#[path = "v6_retained_roots_legacy_codec_tests.rs"]
mod legacy_codec;

fn activate(state: &mut StateMachine) -> TestResult<NativeV6IntentRetirementRecovery> {
    let command = checked(state.prepare_native_v6_retained_root_activation())?;
    let capsule = checked(NativeV6IntentRetirementRecovery::prepared_root_activation(
        state
            .v6_enrollment
            .as_ref()
            .ok_or("enrollment")?
            .command
            .cluster_digest,
        state.last_applied_log.ok_or("applied")?.index + 1,
        command.clone(),
    ))?;
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&capsule))?,
        NativeV6IntentRetirementResolution::Pending
    );
    apply(
        state,
        RecordCommand::ActivateNativeV6RetainedRoots {
            activation: command,
        },
    )?;
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&capsule))?,
        NativeV6IntentRetirementResolution::EffectsObserved
    );
    Ok(capsule)
}

#[test]
fn native_retention_provenance_activation_atomic_floor_and_original_wire_refusal() -> TestResult {
    let mut state = fixture()?;
    assert!(state.prepare_native_v6_retained_root_activation().is_err());
    retire(&mut state, 32)?;
    let before = state.v6_root.clone();
    let legacy = state.snapshot_bytes()?;
    assert!(legacy_codec::from_snapshot(&legacy).is_ok());
    let old_request = checked(ApplicationRequest::records(
        state.last_applied_log.ok_or("applied")?.index + 1,
        RecordCommand::RetireNativeV6Intents {
            retirement: checked(state.prepare_native_v6_intent_retirement(32))?,
        },
    ))?;
    assert!(
        legacy_codec::decode_application(&serde_json::to_vec(&old_request)?).is_ok(),
        "same old decoder must accept the actual pre-activation wire command"
    );
    let command = checked(state.prepare_native_v6_retained_root_activation())?;
    let request = checked(ApplicationRequest::records(
        state.last_applied_log.ok_or("applied")?.index + 1,
        RecordCommand::ActivateNativeV6RetainedRoots {
            activation: command,
        },
    ))?;
    let bytes = serde_json::to_vec(&request)?;
    assert!(
        legacy_codec::decode_application(&bytes).is_err(),
        "new activation must not fall through to legacy untagged request"
    );
    let roundtrip: ApplicationRequest = serde_json::from_slice(&bytes)?;
    assert_eq!(serde_json::to_vec(&roundtrip)?, bytes);
    let capsule = activate(&mut state)?;
    assert!(capsule.activates_retained_roots());
    assert_eq!(capsule.selected_intents(), 0);
    assert!(
        state.v6_root == before,
        "activation preserves exact current sealed root"
    );
    assert_eq!(state.records_format_version(), Some(7));
    let active = state.snapshot_bytes()?;
    assert!(StateMachine::from_snapshot(&active).is_ok());
    assert!(
        legacy_codec::from_snapshot(&active).is_err(),
        "old actual format calculation refuses the new durable fence"
    );
    // Empty lineage still carries the floor; it cannot disappear because an
    // optional vector or provenance map has no entries yet.
    assert!(
        state
            .v6_root
            .as_ref()
            .ok_or("root")?
            .restore_lineage
            .is_empty()
    );
    let mut mislabeled: serde_json::Value = serde_json::from_slice(&active)?;
    mislabeled["format_version"] = serde_json::json!(6);
    assert!(StateMachine::from_snapshot(&serde_json::to_vec(&mislabeled)?).is_err());
    Ok(())
}

#[test]
fn native_retention_provenance_actual_epoch_apply_keeps_source_target_and_later_publications()
-> TestResult {
    let mut state = fixture()?;
    retire(&mut state, 32)?;
    activate(&mut state)?;
    let first_source = state.v6_root.clone().ok_or("source")?;
    epoch_restore(&mut state, 701)?;
    let first_target = state.v6_root.clone().ok_or("target")?;
    let ordinary = next(&state, 702)?;
    publish(&mut state, ordinary)?;
    let second_source = state.v6_root.clone().ok_or("second source")?;
    epoch_restore(&mut state, 703)?;
    let second_target = state.v6_root.clone().ok_or("second target")?;
    let ordinary = next(&state, 704)?;
    publish(&mut state, ordinary)?;
    let cold = StateMachine::from_snapshot(&state.snapshot_bytes()?)?;
    assert_eq!(cold.records_format_version(), Some(7));
    let root = cold.v6_root.as_ref().ok_or("cold root")?;
    assert_eq!(root.restore_lineage.len(), 2);
    for (index, source, target) in [
        (0, first_source, first_target),
        (1, second_source, second_target),
    ] {
        let step = &root.restore_lineage[index];
        let retained = step.retained_roots.as_ref().ok_or("retained roots")?;
        assert!(retained.source == source.command);
        assert!(retained.target == target.command);
        assert_eq!(
            step.pending.command.source.publication_log,
            source.publication_log
        );
        assert_eq!(step.publication_log, target.publication_log);
        assert_ne!(
            retained.target.envelope.sealed(),
            root.command.envelope.sealed()
        );
    }
    checked(cold.validate())?;
    let mut downgraded = cold.clone();
    downgraded.v6_retained_root_protocol = None;
    assert!(downgraded.validate().is_err());
    for case in 0..6 {
        let mut damaged = cold.clone();
        let step = &mut damaged.v6_root.as_mut().ok_or("root")?.restore_lineage[0];
        let roots = step.retained_roots.as_mut().ok_or("roots")?;
        match case {
            0 => roots.source.enrollment_digest[0] ^= 1,
            1 => roots.source.intent_log.index += 1,
            2 => roots.target.intent_log.leader_id.term += 1,
            3 => roots.source.intent.closure_manifest_sha256[0] ^= 1,
            4 => roots.source.intent.ciphertext_bytes += 1,
            _ => step.retained_roots = None,
        }
        assert!(damaged.validate().is_err());
    }
    Ok(())
}

#[test]
fn native_retention_provenance_legacy_missing_roots_and_stale_activation_are_holds() -> TestResult {
    let mut legacy = fixture()?;
    epoch_restore(&mut legacy, 711)?;
    retire(&mut legacy, 32)?;
    let root = legacy.v6_root.clone();
    let enrollment = legacy.v6_enrollment.clone();
    assert!(matches!(
        legacy.prepare_native_v6_retained_root_activation(),
        Err(RecordRejection::MissingDependency)
    ));
    let supplied: NativeV6RetainedRootActivation = serde_json::from_value(serde_json::json!({
        "protocol":1, "source":checked(NativeV6RetentionSource::from_state(&legacy))?,
    }))?;
    assert_eq!(
        legacy.apply_native_v6_retained_root_activation(&supplied),
        Err(RecordRejection::MissingDependency)
    );
    assert!(legacy.v6_root == root && legacy.v6_enrollment == enrollment);
    assert!(legacy.v6_retained_root_protocol.is_none());

    let mut state = fixture()?;
    retire(&mut state, 32)?;
    let activation = checked(state.prepare_native_v6_retained_root_activation())?;
    let capsule = checked(NativeV6IntentRetirementRecovery::prepared_root_activation(
        [1; 32],
        state.last_applied_log.ok_or("applied")?.index + 1,
        activation.clone(),
    ))?;
    let changed = next(&state, 712)?;
    publish(&mut state, changed)?;
    let root = state.v6_root.clone();
    assert_eq!(
        state.apply_native_v6_retained_root_activation(&activation),
        Err(RecordRejection::StaleRoot)
    );
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&capsule))?,
        NativeV6IntentRetirementResolution::SupersededByNewRoot
    );
    assert!(state.v6_retained_root_protocol.is_none());
    assert!(state.v6_root == root);
    Ok(())
}

#[test]
fn native_retention_provenance_capsule_has_distinct_canonical_read_only_operation() -> TestResult {
    let mut state = fixture()?;
    retire(&mut state, 32)?;
    let capsule = activate(&mut state)?;
    let original = checked(capsule.encode())?;
    let decoded = checked(NativeV6IntentRetirementRecovery::decode_for_reconciliation(
        &original,
    ))?;
    assert_eq!(
        checked(decoded.command_digest())?,
        checked(capsule.command_digest())?
    );
    assert_ne!(
        checked(decoded.command_digest())?,
        checked(decoded.command.digest())?
    );
    for case in 0..3 {
        let mut wrong: serde_json::Value = serde_json::from_slice(&original)?;
        match case {
            0 => wrong["format"] = serde_json::json!(1),
            1 => wrong["command"]["source"]["root_digest"][0] = serde_json::json!(99),
            _ => {
                wrong
                    .as_object_mut()
                    .ok_or("capsule")?
                    .remove("retained_root_activation");
            }
        }
        assert!(
            NativeV6IntentRetirementRecovery::decode_for_reconciliation(&serde_json::to_vec(
                &wrong
            )?)
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn native_retention_provenance_existing_count_and_byte_bounds_leave_publication_atomic()
-> TestResult {
    use crate::v6_epoch_restore::{
        NativeV6EpochRestoreCommand, NativeV6EpochRestorePublication, NativeV6EpochRestoreSource,
    };
    let mut count_limited = fixture()?;
    retire(&mut count_limited, 32)?;
    activate(&mut count_limited)?;
    for operation in 800..864 {
        epoch_restore(&mut count_limited, operation)?;
    }
    assert_eq!(
        count_limited
            .v6_root
            .as_ref()
            .ok_or("root")?
            .restore_lineage
            .len(),
        64
    );
    let before = count_limited.v6_root.clone();
    assert!(epoch_restore(&mut count_limited, 864).is_err());
    assert!(count_limited.v6_root == before);
    assert!(count_limited.v6_pending_epoch_restore.is_none());
    checked(count_limited.validate())?;

    let mut state = fixture()?;
    retire(&mut state, 32)?;
    activate(&mut state)?;
    for index in 0..3 {
        // Legal maximum-sized opaque root envelopes exercise the actual
        // 512 KiB serialized-lineage bound, not a lowered test-only constant.
        let intent = next(&state, 900 + index * 2)?;
        let origin = stage(&mut state, intent)?;
        let mut root = root_command(&state, intent, origin)?;
        root.envelope = ReplicatedEnvelope::new(
            NativeV6RootCommand::operation_id(&intent),
            intent.proposed_root_digest,
            vec![0x91; 64 * 1024],
        )?;
        apply(&mut state, RecordCommand::PublishNativeV6 { root })?;
        let mut intent = next(&state, 901 + index * 2)?;
        intent.epoch += 1;
        let command = NativeV6EpochRestoreCommand {
            source: checked(NativeV6EpochRestoreSource::from_current(
                state.v6_enrollment.as_ref().ok_or("enrollment")?,
                state.v6_root.as_ref().ok_or("root")?,
            ))?,
            operation_digest: intent.operation_digest,
            proposed_root_digest: intent.proposed_root_digest,
            next_epoch: intent.epoch,
        };
        apply(
            &mut state,
            RecordCommand::BeginNativeV6EpochRestore { pending: command },
        )?;
        let origin = stage(&mut state, intent)?;
        let pending = state.v6_pending_epoch_restore.clone().ok_or("pending")?;
        let publication = NativeV6EpochRestorePublication {
            root: NativeV6RootCommand {
                intent,
                intent_log: origin,
                enrollment_digest: pending.target_enrollment.digest(),
                envelope: ReplicatedEnvelope::new(
                    NativeV6RootCommand::operation_id(&intent),
                    intent.proposed_root_digest,
                    vec![0x92; 64 * 1024],
                )?,
            },
            pending,
        };
        let root_before = state.v6_root.clone();
        let enrollment_before = state.v6_enrollment.clone();
        let pending_before = state.v6_pending_epoch_restore.clone();
        let index_of_apply = state.last_applied_log.ok_or("applied")?.index + 1;
        let request = checked(ApplicationRequest::records(
            index_of_apply,
            RecordCommand::PublishNativeV6EpochRestore {
                publication: Box::new(publication),
            },
        ))?;
        state.last_applied_log = Some(log(index_of_apply));
        let result = state.apply(&request).result();
        if index < 2 {
            checked(result)?;
            assert!(state.v6_pending_epoch_restore.is_none());
        } else {
            assert_eq!(result, Err(RecordRejection::Budget));
            assert!(state.v6_root == root_before && state.v6_enrollment == enrollment_before);
            assert!(
                state.v6_pending_epoch_restore == pending_before,
                "failed publication cannot consume its pending source"
            );
            assert_eq!(state.records_format_version(), Some(7));
            checked(state.validate())?;
        }
    }
    Ok(())
}
