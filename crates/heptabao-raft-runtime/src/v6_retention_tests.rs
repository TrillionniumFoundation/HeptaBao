//! Real state-machine command and snapshot codecs; no TLS/Actor/AEAD claim.
use super::*;
use crate::v6_root_publication::{NativeV6EnrollmentCommand, NativeV6RootCommand};
use crate::{
    ApplicationRequest, PublishedRecordRoot, RaftRuntimeError, ReplicatedEnvelope, StateMachine,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn prepared_recovery(state: &StateMachine) -> TestResult<NativeV6IntentRetirementRecovery> {
    checked(NativeV6IntentRetirementRecovery::prepared(
        state
            .v6_enrollment
            .as_ref()
            .ok_or("enrollment")?
            .command
            .cluster_digest,
        state.last_applied_log.ok_or("applied")?.index + 1,
        checked(state.prepare_native_v6_intent_retirement(32))?,
    ))
}

#[test]
fn native_retention_recovery_same_source_requires_actual_format_and_selected_absence() -> TestResult
{
    let mut state = fixture()?;
    let newer = next(&state, 501)?;
    publish(&mut state, newer)?;
    let data = prepared_recovery(&state)?;
    assert_eq!(data.selected_intents(), 1);
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&data))?,
        NativeV6IntentRetirementResolution::Pending
    );
    apply(
        &mut state,
        RecordCommand::RetireNativeV6Intents {
            retirement: data.command.clone(),
        },
    )?;
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&data))?,
        NativeV6IntentRetirementResolution::EffectsObserved
    );
    assert_eq!(state.records_format_version(), Some(6));
    // New observations do not carry or invent the original request's ACK.
    assert_eq!(
        checked(NativeV6IntentRetirementRecovery::decode_for_reconciliation(
            &checked(data.encode())?
        ))?,
        data
    );
    Ok(())
}

#[test]
fn native_retention_recovery_strict_supersession_fences_old_command_without_removing_intents()
-> TestResult {
    let mut state = fixture()?;
    let newer = next(&state, 502)?;
    publish(&mut state, newer)?;
    let data = prepared_recovery(&state)?;
    let before = checked(state.native_v6_retained_intents())?;
    let next_root = next(&state, 503)?;
    publish(&mut state, next_root)?;
    assert_eq!(
        checked(state.observe_native_v6_intent_retirement(&data))?,
        NativeV6IntentRetirementResolution::SupersededByNewRoot
    );
    let actual = checked(state.native_v6_retained_intents())?;
    for (id, original) in before {
        assert_eq!(actual.get(&id), Some(&original));
    }
    let snapshot = checked(state.native_v6_retained_intents())?;
    assert_eq!(
        state.apply_native_v6_intent_retirement(&data.command),
        Err(RecordRejection::StaleRoot)
    );
    assert_eq!(checked(state.native_v6_retained_intents())?, snapshot);
    assert!(
        state.v6_retention_protocol.is_none(),
        "reconciliation does not activate retention or delete metadata"
    );
    Ok(())
}

#[test]
fn native_retention_recovery_foreign_or_merely_different_source_is_always_a_hold() -> TestResult {
    let mut state = fixture()?;
    let newer = next(&state, 504)?;
    publish(&mut state, newer)?;
    let actual = prepared_recovery(&state)?;
    for case in 0..7 {
        let mut previous = actual.clone();
        match case {
            0 => previous.cluster_digest[0] ^= 1,
            1 => previous.command.source.enrollment_digest[0] ^= 1,
            2 => previous.command.source.epoch += 1,
            3 => previous.command.source.root_digest[0] ^= 1,
            4 => previous.command.source.generation -= 1,
            5 => {
                previous.command.source.generation -= 1;
                previous.command.source.publication_log.index += 1;
            }
            _ => {
                previous.command.source.generation -= 1;
                previous.command.source.publication_log.index -= 2;
                previous.command.source.intent_log.index -= 2;
                previous.command.source.publication_log.leader_id.term += 1;
            }
        }
        assert_eq!(
            checked(state.observe_native_v6_intent_retirement(&previous))?,
            NativeV6IntentRetirementResolution::Pending
        );
    }
    Ok(())
}

#[test]
fn native_retention_recovery_data_is_canonical_bounded_and_never_a_submission_owner() -> TestResult
{
    let state = fixture()?;
    let data = prepared_recovery(&state)?;
    let canonical = checked(data.encode())?;
    let mut trailing = canonical.clone();
    trailing.push(b'\n');
    assert!(NativeV6IntentRetirementRecovery::decode_for_reconciliation(&trailing).is_err());
    assert!(
        NativeV6IntentRetirementRecovery::decode_for_reconciliation(&vec![b' '; 16 * 1024 + 1])
            .is_err()
    );
    let mut invalid = data.clone();
    invalid.serial = 0;
    assert!(invalid.encode().is_err());
    let decoded = checked(NativeV6IntentRetirementRecovery::decode_for_reconciliation(
        &canonical,
    ))?;
    assert_eq!(
        checked(decoded.command_digest())?,
        checked(data.command_digest())?
    );
    assert_eq!(
        checked(decoded.capsule_digest())?,
        checked(data.capsule_digest())?
    );
    Ok(())
}
fn checked<T>(result: Result<T, RecordRejection>) -> TestResult<T> {
    result.map_err(|error| {
        Box::new(RaftRuntimeError::RecordRejected(error)) as Box<dyn std::error::Error>
    })
}
fn log(index: u64) -> Log {
    openraft::LogId {
        leader_id: openraft::impls::leader_id_adv::LeaderId {
            term: 1,
            node_id: 1,
        },
        index,
    }
}
fn apply(state: &mut StateMachine, command: RecordCommand) -> TestResult<Log> {
    let next = state.last_applied_log.map_or(1, |log| log.index + 1);
    let request = checked(ApplicationRequest::records(next, command))?;
    state.last_applied_log = Some(log(next));
    checked(state.apply(&request).result())?;
    Ok(log(next))
}
fn stage(state: &mut StateMachine, intent: NativeV6CommitIntent) -> TestResult<Log> {
    apply(
        state,
        RecordCommand::Stage {
            object: SealedRecordObject::new_native_v6_commit_intent(intent)?,
        },
    )
}
fn root_command(
    state: &StateMachine,
    intent: NativeV6CommitIntent,
    origin: Log,
) -> TestResult<NativeV6RootCommand> {
    let enrollment = state.v6_enrollment.as_ref().ok_or("enrollment absent")?;
    Ok(NativeV6RootCommand {
        intent,
        intent_log: origin,
        enrollment_digest: enrollment.digest(),
        envelope: ReplicatedEnvelope::new(
            NativeV6RootCommand::operation_id(&intent),
            intent.proposed_root_digest,
            vec![0x55; 64],
        )?,
    })
}
fn next(state: &StateMachine, operation: u64) -> TestResult<NativeV6CommitIntent> {
    let current = state.v6_root.as_ref().ok_or("root absent")?;
    let mut digest = [7_u8; 32];
    digest[..8].copy_from_slice(&operation.to_be_bytes());
    let mut proposed = [9_u8; 32];
    proposed[..8].copy_from_slice(&operation.to_be_bytes());
    Ok(NativeV6CommitIntent {
        operation_digest: digest,
        proposed_root_digest: proposed,
        prior_root_digest: current.command.intent.proposed_root_digest,
        prior_generation: current.command.intent.proposed_generation,
        proposed_generation: current.command.intent.proposed_generation + 1,
        expected_previous_commit_index: current.publication_log.index,
        ..current.command.intent
    })
}
fn publish(state: &mut StateMachine, intent: NativeV6CommitIntent) -> TestResult<Log> {
    let origin = stage(state, intent)?;
    let root = root_command(state, intent, origin)?;
    apply(state, RecordCommand::PublishNativeV6 { root })
}
fn fixture() -> TestResult<StateMachine> {
    let mut state = StateMachine::default();
    state.last_applied_log = Some(log(1));
    state.last_membership = openraft::StoredMembership::new(
        Some(log(1)),
        openraft::Membership::new(
            vec![BTreeSet::from([1, 2, 3])],
            BTreeMap::from([(1, ()), (2, ()), (3, ())]),
        )
        .map_err(|_| "retention fixture membership rejected")?,
    );
    let v5 = PublishedRecordRoot::new(
        RecordRootBase::Empty,
        ReplicatedEnvelope::new("retention-fixture-v5", [4; 32], vec![0x44; 32])?,
        vec![],
    )?;
    let migration = apply(&mut state, RecordCommand::Publish { root: v5 })?;
    apply(
        &mut state,
        RecordCommand::EnrollNativeV6 {
            enrollment: NativeV6EnrollmentCommand {
                cluster_digest: [1; 32],
                epoch: 7,
                membership_log: log(1),
                pins: BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]),
            },
        },
    )?;
    publish(
        &mut state,
        NativeV6CommitIntent {
            cluster_digest: [1; 32],
            epoch: 7,
            operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32],
            object_count: 1,
            ciphertext_bytes: 64,
            prior_root_digest: [4; 32],
            proposed_root_digest: [5; 32],
            prior_generation: 0,
            proposed_generation: 1,
            expected_previous_commit_index: migration.index,
        },
    )?;
    checked(state.validate())?;
    Ok(state)
}
fn retire(state: &mut StateMachine, limit: usize) -> TestResult<NativeV6IntentRetirementCommand> {
    let retirement = checked(state.prepare_native_v6_intent_retirement(limit))?;
    apply(
        state,
        RecordCommand::RetireNativeV6Intents {
            retirement: retirement.clone(),
        },
    )?;
    Ok(retirement)
}
fn epoch_restore(state: &mut StateMachine, operation: u64) -> TestResult {
    use crate::v6_epoch_restore::{
        NativeV6EpochRestoreCommand, NativeV6EpochRestorePublication, NativeV6EpochRestoreSource,
    };
    let mut intent = next(state, operation)?;
    intent.epoch += 1;
    let source = checked(NativeV6EpochRestoreSource::from_current(
        state.v6_enrollment.as_ref().ok_or("enrollment absent")?,
        state.v6_root.as_ref().ok_or("root absent")?,
    ))?;
    let pending = NativeV6EpochRestoreCommand {
        source,
        operation_digest: intent.operation_digest,
        proposed_root_digest: intent.proposed_root_digest,
        next_epoch: intent.epoch,
    };
    apply(state, RecordCommand::BeginNativeV6EpochRestore { pending })?;
    let origin = stage(state, intent)?;
    let pending = state
        .v6_pending_epoch_restore
        .clone()
        .ok_or("pending absent")?;
    let publication = NativeV6EpochRestorePublication {
        root: NativeV6RootCommand {
            intent,
            intent_log: origin,
            enrollment_digest: pending.target_enrollment.digest(),
            envelope: ReplicatedEnvelope::new(
                NativeV6RootCommand::operation_id(&intent),
                intent.proposed_root_digest,
                vec![0x66; 64],
            )?,
        },
        pending,
    };
    apply(
        state,
        RecordCommand::PublishNativeV6EpochRestore {
            publication: Box::new(publication),
        },
    )?;
    Ok(())
}

#[test]
fn native_retention_retires_only_superseded_and_preserves_future_current_and_legacy() -> TestResult
{
    let mut state = fixture()?;
    let original = state.v6_root.clone().ok_or("root absent")?;
    let original_object = SealedRecordObject::new_native_v6_commit_intent(original.command.intent)?;
    let second = next(&state, 10)?;
    publish(&mut state, second)?;
    let future = next(&state, 11)?;
    let future_log = stage(&mut state, future)?;
    let future_object = SealedRecordObject::new_native_v6_commit_intent(future)?;
    let before_root = state.v6_root.clone();
    let before_migration = state
        .records_v5
        .as_ref()
        .and_then(crate::records::RecordState::published);
    let result = retire(&mut state, 32)?;
    assert_eq!(result.intents.len(), 1);
    assert_eq!(result.intents[0].id, original_object.reference().id);
    assert!(state.v6_root == before_root);
    assert_eq!(
        state
            .records_v5
            .as_ref()
            .and_then(crate::records::RecordState::published),
        before_migration
    );
    assert_eq!(
        state.v6_intent_log_id(&future_object.reference().id),
        Some(future_log)
    );
    assert_eq!(
        state.v6_intent_log_id(&original_object.reference().id),
        None
    );
    assert_eq!(state.records_format_version(), Some(6));
    checked(state.validate())?;
    Ok(())
}

#[test]
fn native_retention_replay_cannot_mint_fresh_old_provenance_and_original_prune_stays_fenced()
-> TestResult {
    let mut state = fixture()?;
    let old = state.v6_root.as_ref().ok_or("root absent")?.command.intent;
    let second = next(&state, 12)?;
    publish(&mut state, second)?;
    retire(&mut state, 32)?;
    let old_object = SealedRecordObject::new_native_v6_commit_intent(old)?;
    assert!(stage(&mut state, old).is_err());
    assert!(state.v6_intent_log_id(&old_object.reference().id).is_none());
    let current = SealedRecordObject::new_native_v6_commit_intent(second)?;
    let origin = state.v6_intent_log_id(&current.reference().id);
    stage(&mut state, second)?;
    assert_eq!(state.v6_intent_log_id(&current.reference().id), origin);
    assert!(
        apply(
            &mut state,
            RecordCommand::Prune {
                expected_root: [4; 32],
                ids: vec![current.reference().id]
            }
        )
        .is_err()
    );
    let third = next(&state, 13)?;
    publish(&mut state, third)?;
    checked(state.validate())?;
    Ok(())
}

#[test]
fn native_retention_all_epoch_sources_targets_and_pending_are_preserved() -> TestResult {
    let mut state = fixture()?;
    epoch_restore(&mut state, 20)?;
    let ordinary = next(&state, 21)?;
    publish(&mut state, ordinary)?;
    epoch_restore(&mut state, 22)?;
    let latest = next(&state, 23)?;
    publish(&mut state, latest)?;
    let protected = checked(state.native_v6_protected_intent_logs())?;
    assert_eq!(protected.len(), 5);
    retire(&mut state, 32)?;
    let retained = checked(state.native_v6_retained_intents())?;
    assert!(
        protected
            .iter()
            .all(|origin| retained.values().any(|(_, log)| log == origin))
    );
    let pending_source = checked(
        crate::v6_epoch_restore::NativeV6EpochRestoreSource::from_current(
            state.v6_enrollment.as_ref().ok_or("enrollment absent")?,
            state.v6_root.as_ref().ok_or("root absent")?,
        ),
    )?;
    let mut target = next(&state, 24)?;
    target.epoch += 1;
    apply(
        &mut state,
        RecordCommand::BeginNativeV6EpochRestore {
            pending: crate::v6_epoch_restore::NativeV6EpochRestoreCommand {
                source: pending_source,
                operation_digest: target.operation_digest,
                proposed_root_digest: target.proposed_root_digest,
                next_epoch: target.epoch,
            },
        },
    )?;
    let target_log = stage(&mut state, target)?;
    let before_pending = state.v6_pending_epoch_restore.clone();
    retire(&mut state, 32)?;
    assert!(state.v6_pending_epoch_restore == before_pending);
    assert!(checked(state.native_v6_protected_intent_logs())?.contains(&target_log));
    Ok(())
}

#[test]
fn native_retention_missing_historical_source_is_a_closed_catalog_failure() -> TestResult {
    let mut state = fixture()?;
    epoch_restore(&mut state, 30)?;
    let source_log = state.v6_root.as_ref().ok_or("root absent")?.restore_lineage[0]
        .pending
        .command
        .source
        .intent_log;
    let id = state
        .v6_intent_log_provenance
        .iter()
        .find(|(_, origin)| **origin == source_log)
        .map(|(key, _)| key.clone())
        .ok_or("source provenance absent")?;
    // Matching object/provenance counts alone do not prove historical cover.
    let mut value = serde_json::to_value(&state)?;
    value["v6_intent_log_provenance"]
        .as_object_mut()
        .ok_or("map absent")?
        .remove(&id);
    value["records_v5"]["objects"]
        .as_object_mut()
        .ok_or("objects absent")?
        .remove(&id);
    let damaged: StateMachine = serde_json::from_value(value)?;
    assert!(damaged.prepare_native_v6_intent_retirement(32).is_err());
    Ok(())
}

#[test]
fn native_retention_stale_source_duplicate_wrong_origin_and_live_selection_are_atomic() -> TestResult
{
    let mut state = fixture()?;
    let second = next(&state, 40)?;
    publish(&mut state, second)?;
    let plan = checked(state.prepare_native_v6_intent_retirement(32))?;
    assert_eq!(plan.intents.len(), 1);
    let current = SealedRecordObject::new_native_v6_commit_intent(second)?;
    for case in 0..5 {
        let mut changed = plan.clone();
        match case {
            0 => changed.source.root_digest[0] ^= 1,
            1 => changed.intents.push(changed.intents[0].clone()),
            2 => changed.intents[0].original_log.leader_id.node_id = 2,
            3 => {
                changed.intents[0] = NativeV6RetiredIntent {
                    id: current.reference().id,
                    original_log: state
                        .v6_intent_log_id(&current.reference().id)
                        .ok_or("current origin absent")?,
                }
            }
            _ => changed.protocol = 2,
        }
        let mut attempt = state.clone();
        attempt.last_applied_log =
            Some(log(attempt.last_applied_log.ok_or("last absent")?.index + 1));
        let before = serde_json::to_value(&attempt)?;
        assert!(attempt.apply_native_v6_intent_retirement(&changed).is_err());
        assert_eq!(serde_json::to_value(&attempt)?, before);
    }
    let advanced = next(&state, 41)?;
    publish(&mut state, advanced)?;
    assert!(state.apply_native_v6_intent_retirement(&plan).is_err());
    Ok(())
}

#[test]
fn native_retention_format6_survives_snapshot_and_rejects_downgrade_or_unknown_marker() -> TestResult
{
    let mut state = fixture()?;
    let old = state.snapshot_bytes()?;
    assert_eq!(
        StateMachine::from_snapshot(&old)?.records_format_version(),
        Some(4)
    );
    retire(&mut state, 1)?;
    let bytes = state.snapshot_bytes()?;
    assert_eq!(
        StateMachine::from_snapshot(&bytes)?.records_format_version(),
        Some(6)
    );
    for version in [3, 4, 5, 7] {
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
        changed["format_version"] = serde_json::json!(version);
        assert!(StateMachine::from_snapshot(&serde_json::to_vec(&changed)?).is_err());
    }
    for marker in [0, 2, 255] {
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
        changed["state"]["v6_retention_protocol"] = serde_json::json!(marker);
        assert!(StateMachine::from_snapshot(&serde_json::to_vec(&changed)?).is_err());
    }
    Ok(())
}

#[test]
fn native_retention_removes_the_real_4096_intent_capacity_block_without_widening_it() -> TestResult
{
    let mut state = fixture()?;
    let first = state.v6_root.as_ref().ok_or("root absent")?.command.intent;
    // Sibling proposals at generation one are provably superseded by the
    // published generation-one root. Each uses the actual Stage command.
    for sequence in 1..4096_u64 {
        let mut intent = first;
        intent.operation_digest[..8].copy_from_slice(&sequence.to_be_bytes());
        intent.proposed_root_digest[..8].copy_from_slice(&(sequence + 100).to_be_bytes());
        stage(&mut state, intent)?;
    }
    assert_eq!(state.v6_intent_log_provenance.len(), 4096);
    let following = next(&state, 5000)?;
    assert!(stage(&mut state, following).is_err());
    let removed = retire(&mut state, 32)?;
    assert_eq!(removed.intents.len(), 32);
    assert_eq!(state.v6_intent_log_provenance.len(), 4064);
    publish(&mut state, following)?;
    assert_eq!(state.v6_intent_log_provenance.len(), 4065);
    checked(state.validate())?;
    Ok(())
}

#[path = "v6_retained_roots_tests.rs"]
mod retained_root_tests;
