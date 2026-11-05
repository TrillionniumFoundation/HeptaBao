//! Real precision issuance and the historical-clock merge, without changing
//! any issuance, expiration, reader-format or ordinary successor guard.
use super::*;
use crate::auth::token_precise_issuance::PreparedCreation;
use crate::auth::token_precision::DurationNanos;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn issue_precise(
    state: &mut AuthState,
    root_token: &str,
    ttl: &str,
) -> TestResult<Zeroizing<String>> {
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let mut actor = state.authenticate_from_observed(
        root_token,
        AuthorityTime::Precise(clock.observed_at()?),
        None,
    )?;
    actor.bind_request_clock(Some(clock))?;
    let parent = state.check_principal(&actor, "", 100)?.service()?.clone();
    let recipe = PreparedCreation {
        actor: &actor,
        namespace: "",
        request_path: "auth/token/create",
        creation_seconds: 100,
        parent,
        policies: BTreeSet::from(["default".into()]),
        role: None,
        issued_role: None,
        root: false,
        batch: false,
        no_parent: false,
        entity_alias: None,
        creation_path: "auth/token/create".into(),
        metadata: crate::auth::public_origin::MetadataInput::Absent,
        requested_renewable: true,
        is_sudo: true,
        requested_no_parent: false,
    };
    let mut issued = state.finish_precise_token_creation(recipe, &json!({"ttl":ttl}), clock)?;
    let Value::String(raw) = issued
        .body
        .pointer_mut("/auth/client_token")
        .ok_or("actual precise token absent")?
        .take()
    else {
        return Err("actual precise token type".into());
    };
    state.validate_token_api_precision_state()?;
    state.validate_system_lease_defaults()?;
    Ok(Zeroizing::new(raw))
}

#[test]
fn unmarked_archive_inherits_actual_precision_owner_without_current_tokens() -> TestResult {
    let (original, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    let mut archived = original.clone();
    assert!(!archived.has_token_api_precision_state());
    assert!(archived.terminal_token_clock_floor().is_none());
    let original_tokens = Zeroizing::new(serde_json::to_vec(&archived.tokens)?);
    let mut current = original;
    let temporary = issue_precise(&mut current, &root_token, "60s")?;
    let current_floor = current
        .terminal_token_clock_floor()
        .ok_or("actual current precision floor")?;
    assert!(current.token_api_precision_state);
    assert!(!archived.tokens.contains_key(&hash(&temporary)));
    archived.inherit_native_snapshot_clocks(&current)?;
    archived.validate_token_api_clock_floor(Some(&current))?;
    archived.validate_token_api_precision_state()?;
    assert!(archived.token_api_precision_state);
    assert_eq!(archived.terminal_token_clock_floor(), Some(current_floor));
    assert!(serde_json::to_vec(&archived.tokens)?.as_slice() == original_tokens.as_slice());
    assert!(
        archived
            .authenticate_from_observed(&temporary, AuthorityTime::Precise(current_floor), None)
            .is_err()
    );
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&archived)?)?;
    reopened.validate_system_lease_defaults()?;
    reopened.validate_token_api_precision_state()?;
    assert_eq!(reopened.terminal_token_clock_floor(), Some(current_floor));
    assert!(reopened.token_api_precision_state);
    assert!(
        reopened
            .authenticate_from_observed(&temporary, AuthorityTime::Precise(current_floor), None)
            .is_err()
    );
    Ok(())
}

#[test]
fn expired_archived_precise_lease_never_revives_after_merge_and_reopen() -> TestResult {
    let (mut archived, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    let token = issue_precise(&mut archived, &root_token, "500ms")?;
    let id = hash(&token);
    let lease = archived.tokens[&id]
        .token_api_precision
        .clone()
        .ok_or("actual archived precision lease")?;
    let original_tokens = Zeroizing::new(serde_json::to_vec(&archived.tokens)?);
    archived.authenticate_from_observed(&token, AuthorityTime::Precise(lease.issued_at), None)?;
    let expired_at = lease
        .expires_at
        .ok_or("actual archived precise expiry")?
        .checked_add(DurationNanos::checked(1)?)?;
    let mut current = archived.clone();
    assert!(current.observe_token_api_time(AuthorityTime::Precise(expired_at))?);
    // Existing precise clock ownership remains after the current record is
    // retired. A historical record must not regain authority through restore.
    current
        .tokens
        .remove(&id)
        .ok_or("current token retirement")?;
    assert!(current.token_api_precision_state);
    archived.inherit_native_snapshot_clocks(&current)?;
    archived.validate_token_api_clock_floor(Some(&current))?;
    archived.validate_token_api_precision_state()?;
    assert_eq!(archived.terminal_token_clock_floor(), Some(expired_at));
    assert_eq!(
        archived.tokens[&id].token_api_precision.as_ref(),
        Some(&lease)
    );
    assert!(serde_json::to_vec(&archived.tokens)?.as_slice() == original_tokens.as_slice());
    assert!(
        archived
            .authenticate_from_observed(&token, AuthorityTime::Precise(lease.issued_at), None)
            .is_err()
    );
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&archived)?)?;
    reopened.validate_system_lease_defaults()?;
    reopened.validate_token_api_precision_state()?;
    assert_eq!(
        reopened.tokens[&id].token_api_precision.as_ref(),
        Some(&lease)
    );
    assert_eq!(reopened.terminal_token_clock_floor(), Some(expired_at));
    assert!(
        reopened
            .authenticate_from_observed(&token, AuthorityTime::Precise(lease.issued_at), None)
            .is_err()
    );
    let before = Zeroizing::new(serde_json::to_vec(&reopened)?);
    assert!(!reopened.observe_token_api_time(AuthorityTime::Precise(lease.issued_at))?);
    assert!(serde_json::to_vec(&reopened)?.as_slice() == before.as_slice());
    let mut decreased = reopened.clone();
    decreased.token_api_observed_at = Some(lease.issued_at);
    assert!(
        decreased
            .validate_token_api_clock_floor(Some(&reopened))
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_precision_ownership_is_refused_before_any_clock_merge() -> TestResult {
    let (unmarked, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    let mut valid = unmarked.clone();
    let token = issue_precise(&mut valid, &root_token, "60s")?;
    let floor = valid
        .terminal_token_clock_floor()
        .ok_or("valid precise floor")?;
    for case in 0..5 {
        let mut incoming = valid.clone();
        let mut current = valid.clone();
        match case {
            0 => incoming.token_api_precision_state = false,
            1 => incoming.token_api_observed_at = None,
            2 => current.token_api_precision_state = false,
            3 => current.token_api_observed_at = None,
            4 => {
                incoming
                    .tokens
                    .get_mut(&hash(&token))
                    .ok_or("actual malformed lease owner")?
                    .token_api_precision
                    .as_mut()
                    .ok_or("actual malformed precision")?
                    .issued_at = floor.checked_add(DurationNanos::checked(1)?)?;
            }
            _ => unreachable!(),
        }
        let incoming_before = Zeroizing::new(serde_json::to_vec(&incoming)?);
        let current_before = Zeroizing::new(serde_json::to_vec(&current)?);
        assert!(incoming.inherit_native_snapshot_clocks(&current).is_err());
        assert!(serde_json::to_vec(&incoming)?.as_slice() == incoming_before.as_slice());
        assert!(serde_json::to_vec(&current)?.as_slice() == current_before.as_slice());
    }
    Ok(())
}

#[test]
fn public_origin_floor_survives_restore_without_current_tokens() -> TestResult {
    let (unmarked, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    assert!(unmarked.public_origin_floor.is_none());
    unmarked.validate_public_origin_state()?;
    let mut current = unmarked.clone();
    let temporary = issue_precise(&mut current, &root_token, "60s")?;
    let temporary_id = hash(&temporary);
    assert!(current.public_origin_floor == Some(crate::auth::public_origin::Floor::V1));
    let floor = current
        .terminal_token_clock_floor()
        .ok_or("actual current precision owner")?;
    for retire_temporary in [false, true] {
        let mut selected_current = current.clone();
        if retire_temporary {
            selected_current
                .tokens
                .remove(&temporary_id)
                .ok_or("actual current public-origin token")?;
        }
        selected_current.validate_public_origin_state()?;
        assert!(selected_current.has_public_origin_state());
        let current_before = Zeroizing::new(serde_json::to_vec(&selected_current)?);
        let mut incoming = unmarked.clone();
        let tokens_before = Zeroizing::new(serde_json::to_vec(&incoming.tokens)?);
        incoming.inherit_native_snapshot_clocks(&selected_current)?;
        incoming.validate_public_origin_successor(&selected_current)?;
        incoming.validate_public_origin_state()?;
        incoming.validate_token_api_precision_state()?;
        assert!(incoming.public_origin_floor == Some(crate::auth::public_origin::Floor::V1));
        assert!(serde_json::to_vec(&incoming.tokens)?.as_slice() == tokens_before.as_slice());
        assert!(serde_json::to_vec(&selected_current)?.as_slice() == current_before.as_slice());
        assert!(!incoming.tokens.contains_key(&temporary_id));
        assert!(
            incoming
                .authenticate_from_observed(&temporary, AuthorityTime::Precise(floor), None)
                .is_err()
        );
        let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&incoming)?)?;
        reopened.validate_public_origin_successor(&selected_current)?;
        reopened.validate_public_origin_state()?;
        reopened.validate_token_api_precision_state()?;
        assert!(reopened.public_origin_floor == Some(crate::auth::public_origin::Floor::V1));
        assert!(serde_json::to_vec(&reopened.tokens)?.as_slice() == tokens_before.as_slice());
        assert!(!reopened.tokens.contains_key(&temporary_id));
        assert!(
            reopened
                .authenticate_from_observed(&temporary, AuthorityTime::Precise(floor), None)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn public_origin_floor_merge_preserves_direction_without_synthesis() -> TestResult {
    let (unmarked, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    let mut marked = unmarked.clone();
    let _issued = issue_precise(&mut marked, &root_token, "60s")?;
    assert!(marked.public_origin_floor == Some(crate::auth::public_origin::Floor::V1));
    for (archived, selected_current, expected_present) in [
        (&unmarked, &unmarked, false),
        (&marked, &unmarked, true),
        (&marked, &marked, true),
    ] {
        let mut incoming = archived.clone();
        let tokens_before = Zeroizing::new(serde_json::to_vec(&incoming.tokens)?);
        let current_before = Zeroizing::new(serde_json::to_vec(selected_current)?);
        incoming.inherit_native_snapshot_clocks(selected_current)?;
        incoming.validate_public_origin_successor(selected_current)?;
        assert_eq!(incoming.public_origin_floor.is_some(), expected_present);
        assert!(serde_json::to_vec(&incoming.tokens)?.as_slice() == tokens_before.as_slice());
        assert!(serde_json::to_vec(selected_current)?.as_slice() == current_before.as_slice());
    }
    Ok(())
}

#[test]
fn malformed_public_origin_is_refused_before_any_snapshot_merge() -> TestResult {
    let (mut valid, root_token) = AuthState::bootstrap(100)?;
    let root_token = Zeroizing::new(root_token);
    let issued = issue_precise(&mut valid, &root_token, "60s")?;
    let id = hash(&issued);
    valid.validate_public_origin_state()?;
    for case in 0..4 {
        let mut incoming = valid.clone();
        let mut current = valid.clone();
        match case {
            0 => incoming.public_origin_floor = None,
            1 => current.public_origin_floor = None,
            2 | 3 => {
                let malformed = if case == 2 {
                    &mut incoming
                } else {
                    &mut current
                };
                let token = malformed
                    .tokens
                    .get_mut(&id)
                    .ok_or("actual public-origin token")?;
                let mut origin = serde_json::to_value(
                    token.public_origin.as_ref().ok_or("actual public origin")?,
                )?;
                origin["creation_path"] = json!("");
                token.public_origin = Some(serde_json::from_value(origin)?);
            }
            _ => unreachable!(),
        }
        // These malformed producer facts leave the independent precise lease
        // validator satisfied. The public-origin input check must refuse them
        // before clocks or the other side's valid floor can heal the input.
        incoming.validate_token_api_precision_state()?;
        current.validate_token_api_precision_state()?;
        assert!(if case == 0 || case == 2 {
            incoming.validate_public_origin_state().is_err()
        } else {
            current.validate_public_origin_state().is_err()
        });
        let incoming_before = Zeroizing::new(serde_json::to_vec(&incoming)?);
        let current_before = Zeroizing::new(serde_json::to_vec(&current)?);
        assert!(incoming.inherit_native_snapshot_clocks(&current).is_err());
        assert!(serde_json::to_vec(&incoming)?.as_slice() == incoming_before.as_slice());
        assert!(serde_json::to_vec(&current)?.as_slice() == current_before.as_slice());
    }
    Ok(())
}
