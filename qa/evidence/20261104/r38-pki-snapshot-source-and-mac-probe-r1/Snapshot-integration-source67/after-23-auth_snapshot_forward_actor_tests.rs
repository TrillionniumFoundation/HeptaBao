//! These are actual Auth/Principal components, not Service publication receipts.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn snapshot_actor_final_use_remains_delivery_only_without_second_admission() -> TestResult {
    let (mut auth, raw) = AuthState::bootstrap(100).map_err(|_| "bootstrap")?;
    let id = hash(&raw);
    auth.tokens.get_mut(&id).ok_or("root token")?.uses_remaining = Some(1);
    let actor = auth.authenticate(&raw, 100).map_err(|_| "one actual admission")?;
    assert_eq!(auth.tokens.get(&id).ok_or("admitted token")?.uses_remaining, Some(0));
    let witness = auth.snapshot_forward_actor(&actor, "", AuthorityTime::Coarse(100))
        .map_err(|_| "original Actor witness")?;
    let before = auth.forward_owner_projection_digest().map_err(|_| "owner before")?;
    for now in [100, 101] {
        auth.validate_snapshot_forward_actor(&witness, AuthorityTime::Coarse(now))
            .map_err(|_| "original delivery")?;
    }
    assert_eq!(before, auth.forward_owner_projection_digest().map_err(|_| "owner after")?);
    assert_eq!(auth.tokens.get(&id).ok_or("delivered token")?.uses_remaining, Some(0));
    assert!(auth.authenticate(&raw, 101).is_err());
    Ok(())
}

#[test]
fn snapshot_actor_original_auth_is_distinct_from_a_new_restored_owner() -> TestResult {
    let (auth, raw) = AuthState::bootstrap(100).map_err(|_| "original bootstrap")?;
    let actor = auth.authenticate_read_only(&raw, 100)
        .map_err(|_| "original Actor")?.ok_or("root Actor")?;
    let mut witness = auth.snapshot_forward_actor(&actor, "", AuthorityTime::Coarse(100))
        .map_err(|_| "original witness")?;
    let (restored, _) = AuthState::bootstrap(100).map_err(|_| "separate owner")?;
    assert!(restored.validate_snapshot_forward_actor(&witness, AuthorityTime::Coarse(100)).is_err());
    auth.validate_snapshot_forward_actor(&witness, AuthorityTime::Coarse(100))
        .map_err(|_| "retained original Auth")?;
    witness.namespace = "child".to_owned();
    assert!(auth.validate_snapshot_forward_actor(&witness, AuthorityTime::Coarse(100)).is_err());
    Ok(())
}
