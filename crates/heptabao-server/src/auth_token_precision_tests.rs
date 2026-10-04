use super::super::{AuthState, LeaseOwner, Principal, TokenAuthProvenance, batch, hash};
use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn timestamp(seconds: u64, nanos: u32) -> Timestamp {
    Timestamp::checked(seconds, nanos).unwrap()
}
fn span(nanos: u64) -> DurationNanos {
    DurationNanos::checked(nanos).unwrap()
}
fn setup() -> Result<(AuthState, Principal), Box<dyn std::error::Error>> {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let root = state.authenticate(&raw, 100)?;
    Ok((state, root))
}
fn service(
    state: &mut AuthState,
    root: &Principal,
    uses: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let q = state
        .handle(
            Some(root),
            "",
            "POST",
            "auth/token/create",
            &json!({"ttl":"2s","policies":["default"],"no_default_policy":true,"num_uses":uses}),
            100,
        )?
        .ok_or("route absent")?;
    Ok(q.body["auth"]["client_token"]
        .as_str()
        .ok_or("token absent")?
        .to_owned())
}
fn precise_service(state: &mut AuthState, raw: &str) {
    state.token_api_precision_state = true;
    let token = state.tokens.get_mut(&hash(raw)).unwrap();
    let granted = span(500_000_000);
    token.token_api_precision = Some(ServicePrecision {
        issued_at: timestamp(100, 200_000_000),
        expires_at: Some(timestamp(100, 700_000_000)),
        last_renewed_at: None,
        previous_grant: granted,
        creation_grant: granted,
        requested_period: span(0),
        requested_explicit_max: span(0),
    });
    token.expires_at = Some(101);
    token.token_api_lease_ttl = Some(1);
    token.auth_provenance = Some(TokenAuthProvenance::TokenApi {
        issued_creation_ttl: Some(0),
    });
}
#[test]
fn checked_types_preserve_fraction_and_reject_overflow_or_rollback() -> TestResult {
    assert_eq!(
        timestamp(100, 900_000_000).checked_add(span(250_000_000))?,
        timestamp(101, 150_000_000)
    );
    assert!(Timestamp::checked(0, 1_000_000_000).is_err());
    assert!(
        timestamp(MAX_SECONDS, 999_999_999)
            .checked_add(span(1))
            .is_err()
    );
    assert!(timestamp(MAX_SECONDS, 1).ceil_seconds().is_err());
    assert!(DurationNanos::checked(i64::MAX as u64 + 1).is_err());
    assert!(DurationNanos::from_seconds(u64::MAX).is_err());
    assert!(timestamp(0, 1).elapsed(timestamp(0, 2)).is_err());
    assert_eq!(
        timestamp(MAX_SECONDS, 0).elapsed(timestamp(MAX_SECONDS, 0))?,
        span(0)
    );
    for raw in [
        r#"{"seconds":0,"nanoseconds":1000000000}"#,
        r#"{"seconds":253402300800,"nanoseconds":0}"#,
        r#"{"seconds":0,"nanoseconds":0,"extra":true}"#,
        r#"{"seconds":-1,"nanoseconds":0}"#,
    ] {
        assert!(serde_json::from_str::<Timestamp>(raw).is_err());
    }
    Ok(())
}
#[test]
fn lookup_rounding_and_public_zero_are_not_expiry_authority() -> TestResult {
    let deadline = timestamp(101, 500_000_000);
    assert_eq!(span(500_000_000).public_seconds(), 0);
    assert_eq!(span(500_000_000).ceil_seconds(), 1);
    assert_eq!(
        deadline.lookup_remaining_seconds(timestamp(100, 490_000_000))?,
        1
    );
    assert_eq!(
        deadline.lookup_remaining_seconds(timestamp(100, 510_000_000))?,
        0
    );
    assert_eq!(deadline.truncate_seconds(), timestamp(101, 0));
    assert_eq!(
        deadline.duration_since_epoch(),
        Duration::new(101, 500_000_000)
    );
    let clock = RequestClock::anchored(Duration::new(100, 900_000_000), Instant::now())?;
    assert_eq!(clock.admitted_at(), timestamp(100, 900_000_000));
    assert!(clock.with_seconds_floor(100)?.observed_at()? >= timestamp(100, 900_000_000));
    assert!(clock.with_seconds_floor(101)?.observed_at()? >= timestamp(101, 0));
    Ok(())
}
#[test]
fn precise_service_and_every_ancestor_reject_coarse_authority_and_fractional_expiry() -> TestResult
{
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    let child = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw);
    state.tokens.get_mut(&hash(&child)).unwrap().parent = Some(hash(&raw));
    state.validate_system_lease_defaults()?;
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_system_lease_defaults()?;
    assert!(reopened.authenticate_from(&raw, 100, None).is_err());
    assert!(reopened.authenticate_from(&child, 100, None).is_err());
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000));
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000));
    let actor = reopened.authenticate_from_observed(&raw, before, None)?;
    reopened.authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", before)?;
    assert!(
        reopened
            .authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", after)
            .is_err()
    );
    assert!(
        reopened
            .authenticate_from_observed(&child, before, None)
            .is_ok()
    );
    assert!(
        reopened
            .authenticate_from_observed(&child, after, None)
            .is_err()
    );
    let owner = LeaseOwner::service(&hash(&child))?;
    let cap = reopened
        .resolve_lease_owner_observed(&owner, "", before)
        .ok_or("precise owner absent")?;
    assert_eq!(cap.precise_expires_at, Some(timestamp(100, 700_000_000)));
    assert!(reopened.resolve_lease_owner(&owner, "", 100).is_none());
    assert!(
        reopened
            .resolve_lease_owner_observed(&owner, "", after)
            .is_none()
    );
    // Loading ceil-projected state cannot replace ownership validation.
    reopened.tokens.get_mut(&hash(&raw)).unwrap().expires_at = Some(102);
    assert!(reopened.validate_system_lease_defaults().is_err());
    Ok(())
}
#[test]
fn precise_last_use_keeps_one_affine_request_without_a_second_bearer_admission() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 1)?;
    precise_service(&mut state, &raw);
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000));
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000));
    assert!(
        state
            .authenticate_read_only_from_observed(&raw, before, None)?
            .is_none()
    );
    let actor = state.authenticate_from_observed(&raw, before, None)?;
    assert!(
        state
            .authenticate_from_observed(&raw, before, None)
            .is_err()
    );
    state.authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", before)?;
    assert!(
        state
            .authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", after)
            .is_err()
    );
    assert!(
        state
            .resolve_lease_owner_observed(&LeaseOwner::service(&hash(&raw))?, "", before)
            .is_none()
    );
    Ok(())
}
#[test]
fn precise_batch_and_persisted_owner_are_authenticated_with_whole_creation_anchor() -> TestResult {
    let (mut state, _) = setup()?;
    let mut keys = batch::BatchKeyAuthority::new(100)?;
    let precision = BatchPrecision {
        granted_ttl: span(500_000_000),
        expires_at: timestamp(100, 500_000_000),
    };
    assert!(precision.validate(100, 101).is_ok());
    let wrong = BatchPrecision {
        expires_at: timestamp(100, 900_000_000),
        ..precision.clone()
    };
    assert!(wrong.validate(100, 101).is_err());
    let token = keys.seal(
        batch::BatchClaims {
            token_api_precision: Some(precision),
            token_role: None,
            token_api_policy_names: true,
            namespace: String::new(),
            policies: BTreeSet::from(["default".into()]),
            metadata: BTreeMap::new(),
            display_name: "token".into(),
            path: "auth/token/create-orphan".into(),
            bound_cidrs: Vec::new(),
            issued_at: 100,
            expires_at: 101,
            parent: None,
            entity_id: None,
        },
        100,
    )?;
    state.batch_authority = Some(keys);
    state.token_api_precision_state = true;
    let before = AuthorityTime::Precise(timestamp(100, 350_000_000));
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000));
    assert!(state.authenticate_from(token.as_str(), 100, None).is_err());
    let actor = state.authenticate_from_observed(token.as_str(), before, None)?;
    state.authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", before)?;
    assert!(
        state
            .authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", after)
            .is_err()
    );
    let super::super::batch_principal::VerifiedCredential::Batch(claims) = &actor.credential else {
        return Err("batch authority absent".into());
    };
    let owner = LeaseOwner::from_batch(claims);
    let decoded: LeaseOwner = serde_json::from_slice(&serde_json::to_vec(&owner)?)?;
    let cap = state
        .resolve_lease_owner_observed(&decoded, "", before)
        .ok_or("batch owner absent")?;
    assert_eq!(cap.precise_expires_at, Some(timestamp(100, 500_000_000)));
    assert!(state.resolve_lease_owner(&decoded, "", 100).is_none());
    assert!(
        state
            .resolve_lease_owner_observed(&decoded, "", after)
            .is_none()
    );
    let mut bad = serde_json::to_value(&decoded)?;
    bad["token_api_precision"]["expires_at"]["nanoseconds"] = json!(900_000_000);
    assert!(serde_json::from_value::<LeaseOwner>(bad).is_err());
    Ok(())
}

#[test]
fn precise_token_routes_preserve_public_fraction_and_recheck_target_deadline() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw);
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000));
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000));
    let actor = state.authenticate_from_observed(&raw, before, None)?;
    let lookup = state.token_route_observed(
        Some(&actor),
        "",
        "GET",
        "auth/token/lookup-self",
        &json!({}),
        before,
        None,
    )?;
    assert_eq!(lookup.body["data"]["issue_time"], "1970-01-01T00:01:40.2Z");
    assert_eq!(lookup.body["data"]["expire_time"], "1970-01-01T00:01:40.7Z");
    assert_eq!(lookup.body["data"]["creation_ttl"], 0);
    assert_eq!(lookup.body["data"]["ttl"], 0);
    assert!(
        state
            .token_route_observed(
                Some(&actor),
                "",
                "GET",
                "auth/token/lookup-self",
                &json!({}),
                after,
                None
            )
            .is_err()
    );
    let body = json!({"token":raw});
    assert!(
        state
            .token_route_observed(
                Some(&root),
                "",
                "POST",
                "auth/token/lookup",
                &body,
                before,
                None
            )
            .is_ok()
    );
    let expired = state
        .token_route_observed(
            Some(&root),
            "",
            "POST",
            "auth/token/renew",
            &body,
            after,
            None,
        )
        .err()
        .ok_or("expired renewed")?;
    assert_eq!(
        (expired.status, expired.message.as_str()),
        (400, "token not found")
    );
    let absent = state
        .token_route_observed(
            Some(&root),
            "",
            "POST",
            "auth/token/renew",
            &json!({"token":"hvs.unknown"}),
            after,
            None,
        )
        .err()
        .ok_or("unknown renewed")?;
    assert_eq!(absent.status, 403);
    let accessor = state.tokens[&hash(&raw)].accessor.clone();
    let by_accessor = state.token_route_observed(
        Some(&root),
        "",
        "POST",
        "auth/token/lookup-accessor",
        &json!({"accessor":accessor}),
        before,
        None,
    )?;
    assert_eq!(
        by_accessor.body["data"]["expire_time"],
        "1970-01-01T00:01:40.7Z"
    );
    assert!(
        state
            .token_route(
                Some(&root),
                "",
                "POST",
                "auth/token/lookup",
                &body,
                100,
                None
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn precise_public_clock_serializes_checked_fraction_without_changing_authority() -> TestResult {
    assert_eq!(timestamp(0, 1).rfc3339(), "1970-01-01T00:00:00.000000001Z");
    assert_eq!(timestamp(0, 0).rfc3339(), "1970-01-01T00:00:00Z");
    assert_eq!(
        timestamp(MAX_SECONDS, 999_999_999).rfc3339(),
        "9999-12-31T23:59:59.999999999Z"
    );
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw);
    let token = state.tokens.get_mut(&hash(&raw)).ok_or("token absent")?;
    let lease = token
        .token_api_precision
        .as_mut()
        .ok_or("precision absent")?;
    lease.last_renewed_at = Some(timestamp(100, 300_000_000));
    lease.expires_at = Some(timestamp(100, 800_000_000));
    state.validate_system_lease_defaults()?;
    let lookup = super::super::token_info_observed(
        &state.tokens[&hash(&raw)],
        AuthorityTime::Precise(timestamp(100, 600_000_000)),
    )?;
    assert_eq!(lookup["last_renewal"], 100);
    assert_eq!(lookup["last_renewal_time"], "1970-01-01T00:01:40.3Z");
    assert_eq!(lookup["expire_time"], "1970-01-01T00:01:40.8Z");
    assert!(
        super::super::token_info_observed(&state.tokens[&hash(&raw)], AuthorityTime::Coarse(100))
            .is_err()
    );
    Ok(())
}
