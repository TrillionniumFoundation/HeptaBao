use super::super::{AuthState, LeaseOwner, Principal, TokenAuthProvenance, batch, hash};
use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn timestamp(seconds: u64, nanos: u32) -> Result<Timestamp, PrecisionError> {
    Timestamp::checked(seconds, nanos)
}
fn span(nanos: u64) -> Result<DurationNanos, PrecisionError> {
    DurationNanos::checked(nanos)
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
            &json!({"ttl":"2s","policies":["default"],"no_default_policy":false,"num_uses":uses}),
            100,
        )?
        .ok_or("route absent")?;
    Ok(q.body["auth"]["client_token"]
        .as_str()
        .ok_or("token absent")?
        .to_owned())
}
fn precise_service(state: &mut AuthState, raw: &str) -> TestResult {
    state.token_api_precision_state = true;
    state.token_api_observed_at = Some(timestamp(100, 200_000_000)?);
    let token = state
        .tokens
        .get_mut(&hash(raw))
        .ok_or("issued service token absent")?;
    let granted = span(500_000_000)?;
    token.token_api_precision = Some(ServicePrecision {
        issued_at: timestamp(100, 200_000_000)?,
        grant_started_at: timestamp(100, 200_000_000)?,
        expires_at: Some(timestamp(100, 700_000_000)?),
        last_renewed_at: None,
        previous_grant: granted,
        creation_grant: granted,
        requested_period: span(0)?,
        requested_explicit_max: span(0)?,
    });
    token.expires_at = Some(101);
    token.token_api_lease_ttl = Some(1);
    token.auth_provenance = Some(TokenAuthProvenance::TokenApi {
        issued_creation_ttl: Some(0),
    });
    Ok(())
}

#[test]
fn affine_original_clock_keeps_exact_authority_in_legacy_helpers_and_target_inspection()
-> TestResult {
    let (mut state, mut root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let mut actor = state.authenticate_from_observed(
        &raw,
        AuthorityTime::Precise(clock.observed_at()?),
        None,
    )?;
    actor.bind_request_clock(Some(clock))?;
    root.bind_request_clock(Some(clock))?;
    state.permission(Some(&actor), "", "auth/token/lookup-self", "read", 100)?;
    state.inspection_target(&actor, "", "sys/capabilities-self", &json!({}), 100)?;
    state.inspection_target(&root, "", "sys/capabilities", &json!({"token":raw}), 100)?;
    let owner = state.typed_lease_issuer(&actor, "", 100)?;
    assert_eq!(owner.precise_expires_at, Some(timestamp(100, 700_000_000)?));
    let mut metadata = state.authenticate_mount_metadata_from_observed(
        &raw,
        AuthorityTime::Precise(clock.observed_at()?),
        None,
    )?;
    metadata.bind_request_clock(Some(clock))?;
    assert!(
        state
            .ui_mount_visible(&metadata, "", "secret/", 100)
            .is_ok()
    );
    assert!(
        state
            .authorize_request(&metadata, "", "secret/value", "read", 100)
            .is_err(),
        "metadata admission never becomes an operation capability"
    );
    Ok(())
}

#[test]
fn affine_original_clock_reobserves_expiry_and_cannot_be_replaced_after_admission() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let mut actor = state.authenticate_from_observed(
        &raw,
        AuthorityTime::Precise(timestamp(100, 200_000_000)?),
        None,
    )?;
    // A dispatcher stalled after authentication must still observe elapsed
    // time from its original ingress anchor at every later helper.
    let original = RequestClock::anchored(
        Duration::new(100, 200_000_000),
        Instant::now() - Duration::from_secs(1),
    )?;
    actor.bind_request_clock(Some(original))?;
    let replacement = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    assert!(actor.bind_request_clock(Some(replacement)).is_err());
    assert!(actor.bind_request_clock(None).is_err());
    let before = serde_json::to_vec(&state)?;
    for time in [
        AuthorityTime::Coarse(100),
        AuthorityTime::Precise(timestamp(100, 200_000_000)?),
    ] {
        assert!(state.check_principal_observed(&actor, "", time).is_err());
    }
    assert!(state.typed_lease_issuer(&actor, "", 100).is_err());
    assert_eq!(serde_json::to_vec(&state)?, before);
    Ok(())
}

#[test]
fn affine_clock_does_not_upgrade_unbound_coarse_callers_or_roll_back_durable_floor() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let mut actor = state.authenticate_from_observed(
        &raw,
        AuthorityTime::Precise(timestamp(100, 200_000_000)?),
        None,
    )?;
    assert!(state.check_principal(&actor, "", 100).is_err());
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    actor.bind_request_clock(Some(clock))?;
    assert!(state.check_principal(&actor, "", 100).is_ok());
    state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 800_000_000)?))?;
    let before = serde_json::to_vec(&state)?;
    assert!(state.check_principal(&actor, "", 100).is_err());
    assert_eq!(serde_json::to_vec(&state)?, before);
    Ok(())
}

#[test]
fn checked_types_preserve_fraction_and_reject_overflow_or_rollback() -> TestResult {
    assert_eq!(
        timestamp(100, 900_000_000)?.checked_add(span(250_000_000)?)?,
        timestamp(101, 150_000_000)?
    );
    assert!(Timestamp::checked(0, 1_000_000_000).is_err());
    assert!(
        timestamp(MAX_SECONDS, 999_999_999)?
            .checked_add(span(1)?)
            .is_err()
    );
    assert!(timestamp(MAX_SECONDS, 1)?.ceil_seconds().is_err());
    assert!(DurationNanos::checked(i64::MAX as u64 + 1).is_err());
    assert!(DurationNanos::from_seconds(u64::MAX).is_err());
    assert!(timestamp(0, 1)?.elapsed(timestamp(0, 2)?).is_err());
    assert_eq!(
        timestamp(MAX_SECONDS, 0)?.elapsed(timestamp(MAX_SECONDS, 0)?)?,
        span(0)?
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
    let deadline = timestamp(101, 500_000_000)?;
    assert_eq!(span(500_000_000)?.public_seconds(), 0);
    assert_eq!(span(500_000_000)?.ceil_seconds(), 1);
    assert_eq!(
        deadline.lookup_remaining_seconds(timestamp(100, 490_000_000)?)?,
        1
    );
    assert_eq!(
        deadline.lookup_remaining_seconds(timestamp(100, 510_000_000)?)?,
        0
    );
    assert_eq!(deadline.truncate_seconds(), timestamp(101, 0)?);
    assert_eq!(
        deadline.duration_since_epoch(),
        Duration::new(101, 500_000_000)
    );
    let clock = RequestClock::anchored(Duration::new(100, 900_000_000), Instant::now())?;
    assert_eq!(clock.admitted_at(), timestamp(100, 900_000_000)?);
    assert!(clock.with_seconds_floor(100)?.observed_at()? >= timestamp(100, 900_000_000)?);
    assert!(clock.with_seconds_floor(101)?.observed_at()? >= timestamp(101, 0)?);
    Ok(())
}
#[test]
fn precise_service_and_every_ancestor_reject_coarse_authority_and_fractional_expiry() -> TestResult
{
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    let child = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    state
        .tokens
        .get_mut(&hash(&child))
        .ok_or("issued child token absent")?
        .parent = Some(hash(&raw));
    state.validate_system_lease_defaults()?;
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_system_lease_defaults()?;
    assert!(reopened.authenticate_from(&raw, 100, None).is_err());
    assert!(reopened.authenticate_from(&child, 100, None).is_err());
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000)?);
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000)?);
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
    assert_eq!(cap.precise_expires_at, Some(timestamp(100, 700_000_000)?));
    assert!(reopened.resolve_lease_owner(&owner, "", 100).is_none());
    assert!(
        reopened
            .resolve_lease_owner_observed(&owner, "", after)
            .is_none()
    );
    // Loading ceil-projected state cannot replace ownership validation.
    reopened
        .tokens
        .get_mut(&hash(&raw))
        .ok_or("reopened token absent")?
        .expires_at = Some(102);
    assert!(reopened.validate_system_lease_defaults().is_err());
    Ok(())
}
#[test]
fn precise_last_use_keeps_one_affine_request_without_a_second_bearer_admission() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 1)?;
    precise_service(&mut state, &raw)?;
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000)?);
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000)?);
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
        granted_ttl: span(500_000_000)?,
        expires_at: timestamp(100, 500_000_000)?,
    };
    assert!(precision.validate(100, 101).is_ok());
    let wrong = BatchPrecision {
        expires_at: timestamp(100, 900_000_000)?,
        ..precision.clone()
    };
    assert!(wrong.validate(100, 101).is_err());
    let token = keys.seal(
        batch::BatchClaims {
            token_api_precision: Some(precision),
            token_role: None,
            token_api_policy_names: true,
            public_origin: None,
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
    state.token_api_observed_at = Some(timestamp(100, 200_000_000)?);
    let before = AuthorityTime::Precise(timestamp(100, 350_000_000)?);
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000)?);
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
    assert_eq!(cap.precise_expires_at, Some(timestamp(100, 500_000_000)?));
    assert!(state.resolve_lease_owner(&decoded, "", 100).is_none());
    assert!(
        state
            .resolve_lease_owner_observed(&decoded, "", after)
            .is_none()
    );
    let mut bad = serde_json::to_value(&decoded)?;
    bad["token_api_precision"]["expires_at"]["nanoseconds"] = json!(900_000_000);
    assert!(serde_json::from_value::<LeaseOwner>(bad).is_err());
    // The trusted observed expiry survives Auth-owner persistence. Replaying
    // the earlier exact wall time cannot restore the opaque token or its owner.
    state.observe_token_api_time(after)?;
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_system_lease_defaults()?;
    assert!(
        reopened
            .authenticate_from_observed(token.as_str(), before, None)
            .is_err()
    );
    assert!(
        reopened
            .authorize_request_observed(&actor, "", "auth/token/lookup-self", "read", before)
            .is_err()
    );
    assert!(
        reopened
            .resolve_lease_owner_observed(&decoded, "", before)
            .is_none()
    );
    Ok(())
}

#[test]
fn precise_token_routes_preserve_public_fraction_and_recheck_target_deadline() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let before = AuthorityTime::Precise(timestamp(100, 600_000_000)?);
    let after = AuthorityTime::Precise(timestamp(100, 800_000_000)?);
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
    assert_eq!(timestamp(0, 1)?.rfc3339(), "1970-01-01T00:00:00.000000001Z");
    assert_eq!(timestamp(0, 0)?.rfc3339(), "1970-01-01T00:00:00Z");
    assert_eq!(
        timestamp(MAX_SECONDS, 999_999_999)?.rfc3339(),
        "9999-12-31T23:59:59.999999999Z"
    );
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let token = state.tokens.get_mut(&hash(&raw)).ok_or("token absent")?;
    let lease = token
        .token_api_precision
        .as_mut()
        .ok_or("precision absent")?;
    lease.grant_started_at = timestamp(100, 300_000_000)?;
    lease.last_renewed_at = Some(timestamp(100, 300_000_000)?);
    lease.expires_at = Some(timestamp(100, 800_000_000)?);
    state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 300_000_000)?))?;
    state.validate_system_lease_defaults()?;
    let lookup = super::super::token_info_observed(
        &state.tokens[&hash(&raw)],
        AuthorityTime::Precise(timestamp(100, 600_000_000)?),
    )?;
    assert_eq!(lookup["last_renewal_time"], 100);
    assert_eq!(lookup["last_renewal"], "1970-01-01T00:01:40.3Z");
    assert_eq!(lookup["expire_time"], "1970-01-01T00:01:40.8Z");
    assert!(
        super::super::token_info_observed(&state.tokens[&hash(&raw)], AuthorityTime::Coarse(100))
            .is_err()
    );
    Ok(())
}

#[test]
fn registration_clock_cannot_move_an_already_computed_precise_deadline() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let token = state.tokens.get_mut(&hash(&raw)).ok_or("token absent")?;
    let lease = token
        .token_api_precision
        .as_mut()
        .ok_or("precision absent")?;
    lease.issued_at = timestamp(100, 200_040_000)?;
    state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 200_040_000)?))?;
    state.validate_system_lease_defaults()?;
    assert!(
        state
            .authenticate_from_observed(
                &raw,
                AuthorityTime::Precise(timestamp(100, 700_010_000)?),
                None
            )
            .is_err()
    );
    let token = state.tokens.get_mut(&hash(&raw)).ok_or("token absent")?;
    let lease = token
        .token_api_precision
        .as_mut()
        .ok_or("precision absent")?;
    // A later public registration clock does not add time to an owned grant.
    lease.grant_started_at = timestamp(100, 300_000_000)?;
    lease.last_renewed_at = Some(timestamp(100, 300_020_000)?);
    lease.expires_at = Some(timestamp(100, 800_000_000)?);
    state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 300_020_000)?))?;
    state.validate_system_lease_defaults()?;
    assert!(
        state
            .authenticate_from_observed(
                &raw,
                AuthorityTime::Precise(timestamp(100, 800_010_000)?),
                None
            )
            .is_err()
    );
    Ok(())
}

fn prepared<'a>(
    state: &AuthState,
    root: &'a Principal,
    batch: bool,
) -> Result<super::super::token_precise_issuance::PreparedCreation<'a>, Box<dyn std::error::Error>>
{
    Ok(super::super::token_precise_issuance::PreparedCreation {
        actor: root,
        namespace: "",
        request_path: "auth/token/create",
        creation_seconds: 100,
        parent: state.check_principal(root, "", 100)?.service()?.clone(),
        policies: BTreeSet::from(["default".into()]),
        role: None,
        issued_role: None,
        root: false,
        batch,
        no_parent: false,
        entity_alias: None,
        creation_path: "auth/token/create".into(),
        metadata: super::super::public_origin::MetadataInput::Absent,
        requested_renewable: true,
        is_sudo: true,
        requested_no_parent: false,
    })
}
#[test]
fn staged_precise_creation_and_renewal_keep_zero_public_grant_with_live_private_deadline()
-> TestResult {
    let (mut state, root) = setup()?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let recipe = prepared(&state, &root, false)?;
    let issued = state.finish_precise_token_creation(recipe, &json!({"ttl":"500ms"}), clock)?;
    assert_eq!(issued.body["auth"]["lease_duration"], 0);
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token absent")?;
    let digest = hash(raw);
    state.validate_system_lease_defaults()?;
    let first = state.tokens[&digest]
        .token_api_precision
        .clone()
        .ok_or("lease absent")?;
    assert_eq!(first.previous_grant, span(500_000_000)?);
    assert_eq!(
        first
            .expires_at
            .ok_or("deadline absent")?
            .elapsed(first.grant_started_at)?,
        span(500_000_000)?
    );
    assert!(first.issued_at >= first.grant_started_at);
    assert!(state.authenticate_from(raw, 100, None).is_err());
    let clock = RequestClock::anchored(Duration::new(100, 300_000_000), Instant::now())?;
    let renewal = state
        .renew_precise_token_api_token(&root, "", "auth/token/renew", &digest, &json!({}), clock)?
        .ok_or("renew absent")?;
    assert_eq!(renewal.body["auth"]["lease_duration"], 0);
    state.validate_system_lease_defaults()?;
    let renewed = state.tokens[&digest]
        .token_api_precision
        .as_ref()
        .ok_or("renew precision absent")?;
    assert_eq!(renewed.creation_grant, first.creation_grant);
    assert_eq!(renewed.issued_at, first.issued_at);
    assert_eq!(renewed.previous_grant, span(500_000_000)?);
    assert_eq!(
        renewed
            .expires_at
            .ok_or("renew deadline absent")?
            .elapsed(renewed.grant_started_at)?,
        span(500_000_000)?
    );
    assert!(
        renewed
            .last_renewed_at
            .is_some_and(|at| at >= renewed.grant_started_at)
    );
    assert!(
        state
            .authenticate_from_observed(
                raw,
                AuthorityTime::Precise(timestamp(100, 900_000_000)?),
                None
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn staged_precise_batch_sealing_preserves_authenticated_whole_creation_anchor() -> TestResult {
    let (mut state, root) = setup()?;
    let recipe = prepared(&state, &root, true)?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let mut issued = state.finish_precise_token_creation(recipe, &json!({"ttl":"500ms"}), clock)?;
    assert_eq!(issued.body["auth"]["lease_duration"], 0);
    state.finish_pending_batch_observed(
        &mut issued,
        "",
        100,
        AuthorityTime::Precise(timestamp(100, 400_000_000)?),
    )?;
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("batch absent")?;
    state.authenticate_from_observed(
        raw,
        AuthorityTime::Precise(timestamp(100, 400_000_000)?),
        None,
    )?;
    assert!(
        state
            .authenticate_from_observed(
                raw,
                AuthorityTime::Precise(timestamp(100, 600_000_000)?),
                None
            )
            .is_err()
    );
    assert!(state.authenticate_from(raw, 100, None).is_err());
    state.validate_system_lease_defaults()?;
    Ok(())
}
#[test]
fn coarse_maintenance_never_retires_precision_from_closed_clock_authority() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let before = serde_json::to_vec(&state)?;
    let error = state
        .token_route(
            Some(&root),
            "",
            "POST",
            "auth/token/tidy",
            &json!({}),
            100,
            None,
        )
        .err()
        .ok_or("coarse tidy accepted")?;
    assert_eq!(error.status, 503);
    assert_eq!(serde_json::to_vec(&state)?, before);
    let expired = AuthorityTime::Precise(timestamp(100, 800_000_000)?);
    let tidy = state.token_route_observed(
        Some(&root),
        "",
        "POST",
        "auth/token/tidy",
        &json!({}),
        expired,
        None,
    )?;
    assert_eq!(tidy.body["data"]["removed_tokens"], 1);
    assert!(!state.tokens.contains_key(&hash(&raw)));
    assert!(state.has_token_api_precision_state());
    Ok(())
}

#[test]
fn newly_created_expired_precise_batch_can_be_delivered_but_never_admitted() -> TestResult {
    let (mut state, root) = setup()?;
    let recipe = prepared(&state, &root, true)?;
    let clock = RequestClock::anchored(Duration::new(100, 800_000_000), Instant::now())?;
    let mut issued = state.finish_precise_token_creation(recipe, &json!({"ttl":"1ns"}), clock)?;
    state.finish_pending_batch_observed(
        &mut issued,
        "",
        100,
        AuthorityTime::Precise(timestamp(100, 900_000_000)?),
    )?;
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["auth"]["lease_duration"], 0);
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("opaque token absent")?;
    assert!(
        state
            .authenticate_from_observed(
                raw,
                AuthorityTime::Precise(timestamp(100, 900_000_000)?),
                None
            )
            .is_err()
    );
    assert!(state.authenticate_from(raw, 100, None).is_err());
    state.validate_system_lease_defaults()?;
    Ok(())
}
#[test]
fn expired_precise_orphan_cannot_bypass_its_publication_actor_deadline() -> TestResult {
    let (mut state, raw) = AuthState::bootstrap(100)?;
    let actor = state.authenticate(&raw, 100)?;
    let mut recipe = prepared(&state, &actor, true)?;
    recipe.no_parent = true;
    precise_service(&mut state, &raw)?;
    let clock = RequestClock::anchored(Duration::new(100, 300_000_000), Instant::now())?;
    let mut issued = state.finish_precise_token_creation(recipe, &json!({"ttl":"1ns"}), clock)?;
    let before = serde_json::to_vec(&state)?;
    assert!(
        state
            .finish_pending_batch_observed(
                &mut issued,
                "",
                100,
                AuthorityTime::Precise(timestamp(100, 800_000_000)?)
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    assert!(issued.body["auth"].get("client_token").is_none());
    Ok(())
}
#[test]
fn coarse_publication_cannot_seal_precise_batch_or_reanchor_its_creation() -> TestResult {
    let (mut state, root) = setup()?;
    let recipe = prepared(&state, &root, true)?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let mut issued = state.finish_precise_token_creation(recipe, &json!({"ttl":"500ms"}), clock)?;
    let before = serde_json::to_vec(&state)?;
    assert!(state.finish_pending_batch(&mut issued, "", 100).is_err());
    assert_eq!(serde_json::to_vec(&state)?, before);
    assert!(issued.body["auth"].get("client_token").is_none());
    Ok(())
}

#[test]
fn private_observation_floor_survives_reopen_and_prevents_same_second_token_revival() -> TestResult
{
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    state.authenticate_from_observed(
        &raw,
        AuthorityTime::Precise(timestamp(100, 600_000_000)?),
        None,
    )?;
    assert!(state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 800_000_000)?))?);
    assert!(
        state
            .authenticate_from_observed(
                &raw,
                AuthorityTime::Precise(timestamp(100, 600_000_000)?),
                None
            )
            .is_err()
    );
    let mut reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    reopened.validate_system_lease_defaults()?;
    assert!(
        reopened
            .authenticate_from_observed(
                &raw,
                AuthorityTime::Precise(timestamp(100, 600_000_000)?),
                None
            )
            .is_err()
    );
    let before = serde_json::to_vec(&reopened)?;
    assert!(
        !reopened.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 300_000_000)?))?
    );
    assert_eq!(serde_json::to_vec(&reopened)?, before);
    assert!(
        reopened
            .observe_token_api_time(AuthorityTime::Coarse(101))
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&reopened)?, before);
    Ok(())
}
#[test]
fn precise_floor_retirement_and_snapshot_publication_cannot_remove_or_lower_it() -> TestResult {
    let (mut state, root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    state.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 800_000_000)?))?;
    state.tokens.remove(&hash(&raw));
    assert!(state.has_token_api_precision_state());
    state.validate_system_lease_defaults()?;
    let same: AuthState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    same.validate_token_api_clock_floor(Some(&state))?;
    let mut lower = same.clone();
    lower.token_api_observed_at = Some(timestamp(100, 700_000_000)?);
    assert!(lower.validate_token_api_clock_floor(Some(&state)).is_err());
    lower.token_api_observed_at = None;
    lower.token_api_precision_state = false;
    assert!(lower.validate_token_api_clock_floor(Some(&state)).is_err());
    let mut higher = same.clone();
    higher.observe_token_api_time(AuthorityTime::Precise(timestamp(100, 900_000_000)?))?;
    higher.validate_token_api_clock_floor(Some(&state))?;
    Ok(())
}
#[test]
fn request_floor_does_not_add_elapsed_again_or_move_the_monotonic_deadline_origin() -> TestResult {
    let started = Instant::now()
        .checked_sub(Duration::from_millis(250))
        .ok_or("instant")?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), started)?;
    let floor = timestamp(1000, 800_000_000)?;
    let normalized = clock.with_timestamp_floor(floor);
    assert_eq!(normalized.started(), started);
    assert_eq!(normalized.admitted_at(), floor);
    assert_eq!(normalized.observed_at()?, floor);
    assert_eq!(normalized.with_seconds_floor(999)?.observed_at()?, floor);
    let mut state = setup()?.0;
    state.token_api_precision_state = true;
    state.token_api_observed_at = Some(floor);
    assert_eq!(state.token_api_request_clock(clock).observed_at()?, floor);
    Ok(())
}
#[test]
fn precise_observation_floor_is_bounded_and_cannot_be_forged_through_creation_body() -> TestResult {
    let (mut state, root) = setup()?;
    let recipe = prepared(&state, &root, false)?;
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    let issued = state.finish_precise_token_creation(recipe,
        &json!({"ttl":"500ms", "token_api_observed_at":{"seconds":253402300799_u64,"nanoseconds":999999999}}), clock)?;
    assert_eq!(issued.body["auth"]["lease_duration"], 0);
    assert_eq!(
        state.token_api_observed_at.ok_or("floor absent")?.seconds(),
        100
    );
    state.validate_system_lease_defaults()?;
    let base = serde_json::to_value(&state)?;
    for bad in [
        json!({"seconds":100,"nanoseconds":1000000000}),
        json!({"seconds":253402300800_u64,"nanoseconds":0}),
        json!("future"),
        json!(-1),
    ] {
        let mut malformed = base.clone();
        malformed["token_api_observed_at"] = bad;
        assert!(serde_json::from_value::<AuthState>(malformed).is_err());
    }
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .ok_or("auth object")?
        .remove("token_api_observed_at");
    let missing: AuthState = serde_json::from_value(missing)?;
    assert!(missing.validate_token_api_precision_state().is_err());
    Ok(())
}

#[test]
fn original_actor_clock_drives_plain_target_lookup_and_provider_delivery_gate() -> TestResult {
    let (mut state, root_raw) = AuthState::bootstrap(100)?;
    let mut root = state.authenticate(&root_raw, 100)?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let accessor = state
        .tokens
        .get(&hash(&raw))
        .ok_or("target absent")?
        .accessor
        .clone();
    let clock = RequestClock::anchored(Duration::new(100, 200_000_000), Instant::now())?;
    root.bind_request_clock(Some(clock))?;
    // These explicit legacy argument projections must use the bound actual
    // ingress clock, rather than claim that integer 100 is precise authority.
    for (path, body) in [
        ("auth/token/lookup", json!({"token":raw})),
        ("auth/token/lookup-accessor", json!({"accessor":accessor})),
    ] {
        let response = state
            .handle(Some(&root), "", "POST", path, &body, 100)?
            .ok_or("lookup route absent")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["ttl"], 0);
    }
    state.validate_provider_renewal_delivery(&root, "", "auth/token/renew", &hash(&raw), 100)?;
    let unbound_root = state.authenticate(&root_raw, 100)?;
    assert!(
        state
            .validate_provider_renewal_delivery(
                &unbound_root,
                "",
                "auth/token/renew",
                &hash(&raw),
                100
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn original_actor_clock_rejects_expired_target_and_keeps_wrapping_whole_owner() -> TestResult {
    let (mut state, mut root) = setup()?;
    let raw = service(&mut state, &root, 0)?;
    precise_service(&mut state, &raw)?;
    let wrapped = state.wrap_response(
        "",
        "sys/wrapping/wrap",
        2,
        &json!({"data":{"marker":"actual-owner"}}),
        100,
    )?;
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let clock = RequestClock::anchored(
        Duration::new(100, 200_000_000),
        Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("old anchor")?,
    )?;
    root.bind_request_clock(Some(clock))?;
    let before = serde_json::to_vec(&state)?;
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/token/lookup",
                &json!({"token":raw}),
                100
            )
            .is_err()
    );
    assert!(
        state
            .validate_provider_renewal_delivery(&root, "", "auth/token/renew", &hash(&raw), 100)
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&state)?, before);
    let response = state.wrapping_route(
        Some(&root),
        "",
        "PUT",
        "sys/wrapping/unwrap",
        &json!({"token":wrapper}),
        100,
    )?;
    assert_eq!(response.body["data"]["marker"], "actual-owner");
    assert!(
        state
            .lookup_wrapping_request(&wrapper, "", "POST", &json!({}), 101)
            .is_err()
    );
    Ok(())
}
