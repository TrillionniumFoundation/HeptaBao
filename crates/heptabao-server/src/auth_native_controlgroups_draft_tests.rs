//! Auth leaf controls, not HTTP/native publication or identity/quorum evidence.
use super::*;
use control_groups::{ResolvedFactor, ResourceBinding};
use std::time::{Duration, Instant};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    auth: AuthState,
    requester: Zeroizing<String>,
    reviewer: Zeroizing<String>,
}

fn clock(seconds: u64) -> Result<RequestClock, token_precision::PrecisionError> {
    RequestClock::anchored(Duration::from_secs(seconds), Instant::now())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    let root = Zeroizing::new(root);
    let requester = Zeroizing::new("hvs.synthetic-draft-requester".to_owned());
    let reviewer = Zeroizing::new("hvs.synthetic-draft-reviewer".to_owned());
    // Synthetic stored credential records are fixture input. Principals below
    // are produced only by the real authenticate_from_observed dispatcher.
    let template = auth.tokens.get(&hash(&root)).ok_or("root")?.clone();
    for (raw, entity, policy) in [
        (requester.as_str(), "entity-requester", "controlled"),
        (reviewer.as_str(), "entity-reviewer", "reviewer"),
    ] {
        let mut token = template.clone();
        token.root = false;
        token.entity_id = Some(entity.into());
        token.accessor = format!("a.{entity}");
        token.policies = BTreeSet::from([policy.into()]);
        token.expires_at = Some(500);
        token.max_expires_at = Some(500);
        auth.store_token(hash(raw), token);
    }
    let policy = parse_policy(&json!(
        r#"path "secret/data/key" {
      capabilities=["create","update","read"] control_group={ttl="60s"
      factor "ops" {identity {group_ids=["group-ops"] approvals=1 self_authorization=false}}}}
    "#
    ))?;
    auth.observe_control_group_policy(&policy);
    auth.policies
        .entry("".into())
        .or_default()
        .insert("controlled".into(), policy);
    auth.policies.entry("".into()).or_default().insert(
        "reviewer".into(),
        parse_policy(&json!(
            r#"path "sys/control-group/*" { capabilities=["update"] }"#
        ))?,
    );
    auth.validate_control_group_state()?;
    Ok(Fixture {
        auth,
        requester,
        reviewer,
    })
}

fn actor(auth: &mut AuthState, raw: &str, clock: RequestClock) -> Result<Principal, AuthError> {
    let mut actor =
        auth.authenticate_from_observed(raw, NativeCgAuthDelta::original_time(clock)?, None)?;
    actor.bind_request_clock(Some(clock))?;
    actor.bind_identity_policies(BTreeSet::new());
    Ok(actor)
}

fn owner(auth: &AuthState, requester: &Principal) -> Result<DeferredRequest, AuthError> {
    let (actor_digest, actor_accessor, actor_entity_id) =
        auth.control_group_actor_binding(requester)?;
    Ok(DeferredRequest {
        cluster_id: "synthetic-native-cg-cluster".into(),
        namespace: String::new(),
        namespace_id: "root".into(),
        namespace_incarnation: 0,
        resource_binding: ResourceBinding::System,
        actor_digest,
        actor_accessor,
        actor_entity_id: actor_entity_id.clone(),
        actor_entity: json!({"ID":actor_entity_id,"name":"requester","namespace_id":"root","aliases":[]}),
        request_accessor: String::new(),
        credential: None,
        method: "POST".into(),
        path: "secret/data/key".into(),
        capability: "update".into(),
        requires_sudo: false,
        body: json!({"data":{"value":"synthetic-native-cg-value"}}),
        transport_method: "POST".into(),
        transport_path: "secret/data/key".into(),
        transport_namespace: String::new(),
        transport_body: json!({"data":{"value":"synthetic-native-cg-value"}}),
        logical_data: None,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        created_at: 100,
        expires_at: 160,
        precision: None,
        creation_time: crate::engines::timestamp(100),
        factors: vec![ResolvedFactor {
            name: "controlled:0:ops".into(),
            group_ids: BTreeSet::from(["group-ops".into()]),
            approvals: 1,
            self_authorization: false,
        }],
        authorizations: BTreeMap::new(),
    })
}

fn deferred(
    f: &mut Fixture,
) -> Result<(AuthState, Zeroizing<String>, String), Box<dyn std::error::Error>> {
    let clock = clock(100)?;
    let principal = actor(&mut f.auth, &f.requester, clock)?;
    let request = owner(&f.auth, &principal)?;
    let (delta, candidate, mut response) =
        NativeCgAuthDelta::defer(&f.auth, clock, principal, request, &f.requester)?;
    delta.check_candidate(&f.auth, &candidate)?;
    let raw = Zeroizing::new(
        response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned(),
    );
    let accessor = response.body["wrap_info"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    crate::service::erase_json(&mut response.body);
    Ok((candidate, raw, accessor))
}

#[test]
fn native_cg_auth_defer_exact_delta_rejects_other_token_and_policy_changes() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = fixture()?;
    let original = digest(&f.auth)?;
    let clock = clock(100)?;
    let principal = actor(&mut f.auth, &f.requester, clock)?;
    let request = owner(&f.auth, &principal)?;
    let (delta, candidate, mut response) =
        NativeCgAuthDelta::defer(&f.auth, clock, principal, request, &f.requester)?;
    assert!(digest(&f.auth)? == original);
    assert_eq!(f.auth.control_groups.requests.len(), 0);
    assert_eq!(candidate.control_groups.requests.len(), 1);
    delta.check_candidate(&f.auth, &candidate)?;
    let bytes = encoded(&candidate)?;
    let restored: AuthState = serde_json::from_slice(&bytes)?;
    delta.check_candidate(&f.auth, &restored)?;
    let mut poisoned = candidate.clone();
    poisoned
        .tokens
        .get_mut(&hash(&f.reviewer))
        .ok_or("reviewer")?
        .display_name
        .push('x');
    assert!(delta.check_candidate(&f.auth, &poisoned).is_err());
    let mut poisoned = candidate.clone();
    poisoned
        .policies
        .get_mut("")
        .ok_or("policies")?
        .remove("reviewer");
    assert!(delta.check_candidate(&f.auth, &poisoned).is_err());
    let mut changed_source = f.auth.clone();
    changed_source.tokens.remove(&hash(&f.requester));
    assert!(delta.check_source(&changed_source).is_err());
    crate::service::erase_json(&mut response.body);
    Ok(())
}

#[test]
fn native_cg_auth_observe_expires_only_matching_request_and_preserves_floor() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = fixture()?;
    let (source, raw, _) = deferred(&mut f)?;
    let before = digest(&source)?;
    let (delta, candidate) = NativeCgAuthDelta::observe(&source, clock(161)?)?;
    delta.check_candidate(&source, &candidate)?;
    assert!(digest(&source)? == before);
    assert_eq!(source.control_groups.requests.len(), 1);
    assert_eq!(candidate.control_groups.requests.len(), 0);
    assert_eq!(
        candidate
            .tokens
            .get(&hash(&raw))
            .ok_or("wrapper")?
            .uses_remaining,
        Some(0)
    );
    assert!(candidate.control_groups.floor);
    assert!(candidate.control_groups.clock >= 161);
    let mut rollback = candidate.clone();
    rollback.control_groups.floor = false;
    assert!(delta.check_candidate(&source, &rollback).is_err());
    let mut rollback = candidate.clone();
    rollback.control_groups.clock = 100;
    assert!(delta.check_candidate(&source, &rollback).is_err());
    let mut other = candidate.clone();
    other
        .tokens
        .get_mut(&hash(&f.reviewer))
        .ok_or("reviewer")?
        .uses_remaining = Some(0);
    assert!(delta.check_candidate(&source, &other).is_err());
    Ok(())
}

#[test]
fn native_cg_auth_authorize_exact_approval_and_duplicate_rejection_survive_decode() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = fixture()?;
    let (mut source, _, accessor) = deferred(&mut f)?;
    let clock = clock(100)?;
    let reviewer = actor(&mut source, &f.reviewer, clock)?;
    let (delta, candidate) = NativeCgAuthDelta::authorize(
        &source,
        clock,
        reviewer,
        &accessor,
        "reviewer".into(),
        &f.reviewer,
    )?;
    delta.check_candidate(&source, &candidate)?;
    let request = candidate.control_group_by_accessor(
        &accessor,
        "",
        NativeCgAuthDelta::original_time(clock)?,
    )?;
    assert_eq!(request.authorizations.len(), 1);
    assert_eq!(
        source
            .control_group_by_accessor(&accessor, "", NativeCgAuthDelta::original_time(clock)?)?
            .authorizations
            .len(),
        0
    );
    let mut restored: AuthState = serde_json::from_slice(&encoded(&candidate)?)?;
    delta.check_candidate(&source, &restored)?;
    let second = actor(&mut restored, &f.reviewer, clock)?;
    assert!(
        NativeCgAuthDelta::authorize(
            &restored,
            clock,
            second,
            &accessor,
            "reviewer".into(),
            &f.reviewer
        )
        .is_err()
    );
    let mut tampered = candidate.clone();
    tampered
        .control_groups
        .requests
        .values_mut()
        .next()
        .ok_or("request")?
        .authorizations
        .clear();
    assert!(delta.check_candidate(&source, &tampered).is_err());
    Ok(())
}

#[test]
fn native_cg_auth_execute_stages_real_finite_use_and_claim_without_publishing() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = fixture()?;
    let (source, raw, accessor) = deferred(&mut f)?;
    let clock = clock(100)?;
    let mut admitted = source.clone();
    let caller = actor(&mut admitted, &raw, clock)?;
    assert!(caller.consumed_use());
    let mut requester_source = source.clone();
    let requester = actor(&mut requester_source, &f.requester, clock)?;
    let (delta, candidate, request) =
        NativeCgAuthDelta::execute(&source, &admitted, clock, caller, requester, &raw)?;
    delta.check_candidate(&source, &candidate)?;
    assert!(request.request_accessor == accessor);
    assert_eq!(source.control_groups.requests.len(), 1);
    assert_eq!(
        source
            .tokens
            .get(&hash(&raw))
            .ok_or("sourcewrapper")?
            .uses_remaining,
        Some(1)
    );
    assert_eq!(candidate.control_groups.requests.len(), 0);
    assert_eq!(
        candidate
            .tokens
            .get(&hash(&raw))
            .ok_or("candidatewrapper")?
            .uses_remaining,
        Some(0)
    );
    let mut poisoned = candidate.clone();
    poisoned
        .tokens
        .get_mut(&hash(&raw))
        .ok_or("wrapper")?
        .uses_remaining = Some(1);
    assert!(delta.check_candidate(&source, &poisoned).is_err());
    // Move the exact original Principals once into the future Service owners;
    // no Clone/serde/bearer re-authentication participates in this handoff.
    let (binding, caller, requester, retained) = delta.into_execute_parts()?;
    binding.check_candidate(&source, &candidate)?;
    assert!(caller.consumed_use());
    assert!(source.control_group_actor_binding(&requester)?.0 == retained.actor_digest);
    // Native Service must join this delta to its independently owned real KV2
    // result before one CAS append. No publication is performed by this test.
    let mut committed = candidate.clone();
    assert!(
        committed
            .authenticate_from_observed(&raw, NativeCgAuthDelta::original_time(clock)?, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_cg_auth_rejects_detached_consumption_clock_and_missing_or_shorter_deadline() -> TestResult
{
    let f = fixture()?;
    assert!(NativeCgAuthDelta::observe(&f.auth, clock(100)?).is_err());
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = f;
    let (source, raw, _) = deferred(&mut f)?;
    let clock = clock(100)?;
    let mut admitted = source.clone();
    let caller = actor(&mut admitted, &raw, clock)?;
    let mut requester_source = source.clone();
    let requester = actor(&mut requester_source, &f.requester, clock)?;
    admitted
        .tokens
        .get_mut(&hash(&f.reviewer))
        .ok_or("reviewer")?
        .display_name
        .push('x');
    assert!(
        NativeCgAuthDelta::execute(&source, &admitted, clock, caller, requester, &raw).is_err()
    );
    let (delta, candidate) = NativeCgAuthDelta::observe(&source, clock)?;
    {
        let _shorter = crate::request_deadline::RequestDeadlineScope::enter(Instant::now());
        assert!(delta.check_candidate(&source, &candidate).is_err());
    }
    assert!(delta.into_execute_parts().is_err());
    let mut unchanged = source.clone();
    let actor = actor(&mut unchanged, &f.requester, clock)?;
    let different = RequestClock::anchored(Duration::from_secs(100), Instant::now())?;
    let request = owner(&source, &actor)?;
    assert!(NativeCgAuthDelta::defer(&source, different, actor, request, &f.requester).is_err());
    Ok(())
}
