//! Node-local OpenBao 2.7.1 memorystore semantics for the bounded native slice.
use super::*;
use crate::auth::rate_limit_quotas::{Definition, Registry};
use std::net::IpAddr;
const MAX_CLIENTS: usize = 8192;
#[derive(Default)]
pub(super) struct Runtime {
    buckets: BTreeMap<(String, u64, IpAddr), Bucket>,
    sweep: BTreeMap<(String, u64), (Instant, u64)>,
    owner: Option<RuntimeOwner>,
    active: Option<ha_activation::ActivationKey>,
    ingress_entry: Option<QuotaIngressEntry>,
    standby_rejection: Option<StandbyQuotaRejection>,
}
// Auth is reloaded during ordinary HA catch-up. Its deserialized runtime Arc
// is not a new node-local quota session. These fields identify the actual live
// Service activation; none is serialized into Auth, a snapshot or a peer frame.
enum RuntimeOwner {
    Standalone(Arc<()>),
    Ha(HaSession),
}
struct HaSession {
    process: std::sync::Weak<Mutex<HaProcess>>,
    cluster_id: String,
    replay_epoch: u64,
    unseal_nonce: String,
}
impl RuntimeOwner {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Standalone(left), Self::Standalone(right)) => Arc::ptr_eq(left, right),
            (Self::Ha(left), Self::Ha(right)) => {
                std::sync::Weak::ptr_eq(&left.process, &right.process)
                    && left.cluster_id == right.cluster_id
                    && left.replay_epoch == right.replay_epoch
                    && left.unseal_nonce == right.unseal_nonce
            }
            _ => false,
        }
    }
}
#[derive(Clone, Copy)]
enum HaRole {
    Active(ha_activation::ActivationKey),
    Standby,
}
struct Limiter {
    start: Instant,
    last_tick: u64,
    remaining: u64,
}
struct Bucket {
    limiter: Option<Limiter>,
    blocked_until: Option<Instant>,
}
struct Rejected {
    retry_after: u64,
}
impl Runtime {
    pub(super) fn begin_barrier_activation(&mut self) {
        // This is called only at the actual storage teardown/unseal boundary.
        // The Shamir nonce can rotate after nested HA sync, and legacy unseal
        // does not rotate it there, so nonce comparison alone is insufficient.
        // An in-flight affine refusal must remain visible to the caller's
        // source checks (or the next-entry stale guard), never disappear here.
        let ingress_entry = self.ingress_entry.take();
        let standby_rejection = self.standby_rejection.take();
        *self = Self::default();
        self.ingress_entry = ingress_entry;
        self.standby_rejection = standby_rejection;
    }
    fn synchronize_owner(&mut self, owner: RuntimeOwner) {
        if self.owner.as_ref().is_none_or(|current| !current.same(&owner)) {
            self.buckets.clear();
            self.sweep.clear();
            self.owner = Some(owner);
            self.active = None;
        }
    }
    fn observe_ha_role(&mut self, role: HaRole) {
        let next = match role {
            HaRole::Active(key) => Some(key),
            HaRole::Standby => None,
        };
        // An actual new local application activation or transition back to a
        // ready standby rebuilds the upstream node-local memorystore. A
        // continuous standby ignores other nodes' election terms. A transient
        // failed probe does not call this method or reset a live bucket.
        if self.active != next {
            self.buckets.clear();
            self.sweep.clear();
            self.active = next;
        }
    }
    fn purge_at(&mut self, definition: &Definition, now: Instant) {
        let sweep = self
            .sweep
            .entry((definition.name.clone(), definition.revision))
            .or_insert((now, 0));
        let tick = now.saturating_duration_since(sweep.0).as_secs() / 60;
        if tick <= sweep.1 {
            return;
        }
        sweep.1 = tick;
        let swept_at = sweep.0 + Duration::from_secs(tick * 60);
        self.buckets.retain(|(name, revision, _), bucket| {
            if name != &definition.name || *revision != definition.revision {
                return true;
            }
            if bucket.limiter.as_ref().is_some_and(|b| {
                let last_time = b.start + Duration::from_secs(b.last_tick * definition.interval);
                swept_at.saturating_duration_since(last_time) > Duration::from_secs(180)
            }) {
                bucket.limiter = None;
            }
            bucket.limiter.is_some() || bucket.blocked_until.is_some_and(|until| swept_at < until)
        });
    }
    fn take_at(
        &mut self,
        definition: &Definition,
        peer: IpAddr,
        now: Instant,
    ) -> Result<Option<Rejected>, ()> {
        self.purge_at(definition, now);
        self.buckets.retain(|(name, revision, _), _| {
            name != &definition.name || *revision == definition.revision
        });
        let key = (definition.name.clone(), definition.revision, peer);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= MAX_CLIENTS {
            return Err(());
        }
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            limiter: None,
            blocked_until: None,
        });
        // Blocked clients are an independent clock/owner, as in upstream. An
        // idle limiter sweep cannot shorten a configured block interval.
        if let Some(until) = bucket.blocked_until {
            if now < until {
                return Ok(Some(Rejected {
                    retry_after: until.saturating_duration_since(now).as_secs(),
                }));
            }
            bucket.blocked_until = None;
        }
        let limiter = bucket.limiter.get_or_insert_with(|| Limiter {
            start: now,
            last_tick: 0,
            remaining: definition.tokens(),
        });
        let elapsed = now.saturating_duration_since(limiter.start);
        let tick = elapsed.as_secs() / definition.interval;
        if tick > limiter.last_tick {
            limiter.last_tick = tick;
            limiter.remaining = definition.tokens();
        }
        if limiter.remaining > 0 {
            limiter.remaining -= 1;
            return Ok(None);
        }
        let retry_after = if definition.block_interval > 0 {
            let until = now
                .checked_add(Duration::from_secs(definition.block_interval))
                .ok_or(())?;
            bucket.blocked_until = Some(until);
            definition.block_interval.saturating_sub(1)
        } else {
            let next = Duration::from_secs((tick + 1).checked_mul(definition.interval).ok_or(())?);
            next.saturating_sub(elapsed).as_secs()
        };
        Ok(Some(Rejected { retry_after }))
    }
    fn synchronize(&mut self, registry: &Registry, owner: RuntimeOwner) {
        self.synchronize_owner(owner);
        self.buckets.retain(|(name, revision, _), _| {
            registry
                .definitions
                .get(name)
                .is_some_and(|d| d.revision == *revision)
        });
        self.sweep.retain(|(name, revision), _| {
            registry
                .definitions
                .get(name)
                .is_some_and(|d| d.revision == *revision)
        });
    }
}
impl Service {
    fn rate_limit_quota_ha_session(&self) -> Option<HaSession> {
        if !self.ha_activation_permitted() {
            return None;
        }
        let state = self.state.as_ref()?;
        Some(HaSession {
            process: Arc::downgrade(self.ha.as_ref()?),
            cluster_id: state.cluster_id.clone(),
            replay_epoch: state.replay_epoch,
            unseal_nonce: self.unseal_nonce.clone(),
        })
    }

    // The caller has just completed the ordinary authenticated HA catch-up.
    // A leader additionally needs the existing application activation event;
    // a remembered leader id alone cannot admit its node-local counter.
    fn rate_limit_quota_ha_role(&self) -> Result<HaRole, Response> {
        let unavailable = || Response::error(503, "HA rate limit quota session is unavailable");
        if !self.ha_activation_permitted() {
            return Err(unavailable());
        }
        let process = self.ha.as_ref().ok_or_else(unavailable)?
            .lock_for_request().map_err(|_| unavailable())?;
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        if !process.bootstrap_ready() || process.cluster_id() != state.cluster_id {
            return Err(unavailable());
        }
        let observed = process.leader_status().map_err(|_| unavailable())?;
        if let Some(key) = ha_activation::ActivationKey::from_observation(observed) {
            if self.ha_activation.as_ref().is_none_or(|event| !event.matches(key)) {
                return Err(unavailable());
            }
            Ok(HaRole::Active(key))
        } else if !observed.local_is_leader
            && observed.leader.is_some_and(|leader| leader != observed.local_id)
        {
            Ok(HaRole::Standby)
        } else {
            Err(unavailable())
        }
    }

    pub(super) fn record_rate_limit_quota_activation(
        &mut self,
        key: ha_activation::ActivationKey,
    ) {
        let Some(session) = self.rate_limit_quota_ha_session() else {
            return;
        };
        self.rate_limit_quotas.synchronize_owner(RuntimeOwner::Ha(session));
        self.rate_limit_quotas.observe_ha_role(HaRole::Active(key));
    }

    pub(super) fn rate_limit_quota_response(
        &mut self,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        self.rate_limit_quota_response_with_ingress(request, None)
    }

    fn rate_limit_quota_response_with_ingress(
        &mut self,
        request: &RequestView<'_>,
        ingress: Option<QuotaIngressEntry>,
    ) -> Option<Response> {
        let state = self.state.as_ref()?;
        let registry = state.auth.rate_limit_quota_registry()?;
        let owner = if self.ha.is_some() {
            let Some(session) = self.rate_limit_quota_ha_session() else {
                return Some(Response::error(503, "HA rate limit quota session is unavailable"));
            };
            RuntimeOwner::Ha(session)
        } else {
            RuntimeOwner::Standalone(Arc::clone(&registry.runtime_owner))
        };
        // Keep deleted and revised rule pruning even for exempt/nonmatching
        // requests. Only committed current definitions reach this boundary.
        self.rate_limit_quotas.synchronize(registry, owner);
        if registry.definitions.is_empty() || registry.config.exempt(request.path) {
            return None;
        }
        let (mount, role) = match state.auth.rate_limit_approle_scope(
            request.namespace,
            request.method,
            request.path,
            request.body,
        ) {
            Ok(Some(scope)) => scope,
            Ok(None) => return None,
            Err(e) => return Some(Response::error(e.status, &e.message)),
        };
        let selected = registry
            .definitions
            .values()
            .find(|d| !role.is_empty() && d.path == mount && d.role == role)
            .or_else(|| {
                registry
                    .definitions
                    .values()
                    .find(|d| d.role.is_empty() && d.path == request.path)
            })
            .or_else(|| {
                registry
                    .definitions
                    .values()
                    .find(|d| d.role.is_empty() && d.path == mount)
            });
        let definition = selected?;
        let actual_standby = if self.ha.is_some() {
            let role = match self.rate_limit_quota_ha_role() {
                Ok(role) => role,
                Err(response) => return Some(response),
            };
            self.rate_limit_quotas.observe_ha_role(role);
            matches!(role, HaRole::Standby)
        } else {
            false
        };
        let Some(peer) = request.origin_peer else {
            return Some(Response::error(
                503,
                "rate limit quota requires an observed transport peer",
            ));
        };
        match self
            .rate_limit_quotas
            .take_at(definition, peer, Instant::now())
        {
            Ok(None) => None,
            Ok(Some(rejected)) => {
                let mut response = Response::error(429, "rate limit quota exceeded");
                response.response_headers = ResponseHeaders::from_sdk(
                    Some(&json!({"Retry-After":[rejected.retry_after.to_string()]})),
                    &["Retry-After".into()],
                )
                .unwrap_or_default();
                if actual_standby && let Some(entry) = ingress {
                    match StandbyQuotaRejection::capture(self, request, entry, &response) {
                        Ok(rejection) => self.rate_limit_quotas.standby_rejection = Some(rejection),
                        Err(error) => return Some(error),
                    }
                }
                Some(response)
            }
            Err(()) => Some(Response::error(
                503,
                "rate limit quota client capacity exhausted",
            )),
        }
    }
}

// A denial from a real standby ingress bucket has not admitted an Actor,
// observed a credential expiry, consumed a SecretID, or dispatched the route.
// The sole top-level entry moves through the first handle_inner invocation;
// nested dispatch, forwarding and control-group resume cannot create it.
pub(super) struct QuotaIngressEntry {
    fingerprint: String,
    clock: RequestClock,
    now: u64,
    deadline: Instant,
    audit_sequence: u64,
    audit_previous: [u8; 32],
}

// Not Clone and not serialized. Only take_at's actual rejected branch creates
// this value. It conveys a local public refusal, never an authenticated read,
// Actor, Raft publication, completed-forward receipt or fresh time observation.
pub(super) struct StandbyQuotaRejection {
    entry: QuotaIngressEntry,
    owner: RuntimeOwner,
    identity: crate::state_record_root::StateIdentity,
    generation: u64,
    token_floor: Option<Timestamp>,
    barrier_digest: [u8; 32],
    response_digest: [u8; 32],
}

impl Runtime {
    pub(super) fn has_pending_ingress(&self) -> bool {
        self.ingress_entry.is_some() || self.standby_rejection.is_some()
    }

    pub(super) fn take_ingress_entry(&mut self) -> Option<QuotaIngressEntry> {
        self.ingress_entry.take()
    }

    pub(super) fn take_standby_rejection(&mut self) -> Option<StandbyQuotaRejection> {
        self.standby_rejection.take()
    }
}

impl QuotaIngressEntry {
    fn same_request(&self, request: &RequestView<'_>) -> bool {
        request.allow_forward
            && request.namespace.is_empty()
            && request.path.starts_with("auth/")
            && request.admission_started == self.clock.started()
            && request.now == self.now
            && request.token_clock.is_some_and(|clock| {
                clock.started() == self.clock.started()
                    && clock.admitted_at() == self.clock.admitted_at()
            })
    }

    fn clock_live(&self, now: u64, clock: Option<RequestClock>) -> bool {
        now == self.now
            && crate::request_deadline::current() == Some(self.deadline)
            && Instant::now() < self.deadline
            && clock.is_some_and(|clock| {
                clock.started() == self.clock.started()
                    && clock.admitted_at() == self.clock.admitted_at()
                    && clock.observed_at().is_ok()
            })
    }
}

fn ingress_unavailable() -> Response {
    Response::error(503, "standby quota rejection custody changed")
}

impl StandbyQuotaRejection {
    fn capture(
        service: &mut Service,
        request: &RequestView<'_>,
        entry: QuotaIngressEntry,
        response: &Response,
    ) -> Result<Self, Response> {
        if !entry.same_request(request)
            || service.rate_limit_quotas.standby_rejection.is_some()
            || response.status != 429
        {
            return Err(ingress_unavailable());
        }
        let state = service.state.as_ref().ok_or_else(ingress_unavailable)?;
        let rejection = Self {
            entry,
            owner: RuntimeOwner::Ha(
                service.rate_limit_quota_ha_session().ok_or_else(ingress_unavailable)?,
            ),
            identity: service.current_state_identity()?,
            generation: service.durable.as_ref().ok_or_else(ingress_unavailable)?.generation(),
            token_floor: state.auth.terminal_token_clock_floor(),
            barrier_digest: crypto::digest(
                service.barrier_key.as_ref().ok_or_else(ingress_unavailable)?.as_slice(),
            ),
            response_digest: crate::ha_forward_completion::response_digest(response)
                .map_err(|_| ingress_unavailable())?,
        };
        rejection.check(
            service, response, &rejection.entry.fingerprint,
            request.now, request.token_clock, false,
        )?;
        Ok(rejection)
    }

    fn check(
        &self,
        service: &mut Service,
        response: &Response,
        fingerprint: &str,
        now: u64,
        clock: Option<RequestClock>,
        after_audit: bool,
    ) -> Result<(), Response> {
        if fingerprint != self.entry.fingerprint
            || !self.entry.clock_live(now, clock)
            || crate::ha_forward_completion::CompletionScope::active()
            || service.recovery_required
            || service.audit_failed
            || service.pending_forward_delivery.is_some()
            || service.pending_ordinary_kv_commit_notice.is_some()
            || service.rate_limit_quotas.has_pending_ingress()
            || response.status != 429
            || response.unwrapped_json.is_some()
            || response.consistency_index.is_some()
            || crate::ha_forward_completion::response_digest(response)
                .map_err(|_| ingress_unavailable())? != self.response_digest
        {
            return Err(ingress_unavailable());
        }
        #[cfg(feature = "fixture-native-v6-service")]
        if service.native_failure_notice.is_some() {
            return Err(ingress_unavailable());
        }
        let expected_sequence = if after_audit {
            self.entry.audit_sequence.checked_add(1).ok_or_else(ingress_unavailable)?
        } else {
            self.entry.audit_sequence
        };
        if service.audit_sequence != expected_sequence
            || if after_audit {
                service.audit_previous == self.entry.audit_previous
            } else {
                service.audit_previous != self.entry.audit_previous
            }
        {
            return Err(ingress_unavailable());
        }
        let owner = RuntimeOwner::Ha(
            service.rate_limit_quota_ha_session().ok_or_else(ingress_unavailable)?,
        );
        if !self.owner.same(&owner)
            || service.rate_limit_quotas.owner.as_ref().is_none_or(|live| !live.same(&owner))
            || service.rate_limit_quotas.active.is_some()
            || !matches!(service.rate_limit_quota_ha_role()?, HaRole::Standby)
            || service.current_state_identity()? != self.identity
            || service.state.as_ref().ok_or_else(ingress_unavailable)?
                .auth.terminal_token_clock_floor() != self.token_floor
            || crypto::digest(
                service.barrier_key.as_ref().ok_or_else(ingress_unavailable)?.as_slice(),
            ) != self.barrier_digest
        {
            return Err(ingress_unavailable());
        }
        let durable = service.durable.as_mut().ok_or_else(ingress_unavailable)?;
        durable.verify_live_ownership().map_err(|_| ingress_unavailable())?;
        if durable.generation() != self.generation
            || !self.entry.clock_live(now, clock)
        {
            return Err(ingress_unavailable());
        }
        Ok(())
    }
}

impl Service {
    // Called only after the top-level request audit and immediately before its
    // first handle_inner. The entry is taken on entry, not left for an inner
    // route to borrow. There is no new clock, deadline or admission here.
    pub(super) fn stage_quota_ingress(
        &mut self,
        fingerprint: &str,
        now: u64,
        admission_started: Instant,
        clock: Option<RequestClock>,
        allow_forward: bool,
    ) {
        if !allow_forward
            || crate::ha_forward_completion::CompletionScope::active()
            || self.rate_limit_quotas.has_pending_ingress()
        {
            return;
        }
        let (Some(clock), Some(deadline)) = (clock, crate::request_deadline::current()) else {
            return;
        };
        if clock.started() != admission_started || Instant::now() >= deadline {
            return;
        }
        self.rate_limit_quotas.ingress_entry = Some(QuotaIngressEntry {
            fingerprint: fingerprint.to_owned(),
            clock,
            now,
            deadline,
            audit_sequence: self.audit_sequence,
            audit_previous: self.audit_previous,
        });
    }

    pub(super) fn standby_rate_limit_quota_response(
        &mut self,
        request: &RequestView<'_>,
        ingress: Option<QuotaIngressEntry>,
    ) -> Option<Response> {
        self.rate_limit_quota_response_with_ingress(request, ingress)
    }

    // Only the exclusive top-level completion branch consumes this private
    // refusal. Normal requests still enter the unmodified terminal floor path.
    pub(super) fn complete_standby_quota_rejection(
        &mut self,
        rejection: StandbyQuotaRejection,
        mut response: Response,
        fingerprint: &str,
        now: u64,
        clock: Option<RequestClock>,
    ) -> Response {
        // A local refusal must never mint a peer completion from this call.
        crate::ha_forward_completion::audited(None);
        let admissible = rejection.check(self, &response, fingerprint, now, clock, false).is_ok();
        if !admissible {
            erase_json(&mut response.body);
            response = ingress_unavailable();
        }
        if self.audit_event("response", fingerprint, now, Some(response.status)).is_err() {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            erase_json(&mut response.body);
            #[cfg(target_os = "linux")]
            if self.seal.as_ref().is_some_and(|seal| seal.is_wrapper()) {
                self.fence_wrapper_barrier_delivery();
            }
            return Response::error(
                503, "quota rejection response audit failed; authoritative recovery required",
            );
        }
        if admissible
            && rejection.check(self, &response, fingerprint, now, clock, true).is_err()
        {
            erase_json(&mut response.body);
            response = ingress_unavailable();
            if self.audit_event("quota_rejection_veto", fingerprint, now, Some(503)).is_err() {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                #[cfg(target_os = "linux")]
                if self.seal.as_ref().is_some_and(|seal| seal.is_wrapper()) {
                    self.fence_wrapper_barrier_delivery();
                }
                return Response::error(
                    503, "quota rejection veto audit failed; authoritative recovery required",
                );
            }
        }
        response.consistency_index = None;
        response
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    pub(super) fn definition(rate: f64, interval: u64, block: u64) -> Definition {
        Definition {
            name: "quota".into(),
            path: "auth/approle/".into(),
            role: "".into(),
            rate,
            interval,
            block_interval: block,
            revision: 1,
        }
    }
    #[test]
    fn quota_bucket_refills_full_burst_only_at_interval_tick_and_is_peer_local() -> TestResult {
        let mut runtime = Runtime::default();
        let d = definition(2.0, 10, 0);
        let now = Instant::now();
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)), now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(10))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        Ok(())
    }
    #[test]
    fn quota_block_is_not_extended_by_retry_and_update_resets_bucket() -> TestResult {
        let mut runtime = Runtime::default();
        let mut d = definition(1.0, 1, 5);
        let now = Instant::now();
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(4))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        d.revision = 2;
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(5))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        Ok(())
    }
}

#[cfg(test)]
mod service_tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn peer_call(
        service: &mut Service,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> Response {
        service.handle_request_at(
            ServiceRequest::new(method, path, "", token, body)
                .with_origin_peer(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            100,
        )
    }
    #[test]
    fn rate_limit_failed_role_resolution_charges_fallback_and_management_resolves_login_role()
    -> TestResult {
        for fallback in ["auth/approle/login", "auth/approle/"] {
            let root = Root::new();
            let mut service = root.service()?;
            let (_, admin) = bootstrap(&mut service)?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/auth/approle",
                    &admin,
                    json!({"type":"approle"})
                )
                .status,
                204
            );
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "auth/approle/role/limited",
                    &admin,
                    json!({})
                )
                .status,
                204
            );
            let role_id = call(
                &mut service,
                "GET",
                "auth/approle/role/limited/role-id",
                &admin,
                json!({}),
            )
            .body["data"]["role_id"]
                .as_str()
                .ok_or("role ID")?
                .to_owned();
            for (name, path, role) in [
                ("specific", "auth/approle/", "limited"),
                ("fallback", fallback, ""),
            ] {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        &format!("sys/quotas/rate-limit/{name}"),
                        &admin,
                        json!({"path":path,"role":role,"rate":1,"interval":"1h"})
                    )
                    .status,
                    204
                );
            }
            let invalid = json!({"role_id":"unknown-role-id","secret_id":"wrong-secret"});
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    "auth/approle/login",
                    "",
                    invalid.clone()
                )
                .status,
                400
            );
            let exhausted = peer_call(&mut service, "POST", "auth/approle/login", "", invalid);
            assert_eq!(exhausted.status, 429);
            assert!(exhausted.body.get("auth").is_none());
            // A non-login request still resolves its actual role_id before
            // dispatch; it consumes the separate role bucket, not fallback.
            let management = peer_call(
                &mut service,
                "POST",
                "auth/approle/role/limited",
                &admin,
                json!({"role_id":role_id}),
            );
            assert_ne!(management.status, 429);
            let named_exhausted = peer_call(
                &mut service,
                "POST",
                "auth/approle/login",
                "",
                json!({"role_id":role_id,"secret_id":"wrong-secret"}),
            );
            assert_eq!(named_exhausted.status, 429);
            assert!(named_exhausted.body.get("auth").is_none());
        }
        Ok(())
    }

    #[test]
    fn rate_limit_denial_preserves_single_use_secret_id_and_invalid_secret_still_counts()
    -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        for mount in ["approle", "forms"] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    &format!("sys/auth/{mount}"),
                    &admin,
                    json!({"type":"approle"})
                )
                .status,
                204
            );
            let role = format!("auth/{mount}/role/limited");
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    &role,
                    &admin,
                    json!({"secret_id_num_uses":1})
                )
                .status,
                204
            );
            let role_id = call(
                &mut service,
                "GET",
                &format!("{role}/role-id"),
                &admin,
                json!({}),
            )
            .body["data"]["role_id"]
                .as_str()
                .ok_or("role")?
                .to_owned();
            let sid = call(
                &mut service,
                "POST",
                &format!("{role}/secret-id"),
                &admin,
                json!({}),
            )
            .body["data"]["secret_id"]
                .as_str()
                .ok_or("sid")?
                .to_owned();
            let rule = format!("sys/quotas/rate-limit/{mount}");
            let settings =
                json!({"path":format!("auth/{mount}/"),"role":"limited","rate":1,"interval":"1h"});
            let created = call(&mut service, "POST", &rule, &admin, settings.clone());
            assert_eq!(
                created.status, 204,
                "quota create errors: {:?}",
                created.body["errors"]
            );
            let login = format!("auth/{mount}/login");
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":"wrong-secret"})
                )
                .status,
                400
            );
            let wire = format!(
                "POST /v1/{login} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\nrole_id={role_id}&secret_id={sid}",
                "role_id=&secret_id=".len() + role_id.len() + sid.len()
            );
            let denied =
                crate::http::logical_data_wire_fixture(&mut service, wire.as_bytes(), 100)?;
            assert_eq!(denied.status, 429);
            assert!(denied.body.get("auth").is_none());
            for ((name, _, _), bucket) in &mut service.rate_limit_quotas.buckets {
                if name == mount {
                    bucket
                        .limiter
                        .as_mut()
                        .ok_or("quota fixture missing active limiter")?
                        .start = Instant::now() - Duration::from_secs(3600);
                }
            }
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":sid})
                )
                .status,
                200
            );
            assert_eq!(
                call(&mut service, "POST", &rule, &admin, settings).status,
                204
            );
            assert_eq!(
                peer_call(
                    &mut service,
                    "POST",
                    &login,
                    "",
                    json!({"role_id":role_id,"secret_id":sid})
                )
                .status,
                400
            );
        }
        Ok(())
    }
    #[test]
    fn rate_limit_acl_api_namespace_scope_and_unsupported_ranges_fail_closed() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(&mut service, "GET", "sys/quotas/config", "", json!({})).status,
            403
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        assert_eq!(call(&mut service,"POST","sys/policies/acl/quota-manager",&admin,json!({"policy":"path \"sys/quotas/*\" { capabilities = [\"read\", \"update\", \"list\", \"delete\"] }"})).status,204);
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["quota-manager"],"ttl":60}),
        );
        assert_eq!(issued.status, 200);
        let manager = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("manager token")?
            .to_owned();
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({"path":"auth/forms","rate":2})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "GET",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({})
            )
            .body["data"]["path"],
            "auth/forms/"
        );
        assert_eq!(
            call(
                &mut service,
                "LIST",
                "sys/quotas/rate-limit",
                &manager,
                json!({})
            )
            .body["data"]["keys"],
            json!(["managed"])
        );
        for body in [
            json!({"path":"","rate":2}),
            json!({"path":"secret/","rate":2}),
            json!({"path":"auth/forms/","rate":0}),
            json!({"path":"auth/forms/","rate":2,"inheritable":true}),
            json!({"path":"auth/forms/login","role":"r","rate":2}),
        ] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/quotas/rate-limit/unsupported",
                    &manager,
                    body
                )
                .status,
                400
            );
        }
        for field in [
            "enable_rate_limit_audit_logging",
            "enable_rate_limit_response_headers",
        ] {
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/quotas/config",
                    &manager,
                    json!({field:true})
                )
                .status,
                400
            );
        }
        assert_eq!(
            call(
                &mut service,
                "DELETE",
                "sys/quotas/rate-limit/managed",
                &manager,
                json!({})
            )
            .status,
            204
        );
        Ok(())
    }
    #[test]
    fn rate_limit_native_owner_reopens_and_floor_survives_delete_remount_and_snapshot() -> TestResult
    {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        let previous = service.state.clone().ok_or("previous state")?;
        let created = call(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/retained",
            &admin,
            json!({"path":"auth/forms/login","rate":1,"interval":"1h"}),
        );
        assert_eq!(
            created.status, 204,
            "quota create errors: {:?}",
            created.body["errors"]
        );
        let current = service.state.clone().ok_or("current state")?;
        assert_eq!(current.schema, RATE_LIMIT_QUOTA_STATE_SCHEMA);
        assert!(Service::validate_snapshot_protected_floor(&current, &previous).is_err());
        assert!(
            previous
                .validate_publication_schema(Some(&current))
                .is_err()
        );
        {
            // Match the actual listener deadline. Missing ingress authority is
            // a separate 503 guard and must not stand in for quota rejection.
            let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_secs(5),
            );
            let rejected = call(
                &mut service,
                "POST",
                "sys/remount",
                &admin,
                json!({"from":"auth/forms/","to":"auth/moved/"}),
            );
            assert_eq!(
                rejected.status, 400,
                "remount rejection errors: {:?}",
                rejected.body["errors"]
            );
        }
        drop(current);
        drop(previous);
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .body["data"]["interval"],
            3600
        );
        assert_eq!(
            call(&mut reopened, "DELETE", "sys/auth/forms", &admin, json!({})).status,
            204
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .status,
            404
        );
        assert_eq!(
            reopened.state.as_ref().ok_or("reopened state")?.schema,
            RATE_LIMIT_QUOTA_STATE_SCHEMA
        );
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "sys/auth/forms",
                &admin,
                json!({"type":"approle"})
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut reopened,
                "GET",
                "sys/quotas/rate-limit/retained",
                &admin,
                json!({})
            )
            .status,
            404
        );
        Ok(())
    }
    #[test]
    fn rate_limit_idle_limiter_purge_cannot_shorten_independent_block_interval() -> TestResult {
        let mut runtime = Runtime::default();
        let d = super::tests::definition(1.0, 3600, 300);
        let now = Instant::now();
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        assert!(
            runtime
                .take_at(&d, ip, now)
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(241))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_some()
        );
        assert!(
            runtime
                .take_at(&d, ip, now + Duration::from_secs(300))
                .map_err(|()| "quota fixture exceeded runtime bounds")?
                .is_none()
        );
        Ok(())
    }
}
