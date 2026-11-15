//! Test-only observations for the two original short-lived HA actor requests.
//! No observation can authorize, consume, refresh or publish a credential.
use super::token_precision::{AuthorityTime, DurationNanos, Timestamp};
use super::{AuthState, Token};
use std::cell::Cell;
use std::io::Write as _;

#[derive(Clone, Copy)]
struct Sample {
    token_present: bool,
    precise_lease: bool,
    effective_clock_available: bool,
    effective_precise: bool,
    lifetime_live: Option<bool>,
    precise_expired: Option<bool>,
    precise_before_issue: Option<bool>,
    remaining_ns: Option<u64>,
    grant_age_ns: Option<u64>,
    finite_exhausted: Option<bool>,
    consume_check: Option<bool>,
}

impl std::fmt::Debug for Sample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sample")
            .field("token_present", &self.token_present)
            .field("precise_lease", &self.precise_lease)
            .field("effective_clock_available", &self.effective_clock_available)
            .field("effective_precise", &self.effective_precise)
            .field("lifetime_live", &self.lifetime_live)
            .field("precise_expired", &self.precise_expired)
            .field("precise_before_issue", &self.precise_before_issue)
            .field("remaining_ns", &self.remaining_ns)
            .field("grant_age_ns", &self.grant_age_ns)
            .field("finite_exhausted", &self.finite_exhausted)
            .field("consume_check", &self.consume_check)
            .finish()
    }
}

impl Sample {
    fn capture(token: Option<&Token>, time: Option<AuthorityTime>, consume: Option<bool>) -> Self {
        let exact = time.and_then(AuthorityTime::exact);
        let lease = token.and_then(|value| value.token_api_precision.as_ref());
        Self {
            token_present: token.is_some(),
            precise_lease: lease.is_some(),
            effective_clock_available: time.is_some(),
            effective_precise: exact.is_some(),
            lifetime_live: token.zip(time).map(|(value, at)| {
                at.service_live(value.token_api_precision.as_ref(), value.expires_at)
            }),
            precise_expired: lease
                .zip(exact)
                .map(|(value, at)| value.expires_at.is_some_and(|end| at > end)),
            precise_before_issue: lease.zip(exact).map(|(value, at)| at < value.issued_at),
            remaining_ns: lease.zip(exact).and_then(|(value, at)| {
                value
                    .expires_at
                    .and_then(|end| end.elapsed(at).ok().map(DurationNanos::nanoseconds))
            }),
            grant_age_ns: lease.zip(exact).and_then(|(value, at)| {
                at.elapsed(value.grant_started_at)
                    .ok()
                    .map(DurationNanos::nanoseconds)
            }),
            finite_exhausted: token.map(|value| value.uses_remaining == Some(0)),
            consume_check: consume,
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    MissingRoute,
    Totp,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::MissingRoute => "missing_route",
            Self::Totp => "totp",
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    kind: Kind,
    entry_local_loaded: bool,
    entry_original_anchor: Sample,
    active_check_count: u64,
    first_active_check: Option<Sample>,
    last_active_check: Option<Sample>,
    admission_status: Option<u16>,
    owner_entered: bool,
    hook_entered: bool,
    hook_returned: bool,
}

thread_local! {
    static ACTIVE: Cell<Option<Record>> = const { Cell::new(None) };
}

fn update(change: impl FnOnce(&mut Record)) {
    ACTIVE.with(|slot| {
        if let Some(mut record) = slot.get() {
            change(&mut record);
            slot.set(Some(record));
        }
    });
}

/// Nested `handle_request` calls suspend this diagnostic. Explicit-clock entry
/// points are not instrumented; neither target expiry test uses them in its hook.
pub(crate) struct Scope {
    previous: Option<Record>,
    finished: bool,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Scope {
    pub(crate) fn enter(
        native: bool,
        route: (&str, &str, &str),
        raw: &str,
        auth: Option<&AuthState>,
        admitted: Timestamp,
    ) -> Self {
        let kind = match route {
            ("GET", "hbqa-absent/route", "") if native => Some(Kind::MissingRoute),
            ("GET", "totp/code/quorum", "") if native => Some(Kind::Totp),
            _ => None,
        };
        let record = kind.map(|kind| {
            // The entry snapshot is the already loaded local graph, not a new
            // ReadIndex or admission decision. Do not retain raw/digested IDs.
            let verifier = (raw.len() <= 256 && raw.starts_with("hvs."))
                .then(|| zeroize::Zeroizing::new(super::hash(raw)));
            let token = auth
                .zip(verifier.as_ref())
                .and_then(|(state, id)| state.tokens.get(id.as_str()));
            let original = AuthorityTime::Precise(admitted);
            Record {
                kind,
                entry_local_loaded: auth.is_some(),
                entry_original_anchor: Sample::capture(token, Some(original), None),
                active_check_count: 0,
                first_active_check: None,
                last_active_check: None,
                admission_status: None,
                owner_entered: false,
                hook_entered: false,
                hook_returned: false,
            }
        });
        Self {
            previous: ACTIVE.with(|slot| slot.replace(record)),
            finished: false,
            _thread_bound: std::marker::PhantomData,
        }
    }

    pub(crate) fn finish(mut self, status: u16) {
        let record = ACTIVE.with(|slot| slot.replace(self.previous.take()));
        self.finished = true;
        let Some(record) = record.filter(|_| matches!(status, 403 | 503)) else {
            return;
        };
        // Only after the original request completed. No successful issuance or
        // live authority check is delayed by diagnostic stderr output.
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-DIAG-ACTOR-LIFETIME kind={} final_status={status} entry_local_loaded={} admission_status={:?} owner_entered={} hook_entered={} hook_returned={} active_check_count={} entry_original_anchor={:?} first_active_check={:?} last_active_check={:?}",
            record.kind.label(),
            record.entry_local_loaded,
            record.admission_status,
            record.owner_entered,
            record.hook_entered,
            record.hook_returned,
            record.active_check_count,
            record.entry_original_anchor,
            record.first_active_check,
            record.last_active_check,
        );
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.finished {
            ACTIVE.with(|slot| slot.set(self.previous.take()));
        }
    }
}

/// Called with the exact effective time of the existing service-token guard.
/// This is a pure projection; the original guard and parent walk still run once.
pub(super) fn observe_active_token(token: &Token, time: AuthorityTime, consume_check: bool) {
    update(|record| {
        let sample = Sample::capture(Some(token), Some(time), Some(consume_check));
        record.active_check_count = record.active_check_count.saturating_add(1);
        if record.first_active_check.is_none() {
            record.first_active_check = Some(sample);
        }
        record.last_active_check = Some(sample);
    });
}

pub(crate) fn admission_result(status: u16) {
    update(|record| record.admission_status = Some(status));
}

pub(crate) fn owner_entered() {
    update(|record| record.owner_entered = true);
}

pub(crate) fn hook_entered() {
    update(|record| record.hook_entered = true);
}

pub(crate) fn hook_returned() {
    update(|record| record.hook_returned = true);
}
