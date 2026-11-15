//! Optional, non-authoritative measurements of an actual native File clock
//! observation.  No route, request, principal, object identity, bytes, path,
//! absolute timestamp or error text is accepted by this module.
//!
//! HB_NATIVE_FILE_CLOCK_PROFILE=1 enables one bounded public marker per call.
//! Timings overlap (notably AuthGate); they are not additive.  Measurements
//! never replace, refresh or participate in an OriginalDeadline/RequestClock.
//! The total starts after the actual clock was observed and ends before the
//! marker is written. It excludes the KV read, TLS, response and marker I/O.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const ENVIRONMENT: &str = "HB_NATIVE_FILE_CLOCK_PROFILE";
const PREFIX: &str = "HB_NATIVE_FILE_CLOCK_PROFILE ";
static NEXT_SAMPLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Candidate,
    DeltaValidation,
    Plan,
    Install,
    ObjectStage,
    LocatorPublication,
    RootPublication,
    DurableReadback,
    AuthGate,
}

const PHASES: [(Phase, &str); 9] = [
    (Phase::Candidate, "candidate"),
    (Phase::DeltaValidation, "delta_validation"),
    (Phase::Plan, "plan"),
    (Phase::Install, "install"),
    (Phase::ObjectStage, "object_stage"),
    (Phase::LocatorPublication, "locator_publication"),
    (Phase::RootPublication, "root_publication"),
    (Phase::DurableReadback, "durable_readback"),
    (Phase::AuthGate, "auth_gate"),
];

#[derive(Clone)]
struct Observation {
    sample: u64,
    started: Instant,
    returned_ok: bool,
    entered: [u64; 9],
    elapsed_ns: [u64; 9],
    object_attempts: u64,
    object_completions: u64,
}

impl Observation {
    fn public_marker(&self) -> String {
        let mut out = String::with_capacity(1200);
        let _ = write!(
            out,
            "{PREFIX}{{\"schema\":\"heptabao.native-file-clock-profile.v1\",\"sample\":{},\"returned_ok\":{},\"total_ns\":{},\"object_attempts\":{},\"object_completions\":{},\"phases\":{{",
            self.sample,
            self.returned_ok,
            nanos(self.started),
            self.object_attempts,
            self.object_completions,
        );
        for (index, (phase, name)) in PHASES.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            let position = *phase as usize;
            let _ = write!(
                out,
                "\"{name}\":{{\"calls\":{},\"ns\":{}}}",
                self.entered[position], self.elapsed_ns[position],
            );
        }
        out.push_str("}}");
        out
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

fn nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

pub(crate) struct Scope {
    sample: Option<u64>,
}

impl Scope {
    pub(crate) fn begin(native_file: bool) -> Self {
        Self::begin_enabled(
            native_file && std::env::var_os(ENVIRONMENT).as_deref() == Some(OsStr::new("1")),
        )
    }

    fn begin_enabled(enabled: bool) -> Self {
        if !enabled {
            return Self { sample: None };
        }
        let sample = ACTIVE.with(|active| {
            let mut slot = active.try_borrow_mut().ok()?;
            if slot.is_some() {
                return None;
            }
            let sample = NEXT_SAMPLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .ok()?;
            *slot = Some(Observation {
                sample,
                started: Instant::now(),
                returned_ok: false,
                entered: [0; 9],
                elapsed_ns: [0; 9],
                object_attempts: 0,
                object_completions: 0,
            });
            Some(sample)
        });
        Self { sample }
    }

    pub(crate) fn returned_ok(&self) {
        if let Some(sample) = self.sample {
            ACTIVE.with(|active| {
                if let Ok(mut slot) = active.try_borrow_mut()
                    && let Some(observed) = slot.as_mut()
                    && observed.sample == sample
                {
                    observed.returned_ok = true;
                }
            });
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some(sample) = self.sample else {
            return;
        };
        let observed = ACTIVE.with(|active| {
            let mut slot = active.try_borrow_mut().ok()?;
            if slot
                .as_ref()
                .is_some_and(|observed| observed.sample == sample)
            {
                slot.take()
            } else {
                None
            }
        });
        if let Some(observed) = observed {
            // A diagnostics sink error must not alter a business outcome.
            let _ = writeln!(std::io::stderr().lock(), "{}", observed.public_marker());
        }
    }
}

pub(crate) struct Span {
    phase: Phase,
    sample: Option<(u64, Instant)>,
}

impl Span {
    pub(crate) fn begin(phase: Phase) -> Self {
        let sample = ACTIVE.with(|active| {
            let slot = active.try_borrow().ok()?;
            Some((slot.as_ref()?.sample, Instant::now()))
        });
        Self { phase, sample }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let Some((sample, started)) = self.sample else {
            return;
        };
        let elapsed = nanos(started);
        ACTIVE.with(|active| {
            if let Ok(mut slot) = active.try_borrow_mut()
                && let Some(observed) = slot.as_mut()
                && observed.sample == sample
            {
                let index = self.phase as usize;
                observed.entered[index] = observed.entered[index].saturating_add(1);
                observed.elapsed_ns[index] = observed.elapsed_ns[index].saturating_add(elapsed);
            }
        });
    }
}

pub(crate) fn object_attempt() {
    ACTIVE.with(|active| {
        if let Ok(mut slot) = active.try_borrow_mut()
            && let Some(observed) = slot.as_mut()
        {
            observed.object_attempts = observed.object_attempts.saturating_add(1);
        }
    });
}

pub(crate) fn object_completed() {
    ACTIVE.with(|active| {
        if let Ok(mut slot) = active.try_borrow_mut()
            && let Some(observed) = slot.as_mut()
        {
            observed.object_completions = observed.object_completions.saturating_add(1);
        }
    });
}

#[cfg(test)]
#[path = "service_native_file_clock_profile_actual_tests.rs"]
mod actual_tests;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn snapshot() -> Option<Observation> {
        ACTIVE.with(|active| active.borrow().clone())
    }

    #[test]
    fn disabled_sampling_has_no_active_measurements() {
        let scope = Scope::begin_enabled(false);
        let span = Span::begin(Phase::Plan);
        object_attempt();
        object_completed();
        scope.returned_ok();
        drop(span);
        assert!(snapshot().is_none());
    }

    #[test]
    fn records_actual_phase_entries_and_partial_object_progress() -> TestResult {
        let scope = Scope::begin_enabled(true);
        for _ in 0..3 {
            let _span = Span::begin(Phase::AuthGate);
        }
        object_attempt();
        object_completed();
        object_attempt();
        let observed = snapshot().ok_or("active sample")?;
        assert_eq!(observed.entered[Phase::AuthGate as usize], 3);
        assert_eq!(observed.object_attempts, 2);
        assert_eq!(observed.object_completions, 1);
        assert!(!observed.returned_ok);
        scope.returned_ok();
        assert!(snapshot().ok_or("active sample")?.returned_ok);
        Ok(())
    }

    #[test]
    fn nested_scope_does_not_replace_parent_observation() -> TestResult {
        let outer = Scope::begin_enabled(true);
        let sample = snapshot().ok_or("outer sample")?.sample;
        let nested = Scope::begin_enabled(true);
        nested.returned_ok();
        drop(nested);
        assert_eq!(snapshot().ok_or("parent preserved")?.sample, sample);
        assert!(!snapshot().ok_or("parent preserved")?.returned_ok);
        outer.returned_ok();
        Ok(())
    }

    #[test]
    fn old_span_cannot_pollute_a_later_scope() -> TestResult {
        let first = Scope::begin_enabled(true);
        let stale = Span::begin(Phase::Plan);
        drop(first);
        let _second = Scope::begin_enabled(true);
        drop(stale);
        assert_eq!(
            snapshot().ok_or("second scope")?.entered[Phase::Plan as usize],
            0
        );
        Ok(())
    }

    #[test]
    fn measurements_remain_local_to_original_thread() -> TestResult {
        let _scope = Scope::begin_enabled(true);
        std::thread::spawn(|| {
            let _span = Span::begin(Phase::Plan);
            object_attempt();
            assert!(snapshot().is_none());
        })
        .join()
        .map_err(|_| "observer thread panicked")?;
        let observed = snapshot().ok_or("parent scope")?;
        assert_eq!(observed.entered[Phase::Plan as usize], 0);
        assert_eq!(observed.object_attempts, 0);
        Ok(())
    }

    #[test]
    fn public_projection_is_fixed_and_bounded_even_at_counter_limit() {
        let observed = Observation {
            sample: u64::MAX,
            started: Instant::now(),
            returned_ok: false,
            entered: [u64::MAX; 9],
            elapsed_ns: [u64::MAX; 9],
            object_attempts: u64::MAX,
            object_completions: u64::MAX,
        };
        let marker = observed.public_marker();
        assert!(marker.starts_with(PREFIX));
        assert!(marker.len() < 1600);
        assert!(!marker.contains("route"));
        assert!(!marker.contains("token"));
        assert!(!marker.contains("path"));
        assert!(!marker.contains("error"));
        assert!(marker.ends_with("}}"));
    }
}
