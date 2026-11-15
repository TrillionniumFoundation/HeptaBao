//! Focused Rust checks for the production cold timing wrapper.
//! These use the real normal-build observer, but no Service, file, network or
//! Raft fixture. Actual missing-file repair is a separate unchanged test.
use super::{ColdNativeHaPhase, observe_cold_native_ha};
use crate::ha::NativeV6RequestObservation;
use crate::request_deadline::RequestDeadlineScope;
use crate::v6_native_custody::OriginalDeadline;
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug)]
struct OwnedMarker(Box<u64>);

#[test]
fn cold_native_ha_timing_preserves_once_and_owned_result_identity() -> TestResult {
    let until = Instant::now() + Duration::from_secs(8);
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture()?;
    let calls = Cell::new(0);

    // The marker deliberately has no Clone or Copy implementation.
    let value = OwnedMarker(Box::new(71));
    let value_identity = std::ptr::from_ref(value.0.as_ref());
    let result: Result<OwnedMarker, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::LocalSelection, deadline, || {
            calls.set(calls.get() + 1);
            Ok(value)
        });
    let returned = result.map_err(|_| "original success changed without a request observer")?;
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), value_identity);
    assert_eq!(calls.get(), 1);
    assert_eq!(crate::request_deadline::current(), Some(until));

    let observation = NativeV6RequestObservation::start(until, "ordinary", false);
    let error = OwnedMarker(Box::new(72));
    let error_identity = std::ptr::from_ref(error.0.as_ref());
    let result: Result<(), OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::MaterializeFull, deadline, || {
            calls.set(calls.get() + 1);
            Err(error)
        });
    let returned = result
        .err()
        .ok_or("original recoverable error became success")?;
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), error_identity);
    assert_eq!(calls.get(), 2);
    assert_eq!(deadline.instant(), until);
    assert_eq!(crate::request_deadline::current(), Some(until));
    observation.finish(None);
    Ok(())
}

#[test]
fn cold_native_ha_timing_preserves_nested_source_and_inner_results() -> TestResult {
    let until = Instant::now() + Duration::from_secs(8);
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture()?;
    let observation = NativeV6RequestObservation::start(until, "ordinary", false);
    let calls = RefCell::new(Vec::new());

    let error = OwnedMarker(Box::new(73));
    let error_identity = std::ptr::from_ref(error.0.as_ref());
    let result: Result<Result<(), OwnedMarker>, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::ReplicaSource, deadline, || {
            calls.borrow_mut().push("source");
            Ok(observe_cold_native_ha(
                ColdNativeHaPhase::ReplicaInstall,
                deadline,
                || {
                    calls.borrow_mut().push("inner");
                    Err(error)
                },
            ))
        });
    let returned = result
        .map_err(|_| "outer source success became an outer error")?
        .err()
        .ok_or("inner installation error became success")?;
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), error_identity);
    assert_eq!(*calls.borrow(), ["source", "inner"]);

    let source_error = OwnedMarker(Box::new(74));
    let source_error_identity = std::ptr::from_ref(source_error.0.as_ref());
    let result: Result<Result<(), OwnedMarker>, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::RepairSource, deadline, || {
            calls.borrow_mut().push("source_error");
            Err(source_error)
        });
    let returned = result
        .err()
        .ok_or("source acquisition failure became outer success")?;
    assert_eq!(
        std::ptr::from_ref(returned.0.as_ref()),
        source_error_identity
    );
    assert_eq!(*calls.borrow(), ["source", "inner", "source_error"]);

    let value = OwnedMarker(Box::new(75));
    let value_identity = std::ptr::from_ref(value.0.as_ref());
    let result: Result<Result<OwnedMarker, OwnedMarker>, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::RepairSource, deadline, || {
            calls.borrow_mut().push("repair_source");
            Ok(observe_cold_native_ha(
                ColdNativeHaPhase::PhysicalRepair,
                deadline,
                || {
                    calls.borrow_mut().push("repair");
                    Ok(value)
                },
            ))
        });
    let returned = result
        .map_err(|_| "source success became an outer error")?
        .map_err(|_| "inner success became an inner error")?;
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), value_identity);
    assert_eq!(
        *calls.borrow(),
        ["source", "inner", "source_error", "repair_source", "repair"]
    );
    assert_eq!(deadline.instant(), until);
    assert_eq!(crate::request_deadline::current(), Some(until));
    observation.finish(None);
    Ok(())
}
