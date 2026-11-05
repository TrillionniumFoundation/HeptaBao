//! Focused Rust checks for the production cold timing wrapper.
//! These use the real normal-build observer, but no Service, file, network or
//! Raft fixture. Actual missing-file repair is a separate unchanged test.
use super::{ColdNativeHaPhase, observe_cold_native_ha};
use crate::ha::NativeV6RequestObservation;
use crate::request_deadline::RequestDeadlineScope;
use crate::v6_native_custody::OriginalDeadline;
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct OwnedMarker(Box<u64>);

#[test]
fn cold_native_ha_timing_preserves_once_and_owned_result_identity() {
    let until = Instant::now() + Duration::from_secs(8);
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture().unwrap();
    let calls = Cell::new(0);

    // The marker deliberately has no Clone or Copy implementation.
    let value = OwnedMarker(Box::new(71));
    let value_identity = std::ptr::from_ref(value.0.as_ref());
    let result: Result<OwnedMarker, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::LocalSelection, deadline, || {
            calls.set(calls.get() + 1);
            Ok(value)
        });
    let returned = result.expect("original success remains success without a request observer");
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
    let returned = result.expect_err("the observer must retain the original recoverable error");
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), error_identity);
    assert_eq!(calls.get(), 2);
    assert_eq!(deadline.instant(), until);
    assert_eq!(crate::request_deadline::current(), Some(until));
    observation.finish(None);
}

#[test]
fn cold_native_ha_timing_preserves_nested_source_and_inner_results() {
    let until = Instant::now() + Duration::from_secs(8);
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture().unwrap();
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
        .expect("outer source success must not become its inner error")
        .expect_err("inner installation error must not become success");
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), error_identity);
    assert_eq!(*calls.borrow(), ["source", "inner"]);

    let source_error = OwnedMarker(Box::new(74));
    let source_error_identity = std::ptr::from_ref(source_error.0.as_ref());
    let result: Result<Result<(), OwnedMarker>, OwnedMarker> =
        observe_cold_native_ha(ColdNativeHaPhase::RepairSource, deadline, || {
            calls.borrow_mut().push("source_error");
            Err(source_error)
        });
    let returned = result.expect_err("source acquisition failure remains the outer error");
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
        .expect("source success remains success")
        .expect("inner success remains success");
    assert_eq!(std::ptr::from_ref(returned.0.as_ref()), value_identity);
    assert_eq!(
        *calls.borrow(),
        ["source", "inner", "source_error", "repair_source", "repair"]
    );
    assert_eq!(deadline.instant(), until);
    assert_eq!(crate::request_deadline::current(), Some(until));
    observation.finish(None);
}
