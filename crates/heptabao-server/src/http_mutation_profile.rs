//! Optional HTTP/1 mutation timing, selected only by a server-process switch.
//!
//! HB_HTTP_MUTATION_PROFILE=1 emits one fixed, numeric response header for a
//! syntactically parsed POST/PUT/DELETE. No request bytes, path, namespace,
//! actor, token, error, absolute timestamp, or identifier enters this module.
//! The header is non-authoritative: it proves neither commit nor delivery.
//! Missing/invalid timing must never authorize a retry. HTTP/2 is not covered.
//!
//! The six durations are queue-to-worker, TLS negotiation, request read/parse,
//! inclusive dispatch, reply preparation/early writes, and accept-to-header.
//! All end before the diagnostic header write. The remaining response write
//! and flush are excluded. The first five are disjoint, with possible gaps;
//! the last is their containing interval and must not be added to them.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const MAX_INTEGER: u128 = (1_u128 << 53) - 1;
const HEADER: &str = "X-HeptaBao-Mutation-Timing";
static NEXT_SAMPLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(super) enum Point {
    TlsStart,
    TlsEnd,
    ReadStart,
    ReadEnd,
    DispatchStart,
    DispatchEnd,
}

struct Observation {
    sample: u64,
    accepted: Instant,
    worker_started: Instant,
    points: [Option<Instant>; 6],
    selected: bool,
    invalid: bool,
    emitted: bool,
}

impl Observation {
    fn values(&self, now: Instant) -> Option<[u64; 6]> {
        if !self.selected || self.invalid || self.emitted {
            return None;
        }
        let points = [
            self.accepted,
            self.worker_started,
            self.points[0]?,
            self.points[1]?,
            self.points[2]?,
            self.points[3]?,
            self.points[4]?,
            self.points[5]?,
            now,
        ];
        if points.windows(2).any(|pair| pair[0] > pair[1]) {
            return None;
        }
        let ranges = [(0, 1), (2, 3), (4, 5), (6, 7), (7, 8), (0, 8)];
        let mut values = [0; 6];
        for (index, (start, end)) in ranges.into_iter().enumerate() {
            let elapsed = points[end]
                .checked_duration_since(points[start])?
                .as_nanos();
            if elapsed > MAX_INTEGER {
                return None;
            }
            values[index] = elapsed as u64;
        }
        Some(values)
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

pub(super) fn enabled() -> bool {
    std::env::var_os("HB_HTTP_MUTATION_PROFILE").as_deref() == Some(OsStr::new("1"))
}

pub(super) struct Scope {
    sample: Option<u64>,
    // Ownership and Drop refer to this thread's ACTIVE slot. Keep future
    // callers from moving this guard to a different request thread.
    _thread_bound: PhantomData<Rc<()>>,
}

impl Scope {
    pub(super) fn begin(enabled: bool, accepted: Instant) -> Self {
        if !enabled {
            return Self {
                sample: None,
                _thread_bound: PhantomData,
            };
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
                accepted,
                worker_started: Instant::now(),
                points: [None; 6],
                selected: false,
                invalid: false,
                emitted: false,
            });
            Some(sample)
        });
        Self {
            sample,
            _thread_bound: PhantomData,
        }
    }

    pub(super) fn point(&self, point: Point) {
        let Some(sample) = self.sample else { return };
        ACTIVE.with(|active| {
            if let Ok(mut slot) = active.try_borrow_mut()
                && let Some(observed) = slot.as_mut()
                && observed.sample == sample
            {
                let entry = &mut observed.points[point as usize];
                if entry.is_some() {
                    observed.invalid = true;
                } else {
                    *entry = Some(Instant::now());
                }
            }
        });
    }

    pub(super) fn select_mutation(&self, selected: bool) {
        let Some(sample) = self.sample else { return };
        ACTIVE.with(|active| {
            if let Ok(mut slot) = active.try_borrow_mut()
                && let Some(observed) = slot.as_mut()
                && observed.sample == sample
            {
                observed.selected = selected;
            }
        });
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some(sample) = self.sample else { return };
        ACTIVE.with(|active| {
            if let Ok(mut slot) = active.try_borrow_mut()
                && slot
                    .as_ref()
                    .is_some_and(|observed| observed.sample == sample)
            {
                *slot = None;
            }
        });
    }
}

/// Build a closed header before touching the existing response writer. A
/// diagnostic arithmetic/borrow/state failure omits it. Once actual bytes are
/// written, a writer failure follows the original I/O/unknown-outcome path;
/// ignoring a partial header write would silently corrupt the response.
pub(super) fn write_header(writer: &mut impl Write) -> io::Result<()> {
    let values = ACTIVE.with(|active| {
        let mut slot = active.try_borrow_mut().ok()?;
        let observed = slot.as_mut()?;
        let values = observed.values(Instant::now())?;
        observed.emitted = true;
        Some(values)
    });
    if let Some([queue, tls, read, dispatch, reply, total]) = values {
        let header = format!("{HEADER}: 1,{queue},{tls},{read},{dispatch},{reply},{total}\r\n");
        writer.write_all(header.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn complete(selected: bool) -> Scope {
        let scope = Scope::begin(true, Instant::now());
        for point in [
            Point::TlsStart,
            Point::TlsEnd,
            Point::ReadStart,
            Point::ReadEnd,
            Point::DispatchStart,
            Point::DispatchEnd,
        ] {
            scope.point(point);
        }
        scope.select_mutation(selected);
        scope
    }

    #[test]
    fn disabled_and_non_mutation_write_nothing() -> TestResult {
        let disabled = Scope::begin(false, Instant::now());
        disabled.select_mutation(true);
        let mut out = Vec::new();
        write_header(&mut out)?;
        assert!(out.is_empty());
        drop(disabled);
        let _scope = complete(false);
        write_header(&mut out)?;
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn complete_is_single_fixed_numeric_header_and_scope_retires() -> TestResult {
        let scope = complete(true);
        let mut out = Vec::new();
        write_header(&mut out)?;
        let first = out.clone();
        write_header(&mut out)?;
        assert_eq!(out, first);
        let line = std::str::from_utf8(&out)?;
        assert!(line.starts_with("X-HeptaBao-Mutation-Timing: 1,"));
        assert!(line.ends_with("\r\n"));
        let numbers: Vec<u64> = line
            .strip_prefix("X-HeptaBao-Mutation-Timing: ")
            .ok_or("fixed mutation timing header prefix")?
            .strip_suffix("\r\n")
            .ok_or("mutation timing header terminator")?
            .split(',')
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()?;
        assert_eq!(numbers.len(), 7);
        assert_eq!(numbers[0], 1);
        assert!(numbers[1..6].iter().sum::<u64>() <= numbers[6]);
        assert!(out.len() <= 176);
        drop(scope);
        let mut after = Vec::new();
        write_header(&mut after)?;
        assert!(after.is_empty());
        Ok(())
    }

    #[test]
    fn incomplete_duplicate_and_nonmonotonic_observations_are_omitted() -> TestResult {
        {
            let scope = Scope::begin(true, Instant::now());
            scope.select_mutation(true);
            let mut out = Vec::new();
            write_header(&mut out)?;
            assert!(out.is_empty());
        }
        {
            let scope = complete(true);
            scope.point(Point::DispatchEnd);
            let mut out = Vec::new();
            write_header(&mut out)?;
            assert!(out.is_empty());
        }
        let _scope = complete(true);
        ACTIVE.with(|slot| -> TestResult {
            slot.borrow_mut()
                .as_mut()
                .ok_or("active timing observation")?
                .accepted = Instant::now() + Duration::from_secs(1);
            Ok(())
        })?;
        let mut out = Vec::new();
        write_header(&mut out)?;
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn nested_scope_does_not_replace_or_retire_original() -> TestResult {
        let original = complete(true);
        let nested = Scope::begin(true, Instant::now());
        nested.point(Point::TlsStart);
        drop(nested);
        let mut out = Vec::new();
        write_header(&mut out)?;
        assert!(!out.is_empty());
        drop(original);
        assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
        Ok(())
    }

    #[test]
    fn observation_does_not_cross_threads() -> TestResult {
        let _scope = complete(true);
        std::thread::spawn(|| -> io::Result<()> {
            let mut out = Vec::new();
            write_header(&mut out)?;
            assert!(out.is_empty());
            Ok(())
        })
        .join()
        .map_err(|_| "observer thread panicked")??;
        let mut out = Vec::new();
        write_header(&mut out)?;
        assert!(!out.is_empty());
        Ok(())
    }

    #[test]
    fn real_writer_failure_remains_original_io_error_without_second_write() -> TestResult {
        struct Fails {
            writes: usize,
            flushes: usize,
        }
        impl Write for Fails {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let _scope = complete(true);
        let mut writer = Fails {
            writes: 0,
            flushes: 0,
        };
        assert_eq!(
            write_header(&mut writer)
                .err()
                .ok_or("original writer error required")?
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 0, "header must not add a flush");
        write_header(&mut writer)?;
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 0, "header must not add a flush");
        Ok(())
    }

    #[test]
    fn exact_numeric_ranges_are_disjoint_inside_the_total() {
        let accepted = Instant::now();
        let t = |offset| accepted + Duration::from_nanos(offset);
        let observed = Observation {
            sample: 1,
            accepted,
            worker_started: t(1),
            points: [
                Some(t(3)),
                Some(t(7)),
                Some(t(9)),
                Some(t(14)),
                Some(t(18)),
                Some(t(29)),
            ],
            selected: true,
            invalid: false,
            emitted: false,
        };
        assert_eq!(observed.values(t(32)), Some([1, 4, 5, 11, 3, 32]));
        assert_eq!(observed.values(t(28)), None);
    }
}
