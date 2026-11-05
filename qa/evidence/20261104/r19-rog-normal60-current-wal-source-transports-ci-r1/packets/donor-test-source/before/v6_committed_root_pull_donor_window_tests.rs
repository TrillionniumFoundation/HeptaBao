//! Actual Raft/pinned-TLS regressions for progress shared across donor windows.
//! The source barrier observes real authenticated requests; it grants no read,
//! publication, deadline, durability, or actor authority.
use super::*;
use std::sync::Condvar;
use std::sync::atomic::AtomicUsize;

const OBJECTS: usize = 24;
const WORKERS_PER_DONOR: usize = 4;

#[derive(Default)]
struct Wave {
    requests: Vec<(u64, [u8; 32])>,
    first: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    released: bool,
}

#[derive(Default)]
struct Observed {
    wave: Mutex<Wave>,
    changed: Condvar,
    stop: AtomicBool,
    finished: AtomicUsize,
}

impl Observed {
    fn object(
        &self,
        donor: u64,
        bytes: &[u8],
        until: Instant,
        silent: bool,
    ) -> Result<(), HaError> {
        if bytes.len() < 36 {
            return Err(HaError::InvalidFrame);
        }
        let id: [u8; 32] = bytes[bytes.len() - 36..bytes.len() - 4]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        let mut wave = self.wave.lock().map_err(|_| HaError::OutcomeUnknown)?;
        wave.requests.push((donor, id));
        if !wave.released {
            wave.first.entry(donor).or_default().insert(id);
            if wave
                .first
                .get(&1)
                .is_some_and(|ids| ids.len() == WORKERS_PER_DONOR)
                && wave
                    .first
                    .get(&2)
                    .is_some_and(|ids| ids.len() == WORKERS_PER_DONOR)
            {
                wave.released = true;
                self.changed.notify_all();
            }
        }
        while (!wave.released || silent) && !self.stop.load(Ordering::Acquire) {
            let remaining = until
                .checked_duration_since(Instant::now())
                .ok_or(HaError::OutcomeUnknown)?;
            let (next, _) = self
                .changed
                .wait_timeout(wave, remaining)
                .map_err(|_| HaError::OutcomeUnknown)?;
            wave = next;
        }
        if self.stop.load(Ordering::Acquire) {
            return Err(HaError::OutcomeUnknown);
        }
        Ok(())
    }
}

struct TwoSources {
    routes: BTreeMap<u64, NodeId>,
    endpoints: BTreeMap<NodeId, TlsPeerEndpoint>,
    observed: Arc<Observed>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl TwoSources {
    fn start(
        fixture: &CurrentClosureFixture<'_>,
        until: Instant,
        first_silent: bool,
    ) -> TestResult<Self> {
        let listeners = (1..=2)
            .map(|id| -> TestResult<_> {
                let listener = Arc::new(TcpListener::bind("127.0.0.1:0")?);
                listener.set_nonblocking(true)?;
                Ok((id, listener))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        let mut routes = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        for id in 1..=3 {
            let route = NodeId::parse(format!("donor-window-voter-{id}"))?;
            let endpoint = TlsPeerEndpoint::new(
                listeners[&if id == 3 { 1 } else { id }].local_addr()?,
                "localhost",
            )?;
            endpoints.insert(route.clone(), endpoint);
            routes.insert(id, route);
        }
        let pinned = Arc::new(PinnedClientCertificateMap::new(
            fixture
                .tls
                .pins
                .iter()
                .map(|(&id, &pin)| Ok((pin, private_peer_name(id)?)))
                .collect::<Result<BTreeMap<_, _>, HaError>>()?,
        )?);
        let observed = Arc::new(Observed::default());
        let sources = (1..=2)
            .map(|donor| -> TestResult<_> {
                Ok((
                    donor,
                    Arc::new(NativeV6CommittedRootSource::new(
                        fixture.nodes[donor as usize - 1].clone(),
                        fixture.runtime.handle().clone(),
                        fixture.stores[donor as usize - 1].clone(),
                        fixture.enrollment,
                    )?),
                ))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        let mut owned = Self {
            routes,
            endpoints,
            observed,
            workers: Vec::new(),
        };
        for (donor, source) in sources {
            for _ in 0..WORKERS_PER_DONOR {
                let source = source.clone();
                let listener = listeners[&donor].clone();
                let pinned = pinned.clone();
                let observed = owned.observed.clone();
                let server = fixture.tls.servers[&donor].clone();
                owned.workers.push(thread::spawn(move || {
                    while !observed.stop.load(Ordering::Acquire) {
                        let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                            break;
                        };
                        let _ = serve_one_mtls_authenticated_peer_frame(
                            &listener,
                            server.clone(),
                            &pinned,
                            remaining.min(Duration::from_secs(8)),
                            false,
                            |frame| {
                                if frame.payload().starts_with(b"HBVP2\x02") {
                                    observed.object(
                                        donor,
                                        frame.payload(),
                                        until.min(frame.deadline()),
                                        first_silent && donor == 1,
                                    )?;
                                }
                                // Every successful reply still comes from the unchanged production
                                // source, including fresh actual ReadIndex and exact leaf checks.
                                source.handle_authenticated(frame)
                            },
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    observed.finished.fetch_add(1, Ordering::AcqRel);
                }));
            }
        }
        Ok(owned)
    }

    fn stop_and_join(&mut self) -> TestResult {
        {
            // Share the wait mutex while changing the predicate so shutdown
            // cannot lose its wake between a worker's check and actual wait.
            let _wave = match self.observed.wave.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.observed.stop.store(true, Ordering::Release);
            self.observed.changed.notify_all();
        }
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        if panicked {
            return Err("actual donor worker panicked".into());
        }
        assert_eq!(
            self.observed.finished.load(Ordering::Acquire),
            2 * WORKERS_PER_DONOR
        );
        Ok(())
    }
}

impl Drop for TwoSources {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run_two_donor_recovery(first_silent: bool) -> TestResult {
    with_current_committed_closure_population(OBJECTS, |fixture| {
        assert_eq!(fixture.references.len(), OBJECTS);
        assert_eq!(blob_count(&fixture.root.0.join("cipher-3"))?, 0);
        assert!(!fixture.nodes[2].local_leader_observation()?.local_is_leader);
        let started = Instant::now();
        let until = started + Duration::from_secs(14);
        let mut sources = TwoSources::start(&fixture, until, first_silent)?;
        let transport = MutualTlsPeerTransport::new(
            sources.endpoints.clone(),
            fixture.tls.clients[&3].clone(),
            Duration::from_secs(14),
        )?;
        let selected = fixture
            .runtime
            .block_on(fixture.nodes[2].native_v6_committed_root_read(until))?
            .ok_or("actual follower root absent")?;
        let generation = selected.application_generation();
        let before_log = fixture
            .runtime
            .block_on(fixture.nodes[2].membership_observation())?
            .applied_index;
        let (recovered, tasks) =
            crate::v6_closure_quorum::committed_pull::observe_pull_tasks(|| {
                recover_native_v6_committed_closure(
                    &fixture.nodes[2],
                    fixture.runtime.handle(),
                    &transport,
                    &sources.routes,
                    &fixture.stores[2],
                    selected,
                )
            })?;
        // Check owned client task cleanup before releasing any silent source handler.
        assert_eq!(tasks.spawned, tasks.joined);
        assert_eq!(tasks.active_frames, 0);
        assert!(tasks.peak_frames <= 8);
        assert!(tasks.per_donor_peak_frames.values().all(|peak| *peak <= 4));
        let recovered = recovered?;
        assert!(Instant::now() < until);
        assert_eq!(recovered.read().operation_deadline(), until);
        assert_eq!(recovered.read().application_generation(), generation);
        assert_eq!(recovered.read().root(), fixture.published);
        assert_eq!(recovered.local_receipt().object_count(), OBJECTS);
        fixture
            .runtime
            .block_on(fixture.nodes[2].verify_native_v6_committed_root_read(recovered.read()))?;
        assert_eq!(
            fixture
                .runtime
                .block_on(fixture.nodes[2].membership_observation())?
                .applied_index,
            before_log
        );
        assert_eq!(
            fixture.stores[2].reopen_root_closure(fixture.published, &mut || Ok(()))?,
            fixture.references
        );
        for reference in fixture.references {
            assert_eq!(
                fixture.stores[2].read_local(reference)?,
                fixture.stores[0].read_local(reference)?
            );
        }
        sources.stop_and_join()?;
        assert!(
            Instant::now() < until,
            "source joins retain the original operation bound"
        );
        let wave = sources
            .observed
            .wave
            .lock()
            .map_err(|_| "source observation poisoned")?;
        let first = wave
            .first
            .get(&1)
            .ok_or("first donor did not receive a full window")?;
        let second = wave
            .first
            .get(&2)
            .ok_or("second donor did not receive a full window")?;
        assert_eq!(first.len(), WORKERS_PER_DONOR);
        assert_eq!(second.len(), WORKERS_PER_DONOR);
        assert!(
            first.is_disjoint(second),
            "healthy windows must advance eight distinct leaves"
        );
        let expected: BTreeSet<_> = fixture
            .references
            .iter()
            .map(|reference| reference.id)
            .collect();
        assert_eq!(
            wave.requests
                .iter()
                .map(|(_, id)| *id)
                .collect::<BTreeSet<_>>(),
            expected
        );
        if first_silent {
            let slow: Vec<_> = wave
                .requests
                .iter()
                .filter(|(donor, _)| *donor == 1)
                .collect();
            let healthy: Vec<_> = wave
                .requests
                .iter()
                .filter(|(donor, _)| *donor == 2)
                .map(|(_, id)| *id)
                .collect();
            assert_eq!(
                slow.len(),
                WORKERS_PER_DONOR,
                "a silent source retains only its original four requests"
            );
            assert_eq!(
                healthy.len(),
                OBJECTS,
                "the healthy source fetches every leaf exactly once"
            );
            assert_eq!(healthy.iter().copied().collect::<BTreeSet<_>>(), expected);
            assert!(
                healthy[healthy.len() - WORKERS_PER_DONOR..]
                    .iter()
                    .all(|id| first.contains(id)),
                "the healthy donor takes over the silent source's unresolved tail"
            );
        } else {
            assert!(
                wave.requests.len() <= OBJECTS + 2 * WORKERS_PER_DONOR,
                "duplicate races are confined to the unresolved tail"
            );
        }
        eprintln!(
            "native two-donor pull: first_silent={first_silent} objects={OBJECTS} requests={} elapsed_ms={} peak_frames={} tasks_joined={} original_budget_ms=14000",
            wave.requests.len(),
            started.elapsed().as_millis(),
            tasks.peak_frames,
            tasks.joined
        );
        Ok(())
    })
}

#[test]
fn committed_root_pull_two_healthy_donors_share_distinct_windows() -> TestResult {
    run_two_donor_recovery(false)
}

#[test]
fn committed_root_pull_silent_object_donor_keeps_capacity_bounded_and_healthy_tail_fallback()
-> TestResult {
    run_two_donor_recovery(true)
}
