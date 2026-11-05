//! Two additional refusal probes over a real activated three-voter Service.
//! They do not change the original snapshot selectors or their denominator.
//! The proof and original Actor are actual owners; the observer changes only
//! a fixture file or waits for real expiry after the complete local graph.
use super::*;
use crate::auth::{AuthorityTime, Principal};
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::rc::Rc;

const SNAPSHOT_PATH: &str = "sys/storage/raft/snapshot";

// Input setup uses the exact private canonical_seal_identity algorithm from
// service_snapshot_transfer.rs, without widening that production helper's
// visibility. Read the real fixture file and compare its live Service owner.
fn live_seal_identity(service: &Service) -> TestResult<[u8; 32]> {
    let seal = load_seal_metadata(&service.data_dir)?.ok_or("live seal absent")?;
    assert!(service.seal.as_ref() == Some(&seal));
    seal.validate()?;
    let associated = seal.associated_data();
    let wrapped = Zeroizing::new(STANDARD.decode(&seal.wrapped_barrier_key)?);
    let mut hash = Sha256::new();
    hash.update(b"heptabao.native-snapshot.seal-metadata.v1\0");
    hash.update((associated.len() as u64).to_le_bytes());
    hash.update(&associated);
    hash.update((wrapped.len() as u64).to_le_bytes());
    hash.update(wrapped.as_slice());
    Ok(hash.finalize().into())
}

fn activated() -> TestResult<(Pipeline, usize)> {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "borrowed-snapshot-actual-activation",
    )?;
    Ok((pipeline, leader))
}

fn authorize(service: &Service, actor: &Principal, clock: RequestClock) -> Result<(), Response> {
    let observed = clock
        .observed_at()
        .map_err(|_| Response::error(503, "snapshot test original clock unavailable"))?;
    service
        .state
        .as_ref()
        .ok_or_else(|| Response::error(503, "snapshot test state unavailable"))?
        .auth
        .authorize_request_observed(
            actor,
            "",
            SNAPSHOT_PATH,
            "read",
            AuthorityTime::Precise(observed),
        )
        .map_err(|error| Response::error(error.status, &error.message))
}

fn actor(service: &Service, token: &str, clock: RequestClock) -> TestResult<Principal> {
    let mut actor = service
        .state
        .as_ref()
        .ok_or("snapshot test state absent")?
        .auth
        .authenticate_read_only_from_observed(
            token,
            AuthorityTime::Precise(clock.observed_at()?),
            None,
        )?
        .ok_or("snapshot test requires an actual unlimited token")?;
    actor.bind_request_clock(Some(clock))?;
    assert!(actor.is_root());
    authorize(service, &actor, clock).map_err(|_| "snapshot actual Actor refused")?;
    Ok(actor)
}

struct RestoreSeal {
    original: PathBuf,
    held: PathBuf,
    moved: Rc<Cell<bool>>,
}

impl RestoreSeal {
    fn restore(&self) -> io::Result<()> {
        if self.moved.get() {
            // Both names are inside this test's owned Service directory. Do
            // not overwrite an unexpected replacement, even during cleanup.
            if self.original.try_exists()? {
                return Err(io::Error::other("fixture seal unexpectedly replaced"));
            }
            fs::rename(&self.held, &self.original)?;
            self.moved.set(false);
        }
        Ok(())
    }
}

impl Drop for RestoreSeal {
    fn drop(&mut self) {
        // Pipeline owns eventual directory cleanup even if an assertion fails.
        let _ = self.restore();
    }
}

#[test]
fn borrowed_snapshot_export_rejects_live_seal_change_after_local_graph() -> TestResult {
    let (pipeline, leader) = activated()?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "snapshot test writer lock")?;
    let actor = actor(&writer, pipeline.admin(), clock)?;
    let source_auth = writer.state.as_ref().ok_or("state absent")?.auth.clone();
    let proof = writer
        .capture_native_ha_request_proof(&mut || {
            source_auth
                .authorize_request_observed(
                    &actor,
                    "",
                    SNAPSHOT_PATH,
                    "read",
                    AuthorityTime::Precise(clock.observed_at().map_err(|_| {
                        Response::error(503, "snapshot test original clock unavailable")
                    })?),
                )
                .map_err(|error| Response::error(error.status, &error.message))
        })
        .map_err(|_| "snapshot actual proof capture refused")?
        .ok_or("snapshot actual proof absent")?;
    let identity = proof.identity();
    let generation = proof.generation();
    let seal_identity = live_seal_identity(&writer)?;
    let flags = (writer.recovery_required, writer.audit_failed);
    let moved = Rc::new(Cell::new(false));
    let seal = RestoreSeal {
        original: writer.data_dir.join(SEAL_METADATA_FILE),
        held: writer.data_dir.join("borrowed-snapshot-owned-seal-held"),
        moved: Rc::clone(&moved),
    };
    assert!(fs::symlink_metadata(&seal.original)?.file_type().is_file());
    assert!(!seal.held.try_exists()?);
    let original = seal.original.clone();
    let held = seal.held.clone();
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let observation =
        proof.observe_snapshot_after_local_graph_once(move |service, selected, original_until| {
            assert_eq!(selected, identity);
            assert_eq!(original_until, until);
            assert!(Instant::now() < until);
            assert_eq!(service.current_state_identity().ok(), Some(identity));
            assert!(!seen.replace(true), "one actual completed local graph only");
            assert!(
                fs::rename(&original, &held).is_ok(),
                "move only fixture-owned seal"
            );
            moved.set(true);
        });
    let directory = pipeline.files.path.join("borrowed-snapshot-seal-spool");
    private_directory(&directory)?;
    let spool = SnapshotSpool::open(&directory)?;
    let lease = spool.lease()?;
    let local = lease.file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, until)?;
    let output = lease.file(crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE, until)?;
    let result =
        proof.export_snapshot_archive(&mut writer, local, output, seal_identity, &mut |service| {
            authorize(service, &actor, clock)
        });
    drop(observation);
    // Return the same inode before asserting, including on an unexpected Ok.
    seal.restore()?;
    assert!(
        observed.get(),
        "the real full local graph must finish first"
    );
    let refusal = match result {
        Ok(_) => return Err("snapshot export accepted a changed live seal".into()),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.status, 503);
    assert!(refusal.body.get("data").is_none());
    assert!(refusal.unwrapped_json.is_none() && refusal.consistency_index.is_none());
    assert!(Instant::now() < until);
    assert_eq!(writer.current_state_identity().ok(), Some(identity));
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("durable not returned")?
            .generation(),
        generation
    );
    assert_eq!((writer.recovery_required, writer.audit_failed), flags);
    // Observe the actual original consensus component without granting local
    // Seal authority. Restoring the inode cannot revive the refused attempt.
    proof
        .observe_snapshot_original_consensus_for_test()
        .map_err(|_| "original consensus witness no longer live")?;
    let refused = proof
        .check_warm(&writer)
        .err()
        .ok_or("restoring the seal revived the refused original proof")?;
    assert_eq!(refused.status, 503);
    authorize(&writer, &actor, clock).map_err(|_| "original Actor no longer live")?;
    drop(writer);
    drop(_scope);

    // A genuinely separate Service request owns its own fresh Actor, clock,
    // physical seal capture and current quorum. Reuse no old proof or memo.
    let fresh_until = Instant::now() + REQUEST_BUDGET;
    let _fresh_scope = RequestDeadlineScope::enter(fresh_until);
    let mut writer = lock_until(service, fresh_until).map_err(|_| "fresh snapshot writer lock")?;
    let mut request = pending(&mut writer, pipeline.admin(), fresh_until)?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    expect(
        writer.finish_external_request(*request, result),
        200,
        "fresh-snapshot-after-original-sticky-refusal",
    )?;
    assert!(file.is_some(), "fresh request must deliver its own archive");
    assert_eq!(
        proof
            .check_warm(&writer)
            .err()
            .ok_or("fresh request revived the refused original proof")?
            .status,
        503
    );
    Ok(())
}

#[test]
fn borrowed_snapshot_export_rejects_real_actor_expiry_after_local_graph() -> TestResult {
    let (pipeline, leader) = activated()?;
    let mut issued = expect(
        pipeline.call(
            leader,
            "POST",
            "auth/token/create",
            pipeline.admin(),
            json!({"policies":["root"],"ttl":"2s","no_default_policy":true,"no_parent":true}),
        )?,
        200,
        "borrowed-snapshot-real-two-second-actor",
    )?;
    let issued_finished = Instant::now();
    let token = secret_field(&mut issued, "/auth/client_token")?;
    let began = Instant::now();
    let until = began + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, began)?;
    let service = pipeline.services[leader].as_ref().ok_or("Service absent")?;
    let mut writer = lock_until(service, until).map_err(|_| "snapshot test writer lock")?;
    // There is one non-cloneable Principal and one original precise clock.
    // Rc permits only sequential shared test observations of that same owner.
    let actor = Rc::new(actor(&writer, &token, clock)?);
    let source_auth = writer.state.as_ref().ok_or("state absent")?.auth.clone();
    let proof = writer
        .capture_native_ha_request_proof(&mut || {
            source_auth
                .authorize_request_observed(
                    &actor,
                    "",
                    SNAPSHOT_PATH,
                    "read",
                    AuthorityTime::Precise(clock.observed_at().map_err(|_| {
                        Response::error(503, "snapshot test original clock unavailable")
                    })?),
                )
                .map_err(|error| Response::error(error.status, &error.message))
        })
        .map_err(|_| "snapshot actual proof capture refused")?
        .ok_or("snapshot actual proof absent")?;
    let identity = proof.identity();
    let generation = proof.generation();
    let seal_identity = live_seal_identity(&writer)?;
    let flags = (writer.recovery_required, writer.audit_failed);
    let observed = Rc::new(Cell::new(false));
    let seen = Rc::clone(&observed);
    let observed_actor = Rc::clone(&actor);
    let observation =
        proof.observe_snapshot_after_local_graph_once(move |service, selected, original_until| {
            assert_eq!(selected, identity);
            assert_eq!(original_until, until);
            assert_eq!(service.current_state_identity().ok(), Some(identity));
            assert!(
                authorize(service, &observed_actor, clock).is_ok(),
                "the same actual two-second Actor must still be live after the local graph"
            );
            assert!(!seen.replace(true), "one actual completed local graph only");
            // Issuance finished after the precise grant began. This wait
            // expires that original grant; it never refreshes or re-anchors it.
            let expired_after = issued_finished + Duration::from_millis(2100);
            thread::sleep(expired_after.saturating_duration_since(Instant::now()));
            assert!(
                Instant::now() < until,
                "the original request is not extended"
            );
        });
    let denied = Cell::new(false);
    let directory = pipeline.files.path.join("borrowed-snapshot-actor-spool");
    private_directory(&directory)?;
    let spool = SnapshotSpool::open(&directory)?;
    let lease = spool.lease()?;
    let local = lease.file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, until)?;
    let output = lease.file(crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE, until)?;
    let result =
        proof.export_snapshot_archive(&mut writer, local, output, seal_identity, &mut |service| {
            let actual = authorize(service, &actor, clock);
            if let Err(refusal) = &actual {
                assert!(
                    observed.get(),
                    "Actor must not expire before the observed boundary"
                );
                assert_eq!(refusal.status, 403);
                denied.set(true);
            }
            actual
        });
    drop(observation);
    assert!(
        observed.get(),
        "the real full local graph must finish first"
    );
    assert!(
        denied.get(),
        "the unchanged next Actor callback must observe real expiry"
    );
    let refusal = match result {
        Ok(_) => return Err("snapshot export accepted an expired original Actor".into()),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.status, 503);
    assert!(refusal.body.get("data").is_none());
    assert!(refusal.unwrapped_json.is_none() && refusal.consistency_index.is_none());
    assert!(Instant::now() < until);
    assert_eq!(writer.current_state_identity().ok(), Some(identity));
    assert_eq!(
        writer
            .durable
            .as_ref()
            .ok_or("durable not returned")?
            .generation(),
        generation
    );
    assert_eq!((writer.recovery_required, writer.audit_failed), flags);
    proof
        .check_warm(&writer)
        .map_err(|_| "original ReadIndex expired instead of Actor")?;
    let actual = authorize(&writer, &actor, clock)
        .err()
        .ok_or("actual Actor did not expire")?;
    assert_eq!(actual.status, 403);
    Ok(())
}

#[path = "service_native_v6_ha_restore_borrowed_tests.rs"]
mod borrowed_historical_tests;
