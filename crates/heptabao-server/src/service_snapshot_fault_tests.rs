//! Real native archive/Service and three-node Raft, not fabricated receipts.
use super::*;
use crate::fixture_native_restore::{NativeRestoreFaultGate, Phase};
use std::os::unix::net::UnixStream;

fn ready(controller: &mut UnixStream) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    controller.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut length = [0_u8; 2];
    controller.read_exact(&mut length)?;
    let count = usize::from(u16::from_be_bytes(length));
    if !(1..=510).contains(&count) {
        return Err("invalid ready frame".into());
    }
    let mut payload = [0_u8; 510];
    controller.read_exact(&mut payload[..count])?;
    Ok(serde_json::from_slice(&payload[..count])?)
}

#[test]
fn native_restore_gate_errors_distinguish_staging_from_accepted_publish() -> TestResult {
    for phase in [Phase::BeforeRootPublish, Phase::AfterRootCommitBeforeLocal] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        write(&mut service, &token, "saved");
        let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
        let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
        service.ha = Some(Arc::clone(&cluster.processes[0]));
        let (gate, mut controller) = NativeRestoreFaultGate::test_pair(phase)?;
        service.native_restore_fault = Some(gate);
        let saved = archive_bytes(&mut service, &token)?;
        // Real changing writes cross the ordinary 64-publication GC cadence;
        // otherwise restore may reuse old archived objects with no Stage.
        for index in 0..66 {
            write(&mut service, &token, &format!("live-{index}"));
        }
        assert!(
            service.native_restore_fault.is_some(),
            "save and ordinary writes must not consume the gate"
        );
        let before = service.current_state_identity().map_err(|_| "identity")?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let local_root = service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?
            .ok_or("local root")?;
        let epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
        let nonce = service.unseal_nonce.clone();
        let worker = std::thread::spawn(move || {
            // Close after the actual ready event to exercise defined gate EOF,
            // not an assumed crash or a synthetic CommitReceipt.
            ready(&mut controller)
        });
        let mut restore = pending(
            &mut service,
            &token,
            "POST",
            Instant::now() + Duration::from_secs(5),
        )?;
        let (result, file) = restore.execute_snapshot_transfer(&mut saved.as_slice());
        assert!(file.is_none());
        let response = service.finish_external_request(*restore, result);
        let observed = worker
            .join()
            .map_err(|_| "controller thread")?
            .map_err(|_| "controller ready")?;
        assert_eq!(response.status, 503);
        assert!(service.native_restore_fault.is_none());
        assert_eq!(observed["pid"], std::process::id());
        assert_eq!(observed["local_generation"], generation);
        assert_eq!(observed["old_root"], hex(&before.digest()));
        assert!(
            observed["stage_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
        assert!(
            observed["stage_index"]
                .as_u64()
                .is_some_and(|index| index > 0)
        );
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            before
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            service
                .durable
                .as_ref()
                .ok_or("durable")?
                .get("system", "state")?
                .ok_or("root")?
                .expose(),
            local_root.expose()
        );
        assert_eq!(service.unseal_nonce, nonce);
        if phase == Phase::BeforeRootPublish {
            assert!(observed["commit_index"].is_null());
            assert!(!service.recovery_required);
            service.sync_from_ha().map_err(|_| "observe old root")?;
            assert_eq!(
                service.current_state_identity().map_err(|_| "identity")?,
                before
            );
            assert_eq!(service.state.as_ref().ok_or("state")?.replay_epoch, epoch);
        } else {
            assert!(observed["commit_index"].as_u64() > observed["stage_index"].as_u64());
            assert!(service.recovery_required);
            assert_eq!(response.body["recovery_required"], true);
            assert_eq!(response.body["retry_allowed"], false);
            drop(service);
            service = root.service()?;
            service.ha = Some(Arc::clone(&cluster.processes[0]));
            assert_eq!(
                call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
                200
            );
            service
                .sync_from_ha()
                .map_err(|_| "recover committed root")?;
            assert_eq!(
                service.state.as_ref().ok_or("state")?.replay_epoch,
                epoch + 1
            );
            assert_eq!(
                hex(&service
                    .current_state_identity()
                    .map_err(|_| "identity")?
                    .digest()),
                observed["new_root"]
            );
        }
        let expected = if phase == Phase::BeforeRootPublish {
            "live-65"
        } else {
            "saved"
        };
        assert_eq!(
            call(
                &mut service,
                "GET",
                "secret/data/ha-snapshot",
                &token,
                json!({})
            )
            .body["data"]["data"]["value"],
            expected
        );
    }
    Ok(())
}

#[test]
fn native_restore_p_release_still_runs_the_original_actor_guard() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "live");
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["root"],"ttl":1}),
    );
    let short = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("short actor")?;
    let actor = service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate(short, 100)
        .map_err(|_| "admit actor")?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let _saved = archive_bytes(&mut service, &token)?;
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let mut candidate = service.state.clone().ok_or("state")?;
    candidate.replay_epoch += 1;
    candidate.engines.handle(
        "",
        "PUT",
        "secret/data/ha-snapshot",
        &json!({"data":{"value":"candidate-not-published"}}),
        100,
    )?;
    let plan = service
        .prepare_record_plan(&candidate)
        .map_err(|_| "plan")?;
    let (gate, mut controller) = NativeRestoreFaultGate::test_pair(Phase::BeforeRootPublish)?;
    let context = crate::fixture_native_restore::NativeRestoreFaultContext::new(
        gate,
        before,
        plan.identity,
        generation,
    );
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed_release = Arc::clone(&released);
    let worker = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let event = ready(&mut controller)?;
            let release = serde_json::to_vec(
                &json!({"version":1,"phase":event["phase"],"nonce":event["nonce"],"action":"release"}),
            )?;
            released.store(true, std::sync::atomic::Ordering::Release);
            controller.write_all(&(release.len() as u16).to_be_bytes())?;
            controller.write_all(&release)?;
            Ok(())
        },
    );
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(5),
    );
    let error = service
        .commit_record_plan_with_before_publish(
            &candidate,
            plan,
            |auth| {
                assert!(observed_release.load(std::sync::atomic::Ordering::Acquire));
                auth.authorize_request(&actor, "", "sys/storage/raft/snapshot", "update", 101)
                    .map_err(|error| Response::error(error.status, &error.message))
            },
            Some(context),
        )
        .err()
        .ok_or("actor rejection lost")?;
    worker
        .join()
        .map_err(|_| "controller thread")?
        .map_err(|_| "release")?;
    assert_eq!(error.status, 403);
    assert!(!service.recovery_required);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}
