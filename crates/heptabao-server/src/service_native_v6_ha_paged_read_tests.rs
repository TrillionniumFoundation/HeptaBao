//! Actual local barrier and three-node committed ReadIndex fixtures. The parent
//! uses explicit ciphertext transport; these tests do not claim network HA ACKs.
use super::*;

const PAGED_BYTES: usize = 2 * 1024 * 1024;
const PAGED_PATH: &str = "secret/data/paged-proof";

fn paged_current_fixture() -> TestResult<(Root, Service, Root, Service, Zeroizing<String>, Cluster)>
{
    let (source_files, mut source, _source_key, token) = initialized()?;
    assert_eq!(
        call(
            &mut source,
            "POST",
            PAGED_PATH,
            &token,
            json!({"options":{"cas":0},"data":{"payload":"p".repeat(PAGED_BYTES)}}),
        )
        .status,
        200,
    );
    let (target_files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let prior = source
        .current_state_identity()
        .map_err(|_| "paged source identity")?
        .digest();
    let (cluster, enrollment, index) =
        cluster(&source, &source_files.path.join("paged-proof-raft"))?;
    let (published, _) = publish(&mut source, &cluster, &enrollment, prior, 0, index)?;
    let ha = cluster.processes[1].clone();
    target.ha = Some(ha.clone());
    install_warm(&mut target, &ha, &token)?;
    assert_eq!(
        target
            .current_state_identity()
            .map_err(|_| "paged target identity")?
            .digest(),
        published.root_digest(),
    );
    assert_eq!(
        target
            .native_root
            .as_ref()
            .ok_or("paged native root")?
            .reader_floor
            .native_kv2_format,
        2,
    );
    Ok((source_files, source, target_files, target, token, cluster))
}

fn actual_first_payload_file(service: &mut Service) -> TestResult<PathBuf> {
    let root = service.native_root.as_ref().ok_or("native root")?.clone();
    let deadline = OriginalDeadline::capture()?;
    let durable = service.durable.as_mut().ok_or("durable")?;
    // Fixture discovery authenticates real typed metadata. No fabricated
    // digest, graph or filename is accepted by the production proof below.
    let source = native_blob_source::NativeSource::new_checked(durable, deadline, || Ok(()))?;
    let (_, native) = v6_records::materialize_metadata_for_service(
        &root,
        context(&root).map_err(|_| "typed paged context")?,
        &source,
    )?;
    let mut first = None;
    for (mount, view) in native {
        view.visit_paged_payload_references(
            |reference| {
                if first.is_none() {
                    first = Some((ObjectDomain::Kv2(mount.clone()), reference.clone()));
                }
                Ok(())
            },
            &|| deadline.check().map_err(|_| RecordError::Invalid),
        )?;
    }
    drop(source);
    let (domain, reference) = first.ok_or("actual paged payload reference")?;
    let marker = durable
        .get("system", &v6_records::native_resource(&domain, &reference))?
        .ok_or("actual payload locator")?;
    let bytes = marker.expose();
    if bytes.len() != 72 {
        return Err("fixture payload locator width".into());
    }
    let path = service.data_dir.join(format!(
        "nv6.{}.{}.hbo",
        hex(&bytes[16..32]),
        hex(&bytes[32..64]),
    ));
    assert!(path.is_file());
    Ok(path)
}

fn actual_paged_point_read(service: &mut Service, token: &str) -> TestResult<(bool, u16)> {
    let actual = service.state.as_ref().ok_or("actual native state")?;
    let auth = actual.auth.clone();
    let principal = auth
        .authenticate_read_only(token, 100)?
        .ok_or("actual original principal")?;
    let mut candidate = actual.clone();
    let actor = || authorize(&auth, &principal, PAGED_PATH);
    actor().map_err(|_| "original point-read actor")?;
    let deadline = OriginalDeadline::capture()?;
    let source = native_blob_source::NativeSource::new_checked(
        service.durable.as_mut().ok_or("actual durable")?,
        deadline,
        || actor().map_err(|_| ServiceError::BarrierFailure),
    )?;
    let response = candidate.engines.dispatch_native_paged(
        "",
        "GET",
        PAGED_PATH,
        &json!({"version":1}),
        crate::auth::Timestamp::whole(100)?,
        |mount, reference| source.read_paged_payload(&ObjectDomain::Kv2(mount.clone()), reference),
    );
    drop(source);
    actor().map_err(|_| "original point-read actor after delivery")?;
    Ok(match response {
        Ok(response) => {
            assert_eq!(
                response.body["data"]["data"]["payload"],
                "p".repeat(PAGED_BYTES)
            );
            (true, response.status)
        }
        Err(error) => (false, error.status),
    })
}

#[test]
fn native_ha_paged_request_proof_pins_history_but_point_read_and_cold_load_authenticate_body()
-> TestResult {
    let (_source_files, _source, target_files, mut target, token, _cluster) =
        paged_current_fixture()?;
    let _scope = scope();
    let physical = actual_first_payload_file(&mut target)?;
    assert_eq!(actual_paged_point_read(&mut target, &token)?, (true, 200));
    let root = selected_bytes(&target)?;
    let generation = target.durable.as_ref().ok_or("durable")?.generation();
    let mut damaged = fs::read(&physical)?;
    *damaged.last_mut().ok_or("payload ciphertext")? ^= 1;
    fs::write(&physical, &damaged)?;

    // Same-size corruption proves the warm proof did not decrypt historical
    // JSON. It must still authenticate metadata and open every actual locator.
    let proof = target
        .capture_native_ha_request_proof(&mut || Ok(()))
        .map_err(|_| "actual metadata and locator proof")?
        .ok_or("actual paged proof")?;
    proof
        .check_checked(&mut target, &mut || Ok(()))
        .map_err(|_| "actual metadata and locator proof recheck")?;
    // Exact-current warm synchronization has the same floor2 boundary. It
    // must not overwrite an existing same-sized bad payload from a peer.
    let ha = target.ha.as_ref().ok_or("actual HA")?.clone();
    install_warm(&mut target, &ha, &token)?;
    let (delivered, status) = actual_paged_point_read(&mut target, &token)?;
    assert!(
        !delivered,
        "selected corrupted payload must never be delivered"
    );
    assert!(status >= 400);
    assert_eq!(selected_bytes(&target)?, root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(fs::read(&physical)?, damaged);

    // The request optimization never enters cold recovery. Existing bad bytes
    // still fail full closure authentication and are never overwritten.
    let key = Zeroizing::new(**target.barrier_key.as_ref().ok_or("actual barrier")?);
    drop((proof, target));
    assert!(cold_load(&target_files, &ha, &key).is_err());
    assert_eq!(fs::read(&physical)?, damaged);
    Ok(())
}

#[test]
fn native_ha_paged_request_proof_refuses_missing_truncated_and_aliased_actual_locators()
-> TestResult {
    let (_source_files, _source, _target_files, mut target, token, _cluster) =
        paged_current_fixture()?;
    let _scope = scope();
    let physical = actual_first_payload_file(&mut target)?;
    let original = fs::read(&physical)?;
    let root = selected_bytes(&target)?;
    let generation = target.durable.as_ref().ok_or("durable")?.generation();
    let proof = target
        .capture_native_ha_request_proof(&mut || Ok(()))
        .map_err(|_| "original actual proof")?
        .ok_or("original proof")?;

    fs::write(&physical, &original[..original.len() - 1])?;
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err()
    );
    assert!(proof.check_checked(&mut target, &mut || Ok(())).is_err());
    fs::write(&physical, &original)?;

    let hidden = physical.with_extension("fixture-hidden");
    fs::rename(&physical, &hidden)?;
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err()
    );
    assert!(
        !physical.exists(),
        "request proof must not silently repair missing bytes"
    );
    fs::rename(&hidden, &physical)?;

    #[cfg(unix)]
    {
        let alias = physical.with_extension("fixture-alias");
        fs::hard_link(&physical, &alias)?;
        assert!(
            target
                .capture_native_ha_request_proof(&mut || Ok(()))
                .is_err()
        );
        fs::remove_file(&alias)?;
        fs::rename(&physical, &hidden)?;
        std::os::unix::fs::symlink(&hidden, &physical)?;
        assert!(
            target
                .capture_native_ha_request_proof(&mut || Ok(()))
                .is_err()
        );
        fs::remove_file(&physical)?;
        fs::rename(&hidden, &physical)?;
    }

    proof
        .check_checked(&mut target, &mut || Ok(()))
        .map_err(|_| "original proof after explicit fixture fault removal")?;
    assert_eq!(selected_bytes(&target)?, root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(fs::read(&physical)?, original);

    // A current-root warm sync may repair a genuinely missing payload from the
    // committed shared graph. It still performs full post-repair local graph
    // authentication, with no root or journal publication and no new deadline.
    fs::remove_file(&physical)?;
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err()
    );
    assert!(!physical.exists());
    let ha = target.ha.as_ref().ok_or("actual HA")?.clone();
    install_warm(&mut target, &ha, &token)?;
    assert!(physical.is_file());
    assert_eq!(actual_paged_point_read(&mut target, &token)?, (true, 200));
    proof
        .check_checked(&mut target, &mut || Ok(()))
        .map_err(|_| "original proof after actual committed missing-file repair")?;
    assert_eq!(selected_bytes(&target)?, root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn native_ha_paged_request_proof_retains_original_actor_and_expired_deadline() -> TestResult {
    let (_source_files, _source, _target_files, mut target, _token, _cluster) =
        paged_current_fixture()?;
    let _scope = scope();
    let root = selected_bytes(&target)?;
    let generation = target.durable.as_ref().ok_or("durable")?.generation();
    let mut calls = 0;
    let result = target.capture_native_ha_request_proof(&mut || {
        calls += 1;
        if calls > 1 {
            Err(Response::error(403, "synthetic original Actor revoked"))
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert!(
        calls > 1,
        "the original Actor must be checked within real source custody"
    );
    let proof = target
        .capture_native_ha_request_proof(&mut || Ok(()))
        .map_err(|_| "original live proof")?
        .ok_or("original live proof")?;
    let expired = RequestDeadlineScope::enter(Instant::now());
    assert!(
        target
            .capture_native_ha_request_proof(&mut || Ok(()))
            .is_err()
    );
    assert!(proof.check_checked(&mut target, &mut || Ok(())).is_err());
    assert_eq!(selected_bytes(&target)?, root);
    assert_eq!(
        target.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    drop(expired);
    Ok(())
}

#[test]
fn borrowed_native_request_proof_rejects_seal_change_after_actual_metadata_read() -> TestResult {
    use std::cell::Cell;

    struct HeldSeal {
        original: PathBuf,
        held: PathBuf,
        moved: Cell<bool>,
    }
    impl HeldSeal {
        fn restore(&self) -> std::io::Result<()> {
            if self.moved.get() {
                if self.original.try_exists()? {
                    return Err(std::io::Error::other("fixture seal unexpectedly replaced"));
                }
                fs::rename(&self.held, &self.original)?;
                self.moved.set(false);
            }
            Ok(())
        }
    }
    impl Drop for HeldSeal {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    let (_source_files, _source, _target_files, mut target, token, _cluster) =
        paged_current_fixture()?;
    let until = Instant::now() + REQUEST_BUDGET;
    let _scope = RequestDeadlineScope::enter(until);
    let root_before = selected_bytes(&target)?;
    let identity_before = target
        .current_state_identity()
        .map_err(|_| "original paged identity")?;
    let epoch_before = target.state.as_ref().ok_or("state absent")?.replay_epoch;
    let flags_before = (target.recovery_required, target.audit_failed);
    let nonce_before = Zeroizing::new(target.unseal_nonce.clone());
    let durable_before = {
        let durable = target.durable.as_mut().ok_or("durable absent")?;
        durable.verify_live_ownership()?;
        (
            durable.generation(),
            durable.replay_epoch(),
            durable.recovery_required(),
        )
    };
    let auth = target.state.as_ref().ok_or("state absent")?.auth.clone();
    let principal = auth
        .authenticate_read_only(&token, 100)?
        .ok_or("actual original principal")?;
    let mut original_actor = || authorize(&auth, &principal, PAGED_PATH);
    original_actor().map_err(|_| "original paged actor denied")?;
    let proof = target
        .capture_native_ha_request_proof(&mut original_actor)
        .map_err(|_| "original paged proof refused")?
        .ok_or("original paged proof absent")?;
    let seal = HeldSeal {
        original: target.data_dir.join(SEAL_METADATA_FILE),
        held: target
            .data_dir
            .join("borrowed-request-proof-owned-seal-held"),
        moved: Cell::new(false),
    };
    assert!(fs::symlink_metadata(&seal.original)?.file_type().is_file());
    assert!(!seal.held.try_exists()?);
    let observed = Cell::new(false);
    let mut move_error = None;
    let result = proof.check_with(
        &mut target,
        |installed, metadata, native, root, deadline| {
            original_actor()?;
            Service::check_native_installed(installed, metadata, native, root, deadline)?;
            original_actor()?;
            assert_eq!(deadline.instant(), until);
            assert!(Instant::now() < until);
            assert_eq!(root.reader_floor.native_kv2_format, 2);
            assert!(
                !observed.replace(true),
                "one actual metadata completion boundary only"
            );
            // Real filesystem change after complete metadata materialization and
            // the installed-state comparison. The existing tail gate must refuse;
            // this callback returns success and cannot supply that refusal.
            match fs::rename(&seal.original, &seal.held) {
                Ok(()) => seal.moved.set(true),
                Err(error) => move_error = Some(error),
            }
            Ok(())
        },
    );
    let actually_moved = seal.moved.get();
    seal.restore()?;
    if let Some(error) = move_error {
        return Err(error.into());
    }
    assert!(
        observed.get(),
        "the actual metadata completion callback must execute"
    );
    assert!(actually_moved, "the live seal must actually have moved");
    assert!(
        Instant::now() < until,
        "refusal must occur within the original live request budget"
    );
    let Err(response) = result else {
        return Err("the existing tail gate must reject the missing seal".into());
    };
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
    assert_eq!(selected_bytes(&target)?, root_before);
    assert_eq!(
        target
            .current_state_identity()
            .map_err(|_| "retained paged identity")?,
        identity_before,
    );
    assert_eq!(
        target
            .state
            .as_ref()
            .ok_or("retained state absent")?
            .replay_epoch,
        epoch_before
    );
    assert_eq!(
        (target.recovery_required, target.audit_failed),
        flags_before
    );
    assert!(target.unseal_nonce == *nonce_before);
    let durable = target
        .durable
        .as_mut()
        .ok_or("actual durable was not returned")?;
    assert_eq!(
        (
            durable.generation(),
            durable.replay_epoch(),
            durable.recovery_required()
        ),
        durable_before,
    );
    durable.verify_live_ownership()?;
    assert_eq!(
        (
            durable.generation(),
            durable.replay_epoch(),
            durable.recovery_required()
        ),
        durable_before,
    );
    Ok(())
}
