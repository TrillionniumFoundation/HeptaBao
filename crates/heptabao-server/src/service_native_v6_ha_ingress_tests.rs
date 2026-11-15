//! Real local File Service, actual durable roots and the existing three-Raft
//! fixture. These tests do not qualify physical LAN failover.
use super::*;
use crate::service::native_v6_ha_install::NativeIngressSelectionPermit;

fn bind_fresh(target: &mut Service, label: &str) -> TestResult<NativeIngressSelectionPermit> {
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    target.bind_native_request_failure(label, Some(clock), started, "secret/data/install-history");
    target.arm_native_pre_admission_read(true);
    let binding = target
        .take_native_fresh_ingress_binding()
        .ok_or("actual ingress binding absent")?;
    let ha = target.ha.clone().ok_or("actual HA owner absent")?;
    NativeIngressSelectionPermit::capture(target, binding, &ha)
        .map_err(|_| "actual ingress environment refused".into())
}

fn with_installed(
    check: impl FnOnce(&mut Service, &Arc<Mutex<HaProcess>>, &Path) -> TestResult,
) -> TestResult {
    let (source_files, mut source, _key, token) = initialized()?;
    populate(&mut source, &token, 1);
    let (_files, mut target, _target_key, _target_token) = initialized()?;
    seed_different_local_barrier(&source, &mut target)?;
    let prior = source
        .current_state_identity()
        .map_err(|_| "source identity")?
        .digest();
    let raft_directory = source_files.path.join("fresh-ingress-raft");
    let (cluster, enrollment, index) = cluster(&source, &raft_directory)?;
    publish(&mut source, &cluster, &enrollment, prior, 0, index)?;
    let ha = Arc::clone(&cluster.processes[0]);
    target.ha = Some(Arc::clone(&ha));
    install_warm(&mut target, &ha, &token)?;
    let _scope = scope();
    check(
        &mut target,
        &ha,
        &raft_directory.join("1/native-v6-ciphertext"),
    )
}

#[test]
fn fresh_ingress_permission_is_affine_and_resumed_binding_never_arms() -> TestResult {
    with_installed(|target, _ha, _directory| {
        let started = Instant::now();
        let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
        target.bind_native_request_failure(
            "fresh-only",
            Some(clock),
            started,
            "secret/data/install-history",
        );
        target.arm_native_pre_admission_read(false);
        assert!(
            target.take_native_fresh_ingress_binding().is_none(),
            "resumed request has no new ingress authority"
        );
        target.arm_native_pre_admission_read(true);
        let binding = target
            .take_native_fresh_ingress_binding()
            .ok_or("fresh binding absent")?;
        assert!(
            target.take_native_fresh_ingress_binding().is_none(),
            "one actual binding is issued once"
        );
        let ha = target.ha.clone().ok_or("HA absent")?;
        let permit = NativeIngressSelectionPermit::capture(target, binding, &ha)
            .map_err(|_| "capture failed")?;
        let deadline = OriginalDeadline::capture()?;
        let root = target
            .current_state_identity()
            .map_err(|_| "root absent")?
            .digest();
        permit.check_initial_read(deadline, root)?;
        assert!(
            permit.check_initial_read(deadline, root).is_err(),
            "an initial read is not replayable"
        );
        Ok(())
    })
}

#[test]
fn fresh_ingress_permission_rejects_actual_new_request_nonce_or_selected_root() -> TestResult {
    with_installed(|target, _ha, _directory| {
        let permit = bind_fresh(target, "first-attempt")?;
        let original = target.unseal_nonce.clone();
        target.unseal_nonce.push_str("-different-owner");
        assert!(permit.check(target).is_err());
        target.unseal_nonce = original;
        assert!(
            permit.reselection_is_refused(),
            "restoring the same nonce cannot revive a refused continuation"
        );
        let _next = bind_fresh(target, "second-actual-request")?;
        assert!(
            permit.check(target).is_err(),
            "a newly admitted request cannot revive the old permission"
        );
        let next = bind_fresh(target, "wrong-root-request")?;
        let deadline = OriginalDeadline::capture()?;
        assert!(next.check_initial_read(deadline, [0xff; 32]).is_err());
        assert!(next.reselection_is_refused());
        Ok(())
    })
}

#[test]
fn fresh_ingress_actual_failed_repair_closes_reselection_before_any_result() -> TestResult {
    with_installed(|target, ha, directory| {
        let permit = bind_fresh(target, "actual-repair-entry")?;
        let deadline = OriginalDeadline::capture()?;
        let root = target
            .current_state_identity()
            .map_err(|_| "local root")?
            .digest();
        let process = ha.lock_for_request().map_err(|_| "process lock")?;
        // Remove the actual selected ciphertext manifest, not a test receipt.
        // The original recovery path is allowed to fail because this fixture's
        // ciphertext distribution is explicit setup rather than peer TLS.
        let selected = process
            .native_v6_committed_read(deadline)?
            .ok_or("selected root absent")?;
        let digest = selected.published().intent().closure_manifest_sha256;
        let manifest = directory.join(format!("v6-closure-{}.manifest", hex(&digest)));
        fs::remove_file(&manifest)?;
        let result = process.native_v6_committed_fresh_ingress_read(deadline, root, &permit);
        assert!(
            !matches!(
                result,
                Ok(Some(crate::ha::NativeV6IngressRead::Superseded(_)))
            ),
            "physical failure followed by actual repair cannot create no-effects authority"
        );
        assert!(
            permit.reselection_is_refused(),
            "repair entry or its error must remain sticky"
        );
        Ok(())
    })
}
