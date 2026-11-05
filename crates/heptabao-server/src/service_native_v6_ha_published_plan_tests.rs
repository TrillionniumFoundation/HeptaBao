//! Same-call publisher-plan reuse retains actual three-voter publication and
//! local/ciphertext custody. These are internal invariant and real pipeline
//! tests; they do not claim separate physical hosts or a public client ACK.
use super::*;
use crate::engines::kv2_native_records::PagedPayloadValidationMemo;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

type Frontier = (
    crate::state_record_root::StateIdentity,
    u64,
    u64,
    Vec<Option<Vec<u8>>>,
);

fn frontier(service: &Service) -> TestResult<Frontier> {
    let owner = service
        .durable
        .as_ref()
        .ok_or("actual local owner absent")?;
    let mut values = Vec::new();
    for resource in [
        "state",
        native_v6_reader::ACTIVE_CURSOR_RESOURCE,
        native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
        native_v6_ha_install::HA_CURSOR_RESOURCE,
    ] {
        values.push(
            owner
                .get("system", resource)?
                .map(|value| value.expose().to_vec()),
        );
    }
    Ok((
        service
            .current_state_identity()
            .map_err(|_| "actual local identity")?,
        owner.generation(),
        owner.replay_epoch(),
        values,
    ))
}

#[test]
fn native_ha_published_local_plan_exact_read_rejects_changed_plan_auth_and_source() -> TestResult {
    // Every refusal owns a separate real pipeline. Failed activation is never
    // reset by test metadata, and no rejected plan is retried with a new budget.
    for case in [
        "exact",
        "root_bytes",
        "generation",
        "condition",
        "auth",
        "current_root",
    ] {
        let (pipeline, leader) = setup()?;
        let old_state = pipeline.with_service(leader, |service| {
            Ok(service.state.as_ref().ok_or("actual source state")?.clone())
        })?;
        if case == "auth" {
            expect(pipeline.call(leader, "PUT", "sys/policies/acl/local-plan-proof",
                pipeline.admin(), json!({"policy":"path \"secret/data/plan-proof\" { capabilities = [\"read\"] }"}))?,
                204, "actual changed Auth before local plan")?;
        }
        let service = pipeline.services[leader]
            .as_ref()
            .ok_or("actual service")?
            .clone();
        let ha = pipeline.processes[leader]
            .as_ref()
            .ok_or("actual process")?
            .clone();
        let until = Instant::now() + REQUEST_BUDGET;
        let _scope = RequestDeadlineScope::enter(until);
        let mut writer = lock_until(&service, until).map_err(|_| "original writer lock")?;
        let actual = writer.state.as_ref().ok_or("actual state")?.clone();
        let expected_auth = owner_store::serialize_owner(&actual.auth)?;
        let calls = Cell::new(0usize);
        // This is an internal data invariant probe, not a fabricated HTTP
        // principal. It retains the exact authenticated source Auth throughout.
        let mut original = |auth: &AuthState| -> Result<(), Response> {
            calls.set(calls.get() + 1);
            if Instant::now() >= until
                || owner_store::serialize_owner(auth)
                    .map_err(|_| Response::error(503, "auth encoding"))?
                    .as_slice()
                    != expected_auth.as_slice()
            {
                return Err(Response::error(503, "original source changed"));
            }
            Ok(())
        };
        let mut plan = writer
            .prepare_native_live_root_checked(&actual, &mut original)
            .map_err(|_| "actual current native plan")?;
        let mut installed = writer
            .install_prepared_native_candidate(&plan, &mut original)
            .map_err(|_| "actual typed candidate")?;
        let committed = {
            let process = ha.lock_for_request().map_err(|_| "original process lock")?;
            let read = process
                .native_v6_committed_read_for_local_root(
                    OriginalDeadline::capture()?,
                    plan.root
                        .identity()
                        .map_err(|error| format!("root identity: {error:?}"))?
                        .digest(),
                )?
                .ok_or("actual current native read")?;
            assert_eq!(
                read.published().root_digest(),
                plan.root
                    .identity()
                    .map_err(|error| format!("root identity: {error:?}"))?
                    .digest()
            );
            process.verify_native_v6_committed_read(&read)?;
            read
        };
        match case {
            "root_bytes" => plan.bytes[0] ^= 1,
            "generation" => {
                plan.source_generation = plan
                    .source_generation
                    .checked_add(1)
                    .ok_or("test generation overflow")?
            }
            "condition" => plan.conditions[0].expected = None,
            "auth" => installed.auth = old_state.auth.clone(),
            "current_root" => {
                drop(writer);
                expect(pipeline.call(leader, "POST", "secret/data/pipeline/history", pipeline.admin(),
                    json!({"options":{"cas":1},"data":{"value":"real intervening publication"}}))?,
                    200, "actual intervening root publication")?;
                writer = lock_until(&service, until).map_err(|_| "original writer relock")?;
            }
            "exact" => {}
            _ => return Err("unknown test case".into()),
        }
        let before = frontier(&writer)?;
        let memo = RefCell::new(PagedPayloadValidationMemo::default());
        calls.set(0);
        let result = writer.sync_published_native_v6_local_plan_checked(
            &ha,
            committed,
            &plan,
            &installed,
            &memo,
            &mut original,
        );
        assert!(calls.get() > 0, "the real original source gate must run");
        if case == "exact" {
            assert!(
                result.is_ok(),
                "exact real current plan/read must remain usable"
            );
        } else {
            assert!(result.is_err(), "changed plan/Auth/source must be refused");
        }
        assert!(
            frontier(&writer)? == before,
            "invariant probe must not publish local state or cursors"
        );
        assert!(
            Instant::now() < until,
            "original 15-second invariant budget"
        );
        drop(writer);
        drop(ha);
        drop(service);
    }
    Ok(())
}

#[test]
fn native_ha_published_local_plan_changed_cipher_after_actual_commit_is_unknown() -> TestResult {
    let (mut pipeline, leader) = setup()?;
    let (source, bytes) = fixture(128)?;
    let until = Instant::now() + REQUEST_BUDGET;
    let mut pending = begin(&pipeline, leader, pipeline.admin(), until)?;
    let transfer = pending.execute_native_kv2_large_transfer(&mut &bytes[..]);
    let before = pipeline.with_service(leader, frontier)?;
    let original_identity = before.0;
    let ha = pipeline.processes[leader]
        .as_ref()
        .ok_or("actual publisher process")?
        .clone();
    let directory = pipeline.configs[leader]
        .raft_dir
        .join("native-v6-ciphertext");
    type Damage = (PathBuf, Vec<u8>, crate::state_record_root::StateIdentity);
    let observed: Rc<RefCell<Option<Result<Damage, &'static str>>>> = Rc::new(RefCell::new(None));
    let seen = Rc::clone(&observed);
    // The existing observer fires once after the actual import root commit and
    // original Actor check. We alter one real fixture-owned ciphertext inode;
    // no boolean or synthetic denial stands in for the production file reader.
    let observer =
        native_kv2_large::local_install_observer::arm(move |candidate, original_until| {
            let result = (|| -> TestResult<Damage> {
                assert_eq!(original_until, until);
                assert_ne!(candidate, original_identity);
                let _scope = RequestDeadlineScope::enter(original_until);
                let process = ha
                    .lock_for_request()
                    .map_err(|_| "original actual publisher lock")?;
                let read = process
                    .native_v6_committed_read_for_local_root(
                        OriginalDeadline::capture()?,
                        candidate.digest(),
                    )?
                    .ok_or("actual published import root")?;
                assert_eq!(read.published().root_digest(), candidate.digest());
                process.verify_native_v6_committed_read(&read)?;
                let store = process.native_install_test_store()?;
                let references = store.reopen_root_closure(read.published(), &mut || Ok(()))?;
                let reference = references
                    .first()
                    .ok_or("actual published cipher reference")?;
                let leaf = directory.join(format!("v6-{}.blob", hex(&reference.id)));
                let mut damaged = fs::read(&leaf)?;
                if damaged.is_empty() {
                    return Err("actual cipher leaf empty".into());
                }
                damaged[0] ^= 0x80;
                let mut file = OpenOptions::new().write(true).open(&leaf)?;
                file.write_all(&damaged)?;
                file.sync_all()?;
                Ok((leaf, damaged, candidate))
            })();
            let result = result.map_err(|_| "actual cipher mutation observation failed");
            assert!(
                seen.borrow_mut().replace(result).is_none(),
                "exactly one original import observation"
            );
        });
    let response = finish(&pipeline, leader, *pending, transfer, until)?;
    drop(observer);
    let damage = observed
        .borrow_mut()
        .take()
        .ok_or("actual install observer absent")?;
    let (leaf, damaged, committed) = damage?;
    assert_uncertain_import(&response);
    assert!(
        fs::read(&leaf)? == damaged,
        "existing corrupt HA ciphertext must never be overwritten"
    );
    pipeline.with_service(leader, |service| {
        assert!(
            frontier(service)? == before,
            "post-commit local failure must retain original local root"
        );
        assert!(service.recovery_required && service.ha_activation.is_none());
        Ok(())
    })?;
    assert!(
        Instant::now() < until,
        "corruption never extends the original request deadline"
    );
    pipeline.stop_process(leader)?;
    let successor = pipeline.ready_leader()?;
    assert_ne!(successor, leader);
    assert_eq!(pipeline.native_selection(successor)?.1, committed.digest());
    assert_history(&pipeline, successor, &source)?;
    // The damaged old owner stays closed. Ordinary cold/rejoin success remains
    // covered by the original full34 and lost-delivery tests, unchanged.
    Ok(())
}
