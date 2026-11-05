//! Actual formal file profile and real barrier journals; no fixture selector,
//! provider, production path, business-mount workaround or native guard skip.
use super::*;
use crate::service::tests::Root;
use heptabao_durable_service::{BackendBundle, BackendError, DurableBackend};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ACTIVATE: &str = "sys/storage/native-v6/activate";

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let nonce = Zeroizing::new(hex(&crypto::random::<32>()?));
    let mut response = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({
            "secret_shares":1,"secret_threshold":1,"recovery_nonce":nonce.as_str()
        }),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["init_ack_required"], true);
    let key = Zeroizing::new(
        response.body["keys"][0]
            .as_str()
            .ok_or("Shamir share")?
            .to_owned(),
    );
    let admin = Zeroizing::new(
        response.body["root_token"]
            .as_str()
            .ok_or("root token")?
            .to_owned(),
    );
    erase_json(&mut response.body);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", &admin, json!({})).status,
        204
    );
    assert!(!initialization_recovery_pending(&service.data_dir)?);
    assert!(service.record_root.is_none() && service.native_root.is_none());
    assert!(matches!(
        service
            .current_state_identity()
            .map_err(|_| "legacy identity")?,
        StateIdentity::Legacy(_)
    ));
    Ok((files, service, key, admin))
}

fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(!service.recovery_required);
    Ok(service)
}

fn owner_bytes(state: &State) -> TestResult<[Zeroizing<Vec<u8>>; 5]> {
    Ok([
        owner_store::serialize_owner(&state.namespaces)?,
        owner_store::serialize_owner(&state.auth)?,
        owner_store::serialize_owner(&state.engines)?,
        owner_store::serialize_owner(&state.database)?,
        owner_store::serialize_owner(&state.raft_admin)?,
    ])
}

fn actor(service: &Service, admin: &str) -> TestResult<(Principal, u64)> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let principal = service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .authenticate_read_only(admin, now)?
        .ok_or("actual root actor")?;
    assert!(principal.is_root());
    Ok((principal, now))
}

fn publish_as_root(
    proof: LegacySourcePromotion,
    service: &mut Service,
    admin: &str,
) -> Result<(), Response> {
    let (principal, now) = actor(service, admin).map_err(|_| rejected())?;
    proof.publish(service, &mut |auth| {
        auth.authorize_request_parameters(&principal, "", "POST", ACTIVATE, &json!({}), now)
            .map_err(|error| Response::error(error.status, &error.message))
    })
}

#[test]
fn formal_freshfile_without_business_writes_activates_floor2_and_cold_opens() -> TestResult {
    let (files, mut service, key, admin) = initialized()?;
    let mounts = call(&mut service, "GET", "sys/mounts", &admin, json!({}));
    assert_eq!(mounts.status, 200);
    // The public API always exposes these three built-in control mounts.
    // Prove there is no business mount instead of requiring an impossible
    // empty public listing, then retain the exact listing across cold reopen.
    assert_eq!(
        mounts.body["data"]
            .as_object()
            .ok_or("mount listing")?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["cubbyhole/", "identity/", "sys/"]
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .namespace_is_empty("")
    );
    assert!(service.record_root.is_none());
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    assert_eq!(
        service.capacity_response("GET", &json!({})).body["data"]["profile"],
        "bounded-native-record-state-v6-paged"
    );
    let retained = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", ACTIVE_SOURCE_ROOT_RESOURCE)?
        .ok_or("real V5 checkpoint")?;
    assert!(
        records::decode_root(retained.expose())
            .map_err(|_| "typed V5")?
            .is_some()
    );
    let warm_identity = service
        .current_state_identity()
        .map_err(|_| "warm identity")?;
    for path in ["sys/mounts", "sys/mounts/", "sys/auth", "sys/auth/"] {
        let response = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(
            response.status,
            200,
            "warm catalog {path}: {:?}",
            response.body.get("errors")
        );
    }
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "warm identity after reads")?,
        warm_identity
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("cold native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    assert!(service.record_root.is_none());
    let cold_mounts = call(&mut service, "GET", "sys/mounts", &admin, json!({}));
    assert_eq!(
        cold_mounts.status,
        200,
        "cold catalog: {:?}",
        cold_mounts.body.get("errors")
    );
    assert_eq!(cold_mounts.body["data"], mounts.body["data"]);
    for path in ["sys/mounts/", "sys/auth", "sys/auth/"] {
        let response = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(
            response.status,
            200,
            "cold catalog {path}: {:?}",
            response.body.get("errors")
        );
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("cold state")?
            .engines
            .namespace_is_empty("")
    );
    Ok(())
}

#[test]
fn formal_native_metadata_reads_require_original_acl_after_cold_reopen() -> TestResult {
    fn token(service: &mut Service, admin: &str, policy: &str) -> TestResult<Zeroizing<String>> {
        let mut response = call(
            service,
            "POST",
            "auth/token/create",
            admin,
            json!({"policies":[policy], "ttl":"10m"}),
        );
        assert_eq!(response.status, 200);
        let token = Zeroizing::new(
            response.body["auth"]["client_token"]
                .as_str()
                .ok_or("actual catalog token")?
                .to_owned(),
        );
        erase_json(&mut response.body);
        Ok(token)
    }
    let (files, mut service, key, admin) = initialized()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    let denied = token(&mut service, &admin, "default")?;
    for path in ["sys/mounts", "sys/auth"] {
        let response = call(&mut service, "GET", path, &denied, json!({}));
        assert_eq!(response.status, 403);
        assert!(response.body.get("data").is_none());
        assert_eq!(call(&mut service, "GET", path, "", json!({})).status, 403);
    }
    assert_eq!(call(&mut service, "POST", "sys/policies/acl/catalog-reader", &admin,
        json!({"policy": "path \"sys/mounts\" { capabilities = [\"read\"] }\npath \"sys/auth\" { capabilities = [\"read\"] }"})).status, 204);
    let reader = token(&mut service, &admin, "catalog-reader")?;
    for path in ["sys/mounts", "sys/auth"] {
        let expected = call(&mut service, "GET", path, &admin, json!({}));
        assert_eq!(expected.status, 200);
        let response = call(&mut service, "GET", path, &reader, json!({}));
        assert_eq!(
            response.status,
            200,
            "authorized catalog {path}: {:?}",
            response.body.get("errors")
        );
        assert_eq!(response.body["data"], expected.body["data"]);
    }
    drop(service);
    let mut service = reopen(&files, &key)?;
    for path in ["sys/mounts", "sys/auth"] {
        assert_eq!(
            call(&mut service, "GET", path, &denied, json!({})).status,
            403
        );
        let response = call(&mut service, "GET", path, &reader, json!({}));
        assert_eq!(
            response.status,
            200,
            "cold authorized catalog {path}: {:?}",
            response.body.get("errors")
        );
    }
    Ok(())
}

#[test]
fn formal_auth_only_promotion_preserves_all_five_owners_identity_and_finite_uses() -> TestResult {
    let (files, mut service, key, admin) = initialized()?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    // Historical V4 Auth-owner fixture: real Auth domain methods and the
    // existing V4 publisher precede today's generic dispatch upgrade. This
    // component case is not public response-delivery qualification.
    let (principal, now) = actor(&service, &admin)?;
    let mut historical = service.state.as_ref().ok_or("state")?.clone();
    let mut issued = historical
        .auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"],"ttl":"1h","num_uses":3}),
            now,
        )?
        .ok_or("Auth issuance")?;
    assert_eq!(issued.status, 200);
    let child = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("finite token")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    let child_principal = historical.auth.authenticate(&child, now)?;
    assert_eq!(
        historical
            .auth
            .handle(
                Some(&child_principal),
                "",
                "POST",
                "cubbyhole/private",
                &json!({"value":"retained-auth-owner"}),
                now
            )?
            .ok_or("historical cubbyhole route")?
            .status,
        204
    );
    historical.schema = historical.writer_schema();
    service
        .commit_state(&mut historical)
        .map_err(|_| "historical V4 Auth publication")?;
    service.state = Some(historical);
    assert!(
        service.record_root.is_none(),
        "historical Auth fixture has no engine record source"
    );
    let original_identity = service.current_state_identity().map_err(|_| "identity")?;
    let before = owner_bytes(service.state.as_ref().ok_or("state")?)?;
    let proof = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
        .map_err(|_| "prepare")?;
    assert_eq!(proof.source_identity, original_identity);
    assert_eq!(
        crypto::digest(&owner_store::serialize_owner(
            service.state.as_ref().ok_or("state")?
        )?),
        original_identity.digest()
    );
    let projected = owner_bytes(&proof.candidate)?;
    for (actual, expected) in projected.iter().zip(&before) {
        assert!(
            actual.as_slice() == expected.as_slice(),
            "format promotion changed an actual source owner"
        );
    }
    publish_as_root(proof, &mut service, &admin).map_err(|_| "publish")?;
    assert!(service.record_root.is_some() && service.native_root.is_none());
    let reopened_owners = owner_bytes(service.state.as_ref().ok_or("reopened V5 state")?)?;
    for (actual, expected) in reopened_owners.iter().zip(&before) {
        assert!(actual.as_slice() == expected.as_slice());
    }
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    for expected in [200, 200, 403] {
        let mut response = call(&mut service, "GET", "cubbyhole/private", &child, json!({}));
        assert_eq!(response.status, expected);
        if expected == 200 {
            assert_eq!(response.body["data"]["value"], "retained-auth-owner");
        }
        erase_json(&mut response.body);
    }
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        call(&mut service, "GET", "cubbyhole/private", &child, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn source_promotion_rejects_each_corrupt_actual_owner_and_detached_warm_state() -> TestResult {
    for owner in crate::state_record_root::OWNER_NAMES {
        let (_files, mut service, _key, _admin) = initialized()?;
        let durable = service.durable.as_mut().ok_or("durable")?;
        let source = durable.get("system", "state")?.ok_or("manifest")?;
        let manifest = owner_store::decode_manifest(source.expose())?.ok_or("V4")?;
        let resource = manifest.chunk_resource(owner, 0)?;
        durable.apply_batch_in_replay_epoch(
            durable.replay_epoch(),
            "owned-corruption-test",
            "system",
            format!("corrupt-{owner}"),
            [7; 32],
            vec![(
                resource,
                Some(Secret::new(b"corrupt-owned-test-chunk".to_vec())?),
            )],
        )?;
        let generation = durable.generation();
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        assert!(
            LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?).is_err()
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert!(service.record_root.is_none() && service.native_root.is_none());
    }
    let (_files, mut service, _key, _admin) = initialized()?;
    service
        .state
        .as_mut()
        .ok_or("state")?
        .cluster_id
        .push_str("-detached-warm-candidate");
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    assert!(LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?).is_err());
    Ok(())
}

#[test]
fn source_promotion_rejects_replaced_manifest_and_does_not_accept_fixture_selector() -> TestResult {
    let (_files, mut service, _key, admin) = initialized()?;
    let (_other_files, other, _other_key, _other_admin) = initialized()?;
    let other_source = other
        .durable
        .as_ref()
        .ok_or("other durable")?
        .get("system", "state")?
        .ok_or("other manifest")?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let proof = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
        .map_err(|_| "prepare")?;
    let durable = service.durable.as_mut().ok_or("durable")?;
    assert_ne!(
        durable.get("system", "state")?.ok_or("source")?.expose(),
        other_source.expose()
    );
    durable.apply_batch_in_replay_epoch(
        durable.replay_epoch(),
        "owned-replacement-test",
        "system",
        "replace-source",
        [8; 32],
        vec![("state".into(), Some(other_source))],
    )?;
    let generation = durable.generation();
    assert!(publish_as_root(proof, &mut service, &admin).is_err());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(service.record_root.is_none() && service.native_root.is_none());
    let (_files, mut service, _key, _admin) = initialized()?;
    service.native_storage_profile = None; // retain captured internal fixture-shaped owner only
    assert!(service.native_candidate_profile.is_some());
    assert!(LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?).is_err());
    Ok(())
}

#[test]
fn source_promotion_preserves_actual_opaque_capacity_before_any_append() -> TestResult {
    let (_files, mut service, _key, _admin) = initialized()?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let journal = fs::read(service.data_dir.join("journal.hbj"))?;
    service.state_capacity = 1;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let refusal = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
        .err()
        .ok_or("unchanged capacity must refuse source promotion")?;
    assert_eq!(refusal.status, 507);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(fs::read(service.data_dir.join("journal.hbj"))?, journal);
    assert!(service.record_root.is_none() && service.native_root.is_none());
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn source_promotion_original_expired_budget_cannot_be_extended_before_append() -> TestResult {
    let (_files, mut service, _key, admin) = initialized()?;
    // This isolated negative fault makes the captured original expire. The
    // real activation helper and all successful requests retain their 15s cap.
    let until = Instant::now() + Duration::from_millis(500);
    let original = crate::request_deadline::RequestDeadlineScope::enter(until);
    let proof = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
        .map_err(|_| "prepare")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    drop(original);
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(5));
    let _later = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    assert!(publish_as_root(proof, &mut service, &admin).is_err());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(service.record_root.is_none() && service.native_root.is_none());
    Ok(())
}

// Observe the exact barrier-authenticated transaction ID and event tag only
// after the owned FileBackend's real append+fsync succeeds. No frame is replayed
// and no backend OutcomeUnknown error is converted into an acknowledgement.
#[derive(Clone, Copy)]
enum AckFault {
    None,
    LostApply,
    LateApply(Instant),
}
struct PromotionJournal {
    inner: heptabao_durable_service::FileBackend,
    barrier: AeadBarrier,
    trace: Arc<Mutex<Vec<u8>>>,
    fault: AckFault,
}
impl PromotionJournal {
    fn selected_tag(&self, frame: &[u8]) -> Result<Option<u8>, BackendError> {
        let invalid = || BackendError::OutcomeUnknown;
        let u32_at = |offset: usize| -> Result<usize, BackendError> {
            Ok(u32::from_le_bytes(
                frame
                    .get(offset..offset + 4)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize)
        };
        if frame.len().checked_sub(4) != Some(u32_at(0)?) {
            return Err(invalid());
        }
        let protected_end = 16usize.checked_add(u32_at(12)?).ok_or_else(invalid)?;
        if protected_end.checked_add(32) != Some(frame.len()) {
            return Err(invalid());
        }
        let mut context = b"heptabao.durable-service.journal.v2".to_vec();
        context.extend_from_slice(frame.get(4..12).ok_or_else(invalid)?);
        let plain = Zeroizing::new(
            heptabao_durable_service::Barrier::open(
                &self.barrier,
                &context,
                frame.get(16..protected_end).ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?,
        );
        let tag = *plain.first().ok_or_else(invalid)?;
        if !matches!(tag, 1 | 2 | 5) {
            return Ok(None);
        }
        let mut offset = 1usize;
        for number in 0..3 {
            let length_end = offset.checked_add(4).ok_or_else(invalid)?;
            let length = u32::from_le_bytes(
                plain
                    .get(offset..length_end)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize;
            let end = length_end.checked_add(length).ok_or_else(invalid)?;
            let field = std::str::from_utf8(plain.get(length_end..end).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if number == 2
                && (!field.starts_with("native6-source-promotion-") || !field.ends_with("-root"))
            {
                return Ok(None);
            }
            offset = end;
        }
        Ok(Some(tag))
    }
}
impl DurableBackend for PromotionJournal {
    fn verify(&self) -> Result<(), BackendError> {
        self.inner.verify()
    }
    fn verify_live_ownership(&mut self) -> Result<(), BackendError> {
        self.inner.verify_live_ownership()
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.inner.load()
    }
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(initial)
    }
    fn append_journal(&mut self, expected: usize, frame: &[u8]) -> Result<usize, BackendError> {
        let written = self.inner.append_journal(expected, frame)?;
        if let Some(tag) = self.selected_tag(frame)? {
            self.trace
                .lock()
                .map_err(|_| BackendError::OutcomeUnknown)?
                .push(tag);
            match (self.fault, tag) {
                (AckFault::LostApply, 5) => return Err(BackendError::OutcomeUnknown),
                (AckFault::LateApply(until), 5) => std::thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                ),
                _ => {}
            }
        }
        Ok(written)
    }
    fn truncate_journal(&mut self, expected: usize, new: usize) -> Result<(), BackendError> {
        self.inner.truncate_journal(expected, new)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.publish_checkpoint(expected, replacement)
    }
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}
fn install_journal_observation(
    service: &mut Service,
    fault: AckFault,
) -> TestResult<Arc<Mutex<Vec<u8>>>> {
    let barrier = Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier")?);
    drop(service.durable.take().ok_or("durable owner")?);
    let trace = Arc::new(Mutex::new(Vec::new()));
    let backend = PromotionJournal {
        inner: heptabao_durable_service::FileBackend::open(&service.data_dir)?,
        barrier: AeadBarrier::new(*barrier)?,
        trace: Arc::clone(&trace),
        fault,
    };
    service.durable = Some(DurableService::reopen_with_backend(
        Box::new(backend) as Box<dyn DurableBackend>,
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?);
    Ok(trace)
}

#[test]
fn source_promotion_gate_after_each_actual_append_keeps_exact_cold_transaction_prefix() -> TestResult
{
    for (stop_after, expected_trace, is_v5) in [
        (1, vec![1], false),
        (5, vec![1, 5], true),
        (2, vec![1, 5, 2], true),
    ] {
        let (files, mut service, key, admin) = initialized()?;
        let source = service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?
            .ok_or("V4 source")?;
        let trace = install_journal_observation(&mut service, AckFault::None)?;
        let _original = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let proof = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
            .map_err(|_| "prepare")?;
        let expected_v5 = proof.plan.bytes.clone();
        let (principal, now) = actor(&service, &admin)?;
        let response = proof
            .publish(&mut service, &mut |auth| {
                auth.authorize_request_parameters(
                    &principal,
                    "",
                    "POST",
                    ACTIVATE,
                    &json!({}),
                    now,
                )
                .map_err(|error| Response::error(error.status, &error.message))?;
                if trace.lock().map_err(|_| rejected())?.last() == Some(&stop_after) {
                    return Err(Response::error(
                        403,
                        "owned fixture authority refused after observed append",
                    ));
                }
                Ok(())
            })
            .err()
            .ok_or("phase gate must fail")?;
        assert_eq!(response.status, 503);
        assert!(response.body["recovery_reference"].as_str().is_some());
        assert!(service.recovery_required && service.native_root.is_none());
        assert_eq!(*trace.lock().map_err(|_| "trace")?, expected_trace);
        drop(service);
        let service = reopen(&files, &key)?;
        let current = service
            .durable
            .as_ref()
            .ok_or("cold durable")?
            .get("system", "state")?
            .ok_or("cold root")?;
        assert!(
            service.native_root.is_none(),
            "neither cold recovery nor a lost response may replay V6 activation"
        );
        if is_v5 {
            assert!(service.record_root.is_some());
            assert!(current.expose() == expected_v5.as_slice());
        } else {
            assert!(service.record_root.is_none());
            assert!(current.expose() == source.expose());
        }
    }
    Ok(())
}

#[test]
fn formal_source_promotion_lost_actual_append_ack_fences_and_cold_recovers_v5_without_replay()
-> TestResult {
    let (files, mut service, key, admin) = initialized()?;
    let trace = install_journal_observation(&mut service, AckFault::LostApply)?;
    let response = call(&mut service, "POST", ACTIVATE, &admin, json!({}));
    assert_eq!(response.status, 503);
    assert!(
        *trace.lock().map_err(|_| "trace")? == vec![1, 5],
        "must lose acknowledgement of the actual promotion root Apply"
    );
    assert!(service.recovery_required);
    assert!(response.body["recovery_reference"].as_str().is_some());
    assert!(service.native_root.is_none());
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        503
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert!(service.record_root.is_some() && service.native_root.is_none());
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", ACTIVE_CURSOR_RESOURCE)?
            .is_none()
    );
    let identity = service
        .current_state_identity()
        .map_err(|_| "cold V5 identity")?;
    assert!(matches!(identity, StateIdentity::RecordsV5(_)));
    assert_eq!(
        call(&mut service, "GET", "sys/mounts", &admin, json!({})).status,
        200
    );
    assert!(
        service.native_root.is_none(),
        "cold reopen cannot automatically replay activation"
    );
    Ok(())
}

#[test]
fn source_promotion_actual_append_late_ack_never_installs_warm_state_and_cold_is_v5() -> TestResult
{
    let (files, mut service, key, admin) = initialized()?;
    let until = Instant::now() + Duration::from_secs(2);
    let trace = install_journal_observation(&mut service, AckFault::LateApply(until))?;
    let _original = crate::request_deadline::RequestDeadlineScope::enter(until);
    let proof = LegacySourcePromotion::prepare(&mut service, OriginalDeadline::capture()?)
        .map_err(|_| "prepare")?;
    let response = publish_as_root(proof, &mut service, &admin)
        .err()
        .ok_or("late success must fail")?;
    assert_eq!(response.status, 503);
    assert!(*trace.lock().map_err(|_| "trace")? == vec![1, 5]);
    assert!(service.recovery_required);
    assert_eq!(response.body["retry_allowed"], false);
    assert_eq!(
        response.body["source_promotion_outcome"],
        "unknown_requires_reopen"
    );
    assert!(service.record_root.is_none() && service.native_root.is_none());
    assert!(Instant::now() >= until);
    assert_eq!(crate::request_deadline::current(), Some(until));
    // The failed operation stays expired. Cold reopen is a separate request
    // after its original scope ends; it must not inherit that dead deadline.
    drop(_original);
    assert!(crate::request_deadline::current().is_none());
    drop(service);
    let service = reopen(&files, &key)?;
    assert!(service.record_root.is_some() && service.native_root.is_none());
    Ok(())
}

#[test]
fn formal_native_openapi_public_discovery_preserves_visibility_and_cold_state() -> TestResult {
    const PATH: &str = "sys/internal/specs/openapi";
    let (files, mut service, key, admin) = initialized()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    for (name, public) in [("openapi-visible", true), ("openapi-hidden", false)] {
        let mut body = json!({"type":"kv","options":{"version":"2"}});
        if public {
            body["config"] = json!({"listing_visibility":"unauth"});
        }
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/mounts/{name}"),
                &admin,
                body
            )
            .status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("{name}/data/value"),
                &admin,
                json!({"data":{"value":"synthetic-openapi-state"}})
            )
            .status,
            200
        );
    }
    fn business(service: &Service) -> TestResult<[Vec<u8>; 4]> {
        let state = service.state.as_ref().ok_or("state for discovery")?;
        let root = service.native_root.as_ref().ok_or("formal native root")?;
        Ok([
            owner_store::serialize_owner(&state.namespaces)?.to_vec(),
            owner_store::serialize_owner(&state.database)?.to_vec(),
            owner_store::serialize_owner(&state.raft_admin)?.to_vec(),
            serde_json::to_vec(&root.kv2)?,
        ])
    }
    let before = business(&service)?;
    let root_document = call(&mut service, "GET", PATH, &admin, json!({}));
    assert_eq!(root_document.status, 200);
    assert_eq!(root_document.body["openapi"], "3.0.2");
    assert!(
        root_document.body["paths"]
            .get("/openapi-visible/data/{path}")
            .is_some()
    );
    assert!(
        root_document.body["paths"]
            .get("/openapi-hidden/data/{path}")
            .is_some()
    );
    let anonymous = call(&mut service, "GET", PATH, "", json!({}));
    assert_eq!(anonymous.status, 200);
    assert!(
        anonymous.body["paths"]
            .get("/openapi-visible/data/{path}")
            .is_some()
    );
    assert!(
        anonymous.body["paths"]
            .get("/openapi-hidden/data/{path}")
            .is_none()
    );
    assert!(anonymous.body["paths"].get("/auth/token/create").is_none());
    assert_eq!(anonymous.body["openapi"], "3.0.2");
    let generic = call(
        &mut service,
        "POST",
        PATH,
        &admin,
        json!({"generic_mount_paths":true}),
    );
    assert_eq!(generic.status, 200);
    assert!(
        generic.body["paths"]
            .get("/{openapi_visible_mount_path}/data/{path}")
            .is_some()
    );
    assert!(
        generic.body["paths"]
            .get("/openapi-visible/data/{path}")
            .is_none()
    );
    for (method, body, expected) in [
        ("DELETE", json!({}), 405),
        ("PUT", json!({}), 200),
        ("POST", json!({"generic_mount_paths":"invalid"}), 400),
        ("POST", json!({"unrecognized":true}), 200),
    ] {
        assert_eq!(
            call(&mut service, method, PATH, &admin, body).status,
            expected
        );
    }
    for path in ["sys/mounts", "sys/auth", "openapi-visible/data/value"] {
        assert_eq!(call(&mut service, "GET", path, "", json!({})).status, 403);
    }
    let after = business(&service)?;
    for index in 0..4 {
        assert_eq!(before[index].as_slice(), after[index].as_slice());
    }
    drop(service);
    let mut service = reopen(&files, &key)?;
    let reopened = call(&mut service, "GET", PATH, &admin, json!({}));
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, root_document.body);
    let reopened = call(&mut service, "GET", PATH, "", json!({}));
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, anonymous.body);
    for mount in ["openapi-visible", "openapi-hidden"] {
        let read = call(
            &mut service,
            "GET",
            &format!("{mount}/data/value"),
            &admin,
            json!({}),
        );
        assert_eq!(read.status, 200);
        assert_eq!(
            read.body["data"]["data"]["value"],
            "synthetic-openapi-state"
        );
    }
    Ok(())
}

#[test]
fn formal_native_openapi_preserves_bearer_uses_revocation_and_catalog_acl() -> TestResult {
    const PATH: &str = "sys/internal/specs/openapi";
    fn issue(service: &mut Service, admin: &str, uses: u64) -> TestResult<Zeroizing<String>> {
        let mut response = call(
            service,
            "POST",
            "auth/token/create",
            admin,
            json!({"policies":["openapi-unrelated"],"no_default_policy":true,"ttl":"10m","num_uses":uses}),
        );
        assert_eq!(response.status, 200);
        let token = Zeroizing::new(
            response.body["auth"]["client_token"]
                .as_str()
                .ok_or("actual OpenAPI bearer")?
                .to_owned(),
        );
        erase_json(&mut response.body);
        Ok(token)
    }
    let (files, mut service, key, admin) = initialized()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/openapi-unrelated",
            &admin,
            json!({"policy":"path \"unrelated/data/value\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/unrelated",
            &admin,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "unrelated/data/value",
            &admin,
            json!({"data":{"value":"synthetic-finite-use"}})
        )
        .status,
        200
    );
    let ordinary = issue(&mut service, &admin, 0)?;
    let finite = issue(&mut service, &admin, 2)?;
    for token in [&ordinary, &finite] {
        let response = call(&mut service, "GET", PATH, token, json!({}));
        assert_eq!(response.status, 200);
        assert!(response.body["paths"].get("/sys/health").is_none());
        assert!(response.body["paths"].get("/auth/token/create").is_none());
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            PATH,
            &finite,
            json!({"generic_mount_paths":true})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", PATH, &finite, json!({})).status,
        200
    );
    for (method, body, expected) in [
        ("PUT", json!({}), 200),
        ("DELETE", json!({}), 405),
        ("POST", json!({"generic_mount_paths":"invalid"}), 400),
    ] {
        assert_eq!(
            call(&mut service, method, PATH, &finite, body).status,
            expected
        );
    }
    let uses = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":finite.as_str()}),
    );
    assert_eq!(uses.status, 200);
    assert_eq!(uses.body["data"]["num_uses"], 2);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "unrelated/data/value",
            &finite,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", PATH, &finite, json!({})).status,
        200
    );
    let uses = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":finite.as_str()}),
    );
    assert_eq!(uses.status, 200);
    assert_eq!(uses.body["data"]["num_uses"], 1);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "unrelated/data/value",
            &finite,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", PATH, &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "unrelated/data/value",
            &finite,
            json!({})
        )
        .status,
        403
    );
    for path in ["sys/mounts", "sys/auth"] {
        assert_eq!(
            call(&mut service, "GET", path, &ordinary, json!({})).status,
            403
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/ungranted-openapi",
            &ordinary,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            PATH,
            "invalid-openapi-fixture-token",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":ordinary.as_str()})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", PATH, &ordinary, json!({})).status,
        403
    );
    drop(service);
    let mut service = reopen(&files, &key)?;
    for token in [&ordinary, &finite] {
        assert_eq!(
            call(&mut service, "GET", PATH, token, json!({})).status,
            403
        );
    }
    assert_eq!(call(&mut service, "GET", PATH, "", json!({})).status, 200);
    Ok(())
}

#[test]
fn formal_native_openapi_binds_plain_namespace_without_root_mount_disclosure() -> TestResult {
    const PATH: &str = "sys/internal/specs/openapi";
    fn scoped(
        service: &mut Service,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let execution =
            service.begin_request(ServiceRequest::new(method, path, namespace, token, body));
        service.finish_synchronous_request(execution)
    }
    let (files, mut service, key, admin) = initialized()?;
    assert_eq!(
        call(&mut service, "POST", ACTIVATE, &admin, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/root-only-openapi",
            &admin,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/openapi-child",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        scoped(
            &mut service,
            "POST",
            "sys/mounts/child-only-openapi",
            "openapi-child",
            &admin,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    let child = scoped(
        &mut service,
        "GET",
        PATH,
        "openapi-child",
        &admin,
        json!({}),
    );
    assert_eq!(child.status, 200);
    assert!(
        child.body["paths"]
            .get("/child-only-openapi/data/{path}")
            .is_some()
    );
    assert!(
        child.body["paths"]
            .get("/root-only-openapi/data/{path}")
            .is_none()
    );
    let root_view = call(&mut service, "GET", PATH, &admin, json!({}));
    assert_eq!(root_view.status, 200);
    assert!(
        root_view.body["paths"]
            .get("/root-only-openapi/data/{path}")
            .is_some()
    );
    assert!(
        root_view.body["paths"]
            .get("/child-only-openapi/data/{path}")
            .is_none()
    );
    let anonymous = scoped(&mut service, "GET", PATH, "openapi-child", "", json!({}));
    assert_eq!(anonymous.status, 200);
    assert_eq!(anonymous.body["paths"], json!({}));
    drop(service);
    let mut service = reopen(&files, &key)?;
    let reopened = scoped(
        &mut service,
        "GET",
        PATH,
        "openapi-child",
        &admin,
        json!({}),
    );
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, child.body);
    assert_eq!(
        scoped(
            &mut service,
            "GET",
            PATH,
            "missing-openapi-namespace",
            &admin,
            json!({})
        )
        .status,
        404
    );
    Ok(())
}
