//! Configured File V6, original ordinary wrapping and real mandatory audit.
//! Synthetic credentials remain local. These are Service tests, not physical HA
//! or public HTTPS qualifications, and never manufacture an unwrap Principal.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::cell::RefCell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WRAP: &str = "sys/wrapping/wrap";
const LOOKUP: &str = "sys/wrapping/lookup";
const UNWRAP: &str = "sys/wrapping/unwrap";
const REWRAP: &str = "sys/wrapping/rewrap";
const PAYLOAD: &str = "ordinary-native-wrapping-synthetic-private-value";

fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "native ordinary wrapping error shape={:?}",
        response.body.get("errors")
    );
}
fn text(response: &Response, pointer: &str) -> TestResult<String> {
    response
        .body
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "synthetic wrapping field absent".into())
}
fn secret(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = Zeroizing::new(text(response, pointer)?);
    erase_json(&mut response.body);
    Ok(value)
}
fn no_private(response: &Response) {
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
    assert!(!response.body.to_string().contains(PAYLOAD));
}

#[allow(clippy::too_many_arguments)]
fn call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    namespace: &str,
    body: Value,
    ttl: Option<u64>,
) -> TestResult<Response> {
    *now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(*now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now: *now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: ttl,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert!(service.pending_native_auth_delivery.is_none());
    assert!(service.pending_ordinary_kv_authority.is_none());
    Ok(response)
}

struct Fixture {
    files: Root,
    service: Service,
    admin: Zeroizing<String>,
    key: Zeroizing<String>,
    now: u64,
}
impl Fixture {
    fn open(files: &Root) -> TestResult<Service> {
        let mut service = Service::new(files.path.join("state"), &files.path.join("audit.jsonl"))?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        Ok(service)
    }
    fn initialized() -> TestResult<Self> {
        let mut files = Root::new();
        private_directory(&files.path)?;
        files.path = fs::canonicalize(&files.path)?;
        let mut service = Self::open(&files)?;
        let mut now = 100;
        let mut initialized = call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/init",
            "",
            json!({"secret_shares":1,"secret_threshold":1}),
            None,
        )?;
        status(&initialized, 200);
        let key = Zeroizing::new(text(&initialized, "/keys/0")?);
        let admin = secret(&mut initialized, "/root_token")?;
        status(
            &call(
                &mut service,
                &mut now,
                "",
                "POST",
                "sys/unseal",
                "",
                json!({"key":key.as_str()}),
                None,
            )?,
            200,
        );
        status(
            &call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                "sys/init/ack",
                "",
                json!({}),
                None,
            )?,
            204,
        );
        Ok(Self {
            files,
            service,
            admin,
            key,
            now,
        })
    }
    fn new() -> TestResult<Self> {
        let mut f = Self::initialized()?;
        status(
            &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}), None)?,
            204,
        );
        f.assert_native()?;
        status(
            &f.admin(
                "POST",
                "sys/mounts/wrap-kv",
                json!({"type":"kv","options":{"version":"2"}}),
                None,
            )?,
            204,
        );
        status(
            &f.admin(
                "POST",
                "wrap-kv/data/preserved",
                json!({"options":{"cas":0},"data":{"value":"unchanged-KV"}}),
                None,
            )?,
            200,
        );
        Ok(f)
    }
    fn admin(
        &mut self,
        method: &str,
        path: &str,
        body: Value,
        ttl: Option<u64>,
    ) -> TestResult<Response> {
        call(
            &mut self.service,
            &mut self.now,
            &self.admin,
            method,
            path,
            "",
            body,
            ttl,
        )
    }
    fn actor(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
        ttl: Option<u64>,
    ) -> TestResult<Response> {
        call(
            &mut self.service,
            &mut self.now,
            token,
            method,
            path,
            "",
            body,
            ttl,
        )
    }
    fn wrap(&mut self, ttl: u64) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin("POST", WRAP, json!({"value":PAYLOAD}), Some(ttl))?;
        status(&response, 200);
        assert!(response.body["data"].is_null());
        assert!(!response.body.to_string().contains(PAYLOAD));
        secret(&mut response, "/wrap_info/token")
    }
    fn assert_native(&self) -> TestResult {
        assert!(matches!(
            self.service.native_storage_profile,
            Some(NativeStorageProfile::File)
        ));
        // Normal configured File storage also retains this descriptor-bound owner.
        assert!(self.service.native_candidate_profile.is_some());
        assert!(self.service.native_root.is_some() && self.service.record_root.is_none());
        assert!(!self.service.recovery_required);
        let auth = &self.service.state.as_ref().ok_or("state")?.auth;
        assert!(auth.supports_native_v6_root_storage());
        assert!(auth.validate_wrapping_state().is_ok());
        Ok(())
    }
    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = Self::open(&self.files)?;
        status(
            &call(
                &mut self.service,
                &mut self.now,
                "",
                "POST",
                "sys/unseal",
                "",
                json!({"key":self.key.as_str()}),
                None,
            )?,
            200,
        );
        self.assert_native()?;
        Ok(self)
    }
    fn assert_kv(&mut self) -> TestResult {
        let response = self.admin("GET", "wrap-kv/data/preserved", json!({}), None)?;
        status(&response, 200);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert_eq!(response.body["data"]["data"]["value"], "unchanged-KV");
        Ok(())
    }
    fn root(&self) -> TestResult<RecordStateRootV6> {
        self.service
            .native_root
            .clone()
            .ok_or_else(|| "native root absent".into())
    }
    fn assert_auth_only(&self, before: &RecordStateRootV6) -> TestResult {
        auth_only_root_change(before, &self.root()?, false)
            .map_err(|_| "ordinary wrapping changed an unrelated storage owner")?;
        Ok(())
    }
    fn token(&mut self, policy: &str, uses: u64) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin(
            "POST",
            "auth/token/create",
            json!({
                "policies":[policy],"no_default_policy":true,"ttl":"600s","num_uses":uses,
            }),
            None,
        )?;
        status(&response, 200);
        secret(&mut response, "/auth/client_token")
    }
    fn audited(
        &mut self,
        token: &str,
        path: &str,
        body: Value,
        ttl: Option<u64>,
        budget: Duration,
    ) -> TestResult<(Response, Instant, Instant)> {
        self.now += 1;
        let started = Instant::now();
        let until = started + budget;
        let clock = RequestClock::anchored(Duration::from_secs(self.now), started)?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
        let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
        let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
        let response = self.service.handle_inner(RequestView {
            method: "POST",
            path,
            namespace: "",
            token,
            body: &body,
            now: self.now,
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: ttl,
            origin_peer: None,
            client_certificates: None,
        });
        let owner = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("actual wrapping owner")?;
        assert!(owner.wrapping_owner.is_some());
        assert!(owner.requires_local_proof() && owner.tracks_terminal_checkpoint());
        assert!(owner.proof.is_none() && owner.delivery_checkpoint.is_some());
        let response = self.service.audit_completed_response_with_receipt(
            "native-ordinary-wrapping-actual-audit",
            self.now,
            Some(clock),
            response,
            || {},
        );
        let owner = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("audited wrapping owner")?;
        assert!(matches!(
            owner.proof.as_ref(),
            Some(native_v6_reader::NativeProof::Single(_))
        ));
        Ok((response, started, until))
    }
}

#[test]
fn native_wrapping_formal_source_promotion_preserves_private_reply_and_cold_once_use() -> TestResult
{
    let mut f = Fixture::initialized()?;
    assert!(f.service.native_root.is_none());
    let token = f.wrap(120)?;
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}), None)?,
        204,
    );
    let mut f = f.restart()?;
    let lookup = f.actor(&token, "GET", LOOKUP, json!({}), None)?;
    status(&lookup, 200);
    assert_eq!(lookup.body["data"]["creation_path"], WRAP);
    let response = f.actor(&token, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["value"], PAYLOAD);
    assert!(
        response
            .unwrapped_json
            .as_ref()
            .is_some_and(|u| u.has_stored_reply())
    );
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_formal_wrap_lookup_rewrap_origin_ttl_and_cold_single_consumption() -> TestResult
{
    let mut f = Fixture::new()?;
    let before = f.root()?;
    let token = f.wrap(120)?;
    let first = f.actor(&token, "GET", LOOKUP, json!({}), None)?;
    status(&first, 200);
    status(
        &f.actor("", "POST", LOOKUP, json!({"token":token.as_str()}), None)?,
        200,
    );
    let mut rewrapped = f.admin("POST", REWRAP, json!({"token":token.as_str()}), None)?;
    status(&rewrapped, 200);
    assert_eq!(rewrapped.body["wrap_info"]["creation_path"], WRAP);
    assert_eq!(rewrapped.body["wrap_info"]["ttl"], 120);
    let next = secret(&mut rewrapped, "/wrap_info/token")?;
    assert!(next.as_str() != token.as_str());
    status(&f.actor(&token, "GET", LOOKUP, json!({}), None)?, 400);
    let mut f = f.restart()?;
    let response = f.admin("POST", UNWRAP, json!({"token":next.as_str()}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["value"], PAYLOAD);
    status(
        &f.admin("POST", UNWRAP, json!({"token":next.as_str()}), None)?,
        400,
    );
    f.assert_auth_only(&before)?;
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_self_token_cannot_consume_another_body_target() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.wrap(120)?;
    let second = f.wrap(120)?;
    let rejected = f.actor(
        &first,
        "POST",
        UNWRAP,
        json!({"token":second.as_str()}),
        None,
    )?;
    status(&rejected, 400);
    no_private(&rejected);
    // The presented finite self token was admitted exactly once, even though
    // its request body was invalid. The unrelated target remains untouched.
    status(&f.actor(&first, "POST", UNWRAP, json!({}), None)?, 400);
    let response = f.actor(&second, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["value"], PAYLOAD);
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_actual_acl_denial_keeps_body_wrapper_available() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/wrap-denied",
            json!({
                "policy":"path \"wrap-kv/data/preserved\" { capabilities = [\"read\"] }",
            }),
            None,
        )?,
        204,
    );
    let actor = f.token("wrap-denied", 1)?;
    let token = f.wrap(120)?;
    let response = f.actor(
        &actor,
        "POST",
        UNWRAP,
        json!({"token":token.as_str()}),
        None,
    )?;
    status(&response, 403);
    no_private(&response);
    status(
        &f.actor(&actor, "GET", "wrap-kv/data/preserved", json!({}), None)?,
        403,
    );
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 200);
    Ok(())
}

#[test]
fn native_wrapping_expiry_floor_survives_cold_clock_rollback() -> TestResult {
    let mut f = Fixture::new()?;
    let token = f.wrap(2)?;
    let issued = f.now;
    f.now = issued + 3;
    status(&f.actor(&token, "GET", LOOKUP, json!({}), None)?, 400);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    f.now = issued.saturating_sub(30);
    let mut f = f.restart()?;
    status(&f.actor(&token, "GET", LOOKUP, json!({}), None)?, 400);
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_payload_failure_retains_original_finite_use_consumption() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/wrap-only",
            json!({
                "policy":"path \"sys/wrapping/wrap\" { capabilities = [\"update\"] }",
            }),
            None,
        )?,
        204,
    );
    let actor = f.token("wrap-only", 1)?;
    let response = f.actor(
        &actor,
        "POST",
        WRAP,
        json!({"oversized":"x".repeat(70 * 1024)}),
        Some(120),
    )?;
    status(&response, 413);
    no_private(&response);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    let mut f = f.restart()?;
    status(
        &f.actor(&actor, "POST", WRAP, json!({"value":PAYLOAD}), Some(120))?,
        403,
    );
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_post_audit_body_tampering_cannot_release_or_resurrect_plaintext() -> TestResult {
    let mut f = Fixture::new()?;
    let token = f.wrap(120)?;
    let (mut response, _, _) =
        f.audited(&token, UNWRAP, json!({}), None, Duration::from_secs(15))?;
    status(&response, 200);
    response.body["data"]["value"] = json!("substituted-private-value");
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "wrap-tamper-body");
    status(&response, 503);
    no_private(&response);
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_post_audit_status_and_private_origin_removal_are_both_vetoed() -> TestResult {
    for mutate_status in [false, true] {
        let mut f = Fixture::new()?;
        let token = f.wrap(120)?;
        let (mut response, _, _) =
            f.audited(&token, UNWRAP, json!({}), None, Duration::from_secs(15))?;
        status(&response, 200);
        if mutate_status {
            response.status = 400;
        } else {
            response.unwrapped_json = None;
        }
        let response =
            f.service
                .complete_native_auth_delivery(true, response, "wrap-tamper-private");
        status(&response, 503);
        no_private(&response);
        let mut f = f.restart()?;
        status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    }
    Ok(())
}

#[test]
fn native_wrapping_original_request_deadline_cannot_be_replaced_after_audit() -> TestResult {
    let mut f = Fixture::new()?;
    let token = f.wrap(120)?;
    let (response, _, until) =
        f.audited(&token, UNWRAP, json!({}), None, Duration::from_millis(1500))?;
    status(&response, 200);
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
    let _new_ambient = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "wrap-original-deadline");
    status(&response, 503);
    no_private(&response);
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_original_target_ttl_still_expires_after_real_audit() -> TestResult {
    let mut f = Fixture::new()?;
    let token = f.wrap(2)?;
    let (response, started, _) =
        f.audited(&token, UNWRAP, json!({}), None, Duration::from_secs(15))?;
    status(&response, 200);
    let expiry = started + Duration::from_millis(1100);
    std::thread::sleep(expiry.saturating_duration_since(Instant::now()));
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "wrap-original-ttl");
    status(&response, 503);
    no_private(&response);
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_actual_post_audit_revocation_vetoes_the_original_wrapper_reply() -> TestResult {
    let mut f = Fixture::new()?;
    let admin = Zeroizing::new(f.admin.as_str().to_owned());
    let (response, _, _) = f.audited(
        &admin,
        WRAP,
        json!({"value":PAYLOAD}),
        Some(120),
        Duration::from_secs(15),
    )?;
    status(&response, 200);
    let token = Zeroizing::new(text(&response, "/wrap_info/token")?);
    let original = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("original audited owner")?;
    status(
        &f.admin(
            "POST",
            "auth/token/revoke",
            json!({"token":token.as_str()}),
            None,
        )?,
        204,
    );
    assert!(f.service.pending_native_auth_delivery.is_none());
    f.service.pending_native_auth_delivery = Some(original);
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "wrap-actual-root-revoke");
    status(&response, 503);
    no_private(&response);
    assert!(!response.body.to_string().contains(token.as_str()));
    let mut f = f.restart()?;
    status(&f.actor(&token, "GET", LOOKUP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_real_read_only_audit_descriptor_failure_keeps_consumption_durable() -> TestResult
{
    let mut f = Fixture::new()?;
    let token = f.wrap(120)?;
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let body = json!({});
    let response = f.service.handle_inner(RequestView {
        method: "POST",
        path: UNWRAP,
        namespace: "",
        token: &token,
        body: &body,
        now: f.now,
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    status(&response, 200);
    assert!(f.service.pending_native_auth_delivery.is_some());
    // Same actual audit inode, opened read-only. The real mandatory audit write
    // fails in the kernel; no fabricated successful audit receipt is supplied.
    let readonly = File::open(f.files.path.join("audit.jsonl"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let held = f.service.audit.metadata()?;
        let replacement = readonly.metadata()?;
        assert_eq!(
            (held.dev(), held.ino()),
            (replacement.dev(), replacement.ino())
        );
    }
    let original = std::mem::replace(&mut f.service.audit, readonly);
    let response = f.service.audit_completed_response_with_receipt(
        "wrap-real-audit-write-failure",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 503);
    assert!(f.service.audit_failed);
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "wrap-failed-audit");
    status(&response, 503);
    no_private(&response);
    f.service.audit = original;
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

thread_local! {
    static REPLACE_JOURNAL: RefCell<Option<Result<Option<[u8; 32]>, String>>> = const { RefCell::new(None) };
}
pub(super) fn before_native_wrapping_publication(service: &mut Service) {
    REPLACE_JOURNAL.with(|slot| {
        let enabled = matches!(*slot.borrow(), Some(Ok(None)));
        if !enabled {
            return;
        }
        let result = (|| -> Result<Option<[u8; 32]>, String> {
            let path = service.data_dir.join("journal.hbj");
            let saved = service.data_dir.join("wrapping-test-original-journal.hbj");
            // The request's real clock prelude may already have committed.
            // Bind the original journal at this exact pre-publication hook,
            // after that legitimate write and before replacing its owner.
            let bytes = Zeroizing::new(fs::read(&path).map_err(|error| error.to_string())?);
            let digest = crypto::digest(&bytes);
            fs::rename(&path, &saved).map_err(|error| error.to_string())?;
            let replacement = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| error.to_string())?;
            replacement.sync_all().map_err(|error| error.to_string())?;
            Ok(Some(digest))
        })();
        *slot.borrow_mut() = Some(result);
    });
}
struct JournalFault;
impl Drop for JournalFault {
    fn drop(&mut self) {
        REPLACE_JOURNAL.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[test]
fn native_wrapping_real_journal_owner_loss_before_publication_cannot_install_wrapper() -> TestResult
{
    let mut f = Fixture::new()?;
    let before = f.root()?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    let _fault = JournalFault;
    REPLACE_JOURNAL.with(|slot| *slot.borrow_mut() = Some(Ok(None)));
    let response = f.admin("POST", WRAP, json!({"value":PAYLOAD}), Some(120))?;
    status(&response, 503);
    no_private(&response);
    let actual = REPLACE_JOURNAL
        .with(|slot| slot.borrow_mut().take())
        .ok_or("fault observation")?;
    let original_digest = actual
        .map_err(std::io::Error::other)?
        .ok_or("fault hook not reached")?;
    // A real storage-custody failure may seal or unload the Service. The
    // original durable journal and cold reopen, not continued in-memory
    // availability, establish that the proposed wrapper was never published.
    if let Some(state) = f.service.state.as_ref() {
        assert!(!state.auth.has_live_wrappers());
    }
    let data = f.service.data_dir.clone();
    drop(f.service);
    let journal_after = Zeroizing::new(fs::read(data.join("wrapping-test-original-journal.hbj"))?);
    assert!(crypto::digest(&journal_after) == original_digest);
    fs::remove_file(data.join("journal.hbj"))?;
    fs::rename(
        data.join("wrapping-test-original-journal.hbj"),
        data.join("journal.hbj"),
    )?;
    f.service = Fixture::open(&f.files)?;
    status(
        &call(
            &mut f.service,
            &mut f.now,
            "",
            "POST",
            "sys/unseal",
            "",
            json!({"key":f.key.as_str()}),
            None,
        )?,
        200,
    );
    f.assert_native()?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    f.assert_auth_only(&before)?;
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_exact_selector_does_not_grant_unimplemented_response_composition() -> TestResult
{
    let mut f = Fixture::new()?;
    let before = f.root()?;
    for path in ["sys/wrapping/unknown", "sys/wrapping/wrap/child"] {
        status(&f.admin("POST", path, json!({}), Some(120))?, 501);
    }
    status(&f.admin("POST", WRAP, json!({}), None)?, 400);
    status(&f.admin("GET", WRAP, json!({}), Some(120))?, 405);
    // Auth token output now has its own atomic composition regressions. The
    // independent metadata reader still does not acquire a wrapping writer.
    status(&f.admin("GET", "sys/mounts", json!({}), Some(120))?, 501);
    let token = f.wrap(120)?;
    let response = call(
        &mut f.service,
        &mut f.now,
        &token,
        "POST",
        UNWRAP,
        "foreign",
        json!({}),
        None,
    )?;
    status(&response, 404);
    assert!(response.body.get("data").is_none());
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 200);
    f.assert_auth_only(&before)?;
    f.assert_kv()?;
    Ok(())
}

#[path = "service_native_response_wrapping_tests.rs"]
mod composition_tests;

pub(super) fn before_response_composition_publication(service: &mut Service) {
    composition_tests::before_publication(service);
}
