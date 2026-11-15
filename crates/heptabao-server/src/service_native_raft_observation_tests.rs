//! Real formal file ingress plus exact negative route/ACL boundaries. HA
//! observations are exercised by the sibling genuine three-Raft test module.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::request_deadline::RequestDeadlineScope;
use crate::service::tests::Root;
use std::cell::{Cell, RefCell};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type AuditHook = Box<dyn FnOnce(&mut Service, &mut Response)>;

thread_local! {
    static AFTER_AUDIT: RefCell<Option<AuditHook>> = RefCell::new(None);
    static AFTER_AUDIT_REACHED: Cell<bool> = const { Cell::new(false) };
}

pub(in crate::service) fn after_actual_raft_observation_audit(
    service: &mut Service,
    response: &mut Response,
) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        AFTER_AUDIT_REACHED.with(|reached| reached.set(true));
        hook(service, response);
    }
}

#[cfg(feature = "native-v6-ha")]
pub(in crate::service) struct AuditFault;

#[cfg(feature = "native-v6-ha")]
impl AuditFault {
    fn install_hook(hook: AuditHook) -> Self {
        AFTER_AUDIT.with(|slot| {
            assert!(slot.borrow_mut().replace(hook).is_none());
        });
        AFTER_AUDIT_REACHED.with(|reached| reached.set(false));
        Self
    }

    pub(in crate::service) fn install(hook: impl FnOnce(&mut Service) + 'static) -> Self {
        Self::install_hook(Box::new(move |service, _response| hook(service)))
    }

    pub(in crate::service) fn install_reply(hook: impl FnOnce(&mut Response) + 'static) -> Self {
        Self::install_hook(Box::new(move |_service, response| hook(response)))
    }

    pub(in crate::service) fn reached(&self) -> bool {
        AFTER_AUDIT_REACHED.with(Cell::get)
    }
}

#[cfg(feature = "native-v6-ha")]
impl Drop for AuditFault {
    fn drop(&mut self) {
        AFTER_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
        AFTER_AUDIT_REACHED.with(|reached| reached.set(false));
    }
}

const READS: [&str; 5] = [
    "sys/storage/raft/configuration",
    "sys/storage/raft/snapshot-status",
    "sys/storage/raft/linearizable-read",
    "sys/storage/raft/autopilot/state",
    "sys/storage/raft/autopilot/configuration",
];

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = RequestDeadlineScope::enter(Instant::now() + Duration::from_secs(15));
    let response = service.handle(method, path, "", token, body);
    assert!(service.pending_native_auth_delivery.is_none());
    response
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let mut initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("actual Shamir share absent")?
            .to_owned(),
    );
    let admin = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("actual root token absent")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
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
    assert_eq!(
        call(
            &mut service,
            "POST",
            native_storage::ACTIVATE_PATH,
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    assert!(matches!(
        service.native_storage_profile,
        Some(NativeStorageProfile::File)
    ));
    Ok((files, service, admin))
}

fn policy_token(
    service: &mut Service,
    admin: &str,
    name: &str,
    capabilities: &str,
) -> TestResult<Zeroizing<String>> {
    let policy = format!("path \"sys/storage/raft/*\" {{ capabilities = [{capabilities}] }}");
    assert_eq!(
        call(
            service,
            "PUT",
            &format!("sys/policies/acl/{name}"),
            admin,
            json!({"policy":policy})
        )
        .status,
        204
    );
    let mut issued = call(
        service,
        "POST",
        "auth/token/create",
        admin,
        json!({"policies":[name],"no_default_policy":true,"ttl":"300s"}),
    );
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual scoped token absent")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    Ok(token)
}

#[test]
fn formal_native_raft_reads_require_read_and_sudo_before_disclosing_missing_ha() -> TestResult {
    let (_files, mut service, admin) = initialized()?;
    let read = policy_token(&mut service, &admin, "raft-read-only", "\"read\"")?;
    let sudo = policy_token(&mut service, &admin, "raft-sudo-only", "\"sudo\"")?;
    let both = policy_token(&mut service, &admin, "raft-read-sudo", "\"read\",\"sudo\"")?;
    for path in READS {
        for token in ["", read.as_str(), sudo.as_str()] {
            let response = call(&mut service, "GET", path, token, json!({}));
            assert_eq!(response.status, 403, "{path}");
            assert!(response.body.get("data").is_none());
        }
        for token in [admin.as_str(), both.as_str()] {
            let response = call(&mut service, "GET", path, token, json!({}));
            assert_eq!(response.status, 400, "{path}");
            assert_eq!(response.body["errors"], json!(["HA is not enabled"]));
            assert!(response.body.get("data").is_none());
        }
    }
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .raft_admin
            .is_default()
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn formal_native_raft_observation_selector_never_admits_membership_or_policy_writes() -> TestResult
{
    let (_files, mut service, admin) = initialized()?;
    let before = service.native_root.as_ref().ok_or("native root")?.clone();
    for path in READS.into_iter().chain([
        "sys/storage/raft/join",
        "sys/storage/raft/remove-peer",
        "sys/storage/raft/demote",
        "sys/storage/raft/promote",
        "sys/storage/raft/migrate-owner-state",
    ]) {
        for method in ["POST", "PUT", "DELETE", "LIST", "HEAD"] {
            let response = call(&mut service, method, path, &admin, json!({}));
            assert_eq!(response.status, 501, "{method} {path}");
            assert!(response.body.get("data").is_none());
        }
    }
    for path in READS.map(|path| format!("{path}/")) {
        assert_eq!(
            call(&mut service, "GET", &path, &admin, json!({})).status,
            501
        );
    }
    native_auth::auth_only_root_change(
        &before,
        service.native_root.as_ref().ok_or("native root")?,
        false,
    )
    .map_err(|_| "refused administration changed a business owner")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .raft_admin
            .is_default()
    );
    assert!(!service.recovery_required);
    Ok(())
}
