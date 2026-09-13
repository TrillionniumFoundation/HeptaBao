//! End-to-end through the public Service boundary, not a standalone model.
use crate::Service;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-cubbyhole-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        Ok(Service::new(
            self.0.join("data"),
            &self.0.join("audit.jsonl"),
        )?)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn call(
    service: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> crate::Response {
    service.handle_at(method, path, "", token, body, 100)
}
fn bootstrap(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = call(
        service,
        "",
        "POST",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(response.status, 200);
    let root = response.body["root_token"]
        .as_str()
        .ok_or("no root token")?
        .to_owned();
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("no share")?
        .to_owned();
    assert_eq!(
        call(service, "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    Ok((root, key))
}
fn token(
    service: &mut Service,
    parent: &str,
    body: Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = call(service, parent, "POST", "auth/token/create", body);
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("no token")?
        .to_owned())
}

#[test]
fn cubbyhole_service_reopens_ciphertext_with_token_and_namespace_isolation() -> TestResult {
    let root = Root::new()?;
    let mut service = root.service()?;
    let (admin, key) = bootstrap(&mut service)?;
    let a = token(&mut service, &admin, json!({"policies":["default"]}))?;
    let b = token(&mut service, &admin, json!({"policies":["default"]}))?;
    let marker = "synthetic-cubbyhole-plaintext-never-on-disk-9b2041";
    assert_eq!(
        call(
            &mut service,
            &a,
            "POST",
            "cubbyhole/item",
            json!({"value":marker})
        )
        .status,
        204
    );
    drop(service);
    for directory in [&root.0, &root.0.join("data")] {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                assert!(
                    !fs::read(entry.path())?
                        .windows(marker.len())
                        .any(|bytes| bytes == marker.as_bytes())
                );
            }
        }
    }
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, &a, "GET", "cubbyhole/item", json!({})).status,
        503
    );
    assert_eq!(
        call(&mut service, "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, &a, "GET", "cubbyhole/item", json!({})).body["data"]["value"],
        marker
    );
    for other in [&b, &admin] {
        assert_eq!(
            call(&mut service, other, "GET", "cubbyhole/item", json!({})).status,
            404
        );
    }
    assert_eq!(
        service
            .handle_at("GET", "cubbyhole/item", "another", &a, json!({}), 100)
            .status,
        403
    );
    Ok(())
}

#[test]
fn cubbyhole_service_final_read_and_final_denial_cannot_replay_after_restart() -> TestResult {
    let root = Root::new()?;
    let mut service = root.service()?;
    let (admin, key) = bootstrap(&mut service)?;
    let once = token(
        &mut service,
        &admin,
        json!({"policies":["default"],"num_uses":2}),
    )?;
    let denied = token(
        &mut service,
        &admin,
        json!({"policies":["default"],"num_uses":2}),
    )?;
    for actor in [&once, &denied] {
        assert_eq!(
            call(
                &mut service,
                actor,
                "POST",
                "cubbyhole/item",
                json!({"v":"last-use-secret"})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(&mut service, &once, "GET", "cubbyhole/item", json!({})).body["data"]["v"],
        "last-use-secret"
    );
    assert_eq!(
        call(
            &mut service,
            &denied,
            "POST",
            "sys/policies/acl/not-allowed",
            json!({"policy":""})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    for actor in [&once, &denied] {
        assert_eq!(
            call(&mut service, actor, "GET", "cubbyhole/item", json!({})).status,
            403
        );
    }
    Ok(())
}

#[test]
fn cubbyhole_service_revoke_parent_invalidates_child_across_reopen() -> TestResult {
    let root = Root::new()?;
    let mut service = root.service()?;
    let (admin, key) = bootstrap(&mut service)?;
    let parent = token(&mut service, &admin, json!({}))?;
    let child = token(&mut service, &parent, json!({"policies":["default"]}))?;
    assert_eq!(
        call(
            &mut service,
            &child,
            "POST",
            "cubbyhole/item",
            json!({"v":1})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            &admin,
            "POST",
            "auth/token/revoke",
            json!({"token":parent})
        )
        .status,
        204
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, &child, "GET", "cubbyhole/item", json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn cubbyhole_service_mount_is_builtin_and_cannot_be_replaced() -> TestResult {
    let root = Root::new()?;
    let mut service = root.service()?;
    let (admin, _) = bootstrap(&mut service)?;
    assert_eq!(
        call(&mut service, &admin, "GET", "sys/mounts", json!({})).body["data"]["cubbyhole/"]["type"],
        "cubbyhole"
    );
    assert_eq!(
        call(
            &mut service,
            &admin,
            "GET",
            "sys/mounts/cubbyhole",
            json!({})
        )
        .body["data"]["type"],
        "cubbyhole"
    );
    for method in ["POST", "DELETE"] {
        assert_eq!(
            call(
                &mut service,
                &admin,
                method,
                "sys/mounts/cubbyhole",
                json!({"type":"kv"})
            )
            .status,
            400
        );
    }
    Ok(())
}

#[test]
fn acl_service_narrow_read_rule_prevents_broad_write_privilege_bleed() -> TestResult {
    let root = Root::new()?;
    let mut service = root.service()?;
    let (admin, key) = bootstrap(&mut service)?;
    let policy = "path \"secret/*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\"] } path \"secret/data/locked\" { capabilities = [\"read\"] }";
    assert_eq!(
        call(
            &mut service,
            &admin,
            "POST",
            "sys/policies/acl/restricted",
            json!({"policy":policy})
        )
        .status,
        204
    );
    let reader = token(
        &mut service,
        &admin,
        json!({"policies":["restricted"],"no_default_policy":true}),
    )?;
    assert_eq!(
        call(
            &mut service,
            &admin,
            "POST",
            "secret/data/locked",
            json!({"data":{"v":"original"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            &reader,
            "POST",
            "secret/data/locked",
            json!({"data":{"v":"overwrite"}})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            &reader,
            "GET",
            "secret/data/locked",
            json!({})
        )
        .body["data"]["data"]["v"],
        "original"
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "", "POST", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            &reader,
            "DELETE",
            "secret/data/locked",
            json!({})
        )
        .status,
        403
    );
    Ok(())
}
