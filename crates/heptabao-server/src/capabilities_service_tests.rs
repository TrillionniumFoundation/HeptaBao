//! Only synthetic credentials and private temporary state; exercises Service,
//! encrypted durable storage, audit failure and schema admission together.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-capabilities-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        Ok(Self(path))
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        Ok(Service::new(
            self.0.join("data"),
            &self.0.join("audit.jsonl"),
        )?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn text(value: &Value, pointer: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing field")?
        .to_owned())
}
fn call(service: &mut Service, token: &str, path: &str, body: Value) -> Response {
    service.handle_at("POST", path, "", token, body, 100)
}
fn start(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let init = call(
        service,
        "",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(init.status, 200);
    let root = text(&init.body, "/root_token")?;
    let key = text(&init.body, "/keys_base64/0")?;
    assert_eq!(
        call(service, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    Ok((root, key))
}
fn snapshot(service: &Service) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec(service.state.as_ref().ok_or("state")?)?)
}

fn create_token(
    s: &mut Service,
    root: &str,
    parameters: Value,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let r = call(s, root, "auth/token/create", parameters);
    assert_eq!(r.status, 200);
    Ok((
        text(&r.body, "/auth/client_token")?,
        text(&r.body, "/auth/accessor")?,
    ))
}

#[test]
fn capabilities_root_legacy_single_path_and_multi_path_shapes() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let before = snapshot(&s)?;
    let r = call(
        &mut s,
        &root,
        "sys/capabilities-self",
        json!({"path":"secret/data/a"}),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["capabilities"], json!(["root"]));
    assert_eq!(r.body["secret/data/a"], r.body["data"]["secret/data/a"]);
    let r = call(
        &mut s,
        &root,
        "sys/capabilities-self",
        json!({"paths":["a", "b"]}),
    );
    assert_eq!(r.status, 200);
    assert!(r.body.get("capabilities").is_none());
    assert_eq!(r.body["data"]["b"], json!(["root"]));
    assert_eq!(before, snapshot(&s)?);
    Ok(())
}

#[test]
fn capabilities_share_acl_specificity_union_deny_and_never_grant() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    assert_eq!(call(&mut s, &root, "sys/policies/acl/query", json!({"policy":
        "path \"secret/*\" { capabilities = [\"read\",\"update\",\"delete\"] }\npath \"secret/data/locked\" { capabilities = [\"read\"] }"})).status, 204);
    let (token, _) = create_token(&mut s, &root, json!({"policies":["default","query"]}))?;
    let r = call(
        &mut s,
        &token,
        "sys/capabilities-self",
        json!({"paths":["secret/data/locked","secret/data/other","no-match"]}),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["data"]["secret/data/locked"], json!(["read"]));
    assert_eq!(
        r.body["data"]["secret/data/other"],
        json!(["delete", "read", "update"])
    );
    assert_eq!(r.body["data"]["no-match"], json!(["deny"]));
    assert_eq!(
        call(
            &mut s,
            &token,
            "secret/data/locked",
            json!({"data":{"v":"denied"}})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/policies/acl/query",
            json!({"policy":
        "path \"secret/data/locked\" { capabilities = [\"deny\",\"read\"] }"})
        )
        .status,
        204
    );
    let r = call(
        &mut s,
        &token,
        "sys/capabilities-self",
        json!({"paths":["secret/data/locked"]}),
    );
    assert_eq!(r.body["capabilities"], json!(["deny"]));
    Ok(())
}

#[test]
fn capabilities_target_lookup_never_consumes_finite_uses() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let (token, accessor) =
        create_token(&mut s, &root, json!({"policies":["default"],"num_uses":1}))?;
    let before = snapshot(&s)?;
    for _ in 0..3 {
        let r = call(
            &mut s,
            &root,
            "sys/capabilities",
            json!({"token":token,"paths":["auth/token/lookup-self"]}),
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.body["capabilities"], json!(["read"]));
        assert_eq!(
            call(
                &mut s,
                &root,
                "sys/capabilities-accessor",
                json!({"accessor":accessor,"paths":["auth/token/lookup-self"]})
            )
            .status,
            200
        );
    }
    assert_eq!(before, snapshot(&s)?);
    assert_eq!(
        s.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 100)
            .status,
        200
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/capabilities",
            json!({"token":token,"paths":["auth/token/lookup-self"]})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn capabilities_self_consumes_only_its_normal_affine_admission() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    let (token, _) = create_token(&mut s, &root, json!({"policies":["default"],"num_uses":1}))?;
    assert_eq!(
        call(
            &mut s,
            &token,
            "sys/capabilities-self",
            json!({"paths":["auth/token/lookup-self"]})
        )
        .status,
        200
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut s,
            &token,
            "sys/capabilities-self",
            json!({"paths":["auth/token/lookup-self"]})
        )
        .status,
        403
    );
    Ok(())
}

#[test]
fn capabilities_foreign_selectors_require_endpoint_authorization() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let (token, accessor) = create_token(&mut s, &root, json!({"policies":["default"]}))?;
    assert_eq!(
        call(
            &mut s,
            &token,
            "sys/capabilities",
            json!({"token":root,"paths":["secret/data/a"]})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut s,
            &token,
            "sys/capabilities-accessor",
            json!({"accessor":accessor,"paths":["secret/data/a"]})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/capabilities",
            json!({"token":"not-a-token","paths":["a"]})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/capabilities-accessor",
            json!({"accessor":"absent","paths":["a"]})
        )
        .status,
        400
    );
    Ok(())
}

#[test]
fn capabilities_path_and_selector_bounds_reject_without_state_change() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let before = snapshot(&s)?;
    for payload in [
        json!({}),
        json!({"paths":[]}),
        json!({"paths":["a","a"]}),
        json!({"path":"a","paths":["a"]}),
        json!({"paths":["a"],"token":root}),
        json!({"paths":[3]}),
        json!({"paths":["../outside"]}),
        json!({"paths":["secret/*"]}),
        json!({"paths":["a".repeat(2049)]}),
        json!({"paths":vec!["a";65]}),
    ] {
        assert_eq!(
            call(&mut s, &root, "sys/capabilities-self", payload).status,
            400
        );
    }
    assert_eq!(before, snapshot(&s)?);
    Ok(())
}

#[test]
fn capabilities_live_identity_and_group_revocation_apply_to_foreign_and_self_queries() -> TestResult
{
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    assert_eq!(
        call(
            &mut s,
            &root,
            "auth/approle/role/query",
            json!({"token_policies":["default"],"secret_id_num_uses":0})
        )
        .status,
        204
    );
    let rid = s.handle_at(
        "GET",
        "auth/approle/role/query/role-id",
        "",
        &root,
        json!({}),
        100,
    );
    let sid = call(
        &mut s,
        &root,
        "auth/approle/role/query/secret-id",
        json!({}),
    );
    let login = call(
        &mut s,
        "",
        "auth/approle/login",
        json!({"role_id":rid.body["data"]["role_id"],"secret_id":sid.body["data"]["secret_id"]}),
    );
    let token = text(&login.body, "/auth/client_token")?;
    let entity = text(&login.body, "/auth/entity_id")?;
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/policies/acl/live",
            json!({"policy":"path \"secret/data/a\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            &format!("identity/entity/id/{entity}"),
            json!({"policies":["live"]})
        )
        .status,
        204
    );
    let q = json!({"paths":["secret/data/a"]});
    let foreign = json!({"token":token,"paths":["secret/data/a"]});
    assert_eq!(
        call(&mut s, &token, "sys/capabilities-self", q.clone()).body["capabilities"],
        json!(["read"])
    );
    assert_eq!(
        call(&mut s, &root, "sys/capabilities", foreign.clone()).body["capabilities"],
        json!(["read"])
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            &format!("identity/entity/id/{entity}"),
            json!({"disabled":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut s, &token, "sys/capabilities-self", q.clone()).status,
        403
    );
    assert_eq!(
        call(&mut s, &root, "sys/capabilities", foreign.clone()).body["capabilities"],
        json!(["deny"])
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut s, &root, "sys/capabilities", foreign).body["capabilities"],
        json!(["deny"])
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            &format!("identity/entity/id/{entity}"),
            json!({"disabled":false,"policies":[]})
        )
        .status,
        204
    );
    let group = call(
        &mut s,
        &root,
        "identity/group",
        json!({"name":"live-group","type":"internal","policies":["live"],"member_entity_ids":[entity]}),
    );
    let group_id = text(&group.body, "/data/id")?;
    assert_eq!(
        call(&mut s, &token, "sys/capabilities-self", q.clone()).body["capabilities"],
        json!(["read"])
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            &format!("identity/group/id/{group_id}"),
            json!({"member_entity_ids":[]})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut s, &token, "sys/capabilities-self", q).body["capabilities"],
        json!(["deny"])
    );
    Ok(())
}

#[test]
fn capabilities_cannot_read_other_namespace_tokens_even_with_root_selector() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let issued = s.handle_at(
        "POST",
        "auth/token/create",
        "tenant-a",
        &root,
        json!({"policies":["default"]}),
        100,
    );
    assert_eq!(issued.status, 200);
    let token = text(&issued.body, "/auth/client_token")?;
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/capabilities",
            json!({"token":token,"paths":["a"]})
        )
        .status,
        400
    );
    assert_eq!(
        s.handle_at(
            "POST",
            "sys/capabilities",
            "tenant-a",
            &root,
            json!({"token":token,"paths":["a"]}),
            100
        )
        .status,
        200
    );
    Ok(())
}
