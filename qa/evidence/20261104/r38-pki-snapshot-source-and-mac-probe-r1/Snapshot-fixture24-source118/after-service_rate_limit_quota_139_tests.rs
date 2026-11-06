//! Real configured File storage, real public routing, original 15-second calls.
//! No fixture-native flag or fabricated quota admission supplies the results.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::io::{self, Read};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request(
    service: &mut Service,
    method: &str,
    path: &str,
    namespace: &str,
    token: &str,
    body: Value,
) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle_request(
        ServiceRequest::new(method, path, namespace, token, body)
            .with_origin_peer(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 9))),
    )
}

fn headers(response: &Response) -> TestResult<Value> {
    Ok(serde_json::to_value(&response.response_headers)?)
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    initialized_with_pre141_predecessor(false)
}

fn initialized_pre141() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    initialized_with_pre141_predecessor(true)
}

fn initialized_with_pre141_predecessor(
    historical: bool,
) -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = if historical {
        // Exact 137 -> 139 reader tests migrate a genuinely published ordinary
        // predecessor. The old factory never runs with a selected native
        // profile, and the cold File owner still uses its actual share below.
        let (key, token) = crate::service::tests::bootstrap_pre141_unmounted(&mut service)?;
        let predecessor = service
            .state
            .as_ref()
            .ok_or("historical ordinary predecessor")?;
        assert_eq!(predecessor.schema, CURRENT_STATE_SCHEMA);
        assert!(!predecessor.auth.has_security_contract_state());
        assert!(service.native_storage_profile.is_none() && service.native_root.is_none());
        drop(service);
        service = root.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        (Zeroizing::new(key), Zeroizing::new(token))
    } else {
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let mut response = request(
            &mut service,
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares":1, "secret_threshold":1}),
        );
        assert_eq!(response.status, 200);
        let key = Zeroizing::new(
            response.body["keys_base64"][0]
                .as_str()
                .ok_or("actual share")?
                .to_owned(),
        );
        let token = Zeroizing::new(
            response.body["root_token"]
                .as_str()
                .ok_or("actual root bearer")?
                .to_owned(),
        );
        erase_json(&mut response.body);
        (key, token)
    };
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(&mut service, "POST", "sys/init/ack", "", &token, json!({})).status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/quota-kv",
            "",
            &token,
            json!({"type":"kv", "options":{"version":"2"}})
        )
        .status,
        204
    );
    for name in [
        "item",
        "alpha/exact",
        "alpha/other",
        "outside",
        "blocked/exact",
        "blocked/other",
        "open",
    ] {
        assert_eq!(
            request(
                &mut service,
                "POST",
                &format!("quota-kv/data/{name}"),
                "",
                &token,
                json!({"data":{"value":"synthetic"}})
            )
            .status,
            200
        );
    }
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("actual native root")?
            .reader_floor
            .native_kv2_format,
        2
    );
    Ok((root, service, key, token))
}

fn quota(service: &mut Service, token: &str, name: &str, path: &str, rate: u64) {
    assert_eq!(
        request(
            service,
            "POST",
            &format!("sys/quotas/rate-limit/{name}"),
            "",
            token,
            json!({"path":path,"rate":rate,"interval":"1h"})
        )
        .status,
        204
    );
}

fn snapshot(
    service: &mut Service,
    token: &str,
    input: Option<&[u8]>,
) -> TestResult<(Response, Option<Zeroizing<Vec<u8>>>)> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let method = if input.is_some() { "POST" } else { "GET" };
    let admission = service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        deadline,
    );
    match admission {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let mut reader = io::Cursor::new(input.unwrap_or_default());
            let (observation, file) = pending.execute_snapshot_transfer(&mut reader);
            let response = service.finish_external_request(*pending, observation);
            let bytes = if let Some(mut file) = file {
                file.rewind_checked()?;
                let mut bytes = Zeroizing::new(Vec::new());
                file.read_to_end(&mut bytes)?;
                Some(bytes)
            } else {
                None
            };
            Ok((response, bytes))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("File fixture cannot redirect".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("File fixture cannot forward".into()),
    }
}

#[test]
fn quota_139_actual_native_file_selects_one_exact_glob_mount_or_system_bucket() -> TestResult {
    let (_root, mut service, _key, token) = initialized_pre141()?;
    assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
        json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/quotas"]})).status, 204);
    for (name, path, rate) in [
        ("mount", "quota-kv/", 7),
        ("wide", "quota-kv/data/*", 5),
        ("narrow", "quota-kv/data/alpha/*", 3),
        ("exact", "quota-kv/data/alpha/exact", 1),
    ] {
        quota(&mut service, &token, name, path, rate);
        let read = request(
            &mut service,
            "GET",
            &format!("sys/quotas/rate-limit/{name}"),
            "",
            &token,
            json!({}),
        );
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["path"], path);
    }
    for (path, status, limit, remaining) in [
        ("data/alpha/exact", 200, "1", "0"),
        ("data/alpha/exact", 429, "1", "0"),
        ("data/alpha/other", 200, "3", "2"),
        ("data/alpha/other", 200, "3", "1"),
        ("data/alpha/other", 200, "3", "0"),
        ("data/alpha/other", 429, "3", "0"),
        ("data/outside", 200, "5", "4"),
        ("metadata/outside", 200, "7", "6"),
    ] {
        let response = request(
            &mut service,
            "GET",
            &format!("quota-kv/{path}"),
            "",
            &token,
            json!({}),
        );
        assert_eq!(response.status, status, "actual public route {path}");
        let actual = headers(&response)?;
        assert_eq!(actual["X-Ratelimit-Limit"], json!([limit]));
        assert_eq!(actual["X-Ratelimit-Remaining"], json!([remaining]));
    }
    for (name, status, limit, remaining) in [
        ("exact", 429, "3", "0"),
        ("narrow", 200, "5", "3"),
        ("wide", 200, "7", "5"),
    ] {
        assert_eq!(
            request(
                &mut service,
                "DELETE",
                &format!("sys/quotas/rate-limit/{name}"),
                "",
                &token,
                json!({})
            )
            .status,
            204
        );
        let response = request(
            &mut service,
            "GET",
            "quota-kv/data/alpha/exact",
            "",
            &token,
            json!({}),
        );
        assert_eq!(response.status, status);
        assert_eq!(headers(&response)?["X-Ratelimit-Limit"], json!([limit]));
        assert_eq!(
            headers(&response)?["X-Ratelimit-Remaining"],
            json!([remaining])
        );
    }
    // A terminal star is a prefix selector; an interior star remains literal.
    quota(&mut service, &token, "literal-star", "quota-kv/da*ta/*", 19);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/literal-star",
            "",
            &token,
            json!({})
        )
        .body["data"]["path"],
        "quota-kv/da*ta/*"
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/missing-mount",
            "",
            &token,
            json!({"path":"no-such-mount/data/*","rate":19})
        )
        .status,
        400
    );
    quota(&mut service, &token, "system", "sys/", 2);
    let actual = request(&mut service, "GET", "sys/mounts", "", &token, json!({}));
    assert_eq!(actual.status, 200);
    assert_eq!(headers(&actual)?["X-Ratelimit-Remaining"], json!(["1"]));
    assert_eq!(
        request(&mut service, "GET", "sys/health", "", "", json!({})).status,
        200
    );
    assert_eq!(
        request(&mut service, "GET", "sys/health", "", "", json!({})).status,
        429
    );
    assert_eq!(
        service.state.as_ref().ok_or("published state")?.schema,
        SCOPED_RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn quota_139_native_exemption_exceptions_order_and_empty_entry_survive_cold_reopen() -> TestResult {
    let (root, mut service, key, token) = initialized()?;
    let controls = vec!["sys/quotas*", "sys/unseal*", "sys/seal-status*"];
    let mut paths = controls.clone();
    paths.extend(["quota-kv/data/*", "!quota-kv/data/blocked/*"]);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/quotas/config",
            "",
            &token,
            json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":paths})
        )
        .status,
        204
    );
    quota(&mut service, &token, "global", "", 2);
    for _ in 0..3 {
        let response = request(
            &mut service,
            "GET",
            "quota-kv/data/open",
            "",
            &token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(headers(&response)?, json!({}));
    }
    for status in [200, 200, 429] {
        assert_eq!(
            request(
                &mut service,
                "GET",
                "quota-kv/data/blocked/other",
                "",
                &token,
                json!({})
            )
            .status,
            status
        );
    }
    paths.push("quota-kv/data/blocked/exact");
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/quotas/config",
            "",
            &token,
            json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":paths})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "quota-kv/data/blocked/exact",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "quota-kv/data/blocked/other",
            "",
            &token,
            json!({})
        )
        .status,
        429
    );
    for (rules, expected) in [
        (["quota-kv/data/blocked/*", "!quota-kv/data/blocked/*"], 429),
        (["!quota-kv/data/blocked/*", "quota-kv/data/blocked/*"], 200),
    ] {
        let mut configured = controls.clone();
        configured.extend(rules);
        assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
            json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":configured})).status, 204);
        assert_eq!(
            request(
                &mut service,
                "GET",
                "quota-kv/data/blocked/other",
                "",
                &token,
                json!({})
            )
            .status,
            expected
        );
    }
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let actual = request(
        &mut service,
        "GET",
        "quota-kv/data/blocked/other",
        "",
        &token,
        json!({}),
    );
    assert_eq!(actual.status, 200);
    assert_eq!(headers(&actual)?, json!({}));
    let mut empty = controls;
    empty.insert(0, "");
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/quotas/config",
            "",
            &token,
            json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":empty})
        )
        .status,
        204
    );
    quota(&mut service, &token, "global", "", 1);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "quota-kv/data/open",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "quota-kv/data/open",
            "",
            &token,
            json!({})
        )
        .status,
        429
    );
    Ok(())
}

#[test]
fn quota_139_actual_flat_child_target_requires_root_administration_and_original_acl() -> TestResult
{
    let (root, mut service, key, token) = initialized()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/namespaces/quota-child",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/quota-kv",
            "quota-child",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "quota-kv/data/item",
            "quota-child",
            &token,
            json!({"data":{"value":"synthetic-child"}})
        )
        .status,
        200
    );
    assert_eq!(request(&mut service, "POST", "sys/policies/acl/quota-manager", "quota-child", &token,
        json!({"policy":"path \"sys/quotas/*\" { capabilities = [\"read\", \"update\", \"list\", \"delete\"] }"})).status, 204);
    let mut issued = request(
        &mut service,
        "POST",
        "auth/token/create",
        "quota-child",
        &token,
        json!({"policies":["quota-manager"],"no_default_policy":true,"ttl":"10m"}),
    );
    assert_eq!(issued.status, 200);
    let manager = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual child manager")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
        json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/quotas","sys/unseal"]})).status, 204);
    quota(&mut service, &token, "global", "", 9);
    for (method, path, body) in [
        (
            "POST",
            "sys/quotas/rate-limit/child",
            json!({"rate":3,"interval":"1h"}),
        ),
        ("GET", "sys/quotas/rate-limit/child", json!({})),
        ("LIST", "sys/quotas/rate-limit", json!({})),
        ("POST", "sys/quotas/config", json!({})),
        ("GET", "sys/quotas/config", json!({})),
        ("DELETE", "sys/quotas/rate-limit/child", json!({})),
    ] {
        assert_eq!(
            request(&mut service, method, path, "quota-child", &manager, body).status,
            400,
            "2.7.1 root-only management {method} {path}"
        );
    }
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/child",
            "",
            &manager,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/child",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    // The root namespace's ordinary ACL-authorized route selects the actual
    // child catalog through the absolute public path, without a child API.
    quota(&mut service, &token, "child", "quota-child/", 3);
    let definition = request(
        &mut service,
        "GET",
        "sys/quotas/rate-limit/child",
        "",
        &token,
        json!({}),
    );
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["path"], "quota-child/");
    assert_eq!(definition.body["data"]["inheritable"], false);
    let root_read = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "",
        &token,
        json!({}),
    );
    let child_read = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "quota-child",
        &token,
        json!({}),
    );
    assert_eq!(root_read.status, 200);
    assert_eq!(child_read.status, 200);
    assert_eq!(headers(&root_read)?["X-Ratelimit-Remaining"], json!(["8"]));
    assert_eq!(headers(&child_read)?["X-Ratelimit-Remaining"], json!(["2"]));
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let definition = request(
        &mut service,
        "GET",
        "sys/quotas/rate-limit/child",
        "",
        &token,
        json!({}),
    );
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["path"], "quota-child/");
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/child",
            "quota-child",
            &manager,
            json!({})
        )
        .status,
        400
    );
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/quotas/rate-limit/child",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    let inherited = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "quota-child",
        &token,
        json!({}),
    );
    assert_eq!(inherited.status, 200);
    assert_eq!(headers(&inherited)?["X-Ratelimit-Limit"], json!(["9"]));
    assert_eq!(headers(&inherited)?["X-Ratelimit-Remaining"], json!(["8"]));
    Ok(())
}

#[test]
fn quota_139_actual_file_snapshot_rejects_137_downgrade_and_restores_scoped_definitions()
-> TestResult {
    let (root, mut service, key, token) = initialized_pre141()?;
    assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
        json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/quotas"]})).status, 204);
    assert_eq!(
        service.state.as_ref().ok_or("137 actual state")?.schema,
        EXTENDED_RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    let (old_response, old_snapshot) = snapshot(&mut service, &token, None)?;
    assert_eq!(old_response.status, 200);
    let old_snapshot = old_snapshot.ok_or("137 actual snapshot")?;
    quota(&mut service, &token, "scoped", "quota-kv/data/*", 100);
    let (response, saved) = snapshot(&mut service, &token, None)?;
    assert_eq!(response.status, 200);
    let saved = saved.ok_or("139 actual snapshot")?;
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/quotas/rate-limit/scoped",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service.state.as_ref().ok_or("retained 139 floor")?.schema,
        SCOPED_RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    let (rejected, _) = snapshot(&mut service, &token, Some(&old_snapshot))?;
    assert_eq!(rejected.status, 400);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/scoped",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    let (restored, _) = snapshot(&mut service, &token, Some(&saved))?;
    assert_eq!(restored.status, 200);
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let definition = request(
        &mut service,
        "GET",
        "sys/quotas/rate-limit/scoped",
        "",
        &token,
        json!({}),
    );
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["path"], "quota-kv/data/*");
    let actual = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "",
        &token,
        json!({}),
    );
    assert_eq!(actual.status, 200);
    assert_eq!(headers(&actual)?["X-Ratelimit-Remaining"], json!(["99"]));
    Ok(())
}

#[test]
fn quota_139_actual_file_disable_retires_only_its_quotas_and_keeps_exact_root_custody() -> TestResult
{
    let (root, mut service, key, token) = initialized_pre141()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/other-kv",
            "",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "other-kv/data/retained",
            "",
            &token,
            json!({"data":{"value":"retained"}})
        )
        .status,
        200
    );
    for (name, path) in [
        ("retired-mount", "quota-kv/"),
        ("retired-exact", "quota-kv/data/item"),
        ("retired-glob", "quota-kv/data/*"),
        ("retained-other", "other-kv/"),
    ] {
        quota(&mut service, &token, name, path, 100);
    }
    let prior = service
        .native_root
        .as_ref()
        .ok_or("source native root")?
        .clone();
    let source_auth = service.state.as_ref().ok_or("source state")?.auth.clone();
    assert_eq!(
        request(
            &mut service,
            "DELETE",
            "sys/mounts/quota-kv",
            "",
            &token,
            json!({})
        )
        .status,
        204
    );
    let next = service
        .native_root
        .as_ref()
        .ok_or("published native root")?
        .clone();
    let next_auth = service
        .state
        .as_ref()
        .ok_or("published state")?
        .auth
        .clone();
    let mut expected_graphs = prior.kv2.clone();
    expected_graphs
        .retain(|graph| !(graph.scope.namespace.is_empty() && graph.scope.mount == "quota-kv/"));
    assert!(next.kv2 == expected_graphs);
    for (before, after) in prior.owners.iter().zip(&next.owners) {
        assert_eq!(before.domain, after.domain);
        if !matches!(
            before.domain,
            crate::state_record_root_v6::OwnerDomain::Auth
                | crate::state_record_root_v6::OwnerDomain::Engines
        ) {
            assert_eq!(before.owner, after.owner);
        }
    }
    {
        use crate::auth::rate_limit_quotas::MountRetirement;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let capture = || {
            MountRetirement::capture(
                &source_auth,
                &next_auth,
                "",
                "quota-kv/",
                &prior,
                &next,
                &|| true,
            )
        };
        let wrong_scope = capture()?.ok_or("actual quota retirement")?;
        assert!(
            wrong_scope
                .normalize_owned_disable("", "other-kv/", &prior, &mut next.clone(), &|| true)
                .is_err()
        );
        let mut foreign = next_auth.clone();
        foreign.prune_rate_limit_quotas_mount("", "other-kv/");
        assert!(
            MountRetirement::capture(
                &source_auth,
                &foreign,
                "",
                "quota-kv/",
                &prior,
                &next,
                &|| true
            )
            .is_err()
        );
        let expired = capture()?.ok_or("actual quota retirement")?;
        {
            let _expired = crate::request_deadline::RequestDeadlineScope::enter(Instant::now());
            assert!(
                expired
                    .normalize_owned_disable("", "quota-kv/", &prior, &mut next.clone(), &|| true)
                    .is_err()
            );
        }
        let actual = capture()?.ok_or("actual quota retirement")?;
        let mut comparison = next.clone();
        actual.normalize_owned_disable("", "quota-kv/", &prior, &mut comparison, &|| true)?;
        let auth = crate::state_record_root_v6::OwnerDomain::Auth;
        assert_eq!(
            comparison
                .owners
                .iter()
                .find(|owner| owner.domain == auth)
                .ok_or("comparison Auth")?
                .owner,
            prior
                .owners
                .iter()
                .find(|owner| owner.domain == auth)
                .ok_or("prior Auth")?
                .owner
        );
        // This comparison is never installed. The Service retains the actual
        // committed root, including its authenticated removal and graph delta.
        assert_eq!(
            service
                .native_root
                .as_ref()
                .ok_or("still actual root")?
                .identity()
                .map_err(|_| "root identity")?,
            next.identity().map_err(|_| "target identity")?
        );
    }
    for name in ["retired-mount", "retired-exact", "retired-glob"] {
        assert_eq!(
            request(
                &mut service,
                "GET",
                &format!("sys/quotas/rate-limit/{name}"),
                "",
                &token,
                json!({})
            )
            .status,
            404
        );
    }
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/retained-other",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/retired-mount",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/retained-other",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    let retained = request(
        &mut service,
        "GET",
        "other-kv/data/retained",
        "",
        &token,
        json!({}),
    );
    assert_eq!(retained.status, 200);
    assert_eq!(retained.body["data"]["data"]["value"], "retained");
    assert_eq!(
        service.state.as_ref().ok_or("cold state")?.schema,
        SCOPED_RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    Ok(())
}

#[test]
fn quota_139_actual_file_transit_totp_and_pki_disable_each_use_their_own_owner() -> TestResult {
    let (root, mut service, key, token) = initialized_pre141()?;
    for kind in ["transit", "totp", "pki"] {
        let mount = format!("retired-{kind}");
        assert_eq!(
            request(
                &mut service,
                "POST",
                &format!("sys/mounts/{mount}"),
                "",
                &token,
                json!({"type":kind})
            )
            .status,
            204,
            "actual {kind} enable"
        );
        quota(&mut service, &token, &mount, &format!("{mount}/"), 100);
        assert_eq!(
            request(
                &mut service,
                "DELETE",
                &format!("sys/mounts/{mount}"),
                "",
                &token,
                json!({})
            )
            .status,
            204,
            "actual {kind} disable and exact quota retirement"
        );
        assert_eq!(
            request(
                &mut service,
                "GET",
                &format!("sys/quotas/rate-limit/{mount}"),
                "",
                &token,
                json!({})
            )
            .status,
            404
        );
    }
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    for kind in ["transit", "totp", "pki"] {
        assert_eq!(
            request(
                &mut service,
                "GET",
                &format!("sys/quotas/rate-limit/retired-{kind}"),
                "",
                &token,
                json!({})
            )
            .status,
            404
        );
    }
    assert_eq!(
        service.state.as_ref().ok_or("cold state")?.schema,
        SCOPED_RATE_LIMIT_QUOTA_STATE_SCHEMA
    );
    Ok(())
}

fn role_credentials(
    service: &mut Service,
    token: &str,
    role: &str,
) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    let path = format!("auth/role-quota/role/{role}");
    assert_eq!(
        request(
            service,
            "POST",
            &path,
            "",
            token,
            json!({"secret_id_num_uses":0,"token_ttl":60})
        )
        .status,
        204
    );
    let mut role_id = request(
        service,
        "GET",
        &format!("{path}/role-id"),
        "",
        token,
        json!({}),
    );
    assert_eq!(role_id.status, 200);
    let role_value = Zeroizing::new(
        role_id.body["data"]["role_id"]
            .as_str()
            .ok_or("actual role ID")?
            .to_owned(),
    );
    erase_json(&mut role_id.body);
    let mut sid = request(
        service,
        "POST",
        &format!("{path}/secret-id"),
        "",
        token,
        json!({}),
    );
    assert_eq!(sid.status, 200);
    let sid_value = Zeroizing::new(
        sid.body["data"]["secret_id"]
            .as_str()
            .ok_or("actual secret ID")?
            .to_owned(),
    );
    erase_json(&mut sid.body);
    Ok((role_value, sid_value))
}

#[test]
fn quota_139_actual_role_update_retains_original_role_route_name_and_mount_inheritable()
-> TestResult {
    let (root, mut service, key, token) = initialized()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/auth/role-quota",
            "",
            &token,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    let (limited_id, limited_sid) = role_credentials(&mut service, &token, "limited")?;
    let (other_id, other_sid) = role_credentials(&mut service, &token, "other")?;
    assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
        json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/quotas","sys/unseal"]})).status, 204);
    let path = "sys/quotas/rate-limit/role-limit";
    assert_eq!(request(&mut service, "POST", path, "", &token,
        json!({"path":"auth/role-quota/","role":"limited","rate":1,"interval":"1h","inheritable":true})).status, 204);
    assert_eq!(request(&mut service, "POST", path, "", &token,
        json!({"path":"auth/role-quota/","role":"other","rate":1,"interval":"1h","inheritable":true})).status, 204);
    let definition = request(&mut service, "GET", path, "", &token, json!({}));
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["role"], "limited");
    assert_eq!(definition.body["data"]["inheritable"], true);
    for expected in [200, 429] {
        let mut response = request(
            &mut service,
            "POST",
            "auth/role-quota/login",
            "",
            "",
            json!({"role_id":limited_id.as_str(),"secret_id":limited_sid.as_str()}),
        );
        assert_eq!(response.status, expected);
        assert_eq!(headers(&response)?["X-Ratelimit-Limit"], json!(["1"]));
        erase_json(&mut response.body);
    }
    for _ in 0..2 {
        let mut response = request(
            &mut service,
            "POST",
            "auth/role-quota/login",
            "",
            "",
            json!({"role_id":other_id.as_str(),"secret_id":other_sid.as_str()}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(headers(&response)?, json!({}));
        erase_json(&mut response.body);
    }
    assert_eq!(
        request(
            &mut service,
            "POST",
            path,
            "",
            &token,
            json!({"name":"body-chosen-name","path":"auth/role-quota/","role":"other",
               "rate":2,"interval":"1h","inheritable":true})
        )
        .status,
        204
    );
    let definition = request(&mut service, "GET", path, "", &token, json!({}));
    assert_eq!(definition.body["data"]["name"], "role-limit");
    assert_eq!(definition.body["data"]["role"], "limited");
    assert_eq!(definition.body["data"]["rate"], 2.0);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/body-chosen-name",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let definition = request(&mut service, "GET", path, "", &token, json!({}));
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["name"], "role-limit");
    assert_eq!(definition.body["data"]["role"], "limited");
    assert_eq!(definition.body["data"]["rate"], 2.0);
    assert_eq!(definition.body["data"]["inheritable"], true);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/quotas/rate-limit/body-chosen-name",
            "",
            &token,
            json!({})
        )
        .status,
        404
    );
    let mut response = request(
        &mut service,
        "POST",
        "auth/role-quota/login",
        "",
        "",
        json!({"role_id":limited_id.as_str(),"secret_id":limited_sid.as_str()}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(headers(&response)?["X-Ratelimit-Limit"], json!(["2"]));
    assert_eq!(headers(&response)?["X-Ratelimit-Remaining"], json!(["1"]));
    erase_json(&mut response.body);
    Ok(())
}

#[test]
fn quota_139_actual_mount_inheritable_flag_does_not_select_child_mount_after_cold_reopen()
-> TestResult {
    let (root, mut service, key, token) = initialized()?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/namespaces/quota-child",
            "",
            &token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/mounts/quota-kv",
            "quota-child",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "POST",
            "quota-kv/data/item",
            "quota-child",
            &token,
            json!({"data":{"value":"synthetic-child"}})
        )
        .status,
        200
    );
    assert_eq!(request(&mut service, "POST", "sys/quotas/config", "", &token,
        json!({"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/quotas","sys/unseal"]})).status, 204);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/quotas/rate-limit/root-mount",
            "",
            &token,
            json!({"path":"quota-kv/","rate":1,"interval":"1h","inheritable":true})
        )
        .status,
        204
    );
    for expected in [200, 429] {
        let response = request(
            &mut service,
            "GET",
            "quota-kv/data/item",
            "",
            &token,
            json!({}),
        );
        assert_eq!(response.status, expected);
        assert_eq!(headers(&response)?["X-Ratelimit-Limit"], json!(["1"]));
    }
    for _ in 0..2 {
        let response = request(
            &mut service,
            "GET",
            "quota-kv/data/item",
            "quota-child",
            &token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(headers(&response)?, json!({}));
    }
    drop(service);
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    let definition = request(
        &mut service,
        "GET",
        "sys/quotas/rate-limit/root-mount",
        "",
        &token,
        json!({}),
    );
    assert_eq!(definition.status, 200);
    assert_eq!(definition.body["data"]["inheritable"], true);
    let root_read = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "",
        &token,
        json!({}),
    );
    assert_eq!(root_read.status, 200);
    assert_eq!(headers(&root_read)?["X-Ratelimit-Limit"], json!(["1"]));
    let child_read = request(
        &mut service,
        "GET",
        "quota-kv/data/item",
        "quota-child",
        &token,
        json!({}),
    );
    assert_eq!(child_read.status, 200);
    assert_eq!(headers(&child_read)?, json!({}));
    Ok(())
}
