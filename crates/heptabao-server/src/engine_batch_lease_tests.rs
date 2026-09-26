use super::*;
use crate::auth::{AuthState, BatchClaims, BatchKeyAuthority, LeaseOwner, ResolvedLeaseOwner};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn batch_owner(
    authority: &mut BatchKeyAuthority,
    namespace: &str,
    parent: Option<String>,
    now: u64,
    ttl: u64,
) -> std::result::Result<LeaseOwner, Box<dyn std::error::Error>> {
    let claims = BatchClaims {
        namespace: namespace.into(),
        policies: BTreeSet::from(["default".into()]),
        metadata: BTreeMap::new(),
        display_name: "test-issuer".into(),
        path: "auth/userpass/login/fixture".into(),
        bound_cidrs: Vec::new(),
        issued_at: now,
        expires_at: now + ttl,
        parent,
        entity_id: None,
    };
    let token = authority.seal(claims, now)?;
    Ok(LeaseOwner::from_batch(&authority.open(
        token.as_str(),
        namespace,
        now,
    )?))
}

fn admin(
    state: &mut EngineState,
    namespace: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Result<EngineResponse> {
    state
        .handle(namespace, "POST", path, &body, now)?
        .ok_or_else(|| error(599, "test route missing"))
}

fn setup_ssh(state: &mut EngineState, namespace: &str, now: u64) -> TestResult {
    admin(
        state,
        namespace,
        "sys/mounts/ssh",
        json!({"type":"ssh"}),
        now,
    )?;
    admin(
        state,
        namespace,
        "ssh/roles/worker",
        json!({"key_type":"otp","default_user":"alice","cidr_list":"127.0.0.0/8"}),
        now,
    )?;
    Ok(())
}

#[test]
fn real_parent_revocation_reconciles_batch_ssh_without_a_batch_token_record() -> TestResult {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    let principal = auth.authenticate(&root, 100)?;
    let created = auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"],"ttl":200}),
            100,
        )?
        .ok_or("create")?;
    let parent = Zeroizing::new(
        created.body["auth"]["client_token"]
            .as_str()
            .ok_or("parent")?
            .to_owned(),
    );
    let digest = URL_SAFE_NO_PAD.encode(crate::crypto::digest(parent.as_bytes()));
    let mut authority = BatchKeyAuthority::new(100)?;
    let child_owner = batch_owner(&mut authority, "", Some(digest), 100, 500)?;
    let orphan_owner = batch_owner(&mut authority, "", None, 100, 500)?;
    // Install a real serialized authority as future bootstrap does. This does
    // not fabricate a Token entry or issue a batch through a public API.
    let mut serialized = serde_json::to_value(&auth)?;
    let service_count = serialized["tokens"].as_object().ok_or("tokens")?.len();
    serialized["batch_authority"] = serde_json::to_value(&authority)?;
    auth = serde_json::from_value(serialized)?;
    let child = auth
        .resolve_lease_owner(&child_owner, "", 100)
        .ok_or("live child")?;
    let orphan = auth
        .resolve_lease_owner(&orphan_owner, "", 100)
        .ok_or("live orphan")?;
    assert_eq!(child.expires_at, Some(600));
    assert_eq!(orphan.expires_at, Some(600));
    let mut engines = EngineState::default();
    setup_ssh(&mut engines, "", 100)?;
    let issue = |engines: &mut EngineState, owner: &ResolvedLeaseOwner| {
        engines.handle_service_ssh(
            "",
            "POST",
            "ssh/creds/worker",
            &json!({"ip":"127.0.0.1"}),
            Some(owner),
            100,
        )
    };
    let child_otp = issue(&mut engines, &child)?;
    let orphan_otp = issue(&mut engines, &orphan)?;
    assert_eq!(child_otp.body["lease_duration"], 500);
    assert_eq!(orphan_otp.body["lease_duration"], 500);
    auth.handle(
        Some(&principal),
        "",
        "POST",
        "auth/token/revoke",
        &json!({"token":parent.as_str()}),
        101,
    )?
    .ok_or("revoke")?;
    assert!(auth.resolve_lease_owner(&child_owner, "", 101).is_none());
    assert!(auth.resolve_lease_owner(&orphan_owner, "", 101).is_some());
    let live = engines
        .lease_owners()
        .into_iter()
        .filter(|(ns, owner)| auth.resolve_lease_owner(owner, ns, 101).is_some())
        .collect();
    assert!(engines.reconcile_lease_state(101, &live));
    let verify = |engines: &mut EngineState, response: &EngineResponse| {
        engines.handle_service_ssh(
            "",
            "POST",
            "ssh/verify",
            &json!({"otp":response.body["data"]["key"]}),
            None,
            101,
        )
    };
    assert!(verify(&mut engines, &child_otp).is_err());
    assert_eq!(verify(&mut engines, &orphan_otp)?.status, 200);
    assert_eq!(
        serde_json::to_value(&auth)?["tokens"]
            .as_object()
            .ok_or("tokens")?
            .len(),
        service_count - 1
    );
    let reopened: EngineState = serde_json::from_slice(&serde_json::to_vec(&engines)?)?;
    reopened.validate_lease_state()?;
    assert!(
        reopened
            .all_lease_owners()
            .contains(&("".into(), orphan_owner))
    );
    Ok(())
}

#[test]
fn stored_batch_owner_cannot_move_namespaces_or_issue_into_another_mount_scope() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let owner = batch_owner(&mut authority, "team-a", None, 100, 300)?;
    let issuer = ResolvedLeaseOwner {
        owner,
        expires_at: Some(400),
        entity_id: None,
    };
    let mut engines = EngineState::default();
    setup_ssh(&mut engines, "team-a", 100)?;
    setup_ssh(&mut engines, "team-b", 100)?;
    let before = serde_json::to_vec(&engines)?;
    assert!(
        engines
            .handle_service_ssh(
                "team-b",
                "POST",
                "ssh/creds/worker",
                &json!({"ip":"127.0.0.1"}),
                Some(&issuer),
                100
            )
            .is_err()
    );
    assert_eq!(before, serde_json::to_vec(&engines)?);
    engines.handle_service_ssh(
        "team-a",
        "POST",
        "ssh/creds/worker",
        &json!({"ip":"127.0.0.1"}),
        Some(&issuer),
        100,
    )?;
    engines.validate_lease_state()?;
    let mut serialized = serde_json::to_value(&engines)?;
    let from = serialized["namespaces"]
        .as_object_mut()
        .ok_or("namespaces")?
        .remove("team-a")
        .ok_or("team-a")?;
    serialized["namespaces"]["team-b"] = from;
    let crossed: EngineState = serde_json::from_value(serialized)?;
    assert!(crossed.validate_lease_state().is_err());
    Ok(())
}

#[test]
fn retained_revoked_and_nonleased_pki_owners_stay_visible_to_format_validation() -> TestResult {
    let now = 1_700_000_000;
    let mut authority = BatchKeyAuthority::new(now)?;
    let owner = batch_owner(&mut authority, "team", None, now, 600)?;
    let issuer = ResolvedLeaseOwner {
        owner: owner.clone(),
        expires_at: Some(now + 300),
        entity_id: None,
    };
    let mut engines = EngineState::default();
    admin(
        &mut engines,
        "team",
        "sys/mounts/pki",
        json!({"type":"pki"}),
        now,
    )?;
    admin(
        &mut engines,
        "team",
        "pki/root/generate/internal",
        json!({"common_name":"ca.example.test","ttl":"48h"}),
        now,
    )?;
    for (role, leased) in [("leased", true), ("unleased", false)] {
        admin(
            &mut engines,
            "team",
            &format!("pki/roles/{role}"),
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h","generate_lease":leased}),
            now,
        )?;
        let issued = engines.handle_service_pki(
            "team",
            "POST",
            &format!("pki/issue/{role}"),
            &json!({"common_name":"api.example.test","ttl":"1h"}),
            &issuer,
            now,
        )?;
        assert_eq!(issued.body["data"]["expiration"], now + 300);
    }
    assert!(engines.reconcile_lease_state(now + 1, &BTreeSet::new()));
    assert!(engines.lease_owners().is_empty());
    assert!(engines.all_lease_owners().contains(&("team".into(), owner)));
    let reopened: EngineState = serde_json::from_slice(&serde_json::to_vec(&engines)?)?;
    reopened.validate_lease_state()?;
    assert_eq!(reopened.all_lease_owners().len(), 1);
    let Backend::Pki(pki) = &reopened
        .namespaces
        .get("team")
        .ok_or("team")?
        .mounts
        .get("pki/")
        .ok_or("pki")?
        .backend
    else {
        return Err("pki backend".into());
    };
    assert_eq!(
        pki.issued
            .values()
            .filter(|cert| cert.revoked_at.is_some())
            .count(),
        1
    );
    assert_eq!(
        pki.issued
            .values()
            .filter(|cert| !cert.leased && cert.revoked_at.is_none())
            .count(),
        1
    );
    Ok(())
}

#[test]
fn ldap_renewal_caps_current_owner_and_rejects_changes_without_partial_expiry() -> TestResult {
    let mut authority = BatchKeyAuthority::new(100)?;
    let owner = batch_owner(&mut authority, "team", None, 100, 600)?;
    let mut issuer = ResolvedLeaseOwner {
        owner: owner.clone(),
        expires_at: Some(220),
        entity_id: None,
    };
    let mut ldap = openldap::OpenLdap::default();
    ldap.dispatch("team", "ldap/", "POST", "config", &json!({"url":"ldaps://directory.example.test:636","binddn":"cn=manager,dc=example,dc=test","bindpass":"synthetic-secret","userdn":"ou=people,dc=example,dc=test"}), 100, None)?;
    ldap.dispatch("team", "ldap/", "POST", "role/reader", &json!({
        "creation_ldif":"dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: add\nobjectClass: inetOrgPerson\ncn: {{.Username}}\nsn: User\nuid: {{.Username}}\nuserPassword: {{.Password}}",
        "deletion_ldif":"dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: delete", "default_ttl":60,"max_ttl":600
    }), 100, None)?;
    let openldap::Dispatch::External(plan) = ldap.dispatch(
        "team",
        "ldap/",
        "GET",
        "creds/reader",
        &json!({}),
        100,
        Some(&issuer),
    )?
    else {
        return Err("issue plan".into());
    };
    let id = plan.lease_id.clone();
    assert!(ldap.lease_owners().any(|value| value == &owner));
    // Engine-level completion only: no provider I/O is claimed by this test.
    ldap.finalize(&plan)?;
    let renewed = ldap.renew(&id, &issuer, 500, 110)?;
    assert_eq!(renewed.body["lease_duration"], 110);
    assert_eq!(
        ldap.lease_authority(&id).map(|(_, expires)| expires),
        Some(220)
    );
    issuer.expires_at = Some(180);
    ldap.renew(&id, &issuer, 500, 120)?;
    assert_eq!(
        ldap.lease_authority(&id).map(|(_, expires)| expires),
        Some(180)
    );
    let before = serde_json::to_vec(&ldap)?;
    issuer.expires_at = Some(120);
    assert!(ldap.renew(&id, &issuer, 500, 120).is_err());
    issuer.expires_at = Some(200);
    issuer.owner = batch_owner(&mut authority, "team", None, 100, 600)?;
    assert!(ldap.renew(&id, &issuer, 500, 120).is_err());
    assert_eq!(before, serde_json::to_vec(&ldap)?);
    let reopened: openldap::OpenLdap = serde_json::from_slice(&before)?;
    reopened.validate_scope("team")?;
    assert!(reopened.validate_scope("other").is_err());
    assert_eq!(
        reopened.reconcile_candidates(120, &BTreeSet::new()),
        vec![(id, true)]
    );
    Ok(())
}

#[test]
fn batch_lease_keeps_own_expiry_after_live_parent_shortening_but_stops_at_parent_expiry()
-> TestResult {
    let (mut auth, root) = AuthState::bootstrap(100)?;
    let principal = auth.authenticate(&root, 100)?;
    let parent_response = auth
        .handle(
            Some(&principal),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"],"ttl":120}),
            100,
        )?
        .ok_or("parent")?;
    let parent = Zeroizing::new(
        parent_response.body["auth"]["client_token"]
            .as_str()
            .ok_or("parent token")?
            .to_owned(),
    );
    let digest = URL_SAFE_NO_PAD.encode(crate::crypto::digest(parent.as_bytes()));
    let mut authority = BatchKeyAuthority::new(100)?;
    let owner = batch_owner(&mut authority, "", Some(digest.clone()), 100, 60)?;
    let mut serialized = serde_json::to_value(&auth)?;
    serialized["batch_authority"] = serde_json::to_value(authority)?;
    auth = serde_json::from_value(serialized)?;
    let before = auth.resolve_lease_owner(&owner, "", 100).ok_or("before")?;
    assert_eq!(before.expires_at, Some(160));
    auth.handle(
        Some(&principal),
        "",
        "POST",
        "auth/token/renew",
        &json!({"token":parent.as_str(),"increment":6}),
        100,
    )?
    .ok_or("renew")?;
    let shortened = auth
        .resolve_lease_owner(&owner, "", 100)
        .ok_or("shortened live parent")?;
    assert_eq!(shortened.expires_at, Some(160));
    // The historical service-token owner keeps its existing conservative cap;
    // only the newly implemented batch contract changes in this patch.
    let service_owner = LeaseOwner::service(&digest)?;
    assert_eq!(
        auth.resolve_lease_owner(&service_owner, "", 100)
            .ok_or("service")?
            .expires_at,
        Some(106)
    );
    let mut engines = EngineState::default();
    setup_ssh(&mut engines, "", 100)?;
    let held = engines.handle_service_ssh(
        "",
        "POST",
        "ssh/creds/worker",
        &json!({"ip":"127.0.0.1"}),
        Some(&shortened),
        100,
    )?;
    assert_eq!(held.body["lease_duration"], 60);
    assert!(auth.resolve_lease_owner(&owner, "", 105).is_some());
    assert!(auth.resolve_lease_owner(&owner, "", 106).is_none());
    let live = engines
        .lease_owners()
        .into_iter()
        .filter(|(ns, owner)| auth.resolve_lease_owner(owner, ns, 106).is_some())
        .collect();
    assert!(engines.reconcile_lease_state(106, &live));
    assert!(
        engines
            .handle_service_ssh(
                "",
                "POST",
                "ssh/verify",
                &json!({"otp":held.body["data"]["key"]}),
                None,
                106
            )
            .is_err()
    );
    Ok(())
}
