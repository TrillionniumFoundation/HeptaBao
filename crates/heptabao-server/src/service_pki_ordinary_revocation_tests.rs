//! Real deleted A public owner, current B signature, precise retained state105.
use super::*;
use crate::auth::RequestClock;
use crate::http::ocsp::CarrierBody;
use std::time::{Duration, Instant};

struct Fixture {
    root: Root,
    service: Service,
    unseal: String,
    admin: String,
    first: X509,
    second: X509,
    first_id: String,
    second_id: String,
    first_leaf: X509,
    first_serial: String,
    second_serial: String,
}
fn fixture(remote: &RemoteTransit) -> TestResult<Fixture> {
    let (root, mut service, unseal, admin) = pki_fixture(remote)?;
    let first = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v2", "first"),
    );
    assert_eq!(first.status, 200);
    let first_id = first.body["data"]["issuer_id"]
        .as_str()
        .ok_or("A id")?
        .to_owned();
    let first = cert(&first)?;
    assert_eq!(call(&mut service,"POST","external-ca/roles/leaf",&admin,json!({"allow_any_name":true,"key_type":"ec","key_bits":256,"ttl":"10m","max_ttl":"30m"})).status,200);
    let first_leaf = leaf(&mut service, &admin, "external-ca/issue/leaf");
    assert_eq!(first_leaf.status, 200);
    let first_serial = first_leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("A leaf serial")?
        .to_owned();
    let first_leaf = cert(&first_leaf)?;
    second_signer(remote, &mut service, &admin)?;
    let second = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        root_request("remote:v3", "second"),
    );
    assert_eq!(second.status, 200);
    let second_id = second.body["data"]["issuer_id"]
        .as_str()
        .ok_or("B id")?
        .to_owned();
    let second = cert(&second)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "external-ca/config/issuers",
            &admin,
            json!({"default":second_id})
        )
        .status,
        200
    );
    let second_leaf = leaf(&mut service, &admin, "external-ca/issue/leaf");
    assert_eq!(second_leaf.status, 200);
    let second_serial = second_leaf.body["data"]["serial_number"]
        .as_str()
        .ok_or("B leaf serial")?
        .to_owned();
    let public = first.public_key()?;
    assert!(first_leaf.verify(&public)?);
    let public = second.public_key()?;
    assert!(!first_leaf.verify(&public)?);
    Ok(Fixture {
        root,
        service,
        unseal,
        admin,
        first,
        second,
        first_id,
        second_id,
        first_leaf,
        first_serial,
        second_serial,
    })
}
fn revoke(service: &mut Service, admin: &str, serial: &str) -> TestResult<Response> {
    let state = service.state.as_ref().ok_or("actual request state")?;
    let floor = state.engines.lease_clock().max(100).max(
        state
            .auth
            .terminal_token_clock_floor()
            .map_or(0, |at| at.seconds() + 1),
    );
    let clock = RequestClock::anchored(Duration::new(floor, 125_000_000), Instant::now())?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "external-ca/revoke",
            namespace: "",
            token: admin,
            body: json!({"serial_number":serial}),
            now: floor,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    Ok(service.finish_synchronous_request(execution))
}
fn state_wire(state: &State) -> TestResult<CarrierBody> {
    Ok(CarrierBody(serde_json::to_value(&state.engines)?))
}
fn pki_wire(wire: &mut CarrierBody) -> &mut Value {
    &mut wire.0["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]
}

#[test]
fn pki_revocation105_retired_issuer_current_grant_real_crl_and_public_original_der() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let mut f = fixture(&remote)?;
    let before = remote.calls()?;
    let deleted = call(
        &mut f.service,
        "DELETE",
        &format!("external-ca/issuer/{}", f.first_id),
        &f.admin,
        json!({}),
    );
    assert_eq!(deleted.status, 200);
    assert!(deleted.body["data"].is_null());
    assert_eq!(remote.calls()?, before);
    assert_eq!(
        call(
            &mut f.service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut f.service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v3/grants/external-ca",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    let before = remote.calls()?;
    let denied = revoke(&mut f.service, &f.admin, &f.first_serial)?;
    assert!(denied.status >= 400);
    assert_eq!(
        remote.calls()?,
        before,
        "neither original A nor ungranted current B enters a provider effect"
    );
    let read = call(
        &mut f.service,
        "GET",
        &format!("external-ca/cert/{}", f.first_serial),
        &f.admin,
        json!({}),
    );
    assert_eq!(read.body["data"]["revocation_time"], 0);
    assert_eq!(
        call(
            &mut f.service,
            "POST",
            "sys/external-keys/configs/remote/keys/v3/grants/external-ca",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    let before = remote.calls()?;
    let revoked = revoke(&mut f.service, &f.admin, &f.first_serial)?;
    assert_eq!(
        revoked.status, 200,
        "safe errors: {:?}",
        revoked.body["errors"]
    );
    assert_eq!(remote.calls()?, before + 3);
    {
        let trace = remote
            .trace
            .lock()
            .map_err(|_| "public provider path trace")?;
        assert_eq!(
            trace[before..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "/v1/transit/keys/second",
                "/v1/transit/sign/second",
                "/v1/transit/sign/second"
            ],
            "one current public-key metadata read and two actual CRL effects"
        );
    }
    let stamp = revoked.body["data"]["revocation_time_rfc3339"]
        .as_str()
        .ok_or("precise revocation stamp")?;
    assert!(stamp.contains('.'));
    let read = call(
        &mut f.service,
        "GET",
        &format!("external-ca/cert/{}", f.first_serial),
        &f.admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(cert(&read)?.to_der()?, f.first_leaf.to_der()?);
    assert_eq!(read.body["data"]["revocation_time_rfc3339"], stamp);
    let crl = call(
        &mut f.service,
        "GET",
        &format!("external-ca/issuer/{}/crl", f.second_id),
        "",
        json!({}),
    );
    assert_eq!(crl.status, 200);
    let crl = X509Crl::from_pem(crl.body["data"]["crl"].as_str().ok_or("B CRL")?.as_bytes())?;
    let public = f.second.public_key()?;
    assert!(crl.verify(&public)?);
    let wrong = f.first.public_key()?;
    assert!(!crl.verify(&wrong)?);
    let expected = f
        .first_leaf
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string();
    assert!(
        crl.get_revoked()
            .ok_or("actual revoked entries")?
            .iter()
            .any(|r| r.serial_number().to_bn().is_ok_and(|serial| serial
                .to_hex_str()
                .is_ok_and(|serial| serial.to_string() == expected)))
    );
    assert_eq!(f.service.state.as_ref().ok_or("105")?.schema, 105);
    drop(f.service);
    let mut reopened = f.root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":f.unseal})
        )
        .status,
        200
    );
    let read = call(
        &mut reopened,
        "GET",
        &format!("external-ca/cert/{}", f.first_serial),
        &f.admin,
        json!({}),
    );
    assert_eq!(cert(&read)?.to_der()?, f.first_leaf.to_der()?);
    assert_eq!(read.body["data"]["revocation_time_rfc3339"], stamp);
    let before = remote.calls()?;
    let deleted = call(
        &mut reopened,
        "DELETE",
        &format!("external-ca/issuer/{}", f.second_id),
        &f.admin,
        json!({}),
    );
    assert_eq!(deleted.status, 200);
    assert_eq!(
        deleted.body["warnings"],
        json!([
            format!(
                "Deleted issuer {} (via issuer_ref {}); this was configured as the default issuer. Operations without an explicit issuer will not work until a new default is configured.",
                f.second_id, f.second_id
            ),
            "1 roles reference default"
        ])
    );
    let no_signer = revoke(&mut reopened, &f.admin, &f.second_serial)?;
    assert_eq!(no_signer.status, 200);
    assert!(
        no_signer.body["data"]["revocation_time_rfc3339"]
            .as_str()
            .ok_or("retired stamp")?
            .contains('.')
    );
    assert_eq!(
        remote.calls()?,
        before,
        "public history never recovers private authority"
    );
    assert_eq!(reopened.state.as_ref().ok_or("retired105")?.schema, 105);
    Ok(())
}

#[test]
fn pki_revocation105_authentic_predecessor_clock_record_and_restore_fences() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let mut f = fixture(&remote)?;
    let predecessor = f
        .service
        .state
        .as_ref()
        .ok_or("actual94 predecessor")?
        .clone();
    assert_eq!(predecessor.schema, 94);
    assert!(!predecessor.engines.has_ordinary_pki_revocation_state());
    let backup = Zeroizing::new(
        f.service
            .durable
            .as_ref()
            .ok_or("durable")?
            .export_backup()?,
    );
    let revoked = revoke(&mut f.service, &f.admin, &f.second_serial)?;
    assert_eq!(revoked.status, 200);
    let current = f.service.state.as_ref().ok_or("actual105")?.clone();
    assert!(
        current.schema == 105
            && current.writer_schema() == 105
            && current.engines.has_ordinary_pki_revocation_state()
    );
    current
        .validate_format()
        .map_err(|_| "current105 rejected")?;
    for schema in [94, 99, 101, 103, 104] {
        let mut lower = current.clone();
        lower.schema = schema;
        assert!(
            lower.validate_format().is_err()
                && lower
                    .validate_publication_schema(Some(&predecessor))
                    .is_err()
        );
        assert_eq!(lower.writer_schema(), 105);
        assert!(f.service.prepare_record_plan(&mut lower).is_err());
    }
    let canonical = f.second_serial.replace(':', "");
    for mode in 0..4 {
        let mut wire = state_wire(&current)?;
        match mode {
            0 => wire.0["pki_revocation_clock"] = Value::Null,
            1 => wire.0["pki_revocation_clock"] = json!({"seconds":1,"nanoseconds":0}),
            2 => {
                pki_wire(&mut wire)["ordinary_revocations"]
                    .as_object_mut()
                    .ok_or("retained map")?
                    .remove(&canonical);
            }
            _ => {
                pki_wire(&mut wire)["ordinary_revocations"][&canonical]["original_issuer"] =
                    json!(f.first_id)
            }
        }
        let mut invalid = current.clone();
        invalid.engines = serde_json::from_value(wire.0.clone())?;
        assert!(
            invalid.validate_format().is_err()
                || invalid.validate_publication_schema(Some(&current)).is_err()
        );
        assert!(f.service.prepare_record_plan(&mut invalid).is_err());
    }
    assert!(f.service.prepare_snapshot_restore(&backup).is_err());
    assert_eq!(
        call(
            &mut f.service,
            "DELETE",
            "sys/mounts/external-ca",
            &f.admin,
            json!({})
        )
        .status,
        204
    );
    let retired = f.service.state.as_ref().ok_or("sticky105")?;
    assert!(
        retired.schema == 105
            && retired.writer_schema() == 105
            && retired.engines.has_ordinary_pki_revocation_state()
    );
    assert!(f.service.prepare_snapshot_restore(&backup).is_err());
    predecessor
        .validate_format()
        .map_err(|_| "real94 predecessor changed")?;
    Ok(())
}
