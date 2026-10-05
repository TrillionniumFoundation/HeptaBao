//! Actual external signer retirement, independent private/public owner binding,
//! fully authenticated received graphs and backups, and sticky reader88.
use super::*;
use crate::state_record_root::{OpaqueOwnerRef, RecordStateRoot, digest_owner};
use crate::state_records::{ObjectId, ObjectRef, RecordError, RecordReader, StagedObject};
use std::sync::Arc;

fn pki_value(service: &Service, namespace: &str, mount: &str) -> TestResult<CarrierBody> {
    let state = service.state.as_ref().ok_or("actual state")?;
    let engines = CarrierBody(serde_json::to_value(&state.engines)?);
    Ok(CarrierBody(
        engines.0["namespaces"][namespace]["mounts"][mount]["backend"]["Pki"].clone(),
    ))
}
fn root_certificate(response: &Response) -> TestResult<X509> {
    assert!(response.status == 200, "actual root publication");
    Ok(X509::from_pem(
        response.body["data"]["certificate"]
            .as_str()
            .ok_or("actual root PEM")?
            .as_bytes(),
    )?)
}
fn issue_custom(service: &mut Service, admin: &str, issuer: &X509) -> TestResult<(String, String)> {
    let response = call(
        service,
        "POST",
        "external-ca/issue/profile",
        admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    let (serial, pem) = profile_leaf(&response, issuer, true)?;
    Ok((serial.replace(':', ""), pem))
}
fn capture_ids(response: &Response) -> TestResult<(String, String)> {
    Ok((
        response.body["data"]["issuer_id"]
            .as_str()
            .ok_or("actual issuer ID")?
            .to_owned(),
        response.body["data"]["key_id"]
            .as_str()
            .ok_or("actual key ID")?
            .to_owned(),
    ))
}
fn delete_root(service: &mut Service, admin: &str) {
    assert!(
        call(service, "POST", "external-ca/root/delete", admin, json!({})).status == 200,
        "root deletion succeeds while retaining actual signed leaf history"
    );
}
fn read_leaf(service: &mut Service, admin: &str, serial: &str, pem: &str) {
    let read = call(
        service,
        "GET",
        &format!("external-ca/cert/{serial}"),
        admin,
        json!({}),
    );
    assert!(
        read.status == 200
            && read.body["data"]["certificate"] == pem
            && read.body["data"].get("private_key").is_none(),
        "exact public historical leaf bytes"
    );
}

#[test]
fn pki_profile88_external_retirement_same_key_real_ids_mixed_local_rotation_and_original_fence()
-> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let first = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    let issuer_a = root_certificate(&first)?;
    let (id_a, key_a) = capture_ids(&first)?;
    assert_role(
        &call(
            &mut service,
            "POST",
            "external-ca/roles/profile",
            &admin,
            role_body(&custom_profile()),
        ),
        &custom_profile(),
    );
    let (leaf_a, pem_a) = issue_custom(&mut service, &admin, &issuer_a)?;
    let pending = match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "external-ca/issue/profile",
        namespace: "",
        token: &admin,
        body: json!({"common_name":"staged.example.test","ttl":"10m"}),
        now: 100,
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(_) => {
            return Err("actual captured issuer effect did not stage".into());
        }
    };
    let observation = pending.execute();
    delete_root(&mut service, &admin);
    let retired = pki_value(&service, "", "external-ca/")?;
    assert!(
        retired.0["root"].is_null()
            && retired.0["external"].get("root").is_none()
            && retired.0["external"].get("crls").is_none()
            && retired.0["external"]["archived_issuers"]
                .as_object()
                .is_some_and(|rows| rows.len() == 1)
            && retired.0["external"]["issued_public"][&leaf_a]["issuer_id"] == id_a
            && retired.0["issued"][&leaf_a]["external_issuer_owner"]["issuer_id"] == id_a,
        "actual public signer and independent private owner survive retirement"
    );
    let before_read = remote.calls()?;
    read_leaf(&mut service, &admin, &leaf_a, &pem_a);
    assert!(
        remote.calls()? == before_read,
        "history never requests KMS authority"
    );
    assert!(
        call(
            &mut service,
            "POST",
            &format!("external-ca/issuer/{id_a}/issue/profile"),
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"})
        )
        .status
            >= 400,
        "retired public archive is unavailable for issuer selection"
    );
    let second = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    let issuer_b = root_certificate(&second)?;
    let (id_b, key_b) = capture_ids(&second)?;
    assert!(
        id_a != id_b
            && key_a != key_b
            && issuer_a.public_key()?.public_key_to_der()?
                == issuer_b.public_key()?.public_key_to_der()?
            && issuer_a.to_der()? != issuer_b.to_der()?,
        "same actual provider public key produces distinct real issuer/key identities and signed CA bytes"
    );
    let before_finish = service.current_state_identity().map_err(|_| "identity")?;
    let withheld = service.finish_external_request(*pending, observation);
    assert!(
        withheld.status == 503
            && withheld.body.get("data").is_none()
            && service.current_state_identity().map_err(|_| "identity")? == before_finish,
        "original namespace/mount/config/state/provider/issuer capture cannot rebind to same-key successor"
    );
    let (leaf_b, pem_b) = issue_custom(&mut service, &admin, &issuer_b)?;
    let history = pki_value(&service, "", "external-ca/")?;
    assert!(
        history.0["external"]["archived_issuers"]
            .as_object()
            .is_some_and(|rows| rows.len() == 2)
            && history.0["external"]["issued_public"][&leaf_a]["issuer_id"] == id_a
            && history.0["external"]["issued_public"][&leaf_b]["issuer_id"] == id_b,
        "same-key renewal never relabels old history"
    );
    delete_root(&mut service, &admin);
    let local = call(
        &mut service,
        "POST",
        "external-ca/root/generate/internal",
        &admin,
        json!({"common_name":"local-ca.example.test","key_type":"ec","key_bits":256,"ttl":"1h"}),
    );
    let local_issuer = root_certificate(&local)?;
    let local_id = local.body["data"]["issuer_id"]
        .as_str()
        .ok_or("actual local issuer ID")?
        .to_owned();
    let (leaf_local, pem_local) = issue_custom(&mut service, &admin, &local_issuer)?;
    let mixed = pki_value(&service, "", "external-ca/")?;
    assert!(
        mixed.0["issued"][&leaf_local]["local_issuer_id"] == local_id
            && mixed.0["issued"][&leaf_local]
                .get("external_issuer_owner")
                .is_none()
            && mixed.0["issued"][&leaf_a].get("local_issuer_id").is_none()
            && mixed.0["issued"][&leaf_b].get("local_issuer_id").is_none()
            && service
                .state
                .as_ref()
                .ok_or("mixed state")?
                .validate_format()
                .is_ok(),
        "new local identity binds its real leaf without assigning external history"
    );
    delete_root(&mut service, &admin);
    let mut third_body = body();
    third_body["common_name"] = json!("third-ca.example.test");
    let third = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        third_body,
    );
    let issuer_c = root_certificate(&third)?;
    let (leaf_c, pem_c) = issue_custom(&mut service, &admin, &issuer_c)?;
    delete_root(&mut service, &admin);
    assert!(
        service
            .state
            .as_ref()
            .ok_or("mixed retired state")?
            .validate_format()
            .is_ok(),
        "external to local to external retains independent public retired signers"
    );
    for (serial, pem) in [
        (&leaf_a, &pem_a),
        (&leaf_b, &pem_b),
        (&leaf_local, &pem_local),
        (&leaf_c, &pem_c),
    ] {
        read_leaf(&mut service, &admin, serial, pem);
    }
    let backup = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    assert!(
        service.prepare_snapshot_restore(&backup).is_ok(),
        "actual encrypted mixed-history backup validates"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual encrypted mixed historical owners reopen"
    );
    let before = remote.calls()?;
    for (serial, pem) in [
        (&leaf_a, &pem_a),
        (&leaf_b, &pem_b),
        (&leaf_local, &pem_local),
        (&leaf_c, &pem_c),
    ] {
        read_leaf(&mut reopened, &admin, serial, pem);
    }
    assert!(
        remote.calls()? == before && reopened.state.as_ref().ok_or("reopened")?.schema == 88,
        "retired public signatures validate without network or revived private authority"
    );
    Ok(())
}

struct CapturedGraph<'a> {
    source: &'a Service,
    root: RecordStateRoot,
    replacements: BTreeMap<ObjectId, Arc<StagedObject>>,
}
impl RecordReader for CapturedGraph<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        if let Some(object) = self.replacements.get(&reference.id) {
            if object.reference() != reference {
                return Err(RecordError::Corrupt);
            }
            return Ok(Zeroizing::new(object.bytes().to_vec()));
        }
        crate::service::records::DurableReader(
            self.source.durable.as_ref().ok_or(RecordError::Missing)?,
        )
        .read_object(reference)
    }
}
fn captured_engine_graph<'a>(
    source: &'a Service,
    engine_bytes: &[u8],
) -> TestResult<CapturedGraph<'a>> {
    let mut root = source
        .record_root
        .as_ref()
        .ok_or("actual record root")?
        .clone();
    let key = root.address_key();
    let mut replacements = BTreeMap::new();
    let mut chunks = Vec::new();
    for bytes in engine_bytes.chunks(crate::state_record_root::OWNER_CHUNK_BYTES) {
        let object = StagedObject::owner_chunk(&key, bytes).map_err(|_| "actual owner chunk")?;
        chunks.push(object.reference().clone());
        replacements.insert(object.reference().id, object);
    }
    root.owners[2] = OpaqueOwnerRef {
        name: "engines".into(),
        total_bytes: engine_bytes.len() as u64,
        chunks,
        digest: digest_owner(&key, "engines", engine_bytes)
            .map_err(|_| "actual typed engine owner digest")?,
    };
    root.validate()
        .map_err(|_| "complete authenticated record root")?;
    Ok(CapturedGraph {
        source,
        root,
        replacements,
    })
}
fn authenticated_graph_backup(graph: &CapturedGraph<'_>) -> TestResult<Zeroizing<Vec<u8>>> {
    let isolated = Root::new();
    private_directory(&isolated.path)?;
    let key = **graph
        .source
        .barrier_key
        .as_ref()
        .ok_or("actual barrier key")?;
    let barrier = AeadBarrier::new(key).map_err(|_| "actual barrier")?;
    let limit = graph
        .source
        .durable
        .as_ref()
        .ok_or("source durable")?
        .capacity_status()
        .retained_request_limit;
    let mut durable = DurableService::create_new(isolated.path.join("archive"), barrier, limit)?;
    let original = Zeroizing::new(
        graph
            .source
            .durable
            .as_ref()
            .ok_or("source durable")?
            .export_backup()?,
    );
    durable.restore_backup(&original, true)?;
    for (index, object) in graph.replacements.values().enumerate() {
        durable.put_in_replay_epoch(
            durable.replay_epoch(),
            PutRequest::new(
                "test",
                "system",
                format!("captured-engine-{index}"),
                object.reference().resource(),
                [2; 32],
                Secret::new(object.bytes().to_vec())?,
            )?,
        )?;
    }
    let root_bytes = graph.root.encode().map_err(|_| "complete root encoding")?;
    durable.put_in_replay_epoch(
        durable.replay_epoch(),
        PutRequest::new(
            "test",
            "system",
            "captured-root",
            "state",
            [3; 32],
            Secret::new(root_bytes.to_vec())?,
        )?,
    )?;
    Ok(Zeroizing::new(durable.export_backup()?))
}

#[test]
fn pki_profile88_retired_archive_tamper_closed_received_graph_and_authenticated_backup()
-> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let a = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    let issuer_a = root_certificate(&a)?;
    let (id_a, _) = capture_ids(&a)?;
    assert_role(
        &call(
            &mut service,
            "POST",
            "external-ca/roles/profile",
            &admin,
            role_body(&custom_profile()),
        ),
        &custom_profile(),
    );
    let (leaf_a, pem_a) = issue_custom(&mut service, &admin, &issuer_a)?;
    delete_root(&mut service, &admin);
    let b = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    let issuer_b = root_certificate(&b)?;
    let (id_b, _) = capture_ids(&b)?;
    let (leaf_b, _pem_b) = issue_custom(&mut service, &admin, &issuer_b)?;
    delete_root(&mut service, &admin);
    let original = service.state.as_ref().ok_or("actual state")?.clone();
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service
        .durable
        .as_ref()
        .ok_or("actual durable")?
        .generation();
    let canonical = crate::service::owner_store::serialize_owner(&original.engines)
        .map_err(|_| "real engine bytes")?;
    let graph = captured_engine_graph(&service, &canonical)?;
    assert!(
        Service::materialize_record_state(&graph.root, &graph).is_ok(),
        "positive complete authenticated received graph includes retired issuer and original private leaf owners"
    );
    let valid_backup = authenticated_graph_backup(&graph)?;
    assert!(
        service.prepare_snapshot_restore(&valid_backup).is_ok(),
        "positive barrier-authenticated complete graph backup, without missing unrelated records"
    );
    for change in 0..10 {
        let mut encoded = CarrierBody(serde_json::to_value(&original.engines)?);
        let pki = &mut encoded.0["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"];
        match change {
            0 => pki["external"]["issued_public"][&leaf_a]["issuer_id"] = json!(id_b),
            1 => pki["issued"][&leaf_a]["external_issuer_owner"]["issuer_id"] = json!(id_b),
            2 => {
                let octet =
                    &mut pki["issued"][&leaf_a]["external_issuer_owner"]["issuer_sha256"][0];
                *octet = json!(octet.as_u64().ok_or("owner digest byte")? ^ 1);
            }
            3 => {
                let der = pki["external"]["archived_issuers"][&id_a]["certificate_der"]
                    .as_array_mut()
                    .ok_or("CA bytes")?;
                let byte = der.last_mut().ok_or("CA signature byte")?;
                *byte = json!(byte.as_u64().ok_or("CA signature octet")? ^ 1);
            }
            4 => {
                pki["external"]["archived_issuers"]
                    .as_object_mut()
                    .ok_or("archives")?
                    .remove(&id_a);
            }
            5 => {
                let mut replacement = pki["external"]["archived_issuers"][&id_b].clone();
                replacement["issuer_id"] = json!(id_a);
                pki["external"]["archived_issuers"][&id_a] = replacement;
            }
            6 => {
                let projection = pki["external"]["issued_public"][&leaf_b].clone();
                pki["external"]["issued_public"][&leaf_a] = projection;
            }
            7 => {
                pki["issued"][&leaf_a]["local_issuer_id"] = json!(id_b);
            }
            8 => {
                pki["external"]["archived_issuers"][&id_a]["public_key"] = json!(vec![0u8; 32]);
            }
            _ => {
                pki["issued"][&leaf_a]["certificate_der"] =
                    pki["external"]["archived_issuers"][&id_a]["certificate_der"].clone();
            }
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&encoded.0)?);
        let graph = captured_engine_graph(&service, &bytes)?;
        assert!(
            Service::materialize_record_state(&graph.root, &graph).is_err(),
            "complete received graph rejects actual issuer redirection, archive replacement, wrong key, CA/leaf DER or private owner tamper"
        );
        let backup = authenticated_graph_backup(&graph)?;
        assert!(
            service.prepare_snapshot_restore(&backup).is_err(),
            "same complete archive is barrier-authenticated yet rejects captured signer tamper before restore"
        );
        let mut reader = backup.as_slice();
        assert!(
            service
                .prepare_snapshot_restore_from_reader(&mut reader, backup.len() as u64)
                .is_err(),
            "streamed authenticated backup enforces the same actual public/private owner binding"
        );
        let mut invalid = original.clone();
        invalid.engines = serde_json::from_slice(&bytes)?;
        assert!(
            invalid.validate_format().is_err() && service.commit_state(&mut invalid).is_err(),
            "actual publication also rejects signer-owner tamper"
        );
        assert!(
            service.current_state_identity().map_err(|_| "identity")? == before
                && service.durable.as_ref().ok_or("durable")?.generation() == generation,
            "every invalid received/backup candidate leaves original private publication intact"
        );
    }
    for field in ["reference", "pkcs8", "provider_grant"] {
        let mut encoded = CarrierBody(serde_json::to_value(&original.engines)?);
        encoded.0["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["external"]["archived_issuers"]
            [&id_a][field] = json!("forbidden");
        let bytes = Zeroizing::new(serde_json::to_vec(&encoded.0)?);
        assert!(
            serde_json::from_slice::<EngineState>(&bytes).is_err(),
            "strict archive never grants provider/private authority"
        );
        let graph = captured_engine_graph(&service, &bytes)?;
        let backup = authenticated_graph_backup(&graph)?;
        assert!(
            service.prepare_snapshot_restore(&backup).is_err(),
            "authenticated owner decoder denies archive authority fields"
        );
    }
    read_leaf(&mut service, &admin, &leaf_a, &pem_a);
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "original encrypted historical owner still reopens after all rejections"
    );
    read_leaf(&mut reopened, &admin, &leaf_a, &pem_a);
    Ok(())
}

#[test]
fn pki_profile88_actual_external_namespace_owner_archives_remain_separate() -> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let mut rows = Vec::new();
    for namespace in ["team-a", "team-b"] {
        assert!(
            call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{namespace}"),
                &admin,
                json!({})
            )
            .status
                == 200,
            "actual namespace creation"
        );
        for (path, input, status) in [
            ("sys/mounts/external-ca", json!({"type":"pki"}), 204),
            (
                "sys/external-keys/configs/remote",
                json!({"plugin":"transit","verify":false,
                "address":remote.origin(),"token":remote.admin,"mount_path":"transit"}),
                204,
            ),
            (
                "sys/external-keys/configs/remote/keys/v2",
                json!({"verify":false,"name":"remote","version":2}),
                204,
            ),
            (
                "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
                json!({}),
                204,
            ),
        ] {
            assert!(
                service
                    .handle_at("POST", path, namespace, &admin, input, 100)
                    .status
                    == status,
                "actual namespace-specific provider/config/grant and mount admission"
            );
        }
        let generated = service.handle_at(
            "POST",
            "external-ca/root/generate/kms",
            namespace,
            &admin,
            body(),
            100,
        );
        let issuer = root_certificate(&generated)?;
        let (id, _) = capture_ids(&generated)?;
        assert_role(
            &service.handle_at(
                "POST",
                "external-ca/roles/profile",
                namespace,
                &admin,
                role_body(&custom_profile()),
                100,
            ),
            &custom_profile(),
        );
        let issued = service.handle_at(
            "POST",
            "external-ca/issue/profile",
            namespace,
            &admin,
            json!({"common_name":"leaf.example.test","ttl":"10m"}),
            100,
        );
        let (serial, pem) = profile_leaf(&issued, &issuer, true)?;
        let serial = serial.replace(':', "");
        assert!(
            service
                .handle_at(
                    "POST",
                    "external-ca/root/delete",
                    namespace,
                    &admin,
                    json!({}),
                    100
                )
                .status
                == 200,
            "actual namespaced root deletion succeeds"
        );
        let stored = pki_value(&service, namespace, "external-ca/")?;
        assert!(
            stored.0["external"]["archived_issuers"]
                .as_object()
                .is_some_and(|map| map.len() == 1)
                && stored.0["external"]["issued_public"][&serial]["issuer_id"] == id
                && stored.0["issued"][&serial]["external_issuer_owner"]["issuer_id"] == id,
            "private and public issuer captures stay inside the actual namespace mount"
        );
        rows.push((namespace, serial, pem, id));
    }
    assert!(
        rows[0].3 != rows[1].3,
        "same provider key never merges namespace issuer identities"
    );
    let original = service.state.as_ref().ok_or("namespace state")?.clone();
    let mut encoded = CarrierBody(serde_json::to_value(&original.engines)?);
    let foreign =
        encoded.0["namespaces"][rows[0].0]["mounts"]["external-ca/"]["backend"]["Pki"]["external"]
            ["archived_issuers"][&rows[0].3]
            .clone();
    encoded.0["namespaces"][rows[1].0]["mounts"]["external-ca/"]["backend"]["Pki"]["external"]["archived_issuers"]
        [&rows[1].3] = foreign;
    let bytes = Zeroizing::new(serde_json::to_vec(&encoded.0)?);
    let graph = captured_engine_graph(&service, &bytes)?;
    assert!(
        Service::materialize_record_state(&graph.root, &graph).is_err(),
        "received record cannot substitute another namespace's actual issuer archive"
    );
    let backup = authenticated_graph_backup(&graph)?;
    assert!(
        service.prepare_snapshot_restore(&backup).is_err(),
        "authenticated complete namespace backup rejects foreign archive substitution"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200,
        "actual multi-namespace archive encrypted reopen"
    );
    let before = remote.calls()?;
    for (namespace, serial, pem, _) in rows {
        let response = reopened.handle_at(
            "GET",
            &format!("external-ca/cert/{serial}"),
            namespace,
            &admin,
            json!({}),
            100,
        );
        assert!(
            response.status == 200 && response.body["data"]["certificate"] == pem,
            "each actual namespace retains exact historical signed leaf"
        );
    }
    assert!(
        remote.calls()? == before,
        "namespace history reads never use provider authority"
    );
    Ok(())
}

#[test]
fn pki_profile88_last_external_archive_tidy_preserves_actual85_input_and_sticky88_floor()
-> TestResult {
    let remote = RemoteTransit::new_kind("ecdsa-p256")?;
    let (root, mut service, unseal, admin) = pki_fixture(&remote)?;
    let generated = call(
        &mut service,
        "POST",
        "external-ca/root/generate/kms",
        &admin,
        body(),
    );
    let issuer = root_certificate(&generated)?;
    let mut predecessor = install_historical85_role(&mut service, "", "external-ca/")?;
    let old85 = Zeroizing::new(service.durable.as_ref().ok_or("durable")?.export_backup()?);
    let mut old_restore = service
        .prepare_snapshot_restore(&old85)
        .map_err(|_| "actual85 prepared restore")?;
    let old_plan = service
        .prepare_record_plan(&mut predecessor)
        .map_err(|_| "actual85 received plan")?;
    assert_role(
        &call(
            &mut service,
            "PATCH",
            "external-ca/roles/historical",
            &admin,
            custom_profile(),
        ),
        &custom_profile(),
    );
    let issued = call(
        &mut service,
        "POST",
        "external-ca/issue/historical",
        &admin,
        json!({"common_name":"leaf.example.test","ttl":"10m"}),
    );
    let (serial, pem) = profile_leaf(&issued, &issuer, true)?;
    let serial = serial.replace(':', "");
    delete_root(&mut service, &admin);
    assert!(
        call(
            &mut service,
            "DELETE",
            "external-ca/roles/historical",
            &admin,
            json!({})
        )
        .status
            == 204,
        "remove only role while signed leaf and public archive remain real owners"
    );
    let current = service.state.as_ref().ok_or("actual retired owner")?;
    assert!(
        current.schema == 88 && current.engines.has_pki_role_leaf_profile_state(),
        "retired last signer/private leaf requires88 without a role descriptor"
    );
    let stored = pki_value(&service, "", "external-ca/")?;
    assert!(
        stored.0["external"]["archived_issuers"]
            .as_object()
            .is_some_and(|map| map.len() == 1),
        "root/delete keeps last actual referenced archive"
    );
    read_leaf(&mut service, &admin, &serial, &pem);
    assert!(
        service
            .handle_at(
                "POST",
                "external-ca/tidy",
                "",
                &admin,
                json!({"safety_buffer":"0s"}),
                701
            )
            .status
            == 204,
        "actual certificate expiration and zero-buffer tidy remove original references"
    );
    let stored = pki_value(&service, "", "external-ca/")?;
    assert!(
        stored.0["issued"]
            .as_object()
            .is_some_and(|map| map.is_empty())
            && stored.0.get("external").is_none(),
        "only after actual last issued record removal does its public archive disappear"
    );
    let retired = service.state.as_ref().ok_or("sticky88")?.clone();
    assert!(
        retired.schema == 88
            && retired.writer_schema() == 88
            && !retired.engines.has_pki_role_leaf_profile_state()
            && retired.validate_format().is_ok(),
        "last archive/private reference removal keeps durable reader88 despite no active profile facts"
    );
    for schema in [65, 71, 80, 81, 82, 83, 84, 85, 86, 87] {
        let mut lowered = retired.clone();
        lowered.schema = schema;
        assert!(
            lowered.validate_publication_schema(Some(&retired)).is_err()
                && service.commit_state(&mut lowered).is_err(),
            "lowered-format publication refuses real sticky88"
        );
    }
    assert!(
        service.prepare_snapshot_restore(&old85).is_err(),
        "original authenticated85 bytes remain immutable and fail after last owner retirement"
    );
    let mut reader = old85.as_slice();
    assert!(
        service
            .prepare_snapshot_restore_from_reader(&mut reader, old85.len() as u64)
            .is_err(),
        "streamed original85 backup independently fails sticky88"
    );
    let before = service.current_state_identity().map_err(|_| "identity")?;
    old_restore.fixture_rebind_base_for_protected_floor(before);
    let principal = service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate_from(&admin, 701, None)
        .map_err(|_| "actual restore principal")?;
    let input = json!({});
    let request = RequestView {
        method: "POST",
        path: "sys/storage/raft/snapshot-force",
        namespace: "",
        token: &admin,
        body: &input,
        now: 701,
        admission_started: std::time::Instant::now(),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    };
    let rejected = service.commit_snapshot_restore(old_restore, &principal, &request);
    assert!(
        rejected.status == 400
            && rejected.body["errors"][0] == "snapshot would downgrade PKI role leaf profiles",
        "held actual85 restore reaches final protected gate after original last-archive tidy"
    );
    assert!(
        service
            .install_received_record_state(predecessor, old_plan)
            .is_err()
            && service.current_state_identity().map_err(|_| "identity")? == before,
        "original85 received graph cannot roll last-owner state back"
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status
            == 200
            && reopened.state.as_ref().ok_or("restart")?.schema == 88
            && reopened.state.as_ref().ok_or("restart")?.writer_schema() == 88,
        "actual encrypted restart retains sticky88 after original archive/reference deletion"
    );
    assert!(
        reopened.prepare_snapshot_restore(&old85).is_err(),
        "original85 remains denied after encrypted restart"
    );
    Ok(())
}
