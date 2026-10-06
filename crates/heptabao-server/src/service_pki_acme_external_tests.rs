//! Real TLS Transit signs ACME CSR leaves; public accounts never become token owners.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::x509::{X509, X509NameBuilder, X509Req, extension::SubjectAlternativeName};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};

fn key() -> TestResult<(PKey<Private>, Value)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group)?;
    let mut x = openssl::bn::BigNum::new()?;
    let mut y = openssl::bn::BigNum::new()?;
    let mut context = BigNumContext::new()?;
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)?;
    let jwk = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(x.to_vec_padded(32)?),"y":URL_SAFE_NO_PAD.encode(y.to_vec_padded(32)?)});
    Ok((PKey::from_ec_key(ec)?, jwk))
}
fn signed(
    key: &PKey<Private>,
    jwk: &Value,
    nonce: &str,
    url: &str,
    kid: Option<&str>,
    payload: Option<Value>,
) -> TestResult<Value> {
    let mut header = json!({"alg":"ES256","nonce":nonce,"url":url});
    match kid {
        Some(kid) => header["kid"] = json!(kid),
        None => header["jwk"] = jwk.clone(),
    }
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = payload
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let message = format!("{protected}.{payload}");
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(message.as_bytes())?;
    let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    let mut raw = signature.r().to_vec_padded(32)?;
    raw.extend(signature.s().to_vec_padded(32)?);
    Ok(json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(raw)}))
}
fn header(response: &Response, name: &str) -> TestResult<String> {
    let h = serde_json::to_value(&response.response_headers)?;
    Ok(h[name][0]
        .as_str()
        .ok_or("actual filtered ACME header")?
        .to_owned())
}

fn nonce(service: &mut Service) -> TestResult<String> {
    let response = call(service, "HEAD", "external-ca/acme/new-nonce", "", json!({}));
    assert_eq!(response.status, 200);
    header(&response, "Replay-Nonce")
}

fn order_post(
    service: &mut Service,
    key: &PKey<Private>,
    jwk: &Value,
    kid: &str,
    endpoint: &str,
    payload: Option<Value>,
) -> TestResult<Response> {
    let n = nonce(service)?;
    let base = "https://acme.example.test/v1/external-ca/acme/";
    let request = signed(
        key,
        jwk,
        &n,
        &format!("{base}{endpoint}"),
        Some(kid),
        payload,
    )?;
    Ok(call(
        service,
        "POST",
        &format!("external-ca/acme/{endpoint}"),
        "",
        request,
    ))
}
fn order_account(service: &mut Service, key: &PKey<Private>, jwk: &Value) -> TestResult<String> {
    let n = nonce(service)?;
    let created = call(
        service,
        "POST",
        "external-ca/acme/new-account",
        "",
        signed(
            key,
            jwk,
            &n,
            "https://acme.example.test/v1/external-ca/acme/new-account",
            None,
            Some(json!({"termsOfServiceAgreed":true})),
        )?,
    );
    assert_eq!(created.status, 201);
    header(&created, "Location")
}

fn maintenance_clock(at: u64) -> TestResult<RequestClock> {
    Ok(RequestClock::anchored(
        Duration::from_secs(at),
        std::time::Instant::now(),
    )?)
}

fn csr(domain: &str) -> TestResult<(PKey<Private>, Vec<u8>)> {
    let (private, _) = key()?;
    let request = csr_with_key(domain, &private)?;
    Ok((private, request))
}
fn csr_with_key(domain: &str, private: &PKey<Private>) -> TestResult<Vec<u8>> {
    let mut request = X509Req::builder()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, domain)?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "UntrustedSubjectMustBeIgnored")?;
    request.set_subject_name(&name.build())?;
    request.set_pubkey(private)?;
    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(
        SubjectAlternativeName::new()
            .dns(domain)
            .build(&request.x509v3_context(None))?,
    )?;
    request.add_extensions(&extensions)?;
    request.sign(private, MessageDigest::sha256())?;
    let request = request.build();
    assert!(request.verify(private)?);
    Ok(request.to_der()?)
}
fn ready(
    service: &mut Service,
    admin: &str,
    key: &PKey<Private>,
    jwk: &Value,
    kid: &str,
    domain: &str,
) -> TestResult<String> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    assert_eq!(
        call(
            service,
            "POST",
            "external-ca/config/acme",
            admin,
            json!({"dns_resolver":socket.local_addr()?.to_string()})
        )
        .status,
        200
    );
    let created = order_post(
        service,
        key,
        jwk,
        kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"dns","value":domain}]})),
    )?;
    assert_eq!(created.status, 201);
    let order = header(&created, "Location")?
        .split("/acme/")
        .nth(1)
        .ok_or("order route")?
        .to_owned();
    let auth = created.body["__heptabao_acme"]["authorizations"][0]
        .as_str()
        .ok_or("auth")?
        .split("/acme/")
        .nth(1)
        .ok_or("auth route")?
        .to_owned();
    let fetched = order_post(service, key, jwk, kid, &auth, None)?;
    let challenge = fetched.body["__heptabao_acme"]["challenges"]
        .as_array()
        .ok_or("challenges")?
        .iter()
        .find(|c| c["type"] == "dns-01")
        .ok_or("DNS challenge")?["url"]
        .as_str()
        .ok_or("challenge URL")?
        .split("/acme/")
        .nth(1)
        .ok_or("challenge route")?
        .to_owned();
    assert_eq!(
        order_post(service, key, jwk, kid, &challenge, Some(json!({})))?.status,
        200
    );
    let plan = service
        .prepare_acme_maintenance(maintenance_clock(101)?)
        .map_err(|_| "proof plan")?
        .ok_or("queued proof")?;
    let token = fetched.body["__heptabao_acme"]["challenges"]
        .as_array()
        .ok_or("public challenges")?
        .iter()
        .find(|challenge| challenge["type"] == "dns-01")
        .ok_or("public DNS challenge")?["token"]
        .as_str()
        .ok_or("public DNS token")?;
    let thumbprint = URL_SAFE_NO_PAD.encode(crate::crypto::digest(&serde_json::to_vec(jwk)?));
    let proof = URL_SAFE_NO_PAD.encode(crate::crypto::digest(
        format!("{token}.{thumbprint}").as_bytes(),
    ));
    let thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut query = vec![0; 2048];
        let (n, peer) = socket.recv_from(&mut query)?;
        query.truncate(n);
        let mut response = query[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 30]);
        response.extend_from_slice(&((proof.len() + 1) as u16).to_be_bytes());
        response.push(proof.len() as u8);
        response.extend_from_slice(proof.as_bytes());
        socket.send_to(&response, peer)?;
        Ok(())
    });
    let result = plan.execute_fixture_public_proof(service);
    thread.join().map_err(|_| "DNS responder")??;
    assert!(result.is_ok(), "{result:?}");
    service
        .finish_acme_maintenance(plan, result)
        .map_err(|_| "proof publication")?;
    assert_eq!(
        order_post(service, key, jwk, kid, &order, None)?.body["__heptabao_acme"]["status"],
        "ready"
    );
    Ok(order)
}

fn setup_remote(service: &mut Service, admin: &str) -> TestResult {
    for (path, body, status) in [
        (
            "external-ca/config/cluster",
            json!({"path":"https://acme.example.test/v1/external-ca"}),
            200,
        ),
        (
            "external-ca/config/acme",
            json!({"enabled":true,"eab_policy":"not-required"}),
            200,
        ),
        (
            "sys/mounts/external-ca/tune",
            json!({"allowed_response_headers":["Replay-Nonce","Link","Location"]}),
            204,
        ),
    ] {
        assert_eq!(call(service, "POST", path, admin, body).status, status);
    }
    Ok(())
}
fn prepare_signed_finalize(
    service: &mut Service,
    account: &PKey<Private>,
    jwk: &Value,
    kid: &str,
    order: &str,
    raw: &[u8],
) -> TestResult<PendingExternalRequest> {
    let n = nonce(service)?;
    let endpoint = format!("{order}/finalize");
    let request = signed(
        account,
        jwk,
        &n,
        &format!("https://acme.example.test/v1/external-ca/acme/{endpoint}"),
        Some(kid),
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(raw)})),
    )?;
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: &format!("external-ca/acme/{endpoint}"),
        namespace: "",
        token: "",
        body: request,
        now: 100,
        allow_forward: true,
        enforce_namespace: false,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(response) => Err(format!(
            "actual ACME TLS signer not staged: status {}",
            response.status
        )
        .into()),
    }
}
fn assert_no_completed_order(service: &Service, order: &str) -> TestResult {
    let mut state = serde_json::to_value(&service.state.as_ref().ok_or("current state")?.engines)?;
    let id = order.strip_prefix("order/").ok_or("order id")?;
    assert!(state["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"]["acme_protocol"]["orders"][id]["certificate"].is_null());
    erase_json(&mut state);
    Ok(())
}
#[test]
fn pki_acme_external_real_seven_TLS_signers_csr_public_binding_encrypted_reopen() -> TestResult {
    for kind in [
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "ecdsa-p521",
        "rsa-2048",
        "rsa-3072",
        "rsa-4096",
    ] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = leaf_fixture(&remote)?;
        setup_remote(&mut service, &admin)?;
        let (account, jwk) = key()?;
        let kid = order_account(&mut service, &account, &jwk)?;
        let domain = "managed.acme.example.test";
        let order = ready(&mut service, &admin, &account, &jwk, &kid, domain)?;
        let (leaf, raw) = csr(domain)?;
        let before = remote.calls()?;
        let finalized = order_post(
            &mut service,
            &account,
            &jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(json!({"csr":URL_SAFE_NO_PAD.encode(&raw)})),
        )?;
        assert_eq!(
            finalized.status,
            200,
            "remote kind {kind} static errors {:?}",
            finalized.body.get("errors")
        );
        assert_eq!(finalized.body["__heptabao_acme"]["status"], "valid");
        assert_eq!(
            remote.calls()?,
            before + 2,
            "one metadata and one remote signature"
        );
        let cert = finalized.body["__heptabao_acme"]["certificate"]
            .as_str()
            .ok_or("certificate URL")?
            .split("/acme/")
            .nth(1)
            .ok_or("certificate route")?
            .to_owned();
        let fetched = order_post(&mut service, &account, &jwk, &kid, &cert, None)?;
        assert_eq!(fetched.status, 200);
        let pem = fetched.body["__heptabao_acme"]
            .as_str()
            .ok_or("public signed certificate chain")?
            .to_owned();
        let chain = X509::stack_from_pem(pem.as_bytes())?;
        assert_eq!(chain.len(), 2);
        let issuer = chain[1].public_key()?;
        assert!(chain[0].verify(&issuer)? && chain[1].verify(&issuer)?);
        assert_eq!(
            chain[0].public_key()?.public_key_to_der()?,
            leaf.public_key_to_der()?
        );
        let (wrong, _) = key()?;
        assert!(!chain[0].verify(&wrong).unwrap_or(false));
        let current = service.state.as_ref().ok_or("current typed owner")?;
        assert_eq!(current.schema, 99);
        assert!(current.validate_format().is_ok());
        let mut graph = serde_json::to_value(&current.engines)?;
        let actual = &graph["namespaces"][""]["mounts"]["external-ca/"]["backend"]["Pki"];
        assert_eq!(
            actual["issued"]
                .as_object()
                .ok_or("native lease-owned issuance")?
                .len(),
            0,
            "public ACME account never creates a token lease"
        );
        erase_json(&mut graph);
        let calls = remote.calls()?;
        drop(service);
        let mut reopened = root.service()?;
        reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status,
            200
        );
        assert_eq!(
            order_post(&mut reopened, &account, &jwk, &kid, &cert, None)?.body["__heptabao_acme"],
            pem
        );
        assert_eq!(
            remote.calls()?,
            calls,
            "encrypted certificate recovery uses stored signed DER"
        );
        let repeated = order_post(
            &mut reopened,
            &account,
            &jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(json!({"csr":URL_SAFE_NO_PAD.encode(&raw)})),
        )?;
        assert_eq!(
            repeated.status, 403,
            "immutable completed order cannot sign twice"
        );
        assert_eq!(remote.calls()?, calls);
    }
    Ok(())
}
#[test]
fn pki_acme_external_account_retirement_during_real_sign_vetoes_publication() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    setup_remote(&mut service, &admin)?;
    let (account, jwk) = key()?;
    let kid = order_account(&mut service, &account, &jwk)?;
    let order = ready(
        &mut service,
        &admin,
        &account,
        &jwk,
        &kid,
        "retired.acme.example.test",
    )?;
    let (_, raw) = csr("retired.acme.example.test")?;
    let pending = prepare_signed_finalize(&mut service, &account, &jwk, &kid, &order, &raw)?;
    let result = pending.execute();
    let endpoint = kid.split("/acme/").nth(1).ok_or("account route")?;
    let retired = order_post(
        &mut service,
        &account,
        &jwk,
        &kid,
        endpoint,
        Some(json!({"status":"deactivated"})),
    )?;
    assert_eq!(retired.status, 200);
    let response = service.finish_external_request(pending, result);
    assert_eq!(
        response.status, 503,
        "original public owner cannot publish after account retirement"
    );
    assert!(response.response_headers.is_empty());
    assert_no_completed_order(&service, &order)?;
    Ok(())
}
#[test]
fn pki_acme_external_sign_grant_retirement_during_effect_vetoes_publication() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = leaf_fixture(&remote)?;
    setup_remote(&mut service, &admin)?;
    let (account, jwk) = key()?;
    let kid = order_account(&mut service, &account, &jwk)?;
    let order = ready(
        &mut service,
        &admin,
        &account,
        &jwk,
        &kid,
        "grant.acme.example.test",
    )?;
    let (_, raw) = csr("grant.acme.example.test")?;
    let pending = prepare_signed_finalize(&mut service, &account, &jwk, &kid, &order, &raw)?;
    let result = pending.execute();
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v2/grants/external-ca",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let response = service.finish_external_request(pending, result);
    assert_eq!(
        response.status, 503,
        "actual current mount sign grant remains required"
    );
    assert!(response.response_headers.is_empty());
    assert_no_completed_order(&service, &order)?;
    Ok(())
}
