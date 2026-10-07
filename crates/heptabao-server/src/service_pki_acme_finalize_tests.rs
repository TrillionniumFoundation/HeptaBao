//! Actual JWS, owned DNS proof, signed CSR and encrypted order certificate.
use super::*;
use openssl::x509::{X509, X509NameBuilder, X509Req, extension::SubjectAlternativeName};
use x509_parser::prelude::FromDer;

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
            "acmeca/config/acme",
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
    let proof = URL_SAFE_NO_PAD.encode(crate::crypto::digest(
        format!("{}.{}", plan.queued.challenge.token, plan.queued.thumbprint).as_bytes(),
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
    let result = plan.execute_port(80);
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
#[test]
fn pki_acme99_finalize_actual_dns_csr_signature_chain_encrypted_reopen_and_rollback() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (account_key, jwk) = key()?;
    let kid = order_account(&mut service, &account_key, &jwk)?;
    let domain = "finalize.dns-proof.example";
    let order = ready(&mut service, &admin, &account_key, &jwk, &kid, domain)?;
    let account_csr = csr_with_key(domain, &account_key)?;
    let rejected = order_post(
        &mut service,
        &account_key,
        &jwk,
        &kid,
        &format!("{order}/finalize"),
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(&account_csr)})),
    )?;
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:badCSR"
    );
    assert_eq!(
        rejected.body["__heptabao_acme"]["detail"],
        "the CSR is unacceptable: certificate public key must not match account key"
    );
    assert_eq!(
        order_post(&mut service, &account_key, &jwk, &kid, &order, None)?.body["__heptabao_acme"]["status"],
        "ready",
        "account-key CSR rejection does not complete an order"
    );
    let (leaf_key, raw) = csr(domain)?;
    let predecessor = service.state.as_ref().ok_or("predecessor")?.clone();
    let finalized = order_post(
        &mut service,
        &account_key,
        &jwk,
        &kid,
        &format!("{order}/finalize"),
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(&raw)})),
    )?;
    assert_eq!(
        finalized.status,
        200,
        "static errors {:?}",
        finalized.body.get("errors")
    );
    assert_eq!(finalized.body["__heptabao_acme"]["status"], "valid");
    let cert_path = finalized.body["__heptabao_acme"]["certificate"]
        .as_str()
        .ok_or("certificate URL")?
        .split("/acme/")
        .nth(1)
        .ok_or("certificate route")?
        .to_owned();
    let fetched = order_post(&mut service, &account_key, &jwk, &kid, &cert_path, None)?;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body["media"], "certificate");
    let pem = fetched.body["__heptabao_acme"]
        .as_str()
        .ok_or("public signed PEM chain")?
        .to_owned();
    let chain = X509::stack_from_pem(pem.as_bytes())?;
    assert_eq!(chain.len(), 2);
    let actual_serial = chain[0]
        .serial_number()
        .to_bn()?
        .to_vec()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let public_route = format!("acmeca/cert/{actual_serial}");
    let public_read = call(&mut service, "GET", &public_route, "", json!({}));
    assert_eq!(
        public_read.status, 200,
        "actual DER serial is public without a Vault token"
    );
    let public_pem = public_read.body["data"]["certificate"]
        .as_str()
        .ok_or("public PKI certificate")?;
    assert_eq!(
        X509::from_pem(public_pem.as_bytes())?.to_der()?,
        chain[0].to_der()?
    );
    assert!(!public_pem.ends_with('\n'));
    assert_eq!(public_read.body["data"]["revocation_time"], 0);
    {
        let alias = actual_serial.to_uppercase();
        let alias_read = call(
            &mut service,
            "GET",
            &format!("acmeca/cert/{alias}"),
            "",
            json!({}),
        );
        assert_eq!(alias_read.status, 200);
        assert_eq!(
            alias_read.body, public_read.body,
            "alias derives only from actual signed INTEGER"
        );
    }
    let absent_alias = call(
        &mut service,
        "GET",
        &format!("acmeca/cert/00:{actual_serial}"),
        "",
        json!({}),
    );
    assert_eq!(
        absent_alias.status, 404,
        "native canonical ACME key does not accept a leading-zero alias"
    );
    assert_eq!(absent_alias.body, json!({"errors":[]}));
    let raw_read = call(
        &mut service,
        "GET",
        &format!("{public_route}/raw"),
        "",
        json!({}),
    );
    assert_eq!(raw_read.status, 200);
    let encoded = raw_read.body["__heptabao_pki_certificate"]
        .as_str()
        .ok_or("raw public DER")?;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(encoded)?,
        chain[0].to_der()?
    );
    let issuer_key = chain[1].public_key()?;
    assert!(chain[0].verify(&issuer_key)?);
    assert_eq!(
        chain[0].public_key()?.public_key_to_der()?,
        leaf_key.public_key_to_der()?
    );
    assert_eq!(
        chain[0]
            .subject_name()
            .entries_by_nid(Nid::ORGANIZATIONNAME)
            .count(),
        0,
        "untrusted CSR subject is not copied"
    );
    assert!(
        chain[0].not_after() <= chain[1].not_after(),
        "native ACME truncates the admitted CA boundary"
    );
    let current = service.state.as_ref().ok_or("current")?.clone();
    assert!(
        predecessor
            .engines
            .validate_acme_successor(Some(&current.engines), |_| false)
            .is_err()
    );
    assert!(Service::validate_snapshot_protected_floor(&current, &predecessor).is_err());
    let mut graph = serde_json::to_value(&current.engines)?;
    let path = &mut graph["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"];
    assert_eq!(
        path["issued"]
            .as_object()
            .ok_or("Vault-owned issuance map")?
            .len(),
        0,
        "ACME account cannot mint a Vault LeaseOwner"
    );
    let order_id = order.strip_prefix("order/").ok_or("order id")?;
    let der = path["acme_protocol"]["orders"][order_id]["certificate"]["der"]
        .as_array_mut()
        .ok_or("captured signed DER")?;
    let last = der.last_mut().ok_or("signature byte")?;
    *last = json!(last.as_u64().ok_or("byte")? ^ 1);
    let mut damaged = current.clone();
    damaged.engines = serde_json::from_value(graph.clone())?;
    erase_json(&mut graph);
    assert!(
        service.prepare_record_plan(&mut damaged).is_err(),
        "authenticated state still validates actual signed DER"
    );
    assert_eq!(
        order_post(
            &mut service,
            &account_key,
            &jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(json!({"csr":URL_SAFE_NO_PAD.encode(&raw)}))
        )?
        .status,
        403,
        "one completed order cannot re-sign"
    );
    drop(service);
    let mut reopened = directory.service()?;
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
    let reopened_public = call(&mut reopened, "GET", &public_route, "", json!({}));
    assert_eq!(reopened_public.status, 200);
    assert_eq!(
        reopened_public.body, public_read.body,
        "encrypted reopen preserves the public ACME certificate asset"
    );
    assert_eq!(
        order_post(&mut reopened, &account_key, &jwk, &kid, &cert_path, None)?.body["__heptabao_acme"],
        pem
    );
    assert_eq!(
        order_post(&mut reopened, &account_key, &jwk, &kid, &order, None)?.body["__heptabao_acme"]
            ["status"],
        "valid"
    );
    Ok(())
}
#[test]
fn pki_acme99_finalize_pending_and_malformed_csr_have_no_signing_or_certificate_asset() -> TestResult
{
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let created = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"dns","value":"pending.example"}]})),
    )?;
    let order = header(&created, "Location")?
        .split("/acme/")
        .nth(1)
        .ok_or("order route")?
        .to_owned();
    let (_, raw) = csr("pending.example")?;
    for (payload, status, kind) in [
        (json!({}), 400, "malformed"),
        (json!({"csr":7}), 400, "malformed"),
        (json!({"csr":"***"}), 400, "malformed"),
        (
            json!({"csr":URL_SAFE_NO_PAD.encode(&raw)}),
            403,
            "orderNotReady",
        ),
    ] {
        let response = order_post(
            &mut service,
            &key,
            &jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(payload),
        )?;
        assert_eq!(response.status, status);
        assert_eq!(
            response.body["__heptabao_acme"]["type"],
            format!("urn:ietf:params:acme:error:{kind}")
        );
    }
    assert_eq!(
        order_post(
            &mut service,
            &key,
            &jwk,
            &kid,
            &format!("{order}/cert"),
            None
        )?
        .status,
        403
    );
    let mut graph = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
    let order_id = order.strip_prefix("order/").ok_or("id")?;
    assert!(
        graph["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"]["acme_protocol"]["orders"]
            [order_id]
            .get("certificate")
            .is_none()
    );
    erase_json(&mut graph);
    Ok(())
}

// This negative CSR is still genuinely signed. The wire difference is the
// omitted RSA AlgorithmIdentifier NULL parameter observed in the native parser.
fn rsa_csr_without_parameters(domain: &str) -> TestResult<Vec<u8>> {
    fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            let bytes = content.len().to_be_bytes();
            let bytes = &bytes[bytes
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(bytes.len() - 1)..];
            out.push(0x80 | bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(content);
        out
    }
    fn content(encoded: &[u8]) -> TestResult<&[u8]> {
        if encoded.len() < 2 {
            return Err("test DER bounds".into());
        }
        let (offset, length) = if encoded[1] & 0x80 == 0 {
            (2, encoded[1] as usize)
        } else {
            let width = (encoded[1] & 0x7f) as usize;
            if width == 0 || width > std::mem::size_of::<usize>() || encoded.len() < 2 + width {
                return Err("test DER length".into());
            }
            let length = encoded[2..2 + width]
                .iter()
                .fold(0usize, |n, b| (n << 8) | *b as usize);
            (2 + width, length)
        };
        if offset + length != encoded.len() {
            return Err("test complete DER".into());
        }
        Ok(&encoded[offset..])
    }
    let private = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
    let raw = csr_with_key(domain, &private)?;
    let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(&raw)?;
    let spki = parsed.certification_request_info.subject_pki.raw;
    let spki_content = content(spki)?;
    let original_algorithm = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    assert!(spki_content.starts_with(&original_algorithm));
    let mut alternative = vec![
        0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    alternative.extend_from_slice(&spki_content[original_algorithm.len()..]);
    let alternative = encode(0x30, &alternative);
    let info = content(parsed.certification_request_info.raw)?;
    let position = info
        .windows(spki.len())
        .position(|v| v == spki)
        .ok_or("actual CSR SPKI position")?;
    let mut replaced = info[..position].to_vec();
    replaced.extend_from_slice(&alternative);
    replaced.extend_from_slice(&info[position + spki.len()..]);
    let tbs = encode(0x30, &replaced);
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &private)?;
    signer.update(&tbs)?;
    let signature = signer.sign_to_vec()?;
    let mut fields = tbs;
    fields.extend_from_slice(&[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ]);
    let mut bit_string = vec![0];
    bit_string.extend_from_slice(&signature);
    fields.extend_from_slice(&encode(3, &bit_string));
    let alternate = encode(0x30, &fields);
    assert!(X509Req::from_der(&alternate)?.verify(&private)?);
    assert_ne!(raw, alternate);
    Ok(alternate)
}
#[test]
fn pki_acme99_finalize_rsa_missing_parameters_rejected_before_order_state() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (account, jwk) = key()?;
    let kid = order_account(&mut service, &account, &jwk)?;
    let domain = "missing-parameters.dns-proof.example";
    let created = order_post(
        &mut service,
        &account,
        &jwk,
        &kid,
        "new-order",
        Some(json!({"identifiers":[{"type":"dns","value":domain}]})),
    )?;
    assert_eq!(created.status, 201);
    let order = header(&created, "Location")?
        .split("/acme/")
        .nth(1)
        .ok_or("order route")?
        .to_owned();
    let alternate = rsa_csr_without_parameters(domain)?;
    let rejected = order_post(
        &mut service,
        &account,
        &jwk,
        &kid,
        &format!("{order}/finalize"),
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(alternate)})),
    )?;
    assert_eq!(rejected.status, 400);
    assert_eq!(
        rejected.body["__heptabao_acme"]["type"],
        "urn:ietf:params:acme:error:malformed"
    );
    assert_eq!(
        rejected.body["__heptabao_acme"]["detail"],
        "the request message was malformed: failed to parse csr: x509: RSA key missing NULL parameters"
    );
    let pending = order_post(&mut service, &account, &jwk, &kid, &order, None)?;
    assert_eq!(pending.body["__heptabao_acme"]["status"], "pending");
    Ok(())
}

#[test]
fn pki_acme99_revoke_account_and_leaf_possession_actual_crl_reopen_and_rollback() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (account_key, account_jwk) = key()?;
    let kid = order_account(&mut service, &account_key, &account_jwk)?;
    let (other_key, other_jwk) = key()?;
    let other_kid = order_account(&mut service, &other_key, &other_jwk)?;
    let mut last_public = None;
    for possession in [false, true] {
        let domain = if possession {
            "possession.revoke-proof.example"
        } else {
            "account.revoke-proof.example"
        };
        let order = ready(
            &mut service,
            &admin,
            &account_key,
            &account_jwk,
            &kid,
            domain,
        )?;
        let (leaf_key, leaf_jwk) = key()?;
        let csr = csr_with_key(domain, &leaf_key)?;
        let issued = order_post(
            &mut service,
            &account_key,
            &account_jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(json!({"csr":URL_SAFE_NO_PAD.encode(&csr)})),
        )?;
        assert_eq!(issued.status, 200);
        let fetched = order_post(
            &mut service,
            &account_key,
            &account_jwk,
            &kid,
            &format!("{order}/cert"),
            None,
        )?;
        let certificates = X509::stack_from_pem(
            fetched.body["__heptabao_acme"]
                .as_str()
                .ok_or("PEM")?
                .as_bytes(),
        )?;
        assert_eq!(certificates.len(), 2);
        let raw = certificates[0].to_der()?;
        let serial = certificates[0]
            .serial_number()
            .to_bn()?
            .to_hex_str()?
            .to_string();
        let route = format!("acmeca/cert/{serial}");
        let body = json!({"certificate":URL_SAFE_NO_PAD.encode(&raw)});
        let cross = order_post(
            &mut service,
            &other_key,
            &other_jwk,
            &other_kid,
            "revoke-cert",
            Some(body.clone()),
        )?;
        assert_eq!(cross.status, 400);
        assert_eq!(
            cross.body["__heptabao_acme"]["type"],
            "urn:ietf:params:acme:error:malformed"
        );
        let n = nonce(&mut service)?;
        let wrong = call(
            &mut service,
            "POST",
            "acmeca/acme/revoke-cert",
            "",
            signed(
                &other_key,
                &other_jwk,
                &n,
                "https://acme.example.test/v1/acmeca/acme/revoke-cert",
                None,
                Some(body.clone()),
            )?,
        );
        assert_eq!(wrong.status, 400);
        let bad_reason = order_post(
            &mut service,
            &account_key,
            &account_jwk,
            &kid,
            "revoke-cert",
            Some(json!({"certificate":URL_SAFE_NO_PAD.encode(&raw),"reason":1})),
        )?;
        assert_eq!(bad_reason.status, 400);
        assert_eq!(
            bad_reason.body["__heptabao_acme"]["type"],
            "urn:ietf:params:acme:error:badRevocationReason"
        );
        assert_eq!(
            call(&mut service, "GET", &route, "", json!({})).body["data"]["revocation_time"],
            0
        );
        let predecessor = service.state.as_ref().ok_or("predecessor")?.clone();
        let revoked = if possession {
            let n = nonce(&mut service)?;
            call(
                &mut service,
                "POST",
                "acmeca/acme/revoke-cert",
                "",
                signed(
                    &leaf_key,
                    &leaf_jwk,
                    &n,
                    "https://acme.example.test/v1/acmeca/acme/revoke-cert",
                    None,
                    Some(body.clone()),
                )?,
            )
        } else {
            order_post(
                &mut service,
                &account_key,
                &account_jwk,
                &kid,
                "revoke-cert",
                Some(json!({"certificate":URL_SAFE_NO_PAD.encode(&raw),"reason":0.9})),
            )?
        };
        assert_eq!(revoked.status, 200, "{:?}", revoked.body);
        assert_eq!(revoked.body["__heptabao_acme"]["state"], "revoked");
        let public = call(&mut service, "GET", &route, "", json!({}));
        assert_eq!(public.status, 200);
        assert_eq!(
            public.body["data"]["revocation_time"],
            revoked.body["__heptabao_acme"]["revocation_time"]
        );
        assert_eq!(
            public.body["data"]["revocation_time_rfc3339"],
            revoked.body["__heptabao_acme"]["revocation_time_rfc3339"]
        );
        let repeated = order_post(
            &mut service,
            &account_key,
            &account_jwk,
            &kid,
            "revoke-cert",
            Some(body),
        )?;
        assert_eq!(repeated.status, 400);
        assert_eq!(
            repeated.body["__heptabao_acme"]["type"],
            "urn:ietf:params:acme:error:alreadyRevoked"
        );
        assert_eq!(
            repeated.body["__heptabao_acme"]["detail"],
            "unable to revoke certificate: the request specified a certificate to be revoked that has already been revoked"
        );
        let crl = call(&mut service, "GET", "acmeca/crl", "", json!({}));
        assert_eq!(crl.status, 200);
        let der = base64::engine::general_purpose::STANDARD
            .decode(crl.body["__heptabao_pki_crl"].as_str().ok_or("CRL DER")?)?;
        let crl = openssl::x509::X509Crl::from_der(&der)?;
        let issuer_public = certificates[1].public_key()?;
        assert!(crl.verify(&issuer_public)?);
        assert!(crl.get_revoked().ok_or("revoked entries")?.iter().any(|r| {
            r.serial_number().to_bn().is_ok_and(|r| {
                certificates[0]
                    .serial_number()
                    .to_bn()
                    .is_ok_and(|s| r == s)
            })
        }));
        let current = service.state.as_ref().ok_or("current")?.clone();
        assert!(
            current
                .engines
                .validate_acme_successor(Some(&predecessor.engines), |_| false)
                .is_ok()
        );
        assert!(
            predecessor
                .engines
                .validate_acme_successor(Some(&current.engines), |_| false)
                .is_err()
        );
        let mut graph = serde_json::to_value(&current.engines)?;
        let protocol =
            &mut graph["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"]["acme_protocol"];
        protocol["revocations"] = json!({});
        let mut rollback = current.clone();
        rollback.engines = serde_json::from_value(graph.clone())?;
        erase_json(&mut graph);
        assert!(
            rollback
                .engines
                .validate_acme_successor(Some(&current.engines), |_| false)
                .is_err(),
            "same owner/certificate/nonce ledger cannot erase revocation"
        );
        last_public = Some((route, public.body.clone()));
    }
    drop(service);
    let mut reopened = directory.service()?;
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
    let (route, expected) = last_public.ok_or("revoked certificate")?;
    assert_eq!(
        call(&mut reopened, "GET", &route, "", json!({})).body,
        expected
    );
    Ok(())
}

#[test]
fn pki_acme99_actual_vault_acl_revoke_retains_operator_without_public_principal() -> TestResult {
    let directory = Root::new();
    let mut service = directory.service()?;
    let (unseal, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (account_key, jwk) = key()?;
    let kid = order_account(&mut service, &account_key, &jwk)?;
    let domain = "operator.revoke-proof.example";
    let order = ready(&mut service, &admin, &account_key, &jwk, &kid, domain)?;
    let (_, csr) = csr(domain)?;
    let finalized = order_post(
        &mut service,
        &account_key,
        &jwk,
        &kid,
        &format!("{order}/finalize"),
        Some(json!({"csr":URL_SAFE_NO_PAD.encode(csr)})),
    )?;
    assert_eq!(finalized.status, 200);
    let fetched = order_post(
        &mut service,
        &account_key,
        &jwk,
        &kid,
        &format!("{order}/cert"),
        None,
    )?;
    assert_eq!(fetched.status, 200);
    let encoded = fetched.body["__heptabao_acme"]
        .as_str()
        .ok_or("actual certificate chain")?;
    let certificates = X509::stack_from_pem(encoded.as_bytes())?;
    let serial = certificates[0]
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string()
        .to_lowercase();
    let serial = serial
        .as_bytes()
        .chunks(2)
        .map(|b| std::str::from_utf8(b))
        .collect::<Result<Vec<_>, _>>()?
        .join(":");
    let before = service.state.as_ref().ok_or("state")?.clone();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/revoke",
            "",
            json!({"serial_number":serial})
        )
        .status,
        403
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .validate_acme_successor(Some(&before.engines), |_| false)
            .is_ok()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/acme-revoker",
            &admin,
            json!({"policy":"path \"acmeca/revoke\" { capabilities = [\"update\"] }"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &admin,
        json!({"policies":["acme-revoker"],"no_default_policy":true,"ttl":"30m"}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual revocation actor")?
        .to_owned();
    let revoked = call(
        &mut service,
        "POST",
        "acmeca/revoke",
        &actor,
        json!({"serial_number":serial}),
    );
    assert_eq!(revoked.status, 200, "{:?}", revoked.body.get("errors"));
    assert_eq!(revoked.body["data"]["state"], "revoked");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "acmeca/revoke",
            &actor,
            json!({"serial_number":serial})
        )
        .body["data"],
        revoked.body["data"]
    );
    let public_route = format!("acmeca/cert/{serial}");
    let public = call(&mut service, "GET", &public_route, "", json!({}));
    assert_eq!(
        public.body["data"]["revocation_time_rfc3339"],
        revoked.body["data"]["revocation_time_rfc3339"]
    );
    let crl = call(&mut service, "GET", "acmeca/crl", "", json!({}));
    assert_eq!(crl.status, 200);
    let der = base64::engine::general_purpose::STANDARD
        .decode(crl.body["__heptabao_pki_crl"].as_str().ok_or("CRL")?)?;
    let crl = openssl::x509::X509Crl::from_der(&der)?;
    let issuer_public = certificates[1].public_key()?;
    assert!(crl.verify(&issuer_public)?);
    assert!(crl.get_revoked().ok_or("revoked entries")?.iter().any(|r| {
        r.serial_number().to_bn().is_ok_and(|r| {
            certificates[0]
                .serial_number()
                .to_bn()
                .is_ok_and(|s| r == s)
        })
    }));
    let graph = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
    let pki = &graph["namespaces"][""]["mounts"]["acmeca/"]["backend"]["Pki"];
    assert!(
        pki["issued"].as_object().is_none_or(|v| v.is_empty()),
        "public ACME certificate never becomes a Vault issued lease"
    );
    assert_eq!(
        pki["acme_protocol"]["revocations"][serial.replace(':', "")]["proof"]["kind"],
        "Administrative"
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &admin,
            json!({"token":actor})
        )
        .status,
        204
    );
    drop(service);
    let mut reopened = directory.service()?;
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
        call(&mut reopened, "GET", &public_route, "", json!({})).body,
        public.body
    );
    Ok(())
}

#[test]
fn pki_acme99_operator_original_two_second_actor_expires_before_actual_crl_sign() -> TestResult {
    use crate::auth::{AuthorityTime, RequestClock};
    let directory = Root::new();
    let mut service = directory.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    setup(&mut service, &admin)?;
    let (key, jwk) = key()?;
    let kid = order_account(&mut service, &key, &jwk)?;
    let domain = "deadline.operator-revoke.example";
    let order = ready(&mut service, &admin, &key, &jwk, &kid, domain)?;
    let (_, csr) = csr(domain)?;
    assert_eq!(
        order_post(
            &mut service,
            &key,
            &jwk,
            &kid,
            &format!("{order}/finalize"),
            Some(json!({"csr":URL_SAFE_NO_PAD.encode(csr)}))
        )?
        .status,
        200
    );
    let fetched = order_post(
        &mut service,
        &key,
        &jwk,
        &kid,
        &format!("{order}/cert"),
        None,
    )?;
    let certificates = X509::stack_from_pem(
        fetched.body["__heptabao_acme"]
            .as_str()
            .ok_or("actual PEM")?
            .as_bytes(),
    )?;
    let serial = certificates[0]
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string()
        .to_lowercase();
    let state = service.state.as_ref().ok_or("state")?;
    let base = state.engines.lease_clock().max(100).max(
        state
            .auth
            .terminal_token_clock_floor()
            .map_or(0, |at| at.ceil_seconds().unwrap_or(at.seconds())),
    );
    let issue_clock =
        RequestClock::anchored(Duration::new(base, 250_000_000), std::time::Instant::now())?;
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "auth/token/create",
            namespace: "",
            token: &admin,
            body: json!({"ttl":"2s","policies":["root"],"no_default_policy":true}),
            now: base,
            allow_forward: true,
            enforce_namespace: false,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        issue_clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert_eq!(response.status, 200);
    let actor = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual actor")?
        .to_owned();
    let clock =
        RequestClock::anchored(Duration::new(base, 500_000_000), std::time::Instant::now())?;
    let state = service.state.as_mut().ok_or("state")?;
    let time = AuthorityTime::Precise(clock.observed_at()?);
    let principal = state.auth.authenticate_from_observed(&actor, time, None)?;
    state
        .auth
        .authorize_request_observed(&principal, "", "acmeca/revoke", "update", time)?;
    let owner = state
        .auth
        .typed_lease_issuer_observed(&principal, "", time)?;
    let expiry = owner
        .precise_expires_at
        .ok_or("actual precise two-second actor")?;
    assert_eq!(expiry.seconds(), base + 2);
    assert!(expiry < crate::auth::Timestamp::checked(base + 2, 500_000_000)?);
    let original = serde_json::to_value(&state.engines)?;
    let mut candidate = state.engines.clone();
    let mut guard_calls = 0;
    let result = candidate.handle_service_pki_operator_revoke(
        "",
        "POST",
        "acmeca/revoke",
        &json!({"serial_number":serial}),
        crate::engines::PkiRequestContext {
            owner: Some(&owner),
            time,
            clock: Some(clock),
            identity_templates: None,
        },
        || {
            guard_calls += 1;
            if guard_calls == 1 {
                std::thread::sleep(Duration::from_millis(2100));
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    let rejected = result.err().ok_or("actual expiry rejection")?;
    assert_eq!(rejected.status, 403);
    assert_eq!(
        rejected.message,
        "administrative PKI original caller expired before signing"
    );
    assert_eq!(
        guard_calls, 2,
        "the actual TBS guard observes the same actor after metadata delay"
    );
    assert!(clock.observed_at()? > expiry);
    assert_eq!(
        serde_json::to_value(&candidate)?,
        original,
        "no revocation receipt or new signed CRL installs after private actor expiry"
    );
    assert_eq!(serde_json::to_value(&state.engines)?, original);
    Ok(())
}
