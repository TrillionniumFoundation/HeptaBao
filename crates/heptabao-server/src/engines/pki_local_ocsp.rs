//! Closed local OCSP projections. Caller bytes supply only a bounded CertID;
//! the owned issuer, durable revocation state and server clock build ResponseData.
use super::*;
use openssl::{
    hash::{MessageDigest, hash},
    ocsp::{OcspRequest, OcspResponse},
};
use x509_parser::prelude::{FromDer, X509Certificate};

pub(crate) const MAX_OCSP_REQUEST: usize = 2048;
pub(crate) const MAX_OCSP_RESPONSE: usize = 16 * 1024;
const REQUEST_MARKER: &str = "__heptabao_pki_ocsp_request";
const RESPONSE_MARKER: &str = "__heptabao_pki_ocsp_response";
const BASIC_RESPONSE_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

#[derive(Clone, Copy)]
enum RequestHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
impl RequestHash {
    fn from_oid(value: &[u8]) -> Option<Self> {
        match value {
            [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Some(Self::Sha1),
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Some(Self::Sha256),
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Some(Self::Sha384),
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Some(Self::Sha512),
            _ => None,
        }
    }
    fn oid(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
            Self::Sha256 => &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1],
            Self::Sha384 => &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2],
            Self::Sha512 => &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3],
        }
    }
    fn digest(self) -> MessageDigest {
        match self {
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
    fn hash(self, bytes: &[u8]) -> Result<Vec<u8>> {
        hash(self.digest(), bytes)
            .map(|v| v.to_vec())
            .map_err(|_| error(503, "local OCSP issuer hash unavailable"))
    }
}

/// A depth-bounded DER reader used only after the maintained OCSP parser's
/// byte-exact roundtrip. Every child is an input slice; no caller-sized allocation.
struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn take(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.bytes.first().copied()? != tag {
            return None;
        }
        let first = *self.bytes.get(1)?;
        let (length, header) = if first < 128 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 2 || *self.bytes.get(2)? == 0 {
                return None;
            }
            let encoded = self.bytes.get(2..2 + count)?;
            let mut length = 0usize;
            for byte in encoded {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            if length < 128 {
                return None;
            }
            (length, 2 + count)
        };
        let end = header.checked_add(length)?;
        let value = self.bytes.get(header..end)?;
        self.bytes = self.bytes.get(end..)?;
        Some(value)
    }
    fn done(&self) -> bool {
        self.bytes.is_empty()
    }
}

struct CertId {
    hash: RequestHash,
    name: Vec<u8>,
    key: Vec<u8>,
    serial: Vec<u8>,
}

fn extensions(bytes: &[u8]) -> Option<()> {
    let mut outer = Reader::new(bytes);
    let mut sequence = Reader::new(outer.take(0x30)?);
    if !outer.done() {
        return None;
    }
    let mut count = 0;
    while !sequence.done() {
        count += 1;
        if count > 16 {
            return None;
        }
        let mut item = Reader::new(sequence.take(0x30)?);
        let object = item.take(0x06)?;
        if object.is_empty() {
            return None;
        }
        if item.bytes.first() == Some(&0x01) {
            // The responder ignores request extensions, including critical
            // ones, as the pinned provider does. It never echoes their values.
            // FALSE is a DEFAULT and its explicit form is noncanonical DER.
            if item.take(0x01)? != [0xff] {
                return None;
            }
        }
        item.take(0x04)?;
        if !item.done() {
            return None;
        }
    }
    Some(())
}

fn parse_single(bytes: &[u8], first: bool) -> Option<Option<CertId>> {
    let mut single = Reader::new(bytes);
    let mut cert = Reader::new(single.take(0x30)?);
    let mut algorithm = Reader::new(cert.take(0x30)?);
    let hash_oid = algorithm.take(0x06)?;
    if hash_oid.is_empty() {
        return None;
    }
    if !algorithm.done() && !algorithm.take(0x05)?.is_empty() {
        return None;
    }
    if !algorithm.done() {
        return None;
    }
    let name = cert.take(0x04)?;
    let key = cert.take(0x04)?;
    let serial = cert.take(0x02)?;
    if !cert.done()
        || serial.is_empty()
        || serial.len() > 256
        || serial[0] & 0x80 != 0
        || (serial.len() > 1 && serial[0] == 0 && serial[1] & 0x80 == 0)
    {
        return None;
    }
    if !single.done() {
        extensions(single.take(0xa0)?)?;
    }
    if !single.done() {
        return None;
    }
    if !first {
        return Some(None);
    }
    let hash = RequestHash::from_oid(hash_oid)?;
    if name.len() != hash.digest().size() || key.len() != name.len() {
        return None;
    }
    let serial = if serial.len() > 1 && serial[0] == 0 {
        &serial[1..]
    } else {
        serial
    };
    Some(Some(CertId {
        hash,
        name: name.to_vec(),
        key: key.to_vec(),
        serial: serial.to_vec(),
    }))
}

fn parse_request(bytes: &[u8]) -> Option<CertId> {
    if bytes.is_empty() || bytes.len() >= MAX_OCSP_REQUEST {
        return None;
    }
    let parsed = OcspRequest::from_der(bytes).ok()?;
    if parsed.to_der().ok()?.as_slice() != bytes {
        return None;
    }
    let mut outer = Reader::new(bytes);
    let mut request = Reader::new(outer.take(0x30)?);
    if !outer.done() {
        return None;
    }
    let mut tbs = Reader::new(request.take(0x30)?);
    // A signature and requestorName are outside this closed unsigned lane.
    if !request.done() {
        return None;
    }
    if tbs.bytes.first() == Some(&0xa0) {
        let mut version = Reader::new(tbs.take(0xa0)?);
        if version.take(0x02)? != [0] || !version.done() {
            return None;
        }
    }
    let mut list = Reader::new(tbs.take(0x30)?);
    let first = parse_single(list.take(0x30)?, true)??;
    let mut count = 1;
    while !list.done() {
        count += 1;
        if count > 128 {
            return None;
        }
        // Validate all bounded, canonical structures but respond only to the
        // first CertID. Later entries cannot select another signing payload.
        parse_single(list.take(0x30)?, false)?;
    }
    if !tbs.done() {
        extensions(tbs.take(0xa2)?)?;
    }
    if !tbs.done() {
        return None;
    }
    Some(first)
}

fn issuer_hashes(root: &RootCa, digest: RequestHash) -> Result<(Vec<u8>, Vec<u8>)> {
    let (rest, certificate) = X509Certificate::from_der(&root.certificate_der)
        .map_err(|_| error(503, "invalid local OCSP issuer certificate"))?;
    if !rest.is_empty() || certificate.public_key().subject_public_key.unused_bits != 0 {
        return Err(error(503, "invalid local OCSP issuer public bits"));
    }
    root.validate_local_certificate()?;
    Ok((
        digest.hash(certificate.subject().as_raw())?,
        digest.hash(certificate.public_key().subject_public_key.data.as_ref())?,
    ))
}

fn generalized_time(seconds: u64) -> Result<Vec<u8>> {
    if seconds > 253_402_300_799 {
        return Err(error(503, "local OCSP time outside bounds"));
    }
    let stamp = timestamp(seconds);
    let value: String = stamp
        .chars()
        .filter(|c| !matches!(c, '-' | ':' | 'T'))
        .collect();
    Ok(der(0x18, value.as_bytes()))
}

fn error_response(http_status: u16, response_status: u8) -> EngineResponse {
    EngineResponse {
        status: http_status,
        body: json!({"__heptabao_pki_ocsp_response":BASE64.encode(seq(&[der(0x0a, &[response_status])]))}),
        mutated: false,
    }
}

fn signed_response(
    root: &RootCa,
    request: &CertId,
    revoked: Option<u64>,
    unknown: bool,
    now: u64,
    expiry: u64,
) -> Result<EngineResponse> {
    let pair = root.local_key()?;
    // The pinned Go OCSP provider supports RSA/ECDSA, not the other owned-key
    // families. Do not claim external, Ed25519 or ML-DSA OCSP qualification.
    if matches!(
        pair.kind(),
        LocalKeyKind::Ed25519
            | LocalKeyKind::Mldsa44
            | LocalKeyKind::Mldsa65
            | LocalKeyKind::Mldsa87
    ) {
        return Err(error(503, "local OCSP signing algorithm unavailable"));
    }
    let (name, key) = issuer_hashes(root, request.hash)?;
    let cert_id = seq(&[
        seq(&[oid(request.hash.oid()), der(0x05, &[])]),
        octet_string(&name),
        octet_string(&key),
        integer(&request.serial),
    ]);
    let status = if unknown {
        context_primitive(2, &[])
    } else if let Some(at) = revoked {
        // IMPLICIT RevokedInfo: time only; unspecified reason is omitted.
        der(0xa1, &generalized_time(at)?)
    } else {
        context_primitive(0, &[])
    };
    let mut single = vec![cert_id, status, generalized_time(now)?];
    if expiry != 0 {
        single.push(context_explicit(
            0,
            &generalized_time(
                now.checked_add(expiry)
                    .ok_or_else(|| error(503, "local OCSP expiry overflow"))?,
            )?,
        ));
    }
    let tbs = seq(&[
        context_explicit(1, &root_fields::certificate_subject(&root.certificate_der)?),
        generalized_time(now / 60 * 60)?,
        seq(&[seq(&single)]),
    ]);
    if crate::request_deadline::current()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(error(503, "local OCSP request deadline exceeded"));
    }
    let signature = pair.sign(&tbs)?;
    if !pair.public()?.verify(&tbs, &signature)? {
        return Err(error(503, "local OCSP signature failed validation"));
    }
    if crate::request_deadline::current()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(error(503, "local OCSP request deadline exceeded"));
    }
    let basic = seq(&[
        tbs,
        pair.kind().signature_algorithm(),
        bit_string(&signature, 0),
    ]);
    let bytes = seq(&[
        der(0x0a, &[0]),
        context_explicit(0, &seq(&[oid(BASIC_RESPONSE_OID), octet_string(&basic)])),
    ]);
    if bytes.len() > MAX_OCSP_RESPONSE {
        return Err(error(503, "local OCSP response exceeds bounds"));
    }
    let decoded =
        OcspResponse::from_der(&bytes).map_err(|_| error(503, "local OCSP response invalid"))?;
    if decoded
        .to_der()
        .map_err(|_| error(503, "local OCSP response invalid"))?
        != bytes
    {
        return Err(error(503, "local OCSP response is noncanonical"));
    }
    Ok(EngineResponse {
        status: 200,
        body: json!({"__heptabao_pki_ocsp_response":BASE64.encode(bytes)}),
        mutated: false,
    })
}

fn project_response(result: Result<EngineResponse>) -> Result<EngineResponse> {
    match result {
        Ok(response) => Ok(response),
        Err(_)
            if crate::request_deadline::current()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline) =>
        {
            Err(error(503, "local OCSP request deadline exceeded"))
        }
        Err(_) => Ok(error_response(500, 2)),
    }
}

impl Pki {
    pub(super) fn local_ocsp(
        &self,
        get: bool,
        suffix: Option<&str>,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        let (disabled, expiry) = self.local_ocsp_policy()?;
        if disabled {
            return Ok(error_response(401, 6));
        }
        let encoded = if let Some(suffix) = suffix {
            if reject_unknown(body, &[]).is_err() {
                return Ok(error_response(400, 1));
            }
            suffix
        } else {
            if reject_unknown(body, &[REQUEST_MARKER]).is_err() {
                return Ok(error_response(400, 1));
            }
            match body.get(REQUEST_MARKER).and_then(Value::as_str) {
                Some(value) => value,
                None => return Ok(error_response(400, 1)),
            }
        };
        if encoded.len()
            >= if get {
                MAX_OCSP_REQUEST
            } else {
                MAX_OCSP_REQUEST.div_ceil(3) * 4 + 1
            }
        {
            return Ok(error_response(400, 1));
        }
        let bytes = match BASE64.decode(encoded) {
            Ok(bytes) if BASE64.encode(&bytes) == encoded => bytes,
            _ => return Ok(error_response(400, 1)),
        };
        let Some(request) = parse_request(&bytes) else {
            return Ok(error_response(400, 1));
        };
        let serial: String = request.serial.iter().map(|v| format!("{v:02x}")).collect();
        let revoked = self
            .issued
            .iter()
            .find(|(stored, _)| stored.trim_start_matches('0') == serial.trim_start_matches('0'))
            .map(|(_, cert)| cert)
            .filter(|cert| cert.revoked_at.is_some());
        let revoked_ca = self.signed_ca_revocation_for_serial(&serial);
        for root in self.local_roots() {
            if revoked_ca.is_some_and(|(issuer, _)| issuer != root.issuer_id) {
                continue;
            }
            if let Some(cert) = revoked {
                if !cert.local_issuer_id.is_empty() {
                    if cert.local_issuer_id != root.issuer_id {
                        continue;
                    }
                } else {
                    let Ok((rest, leaf)) = X509Certificate::from_der(&cert.certificate_der) else {
                        return Ok(error_response(500, 2));
                    };
                    let public = root.local_key()?.public()?;
                    if !rest.is_empty()
                        || leaf.issuer().as_raw()
                            != root_fields::certificate_subject(&root.certificate_der)?
                        || !public
                            .verify(leaf.tbs_certificate.as_ref(), &leaf.signature_value.data)?
                    {
                        continue;
                    }
                }
            }
            let (name, key) = match issuer_hashes(root, request.hash) {
                Ok(hashes) => hashes,
                Err(_) => return Ok(error_response(500, 2)),
            };
            if request.name == name && request.key == key {
                return project_response(signed_response(
                    root,
                    &request,
                    revoked
                        .and_then(|cert| cert.revoked_at)
                        .or(revoked_ca.map(|(_, at)| at)),
                    false,
                    now,
                    expiry,
                ));
            }
        }
        let Some(root) = self
            .local_issuer("default")
            .ok()
            .filter(|root| !root.is_external())
        else {
            return Ok(error_response(401, 6));
        };
        project_response(signed_response(root, &request, None, true, now, expiry))
    }
}

/// The HTTP carrier cannot select an arbitrary content type or unchecked bytes.
/// Errors have the exact five-byte protocol form; success must roundtrip through
/// the maintained OCSP decoder and contain a real BasicOCSPResponse.
pub(crate) fn raw_response(status: u16, body: &Value) -> Option<Vec<u8>> {
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let text = object.get(RESPONSE_MARKER)?.as_str()?;
    if text.len() > MAX_OCSP_RESPONSE.div_ceil(3) * 4 {
        return None;
    }
    let bytes = BASE64.decode(text).ok()?;
    if bytes.len() > MAX_OCSP_RESPONSE || BASE64.encode(&bytes) != text {
        return None;
    }
    let expected = match status {
        200 => 0,
        400 => 1,
        401 => 6,
        500 => 2,
        _ => return None,
    };
    let response = OcspResponse::from_der(&bytes).ok()?;
    if response.status().as_raw() != expected || response.to_der().ok()? != bytes {
        return None;
    }
    if expected == 0 {
        response.basic().ok()?;
    } else if bytes != [0x30, 3, 0x0a, 1, expected as u8] {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ocsp::{OcspCertId, OcspCertStatus, OcspFlag},
        stack::Stack,
        x509::{X509, store::X509StoreBuilder},
    };
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |v| v.as_secs())
    }
    fn generate(pki: &mut Pki, name: &str, kind: &str, bits: u32, now: u64) -> Result<()> {
        pki.handle_admin("POST", "root/generate/internal", &json!({"common_name":format!("{name}.example.test"),"organization":["OCSP full DN"],"issuer_name":name,"key_type":kind,"key_bits":bits,"ttl":"48h"}), now)?;
        Ok(())
    }
    fn issue(pki: &mut Pki, root: &str, at: u64) -> TestResult {
        pki.handle_admin("POST", "roles/web", &json!({"issuer_ref":root,"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h"}),at)?;
        pki.issue(
            "pki/",
            "web",
            &json!({"common_name":"leaf.example.test","ttl":"1h"}),
            &serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?,
            None,
            at,
        )?;
        Ok(())
    }
    fn make_request(
        leaf: &[u8],
        issuer: &[u8],
        digest: MessageDigest,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        let leaf = X509::from_der(leaf)?;
        let issuer = X509::from_der(issuer)?;
        let mut request = OcspRequest::new()?;
        request.add_id(OcspCertId::from_cert(digest, &leaf, &issuer)?)?;
        Ok(request.to_der()?)
    }
    fn verify(
        response: &EngineResponse,
        leaf: &[u8],
        issuer: &[u8],
        digest: MessageDigest,
        status: OcspCertStatus,
        expiry: bool,
    ) -> TestResult {
        assert_eq!(response.status, 200);
        let bytes = raw_response(200, &response.body).ok_or("closed raw OCSP response")?;
        let response = OcspResponse::from_der(&bytes)?;
        let basic = response.basic()?;
        let leaf = X509::from_der(leaf)?;
        let issuer = X509::from_der(issuer)?;
        let mut certs = Stack::new()?;
        certs.push(issuer.clone())?;
        let mut trust = X509StoreBuilder::new()?;
        trust.add_cert(issuer.clone())?;
        basic.verify(&certs, &trust.build(), OcspFlag::empty())?;
        // OCSP_cert_to_id hashes the leaf issuer DN. Unknown rewrites that
        // hash to the default signer, retaining only the requested serial.
        let projected_leaf = if status == OcspCertStatus::UNKNOWN {
            let mut builder = X509::builder()?;
            builder.set_serial_number(leaf.serial_number())?;
            builder.set_issuer_name(issuer.subject_name())?;
            builder.build()
        } else {
            leaf
        };
        let id = OcspCertId::from_cert(digest, &projected_leaf, &issuer)?;
        let observed = basic.find_status(&id).ok_or("actual OCSP CertID status")?;
        assert_eq!(observed.status, status);
        assert_eq!(observed.next_update().is_some(), expiry);
        Ok(())
    }
    #[test]
    fn actual_classic_issuer_ocsp_hashes_signatures_revocation_and_expiry() -> TestResult {
        let now = now();
        for (kind, bits) in [("rsa", 2048), ("ec", 256)] {
            let mut pki = Pki::default();
            generate(&mut pki, "alpha", kind, bits, now)?;
            issue(&mut pki, "alpha", now + 1)?;
            let (serial, leaf) = pki
                .issued
                .iter()
                .next()
                .map(|(s, c)| (s.clone(), c.certificate_der.clone()))
                .ok_or("leaf")?;
            let issuer = pki.root.as_ref().ok_or("issuer")?.certificate_der.clone();
            for hash in [
                MessageDigest::sha1(),
                MessageDigest::sha256(),
                MessageDigest::sha384(),
                MessageDigest::sha512(),
            ] {
                let request = make_request(&leaf, &issuer, hash)?;
                let response = pki.local_ocsp(
                    false,
                    None,
                    &json!({"__heptabao_pki_ocsp_request":BASE64.encode(&request)}),
                    now + 2,
                )?;
                verify(&response, &leaf, &issuer, hash, OcspCertStatus::GOOD, true)?;
                let get =
                    pki.local_ocsp(true, Some(&BASE64.encode(&request)), &json!({}), now + 2)?;
                verify(&get, &leaf, &issuer, hash, OcspCertStatus::GOOD, true)?;
            }
            pki.handle_admin("POST", "revoke", &json!({"serial_number":serial}), now + 3)?;
            let request = make_request(&leaf, &issuer, MessageDigest::sha256())?;
            let response = pki.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(&request)}),
                now + 4,
            )?;
            verify(
                &response,
                &leaf,
                &issuer,
                MessageDigest::sha256(),
                OcspCertStatus::REVOKED,
                true,
            )?;
            pki.handle_admin("POST", "config/crl", &json!({"ocsp_expiry":"0s"}), now + 5)?;
            let reopened: Pki = serde_json::from_slice(&serde_json::to_vec(&pki)?)?;
            let response = reopened.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(&request)}),
                now + 6,
            )?;
            verify(
                &response,
                &leaf,
                &issuer,
                MessageDigest::sha256(),
                OcspCertStatus::REVOKED,
                false,
            )?;
        }
        Ok(())
    }
    #[test]
    fn actual_first_request_extensions_version_and_default_unknown() -> TestResult {
        let at = now();
        let mut pki = Pki::default();
        generate(&mut pki, "alpha", "rsa", 2048, at)?;
        issue(&mut pki, "alpha", at + 1)?;
        let leaf = pki
            .issued
            .values()
            .next()
            .ok_or("leaf")?
            .certificate_der
            .clone();
        let issuer = pki.root.as_ref().ok_or("issuer")?.certificate_der.clone();
        let original = make_request(&leaf, &issuer, MessageDigest::sha256())?;
        let mut outer = Reader::new(&original);
        let mut request = Reader::new(outer.take(0x30).ok_or("request")?);
        let mut tbs = Reader::new(request.take(0x30).ok_or("tbs")?);
        let list = tbs.take(0x30).ok_or("list")?.to_vec();
        let mut items = Reader::new(&list);
        let single = der(0x30, items.take(0x30).ok_or("single")?);
        for critical in [false, true] {
            let mut fields = vec![oid(&[0x2a, 3, 4])];
            if critical {
                fields.push(der(0x01, &[0xff]));
            }
            fields.push(octet_string(b"opaque extension is not signed or echoed"));
            let extension = context_explicit(2, &seq(&[seq(&fields)]));
            let variant = seq(&[seq(&[seq(std::slice::from_ref(&single)), extension])]);
            let response = pki.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(variant)}),
                at + 2,
            )?;
            verify(
                &response,
                &leaf,
                &issuer,
                MessageDigest::sha256(),
                OcspCertStatus::GOOD,
                true,
            )?;
        }
        for variant in [
            seq(&[seq(&[
                context_explicit(0, &integer(&[0])),
                seq(std::slice::from_ref(&single)),
            ])]),
            seq(&[seq(&[seq(&[single.clone(), single.clone()])])]),
        ] {
            let response = pki.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(variant)}),
                at + 2,
            )?;
            verify(
                &response,
                &leaf,
                &issuer,
                MessageDigest::sha256(),
                OcspCertStatus::GOOD,
                true,
            )?;
        }
        for variant in [
            seq(&[seq(&[
                context_explicit(1, &der(0x86, b"https://example.test")),
                seq(std::slice::from_ref(&single)),
            ])]),
            seq(&[
                seq(&[seq(&[single])]),
                context_explicit(
                    0,
                    &seq(&[
                        LocalKeyKind::Ec256.signature_algorithm(),
                        bit_string(b"fake signature", 0),
                    ]),
                ),
            ]),
        ] {
            assert!(parse_request(&variant).is_none());
        }
        let mut foreign = Pki::default();
        generate(&mut foreign, "foreign", "ec", 256, at)?;
        issue(&mut foreign, "foreign", at + 1)?;
        let foreign_leaf = foreign
            .issued
            .values()
            .next()
            .ok_or("foreign leaf")?
            .certificate_der
            .clone();
        let foreign_issuer = foreign
            .root
            .as_ref()
            .ok_or("foreign issuer")?
            .certificate_der
            .clone();
        let request = make_request(&foreign_leaf, &foreign_issuer, MessageDigest::sha256())?;
        let response = pki.local_ocsp(
            false,
            None,
            &json!({"__heptabao_pki_ocsp_request":BASE64.encode(&request)}),
            at + 2,
        )?;
        verify(
            &response,
            &foreign_leaf,
            &issuer,
            MessageDigest::sha256(),
            OcspCertStatus::UNKNOWN,
            true,
        )?;
        {
            let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
                std::time::Instant::now() - std::time::Duration::from_secs(1),
            );
            let result = pki.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(original)}),
                at + 2,
            );
            assert!(result.is_err_and(|error| error.status == 503));
        }
        Ok(())
    }
    #[test]
    fn actual_signed_ca_revocation_matches_the_owned_signing_issuer_after_restart() -> TestResult {
        let at = now();
        let mut ca = Pki::default();
        generate(&mut ca, "alpha", "ec", 256, at)?;
        let alpha = ca.local_issuer("alpha")?.certificate_der.clone();
        generate(&mut ca, "beta", "ec", 256, at)?;
        let beta = ca.local_issuer("beta")?.certificate_der.clone();
        let mut intermediate = Pki::default();
        let csr = intermediate.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"intermediate.example.test","key_type":"ec","key_bits":256}),
            at + 1,
        )?;
        let csr = csr.body["data"]["csr"].as_str().ok_or("CSR")?;
        let signed = ca.handle_admin(
            "POST",
            "issuer/alpha/sign-intermediate",
            &json!({"csr":csr,"use_csr_values":true,"ttl":"24h"}),
            at + 2,
        )?;
        let serial = signed.body["data"]["serial_number"]
            .as_str()
            .ok_or("CA serial")?
            .to_owned();
        let leaf = X509::from_pem(
            signed.body["data"]["certificate"]
                .as_str()
                .ok_or("CA certificate")?
                .as_bytes(),
        )?;
        let leaf_der = leaf.to_der()?;
        let request = make_request(&leaf_der, &alpha, MessageDigest::sha256())?;
        let body = json!({"__heptabao_pki_ocsp_request":BASE64.encode(&request)});
        verify(
            &ca.local_ocsp(false, None, &body, at + 3)?,
            &leaf_der,
            &alpha,
            MessageDigest::sha256(),
            OcspCertStatus::GOOD,
            true,
        )?;
        ca.handle_admin("POST", "revoke", &json!({"serial_number":serial}), at + 4)?;
        ca.validate("", "pki/", at + 4)?;
        let encoded = Zeroizing::new(serde_json::to_vec(&ca)?);
        let reopened: Pki = serde_json::from_slice(&encoded)?;
        reopened.validate("", "pki/", at + 5)?;
        verify(
            &reopened.local_ocsp(false, None, &body, at + 5)?,
            &leaf_der,
            &alpha,
            MessageDigest::sha256(),
            OcspCertStatus::REVOKED,
            true,
        )?;
        // The same real CA serial under another actual issuer's CertID cannot
        // borrow alpha's revocation or signature. Pinned lookup returns Unknown.
        let beta_cert = X509::from_der(&beta)?;
        let mut other = X509::builder()?;
        other.set_serial_number(leaf.serial_number())?;
        other.set_issuer_name(beta_cert.subject_name())?;
        let mut request = OcspRequest::new()?;
        request.add_id(OcspCertId::from_cert(
            MessageDigest::sha256(),
            &other.build(),
            &beta_cert,
        )?)?;
        let body = json!({"__heptabao_pki_ocsp_request":BASE64.encode(request.to_der()?)});
        verify(
            &reopened.local_ocsp(false, None, &body, at + 5)?,
            &leaf_der,
            &alpha,
            MessageDigest::sha256(),
            OcspCertStatus::UNKNOWN,
            true,
        )?;
        Ok(())
    }

    #[test]
    fn actual_parent_signed_owned_intermediate_ocsp_chain_and_restart() -> TestResult {
        let at = now();
        let mut parent = Pki::default();
        generate(&mut parent, "parent", "ec", 384, at)?;
        let parent_der = parent
            .root
            .as_ref()
            .ok_or("parent")?
            .certificate_der
            .clone();
        let mut intermediate = Pki::default();
        let csr = intermediate.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"intermediate.example.test","key_type":"ec","key_bits":256}),
            at + 1,
        )?;
        let signed = parent.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"24h"}),
            at + 2,
        )?;
        let chain = signed.body["data"]["ca_chain"]
            .as_array()
            .ok_or("CA chain")?
            .iter()
            .map(|value| value.as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        intermediate.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":chain}),
            at + 3,
        )?;
        intermediate.validate("", "pki/", at + 3)?;
        issue(&mut intermediate, "default", at + 4)?;
        let (serial, leaf) = intermediate
            .issued
            .iter()
            .next()
            .map(|(serial, cert)| (serial.clone(), cert.certificate_der.clone()))
            .ok_or("leaf")?;
        let issuer_der = intermediate
            .root
            .as_ref()
            .ok_or("intermediate")?
            .certificate_der
            .clone();
        // Trust only the actual parent; the responder is a non-self-signed
        // owned intermediate in the untrusted chain, without partial-chain flags.
        let issuer = X509::from_der(&issuer_der)?;
        let leaf_cert = X509::from_der(&leaf)?;
        let mut issuers = Stack::new()?;
        issuers.push(issuer.clone())?;
        let mut trust = X509StoreBuilder::new()?;
        trust.add_cert(X509::from_der(&parent_der)?)?;
        let trust = trust.build();
        for digest in [
            MessageDigest::sha1(),
            MessageDigest::sha256(),
            MessageDigest::sha384(),
            MessageDigest::sha512(),
        ] {
            let request = make_request(&leaf, &issuer_der, digest)?;
            for (get, body) in [
                (false, json!({REQUEST_MARKER:BASE64.encode(&request)})),
                (true, json!({})),
            ] {
                let response = intermediate.local_ocsp(
                    get,
                    get.then_some(BASE64.encode(&request)).as_deref(),
                    &body,
                    at + 5,
                )?;
                assert_eq!(response.status, 200);
                let bytes = raw_response(200, &response.body).ok_or("raw OCSP")?;
                let basic = OcspResponse::from_der(&bytes)?.basic()?;
                basic.verify(&issuers, &trust, OcspFlag::empty())?;
                let id = OcspCertId::from_cert(digest, &leaf_cert, &issuer)?;
                assert_eq!(
                    basic.find_status(&id).ok_or("CertID")?.status,
                    OcspCertStatus::GOOD
                );
            }
        }
        intermediate.handle_admin("POST", "revoke", &json!({"serial_number":serial}), at + 6)?;
        let encoded = Zeroizing::new(serde_json::to_vec(&intermediate)?);
        let reopened: Pki = serde_json::from_slice(&encoded)?;
        reopened.validate("", "pki/", at + 7)?;
        let request = make_request(&leaf, &issuer_der, MessageDigest::sha256())?;
        let response = reopened.local_ocsp(
            false,
            None,
            &json!({REQUEST_MARKER:BASE64.encode(&request)}),
            at + 7,
        )?;
        assert_eq!(response.status, 200);
        let bytes = raw_response(200, &response.body).ok_or("raw OCSP")?;
        let basic = OcspResponse::from_der(&bytes)?.basic()?;
        basic.verify(&issuers, &trust, OcspFlag::empty())?;
        let id = OcspCertId::from_cert(MessageDigest::sha256(), &leaf_cert, &issuer)?;
        assert_eq!(
            basic.find_status(&id).ok_or("reopened CertID")?.status,
            OcspCertStatus::REVOKED
        );
        Ok(())
    }

    #[test]
    fn canonical_bounded_requests_and_disabled_priority() -> TestResult {
        let mut pki = Pki::default();
        generate(&mut pki, "alpha", "ec", 256, now())?;
        for input in [
            Vec::new(),
            vec![0; 2047],
            vec![0; 2048],
            vec![0x30, 0x80, 0, 0],
            vec![0x30, 0x81, 0],
        ] {
            let response = pki.local_ocsp(
                false,
                None,
                &json!({"__heptabao_pki_ocsp_request":BASE64.encode(input)}),
                now(),
            )?;
            assert_eq!(
                raw_response(400, &response.body),
                Some(vec![0x30, 3, 0x0a, 1, 1])
            );
        }
        pki.handle_admin("POST", "config/crl", &json!({"ocsp_disable":true}), now())?;
        let response = pki.local_ocsp(
            false,
            None,
            &json!({"untrusted":"arbitrary signing bytes"}),
            now(),
        )?;
        assert_eq!(response.status, 401);
        assert_eq!(
            raw_response(401, &response.body),
            Some(vec![0x30, 3, 0x0a, 1, 6])
        );
        for body in [
            json!({"__heptabao_pki_ocsp_response":"MA=="}),
            json!({"__heptabao_pki_ocsp_response":"MAMKAQE=","extra":true}),
        ] {
            assert!(raw_response(400, &body).is_none());
        }
        Ok(())
    }
}
