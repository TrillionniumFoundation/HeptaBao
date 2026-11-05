//! Independent wire decoding plus real trusted-public-key SHA1 verification.
use super::*;
use openssl::{bn::BigNum, rsa::Rsa};
use ssh_key::{certificate::CertType, public::KeyData};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

// Deliberately separate from the producer's read_string/options helpers.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn bytes(&mut self, count: usize) -> TestResult<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or("decode overflow")?;
        let value = self.bytes.get(self.at..end).ok_or("truncated wire")?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> TestResult<u32> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into()?))
    }
    fn u64(&mut self) -> TestResult<u64> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into()?))
    }
    fn string(&mut self) -> TestResult<&'a [u8]> {
        let length = self.u32()? as usize;
        self.bytes(length)
    }
}
fn utf8(value: &[u8]) -> TestResult<String> {
    Ok(std::str::from_utf8(value)?.to_owned())
}
fn map(raw: &[u8]) -> TestResult<BTreeMap<String, String>> {
    let mut input = Reader { bytes: raw, at: 0 };
    let mut entries = BTreeMap::new();
    let mut prior = String::new();
    while input.at < raw.len() {
        let name = utf8(input.string()?)?;
        if name <= prior {
            return Err("noncanonical option order".into());
        }
        prior = name.clone();
        let nested = input.string()?;
        let value = if nested.is_empty() {
            String::new()
        } else {
            let mut nested_input = Reader {
                bytes: nested,
                at: 0,
            };
            let value = utf8(nested_input.string()?)?;
            if nested_input.at != nested.len() {
                return Err("trailing option bytes".into());
            }
            value
        };
        if entries.insert(name, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    Ok(entries)
}
struct Parsed {
    serial: u64,
    kind: u32,
    key_id: String,
    principals: Vec<String>,
    after: u64,
    before: u64,
    critical: BTreeMap<String, String>,
    extensions: BTreeMap<String, String>,
    nonce: Vec<u8>,
    issuer: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    raw: Vec<u8>,
}
fn decode(line: &str, subject: &PublicKey) -> TestResult<Parsed> {
    let mut words = line.split_whitespace();
    let outer = words.next().ok_or("missing tag")?;
    let raw = STANDARD.decode(words.next().ok_or("missing payload")?)?;
    if words.next().is_some() {
        return Err("unexpected certificate comment".into());
    }
    let mut input = Reader { bytes: &raw, at: 0 };
    let tag = utf8(input.string()?)?;
    if tag != outer || tag != subject.algorithm().to_certificate_type() {
        return Err("wrong subject certificate tag".into());
    }
    let nonce = input.string()?.to_vec();
    let subject_bytes = subject.to_bytes()?;
    let mut subject_reader = Reader {
        bytes: &subject_bytes,
        at: 0,
    };
    if utf8(subject_reader.string()?)? != subject.algorithm().as_str() {
        return Err("wrong subject algorithm".into());
    }
    let expected = &subject_bytes[subject_reader.at..];
    if input.bytes(expected.len())? != expected {
        return Err("subject key differs".into());
    }
    let serial = input.u64()?;
    let kind = input.u32()?;
    let key_id = utf8(input.string()?)?;
    let principals_bytes = input.string()?;
    let mut principal_reader = Reader {
        bytes: principals_bytes,
        at: 0,
    };
    let mut principals = Vec::new();
    while principal_reader.at < principals_bytes.len() {
        principals.push(utf8(principal_reader.string()?)?);
    }
    let after = input.u64()?;
    let before = input.u64()?;
    let critical = map(input.string()?)?;
    let extensions = map(input.string()?)?;
    if !input.string()?.is_empty() {
        return Err("nonempty reserved field".into());
    }
    let issuer = input.string()?.to_vec();
    let tbs = raw[..input.at].to_vec();
    let signature_blob = input.string()?;
    let mut signature_reader = Reader {
        bytes: signature_blob,
        at: 0,
    };
    if utf8(signature_reader.string()?)? != "ssh-rsa" {
        return Err("signature is not explicit ssh-rsa".into());
    }
    let signature = signature_reader.string()?.to_vec();
    if signature_reader.at != signature_blob.len() || input.at != raw.len() {
        return Err("trailing signature/certificate bytes".into());
    }
    Ok(Parsed {
        serial,
        kind,
        key_id,
        principals,
        after,
        before,
        critical,
        extensions,
        nonce,
        issuer,
        tbs,
        signature,
        raw,
    })
}
fn trusted_verifies(cert: &Parsed, issuer: &PublicKey, digest: MessageDigest) -> TestResult<bool> {
    if cert.issuer != issuer.to_bytes()? {
        return Ok(false);
    }
    let KeyData::Rsa(rsa) = issuer.key_data() else {
        return Err("test issuer must be RSA".into());
    };
    let public = PKey::from_rsa(Rsa::from_public_components(
        BigNum::from_slice(rsa.n.as_positive_bytes().ok_or("bad modulus")?)?,
        BigNum::from_slice(rsa.e.as_positive_bytes().ok_or("bad exponent")?)?,
    )?)?;
    let mut verifier = Verifier::new(digest, &public)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    Ok(verifier.verify_oneshot(&cert.signature, &cert.tbs)?)
}
fn policy() -> SigningPolicy {
    SigningPolicy {
        kind: CertType::User,
        principals: vec!["alice".into(), "bob".into()],
        key_id: "original-key-id".into(),
        valid_after: 1_699_999_970,
        valid_before: 1_700_000_090,
        critical_options: BTreeMap::from([
            ("force-command".into(), "true".into()),
            ("source-address".into(), "192.0.2.0/24".into()),
        ]),
        extensions: BTreeMap::from([
            ("empty".into(), String::new()),
            ("permit-pty".into(), String::new()),
            ("custom".into(), "actual".into()),
        ]),
        issuer_ref: "default".into(),
        algorithm_signer: "ssh-rsa".into(),
    }
}
#[test]
fn ssh_legacy_rsa_real_sha1_certificates_preserve_all_wire_fields_and_subject_algorithms()
-> TestResult {
    let issuer = super::super::ssh_ca_crypto::generate("rsa", 2048)?;
    let issuer_public = issuer.public()?;
    for (kind, bits) in [
        ("rsa", 2048),
        ("ed25519", 0),
        ("ec", 256),
        ("ec", 384),
        ("ec", 521),
    ] {
        let subject = super::super::ssh_ca_crypto::generate(kind, bits)?.public()?;
        let policy = policy();
        let nonce = [0x49u8; 32];
        let line = sign(&issuer, &subject, &policy, 73, &nonce)?;
        let cert = decode(&line, &subject)?;
        assert_eq!(cert.serial, 73);
        assert_eq!(cert.kind, 1);
        assert_eq!(cert.key_id, policy.key_id);
        assert_eq!(cert.principals, policy.principals);
        assert_eq!(cert.after, policy.valid_after);
        assert_eq!(cert.before, policy.valid_before);
        assert_eq!(cert.nonce, nonce);
        assert_eq!(cert.critical, policy.critical_options);
        assert_eq!(cert.extensions, policy.extensions);
        assert!(trusted_verifies(
            &cert,
            &issuer_public,
            MessageDigest::sha1()
        )?);
        assert!(!trusted_verifies(
            &cert,
            &issuer_public,
            MessageDigest::sha256()
        )?);
        assert_eq!(cert.signature.len(), issuer.key()?.rsa()?.size() as usize);
        assert!(!line.ends_with('\n'));
        assert!(
            cert.raw.starts_with(
                &(subject.algorithm().to_certificate_type().len() as u32).to_be_bytes()
            )
        );
    }
    Ok(())
}
#[test]
fn ssh_legacy_rsa_trusted_key_tbs_and_signature_tamper_do_not_verify() -> TestResult {
    let issuer = super::super::ssh_ca_crypto::generate("rsa", 2048)?;
    let other = super::super::ssh_ca_crypto::generate("rsa", 2048)?;
    let subject = super::super::ssh_ca_crypto::generate("ed25519", 0)?.public()?;
    let line = sign(&issuer, &subject, &policy(), 81, &[0x15u8; 32])?;
    let mut cert = decode(&line, &subject)?;
    assert!(trusted_verifies(
        &cert,
        &issuer.public()?,
        MessageDigest::sha1()
    )?);
    assert!(!trusted_verifies(
        &cert,
        &other.public()?,
        MessageDigest::sha1()
    )?);
    let offset = cert.tbs.len() - 1;
    cert.tbs[offset] ^= 1;
    assert!(!trusted_verifies(
        &cert,
        &issuer.public()?,
        MessageDigest::sha1()
    )?);
    cert.tbs[offset] ^= 1;
    let last = cert.signature.len() - 1;
    cert.signature[last] ^= 1;
    assert!(!trusted_verifies(
        &cert,
        &issuer.public()?,
        MessageDigest::sha1()
    )?);
    Ok(())
}
#[test]
fn ssh_legacy_rsa_canonical_host_empty_principals_and_malformed_wire_controls() -> TestResult {
    let issuer = super::super::ssh_ca_crypto::generate("rsa", 2048)?;
    let subject = super::super::ssh_ca_crypto::generate("ed25519", 0)?.public()?;
    let mut policy = policy();
    policy.kind = CertType::Host;
    policy.principals.clear();
    let line = sign(&issuer, &subject, &policy, 84, &[9u8; 32])?;
    let cert = decode(&line, &subject)?;
    assert_eq!(cert.kind, 2);
    assert!(cert.principals.is_empty());
    assert!(trusted_verifies(
        &cert,
        &issuer.public()?,
        MessageDigest::sha1()
    )?);
    for bytes in [&cert.raw[..cert.raw.len() - 1], &cert.raw[..3]] {
        let line = format!(
            "{} {}",
            subject.algorithm().to_certificate_type(),
            STANDARD.encode(bytes)
        );
        assert!(decode(&line, &subject).is_err());
    }
    let mut trailing = cert.raw.clone();
    trailing.push(0);
    assert!(
        decode(
            &format!(
                "{} {}",
                subject.algorithm().to_certificate_type(),
                STANDARD.encode(trailing)
            ),
            &subject
        )
        .is_err()
    );
    assert!(
        decode(
            &line.replacen(
                subject.algorithm().to_certificate_type().as_str(),
                "wrong-tag",
                1
            ),
            &subject
        )
        .is_err()
    );
    assert!(sign(&issuer, &subject, &policy, 0, &[0u8; 31]).is_err());
    policy.algorithm_signer = "rsa-sha2-256".into();
    assert!(sign(&issuer, &subject, &policy, 0, &[0u8; 32]).is_err());
    let ed = super::super::ssh_ca_crypto::generate("ed25519", 0)?;
    policy.algorithm_signer = "ssh-rsa".into();
    assert_eq!(
        sign(&ed, &subject, &policy, 0, &[0u8; 32])
            .err()
            .ok_or("issuer algorithm denial")?
            .status,
        500
    );
    Ok(())
}
#[test]
fn ssh_legacy_rsa_original_request_deadline_is_not_rearmed() -> TestResult {
    let issuer = super::super::ssh_ca_crypto::generate("rsa", 2048)?;
    let subject = super::super::ssh_ca_crypto::generate("ed25519", 0)?.public()?;
    let original = std::time::Instant::now() - std::time::Duration::from_millis(1);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(original);
    let _later = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + std::time::Duration::from_secs(15),
    );
    assert_eq!(crate::request_deadline::current(), Some(original));
    assert_eq!(
        sign(&issuer, &subject, &policy(), 0, &[0u8; 32])
            .err()
            .ok_or("expired original")?
            .status,
        503
    );
    Ok(())
}

#[test]
fn ssh_legacy_rsa_actual_ca_sign_and_issue_keep_contextless_refusal_and_return_verified_certificates()
-> TestResult {
    use super::super::ssh_ca::CaState;
    use super::super::ssh_ca_policy::SigningContext;
    use serde_json::json;
    let mut ca = CaState::default();
    let configured = ca
        .handle_admin(
            "POST",
            "config/ca",
            &json!({"key_type":"rsa","key_bits":2048}),
        )?
        .ok_or("actual configured CA")?;
    let issuer = PublicKey::from_openssh(
        configured.body["data"]["public_key"]
            .as_str()
            .ok_or("issuer")?,
    )?;
    ca.put_role(
        "operators",
        &json!({"key_type":"ca","allow_user_certificates":true,
        "allowed_users":"alice","default_user":"alice","ttl":"90s","algorithm_signer":"ssh-rsa"}),
    )?;
    let context = SigningContext {
        role_name: "operators",
        display_name: "original",
        now: 1_700_000_000,
        default_ttl: 3600,
        max_ttl: 86400,
    };
    let subject = super::super::ssh_ca_crypto::generate("ed25519", 0)?.public()?;
    let request = json!({"public_key":subject.to_openssh()?});
    assert_eq!(
        ca.sign(&request, &context, false)
            .err()
            .ok_or("old contextless refusal")?
            .status,
        501
    );
    let identity = super::super::ssh_templates::RequestIdentity::absent();
    let response = ca.sign_authenticated(&request, &context, false, &identity)?;
    assert_eq!(response.status, 200);
    assert!(response.mutated);
    let cert = decode(
        response.body["data"]["signed_key"]
            .as_str()
            .ok_or("signed certificate")?,
        &subject,
    )?;
    assert!(trusted_verifies(&cert, &issuer, MessageDigest::sha1())?);
    assert_eq!(cert.principals, vec!["alice"]);
    assert_eq!(cert.after, 1_699_999_970);
    assert_eq!(cert.before, 1_700_000_090);
    assert_eq!(
        response.body["data"]["serial_number"],
        format!("{:x}", cert.serial)
    );
    let response =
        ca.sign_authenticated(&json!({"key_type":"ed25519"}), &context, true, &identity)?;
    assert_eq!(response.status, 200);
    assert!(response.mutated);
    let issued = super::super::ssh_ca_crypto::import(
        response.body["data"]["private_key"]
            .as_str()
            .ok_or("issued private material")?,
    )?;
    let cert = decode(
        response.body["data"]["signed_key"]
            .as_str()
            .ok_or("issued certificate")?,
        &issued.public()?,
    )?;
    assert!(trusted_verifies(&cert, &issuer, MessageDigest::sha1())?);
    assert_eq!(cert.principals, vec!["alice"]);
    assert_eq!(response.body["data"]["private_key_type"], "ed25519");
    ca.validate()?;
    Ok(())
}
