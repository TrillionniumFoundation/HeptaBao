//! Unknown algorithm rejection at both actual CA entry points; no authority is added.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Verifier,
};
use ssh_key::{Certificate, HashAlg, public::KeyData};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn context() -> SigningContext<'static> {
    SigningContext {
        role_name: "operators",
        display_name: "actual-original",
        now: 1_700_000_000,
        default_ttl: 3600,
        max_ttl: 86400,
    }
}
fn configured(algorithm: &str) -> Result<CaState> {
    let mut ca = CaState::default();
    let response = ca
        .handle_admin(
            "POST",
            "config/ca",
            &json!({
                "key_type":"rsa", "key_bits":2048
            }),
        )?
        .ok_or_else(not_found)?;
    assert_eq!(response.status, 200);
    ca.put_role(
        "operators",
        &json!({
            "key_type":"ca", "allow_user_certificates":true,
            "allowed_users":"alice", "default_user":"alice", "ttl":"90s",
            "algorithm_signer":algorithm, "key_id_format":"actual-original"
        }),
    )?;
    ca.validate()?;
    Ok(ca)
}
fn wire_string(out: &mut Vec<u8>, bytes: &[u8]) -> TestResult {
    out.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn public_line(algorithm: &str, data: &[u8]) -> TestResult<String> {
    let mut bytes = Vec::new();
    wire_string(&mut bytes, algorithm.as_bytes())?;
    wire_string(&mut bytes, data)?;
    Ok(format!("{algorithm} {}", STANDARD.encode(bytes)))
}
fn reject_both_without_mutation(
    normal: &mut CaState,
    legacy: &mut CaState,
    line: &str,
    status: u16,
) -> TestResult {
    let before_normal = zeroize::Zeroizing::new(serde_json::to_vec(normal)?);
    let before_legacy = zeroize::Zeroizing::new(serde_json::to_vec(legacy)?);
    let body = json!({"public_key":line});
    assert_eq!(
        normal
            .sign(&body, &context(), false)
            .err()
            .ok_or("normal must reject")?
            .status,
        status
    );
    assert_eq!(
        legacy
            .sign_authenticated(
                &body,
                &context(),
                false,
                &super::super::ssh_templates::RequestIdentity::absent()
            )
            .err()
            .ok_or("legacy must reject")?
            .status,
        status
    );
    // Avoid printing private issuer material on a failed byte equality assertion.
    assert!(
        zeroize::Zeroizing::new(serde_json::to_vec(normal)?).as_slice() == before_normal.as_slice()
    );
    assert!(
        zeroize::Zeroizing::new(serde_json::to_vec(legacy)?).as_slice() == before_legacy.as_slice()
    );
    normal.validate()?;
    legacy.validate()?;
    Ok(())
}

#[test]
fn ssh115_unknown_opaque_public_key_is_rejected_before_normal_and_legacy_signing() -> TestResult {
    let mut normal = configured("rsa-sha2-256")?;
    let mut legacy = configured("ssh-rsa")?;
    for algorithm in [
        "ssh-future@heptabao.example",
        "ssh-another@heptabao.example",
    ] {
        let line = public_line(algorithm, &[0x42; 32])?;
        let parsed = PublicKey::from_openssh(&line)?;
        assert!(matches!(parsed.key_data(), KeyData::Other(_)));
        assert_eq!(parsed.algorithm().as_str(), algorithm);
        assert_eq!(parsed.to_openssh()?, line);
        reject_both_without_mutation(&mut normal, &mut legacy, &line, 400)?;
    }
    Ok(())
}

struct Wire<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Wire<'a> {
    fn take(&mut self, count: usize) -> TestResult<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or("wire overflow")?;
        let result = self.bytes.get(self.at..end).ok_or("wire truncated")?;
        self.at = end;
        Ok(result)
    }
    fn string(&mut self) -> TestResult<&'a [u8]> {
        let length = u32::from_be_bytes(self.take(4)?.try_into()?) as usize;
        self.take(length)
    }
}
// Independent public-key/TBS/SHA1 verification, without using the producer's parser.
fn verify_legacy(line: &str, subject: &PublicKey, issuer: &PublicKey) -> TestResult {
    let mut fields = line.split_whitespace();
    let tag = fields.next().ok_or("certificate tag")?;
    assert_eq!(tag, subject.algorithm().to_certificate_type());
    let raw = STANDARD.decode(fields.next().ok_or("certificate payload")?)?;
    assert!(fields.next().is_none());
    let mut input = Wire { bytes: &raw, at: 0 };
    assert_eq!(input.string()?, tag.as_bytes());
    assert_eq!(input.string()?.len(), 32);
    let subject_wire = subject.to_bytes()?;
    let mut original = Wire {
        bytes: &subject_wire,
        at: 0,
    };
    assert_eq!(original.string()?, subject.algorithm().as_str().as_bytes());
    assert_eq!(
        input.take(subject_wire.len() - original.at)?,
        &subject_wire[original.at..]
    );
    input.take(8)?; // serial
    assert_eq!(u32::from_be_bytes(input.take(4)?.try_into()?), 1);
    assert_eq!(input.string()?, b"actual-original");
    let principals = input.string()?;
    let mut principal_input = Wire {
        bytes: principals,
        at: 0,
    };
    assert_eq!(principal_input.string()?, b"alice");
    assert_eq!(principal_input.at, principals.len());
    assert_eq!(
        u64::from_be_bytes(input.take(8)?.try_into()?),
        context().now - 30
    );
    assert_eq!(
        u64::from_be_bytes(input.take(8)?.try_into()?),
        context().now + 90
    );
    input.string()?; // critical options: detailed original controls remain unchanged
    input.string()?; // extensions
    assert!(input.string()?.is_empty()); // reserved
    assert_eq!(input.string()?, issuer.to_bytes()?);
    let tbs = &raw[..input.at];
    let signature_blob = input.string()?;
    let mut signature_input = Wire {
        bytes: signature_blob,
        at: 0,
    };
    assert_eq!(signature_input.string()?, b"ssh-rsa");
    let signature = signature_input.string()?;
    assert_eq!(signature_input.at, signature_blob.len());
    assert_eq!(input.at, raw.len());
    let KeyData::Rsa(rsa) = issuer.key_data() else {
        return Err("actual issuer is not RSA".into());
    };
    let public = PKey::from_rsa(Rsa::from_public_components(
        BigNum::from_slice(rsa.n.as_positive_bytes().ok_or("issuer modulus")?)?,
        BigNum::from_slice(rsa.e.as_positive_bytes().ok_or("issuer exponent")?)?,
    )?)?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), &public)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    assert!(verifier.verify_oneshot(signature, tbs)?);
    let mut changed = tbs.to_vec();
    *changed.last_mut().ok_or("TBS byte")? ^= 1;
    assert!(!verifier.verify_oneshot(signature, &changed)?);
    Ok(())
}

#[test]
fn ssh115_all_eight_known_plain_key_algorithms_keep_real_normal_and_legacy_certificates()
-> TestResult {
    let mut normal = configured("rsa-sha2-256")?;
    let mut legacy = configured("ssh-rsa")?;
    let normal_issuer = PublicKey::from_openssh(normal.public_key("default")?)?;
    let legacy_issuer = PublicKey::from_openssh(legacy.public_key("default")?)?;
    let trust = normal_issuer.fingerprint(HashAlg::Sha256);
    for line in known_public_fixtures() {
        let public = PublicKey::from_openssh(line)?;
        assert!(!matches!(public.key_data(), KeyData::Other(_)));
        let body = json!({"public_key":line});
        let response = normal.sign(&body, &context(), false)?;
        assert_eq!(response.status, 200);
        assert!(response.mutated);
        let certificate = Certificate::from_openssh(
            response.body["data"]["signed_key"]
                .as_str()
                .ok_or("normal cert")?,
        )?;
        certificate.validate_at(context().now, [&trust])?;
        assert_eq!(certificate.public_key(), public.key_data());
        assert_eq!(certificate.signature().algorithm().as_str(), "rsa-sha2-256");
        let response = legacy.sign_authenticated(
            &body,
            &context(),
            false,
            &super::super::ssh_templates::RequestIdentity::absent(),
        )?;
        assert_eq!(response.status, 200);
        assert!(response.mutated);
        verify_legacy(
            response.body["data"]["signed_key"]
                .as_str()
                .ok_or("legacy cert")?,
            &public,
            &legacy_issuer,
        )?;
    }
    assert_eq!(normal.signatures, 8);
    assert_eq!(legacy.signatures, 8);
    normal.validate()?;
    legacy.validate()?;
    Ok(())
}

#[test]
fn ssh115_malformed_known_wire_and_expired_original_request_keep_both_entry_vetoes() -> TestResult {
    let mut normal = configured("rsa-sha2-256")?;
    let mut legacy = configured("ssh-rsa")?;
    let malformed = public_line("ssh-ed25519", &[0x13; 31])?;
    assert!(PublicKey::from_openssh(&malformed).is_err());
    reject_both_without_mutation(&mut normal, &mut legacy, &malformed, 400)?;
    let valid = known_public_fixtures()
        .into_iter()
        .find(|line| line.starts_with("ssh-ed25519 "))
        .ok_or("known ED fixture")?;
    // A text algorithm label is not an upstream rejection: validate a real binary tail instead.
    let mut trailing = PublicKey::from_openssh(valid)?.to_bytes()?;
    trailing.push(0x41);
    assert!(PublicKey::from_bytes(&trailing).is_err());
    let trailing = STANDARD.encode(trailing);
    reject_both_without_mutation(&mut normal, &mut legacy, &trailing, 400)?;
    let original = std::time::Instant::now() - std::time::Duration::from_millis(1);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(original);
    let _later = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + std::time::Duration::from_secs(15),
    );
    assert_eq!(crate::request_deadline::current(), Some(original));
    let opaque = public_line("ssh-future@heptabao.example", &[0x42; 32])?;
    reject_both_without_mutation(&mut normal, &mut legacy, &opaque, 503)?;
    reject_both_without_mutation(&mut normal, &mut legacy, valid, 503)?;
    Ok(())
}

// Exact public vectors from the pinned ssh-key 0.6.7 upstream tests; no private keys.
fn known_public_fixtures() -> [&'static str; 8] {
    [
        "ssh-dss AAAAB3NzaC1kc3MAAACBANw9iSUO2UYhFMssjUgW46URqv8bBrDgHeF8HLBOWBvKuXF2Rx2J/XyhgX48SOLMuv0hcPaejlyLarabnF9F2V4dkpPpZSJ+7luHmxEjNxwhsdtg8UteXAWkeCzrQ6MvRJZHcDBjYh56KGvslbFnJsGLXlI4PQCyl6awNImwYGilAAAAFQCJGBU3hZf+QtP9Jh/nbfNlhFu7hwAAAIBHObOQioQVRm3HsVb7mOy3FVKhcLoLO3qoG9gTkd4KeuehtFAC3+rckiX7xSCnE/5BBKdL7VP9WRXac2Nlr9Pwl3e7zPut96wrCHt/TZX6vkfXKkbpUIj5zSqfvyNrWKaYJkfzwAQwrXNS1Hol676Ud/DDEn2oatdEhkS3beWHXAAAAIBgQqaz/YYTRMshzMzYcZ4lqgvgmA55y6v0h39e8HH2A5dwNS6sPUw2jyna+le0dceNRJifFld1J+WYM0vmquSr11DDavgEidOSaXwfMvPPPJqLmbzdtT16N+Gij9U9STQTHPQcQ3xnNNHgQAStzZJbhLOVbDDDo5BO7LMUALDfSA==",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=",
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC5ugtxUB/EEoREXx8BbGZPDzrPbJfrmi6FpUCpP+TldmtNrVD6AFP8V1wjiHwn1hapt+tV1t5uUNBi4YZjZvNmwf/+TmbFdQ9NO+usuVrezPP+ICyQrPgtYr5bHWEHsQQ==",
        "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFhNpNPGSsj2WH79EyBhBZgAs6ix9GLIK0BjQRu8GjT6CUP1OnxfKZpOoVUwyaabZ9XYqL5osuHl9SyAd5CHT3MWAEDy5R6hYu3eD34Y/gpUdlvkaeSXX4rqtJuR+Py+lsHyCcoSKRCO3UNetK4tpLWbd7K7FOFCGsf0baCyikciNY3Yg==",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmjkeMm8k3JkNrf16eb5pG4bc77B6Mt3VN4saltsRV8vASpyWa/PlBgdaeldOaNJ5NK0gqU3KyiUNzHbdcc8572e7IUBDJS/rlaWARiSL4aos2VbNX0k56Z5zYp9m/bq5m9/mlb+PQkNBjIhimgpYNiq2TwBiYeA6tLb79cPtHA0cX5BLk/a5oUpLsiR4kI/f+Q98vVDKasKXXVh5YLkLobrruDB6er2A9fOcIUF0O4JCRLh/Dc161gE3fQrYTMQenbppZzfxrZfQ8YwLPvKjnqm+XRX+pbTtaJuj0EgTSzUK+EZxoSw8CNwiZpxrjwecTMVQ8w/srQmh4ABGuTqk0wP8HcI7hg+fpBv7kiejh5X/Oehxt+Puu85u9GVXb1a0av/vhJvUCBcuISvCA/z1wVJ0xdLhb1/ZiTDdTzyNbZQ0OQijzK+e1SlkNhp+3eGVZu3pNZvnTppwIXv3wg6kV1HodkWGgh1ayY7Buc52Z8okDYqvJat5CzOj5OaQNr/k=",
        "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBIELQJ2DgvaX1yQlKFokfWM2suuaCFI2qp0eJodHyg6O4ifxc3XpRKd1OS8dNYQtE/YjdXSrA+AOnMF5ns2Nkx4AAAAEc3NoOg==",
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAICFo/k5LU8863u66YC9eUO2170QduohPURkQnbLa/dczAAAABHNzaDo=",
    ]
}

#[test]
fn ssh115_primary_bare_base64_and_literal_space_payload_keep_both_real_signature_paths()
-> TestResult {
    let mut normal = configured("rsa-sha2-256")?;
    let mut legacy = configured("ssh-rsa")?;
    let normal_issuer = PublicKey::from_openssh(normal.public_key("default")?)?;
    let legacy_issuer = PublicKey::from_openssh(legacy.public_key("default")?)?;
    let trust = normal_issuer.fingerprint(HashAlg::Sha256);
    let mut count = 0;
    for line in known_public_fixtures() {
        let public = PublicKey::from_openssh(line)?;
        let payload = line.split(' ').nth(1).ok_or("public payload")?;
        let split = payload.len() / 2;
        let mut forms = vec![
            payload.to_owned(),
            format!("ignored-tag {payload} public-comment"),
            format!(" {payload}"),
            format!("{}\r\n{}", &payload[..split], &payload[split..]),
        ];
        if payload.ends_with('=') {
            let mut unusual = payload.as_bytes().to_vec();
            let at = payload.trim_end_matches('=').len() - 1;
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let digit = alphabet
                .iter()
                .position(|byte| *byte == unusual[at])
                .ok_or("base64 digit")?;
            unusual[at] = alphabet[digit | 1];
            forms.push(String::from_utf8(unusual)?);
        }
        for text in forms {
            assert_eq!(signing_public_key(&text)?.key_data(), public.key_data());
            let response = normal.sign(&json!({"public_key":text}), &context(), false)?;
            assert_eq!(response.status, 200);
            let certificate = Certificate::from_openssh(
                response.body["data"]["signed_key"]
                    .as_str()
                    .ok_or("normal cert")?,
            )?;
            certificate.validate_at(context().now, [&trust])?;
            assert_eq!(certificate.public_key(), public.key_data());
            assert_eq!(certificate.signature().algorithm().as_str(), "rsa-sha2-256");
            let response = legacy.sign_authenticated(
                &json!({"public_key":text}),
                &context(),
                false,
                &super::super::ssh_templates::RequestIdentity::absent(),
            )?;
            assert_eq!(response.status, 200);
            verify_legacy(
                response.body["data"]["signed_key"]
                    .as_str()
                    .ok_or("legacy cert")?,
                &public,
                &legacy_issuer,
            )?;
            count += 1;
        }
    }
    assert_eq!(normal.signatures, count);
    assert_eq!(legacy.signatures, count);
    normal.validate()?;
    legacy.validate()?;
    Ok(())
}

#[test]
fn ssh115_primary_bare_issuer_import_keeps_real_private_public_pair_and_duplicate_identity()
-> TestResult {
    let material = crypto_key::generate("rsa", 2048)?;
    let public = material.public()?;
    let payload = STANDARD.encode(public.to_bytes()?);
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&material)?);
    let private = zeroize::Zeroizing::new(serde_json::from_slice::<String>(&encoded)?);
    let mut ca = CaState::default();
    let mut id = None;
    for text in [
        payload.clone(),
        format!("ignored-tag {payload} comment"),
        format!("{payload}\r\n"),
    ] {
        let before = zeroize::Zeroizing::new(serde_json::to_vec(&ca)?);
        let mut body =
            json!({"generate_signing_key":false,"private_key":private.as_str(),"public_key":text});
        let response = ca.handle_admin("POST", "config/ca", &body);
        if let Some(Value::String(value)) = body.get_mut("private_key") {
            zeroize::Zeroize::zeroize(value);
        }
        let response = response?.ok_or("issuer response")?;
        assert_eq!(response.status, 200);
        let actual_id = response.body["data"]["issuer_id"]
            .as_str()
            .ok_or("issuer id")?
            .to_owned();
        if let Some(ref original) = id {
            assert_eq!(&actual_id, original);
            assert!(!response.mutated);
            assert!(
                zeroize::Zeroizing::new(serde_json::to_vec(&ca)?).as_slice() == before.as_slice()
            );
        } else {
            assert!(response.mutated);
            id = Some(actual_id);
        }
        assert_eq!(
            PublicKey::from_openssh(ca.public_key("default")?)?.key_data(),
            public.key_data()
        );
        assert_eq!(ca.issuers.len(), 1);
        ca.validate()?;
    }
    let before = zeroize::Zeroizing::new(serde_json::to_vec(&ca)?);
    let unrelated = known_public_fixtures()
        .into_iter()
        .find(|line| line.starts_with("ssh-ed25519 "))
        .ok_or("ED fixture")?;
    let mut body = json!({"generate_signing_key":false,"private_key":private.as_str(),"public_key":unrelated.split(' ').nth(1).ok_or("ED payload")?});
    let response = ca.handle_admin("POST", "config/ca", &body);
    if let Some(Value::String(value)) = body.get_mut("private_key") {
        zeroize::Zeroize::zeroize(value);
    }
    assert_eq!(
        response.err().ok_or("pair mismatch must reject")?.status,
        400
    );
    assert!(zeroize::Zeroizing::new(serde_json::to_vec(&ca)?).as_slice() == before.as_slice());
    ca.validate()?;
    Ok(())
}

#[test]
fn ssh115_primary_base64_decoder_still_rejects_binary_tail_unknown_overlong_and_original_expiry()
-> TestResult {
    let mut normal = configured("rsa-sha2-256")?;
    let mut legacy = configured("ssh-rsa")?;
    let line = known_public_fixtures()
        .into_iter()
        .find(|line| line.starts_with("ecdsa-sha2-nistp256 "))
        .ok_or("EC fixture")?;
    let payload = line.split(' ').nth(1).ok_or("EC payload")?;
    let mut trailing = PublicKey::from_openssh(line)?.to_bytes()?;
    trailing.push(0x41);
    for input in [
        format!("ssh-ecdsa  {payload}"),
        format!("ssh-ecdsa\t{payload}"),
        format!("  {payload}"),
        payload.trim_end_matches('=').to_owned(),
        format!("{payload}#"),
        STANDARD.encode(trailing),
        "A".repeat(16385),
        public_line("ssh-future@heptabao.example", &[0x42; 32])?
            .split(' ')
            .nth(1)
            .ok_or("opaque payload")?
            .to_owned(),
    ] {
        reject_both_without_mutation(&mut normal, &mut legacy, &input, 400)?;
    }
    let original = std::time::Instant::now() - std::time::Duration::from_millis(1);
    let _original = crate::request_deadline::RequestDeadlineScope::enter(original);
    let _later = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + std::time::Duration::from_secs(15),
    );
    assert_eq!(crate::request_deadline::current(), Some(original));
    reject_both_without_mutation(&mut normal, &mut legacy, payload, 503)?;
    Ok(())
}
