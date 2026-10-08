//! Private explicit ssh-rsa certificate wire producer. No authority is created here.
use super::{Result, bad, error, ssh_ca_crypto::PrivateMaterial, ssh_ca_policy::SigningPolicy};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey},
    rsa::Padding,
    sign::{Signer, Verifier},
};
use ssh_key::PublicKey;
use std::collections::BTreeMap;

const MAX_CERT_BYTES: usize = 16 * 1024 * 1024;
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if out
        .len()
        .checked_add(bytes.len())
        .filter(|n| *n <= MAX_CERT_BYTES)
        .is_none()
    {
        return Err(bad("SSH certificate exceeds the wire bound"));
    }
    out.extend_from_slice(bytes);
    Ok(())
}
fn string(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| bad("SSH wire string overflow"))?;
    append(out, &len.to_be_bytes())?;
    append(out, value)
}
fn options(values: &BTreeMap<String, String>) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for (name, value) in values {
        string(&mut result, name.as_bytes())?;
        if value.is_empty() {
            string(&mut result, &[])?;
        } else {
            let mut nested = Vec::new();
            string(&mut nested, value.as_bytes())?;
            string(&mut result, &nested)?;
        }
    }
    Ok(result)
}
pub(super) fn sign(
    material: &PrivateMaterial,
    subject: &PublicKey,
    policy: &SigningPolicy,
    serial: u64,
    nonce: &[u8],
) -> Result<String> {
    if policy.algorithm_signer != "ssh-rsa" || nonce.len() != 32 {
        return Err(bad("invalid SSH legacy signing inputs"));
    }
    super::ssh_ca_crypto::deadline()?;
    let key = material.key()?;
    if key.id() != Id::RSA {
        return Err(error(
            500,
            "SSH signing algorithm does not match issuer key",
        ));
    }
    let issuer = material.public()?;
    let issuer_blob = issuer
        .to_bytes()
        .map_err(|_| bad("invalid SSH issuer wire key"))?;
    let subject_blob = subject
        .to_bytes()
        .map_err(|_| bad("invalid SSH subject wire key"))?;
    let mut cursor = subject_blob.as_slice();
    let subject_algorithm = read_string(&mut cursor)?;
    if subject_algorithm != subject.algorithm().as_str().as_bytes() || cursor.is_empty() {
        return Err(bad("SSH subject wire algorithm mismatch"));
    }
    let cert_algorithm = subject.algorithm().to_certificate_type();
    let mut tbs = Vec::new();
    string(&mut tbs, cert_algorithm.as_bytes())?;
    string(&mut tbs, nonce)?;
    append(&mut tbs, cursor)?;
    append(&mut tbs, &serial.to_be_bytes())?;
    let kind = match policy.kind {
        ssh_key::certificate::CertType::User => 1u32,
        ssh_key::certificate::CertType::Host => 2u32,
    };
    append(&mut tbs, &kind.to_be_bytes())?;
    string(&mut tbs, policy.key_id.as_bytes())?;
    let mut principals = Vec::new();
    for principal in &policy.principals {
        string(&mut principals, principal.as_bytes())?;
    }
    string(&mut tbs, &principals)?;
    append(&mut tbs, &policy.valid_after.to_be_bytes())?;
    append(&mut tbs, &policy.valid_before.to_be_bytes())?;
    string(&mut tbs, &options(&policy.critical_options)?)?;
    string(&mut tbs, &options(&policy.extensions)?)?;
    string(&mut tbs, &[])?;
    string(&mut tbs, &issuer_blob)?;

    // Actual PKCS1v15 SHA1 signature over the exact certificate TBS.
    let mut signer = Signer::new(MessageDigest::sha1(), &key)
        .map_err(|_| error(503, "SSH legacy signing unavailable"))?;
    signer
        .set_rsa_padding(Padding::PKCS1)
        .map_err(|_| error(503, "SSH legacy signing unavailable"))?;
    let signature = signer
        .sign_oneshot_to_vec(&tbs)
        .map_err(|_| error(503, "SSH legacy signing failed"))?;
    if signature.len() != key.rsa().map_err(|_| bad("invalid SSH RSA issuer"))?.size() as usize {
        return Err(error(503, "SSH legacy signature length mismatch"));
    }
    let public = PKey::public_key_from_der(
        &key.public_key_to_der()
            .map_err(|_| error(503, "SSH legacy public key unavailable"))?,
    )
    .map_err(|_| error(503, "SSH legacy public key unavailable"))?;
    let mut verifier = Verifier::new(MessageDigest::sha1(), &public)
        .map_err(|_| error(503, "SSH legacy verification unavailable"))?;
    verifier
        .set_rsa_padding(Padding::PKCS1)
        .map_err(|_| error(503, "SSH legacy verification unavailable"))?;
    if !verifier
        .verify_oneshot(&signature, &tbs)
        .map_err(|_| error(503, "SSH legacy verification failed"))?
    {
        return Err(error(503, "SSH legacy verification failed"));
    }
    let mut signature_blob = Vec::new();
    string(&mut signature_blob, b"ssh-rsa")?;
    string(&mut signature_blob, &signature)?;
    let mut wire = tbs;
    string(&mut wire, &signature_blob)?;
    super::ssh_ca_crypto::deadline()?;
    Ok(format!("{} {}", cert_algorithm, STANDARD.encode(wire)))
}
fn read_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let header: [u8; 4] = input
        .get(..4)
        .ok_or_else(|| bad("truncated SSH wire"))?
        .try_into()
        .map_err(|_| bad("truncated SSH wire"))?;
    let length = u32::from_be_bytes(header) as usize;
    let end = 4usize
        .checked_add(length)
        .ok_or_else(|| bad("SSH wire length overflow"))?;
    let value = input.get(4..end).ok_or_else(|| bad("truncated SSH wire"))?;
    *input = &input[end..];
    Ok(value)
}
#[cfg(test)]
#[path = "ssh_ca_legacy_tests.rs"]
mod tests;
