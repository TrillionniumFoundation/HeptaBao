//! Native EC/RSA operations through the maintained, locked AWS-LC provider.
//! This module handles API encodings; all cryptographic primitives, entropy,
//! padding and private-key arithmetic are owned by the provider.
use super::*;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    encrypt::{Decrypter, Encrypter},
    hash::{MessageDigest, hash},
    md::{Md, MdRef},
    nid::Nid,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::RsaPssSaltlen,
};

pub(super) fn is_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" | "rsa-2048" | "rsa-3072" | "rsa-4096"
    )
}

pub(super) fn is_rsa(kind: &str) -> bool {
    matches!(kind, "rsa-2048" | "rsa-3072" | "rsa-4096")
}

fn provider_failure(_: openssl::error::ErrorStack) -> EngineError {
    error(500, "asymmetric cryptographic operation failed")
}

pub(super) fn selected_signing_version(key: &Key, body: &Value) -> Result<u64> {
    key.alive()?;
    let number = optional_u64(body, "key_version")?
        .filter(|number| *number != 0)
        .unwrap_or(key.latest_version);
    if number < key.min_encryption_version.max(1) || !key.versions.contains_key(&number) {
        return Err(error(
            500,
            "signing key version is unavailable or disallowed",
        ));
    }
    Ok(number)
}

fn private(material: &[u8]) -> Result<PKey<Private>> {
    PKey::private_key_from_der(material).map_err(|_| error(500, "stored asymmetric key is invalid"))
}

pub(super) fn generate(kind: &str) -> Result<Zeroizing<Vec<u8>>> {
    let pair = if is_rsa(kind) {
        let bits = match kind {
            "rsa-2048" => 2048,
            "rsa-3072" => 3072,
            _ => 4096,
        };
        PKey::from_rsa(Rsa::generate(bits).map_err(provider_failure)?)
    } else {
        let curve = match kind {
            "ecdsa-p256" => Nid::X9_62_PRIME256V1,
            "ecdsa-p384" => Nid::SECP384R1,
            "ecdsa-p521" => Nid::SECP521R1,
            _ => return Err(bad("unsupported asymmetric key type")),
        };
        let group = EcGroup::from_curve_name(curve).map_err(provider_failure)?;
        PKey::from_ec_key(EcKey::generate(&group).map_err(provider_failure)?)
    }
    .map_err(provider_failure)?;
    pair.private_key_to_pkcs8()
        .map(Zeroizing::new)
        .map_err(provider_failure)
}

pub(super) fn public(material: &[u8]) -> Result<String> {
    let pem = private(material)?
        .public_key_to_pem()
        .map_err(provider_failure)?;
    String::from_utf8(pem).map_err(|_| error(500, "public key encoding failed"))
}

pub(super) fn export(kind: &str, material: &[u8], public_key: bool) -> Result<Zeroizing<String>> {
    if public_key {
        return public(material).map(Zeroizing::new);
    }
    let pair = private(material)?;
    let pem = if is_rsa(kind) {
        pair.rsa().map_err(provider_failure)?.private_key_to_pem()
    } else {
        pair.ec_key()
            .map_err(provider_failure)?
            .private_key_to_pem()
    }
    .map(Zeroizing::new)
    .map_err(provider_failure)?;
    // Keep both the temporary PEM bytes and the returned private string scoped
    // to their existing zeroizing owners.
    String::from_utf8(pem.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| error(500, "private key encoding failed"))
}

fn algorithm<'a>(path: &'a str, body: &'a Value) -> Result<&'a str> {
    if !path.is_empty() {
        return Ok(path);
    }
    match body.get("hash_algorithm") {
        None | Some(Value::Null) => Ok("sha2-256"),
        Some(Value::String(value)) if value.is_empty() => Ok("sha2-256"),
        Some(Value::String(value)) => Ok(value),
        _ => Err(bad("algorithm must be a string")),
    }
}

fn digest_algorithm(name: &str) -> Result<(&'static MdRef, MessageDigest)> {
    match name {
        "sha1" => Ok((Md::sha1(), MessageDigest::sha1())),
        "sha2-224" => Ok((Md::sha224(), MessageDigest::sha224())),
        "sha2-256" => Ok((Md::sha256(), MessageDigest::sha256())),
        "sha2-384" => Ok((Md::sha384(), MessageDigest::sha384())),
        "sha2-512" => Ok((Md::sha512(), MessageDigest::sha512())),
        "sha3-224" => Ok((
            Md::from_nid(Nid::SHA3_224)
                .ok_or_else(|| error(503, "provider digest algorithm is unavailable"))?,
            MessageDigest::sha3_224(),
        )),
        "sha3-256" => Ok((
            Md::from_nid(Nid::SHA3_256)
                .ok_or_else(|| error(503, "provider digest algorithm is unavailable"))?,
            MessageDigest::sha3_256(),
        )),
        "sha3-384" => Ok((
            Md::from_nid(Nid::SHA3_384)
                .ok_or_else(|| error(503, "provider digest algorithm is unavailable"))?,
            MessageDigest::sha3_384(),
        )),
        "sha3-512" => Ok((
            Md::from_nid(Nid::SHA3_512)
                .ok_or_else(|| error(503, "provider digest algorithm is unavailable"))?,
            MessageDigest::sha3_512(),
        )),
        _ => Err(bad("unsupported hash algorithm")),
    }
}

fn salt_length(
    body: &Value,
    size: usize,
    digest_size: usize,
    signing: bool,
) -> Result<RsaPssSaltlen> {
    validate_signing_salt_length(body)?;
    let salt = match body.get("salt_length") {
        None => 0,
        Some(Value::String(value)) if value.eq_ignore_ascii_case("auto") => 0,
        Some(Value::String(value)) if value.eq_ignore_ascii_case("hash") => -1,
        Some(Value::String(value)) => value
            .parse::<i64>()
            .map_err(|_| bad("invalid signature salt length"))?,
        Some(Value::Number(value)) => value
            .as_i64()
            .ok_or_else(|| bad("invalid signature salt length"))?,
        Some(Value::Bool(value)) => i64::from(*value),
        _ => return Err(bad("invalid signature salt length")),
    };
    if salt > 0
        && usize::try_from(salt).map_or(true, |salt| salt > size.saturating_sub(digest_size + 2))
    {
        return Err(error(
            if signing { 500 } else { 400 },
            "signature salt length exceeds the key size",
        ));
    }
    match salt {
        0 => Ok(RsaPssSaltlen::MAXIMUM_LENGTH),
        -1 => Ok(RsaPssSaltlen::DIGEST_LENGTH),
        value => i32::try_from(value)
            .map(RsaPssSaltlen::custom)
            .map_err(|_| bad("invalid signature salt length")),
    }
}

struct SigningInput {
    md: Option<&'static MdRef>,
    digest: Zeroizing<Vec<u8>>,
    padding: Padding,
}

fn signing_input(kind: &str, body: &Value, path: &str, input: &[u8]) -> Result<SigningInput> {
    signature_encoding(body)?;
    validate_signing_salt_length(body)?;
    if body
        .get("signature_algorithm")
        .is_some_and(|value| value.is_array() || value.is_object())
    {
        return Err(bad("signature algorithm must be a scalar"));
    }
    let name = algorithm(path, body)?;
    let prehashed = signing_prehashed(body)?;
    if name == "none" {
        if !prehashed || body.get("signature_algorithm").and_then(Value::as_str) != Some("pkcs1v15")
        {
            return Err(bad("hash none requires prehashed PKCS1v15 signing"));
        }
        return Ok(SigningInput {
            md: None,
            digest: Zeroizing::new(input.to_vec()),
            padding: Padding::PKCS1,
        });
    }
    let padding = if is_rsa(kind) {
        match body.get("signature_algorithm") {
            None | Some(Value::Null) => Padding::PKCS1_PSS,
            Some(Value::String(value)) if value.is_empty() || value == "pss" => Padding::PKCS1_PSS,
            Some(Value::String(value)) if value == "pkcs1v15" => Padding::PKCS1,
            _ => return Err(error(500, "unsupported RSA signature algorithm")),
        }
    } else {
        Padding::PKCS1
    };
    let (md, message_digest) = digest_algorithm(name)?;
    let digest = if prehashed {
        Zeroizing::new(input.to_vec())
    } else {
        Zeroizing::new(
            hash(message_digest, input)
                .map_err(provider_failure)?
                .to_vec(),
        )
    };
    Ok(SigningInput {
        md: Some(md),
        digest,
        padding,
    })
}

fn jws_width(kind: &str) -> Result<usize> {
    match kind {
        "ecdsa-p256" => Ok(32),
        "ecdsa-p384" => Ok(48),
        "ecdsa-p521" => Ok(66),
        _ => Err(bad("unsupported ECDSA key type")),
    }
}

pub(super) fn sign(
    kind: &str,
    material: &[u8],
    body: &Value,
    path: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let SigningInput {
        md,
        digest,
        padding,
    } = signing_input(kind, body, path, input)?;
    let pair = private(material)?;
    if !is_rsa(kind) {
        if digest.is_empty() {
            return Err(error(500, "cannot sign an empty ECDSA digest"));
        }
        let ec_key = pair.ec_key().map_err(provider_failure)?;
        let signature = EcdsaSig::sign(&digest, &ec_key).map_err(provider_failure)?;
        if body.get("marshaling_algorithm").and_then(Value::as_str) == Some("jws") {
            let width = i32::try_from(jws_width(kind)?)
                .map_err(|_| error(500, "signature width is invalid"))?;
            let mut encoded = signature
                .r()
                .to_vec_padded(width)
                .map_err(provider_failure)?;
            encoded.extend_from_slice(
                &signature
                    .s()
                    .to_vec_padded(width)
                    .map_err(provider_failure)?,
            );
            return Ok(encoded);
        }
        return signature.to_der().map_err(provider_failure);
    }
    let mut ctx = PkeyCtx::new(&pair).map_err(provider_failure)?;
    ctx.sign_init().map_err(provider_failure)?;
    ctx.set_rsa_padding(padding).map_err(provider_failure)?;
    if let Some(md) = md {
        ctx.set_signature_md(md).map_err(provider_failure)?;
    }
    if padding == Padding::PKCS1_PSS {
        ctx.set_rsa_pss_saltlen(salt_length(
            body,
            pair.size(),
            md.map_or(0, |md| md.size()),
            true,
        )?)
        .map_err(provider_failure)?;
        if let Some(md) = md {
            ctx.set_rsa_mgf1_md(md).map_err(provider_failure)?;
        }
    }
    let mut signature = Vec::new();
    ctx.sign_to_vec(&digest, &mut signature)
        .map_err(provider_failure)?;
    Ok(signature)
}

pub(super) fn verify(
    kind: &str,
    material: &[u8],
    body: &Value,
    path: &str,
    input: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let SigningInput {
        md,
        digest,
        padding,
    } = signing_input(kind, body, path, input)?;
    let pair = private(material)?;
    if !is_rsa(kind) {
        let signature = if body.get("marshaling_algorithm").and_then(Value::as_str) == Some("jws") {
            let width = jws_width(kind)?;
            if signature.len() != width * 2 {
                return Ok(false);
            }
            EcdsaSig::from_private_components(
                BigNum::from_slice(&signature[..width]).map_err(provider_failure)?,
                BigNum::from_slice(&signature[width..]).map_err(provider_failure)?,
            )
            .map_err(provider_failure)?
        } else {
            match EcdsaSig::from_der(signature) {
                Ok(signature) => signature,
                Err(_) => return Err(bad("invalid ASN1 ECDSA signature")),
            }
        };
        let ec_key = pair.ec_key().map_err(provider_failure)?;
        return Ok(signature.verify(&digest, &ec_key).unwrap_or(false));
    }
    let mut ctx = PkeyCtx::new(&pair).map_err(provider_failure)?;
    ctx.verify_init().map_err(provider_failure)?;
    ctx.set_rsa_padding(padding).map_err(provider_failure)?;
    if let Some(md) = md {
        ctx.set_signature_md(md).map_err(provider_failure)?;
    }
    if padding == Padding::PKCS1_PSS {
        ctx.set_rsa_pss_saltlen(salt_length(
            body,
            pair.size(),
            md.map_or(0, |md| md.size()),
            false,
        )?)
        .map_err(provider_failure)?;
        if let Some(md) = md {
            ctx.set_rsa_mgf1_md(md).map_err(provider_failure)?;
        }
    }
    // An invalid signature is a normal negative predicate. Provider failures
    // on the signature bytes must not expose its diagnostic error stack.
    Ok(ctx.verify(&digest, signature).unwrap_or(false))
}

pub(super) fn encrypt(material: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let pair = private(material)?;
    let mut ctx = Encrypter::new(&pair).map_err(provider_failure)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(provider_failure)?;
    ctx.set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(provider_failure)?;
    ctx.set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(provider_failure)?;
    let size = pair.size();
    if plaintext.len() > size.saturating_sub(2 * 32 + 2) {
        return Err(error(500, "plaintext is too long for RSA-OAEP"));
    }
    let mut ciphertext = vec![0; ctx.encrypt_len(plaintext).map_err(provider_failure)?];
    let length = ctx
        .encrypt(plaintext, &mut ciphertext)
        .map_err(provider_failure)?;
    ciphertext.truncate(length);
    Ok(ciphertext)
}

pub(super) fn decrypt(material: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let pair = private(material)?;
    if ciphertext.len() != pair.size() {
        return Err(error(500, "invalid RSA ciphertext length"));
    }
    let mut ctx = Decrypter::new(&pair).map_err(provider_failure)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(provider_failure)?;
    ctx.set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(provider_failure)?;
    ctx.set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(provider_failure)?;
    let mut plaintext = Zeroizing::new(vec![
        0;
        ctx.decrypt_len(ciphertext)
            .map_err(provider_failure)?
    ]);
    let length = ctx
        .decrypt(ciphertext, &mut plaintext)
        .map_err(|_| error(500, "ciphertext authentication failed"))?;
    plaintext.truncate(length);
    Ok(plaintext)
}
