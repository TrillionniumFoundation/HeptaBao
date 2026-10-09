//! Canonical standard asymmetric imports; providers own key arithmetic.
use super::*;
use ml_dsa::pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
    der::{Decode, Encode},
};
use openssl::{
    nid::Nid,
    pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public},
};

const MAX_DER_BYTES: usize = 8192;

pub(super) fn is_kind(kind: &str) -> bool {
    asymmetric::is_kind(kind) || kind == "ed25519"
}

fn invalid() -> EngineError {
    bad("invalid standard asymmetric key material")
}

fn algorithm(kind: &str, value: &AlgorithmIdentifierRef<'_>) -> Result<()> {
    let (oid, curve) = match kind {
        "rsa-2048" | "rsa-3072" | "rsa-4096" => ("1.2.840.113549.1.1.1", None),
        "ecdsa-p256" => ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7")),
        "ecdsa-p384" => ("1.2.840.10045.2.1", Some("1.3.132.0.34")),
        "ecdsa-p521" => ("1.2.840.10045.2.1", Some("1.3.132.0.35")),
        "ed25519" => ("1.3.101.112", None),
        _ => return Err(invalid()),
    };
    if value.oid != ObjectIdentifier::new(oid).map_err(|_| invalid())? {
        return Err(invalid());
    }
    if let Some(curve) = curve {
        let expected = ObjectIdentifier::new(curve).map_err(|_| invalid())?;
        if value.parameters.ok_or_else(invalid)?
            .decode_as::<ObjectIdentifier>().map_err(|_| invalid())? != expected {
            return Err(invalid());
        }
    } else if asymmetric::is_rsa(kind) {
        if value.parameters.ok_or_else(invalid)?.to_der().map_err(|_| invalid())? != [5, 0] {
            return Err(invalid());
        }
    } else if value.parameters.is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn family<T: HasPublic>(kind: &str, pair: &PKeyRef<T>) -> Result<()> {
    if asymmetric::is_rsa(kind) {
        let bits = match kind { "rsa-2048" => 2048, "rsa-3072" => 3072, _ => 4096 };
        if pair.id() != Id::RSA || pair.bits() != bits {
            return Err(invalid());
        }
        let rsa = pair.rsa().map_err(|_| invalid())?;
        if rsa.n().is_negative() || rsa.e().is_negative()
            || !rsa.n().is_bit_set(0) || !rsa.e().is_bit_set(0) || rsa.e().num_bits() < 2
            || rsa.e().ucmp(rsa.n()) != std::cmp::Ordering::Less {
            return Err(invalid());
        }
    } else if kind == "ed25519" {
        if pair.id() != Id::ED25519 || pair.raw_public_key().map_err(|_| invalid())?.len() != 32 {
            return Err(invalid());
        }
    } else {
        let curve = match kind {
            "ecdsa-p256" => Nid::X9_62_PRIME256V1,
            "ecdsa-p384" => Nid::SECP384R1,
            "ecdsa-p521" => Nid::SECP521R1,
            _ => return Err(invalid()),
        };
        if pair.id() != Id::EC {
            return Err(invalid());
        }
        let ec = pair.ec_key().map_err(|_| invalid())?;
        if ec.group().curve_name() != Some(curve) {
            return Err(invalid());
        }
        ec.check_key().map_err(|_| invalid())?;
    }
    Ok(())
}

fn private_pair(kind: &str, material: &[u8]) -> Result<PKey<Private>> {
    if material.is_empty() || material.len() > MAX_DER_BYTES {
        return Err(invalid());
    }
    let pair = PKey::private_key_from_der(material).map_err(|_| invalid())?;
    family(kind, &pair)?;
    if asymmetric::is_rsa(kind) && !pair.rsa().map_err(|_| invalid())?
        .check_key().map_err(|_| invalid())? {
        return Err(invalid());
    }
    if kind == "ed25519" {
        let original = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(material)
            .map_err(|_| invalid())?;
        if original.public_key().as_ref() != pair.raw_public_key().map_err(|_| invalid())? {
            return Err(invalid());
        }
    }
    Ok(pair)
}

pub(super) fn import_private(kind: &str, material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if material.is_empty() || material.len() > MAX_DER_BYTES {
        return Err(invalid());
    }
    let info = PrivateKeyInfoRef::from_der(material).map_err(|_| invalid())?;
    algorithm(kind, &info.algorithm)?;
    let pair = PKey::private_key_from_pkcs8(material).map_err(|_| invalid())?;
    family(kind, &pair)?;
    let canonical = Zeroizing::new(pair.private_key_to_pkcs8().map_err(|_| invalid())?);
    if canonical.len() != material.len() || !openssl::memcmp::eq(canonical.as_slice(), material) {
        return Err(invalid());
    }
    private_pair(kind, &canonical)?;
    Ok(canonical)
}

pub(super) fn validate_private(kind: &str, material: &[u8]) -> Result<()> {
    private_pair(kind, material).map(|_| ())
}

pub(super) fn private_public_der(kind: &str, material: &[u8]) -> Result<Vec<u8>> {
    private_pair(kind, material)?.public_key_to_der().map_err(|_| invalid())
}

pub(super) fn ed25519_pair(material: &[u8]) -> Result<signature::Ed25519KeyPair> {
    private_pair("ed25519", material)?;
    signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(material).map_err(|_| invalid())
}

pub(super) fn public_pair(kind: &str, der: &[u8]) -> Result<PKey<Public>> {
    if der.is_empty() || der.len() > MAX_DER_BYTES {
        return Err(invalid());
    }
    let info = SubjectPublicKeyInfoRef::from_der(der).map_err(|_| invalid())?;
    algorithm(kind, &info.algorithm)?;
    if info.subject_public_key.as_bytes().is_none() {
        return Err(invalid());
    }
    let pair = PKey::public_key_from_der(der).map_err(|_| invalid())?;
    family(kind, &pair)?;
    if pair.public_key_to_der().map_err(|_| invalid())? != der {
        return Err(invalid());
    }
    Ok(pair)
}

pub(super) fn import_public_pem(kind: &str, text: &str) -> Result<Vec<u8>> {
    if text.len() > 12_000 {
        return Err(invalid());
    }
    let body = text.trim().strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|body| body.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(invalid)?;
    let encoded: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = BASE64.decode(encoded).map_err(|_| invalid())?;
    public_pair(kind, &der)?;
    Ok(der)
}

pub(super) fn validate_public(kind: &str, der: &[u8]) -> Result<()> {
    public_pair(kind, der).map(|_| ())
}

pub(super) fn descriptor_public(kind: &str, der: &[u8]) -> Result<String> {
    let pair = public_pair(kind, der)?;
    if kind == "ed25519" {
        Ok(BASE64.encode(pair.raw_public_key().map_err(|_| invalid())?))
    } else {
        String::from_utf8(pair.public_key_to_pem().map_err(|_| invalid())?)
            .map_err(|_| invalid())
    }
}

pub(super) fn export_public(kind: &str, der: &[u8], format: &str) -> Result<String> {
    let pair = public_pair(kind, der)?;
    if format == "der" {
        return Ok(BASE64.encode(der));
    }
    if kind == "ed25519" && matches!(format, "" | "raw") {
        return Ok(BASE64.encode(pair.raw_public_key().map_err(|_| invalid())?));
    }
    if !matches!(format, "" | "pem") {
        return Err(bad("unsupported standard asymmetric public export format"));
    }
    let pem = String::from_utf8(pair.public_key_to_pem().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    Ok(if asymmetric::is_rsa(kind) { pem } else { pem.trim_end_matches('\n').to_owned() })
}

#[cfg(test)]
#[path = "transit_asymmetric_byok_tests.rs"]
mod tests;
