//! FIPS 204 through RustCrypto's pinned implementation, not a second key owner.
//! Persist only the 32-byte seed in the existing encrypted Transit version.
use super::*;
use ml_dsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, der::AnyRef,
    spki::AssociatedAlgorithmIdentifier,
};
use ml_dsa::{Keypair as _, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey};

pub(super) fn is_kind(kind: &str) -> bool {
    matches!(kind, "mldsa-44" | "mldsa-65" | "mldsa-87")
}

fn signing_key<P: MlDsaParams>(material: &[u8]) -> Result<SigningKey<P>> {
    let seed = Zeroizing::new(
        Seed::try_from(material).map_err(|_| error(500, "stored ML-DSA seed is invalid"))?,
    );
    Ok(SigningKey::<P>::from_seed(&seed))
}

fn public_for<P: MlDsaParams>(material: &[u8]) -> Result<Vec<u8>> {
    Ok(signing_key::<P>(material)?
        .verifying_key()
        .encode()
        .to_vec())
}

fn sign_for<P: MlDsaParams>(material: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let pair = signing_key::<P>(material)?;
    let signature = pair
        .expanded_key()
        .sign_randomized(input, b"", &mut getrandom::SysRng)
        .map_err(|_| error(503, "ML-DSA signing entropy is unavailable"))?;
    Ok(signature.encode().to_vec())
}

fn verify_for<P: MlDsaParams>(material: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    let pair = signing_key::<P>(material)?;
    let Ok(signature) = ml_dsa::Signature::<P>::try_from(bytes) else {
        return Ok(false);
    };
    Ok(pair
        .verifying_key()
        .verify_with_context(input, b"", &signature))
}

// The caller owns FIPS 204 preprocessing in the external-mu profile. Use the
// pinned provider's precomputed-mu API; never hash the 64-byte value again.
fn sign_mu_for<P: MlDsaParams>(material: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mu = Zeroizing::new(
        ml_dsa::common::array::Array::<u8, ml_dsa::common::typenum::U64>::try_from(input)
            .map_err(|_| error(500, "ML-DSA external mu must be exactly 64 bytes"))?,
    );
    let pair = signing_key::<P>(material)?;
    let signature = pair
        .expanded_key()
        .sign_mu_randomized(&mu, &mut getrandom::SysRng)
        .map_err(|_| error(503, "ML-DSA signing entropy is unavailable"))?;
    Ok(signature.encode().to_vec())
}

#[cfg(test)]
fn verify_mu_for<P: MlDsaParams>(material: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    let mu = Zeroizing::new(
        ml_dsa::common::array::Array::<u8, ml_dsa::common::typenum::U64>::try_from(input)
            .map_err(|_| error(500, "ML-DSA external mu must be exactly 64 bytes"))?,
    );
    let pair = signing_key::<P>(material)?;
    let Ok(signature) = ml_dsa::Signature::<P>::try_from(bytes) else {
        return Ok(false);
    };
    Ok(pair.verifying_key().verify_mu(&mu, &signature))
}

macro_rules! dispatch {
    ($kind:expr, $function:ident, $($argument:expr),+) => {
        match $kind {
            "mldsa-44" => $function::<MlDsa44>($($argument),+),
            "mldsa-65" => $function::<MlDsa65>($($argument),+),
            "mldsa-87" => $function::<MlDsa87>($($argument),+),
            _ => Err(bad("key does not support ML-DSA signing")),
        }
    };
}

pub(super) fn public(kind: &str, material: &[u8]) -> Result<Vec<u8>> {
    dispatch!(kind, public_for, material)
}
pub(super) fn sign(kind: &str, material: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    dispatch!(kind, sign_for, material, input)
}
pub(super) fn verify(kind: &str, material: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    dispatch!(kind, verify_for, material, input, bytes)
}

pub(super) fn sign_mu(kind: &str, material: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    dispatch!(kind, sign_mu_for, material, input)
}
#[cfg(test)]
pub(super) fn verify_mu(kind: &str, material: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    dispatch!(kind, verify_mu_for, material, input, bytes)
}

impl Transit {
    pub(in crate::engines) fn has_mldsa_state(&self) -> bool {
        // Deleted versions still own key material and still need the reader fence.
        self.keys.values().any(|key| is_kind(&key.kind))
    }

    pub(in crate::engines) fn validate_mldsa_state(&self) -> Result<()> {
        for key in self.keys.values().filter(|key| is_kind(&key.kind)) {
            if key.latest_version == 0
                || !key.versions.contains_key(&key.latest_version)
                || key.min_decryption_version == 0
                || key.min_decryption_version > key.latest_version
                || key.min_encryption_version > key.latest_version
                || key.versions.is_empty()
                || key.versions.len() > 10_000
            {
                return Err(bad("invalid ML-DSA version state"));
            }
            for (number, version) in &key.versions {
                if *number == 0 || *number > key.latest_version || version.encryptions != 0 {
                    return Err(bad("invalid ML-DSA key state"));
                }
                if let Some(public) = version.public_key_only.as_ref() {
                    if key.byok.is_none()
                        || !version.material.is_empty()
                        || !version.hmac_material.is_empty()
                    {
                        return Err(bad("invalid ML-DSA public-only state"));
                    }
                    validate_public(&key.kind, &stored_material(public)?)?;
                } else if stored_material(&version.material)?.len() != 32
                    || stored_material(&version.hmac_material)?.len() != 32
                {
                    return Err(bad("invalid ML-DSA key state"));
                }
            }
        }
        Ok(())
    }
}

// Standard formats are explicitly selected. The default Transit private export
// remains the 32-byte seed; public export remains the raw encoded public key.
fn export_standard_for<P>(
    material: &[u8],
    public_key: bool,
    format: &str,
) -> Result<Zeroizing<String>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    let pair = signing_key::<P>(material)?;
    let (bytes, label) = if public_key {
        let document = pair
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| error(500, "ML-DSA public encoding failed"))?;
        (Zeroizing::new(document.as_bytes().to_vec()), "PUBLIC KEY")
    } else {
        let document = pair
            .to_pkcs8_der()
            .map_err(|_| error(500, "ML-DSA private encoding failed"))?;
        (Zeroizing::new(document.as_bytes().to_vec()), "PRIVATE KEY")
    };
    let encoded = Zeroizing::new(BASE64.encode(bytes.as_slice()));
    if format == "der" {
        return Ok(encoded);
    }
    if format != "pem" {
        return Err(bad("unsupported standard ML-DSA export format"));
    }
    let mut pem = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(line).map_err(|_| error(500, "ML-DSA PEM encoding failed"))?,
        );
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    Ok(pem)
}

pub(super) fn export_standard(
    kind: &str,
    material: &[u8],
    public_key: bool,
    format: &str,
) -> Result<Zeroizing<String>> {
    dispatch!(kind, export_standard_for, material, public_key, format)
}

fn imported_public_for<P>(der: &[u8]) -> Result<ml_dsa::VerifyingKey<P>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    if der.len() > 2614 {
        return Err(bad("ML-DSA public key is too large"));
    }
    let public = ml_dsa::VerifyingKey::<P>::from_public_key_der(der)
        .map_err(|_| bad("invalid ML-DSA public key"))?;
    if public
        .to_public_key_der()
        .map_err(|_| bad("invalid ML-DSA public key"))?
        .as_bytes()
        != der
    {
        return Err(bad("ML-DSA public key must use canonical SPKI"));
    }
    Ok(public)
}

fn import_private_for<P>(der: &[u8]) -> Result<Zeroizing<Vec<u8>>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    if der.len() != 54 {
        return Err(bad("invalid ML-DSA PrivateKeyInfo"));
    }
    let private =
        SigningKey::<P>::from_pkcs8_der(der).map_err(|_| bad("invalid ML-DSA PrivateKeyInfo"))?;
    if private
        .to_pkcs8_der()
        .map_err(|_| bad("invalid ML-DSA PrivateKeyInfo"))?
        .as_bytes()
        != der
    {
        return Err(bad("ML-DSA private key must use canonical PrivateKeyInfo"));
    }
    Ok(Zeroizing::new(private.as_seed().as_slice().to_vec()))
}

pub(super) fn import_private(kind: &str, der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    dispatch!(kind, import_private_for, der)
}

fn canonical_public_for<P>(der: &[u8]) -> Result<Vec<u8>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    imported_public_for::<P>(der).map(|_| der.to_vec())
}

pub(super) fn validate_public(kind: &str, der: &[u8]) -> Result<()> {
    dispatch!(kind, canonical_public_for, der).map(|_| ())
}

pub(super) fn import_public_pem(kind: &str, pem: &str) -> Result<Vec<u8>> {
    if pem.len() > 4096 {
        return Err(bad("ML-DSA public PEM is too large"));
    }
    let contents = pem
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|value| value.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(|| bad("ML-DSA public import requires PUBLIC KEY PEM"))?;
    let encoded: String = contents.lines().map(str::trim).collect();
    let der = BASE64
        .decode(encoded)
        .map_err(|_| bad("invalid ML-DSA public PEM"))?;
    dispatch!(kind, canonical_public_for, &der)
}

fn public_only_for<P>(der: &[u8]) -> Result<Vec<u8>>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    Ok(imported_public_for::<P>(der)?.encode().to_vec())
}
pub(super) fn public_only(kind: &str, der: &[u8]) -> Result<Vec<u8>> {
    dispatch!(kind, public_only_for, der)
}

fn verify_public_for<P>(der: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    let public = imported_public_for::<P>(der)?;
    let Ok(signature) = ml_dsa::Signature::<P>::try_from(bytes) else {
        return Ok(false);
    };
    Ok(public.verify_with_context(input, b"", &signature))
}
pub(super) fn verify_public(kind: &str, der: &[u8], input: &[u8], bytes: &[u8]) -> Result<bool> {
    dispatch!(kind, verify_public_for, der, input, bytes)
}

pub(super) fn export_public(kind: &str, der: &[u8], format: &str) -> Result<Zeroizing<String>> {
    validate_public(kind, der)?;
    let encoded = Zeroizing::new(BASE64.encode(der));
    if format == "der" {
        return Ok(encoded);
    }
    if format != "pem" {
        return Err(bad("unsupported standard ML-DSA export format"));
    }
    let mut pem = Zeroizing::new(String::from("-----BEGIN PUBLIC KEY-----\n"));
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(
            std::str::from_utf8(line).map_err(|_| error(500, "ML-DSA PEM encoding failed"))?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}
