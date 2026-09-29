//! FIPS 204 through RustCrypto's pinned implementation, not a second key owner.
//! Persist only the 32-byte seed in the existing encrypted Transit version.
use super::*;
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
                if *number == 0
                    || *number > key.latest_version
                    || stored_material(&version.material)?.len() != 32
                    || stored_material(&version.hmac_material)?.len() != 32
                    || version.encryptions != 0
                {
                    return Err(bad("invalid ML-DSA key state"));
                }
            }
        }
        Ok(())
    }
}
