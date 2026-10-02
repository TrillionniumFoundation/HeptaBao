//! Isolated draft of the maintained-provider AES BYOK envelope adapter.
//! This crate has no HTTP routes, state publication, or compatibility claim.
#![forbid(unsafe_code)]

use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrapPadded};
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

const RSA_BYTES: usize = 512;
const KEK_BYTES: usize = 32;
const MAX_PRIVATE_BYTES: usize = 8192;

/// Closed error categories never include provider errors or cryptographic data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    UnsupportedTargetLength,
    InvalidWrappingKey,
    InvalidEnvelope,
    EnvelopeAuthenticationFailed,
    ProviderUnavailable,
}

#[derive(Clone, Copy)]
pub enum OaepDigest {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl OaepDigest {
    fn provider(self) -> MessageDigest {
        match self {
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha224 => MessageDigest::sha224(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
}

/// Generate only the wrapping key; the caller must publish it atomically before use.
pub fn generate_wrapping_private_key() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let rsa = Rsa::generate(4096).map_err(|_| CryptoError::ProviderUnavailable)?;
    let key = PKey::from_rsa(rsa).map_err(|_| CryptoError::ProviderUnavailable)?;
    key.private_key_to_pkcs8()
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::ProviderUnavailable)
}

fn wrapping_key(private_pkcs8: &[u8]) -> Result<PKey<Private>, CryptoError> {
    if private_pkcs8.is_empty() || private_pkcs8.len() > MAX_PRIVATE_BYTES {
        return Err(CryptoError::InvalidWrappingKey);
    }
    let key =
        PKey::private_key_from_pkcs8(private_pkcs8).map_err(|_| CryptoError::InvalidWrappingKey)?;
    if key.id() != Id::RSA || key.bits() != 4096 {
        return Err(CryptoError::InvalidWrappingKey);
    }
    let rsa = key.rsa().map_err(|_| CryptoError::InvalidWrappingKey)?;
    if !rsa
        .check_key()
        .map_err(|_| CryptoError::InvalidWrappingKey)?
    {
        return Err(CryptoError::InvalidWrappingKey);
    }
    let canonical = Zeroizing::new(
        key.private_key_to_pkcs8()
            .map_err(|_| CryptoError::InvalidWrappingKey)?,
    );
    if canonical.len() != private_pkcs8.len() || !openssl::memcmp::eq(&canonical, private_pkcs8) {
        return Err(CryptoError::InvalidWrappingKey);
    }
    Ok(key)
}

/// SPKI public PEM, separate from and incapable of exporting the private key.
pub fn wrapping_public_pem(private_pkcs8: &[u8]) -> Result<Vec<u8>, CryptoError> {
    wrapping_key(private_pkcs8)?
        .public_key_to_pem()
        .map_err(|_| CryptoError::ProviderUnavailable)
}

pub fn validate_wrapping_private_key(private_pkcs8: &[u8]) -> Result<(), CryptoError> {
    wrapping_key(private_pkcs8).map(|_| ())
}

/// Unwrap RSA-OAEP(32-byte KEK) || AES-256-KWP(16/32-byte target key).
/// Digest and MGF1 digest are always the same explicit maintained-provider hash.
pub fn unwrap_aes_envelope(
    private_pkcs8: &[u8],
    envelope: &[u8],
    target_length: usize,
    digest: OaepDigest,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let wrapped_length = match target_length {
        16 => 24,
        32 => 40,
        _ => return Err(CryptoError::UnsupportedTargetLength),
    };
    if envelope.len() != RSA_BYTES + wrapped_length {
        return Err(CryptoError::InvalidEnvelope);
    }
    let key = wrapping_key(private_pkcs8)?;
    let mut decrypter = Decrypter::new(&key).map_err(|_| CryptoError::ProviderUnavailable)?;
    decrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| CryptoError::ProviderUnavailable)?;
    decrypter
        .set_rsa_oaep_md(digest.provider())
        .map_err(|_| CryptoError::ProviderUnavailable)?;
    decrypter
        .set_rsa_mgf1_md(digest.provider())
        .map_err(|_| CryptoError::ProviderUnavailable)?;
    let mut kek = Zeroizing::new(vec![0; RSA_BYTES]);
    let actual_length = decrypter
        .decrypt(&envelope[..RSA_BYTES], &mut kek)
        .map_err(|_| CryptoError::EnvelopeAuthenticationFailed)?;
    if actual_length != KEK_BYTES {
        return Err(CryptoError::EnvelopeAuthenticationFailed);
    }
    kek.truncate(actual_length);
    // The application owns zeroizing buffers. The maintained provider's internal
    // KEK copy is outside this adapter's erasure guarantee; no unsafe bridge is used.
    let kwp = AesKek::new(&AES_256, &kek).map_err(|_| CryptoError::ProviderUnavailable)?;
    let mut material = Zeroizing::new(vec![0; wrapped_length]);
    let actual_length = kwp
        .unwrap_with_padding(&envelope[RSA_BYTES..], &mut material)
        .map_err(|_| CryptoError::EnvelopeAuthenticationFailed)?
        .len();
    if actual_length != target_length {
        return Err(CryptoError::EnvelopeAuthenticationFailed);
    }
    material.truncate(actual_length);
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::encrypt::Encrypter;

    type TestResult = Result<(), &'static str>;

    fn private() -> Result<Zeroizing<Vec<u8>>, &'static str> {
        generate_wrapping_private_key().map_err(|_| "wrapping_key_generation_failed")
    }

    fn envelope(
        key: &[u8],
        material: &[u8],
        digest: OaepDigest,
        kek_bytes: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let public =
            PKey::public_key_from_pem(&wrapping_public_pem(key).map_err(|_| "public_key_failed")?)
                .map_err(|_| "public_key_parse_failed")?;
        let mut encrypter = Encrypter::new(&public).map_err(|_| "rsa_encrypt_failed")?;
        encrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|_| "padding_failed")?;
        encrypter
            .set_rsa_oaep_md(digest.provider())
            .map_err(|_| "digest_failed")?;
        encrypter
            .set_rsa_mgf1_md(digest.provider())
            .map_err(|_| "mgf_failed")?;
        let mut output = vec![0; RSA_BYTES];
        let actual = encrypter
            .encrypt(kek_bytes, &mut output)
            .map_err(|_| "rsa_encrypt_failed")?;
        assert!(actual == RSA_BYTES, "fixed RSA envelope length");
        let kwp = AesKek::new(&AES_256, kek_bytes).map_err(|_| "kek_failed")?;
        let mut tail = vec![0; material.len() + 15];
        let wrapped = kwp
            .wrap_with_padding(material, &mut tail)
            .map_err(|_| "kwp_wrap_failed")?;
        output.extend_from_slice(wrapped);
        Ok(output)
    }

    #[test]
    fn canonical_pkcs8_and_spki_remain_stable_across_reload() -> TestResult {
        let key = private()?;
        assert!(validate_wrapping_private_key(&key).is_ok());
        let before = wrapping_public_pem(&key).map_err(|_| "public_key_failed")?;
        let cloned = Zeroizing::new(key.to_vec());
        let after = wrapping_public_pem(&cloned).map_err(|_| "public_key_failed")?;
        assert!(before == after, "reload preserves wrapping public key");
        let parsed = PKey::public_key_from_pem(&after).map_err(|_| "public_key_parse_failed")?;
        assert!(parsed.bits() == 4096 && parsed.id() == Id::RSA);
        assert!(after.starts_with(b"-----BEGIN PUBLIC KEY-----"));
        Ok(())
    }

    #[test]
    fn all_five_oaep_digests_unwrap_both_exact_aes_lengths() -> TestResult {
        let key = private()?;
        for digest in [
            OaepDigest::Sha1,
            OaepDigest::Sha224,
            OaepDigest::Sha256,
            OaepDigest::Sha384,
            OaepDigest::Sha512,
        ] {
            for length in [16, 32] {
                let material = vec![0x50; length];
                let wrapped = envelope(&key, &material, digest, &[0x41; KEK_BYTES])?;
                assert!(wrapped.len() == RSA_BYTES + length + 8);
                let recovered = unwrap_aes_envelope(&key, &wrapped, length, digest)
                    .map_err(|_| "unwrap_failed")?;
                assert!(
                    recovered.as_slice() == material,
                    "imported AES material is exact"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn wrong_digest_rsa_and_kwp_tampering_are_rejected() -> TestResult {
        let key = private()?;
        let wrapped = envelope(&key, &[0x50; 32], OaepDigest::Sha256, &[0x41; KEK_BYTES])?;
        assert!(unwrap_aes_envelope(&key, &wrapped, 32, OaepDigest::Sha512).is_err());
        for offset in [0, RSA_BYTES - 1, RSA_BYTES, wrapped.len() - 1] {
            let mut tampered = wrapped.clone();
            tampered[offset] ^= 1;
            assert!(unwrap_aes_envelope(&key, &tampered, 32, OaepDigest::Sha256).is_err());
        }
        let wrong = private()?;
        assert!(unwrap_aes_envelope(&wrong, &wrapped, 32, OaepDigest::Sha256).is_err());
        Ok(())
    }

    #[test]
    fn target_envelope_and_private_key_bounds_fail_closed() -> TestResult {
        for target in [0, 1, 15, 17, 24, 31, 33, usize::MAX] {
            assert!(matches!(
                unwrap_aes_envelope(&[], &[], target, OaepDigest::Sha256),
                Err(CryptoError::UnsupportedTargetLength)
            ));
        }
        for length in [0, 1, RSA_BYTES, 535, 537, 551, 553, 4096] {
            assert!(matches!(
                unwrap_aes_envelope(&[], &vec![0; length], 32, OaepDigest::Sha256),
                Err(CryptoError::InvalidEnvelope)
            ));
        }
        for length in [0, 1, MAX_PRIVATE_BYTES + 1] {
            assert!(matches!(
                validate_wrapping_private_key(&vec![0; length]),
                Err(CryptoError::InvalidWrappingKey)
            ));
        }
        let rsa = Rsa::generate(2048).map_err(|_| "rsa_generation_failed")?;
        let key = PKey::from_rsa(rsa).map_err(|_| "rsa_key_conversion_failed")?;
        let wrong = Zeroizing::new(
            key.private_key_to_pkcs8()
                .map_err(|_| "private_key_failed")?,
        );
        assert!(matches!(
            validate_wrapping_private_key(&wrong),
            Err(CryptoError::InvalidWrappingKey)
        ));
        let key = private()?;
        let mut trailing = Zeroizing::new(key.to_vec());
        trailing.push(0);
        assert!(matches!(
            validate_wrapping_private_key(&trailing),
            Err(CryptoError::InvalidWrappingKey)
        ));
        Ok(())
    }
}
