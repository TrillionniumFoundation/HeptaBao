//! Versioned cryptographic helpers for the runnable service.
//!
//! The durable barrier key is never persisted in plaintext. Fresh deployments
//! wrap it with a Shamir-protected master key; the resulting shares are supplied
//! out of band. Every nonce and polynomial coefficient comes from the operating
//! system CSPRNG.
use heptabao_durable_service::{Barrier, BarrierError};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroize;

const SHARE_MAGIC: &[u8; 4] = b"HBS1";
const SHARE_SECRET_BYTES: usize = 32;
const SHARE_CHECKSUM_BYTES: usize = 4;
const SHARE_BYTES: usize = SHARE_MAGIC.len() + 3 + SHARE_SECRET_BYTES + SHARE_CHECKSUM_BYTES;
const WRAPPED_KEY_MAGIC: &[u8; 4] = b"HBK1";

pub struct AeadBarrier(aead::LessSafeKey);

impl AeadBarrier {
    pub fn new(mut key: [u8; 32]) -> Result<Self, BarrierError> {
        let result = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map(|key| Self(aead::LessSafeKey::new(key)))
            .map_err(|_| BarrierError);
        key.zeroize();
        result
    }
}

impl Barrier for AeadBarrier {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| BarrierError)?;
        let mut output = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut output,
            )
            .map_err(|_| BarrierError)?;
        let mut protected = Vec::with_capacity(16 + output.len());
        protected.extend_from_slice(b"HBA1");
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&output);
        output.zeroize();
        Ok(protected)
    }

    fn open(&self, context: &[u8], protected: &[u8]) -> Result<Vec<u8>, BarrierError> {
        if protected.len() < 32 || &protected[..4] != b"HBA1" {
            return Err(BarrierError);
        }
        let nonce: [u8; 12] = protected[4..16].try_into().map_err(|_| BarrierError)?;
        let mut data = protected[16..].to_vec();
        let result = self
            .0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut data,
            )
            .map(|plain| plain.to_vec())
            .map_err(|_| BarrierError);
        data.zeroize();
        result
    }
}

/// One authenticated, opaque Shamir share. The index and threshold are public;
/// the value is cleared when the share is dropped.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretShare {
    total: u8,
    threshold: u8,
    index: u8,
    value: [u8; SHARE_SECRET_BYTES],
}

impl std::fmt::Debug for SecretShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretShare")
            .field("total", &self.total)
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl SecretShare {
    #[must_use]
    pub const fn total(&self) -> u8 {
        self.total
    }

    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(SHARE_BYTES);
        encoded.extend_from_slice(SHARE_MAGIC);
        encoded.extend_from_slice(&[self.total, self.threshold, self.index]);
        encoded.extend_from_slice(&self.value);
        let checksum = share_checksum(&encoded);
        encoded.extend_from_slice(&checksum[..SHARE_CHECKSUM_BYTES]);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, &'static str> {
        if encoded.len() != SHARE_BYTES || &encoded[..SHARE_MAGIC.len()] != SHARE_MAGIC {
            return Err("invalid Shamir share format");
        }
        let checksum_offset = SHARE_BYTES - SHARE_CHECKSUM_BYTES;
        let expected = share_checksum(&encoded[..checksum_offset]);
        if encoded[checksum_offset..] != expected[..SHARE_CHECKSUM_BYTES] {
            return Err("invalid Shamir share checksum");
        }
        let total = encoded[4];
        let threshold = encoded[5];
        let index = encoded[6];
        validate_share_parameters(total, threshold)?;
        if index == 0 || index > total {
            return Err("invalid Shamir share index");
        }
        let mut value = [0u8; SHARE_SECRET_BYTES];
        value.copy_from_slice(&encoded[7..7 + SHARE_SECRET_BYTES]);
        Ok(Self {
            total,
            threshold,
            index,
            value,
        })
    }
}

/// Split a 256-bit master key into bounded Shamir shares over GF(256).
pub fn split_secret(
    secret: &[u8; SHARE_SECRET_BYTES],
    total: u8,
    threshold: u8,
) -> Result<Vec<SecretShare>, &'static str> {
    validate_share_parameters(total, threshold)?;
    let mut shares = (1..=total)
        .map(|index| SecretShare {
            total,
            threshold,
            index,
            value: [0; SHARE_SECRET_BYTES],
        })
        .collect::<Vec<_>>();
    let coefficient_count = usize::from(threshold.saturating_sub(1));
    let random = SystemRandom::new();
    for (byte_index, secret_byte) in secret.iter().copied().enumerate() {
        let mut coefficients = vec![0u8; coefficient_count];
        random
            .fill(&mut coefficients)
            .map_err(|_| "operating system randomness unavailable")?;
        for share in &mut shares {
            let x = share.index;
            let mut value = secret_byte;
            let mut power = x;
            for coefficient in &coefficients {
                value ^= gf_mul(*coefficient, power);
                power = gf_mul(power, x);
            }
            share.value[byte_index] = value;
        }
        coefficients.zeroize();
    }
    Ok(shares)
}

/// Reconstruct a 256-bit master key from a threshold of distinct shares.
pub fn combine_shares(shares: &[SecretShare]) -> Result<[u8; SHARE_SECRET_BYTES], &'static str> {
    let first = shares.first().ok_or("no Shamir shares supplied")?;
    validate_share_parameters(first.total, first.threshold)?;
    if shares.len() < usize::from(first.threshold) {
        return Err("insufficient Shamir shares");
    }
    let selected = &shares[..usize::from(first.threshold)];
    for (position, share) in selected.iter().enumerate() {
        if share.total != first.total || share.threshold != first.threshold {
            return Err("Shamir share parameter mismatch");
        }
        if selected[..position]
            .iter()
            .any(|existing| existing.index == share.index)
        {
            return Err("duplicate Shamir share index");
        }
    }

    let mut secret = [0u8; SHARE_SECRET_BYTES];
    for (byte_index, output) in secret.iter_mut().enumerate() {
        let mut value = 0u8;
        for (position, share) in selected.iter().enumerate() {
            let mut basis = 1u8;
            for (other_position, other) in selected.iter().enumerate() {
                if position == other_position {
                    continue;
                }
                let denominator = other.index ^ share.index;
                if denominator == 0 {
                    return Err("duplicate Shamir share index");
                }
                basis = gf_mul(basis, gf_mul(other.index, gf_inverse(denominator)?));
            }
            value ^= gf_mul(share.value[byte_index], basis);
        }
        *output = value;
    }
    Ok(secret)
}

/// Encrypt the durable data-encryption key under the reconstructed seal key.
pub fn wrap_barrier_key(
    seal_key: &[u8; 32],
    context: &[u8],
    barrier_key: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, seal_key).map_err(|_| "invalid seal key")?;
    let key = aead::LessSafeKey::new(unbound);
    let mut nonce = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "operating system randomness unavailable")?;
    let mut ciphertext = barrier_key.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(context),
        &mut ciphertext,
    )
    .map_err(|_| "cannot wrap barrier key")?;
    let mut encoded = Vec::with_capacity(WRAPPED_KEY_MAGIC.len() + nonce.len() + ciphertext.len());
    encoded.extend_from_slice(WRAPPED_KEY_MAGIC);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    ciphertext.zeroize();
    Ok(encoded)
}

/// Authenticate and decrypt the durable data-encryption key.
pub fn unwrap_barrier_key(
    seal_key: &[u8; 32],
    context: &[u8],
    encoded: &[u8],
) -> Result<[u8; 32], &'static str> {
    if encoded.len() != WRAPPED_KEY_MAGIC.len() + 12 + 32 + aead::AES_256_GCM.tag_len()
        || &encoded[..WRAPPED_KEY_MAGIC.len()] != WRAPPED_KEY_MAGIC
    {
        return Err("invalid wrapped barrier key format");
    }
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, seal_key).map_err(|_| "invalid seal key")?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce: [u8; 12] = encoded[4..16]
        .try_into()
        .map_err(|_| "invalid wrapped barrier key nonce")?;
    let mut ciphertext = encoded[16..].to_vec();
    let result = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context),
            &mut ciphertext,
        )
        .map_err(|_| "seal key authentication failed")?;
    if result.len() != 32 {
        ciphertext.zeroize();
        return Err("invalid wrapped barrier key length");
    }
    let mut barrier_key = [0u8; 32];
    barrier_key.copy_from_slice(result);
    ciphertext.zeroize();
    Ok(barrier_key)
}

pub fn random<const N: usize>() -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "operating system randomness unavailable")?;
    Ok(bytes)
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    output.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    output
}

fn validate_share_parameters(total: u8, threshold: u8) -> Result<(), &'static str> {
    if total == 0 || threshold == 0 || threshold > total {
        return Err("invalid Shamir share parameters");
    }
    Ok(())
}

fn share_checksum(encoded_without_checksum: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(36 + encoded_without_checksum.len());
    material.extend_from_slice(b"heptabao.shamir-share.v1\0");
    material.extend_from_slice(encoded_without_checksum);
    let checksum = digest(&material);
    material.zeroize();
    checksum
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn gf_inverse(value: u8) -> Result<u8, &'static str> {
    if value == 0 {
        return Err("zero has no inverse in GF(256)");
    }
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 254u16;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_is_randomized_and_authenticates_payload_context_and_key()
    -> Result<(), BarrierError> {
        let provider = AeadBarrier::new([7; 32])?;
        let secret = b"synthetic-storage-fixture";
        let first = provider.seal(b"snapshot-v2", secret)?;
        let second = provider.seal(b"snapshot-v2", secret)?;
        assert_ne!(first, second);
        assert!(!first.windows(secret.len()).any(|b| b == secret));
        assert_eq!(provider.open(b"snapshot-v2", &first)?, secret);
        assert!(provider.open(b"other-namespace", &first).is_err());
        assert!(
            AeadBarrier::new([8; 32])?
                .open(b"snapshot-v2", &first)
                .is_err()
        );
        let mut altered = first;
        altered[17] ^= 1;
        assert!(provider.open(b"snapshot-v2", &altered).is_err());
        Ok(())
    }

    #[test]
    fn shamir_threshold_reconstructs_from_any_subset_and_rejects_tampering()
    -> Result<(), &'static str> {
        let secret = [0x5a; 32];
        let shares = split_secret(&secret, 5, 3)?;
        assert_eq!(
            combine_shares(&[shares[0].clone(), shares[2].clone(), shares[4].clone()])?,
            secret
        );
        assert_eq!(
            combine_shares(&[shares[1].clone(), shares[2].clone(), shares[3].clone()])?,
            secret
        );
        assert!(combine_shares(&shares[..2]).is_err());
        let mut encoded = shares[0].encode();
        encoded[12] ^= 1;
        assert!(SecretShare::decode(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn wrapped_barrier_key_binds_seal_key_and_metadata() -> Result<(), &'static str> {
        let seal_key = [7; 32];
        let barrier_key = [9; 32];
        let wrapped = wrap_barrier_key(&seal_key, b"seal-generation-1", &barrier_key)?;
        assert_eq!(
            unwrap_barrier_key(&seal_key, b"seal-generation-1", &wrapped)?,
            barrier_key
        );
        assert!(unwrap_barrier_key(&[8; 32], b"seal-generation-1", &wrapped).is_err());
        assert!(unwrap_barrier_key(&seal_key, b"seal-generation-2", &wrapped).is_err());
        Ok(())
    }
}
