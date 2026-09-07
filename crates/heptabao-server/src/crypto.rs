//! Versioned AEAD storage provider. The unseal key is supplied out of band and
//! never persisted by this provider. Every nonce comes from the operating system.
use heptabao_durable_service::{Barrier, BarrierError};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroize;

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
}
