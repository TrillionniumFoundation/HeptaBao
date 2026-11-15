//! Durable root recovery ceremony and commit intent; never a barrier key.
use super::recovery_keys::{Error as KeyError, RecoveryCodec, RecoveryCredential};
use crate::crypto::{self, SecretShare};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::hmac;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
#[cfg(test)]
use zeroize::Zeroizing;

const MAX_SHARES: u8 = u8::MAX;
const INTENT_SEAL_LIMIT: usize = 64 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"heptabao.recovery-rotation.challenge.v1\0";
const DELIVERY_DOMAIN: &[u8] = b"heptabao.recovery-rotation.delivery.v1\0";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidConfiguration,
    InvalidNonce,
    StaleCredential,
    InvalidShare,
    VerificationRejected,
    RandomnessUnavailable,
    InvalidIntent,
    InvalidDelivery,
}
fn nonce() -> Result<String, Error> {
    let mut bytes = crypto::random::<16>().map_err(|_| Error::RandomnessUnavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn valid_nonce(value: &str) -> bool {
    let hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    (value.len() == 32 && value.bytes().all(hex)) // Persisted previous private operation compatibility.
        || (value.len() == 36 && value.bytes().enumerate().all(|(index, byte)|
            if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' } else { hex(byte) }))
}
fn delivery_key(secret: &[u8; 32], binding: [u8; 32], nonce: &str) -> [u8; 32] {
    let mut context = DELIVERY_DOMAIN.to_vec();
    context.extend_from_slice(&binding);
    context.extend_from_slice(nonce.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut result = [0; 32];
    result.copy_from_slice(hmac::sign(&key, &context).as_ref());
    result
}
fn valid_counts(shares: u8, threshold: u8) -> bool {
    shares != 0 && threshold != 0 && threshold <= shares
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Provided(Vec<u8>);
impl Drop for Provided {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryAttempt {
    schema: u32,
    pub(crate) cluster_binding: [u8; 32],
    pub(crate) source: Option<RecoveryCredential>,
    pub(crate) nonce: String,
    pub(crate) shares: u8,
    pub(crate) threshold: u8,
    pub(crate) require_verification: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_codec: Option<RecoveryCodec>,
    pub(crate) old_authorized: bool,
    pub(crate) new_authorized: bool,
    pub(crate) candidate: Option<RecoveryCredential>,
    pub(crate) verification_nonce: Option<String>,
    pub(crate) challenge: [u8; 32],
    pub(crate) delivery_key: Option<[u8; 32]>,
    provided: Vec<Provided>,
}
impl Drop for RecoveryAttempt {
    fn drop(&mut self) {
        if let Some(key) = self.delivery_key.as_mut() {
            key.zeroize();
        }
    }
}
impl RecoveryAttempt {
    pub(crate) fn new(
        cluster_binding: [u8; 32],
        source: Option<&RecoveryCredential>,
        shares: u8,
        threshold: u8,
        require_verification: bool,
    ) -> Result<Self, Error> {
        if !valid_counts(shares, threshold) {
            return Err(Error::InvalidConfiguration);
        }
        if let Some(source) = source {
            source
                .validate_binding(cluster_binding)
                .map_err(|_| Error::StaleCredential)?;
        }
        let mut attempt = Self {
            schema: 2,
            cluster_binding,
            source: source.cloned(),
            nonce: nonce()?,
            shares,
            threshold,
            require_verification,
            target_codec: Some(RecoveryCodec::Indexed33),
            old_authorized: source.is_none(),
            new_authorized: false,
            candidate: None,
            verification_nonce: None,
            challenge: [0; 32],
            delivery_key: None,
            provided: Vec::new(),
        };
        attempt.challenge = attempt.challenge_digest();
        Ok(attempt)
    }
    pub(crate) fn uses_indexed_wire(&self) -> bool {
        self.target_codec.is_some()
    }
    pub(crate) fn bind_delivery(&mut self, secret: &[u8; 32]) -> Result<(), Error> {
        if self.delivery_key.is_some()
            || self.old_authorized && self.source.is_some()
            || self.candidate.is_some()
            || *secret == [0; 32]
        {
            return Err(Error::InvalidDelivery);
        }
        self.delivery_key = Some(delivery_key(secret, self.cluster_binding, &self.nonce));
        self.challenge = self.challenge_digest();
        Ok(())
    }
    fn challenge_digest(&self) -> [u8; 32] {
        let mut bytes = CHALLENGE_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.cluster_binding);
        bytes.extend_from_slice(
            &self
                .source
                .as_ref()
                .map_or([0; 32], RecoveryCredential::fingerprint),
        );
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(&[
            self.shares,
            self.threshold,
            u8::from(self.require_verification),
        ]);
        if self.target_codec.is_some() {
            bytes.extend_from_slice(b"\0indexed33.target.v1");
        }
        if let Some(key) = &self.delivery_key {
            bytes.extend_from_slice(&crypto::digest(key));
        }
        if let Some(candidate) = &self.candidate {
            bytes.extend_from_slice(&candidate.fingerprint());
        }
        if let Some(nonce) = &self.verification_nonce {
            bytes.extend_from_slice(nonce.as_bytes());
        }
        crypto::digest(&bytes)
    }
    pub(crate) fn validate(
        &self,
        cluster_binding: [u8; 32],
        current: Option<&RecoveryCredential>,
    ) -> Result<(), Error> {
        if !matches!(
            (self.schema, self.target_codec),
            (1, None) | (2, Some(RecoveryCodec::Indexed33))
        ) || self.target_codec.is_none() && self.shares > 16
            || self.cluster_binding != cluster_binding
            || self.source.as_ref() != current
            || !valid_nonce(&self.nonce)
            || !valid_counts(self.shares, self.threshold)
            || self.challenge != self.challenge_digest()
            || self.provided.len() > usize::from(MAX_SHARES)
        {
            return Err(Error::StaleCredential);
        }
        if let Some(source) = &self.source {
            source
                .validate_binding(cluster_binding)
                .map_err(|_| Error::StaleCredential)?;
        }
        if self.source.is_none() && !self.old_authorized {
            return Err(Error::InvalidConfiguration);
        }
        let credential = if let Some(candidate) = &self.candidate {
            candidate
                .validate_binding(cluster_binding)
                .map_err(|_| Error::StaleCredential)?;
            if !self.old_authorized
                || !self.require_verification
                || candidate.generation()
                    != self
                        .source
                        .as_ref()
                        .map_or(Some(1), |value| value.generation().checked_add(1))
                        .ok_or(Error::InvalidConfiguration)?
                || candidate.shares() != self.shares
                || candidate.threshold() != self.threshold
                || candidate.uses_indexed_wire() != self.uses_indexed_wire()
                || self
                    .verification_nonce
                    .as_deref()
                    .is_none_or(|value| !valid_nonce(value))
            {
                return Err(Error::InvalidConfiguration);
            }
            Some(candidate)
        } else {
            if self.verification_nonce.is_some() || self.new_authorized {
                return Err(Error::InvalidConfiguration);
            }
            self.source.as_ref()
        };
        let mut indexes = std::collections::BTreeSet::new();
        for provided in &self.provided {
            let credential = credential.ok_or(Error::InvalidShare)?;
            let share = credential
                .decode_share(&provided.0)
                .map_err(|_| Error::InvalidShare)?;
            if share.total() != credential.shares()
                || share.threshold() != credential.threshold()
                || !indexes.insert(share.index())
            {
                return Err(Error::InvalidShare);
            }
        }
        Ok(())
    }
    pub(crate) fn progress(&self) -> usize {
        self.provided.len()
    }
    pub(crate) fn submit(
        &mut self,
        current: Option<&RecoveryCredential>,
        challenge_nonce: &str,
        encoded: &[u8],
        verification: bool,
    ) -> Result<bool, Error> {
        self.validate(self.cluster_binding, current)?;
        let expected = if verification {
            self.verification_nonce
                .as_deref()
                .ok_or(Error::InvalidConfiguration)?
        } else {
            self.nonce.as_str()
        };
        if challenge_nonce != expected {
            return Err(Error::InvalidNonce);
        }
        if verification != self.candidate.is_some() {
            return Err(Error::InvalidConfiguration);
        }
        if !verification && self.old_authorized {
            return Ok(true);
        }
        let credential = if verification {
            self.candidate.as_ref()
        } else {
            self.source.as_ref()
        }
        .ok_or(Error::InvalidConfiguration)?;
        let share = credential
            .decode_share(encoded)
            .map_err(|_| Error::InvalidShare)?;
        if share.total() != credential.shares() || share.threshold() != credential.threshold() {
            return Err(Error::InvalidShare);
        }
        if let Some(previous) = self.provided.iter().find(|provided| {
            credential
                .decode_share(&provided.0)
                .is_ok_and(|value| value.index() == share.index())
        }) {
            if previous.0.as_slice() != encoded {
                return Err(Error::InvalidShare);
            }
        } else {
            self.provided.push(Provided(encoded.to_vec()));
        }
        if self.provided.len() < usize::from(credential.threshold()) {
            return Ok(false);
        }
        let shares = self
            .provided
            .iter()
            .map(|value| credential.decode_share(&value.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidShare)?;
        self.provided.clear();
        credential
            .verify_shares(&shares)
            .map_err(|_| Error::VerificationRejected)?;
        if verification {
            self.new_authorized = true;
        } else {
            self.old_authorized = true;
        }
        Ok(true)
    }
    pub(crate) fn generate_candidate(
        &mut self,
    ) -> Result<(RecoveryCredential, Vec<SecretShare>), Error> {
        self.validate(self.cluster_binding, self.source.as_ref())?;
        if !self.old_authorized || self.candidate.is_some() {
            return Err(Error::InvalidConfiguration);
        }
        let generation = self
            .source
            .as_ref()
            .map_or(Some(1), |value| value.generation().checked_add(1))
            .ok_or(Error::InvalidConfiguration)?;
        let (credential, shares) = RecoveryCredential::generate_with_codec(
            self.cluster_binding,
            generation,
            self.shares,
            self.threshold,
            self.target_codec,
        )
        .map_err(|failure| match failure {
            KeyError::InvalidConfiguration => Error::InvalidConfiguration,
            _ => Error::RandomnessUnavailable,
        })?;
        if self.require_verification {
            self.verification_nonce = Some(nonce()?);
            self.candidate = Some(credential.clone());
            self.challenge = self.challenge_digest();
        }
        Ok((credential, shares))
    }
    pub(crate) fn reset_verification(&mut self) -> Result<(), Error> {
        if self.candidate.is_none() {
            return Err(Error::InvalidConfiguration);
        }
        self.provided.clear();
        self.new_authorized = false;
        self.verification_nonce = Some(nonce()?);
        self.challenge = self.challenge_digest();
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryCommitIntent {
    schema: u32,
    pub(crate) cluster_binding: [u8; 32],
    pub(crate) operation_binding: [u8; 32],
    pub(crate) source_credential: Option<RecoveryCredential>,
    pub(crate) target_fingerprint: [u8; 32],
    pub(crate) source_seal: Vec<u8>,
    pub(crate) target_seal: Vec<u8>,
}
impl RecoveryCommitIntent {
    pub(crate) fn new(
        attempt: &RecoveryAttempt,
        target: &RecoveryCredential,
        source_seal: Vec<u8>,
        target_seal: Vec<u8>,
    ) -> Result<Self, Error> {
        attempt.validate(attempt.cluster_binding, attempt.source.as_ref())?;
        if !attempt.old_authorized
            || attempt.require_verification
                && (!attempt.new_authorized || attempt.candidate.as_ref() != Some(target))
            || target.shares() != attempt.shares
            || target.threshold() != attempt.threshold
            || target.uses_indexed_wire() != attempt.uses_indexed_wire()
        {
            return Err(Error::InvalidIntent);
        }
        let value = Self {
            schema: 1,
            cluster_binding: attempt.cluster_binding,
            operation_binding: attempt.challenge,
            source_credential: attempt.source.clone(),
            target_fingerprint: target.fingerprint(),
            source_seal,
            target_seal,
        };
        value.validate(attempt.cluster_binding, target)?;
        Ok(value)
    }
    pub(crate) fn validate(
        &self,
        binding: [u8; 32],
        target: &RecoveryCredential,
    ) -> Result<(), Error> {
        target
            .validate_binding(binding)
            .map_err(|_| Error::InvalidIntent)?;
        if self.schema != 1
            || self.cluster_binding != binding
            || self.operation_binding == [0; 32]
            || target.fingerprint() != self.target_fingerprint
            || self.source_seal.is_empty()
            || self.target_seal.is_empty()
            || self.source_seal.len() > INTENT_SEAL_LIMIT
            || self.target_seal.len() > INTENT_SEAL_LIMIT
            || target.generation()
                != self
                    .source_credential
                    .as_ref()
                    .map_or(Some(1), |value| value.generation().checked_add(1))
                    .ok_or(Error::InvalidIntent)?
        {
            return Err(Error::InvalidIntent);
        }
        if let Some(source) = &self.source_credential {
            source
                .validate_binding(binding)
                .map_err(|_| Error::InvalidIntent)?;
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDelivery {
    schema: u32,
    cluster_binding: [u8; 32],
    target_fingerprint: [u8; 32],
    authorization: [u8; 32],
    pub(crate) nonce: String,
    pub(crate) verification_nonce: Option<String>,
    pub(crate) keys: Vec<String>,
    pub(crate) keys_base64: Vec<String>,
}
impl Drop for RecoveryDelivery {
    fn drop(&mut self) {
        for key in self.keys.iter_mut().chain(self.keys_base64.iter_mut()) {
            key.zeroize();
        }
    }
}
impl RecoveryDelivery {
    fn context(&self) -> Vec<u8> {
        let mut context = DELIVERY_DOMAIN.to_vec();
        context.extend_from_slice(&self.cluster_binding);
        context.extend_from_slice(&self.target_fingerprint);
        context.extend_from_slice(self.nonce.as_bytes());
        context
    }
    pub(crate) fn new(
        secret: &[u8; 32],
        target: &RecoveryCredential,
        attempt: &RecoveryAttempt,
        keys: Vec<String>,
        keys_base64: Vec<String>,
    ) -> Result<Self, Error> {
        if *secret == [0; 32]
            || keys.len() != usize::from(target.shares())
            || keys_base64.len() != keys.len()
        {
            return Err(Error::InvalidDelivery);
        }
        let mut value = Self {
            schema: 1,
            cluster_binding: attempt.cluster_binding,
            target_fingerprint: target.fingerprint(),
            authorization: [0; 32],
            nonce: attempt.nonce.clone(),
            verification_nonce: attempt.verification_nonce.clone(),
            keys,
            keys_base64,
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        value.authorization = hmac::sign(&key, &value.context())
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidDelivery)?;
        value.validate(attempt.cluster_binding, target)?;
        Ok(value)
    }
    pub(crate) fn validate(
        &self,
        binding: [u8; 32],
        target: &RecoveryCredential,
    ) -> Result<(), Error> {
        target
            .validate_binding(binding)
            .map_err(|_| Error::InvalidDelivery)?;
        if self.schema != 1
            || self.cluster_binding != binding
            || self.target_fingerprint != target.fingerprint()
            || !valid_nonce(&self.nonce)
            || self.keys.len() != usize::from(target.shares())
            || self.keys_base64.len() != self.keys.len()
            || self
                .keys
                .iter()
                .chain(&self.keys_base64)
                .any(|key| key.is_empty() || key.len() > 128)
            || self
                .verification_nonce
                .as_deref()
                .is_some_and(|nonce| !valid_nonce(nonce))
        {
            return Err(Error::InvalidDelivery);
        }
        let mut shares = Vec::new();
        let mut indexes = std::collections::BTreeSet::new();
        for (hex, base64) in self.keys.iter().zip(&self.keys_base64) {
            if hex.len() % 2 != 0
                || !hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(Error::InvalidDelivery);
            }
            let nibble = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            let encoded = zeroize::Zeroizing::new(
                hex.as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| nibble(pair[0]) * 16 + nibble(pair[1]))
                    .collect::<Vec<_>>(),
            );
            if STANDARD.encode(encoded.as_slice()) != *base64 {
                return Err(Error::InvalidDelivery);
            }
            let share = target
                .decode_share(&encoded)
                .map_err(|_| Error::InvalidDelivery)?;
            if share.total() != target.shares() || share.threshold() != target.threshold() {
                return Err(Error::InvalidDelivery);
            }
            let distinct = indexes.insert(share.index());
            if !distinct && !(target.uses_indexed_wire() && target.threshold() == 1) {
                return Err(Error::InvalidDelivery);
            }
            if target.threshold() == 1 {
                target
                    .verify_shares(std::slice::from_ref(&share))
                    .map_err(|_| Error::InvalidDelivery)?;
            }
            shares.push(share);
        }
        target
            .verify_shares(&shares)
            .map_err(|_| Error::InvalidDelivery)?;
        Ok(())
    }
    pub(crate) fn validate_attempt(&self, attempt: &RecoveryAttempt) -> Result<(), Error> {
        let target = attempt.candidate.as_ref().ok_or(Error::InvalidDelivery)?;
        self.validate(attempt.cluster_binding, target)?;
        if self.nonce != attempt.nonce || self.verification_nonce != attempt.verification_nonce {
            return Err(Error::InvalidDelivery);
        }
        let key = attempt
            .delivery_key
            .as_ref()
            .ok_or(Error::InvalidDelivery)?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &self.context(),
            &self.authorization,
        )
        .map_err(|_| Error::InvalidDelivery)
    }
    pub(crate) fn authorize(&self, secret: &[u8; 32]) -> Result<(), Error> {
        let derived =
            zeroize::Zeroizing::new(delivery_key(secret, self.cluster_binding, &self.nonce));
        let key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_slice());
        hmac::verify(&key, &self.context(), &self.authorization).map_err(|_| Error::InvalidDelivery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_quorum_is_durable_and_bound_to_nonce_and_source() -> Result<(), String> {
        let (credential, shares) =
            RecoveryCredential::generate([9; 32], 1, 5, 3).map_err(|error| format!("{error:?}"))?;
        let mut attempt = RecoveryAttempt::new([9; 32], Some(&credential), 3, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        let nonce = attempt.nonce.clone();
        assert_eq!(
            attempt.submit(
                Some(&credential),
                "wrong",
                &credential
                    .encode_share(&shares[0])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Err(Error::InvalidNonce)
        );
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&shares[0])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Ok(false)
        );
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&shares[0])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Ok(false)
        );
        assert_eq!(attempt.progress(), 1);
        let bytes =
            Zeroizing::new(serde_json::to_vec(&attempt).map_err(|error| error.to_string())?);
        let mut loaded: RecoveryAttempt =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        assert_eq!(
            loaded.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&shares[4])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Ok(false)
        );
        assert_eq!(
            loaded.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&shares[2])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Ok(true)
        );
        let (next, _) =
            RecoveryCredential::generate([9; 32], 2, 3, 2).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            loaded.submit(
                Some(&next),
                &nonce,
                &credential
                    .encode_share(&shares[1])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Err(Error::StaleCredential)
        );
        Ok(())
    }
    #[test]
    fn unrelated_quorum_does_not_create_candidate_and_verification_requires_new_shares()
    -> Result<(), String> {
        let (credential, old) =
            RecoveryCredential::generate([9; 32], 1, 5, 3).map_err(|error| format!("{error:?}"))?;
        let (_, wrong) =
            RecoveryCredential::generate([9; 32], 1, 5, 3).map_err(|error| format!("{error:?}"))?;
        let mut attempt = RecoveryAttempt::new([9; 32], Some(&credential), 3, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        let nonce = attempt.nonce.clone();
        for share in &wrong[..2] {
            assert_eq!(
                attempt.submit(
                    Some(&credential),
                    &nonce,
                    &credential
                        .encode_share(share)
                        .map_err(|error| format!("{error:?}"))?,
                    false
                ),
                Ok(false)
            );
        }
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&wrong[2])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Err(Error::VerificationRejected)
        );
        assert_eq!(attempt.progress(), 0);
        assert!(attempt.generate_candidate().is_err());
        for share in &old[..2] {
            assert_eq!(
                attempt.submit(
                    Some(&credential),
                    &nonce,
                    &credential
                        .encode_share(share)
                        .map_err(|error| format!("{error:?}"))?,
                    false
                ),
                Ok(false)
            );
        }
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &nonce,
                &credential
                    .encode_share(&old[2])
                    .map_err(|error| format!("{error:?}"))?,
                false
            ),
            Ok(true)
        );
        let (candidate, new) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(credential.generation(), 1);
        assert_eq!(candidate.generation(), 2);
        let verify = attempt
            .verification_nonce
            .clone()
            .ok_or("missing verification nonce")?;
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &nonce,
                &candidate
                    .encode_share(&new[0])
                    .map_err(|error| format!("{error:?}"))?,
                true
            ),
            Err(Error::InvalidNonce)
        );
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &verify,
                &candidate
                    .encode_share(&new[0])
                    .map_err(|error| format!("{error:?}"))?,
                true
            ),
            Ok(false)
        );
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &verify,
                &candidate
                    .encode_share(&new[2])
                    .map_err(|error| format!("{error:?}"))?,
                true
            ),
            Ok(true)
        );
        Ok(())
    }
    #[test]
    fn immutable_challenge_rejects_tampered_parameters_and_cluster() -> Result<(), String> {
        let (credential, _) =
            RecoveryCredential::generate([9; 32], 1, 5, 3).map_err(|error| format!("{error:?}"))?;
        let mut attempt = RecoveryAttempt::new([9; 32], Some(&credential), 3, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        assert!(attempt.validate([8; 32], Some(&credential)).is_err());
        attempt.threshold = 1;
        assert!(attempt.validate([9; 32], Some(&credential)).is_err());
        Ok(())
    }

    #[test]
    fn commit_intent_cannot_bypass_old_or_new_quorum() -> Result<(), String> {
        let (credential, old) =
            RecoveryCredential::generate([9; 32], 1, 5, 3).map_err(|error| format!("{error:?}"))?;
        let mut attempt = RecoveryAttempt::new([9; 32], Some(&credential), 3, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        let nonce = attempt.nonce.clone();
        let (unrelated, _) =
            RecoveryCredential::generate([9; 32], 2, 3, 2).map_err(|error| format!("{error:?}"))?;
        assert!(
            RecoveryCommitIntent::new(&attempt, &unrelated, b"{}".to_vec(), b"{}".to_vec())
                .is_err()
        );
        for share in &old[..3] {
            attempt
                .submit(
                    Some(&credential),
                    &nonce,
                    &credential
                        .encode_share(share)
                        .map_err(|error| format!("{error:?}"))?,
                    false,
                )
                .map_err(|error| format!("{error:?}"))?;
        }
        let (candidate, new) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            RecoveryCommitIntent::new(&attempt, &candidate, b"{}".to_vec(), b"{}".to_vec())
                .is_err()
        );
        let verify = attempt
            .verification_nonce
            .clone()
            .ok_or("missing verify nonce")?;
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &verify,
                &candidate
                    .encode_share(&new[0])
                    .map_err(|error| format!("{error:?}"))?,
                true
            ),
            Ok(false)
        );
        assert!(
            RecoveryCommitIntent::new(&attempt, &candidate, b"{}".to_vec(), b"{}".to_vec())
                .is_err()
        );
        assert_eq!(
            attempt.submit(
                Some(&credential),
                &verify,
                &candidate
                    .encode_share(&new[1])
                    .map_err(|error| format!("{error:?}"))?,
                true
            ),
            Ok(true)
        );
        let intent =
            RecoveryCommitIntent::new(&attempt, &candidate, b"{}".to_vec(), b"{}".to_vec())
                .map_err(|error| format!("{error:?}"))?;
        assert!(intent.validate([8; 32], &candidate).is_err());
        assert!(intent.validate([9; 32], &unrelated).is_err());
        Ok(())
    }
    #[test]
    fn private_delivery_requires_its_secret_and_actual_candidate_fragments() -> Result<(), String> {
        let mut attempt = RecoveryAttempt::new([9; 32], None, 3, 2, false)
            .map_err(|error| format!("{error:?}"))?;
        attempt
            .bind_delivery(&[7; 32])
            .map_err(|error| format!("{error:?}"))?;
        let (candidate, fragments) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        let mut keys = Vec::new();
        let mut base64 = Vec::new();
        for fragment in fragments {
            let encoded = Zeroizing::new(
                candidate
                    .encode_share(&fragment)
                    .map_err(|error| format!("{error:?}"))?,
            );
            keys.push(encoded.iter().map(|byte| format!("{byte:02x}")).collect());
            base64.push(STANDARD.encode(encoded.as_slice()));
        }
        let key = attempt
            .delivery_key
            .as_ref()
            .ok_or("missing delivery key")?;
        let delivery = RecoveryDelivery::new(key, &candidate, &attempt, keys, base64)
            .map_err(|error| format!("{error:?}"))?;
        assert!(delivery.authorize(&[7; 32]).is_ok());
        assert!(delivery.authorize(&[8; 32]).is_err());
        let bytes =
            Zeroizing::new(serde_json::to_vec(&delivery).map_err(|error| error.to_string())?);
        let mut restored: RecoveryDelivery =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        assert!(restored.validate([9; 32], &candidate).is_ok());
        restored.keys[0] = restored.keys[1].clone();
        assert!(restored.validate([9; 32], &candidate).is_err());
        Ok(())
    }
    #[test]
    fn raw_threshold_one_delivery_checks_every_repeated_fragment() -> Result<(), String> {
        let mut attempt = RecoveryAttempt::new([9; 32], None, 255, 1, false)
            .map_err(|error| format!("{error:?}"))?;
        attempt
            .bind_delivery(&[7; 32])
            .map_err(|error| format!("{error:?}"))?;
        let (candidate, fragments) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        let mut hex = Vec::new();
        let mut base64 = Vec::new();
        for share in fragments {
            let wire = Zeroizing::new(
                candidate
                    .encode_share(&share)
                    .map_err(|error| format!("{error:?}"))?,
            );
            assert_eq!(wire.len(), 32);
            hex.push(wire.iter().map(|byte| format!("{byte:02x}")).collect());
            base64.push(STANDARD.encode(wire.as_slice()));
        }
        let key = attempt
            .delivery_key
            .as_ref()
            .ok_or("missing delivery key")?;
        let mut delivery = RecoveryDelivery::new(key, &candidate, &attempt, hex, base64)
            .map_err(|error| format!("{error:?}"))?;
        assert!(delivery.authorize(&[7; 32]).is_ok());
        delivery.keys[254] = "00".repeat(32);
        delivery.keys_base64[254] = STANDARD.encode([0; 32]);
        assert!(delivery.validate([9; 32], &candidate).is_err());
        Ok(())
    }
    #[test]
    fn uuid_operation_nonce_and_stored_legacy_nonce_keep_exact_binding() -> Result<(), String> {
        let mut attempt = RecoveryAttempt::new([9; 32], None, 3, 2, false)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(attempt.nonce.len(), 36);
        assert!(valid_nonce(&attempt.nonce));
        let mut malformed = attempt.nonce.clone();
        malformed.replace_range(..1, "A");
        assert!(!valid_nonce(&malformed));
        attempt.nonce = "ab".repeat(16);
        attempt.challenge = attempt.challenge_digest();
        assert!(attempt.validate([9; 32], None).is_ok());
        let wire = Zeroizing::new(serde_json::to_vec(&attempt).map_err(|error| error.to_string())?);
        let stored: RecoveryAttempt =
            serde_json::from_slice(&wire).map_err(|error| error.to_string())?;
        assert!(stored.validate([9; 32], None).is_ok());
        Ok(())
    }

    #[test]
    fn persisted_legacy_attempt_keeps_hbs1_target_until_explicit_new_operation()
    -> Result<(), String> {
        let mut old = RecoveryAttempt::new([9; 32], None, 3, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        // Model the actual prior serialized version, not an automatic target-codec migration.
        old.schema = 1;
        old.target_codec = None;
        old.nonce = "ab".repeat(16);
        old.challenge = old.challenge_digest();
        let bytes = Zeroizing::new(serde_json::to_vec(&old).map_err(|error| error.to_string())?);
        assert!(!String::from_utf8_lossy(&bytes).contains("target_codec"));
        let mut stored: RecoveryAttempt =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        assert!(stored.validate([9; 32], None).is_ok());
        let (target, fragments) = stored
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        assert!(!target.uses_indexed_wire());
        assert_eq!(
            &target
                .encode_share(&fragments[0])
                .map_err(|error| format!("{error:?}"))?[..4],
            b"HBS1"
        );
        let mut tampered = RecoveryAttempt::new([9; 32], None, 3, 2, false)
            .map_err(|error| format!("{error:?}"))?;
        tampered.target_codec = None;
        assert!(tampered.validate([9; 32], None).is_err());
        Ok(())
    }

    #[test]
    fn real_old_quorum_cannot_commit_a_target_with_the_wrong_codec() -> Result<(), String> {
        let (source, old_shares) = RecoveryCredential::generate_with_codec([9; 32], 1, 5, 3, None)
            .map_err(|error| format!("{error:?}"))?;
        let mut attempt = RecoveryAttempt::new([9; 32], Some(&source), 3, 2, false)
            .map_err(|error| format!("{error:?}"))?;
        let challenge = attempt.nonce.clone();
        for share in &old_shares[..3] {
            let encoded = Zeroizing::new(
                source
                    .encode_share(share)
                    .map_err(|error| format!("{error:?}"))?,
            );
            attempt
                .submit(Some(&source), &challenge, &encoded, false)
                .map_err(|error| format!("{error:?}"))?;
        }
        let (wrong_codec, _) = RecoveryCredential::generate_with_codec([9; 32], 2, 3, 2, None)
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            RecoveryCommitIntent::new(&attempt, &wrong_codec, b"{}".to_vec(), b"{}".to_vec())
                .is_err()
        );
        let (correct, _) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            RecoveryCommitIntent::new(&attempt, &correct, b"{}".to_vec(), b"{}".to_vec()).is_ok()
        );
        attempt.threshold = 1;
        assert!(attempt.generate_candidate().is_err());
        Ok(())
    }
}
