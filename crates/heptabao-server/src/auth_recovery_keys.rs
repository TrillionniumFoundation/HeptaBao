//! Protected threshold authorization, independent of barrier decryption.
//! Legacy HBS1 bytes remain readable; new indexed codec needs pinned wire qualification.
#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::{self, SecretShare};
use ring::hmac;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const LEGACY_MAX_RECOVERY_SHARES: u8 = 16; // HBS1 credential admission stays unchanged.

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryCodec {
    Indexed33,
}
const DOMAIN: &[u8] = b"heptabao.recovery-authorization.v1\0";

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryCredential {
    schema: u32,
    generation: u64,
    shares: u8,
    threshold: u8,
    cluster_binding: [u8; 32],
    verifier: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codec: Option<RecoveryCodec>,
}

impl fmt::Debug for RecoveryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCredential([REDACTED])")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidConfiguration,
    #[cfg(test)]
    InvalidNonce,
    InvalidShare,
    #[cfg(test)]
    GenerationChanged,
    VerificationRejected,
    #[cfg(test)]
    AlreadyAuthorized,
    RandomnessUnavailable,
}

impl Drop for RecoveryCredential {
    fn drop(&mut self) {
        self.verifier.zeroize();
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPublic {
    pub(crate) generation: u64,
    pub(crate) shares: u8,
    pub(crate) threshold: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codec: Option<RecoveryCodec>,
}
impl RecoveryPublic {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.generation == 0
            || self.shares == 0
            || self.codec.is_none() && self.shares > LEGACY_MAX_RECOVERY_SHARES
            || self.threshold == 0
            || self.threshold > self.shares
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }
}

impl RecoveryCredential {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !matches!(
            (self.schema, self.codec),
            (1, None) | (2, Some(RecoveryCodec::Indexed33))
        ) || self.generation == 0
            || self.shares == 0
            || self.codec.is_none() && self.shares > LEGACY_MAX_RECOVERY_SHARES
            || self.threshold == 0
            || self.threshold > self.shares
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }

    pub(crate) fn validate_binding(&self, cluster_binding: [u8; 32]) -> Result<(), Error> {
        self.validate()?;
        if self.cluster_binding != cluster_binding {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn shares(&self) -> u8 {
        self.shares
    }
    pub(crate) fn threshold(&self) -> u8 {
        self.threshold
    }
    pub(crate) fn public(&self) -> RecoveryPublic {
        RecoveryPublic {
            generation: self.generation,
            shares: self.shares,
            threshold: self.threshold,
            codec: self.codec,
        }
    }
    pub(crate) fn uses_indexed_wire(&self) -> bool {
        self.codec.is_some()
    }
    pub(crate) fn encode_share(&self, share: &SecretShare) -> Result<Vec<u8>, Error> {
        self.validate()?;
        if share.total() != self.shares || share.threshold() != self.threshold {
            return Err(Error::InvalidShare);
        }
        Ok(match self.codec {
            None => share.encode(),
            Some(RecoveryCodec::Indexed33) => share.encode_indexed(),
        })
    }
    pub(crate) fn decode_share(&self, bytes: &[u8]) -> Result<SecretShare, Error> {
        self.validate()?;
        let share = match self.codec {
            None => SecretShare::decode(bytes),
            Some(RecoveryCodec::Indexed33) => {
                SecretShare::decode_indexed(bytes, self.shares, self.threshold)
            }
        }
        .map_err(|_| Error::InvalidShare)?;
        if share.total() != self.shares || share.threshold() != self.threshold {
            return Err(Error::InvalidShare);
        }
        Ok(share)
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut context = Zeroizing::new(self.context());
        context.extend_from_slice(&self.verifier);
        crypto::digest(&context)
    }
    pub(crate) fn verify_shares(&self, shares: &[SecretShare]) -> Result<(), Error> {
        let secret =
            Zeroizing::new(crypto::combine_shares(shares).map_err(|_| Error::InvalidShare)?);
        self.verify_secret(&secret)
    }

    fn context(&self) -> Vec<u8> {
        let mut value = DOMAIN.to_vec();
        value.extend_from_slice(&self.cluster_binding);
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&[self.shares, self.threshold]);
        if self.codec.is_some() {
            value.extend_from_slice(b"\0indexed33.v1");
        }
        value
    }

    #[cfg(test)]
    fn from_secret(
        secret: &[u8; 32],
        cluster_binding: [u8; 32],
        generation: u64,
        shares: u8,
        threshold: u8,
    ) -> Result<Self, Error> {
        Self::from_secret_with_codec(secret, cluster_binding, generation, shares, threshold, None)
    }
    fn from_secret_with_codec(
        secret: &[u8; 32],
        cluster_binding: [u8; 32],
        generation: u64,
        shares: u8,
        threshold: u8,
        codec: Option<RecoveryCodec>,
    ) -> Result<Self, Error> {
        let mut value = Self {
            schema: if codec.is_some() { 2 } else { 1 },
            generation,
            shares,
            threshold,
            cluster_binding,
            verifier: [0; 32],
            codec,
        };
        value.validate()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        value.verifier = hmac::sign(&key, &value.context())
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidConfiguration)?;
        Ok(value)
    }

    pub(crate) fn generate(
        cluster_binding: [u8; 32],
        generation: u64,
        shares: u8,
        threshold: u8,
    ) -> Result<(Self, Vec<SecretShare>), Error> {
        Self::generate_with_codec(
            cluster_binding,
            generation,
            shares,
            threshold,
            Some(RecoveryCodec::Indexed33),
        )
    }
    pub(crate) fn generate_with_codec(
        cluster_binding: [u8; 32],
        generation: u64,
        shares: u8,
        threshold: u8,
        codec: Option<RecoveryCodec>,
    ) -> Result<(Self, Vec<SecretShare>), Error> {
        // Reject invalid shape before drawing randomness or constructing shares.
        Self {
            schema: if codec.is_some() { 2 } else { 1 },
            generation,
            shares,
            threshold,
            cluster_binding,
            verifier: [0; 32],
            codec,
        }
        .validate()?;
        // A separate CSPRNG draw; this function never accepts a barrier key.
        let secret =
            Zeroizing::new(crypto::random::<32>().map_err(|_| Error::RandomnessUnavailable)?);
        let credential = Self::from_secret_with_codec(
            &secret,
            cluster_binding,
            generation,
            shares,
            threshold,
            codec,
        )?;
        let fragments = crypto::split_secret(&secret, shares, threshold)
            .map_err(|_| Error::RandomnessUnavailable)?;
        Ok((credential, fragments))
    }

    fn verify_secret(&self, secret: &[u8; 32]) -> Result<(), Error> {
        self.validate()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        // Library constant-time MAC verification; no plain secret comparison.
        hmac::verify(&key, &self.context(), &self.verifier).map_err(|_| Error::VerificationRejected)
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Progress {
    Pending { provided: u8, required: u8 },
    Authorized,
}

#[cfg(test)]
pub(crate) struct Accumulator {
    credential: RecoveryCredential,
    nonce: String,
    provided: BTreeMap<u8, SecretShare>,
    authorized: bool,
    invalidated: bool,
}

#[cfg(test)]
impl Accumulator {
    pub(crate) fn new(credential: &RecoveryCredential, nonce: &str) -> Result<Self, Error> {
        credential.validate()?;
        if nonce.is_empty()
            || nonce.len() > 64
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::InvalidNonce);
        }
        Ok(Self {
            credential: credential.clone(),
            nonce: nonce.to_owned(),
            provided: BTreeMap::new(),
            authorized: false,
            invalidated: false,
        })
    }

    pub(crate) fn submit(
        &mut self,
        credential: &RecoveryCredential,
        nonce: &str,
        encoded_fragment: &[u8],
    ) -> Result<Progress, Error> {
        if self.authorized {
            return Err(Error::AlreadyAuthorized);
        }
        if self.invalidated {
            return Err(Error::GenerationChanged);
        }
        if self.credential != *credential {
            self.provided.clear();
            self.invalidated = true;
            return Err(Error::GenerationChanged);
        }
        if nonce != self.nonce {
            return Err(Error::InvalidNonce);
        }
        let fragment = credential.decode_share(encoded_fragment)?;
        if fragment.total() != credential.shares || fragment.threshold() != credential.threshold {
            return Err(Error::InvalidShare);
        }
        if let Some(existing) = self.provided.get(&fragment.index()) {
            if existing != &fragment {
                return Err(Error::InvalidShare);
            }
        } else {
            self.provided.insert(fragment.index(), fragment);
        }
        if self.provided.len() < usize::from(credential.threshold) {
            let provided = u8::try_from(self.provided.len()).map_err(|_| Error::InvalidShare)?;
            return Ok(Progress::Pending {
                provided,
                required: credential.threshold,
            });
        }
        let selected: Vec<_> = self.provided.values().cloned().collect();
        let reconstructed = crypto::combine_shares(&selected).map_err(|_| Error::InvalidShare);
        self.provided.clear();
        let secret = Zeroizing::new(reconstructed?);
        let result = credential.verify_secret(&secret);
        result?;
        self.authorized = true;
        Ok(Progress::Authorized) // No secret/barrier/key/token escapes this helper.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Error>;

    fn random_nonce() -> Result<String, Error> {
        let bytes = crypto::random::<32>().map_err(|_| Error::RandomnessUnavailable)?;
        let hex = b"0123456789abcdef";
        Ok(bytes
            .into_iter()
            .flat_map(|byte| {
                [
                    char::from(hex[usize::from(byte >> 4)]),
                    char::from(hex[usize::from(byte & 15)]),
                ]
            })
            .collect())
    }

    #[test]
    fn real_threshold_duplicate_nonce_and_single_consumption() -> TestResult {
        let nonce = random_nonce()?;
        let mut wrong_nonce = nonce.clone();
        let different = if nonce.starts_with('0') { "1" } else { "0" };
        wrong_nonce.replace_range(..1, different);
        let (credential, fragments) = RecoveryCredential::generate([9; 32], 1, 5, 3)?;
        let mut attempt = Accumulator::new(&credential, &nonce)?;
        assert_eq!(
            attempt.submit(
                &credential,
                &wrong_nonce,
                &credential.encode_share(&fragments[0])?
            ),
            Err(Error::InvalidNonce)
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&fragments[0])?
            ),
            Ok(Progress::Pending {
                provided: 1,
                required: 3
            })
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&fragments[0])?
            ),
            Ok(Progress::Pending {
                provided: 1,
                required: 3
            })
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&fragments[4])?
            ),
            Ok(Progress::Pending {
                provided: 2,
                required: 3
            })
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&fragments[2])?
            ),
            Ok(Progress::Authorized)
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&fragments[1])?
            ),
            Err(Error::AlreadyAuthorized)
        );
        Ok(())
    }

    #[test]
    fn unrelated_threshold_cannot_authorize_and_old_generation_is_rejected() -> TestResult {
        let nonce = random_nonce()?;
        let (credential, _) = RecoveryCredential::generate([9; 32], 1, 5, 3)?;
        let (_, unrelated) = RecoveryCredential::generate([9; 32], 1, 5, 3)?;
        let mut attempt = Accumulator::new(&credential, &nonce)?;
        for fragment in &unrelated[..2] {
            assert!(matches!(
                attempt.submit(&credential, &nonce, &credential.encode_share(fragment)?)?,
                Progress::Pending { .. }
            ));
        }
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&unrelated[2])?
            ),
            Err(Error::VerificationRejected)
        );
        assert!(attempt.provided.is_empty());
        let (next, _) = RecoveryCredential::generate([9; 32], 2, 5, 3)?;
        assert_eq!(
            attempt.submit(&next, &nonce, &credential.encode_share(&unrelated[0])?),
            Err(Error::GenerationChanged)
        );
        assert_eq!(
            attempt.submit(
                &credential,
                &nonce,
                &credential.encode_share(&unrelated[0])?
            ),
            Err(Error::GenerationChanged)
        );
        Ok(())
    }

    #[test]
    fn verifier_is_bound_to_cluster_generation_and_parameters() -> TestResult {
        let secret = Zeroizing::new([7; 32]);
        let credential = RecoveryCredential::from_secret(&secret, [9; 32], 4, 5, 3)?;
        for altered in [
            RecoveryCredential {
                cluster_binding: [8; 32],
                ..credential.clone()
            },
            RecoveryCredential {
                generation: 5,
                ..credential.clone()
            },
            RecoveryCredential {
                shares: 6,
                ..credential.clone()
            },
            RecoveryCredential {
                threshold: 2,
                ..credential.clone()
            },
        ] {
            assert_eq!(
                altered.verify_secret(&secret),
                Err(Error::VerificationRejected)
            );
        }
        assert_eq!(format!("{credential:?}"), "RecoveryCredential([REDACTED])");
        assert_eq!(
            RecoveryCredential::generate([9; 32], 1, 5, 0).map(|_| ()),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            RecoveryCredential::generate([9; 32], 1, 5, 6).map(|_| ()),
            Err(Error::InvalidConfiguration)
        );
        Ok(())
    }
    #[test]
    fn legacy_none_codec_serialization_and_new_codec_generation_are_separate() -> Result<(), String>
    {
        let old = RecoveryCredential::from_secret(&[7; 32], [9; 32], 1, 5, 3)
            .map_err(|error| format!("{error:?}"))?;
        let bytes = serde_json::to_vec(&old).map_err(|error| error.to_string())?;
        assert!(!String::from_utf8_lossy(&bytes).contains("codec"));
        let loaded: RecoveryCredential =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        assert!(loaded.validate().is_ok());
        assert_eq!(
            serde_json::to_vec(&loaded).map_err(|error| error.to_string())?,
            bytes
        );
        let (new, fragments) = RecoveryCredential::generate([9; 32], 2, 255, 2)
            .map_err(|error| format!("{error:?}"))?;
        assert!(new.uses_indexed_wire());
        let encoded = new
            .encode_share(&fragments[254])
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(encoded.len(), 33);
        assert!(loaded.decode_share(&encoded).is_err());
        assert!(new.decode_share(&fragments[254].encode()).is_err());
        let mut confused = new.clone();
        confused.schema = 1;
        assert!(confused.validate().is_err());
        Ok(())
    }
    #[test]
    fn hbs1_existing_credential_can_authorize_new_codec_without_rewriting_it() -> Result<(), String>
    {
        let old = RecoveryCredential::from_secret(&[7; 32], [9; 32], 1, 5, 3)
            .map_err(|error| format!("{error:?}"))?;
        let old_bytes =
            Zeroizing::new(serde_json::to_vec(&old).map_err(|error| error.to_string())?);
        let old_fragments =
            crypto::split_secret(&[7; 32], 5, 3).map_err(|error| error.to_string())?;
        let mut attempt = crate::auth::RecoveryAttempt::new([9; 32], Some(&old), 255, 2, true)
            .map_err(|error| format!("{error:?}"))?;
        let nonce = attempt.nonce.clone();
        for share in &old_fragments[..3] {
            attempt
                .submit(
                    Some(&old),
                    &nonce,
                    &old.encode_share(share)
                        .map_err(|error| format!("{error:?}"))?,
                    false,
                )
                .map_err(|error| format!("{error:?}"))?;
        }
        let (next, fragments) = attempt
            .generate_candidate()
            .map_err(|error| format!("{error:?}"))?;
        assert!(next.uses_indexed_wire());
        assert_eq!(next.generation(), 2);
        assert_eq!(next.shares(), 255);
        let verify = attempt
            .verification_nonce
            .clone()
            .ok_or("missing verification nonce")?;
        assert_eq!(
            attempt
                .submit(
                    Some(&old),
                    &verify,
                    &next
                        .encode_share(&fragments[0])
                        .map_err(|error| format!("{error:?}"))?,
                    true
                )
                .map_err(|error| format!("{error:?}"))?,
            false
        );
        assert_eq!(
            attempt
                .submit(
                    Some(&old),
                    &verify,
                    &next
                        .encode_share(&fragments[254])
                        .map_err(|error| format!("{error:?}"))?,
                    true
                )
                .map_err(|error| format!("{error:?}"))?,
            true
        );
        assert_eq!(
            serde_json::to_vec(&old).map_err(|error| error.to_string())?,
            old_bytes.as_slice()
        );
        Ok(())
    }
}
