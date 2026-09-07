#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Authbus integration contracts for HeptaBao.
//!
//! Authbus may authenticate an external identity and issue a short-lived,
//! request-bound assertion. It is never the authoritative writer for HeptaBao
//! policy, token, lease, namespace, audit, seal or authorization state.
//! This crate deliberately supplies no cryptographic implementation or key.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

use heptabao_protocol::{CanonicalTarget, MAX_HTTP_BODY_BYTES, Method, RequestId};

pub const MAX_ASSERTION_TTL_SECONDS: u64 = 30;
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 5;
pub const MAX_IDENTITY_BYTES: usize = 512;
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub const MAX_IN_MEMORY_REPLAY_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeSeconds(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
}

pub trait CryptographicDigestProvider: fmt::Debug + Send + Sync {
    fn algorithm(&self) -> DigestAlgorithm;
    fn digest(&self, input: &[u8]) -> Result<[u8; 32], AuthbusError>;
}

pub trait AssertionSignatureVerifier: fmt::Debug + Send + Sync {
    fn verify(
        &self,
        key_id: &str,
        signed_payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, AuthbusError>;
}

pub trait ReplayCache: fmt::Debug + Send + Sync {
    fn check_and_record(
        &self,
        issuer: &str,
        nonce: [u8; 16],
        now: UnixTimeSeconds,
        expires_at: UnixTimeSeconds,
    ) -> Result<(), AuthbusError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct RequestBinding<'a> {
    pub request_id: &'a RequestId,
    pub method: Method,
    pub canonical_target: &'a str,
    pub host: &'a str,
    pub body: &'a [u8],
}

impl fmt::Debug for RequestBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBinding")
            .field("request_id", &self.request_id)
            .field("method", &self.method)
            .field("canonical_target_bytes", &self.canonical_target.len())
            .field("host_bytes", &self.host.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl RequestBinding<'_> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthbusError> {
        let canonical_target = CanonicalTarget::parse(self.canonical_target)
            .map_err(|_| AuthbusError::InvalidRequestBinding)?;
        if !canonical_target.matches_canonical(self.canonical_target)
            || self.host.is_empty()
            || self.host.len() > 255
            || !self.host.is_ascii()
            || self.host.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'\\')
            })
            || self.body.len() > MAX_HTTP_BODY_BYTES
        {
            return Err(AuthbusError::InvalidRequestBinding);
        }
        let mut encoded = Vec::new();
        append_field(&mut encoded, b"heptabao-authbus-request-v1")?;
        append_field(&mut encoded, self.request_id.as_str().as_bytes())?;
        append_field(&mut encoded, self.method.as_str().as_bytes())?;
        append_field(&mut encoded, self.canonical_target.as_bytes())?;
        append_field(&mut encoded, self.host.as_bytes())?;
        append_field(&mut encoded, self.body)?;
        Ok(encoded)
    }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthbusError> {
    let length = u64::try_from(value.len()).map_err(|_| AuthbusError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[derive(Eq, PartialEq)]
pub struct AuthbusAssertion {
    pub version: u16,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub key_id: String,
    pub issued_at: UnixTimeSeconds,
    pub expires_at: UnixTimeSeconds,
    pub request_digest: [u8; 32],
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

impl fmt::Debug for AuthbusAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthbusAssertion")
            .field("version", &self.version)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("subject", &"[REDACTED_SUBJECT]")
            .field("key_id", &self.key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("request_digest", &"[REDACTED_DIGEST]")
            .field("nonce", &"[REDACTED_NONCE]")
            .field("signature", &"[REDACTED_SIGNATURE]")
            .finish()
    }
}

impl AuthbusAssertion {
    pub fn unsigned_payload(&self) -> Result<Vec<u8>, AuthbusError> {
        let mut encoded = Vec::new();
        append_field(&mut encoded, b"heptabao-authbus-assertion-v1")?;
        append_field(&mut encoded, &self.version.to_be_bytes())?;
        append_field(&mut encoded, self.issuer.as_bytes())?;
        append_field(&mut encoded, self.audience.as_bytes())?;
        append_field(&mut encoded, self.subject.as_bytes())?;
        append_field(&mut encoded, self.key_id.as_bytes())?;
        append_field(&mut encoded, &self.issued_at.0.to_be_bytes())?;
        append_field(&mut encoded, &self.expires_at.0.to_be_bytes())?;
        append_field(&mut encoded, &self.request_digest)?;
        append_field(&mut encoded, &self.nonce)?;
        Ok(encoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    pub required_issuer: String,
    pub required_audience: String,
    pub maximum_ttl_seconds: u64,
    pub maximum_future_skew_seconds: u64,
    pub allowed_key_ids: BTreeSet<String>,
}

impl VerificationPolicy {
    pub fn validate(&self) -> Result<(), AuthbusError> {
        validate_identity(&self.required_issuer)?;
        validate_identity(&self.required_audience)?;
        if self.maximum_ttl_seconds == 0
            || self.maximum_ttl_seconds > MAX_ASSERTION_TTL_SECONDS
            || self.maximum_future_skew_seconds > MAX_CLOCK_SKEW_SECONDS
        {
            return Err(AuthbusError::InvalidPolicy);
        }
        if self.allowed_key_ids.is_empty() {
            return Err(AuthbusError::InvalidPolicy);
        }
        for key_id in &self.allowed_key_ids {
            validate_identity(key_id)?;
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
pub struct VerifiedAuthbusIdentity {
    pub issuer: String,
    pub subject: String,
    pub key_id: String,
    pub assertion_expires_at: UnixTimeSeconds,
    pub authorization_effect: AuthorizationEffect,
}

impl fmt::Debug for VerifiedAuthbusIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthbusIdentity")
            .field("issuer", &self.issuer)
            .field("subject", &"[REDACTED_SUBJECT]")
            .field("key_id", &self.key_id)
            .field("assertion_expires_at", &self.assertion_expires_at)
            .field("authorization_effect", &self.authorization_effect)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationEffect {
    None,
}

pub fn verify_bound_assertion(
    assertion: &AuthbusAssertion,
    request: &RequestBinding<'_>,
    now: UnixTimeSeconds,
    policy: &VerificationPolicy,
    digest_provider: &dyn CryptographicDigestProvider,
    signature_verifier: &dyn AssertionSignatureVerifier,
    replay_cache: &dyn ReplayCache,
) -> Result<VerifiedAuthbusIdentity, AuthbusError> {
    policy.validate()?;
    validate_assertion_shape(assertion)?;
    if digest_provider.algorithm() != DigestAlgorithm::Sha256 {
        return Err(AuthbusError::UnsupportedDigestAlgorithm);
    }
    if assertion.version != 1 {
        return Err(AuthbusError::UnsupportedAssertionVersion);
    }
    if assertion.issuer != policy.required_issuer || assertion.audience != policy.required_audience
    {
        return Err(AuthbusError::IssuerOrAudienceMismatch);
    }
    if !policy.allowed_key_ids.contains(&assertion.key_id) {
        return Err(AuthbusError::KeyNotAllowed);
    }
    if assertion.expires_at <= assertion.issued_at {
        return Err(AuthbusError::InvalidLifetime);
    }
    let ttl = assertion.expires_at.0 - assertion.issued_at.0;
    if ttl > policy.maximum_ttl_seconds {
        return Err(AuthbusError::LifetimeTooLong);
    }
    let latest_acceptable_issue_time = now
        .0
        .checked_add(policy.maximum_future_skew_seconds)
        .ok_or(AuthbusError::ClockOverflow)?;
    if assertion.issued_at.0 > latest_acceptable_issue_time {
        return Err(AuthbusError::NotYetValid);
    }
    if now >= assertion.expires_at {
        return Err(AuthbusError::Expired);
    }
    let mut canonical_request = request.canonical_bytes()?;
    let digest_result = digest_provider.digest(&canonical_request);
    canonical_request.fill(0);
    let expected_digest = digest_result?;
    if !constant_time_equal(&expected_digest, &assertion.request_digest) {
        return Err(AuthbusError::RequestBindingMismatch);
    }
    let mut payload = assertion.unsigned_payload()?;
    let signature_result =
        signature_verifier.verify(&assertion.key_id, &payload, &assertion.signature);
    payload.fill(0);
    if !signature_result? {
        return Err(AuthbusError::InvalidSignature);
    }
    replay_cache.check_and_record(
        &assertion.issuer,
        assertion.nonce,
        now,
        assertion.expires_at,
    )?;
    Ok(VerifiedAuthbusIdentity {
        issuer: assertion.issuer.clone(),
        subject: assertion.subject.clone(),
        key_id: assertion.key_id.clone(),
        assertion_expires_at: assertion.expires_at,
        authorization_effect: AuthorizationEffect::None,
    })
}

fn validate_assertion_shape(assertion: &AuthbusAssertion) -> Result<(), AuthbusError> {
    validate_identity(&assertion.issuer)?;
    validate_identity(&assertion.audience)?;
    validate_identity(&assertion.subject)?;
    validate_identity(&assertion.key_id)?;
    if assertion.request_digest == [0; 32] || assertion.nonce == [0; 16] {
        return Err(AuthbusError::InvalidAssertion);
    }
    if assertion.signature.is_empty() || assertion.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(AuthbusError::InvalidAssertion);
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<(), AuthbusError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\\'))
    {
        return Err(AuthbusError::InvalidIdentity);
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

pub struct InMemoryReplayCache {
    observed: Mutex<BTreeMap<(String, [u8; 16]), UnixTimeSeconds>>,
    max_entries: usize,
}

impl fmt::Debug for InMemoryReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryReplayCache")
            .field("observed", &"[REDACTED]")
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self {
            observed: Mutex::new(BTreeMap::new()),
            max_entries: MAX_IN_MEMORY_REPLAY_ENTRIES,
        }
    }
}

impl InMemoryReplayCache {
    pub fn with_capacity(max_entries: usize) -> Result<Self, AuthbusError> {
        if max_entries == 0 || max_entries > MAX_IN_MEMORY_REPLAY_ENTRIES {
            return Err(AuthbusError::InvalidReplayCacheCapacity);
        }
        Ok(Self {
            observed: Mutex::new(BTreeMap::new()),
            max_entries,
        })
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_record(
        &self,
        issuer: &str,
        nonce: [u8; 16],
        now: UnixTimeSeconds,
        expires_at: UnixTimeSeconds,
    ) -> Result<(), AuthbusError> {
        if expires_at <= now {
            return Err(AuthbusError::Expired);
        }
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| AuthbusError::ReplayCacheFailure)?;
        observed.retain(|_, recorded_expiry| *recorded_expiry > now);
        let current_len = observed.len();
        let key = (issuer.to_owned(), nonce);
        match observed.entry(key) {
            Entry::Occupied(_) => Err(AuthbusError::ReplayDetected),
            Entry::Vacant(entry) => {
                if current_len >= self.max_entries {
                    return Err(AuthbusError::ReplayCacheSaturated);
                }
                entry.insert(expires_at);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthbusError {
    InvalidRequestBinding,
    LengthOverflow,
    InvalidPolicy,
    InvalidIdentity,
    InvalidAssertion,
    InvalidReplayCacheCapacity,
    UnsupportedDigestAlgorithm,
    UnsupportedAssertionVersion,
    IssuerOrAudienceMismatch,
    KeyNotAllowed,
    InvalidLifetime,
    LifetimeTooLong,
    NotYetValid,
    Expired,
    RequestBindingMismatch,
    InvalidSignature,
    ReplayDetected,
    ReplayCacheFailure,
    ReplayCacheSaturated,
    DigestProviderFailure,
    SignatureProviderFailure,
    ClockOverflow,
}

impl fmt::Display for AuthbusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequestBinding => "request binding is invalid",
            Self::LengthOverflow => "canonical field length overflow",
            Self::InvalidPolicy => "verification policy is invalid",
            Self::InvalidIdentity => "identity field is invalid",
            Self::InvalidAssertion => "assertion shape is invalid",
            Self::InvalidReplayCacheCapacity => "replay cache capacity is invalid",
            Self::UnsupportedDigestAlgorithm => "digest algorithm is unsupported",
            Self::UnsupportedAssertionVersion => "assertion version is unsupported",
            Self::IssuerOrAudienceMismatch => "issuer or audience does not match policy",
            Self::KeyNotAllowed => "signing key is not allowed",
            Self::InvalidLifetime => "assertion lifetime is invalid",
            Self::LifetimeTooLong => "assertion lifetime exceeds policy",
            Self::NotYetValid => "assertion is not yet valid",
            Self::Expired => "assertion is expired",
            Self::RequestBindingMismatch => "assertion is bound to another request",
            Self::InvalidSignature => "assertion signature is invalid",
            Self::ReplayDetected => "assertion replay was detected",
            Self::ReplayCacheFailure => "replay cache failed",
            Self::ReplayCacheSaturated => "replay cache is saturated",
            Self::DigestProviderFailure => "digest provider failed",
            Self::SignatureProviderFailure => "signature provider failed",
            Self::ClockOverflow => "wall-clock bound overflow",
        })
    }
}

impl Error for AuthbusError {}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_protocol::RequestId;

    #[derive(Debug)]
    struct TestDigest;

    impl CryptographicDigestProvider for TestDigest {
        fn algorithm(&self) -> DigestAlgorithm {
            DigestAlgorithm::Sha256
        }

        fn digest(&self, input: &[u8]) -> Result<[u8; 32], AuthbusError> {
            let mut output = [0_u8; 32];
            for (index, byte) in input.iter().copied().enumerate() {
                let slot = index % output.len();
                output[slot] = output[slot]
                    .wrapping_add(byte)
                    .rotate_left((slot % 7) as u32);
            }
            if output == [0; 32] {
                return Err(AuthbusError::DigestProviderFailure);
            }
            Ok(output)
        }
    }

    #[derive(Debug)]
    struct TestSignature;

    impl AssertionSignatureVerifier for TestSignature {
        fn verify(
            &self,
            key_id: &str,
            signed_payload: &[u8],
            signature: &[u8],
        ) -> Result<bool, AuthbusError> {
            Ok(key_id == "key-1" && !signed_payload.is_empty() && signature == b"valid")
        }
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy {
            required_issuer: "authbus.dev".to_owned(),
            required_audience: "heptabao.dev".to_owned(),
            maximum_ttl_seconds: 30,
            maximum_future_skew_seconds: 2,
            allowed_key_ids: BTreeSet::from(["key-1".to_owned()]),
        }
    }

    fn binding(request_id: &RequestId) -> RequestBinding<'_> {
        RequestBinding {
            request_id,
            method: Method::Get,
            canonical_target: "/v1/secret/example",
            host: "127.0.0.1",
            body: b"",
        }
    }

    fn assertion(request: &RequestBinding<'_>) -> AuthbusAssertion {
        let mut canonical = request.canonical_bytes().unwrap_or_default();
        let digest = TestDigest.digest(&canonical);
        canonical.fill(0);
        let request_digest = digest.unwrap_or([1; 32]);
        AuthbusAssertion {
            version: 1,
            issuer: "authbus.dev".to_owned(),
            audience: "heptabao.dev".to_owned(),
            subject: "user:alice".to_owned(),
            key_id: "key-1".to_owned(),
            issued_at: UnixTimeSeconds(10),
            expires_at: UnixTimeSeconds(30),
            request_digest,
            nonce: [7; 16],
            signature: b"valid".to_vec(),
        }
    }

    #[test]
    fn valid_assertion_authenticates_but_does_not_authorize() {
        let request_id = RequestId::new("request-0001".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let assertion = assertion(&request);
            let cache = InMemoryReplayCache::default();
            let result = verify_bound_assertion(
                &assertion,
                &request,
                UnixTimeSeconds(20),
                &policy(),
                &TestDigest,
                &TestSignature,
                &cache,
            );
            assert!(result.is_ok());
            if let Ok(identity) = result {
                assert_eq!(identity.subject, "user:alice");
                assert_eq!(identity.authorization_effect, AuthorizationEffect::None);
                assert!(!format!("{identity:?}").contains("user:alice"));
            }
        }
    }

    #[test]
    fn request_binding_debug_redacts_target_host_and_body() {
        let request_id = RequestId::new("request-redaction-0001".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = RequestBinding {
                request_id: &request_id,
                method: Method::Post,
                canonical_target: "/v1/secret/private-path",
                host: "sensitive.internal",
                body: b"body-secret",
            };
            let rendered = format!("{request:?}");
            assert!(!rendered.contains("private-path"));
            assert!(!rendered.contains("sensitive.internal"));
            assert!(!rendered.contains("body-secret"));
            assert!(rendered.contains("body_bytes"));
        }
    }

    #[test]
    fn assertion_debug_redacts_subject_and_cryptographic_fields() {
        let request_id = RequestId::new("request-redaction-0002".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let assertion = assertion(&request);
            let rendered = format!("{assertion:?}");
            assert!(!rendered.contains("user:alice"));
            assert!(!rendered.contains("[7, 7"));
            assert!(!rendered.contains("valid"));
        }
    }

    #[test]
    fn request_binding_mismatch_is_rejected() {
        let request_id = RequestId::new("request-0002".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let assertion = assertion(&request);
            let altered = RequestBinding {
                canonical_target: "/v1/secret/other",
                ..request
            };
            let result = verify_bound_assertion(
                &assertion,
                &altered,
                UnixTimeSeconds(20),
                &policy(),
                &TestDigest,
                &TestSignature,
                &InMemoryReplayCache::default(),
            );
            assert_eq!(result, Err(AuthbusError::RequestBindingMismatch));
        }
    }

    #[test]
    fn replay_is_rejected() {
        let request_id = RequestId::new("request-0003".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let assertion = assertion(&request);
            let cache = InMemoryReplayCache::default();
            let first = verify_bound_assertion(
                &assertion,
                &request,
                UnixTimeSeconds(20),
                &policy(),
                &TestDigest,
                &TestSignature,
                &cache,
            );
            assert!(first.is_ok());
            let second = verify_bound_assertion(
                &assertion,
                &request,
                UnixTimeSeconds(20),
                &policy(),
                &TestDigest,
                &TestSignature,
                &cache,
            );
            assert_eq!(second, Err(AuthbusError::ReplayDetected));
        }
    }

    #[test]
    fn replay_cache_saturation_fails_closed() {
        let cache = InMemoryReplayCache::with_capacity(1);
        assert!(cache.is_ok());
        if let Ok(cache) = cache {
            assert!(
                cache
                    .check_and_record(
                        "authbus.dev",
                        [1; 16],
                        UnixTimeSeconds(10),
                        UnixTimeSeconds(20),
                    )
                    .is_ok()
            );
            assert_eq!(
                cache.check_and_record(
                    "authbus.dev",
                    [2; 16],
                    UnixTimeSeconds(10),
                    UnixTimeSeconds(20),
                ),
                Err(AuthbusError::ReplayCacheSaturated)
            );
        }
    }

    #[test]
    fn invalid_replay_cache_capacity_is_rejected() {
        assert!(matches!(
            InMemoryReplayCache::with_capacity(0),
            Err(AuthbusError::InvalidReplayCacheCapacity)
        ));
        assert!(matches!(
            InMemoryReplayCache::with_capacity(MAX_IN_MEMORY_REPLAY_ENTRIES + 1),
            Err(AuthbusError::InvalidReplayCacheCapacity)
        ));
    }

    #[test]
    fn future_issue_time_respects_bounded_skew() {
        let request_id = RequestId::new("request-0005".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let mut value = assertion(&request);
            value.issued_at = UnixTimeSeconds(23);
            value.expires_at = UnixTimeSeconds(30);
            assert_eq!(
                verify_bound_assertion(
                    &value,
                    &request,
                    UnixTimeSeconds(20),
                    &policy(),
                    &TestDigest,
                    &TestSignature,
                    &InMemoryReplayCache::default(),
                ),
                Err(AuthbusError::NotYetValid)
            );
            value.issued_at = UnixTimeSeconds(22);
            assert!(
                verify_bound_assertion(
                    &value,
                    &request,
                    UnixTimeSeconds(20),
                    &policy(),
                    &TestDigest,
                    &TestSignature,
                    &InMemoryReplayCache::default(),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn replay_cache_prunes_expired_entries() {
        let cache = InMemoryReplayCache::with_capacity(1);
        assert!(cache.is_ok());
        if let Ok(cache) = cache {
            assert!(
                cache
                    .check_and_record(
                        "authbus.dev",
                        [9; 16],
                        UnixTimeSeconds(10),
                        UnixTimeSeconds(11),
                    )
                    .is_ok()
            );
            assert!(
                cache
                    .check_and_record(
                        "authbus.dev",
                        [8; 16],
                        UnixTimeSeconds(11),
                        UnixTimeSeconds(12),
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    fn expiry_key_and_signature_fail_closed() {
        let request_id = RequestId::new("request-0004".to_owned());
        assert!(request_id.is_ok());
        if let Ok(request_id) = request_id {
            let request = binding(&request_id);
            let mut value = assertion(&request);
            assert_eq!(
                verify_bound_assertion(
                    &value,
                    &request,
                    UnixTimeSeconds(30),
                    &policy(),
                    &TestDigest,
                    &TestSignature,
                    &InMemoryReplayCache::default(),
                ),
                Err(AuthbusError::Expired)
            );
            value.expires_at = UnixTimeSeconds(50);
            value.key_id = "key-2".to_owned();
            assert_eq!(
                verify_bound_assertion(
                    &value,
                    &request,
                    UnixTimeSeconds(20),
                    &policy(),
                    &TestDigest,
                    &TestSignature,
                    &InMemoryReplayCache::default(),
                ),
                Err(AuthbusError::KeyNotAllowed)
            );
            value.key_id = "key-1".to_owned();
            value.expires_at = UnixTimeSeconds(30);
            value.signature = b"invalid".to_vec();
            assert_eq!(
                verify_bound_assertion(
                    &value,
                    &request,
                    UnixTimeSeconds(20),
                    &policy(),
                    &TestDigest,
                    &TestSignature,
                    &InMemoryReplayCache::default(),
                ),
                Err(AuthbusError::InvalidSignature)
            );
        }
    }
}
