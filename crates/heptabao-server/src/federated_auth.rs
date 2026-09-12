#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Signed external-identity verification and durable replay admission.
//!
//! The verifier accepts only explicitly configured JWS algorithms and key IDs,
//! rejects duplicate top-level JSON members, binds issuer, audience, namespace
//! and time claims, and records a token fingerprint durably before returning a
//! principal. MFA proofs are HMAC authenticated and channel-bound, and use the
//! same accepted-before-release replay ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroize;

use base64::Engine;
use ring::{digest, hmac, signature};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_JSON_BYTES: usize = 12 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_STRING_BYTES: usize = 1024;
const MAX_GROUPS: usize = 512;
const MAX_REPLAY_ENTRIES: usize = 1_000_000;
const REPLAY_MAGIC: &[u8; 5] = b"HBRL1";
const REPLAY_BODY_BYTES: usize = 5 + 8 + 32 + 8 + 32;
const REPLAY_TAG_BYTES: usize = 32;
const REPLAY_FRAME_BYTES: usize = REPLAY_BODY_BYTES + REPLAY_TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAlgorithm {
    Ed25519,
    Es256,
}

impl JwtAlgorithm {
    fn header_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerificationKey {
    key_id: String,
    algorithm: JwtAlgorithm,
    bytes: Vec<u8>,
}

impl VerificationKey {
    pub fn new(
        key_id: impl Into<String>,
        algorithm: JwtAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, AuthError> {
        let key_id = checked_string(key_id.into())?;
        let valid_encoding = match algorithm {
            JwtAlgorithm::Ed25519 => bytes.len() == 32,
            JwtAlgorithm::Es256 => bytes.len() == 65 && bytes.first() == Some(&4),
        };
        if !valid_encoding || bytes.len() > MAX_KEY_BYTES {
            return Err(AuthError::InvalidKey);
        }
        Ok(Self {
            key_id,
            algorithm,
            bytes,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl fmt::Debug for VerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPolicy {
    issuer: String,
    audiences: BTreeSet<String>,
    required_namespace: Option<String>,
    clock_skew_seconds: u64,
    maximum_token_lifetime_seconds: u64,
}

impl TrustPolicy {
    pub fn new(
        issuer: impl Into<String>,
        audiences: BTreeSet<String>,
        required_namespace: Option<String>,
        clock_skew_seconds: u64,
        maximum_token_lifetime_seconds: u64,
    ) -> Result<Self, AuthError> {
        let issuer = checked_string(issuer.into())?;
        if audiences.is_empty()
            || audiences.len() > 64
            || audiences
                .iter()
                .any(|audience| checked_string(audience.clone()).is_err())
            || clock_skew_seconds > 300
            || !(1..=86_400).contains(&maximum_token_lifetime_seconds)
        {
            return Err(AuthError::InvalidPolicy);
        }
        let required_namespace = required_namespace.map(checked_string).transpose()?;
        Ok(Self {
            issuer,
            audiences,
            required_namespace,
            clock_skew_seconds,
            maximum_token_lifetime_seconds,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    pub issuer: String,
    pub subject: String,
    pub audiences: BTreeSet<String>,
    pub namespace: Option<String>,
    pub groups: BTreeSet<String>,
    pub token_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl VerifiedPrincipal {
    /// Stable replay identity, to be committed in the same authorization
    /// transaction as any token issued from this verified assertion.
    pub fn replay_fingerprint(&self) -> [u8; 32] {
        let mut replay_identity = Vec::with_capacity(
            self.issuer.len()
                + self.subject.len()
                + self.token_id.len()
                + self.namespace.as_ref().map_or(0, String::len)
                + 4,
        );
        for value in [
            self.issuer.as_str(),
            self.subject.as_str(),
            self.namespace.as_deref().unwrap_or(""),
            self.token_id.as_str(),
        ] {
            replay_identity.extend_from_slice(value.as_bytes());
            replay_identity.push(0);
        }
        digest_bytes(&replay_identity)
    }
}

#[derive(Debug)]
pub struct JwtVerifier {
    policy: TrustPolicy,
    keys: BTreeMap<String, VerificationKey>,
}

impl JwtVerifier {
    pub fn new(
        policy: TrustPolicy,
        keys: impl IntoIterator<Item = VerificationKey>,
    ) -> Result<Self, AuthError> {
        let mut by_id = BTreeMap::new();
        for key in keys {
            if by_id.insert(key.key_id.clone(), key).is_some() {
                return Err(AuthError::DuplicateKeyId);
            }
        }
        if by_id.is_empty() {
            return Err(AuthError::InvalidKey);
        }
        Ok(Self {
            policy,
            keys: by_id,
        })
    }

    /// Verify the signed assertion without granting an application capability.
    /// The caller still owns role authorization and durable replay admission;
    /// `heptabao-server` commits both with token issuance in its encrypted state.
    pub fn verify(&self, token: &str, now: u64) -> Result<VerifiedPrincipal, AuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
            return Err(AuthError::MalformedToken);
        }
        let mut parts = token.split('.');
        let encoded_header = parts.next().ok_or(AuthError::MalformedToken)?;
        let encoded_claims = parts.next().ok_or(AuthError::MalformedToken)?;
        let encoded_signature = parts.next().ok_or(AuthError::MalformedToken)?;
        if parts.next().is_some()
            || encoded_header.is_empty()
            || encoded_claims.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(AuthError::MalformedToken);
        }
        let header_bytes = decode_segment(encoded_header)?;
        let claims_bytes = decode_segment(encoded_claims)?;
        let signature_bytes = decode_segment(encoded_signature)?;
        if header_bytes.len() > MAX_JSON_BYTES || claims_bytes.len() > MAX_JSON_BYTES {
            return Err(AuthError::MalformedToken);
        }
        let mut header = parse_unique_object(&header_bytes)?;
        let algorithm_name = take_string(&mut header, "alg")?;
        let key_id = take_string(&mut header, "kid")?;
        if let Some(typ) = take_optional_string(&mut header, "typ")?
            && typ != "JWT"
        {
            return Err(AuthError::MalformedToken);
        }
        if !header.is_empty() {
            return Err(AuthError::MalformedToken);
        }
        let key = self.keys.get(&key_id).ok_or(AuthError::UnknownKeyId)?;
        if algorithm_name != key.algorithm.header_name() {
            return Err(AuthError::AlgorithmDenied);
        }
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        verify_signature(key, signing_input.as_bytes(), &signature_bytes)?;

        let mut claims = parse_unique_object(&claims_bytes)?;
        let issuer = take_string(&mut claims, "iss")?;
        let subject = take_string(&mut claims, "sub")?;
        let audiences = take_audiences(&mut claims)?;
        let expires_at = take_u64(&mut claims, "exp")?;
        let issued_at = take_u64(&mut claims, "iat")?;
        let not_before = take_optional_u64(&mut claims, "nbf")?.unwrap_or(issued_at);
        let token_id = take_string(&mut claims, "jti")?;
        let namespace = take_optional_string(&mut claims, "heptabao_namespace")?;
        let groups = take_string_set(&mut claims, "groups")?;

        if issuer != self.policy.issuer
            || audiences.is_disjoint(&self.policy.audiences)
            || self
                .policy
                .required_namespace
                .as_ref()
                .is_some_and(|required| namespace.as_ref() != Some(required))
        {
            return Err(AuthError::ClaimDenied);
        }
        let skew = self.policy.clock_skew_seconds;
        if now.saturating_add(skew) < not_before
            || issued_at > now.saturating_add(skew)
            || expires_at <= now
            || expires_at <= issued_at
            || not_before >= expires_at
            || expires_at - issued_at > self.policy.maximum_token_lifetime_seconds
        {
            return Err(AuthError::TokenTimeInvalid);
        }
        Ok(VerifiedPrincipal {
            issuer,
            subject,
            audiences,
            namespace,
            groups,
            token_id,
            issued_at,
            expires_at,
        })
    }

    pub fn verify_and_record(
        &self,
        token: &str,
        now: u64,
        replay: &mut PersistentReplayLedger,
    ) -> Result<VerifiedPrincipal, AuthError> {
        let principal = self.verify(token, now)?;
        replay.record_once(principal.replay_fingerprint(), principal.expires_at, now)?;
        Ok(principal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaProof {
    pub subject: String,
    pub factor_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub channel_binding: [u8; 32],
    pub tag: [u8; 32],
}

impl MfaProof {
    pub fn sign(
        subject: impl Into<String>,
        factor_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        nonce: [u8; 16],
        channel_binding: [u8; 32],
        secret: [u8; 32],
    ) -> Result<Self, AuthError> {
        let subject = checked_string(subject.into())?;
        let factor_id = checked_string(factor_id.into())?;
        if secret == [0; 32]
            || nonce == [0; 16]
            || channel_binding == [0; 32]
            || expires_at <= issued_at
            || expires_at - issued_at > 300
        {
            return Err(AuthError::InvalidMfaProof);
        }
        let body = encode_mfa_body(
            &subject,
            &factor_id,
            issued_at,
            expires_at,
            nonce,
            channel_binding,
        )?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let tag = hmac::sign(&key, &body)
            .as_ref()
            .try_into()
            .map_err(|_| AuthError::InvalidMfaProof)?;
        Ok(Self {
            subject,
            factor_id,
            issued_at,
            expires_at,
            nonce,
            channel_binding,
            tag,
        })
    }
}

pub struct MfaVerifier {
    secret: [u8; 32],
    clock_skew_seconds: u64,
}

impl MfaVerifier {
    pub fn new(secret: [u8; 32], clock_skew_seconds: u64) -> Result<Self, AuthError> {
        if secret == [0; 32] || clock_skew_seconds > 60 {
            return Err(AuthError::InvalidPolicy);
        }
        Ok(Self {
            secret,
            clock_skew_seconds,
        })
    }

    /// Verify a proof and return its replay identity without recording it.
    /// Callers must durably admit that identity before releasing authorization.
    pub fn verify(
        &self,
        proof: &MfaProof,
        expected_subject: &str,
        expected_channel_binding: [u8; 32],
        now: u64,
    ) -> Result<[u8; 32], AuthError> {
        if proof.subject != expected_subject
            || proof.channel_binding != expected_channel_binding
            || proof.nonce == [0; 16]
            || expected_channel_binding == [0; 32]
            || proof.expires_at <= proof.issued_at
            || proof.expires_at - proof.issued_at > 300
            || now.saturating_add(self.clock_skew_seconds) < proof.issued_at
            || proof.expires_at.saturating_add(self.clock_skew_seconds) < now
        {
            return Err(AuthError::InvalidMfaProof);
        }
        let body = encode_mfa_body(
            &proof.subject,
            &proof.factor_id,
            proof.issued_at,
            proof.expires_at,
            proof.nonce,
            proof.channel_binding,
        )?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        hmac::verify(&key, &body, &proof.tag).map_err(|_| AuthError::InvalidMfaProof)?;
        let mut replay_material = body;
        replay_material.extend_from_slice(&proof.tag);
        Ok(digest_bytes(&replay_material))
    }

    pub fn verify_and_record(
        &self,
        proof: &MfaProof,
        expected_subject: &str,
        expected_channel_binding: [u8; 32],
        now: u64,
        replay: &mut PersistentReplayLedger,
    ) -> Result<(), AuthError> {
        let fingerprint = self.verify(proof, expected_subject, expected_channel_binding, now)?;
        replay.record_once(fingerprint, proof.expires_at, now)
    }
}

impl fmt::Debug for MfaVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaVerifier")
            .field("secret", &"[REDACTED]")
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .finish()
    }
}

impl Drop for MfaVerifier {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

pub struct PersistentReplayLedger {
    root: PathBuf,
    ledger_path: PathBuf,
    lock_path: PathBuf,
    ledger: File,
    _lock: File,
    key: [u8; 32],
    next_sequence: u64,
    previous_tag: [u8; 32],
    entries: BTreeMap<[u8; 32], u64>,
}

impl PersistentReplayLedger {
    pub fn open(root: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, AuthError> {
        if key == [0; 32] {
            return Err(AuthError::InvalidKey);
        }
        let root = root.as_ref().to_path_buf();
        validate_root(&root)?;
        create_private_root(&root)?;
        let lock_path = root.join("writer.lock");
        let ledger_path = root.join("replay.ledger");
        let lock = create_lock(&lock_path)?;
        let mut ledger = open_ledger(&ledger_path)?;
        let recovered = recover_replay(&mut ledger, key)?;
        let observed_len = ledger.metadata().map_err(|_| AuthError::Io)?.len();
        if recovered.valid_bytes < observed_len {
            ledger
                .set_len(recovered.valid_bytes)
                .and_then(|()| ledger.sync_all())
                .map_err(|_| AuthError::Io)?;
        }
        ledger.seek(SeekFrom::End(0)).map_err(|_| AuthError::Io)?;
        Ok(Self {
            root,
            ledger_path,
            lock_path,
            ledger,
            _lock: lock,
            key,
            next_sequence: recovered
                .last_sequence
                .checked_add(1)
                .ok_or(AuthError::CapacityExceeded)?,
            previous_tag: recovered.previous_tag,
            entries: recovered.entries,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub fn record_once(
        &mut self,
        fingerprint: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), AuthError> {
        if fingerprint == [0; 32] || expires_at < now {
            return Err(AuthError::ReplayRecordInvalid);
        }
        self.entries.retain(|_, expiry| *expiry >= now);
        if self
            .entries
            .get(&fingerprint)
            .is_some_and(|expiry| *expiry >= now)
        {
            return Err(AuthError::ReplayDetected);
        }
        if self.entries.len() >= MAX_REPLAY_ENTRIES {
            return Err(AuthError::CapacityExceeded);
        }
        let body = encode_replay_body(
            self.next_sequence,
            fingerprint,
            expires_at,
            self.previous_tag,
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let tag = hmac::sign(&key, &body);
        let mut frame = Vec::with_capacity(4 + REPLAY_FRAME_BYTES);
        frame.extend_from_slice(&(REPLAY_FRAME_BYTES as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame.extend_from_slice(tag.as_ref());
        if self.ledger.write_all(&frame).is_err()
            || self.ledger.flush().is_err()
            || self.ledger.sync_all().is_err()
        {
            return Err(AuthError::OutcomeUnknown);
        }
        self.previous_tag.copy_from_slice(tag.as_ref());
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AuthError::CapacityExceeded)?;
        self.entries.insert(fingerprint, expires_at);
        Ok(())
    }
}

impl fmt::Debug for PersistentReplayLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentReplayLedger")
            .field("root", &self.root)
            .field("ledger_path", &self.ledger_path)
            .field("key", &"[REDACTED]")
            .field("next_sequence", &self.next_sequence)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl Drop for PersistentReplayLedger {
    fn drop(&mut self) {
        self.key.zeroize();
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    MalformedToken,
    DuplicateJsonKey,
    InvalidJson,
    MissingClaim,
    InvalidClaim,
    InvalidPolicy,
    InvalidKey,
    DuplicateKeyId,
    UnknownKeyId,
    AlgorithmDenied,
    SignatureInvalid,
    ClaimDenied,
    TokenTimeInvalid,
    ReplayDetected,
    ReplayRecordInvalid,
    InvalidMfaProof,
    WriterBusy,
    Tampered,
    CapacityExceeded,
    OutcomeUnknown,
    InvalidRoot,
    Io,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedToken => "federated token is malformed",
            Self::DuplicateJsonKey => "federated token contains a duplicate JSON member",
            Self::InvalidJson => "federated token JSON is invalid",
            Self::MissingClaim => "required federated claim is missing",
            Self::InvalidClaim => "federated claim has an invalid type or value",
            Self::InvalidPolicy => "federated trust policy is invalid",
            Self::InvalidKey => "federated verification or replay key is invalid",
            Self::DuplicateKeyId => "federated verification key ID is duplicated",
            Self::UnknownKeyId => "federated verification key ID is unknown",
            Self::AlgorithmDenied => "federated signature algorithm is denied",
            Self::SignatureInvalid => "federated token signature is invalid",
            Self::ClaimDenied => "federated token claims are outside policy",
            Self::TokenTimeInvalid => "federated token time window is invalid",
            Self::ReplayDetected => "federated authentication replay was detected",
            Self::ReplayRecordInvalid => "federated replay record is invalid",
            Self::InvalidMfaProof => "MFA proof is invalid",
            Self::WriterBusy => "replay ledger already has a writer",
            Self::Tampered => "replay ledger authentication failed",
            Self::CapacityExceeded => "replay ledger capacity is exceeded",
            Self::OutcomeUnknown => "replay ledger durable outcome is unknown",
            Self::InvalidRoot => "replay ledger root is invalid",
            Self::Io => "federated authentication I/O failed",
        })
    }
}

impl Error for AuthError {}

#[derive(Debug)]
struct UniqueObject(BTreeMap<String, Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object without duplicate members")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(UniqueObject(values))
            }
        }
        deserializer.deserialize_map(UniqueVisitor)
    }
}

fn parse_unique_object(bytes: &[u8]) -> Result<BTreeMap<String, Value>, AuthError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let object = UniqueObject::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains("duplicate JSON member") {
            AuthError::DuplicateJsonKey
        } else {
            AuthError::InvalidJson
        }
    })?;
    deserializer.end().map_err(|_| AuthError::InvalidJson)?;
    Ok(object.0)
}

fn decode_segment(value: &str) -> Result<Vec<u8>, AuthError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthError::MalformedToken)
}

fn verify_signature(
    key: &VerificationKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AuthError> {
    let result = match key.algorithm {
        JwtAlgorithm::Ed25519 => signature::UnparsedPublicKey::new(&signature::ED25519, &key.bytes)
            .verify(message, signature_bytes),
        JwtAlgorithm::Es256 => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &key.bytes)
                .verify(message, signature_bytes)
        }
    };
    result.map_err(|_| AuthError::SignatureInvalid)
}

fn take_string(values: &mut BTreeMap<String, Value>, name: &str) -> Result<String, AuthError> {
    match values.remove(name) {
        Some(Value::String(value)) => checked_string(value),
        Some(_) => Err(AuthError::InvalidClaim),
        None => Err(AuthError::MissingClaim),
    }
}

fn take_optional_string(
    values: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<String>, AuthError> {
    match values.remove(name) {
        Some(Value::String(value)) => checked_string(value).map(Some),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(AuthError::InvalidClaim),
    }
}

fn take_u64(values: &mut BTreeMap<String, Value>, name: &str) -> Result<u64, AuthError> {
    match values.remove(name) {
        Some(Value::Number(value)) => value.as_u64().ok_or(AuthError::InvalidClaim),
        Some(_) => Err(AuthError::InvalidClaim),
        None => Err(AuthError::MissingClaim),
    }
}

fn take_optional_u64(
    values: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<u64>, AuthError> {
    match values.remove(name) {
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or(AuthError::InvalidClaim),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(AuthError::InvalidClaim),
    }
}

fn take_audiences(values: &mut BTreeMap<String, Value>) -> Result<BTreeSet<String>, AuthError> {
    match values.remove("aud") {
        Some(Value::String(value)) => Ok(BTreeSet::from([checked_string(value)?])),
        Some(Value::Array(values)) => {
            let mut audiences = BTreeSet::new();
            for value in values {
                let Value::String(value) = value else {
                    return Err(AuthError::InvalidClaim);
                };
                audiences.insert(checked_string(value)?);
            }
            if audiences.is_empty() || audiences.len() > 64 {
                return Err(AuthError::InvalidClaim);
            }
            Ok(audiences)
        }
        Some(_) => Err(AuthError::InvalidClaim),
        None => Err(AuthError::MissingClaim),
    }
}

fn take_string_set(
    values: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<BTreeSet<String>, AuthError> {
    match values.remove(name) {
        None | Some(Value::Null) => Ok(BTreeSet::new()),
        Some(Value::Array(values)) => {
            let mut output = BTreeSet::new();
            for value in values {
                let Value::String(value) = value else {
                    return Err(AuthError::InvalidClaim);
                };
                output.insert(checked_string(value)?);
                if output.len() > MAX_GROUPS {
                    return Err(AuthError::InvalidClaim);
                }
            }
            Ok(output)
        }
        Some(_) => Err(AuthError::InvalidClaim),
    }
}

fn checked_string(value: String) -> Result<String, AuthError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(AuthError::InvalidClaim);
    }
    Ok(value)
}

fn encode_mfa_body(
    subject: &str,
    factor_id: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: [u8; 16],
    channel_binding: [u8; 32],
) -> Result<Vec<u8>, AuthError> {
    let subject_len = u16::try_from(subject.len()).map_err(|_| AuthError::InvalidMfaProof)?;
    let factor_len = u16::try_from(factor_id.len()).map_err(|_| AuthError::InvalidMfaProof)?;
    let mut body = Vec::with_capacity(2 + subject.len() + 2 + factor_id.len() + 8 + 8 + 16 + 32);
    body.extend_from_slice(&subject_len.to_be_bytes());
    body.extend_from_slice(subject.as_bytes());
    body.extend_from_slice(&factor_len.to_be_bytes());
    body.extend_from_slice(factor_id.as_bytes());
    body.extend_from_slice(&issued_at.to_be_bytes());
    body.extend_from_slice(&expires_at.to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&channel_binding);
    Ok(body)
}

#[derive(Debug)]
struct RecoveredReplay {
    valid_bytes: u64,
    last_sequence: u64,
    previous_tag: [u8; 32],
    entries: BTreeMap<[u8; 32], u64>,
}

fn recover_replay(ledger: &mut File, key: [u8; 32]) -> Result<RecoveredReplay, AuthError> {
    ledger.seek(SeekFrom::Start(0)).map_err(|_| AuthError::Io)?;
    let mut bytes = Vec::new();
    ledger.read_to_end(&mut bytes).map_err(|_| AuthError::Io)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    let mut previous_tag = [0_u8; 32];
    let mut entries = BTreeMap::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            break;
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| AuthError::Tampered)?,
        ) as usize;
        if length != REPLAY_FRAME_BYTES {
            return Err(AuthError::Tampered);
        }
        if bytes.len() - offset - 4 < length {
            break;
        }
        let body_start = offset + 4;
        let body_end = body_start + REPLAY_BODY_BYTES;
        let frame_end = body_start + length;
        let body = &bytes[body_start..body_end];
        let tag = &bytes[body_end..frame_end];
        hmac::verify(&key, body, tag).map_err(|_| AuthError::Tampered)?;
        if &body[..5] != REPLAY_MAGIC {
            return Err(AuthError::Tampered);
        }
        let sequence = u64::from_be_bytes(body[5..13].try_into().map_err(|_| AuthError::Tampered)?);
        let fingerprint = body[13..45].try_into().map_err(|_| AuthError::Tampered)?;
        let expires_at =
            u64::from_be_bytes(body[45..53].try_into().map_err(|_| AuthError::Tampered)?);
        let recorded_previous: [u8; 32] =
            body[53..85].try_into().map_err(|_| AuthError::Tampered)?;
        if sequence != expected_sequence
            || recorded_previous != previous_tag
            || fingerprint == [0; 32]
        {
            return Err(AuthError::Tampered);
        }
        previous_tag.copy_from_slice(tag);
        entries.insert(fingerprint, expires_at);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(AuthError::CapacityExceeded)?;
        offset = frame_end;
    }
    Ok(RecoveredReplay {
        valid_bytes: offset as u64,
        last_sequence: expected_sequence - 1,
        previous_tag,
        entries,
    })
}

fn encode_replay_body(
    sequence: u64,
    fingerprint: [u8; 32],
    expires_at: u64,
    previous_tag: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(REPLAY_BODY_BYTES);
    body.extend_from_slice(REPLAY_MAGIC);
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&fingerprint);
    body.extend_from_slice(&expires_at.to_be_bytes());
    body.extend_from_slice(&previous_tag);
    body
}

fn validate_root(path: &Path) -> Result<(), AuthError> {
    if !path.is_absolute() {
        return Err(AuthError::InvalidRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                if current == Path::new("/") || !current.exists() {
                    continue;
                }
                if fs::symlink_metadata(&current)
                    .map_err(|_| AuthError::InvalidRoot)?
                    .file_type()
                    .is_symlink()
                {
                    return Err(AuthError::InvalidRoot);
                }
            }
            Component::CurDir | Component::ParentDir => return Err(AuthError::InvalidRoot),
        }
    }
    Ok(())
}

fn create_private_root(root: &Path) -> Result<(), AuthError> {
    if !root.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(root).map_err(|_| AuthError::Io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root).map_err(|_| AuthError::Io)?;
    }
    if !root.is_dir() {
        return Err(AuthError::InvalidRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(root)
            .map_err(|_| AuthError::Io)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(AuthError::InvalidRoot);
        }
    }
    Ok(())
}

fn create_lock(path: &Path) -> Result<File, AuthError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            AuthError::WriterBusy
        } else {
            AuthError::Io
        }
    })?;
    file.write_all(b"heptabao-federated-auth-writer-v1\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| AuthError::Io)?;
    Ok(file)
}

fn open_ledger(path: &Path) -> Result<File, AuthError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| AuthError::Io)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "heptabao-fed-auth-{name}-{}-{nonce}",
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&root).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&root).unwrap();
        root
    }

    fn token(pair: &Ed25519KeyPair, claims: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key-1","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref());
        format!("{input}.{signature}")
    }

    fn verifier(pair: &Ed25519KeyPair) -> JwtVerifier {
        let policy = TrustPolicy::new(
            "https://issuer.example",
            BTreeSet::from(["heptabao".to_owned()]),
            Some("team-a".to_owned()),
            30,
            600,
        )
        .unwrap();
        let key = VerificationKey::new(
            "key-1",
            JwtAlgorithm::Ed25519,
            pair.public_key().as_ref().to_vec(),
        )
        .unwrap();
        JwtVerifier::new(policy, [key]).unwrap()
    }

    #[test]
    fn signed_token_is_recorded_before_release_and_replay_survives_restart() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let verifier = verifier(&pair);
        let claims = json!({
        "iss":"https://issuer.example", "sub":"alice", "aud":["heptabao"],
        "iat":1000, "nbf":1000, "exp":1300, "jti":"token-1",
        "heptabao_namespace":"team-a", "groups":["developers"]
              })
        .to_string();
        let token = token(&pair, &claims);
        let root = root("jwt");
        {
            let mut replay = PersistentReplayLedger::open(&root, [3; 32]).unwrap();
            let principal = verifier
                .verify_and_record(&token, 1050, &mut replay)
                .unwrap();
            assert_eq!(principal.subject, "alice");
            assert_eq!(
                verifier.verify_and_record(&token, 1050, &mut replay),
                Err(AuthError::ReplayDetected)
            );
        }
        let mut reopened = PersistentReplayLedger::open(&root, [3; 32]).unwrap();
        assert_eq!(
            verifier.verify_and_record(&token, 1050, &mut reopened),
            Err(AuthError::ReplayDetected)
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_claim_and_wrong_namespace_fail_closed() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        let verifier = verifier(&pair);
        let duplicate = r#"{"iss":"https://issuer.example","iss":"https://evil.example","sub":"alice","aud":"heptabao","iat":1000,"exp":1200,"jti":"x","heptabao_namespace":"team-a"}"#;
        let root = root("duplicate");
        let mut replay = PersistentReplayLedger::open(&root, [4; 32]).unwrap();
        assert_eq!(
            verifier.verify_and_record(&token(&pair, duplicate), 1050, &mut replay),
            Err(AuthError::DuplicateJsonKey)
        );
        let wrong = json!({
        "iss":"https://issuer.example", "sub":"alice", "aud":"heptabao",
        "iat":1000, "exp":1200, "jti":"y", "heptabao_namespace":"team-b"
              })
        .to_string();
        assert_eq!(
            verifier.verify_and_record(&token(&pair, &wrong), 1050, &mut replay),
            Err(AuthError::ClaimDenied)
        );
        drop(replay);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_jose_headers_and_trailing_json_are_rejected() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[14; 32]).unwrap();
        let verifier = verifier(&pair);
        let header = URL_SAFE_NO_PAD.encode(
            br#"{"alg":"EdDSA","kid":"key-1","typ":"JWT","jku":"https://evil.example/jwks"}"#,
        );
        let claims = URL_SAFE_NO_PAD.encode(
  br#"{"iss":"https://issuer.example","sub":"alice","aud":"heptabao","iat":1000,"exp":1200,"jti":"strict-1","heptabao_namespace":"team-a"}"#,
        );
        let input = format!("{header}.{claims}");
        let token = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref())
        );
        let root = root("strict-header");
        let mut replay = PersistentReplayLedger::open(&root, [15; 32]).unwrap();
        assert_eq!(
            verifier.verify_and_record(&token, 1050, &mut replay),
            Err(AuthError::MalformedToken)
        );
        drop(replay);
        fs::remove_dir_all(root).unwrap();

        assert_eq!(
            parse_unique_object(br#"{"a":1} trailing"#),
            Err(AuthError::InvalidJson)
        );
    }

    #[test]
    fn mfa_is_channel_bound_and_persistently_single_use() {
        let root = root("mfa");
        let mut replay = PersistentReplayLedger::open(&root, [5; 32]).unwrap();
        let verifier = MfaVerifier::new([6; 32], 10).unwrap();
        let proof =
            MfaProof::sign("alice", "totp-1", 1000, 1100, [9; 16], [10; 32], [6; 32]).unwrap();
        assert_eq!(
            verifier.verify_and_record(&proof, "alice", [11; 32], 1050, &mut replay),
            Err(AuthError::InvalidMfaProof)
        );
        verifier
            .verify_and_record(&proof, "alice", [10; 32], 1050, &mut replay)
            .unwrap();
        assert_eq!(
            verifier.verify_and_record(&proof, "alice", [10; 32], 1050, &mut replay),
            Err(AuthError::ReplayDetected)
        );
        drop(replay);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_replay_ledger_is_rejected() {
        let root = root("tamper");
        {
            let mut replay = PersistentReplayLedger::open(&root, [12; 32]).unwrap();
            replay.record_once([13; 32], 2000, 1000).unwrap();
        }
        let path = root.join("replay.ledger");
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 0x20;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PersistentReplayLedger::open(&root, [12; 32]),
            Err(AuthError::Tampered)
        ));
        let _ = fs::remove_file(root.join("writer.lock"));
        fs::remove_dir_all(root).unwrap();
    }
}
