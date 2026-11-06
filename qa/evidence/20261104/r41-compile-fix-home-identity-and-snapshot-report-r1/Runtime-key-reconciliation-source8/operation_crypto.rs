// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Token-capability encryption of bounded original native SDK result bytes.
//!
//! This module does not authenticate credentials, dispatch operations, grant replay
//! permits, or claim filesystem rollback resistance. Constructors are crate-private;
//! the HTTP constructor must receive bytes only after the trusted middleware verifies
//! the configured bearer. Neither persisted owner hashes nor session IDs are keys.
//!
//! Each operation and immutable ledger gets a distinct AEAD subkey. Every seal additionally obtains a fresh
//! CSPRNG nonce, rejects reuse within this scope, and consumes a bounded nonce budget.
//! Across controller restarts, immutable no-replay admission is the engine's duty.
//! The primitive does not claim that arbitrary printable tokens have high entropy.
use ring::{
	aead, digest, hkdf, hmac,
	rand::{SecureRandom, SystemRandom},
};
use std::{
	collections::HashSet,
	fmt,
	sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

pub(crate) const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_BINDING_BYTES: usize = 1024 * 1024;
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const MAX_SEALS_PER_SCOPE: usize = 16_384;
const PACKET_MAGIC: &[u8; 8] = b"HEPTAOP1";
const INNER_MAGIC: &[u8; 8] = b"HOPIN001";
const NONCE_BYTES: usize = 12;
const OUTER_BYTES: usize = PACKET_MAGIC.len() + NONCE_BYTES;
const INNER_BYTES: usize = INNER_MAGIC.len() + 8 + digest::SHA256_OUTPUT_LEN;
const TAG_BYTES: usize = 16;
pub(crate) const MAX_PACKET_BYTES: usize =
	OUTER_BYTES + INNER_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES;
const EXTRACT_SALT: &[u8] = b"hepta-runtime/native-operation/crypto/extract/v1";
const AEAD_DOMAIN: &[u8] = b"hepta-runtime/native-operation/result-aead/v1";
const REQUEST_DOMAIN: &[u8] = b"hepta-runtime/native-operation/request-binding/v1";
const IDEMPOTENCY_DOMAIN: &[u8] = b"hepta-runtime/native-operation/idempotency-binding/v1";
const POLICY_DOMAIN: &[u8] = b"hepta-runtime/native-operation/private-policy-binding/v1";
const RECORD_SALT: &[u8] = b"hepta-runtime/native-operation/record-key/extract/v1";
const RECORD_DOMAIN: &[u8] = b"hepta-runtime/native-operation/record-key/expand/v1";
const AAD_DOMAIN: &[u8] = b"hepta-runtime/native-operation/result-aad/v1";
const PAYLOAD_SCHEMA: &[u8] = b"serialized-native-sdk-result-family/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CryptoError {
	InvalidBinding,
	InvalidInput,
	PayloadTooLarge,
	EntropyUnavailable,
	NonceUnavailable,
	IntegrityUnavailable,
	KeyUnavailable,
	StateUnavailable,
}
impl fmt::Display for CryptoError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::InvalidBinding => "trusted result binding unavailable",
			Self::InvalidInput => "cryptographic binding input unavailable",
			Self::PayloadTooLarge => "native result exceeds bounded encrypted retention",
			Self::EntropyUnavailable => "cryptographic entropy unavailable",
			Self::NonceUnavailable => "cryptographic nonce or scope budget unavailable",
			Self::IntegrityUnavailable => "retained result authentication unavailable",
			Self::KeyUnavailable => "trusted result key unavailable",
			Self::StateUnavailable => "cryptographic scope state unavailable",
		})
	}
}
impl std::error::Error for CryptoError {}
type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativePayloadKind {
	NativeResult,
	NativeError,
}
impl NativePayloadKind {
	fn label(self) -> &'static [u8] {
		match self {
			Self::NativeResult => b"native_result",
			Self::NativeError => b"native_error",
		}
	}
}

/// Constructed by the validated native operation engine, never deserialized from a
/// request or inferred from unauthenticated packet headers.
#[derive(Clone)]
pub(crate) struct TrustedResultBinding {
	operation_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	request_binding: String,
	ledger_identity: String,
	payload_kind: NativePayloadKind,
}
impl fmt::Debug for TrustedResultBinding {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("TrustedResultBinding([redacted])")
	}
}
impl TrustedResultBinding {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		operation_id: &str,
		owner: &str,
		tool_name: &str,
		accepted_unix_ms: u128,
		policy_binding: &str,
		request_binding: &str,
		ledger_identity: &str,
		payload_kind: NativePayloadKind,
	) -> CryptoResult<Self> {
		if ![
			operation_id,
			owner,
			policy_binding,
			request_binding,
			ledger_identity,
		]
		.into_iter()
		.all(lower_hex_64)
			|| !canonical_tool(tool_name)
		{
			return Err(CryptoError::InvalidBinding);
		}
		let binding = Self {
			operation_id: operation_id.into(),
			owner: owner.into(),
			tool_name: tool_name.into(),
			accepted_unix_ms,
			policy_binding: policy_binding.into(),
			request_binding: request_binding.into(),
			ledger_identity: ledger_identity.into(),
			payload_kind,
		};
		binding.validate()?;
		Ok(binding)
	}
	pub(crate) fn operation_id(&self) -> &str {
		&self.operation_id
	}
	fn validate(&self) -> CryptoResult<()> {
		if ![
			&self.operation_id,
			&self.owner,
			&self.policy_binding,
			&self.request_binding,
			&self.ledger_identity,
		]
		.iter()
		.all(|value| lower_hex_64(value))
			|| !canonical_tool(&self.tool_name)
		{
			return Err(CryptoError::InvalidBinding);
		}
		Ok(())
	}
	fn aad(&self) -> CryptoResult<Vec<u8>> {
		self.validate()?;
		let mut out = Vec::with_capacity(512);
		for field in [
			AAD_DOMAIN,
			PACKET_MAGIC.as_slice(),
			b"chacha20_poly1305".as_slice(),
			PAYLOAD_SCHEMA,
			self.operation_id.as_bytes(),
			self.owner.as_bytes(),
			self.tool_name.as_bytes(),
			self.policy_binding.as_bytes(),
			self.request_binding.as_bytes(),
			self.ledger_identity.as_bytes(),
			self.payload_kind.label(),
		] {
			// Explicit lengths prohibit ambiguous concatenations.
			out.extend_from_slice(&(field.len() as u32).to_be_bytes());
			out.extend_from_slice(field);
		}
		out.extend_from_slice(&self.accepted_unix_ms.to_be_bytes());
		Ok(out)
	}
}
fn canonical_tool(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value.as_bytes()[0].is_ascii_lowercase()
		&& value
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn lower_hex_64(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		out.push(DIGITS[(byte >> 4) as usize] as char);
		out.push(DIGITS[(byte & 0xf) as usize] as char);
	}
	out
}
struct KeyLength;
impl hkdf::KeyType for KeyLength {
	fn len(&self) -> usize {
		32
	}
}
fn expand(prk: &hkdf::Prk, info: &[&[u8]]) -> CryptoResult<Zeroizing<[u8; 32]>> {
	let okm = prk
		.expand(info, KeyLength)
		.map_err(|_| CryptoError::KeyUnavailable)?;
	let mut bytes = Zeroizing::new([0; 32]);
	okm.fill(bytes.as_mut())
		.map_err(|_| CryptoError::KeyUnavailable)?;
	Ok(bytes)
}
struct SecretKeys {
	aead: Zeroizing<[u8; 32]>,
	request: Zeroizing<[u8; 32]>,
	idempotency: Zeroizing<[u8; 32]>,
	policy: Zeroizing<[u8; 32]>,
}
trait Entropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()>;
}
struct SystemEntropy;
impl Entropy for SystemEntropy {
	fn fill(&self, bytes: &mut [u8]) -> CryptoResult<()> {
		SystemRandom::new()
			.fill(bytes)
			.map_err(|_| CryptoError::EntropyUnavailable)
	}
}
#[derive(Default)]
struct NonceLedger {
	uses: HashSet<[u8; 44]>,
}
impl NonceLedger {
	fn reserve(&mut self, trusted: &TrustedResultBinding, nonce: [u8; 12]) -> CryptoResult<()> {
		if self.uses.len() >= MAX_SEALS_PER_SCOPE {
			return Err(CryptoError::NonceUnavailable);
		}
		let mut namespace = digest::Context::new(&digest::SHA256);
		namespace.update(trusted.operation_id.as_bytes());
		namespace.update(trusted.ledger_identity.as_bytes());
		let id_digest = namespace.finish();
		let mut binding = [0; 44];
		binding[..32].copy_from_slice(id_digest.as_ref());
		binding[32..].copy_from_slice(&nonce);
		if !self.uses.insert(binding) {
			return Err(CryptoError::NonceUnavailable);
		}
		Ok(())
	}
}

/// Capability held only by trusted controller state. Clone shares keys and nonce
/// accounting; neither key bytes nor bearer bytes have a serialization/export API.
#[derive(Clone)]
pub(crate) struct ResultCryptoScope {
	keys: Arc<SecretKeys>,
	nonces: Arc<Mutex<NonceLedger>>,
}
impl fmt::Debug for ResultCryptoScope {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ResultCryptoScope([redacted])")
	}
}
impl ResultCryptoScope {
	/// Caller must already have verified these exact bytes as the configured bearer.
	pub(crate) fn from_verified_token(token: &[u8]) -> CryptoResult<Self> {
		if !(32..=4096).contains(&token.len())
			|| token.iter().any(|byte| !(33..=126).contains(byte))
		{
			return Err(CryptoError::InvalidInput);
		}
		let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, EXTRACT_SALT).extract(token);
		Ok(Self {
			keys: Arc::new(SecretKeys {
				aead: expand(&prk, &[AEAD_DOMAIN])?,
				request: expand(&prk, &[REQUEST_DOMAIN])?,
				idempotency: expand(&prk, &[IDEMPOTENCY_DOMAIN])?,
				policy: expand(&prk, &[POLICY_DOMAIN])?,
			}),
			nonces: Arc::new(Mutex::new(NonceLedger::default())),
		})
	}
	/// Session-local keys with no derivation from any persisted owner/session hash.
	pub(crate) fn stdio() -> CryptoResult<Self> {
		Self::stdio_with_entropy(&SystemEntropy)
	}
	fn stdio_with_entropy(entropy: &impl Entropy) -> CryptoResult<Self> {
		let mut aead = Zeroizing::new([0; 32]);
		let mut request = Zeroizing::new([0; 32]);
		let mut idempotency = Zeroizing::new([0; 32]);
		let mut policy = Zeroizing::new([0; 32]);
		entropy.fill(aead.as_mut())?;
		entropy.fill(request.as_mut())?;
		entropy.fill(idempotency.as_mut())?;
		entropy.fill(policy.as_mut())?;
		Ok(Self {
			keys: Arc::new(SecretKeys {
				aead,
				request,
				idempotency,
				policy,
			}),
			nonces: Arc::new(Mutex::new(NonceLedger::default())),
		})
	}
	/// The engine supplies canonical typed arguments AND execution/policy context.
	pub(crate) fn request_binding(&self, canonical_context: &[u8]) -> CryptoResult<String> {
		if canonical_context.is_empty() || canonical_context.len() > MAX_BINDING_BYTES {
			return Err(CryptoError::InvalidInput);
		}
		Ok(self.mac(
			self.keys.request.as_ref(),
			REQUEST_DOMAIN,
			canonical_context,
		))
	}
	pub(crate) fn idempotency_binding(&self, private_key: &[u8]) -> CryptoResult<String> {
		if !(1..=MAX_IDEMPOTENCY_BYTES).contains(&private_key.len()) {
			return Err(CryptoError::InvalidInput);
		}
		Ok(self.mac(
			self.keys.idempotency.as_ref(),
			IDEMPOTENCY_DOMAIN,
			private_key,
		))
	}
	/// Bind the full private policy without publishing a low-entropy config digest.
	pub(crate) fn policy_binding(&self, canonical_policy: &[u8]) -> CryptoResult<String> {
		if canonical_policy.is_empty() || canonical_policy.len() > MAX_BINDING_BYTES {
			return Err(CryptoError::InvalidInput);
		}
		Ok(self.mac(self.keys.policy.as_ref(), POLICY_DOMAIN, canonical_policy))
	}
	fn mac(&self, key: &[u8], domain: &[u8], input: &[u8]) -> String {
		let key = hmac::Key::new(hmac::HMAC_SHA256, key);
		let mut context = hmac::Context::with_key(&key);
		context.update(&(domain.len() as u32).to_be_bytes());
		context.update(domain);
		context.update(&(input.len() as u64).to_be_bytes());
		context.update(input);
		hex(context.sign().as_ref())
	}
	fn record_key(&self, binding: &TrustedResultBinding) -> CryptoResult<aead::LessSafeKey> {
		let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, RECORD_SALT).extract(self.keys.aead.as_ref());
		let key = expand(
			&prk,
			&[
				RECORD_DOMAIN,
				binding.operation_id.as_bytes(),
				binding.ledger_identity.as_bytes(),
			],
		)?;
		let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_ref())
			.map_err(|_| CryptoError::KeyUnavailable)?;
		Ok(aead::LessSafeKey::new(unbound))
	}
	pub(crate) fn seal(
		&self,
		binding: &TrustedResultBinding,
		original_sdk_bytes: &[u8],
	) -> CryptoResult<Vec<u8>> {
		self.seal_with_entropy(binding, original_sdk_bytes, &SystemEntropy)
	}
	fn seal_with_entropy(
		&self,
		binding: &TrustedResultBinding,
		original_sdk_bytes: &[u8],
		entropy: &impl Entropy,
	) -> CryptoResult<Vec<u8>> {
		if original_sdk_bytes.len() > MAX_PAYLOAD_BYTES {
			return Err(CryptoError::PayloadTooLarge);
		}
		let aad = binding.aad()?;
		let mut nonce = [0; NONCE_BYTES];
		entropy.fill(&mut nonce)?;
		self.nonces
			.lock()
			.map_err(|_| CryptoError::StateUnavailable)?
			.reserve(binding, nonce)?;
		let key = self.record_key(binding)?;
		let mut inner = Zeroizing::new(Vec::with_capacity(
			INNER_BYTES + original_sdk_bytes.len() + TAG_BYTES,
		));
		inner.extend_from_slice(INNER_MAGIC);
		inner.extend_from_slice(&(original_sdk_bytes.len() as u64).to_be_bytes());
		inner.extend_from_slice(digest::digest(&digest::SHA256, original_sdk_bytes).as_ref());
		inner.extend_from_slice(original_sdk_bytes);
		key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aead::Aad::from(&aad),
			&mut *inner,
		)
		.map_err(|_| CryptoError::IntegrityUnavailable)?;
		let mut packet = Vec::with_capacity(OUTER_BYTES + inner.len());
		packet.extend_from_slice(PACKET_MAGIC);
		packet.extend_from_slice(&nonce);
		packet.extend_from_slice(&inner);
		Ok(packet)
	}
	pub(crate) fn open(
		&self,
		binding: &TrustedResultBinding,
		packet: &[u8],
	) -> CryptoResult<OpenedPayload> {
		// Reject hostile advertised files before copying/decryption/allocation.
		if packet.len() > MAX_PACKET_BYTES
			|| packet.len() < OUTER_BYTES + INNER_BYTES + TAG_BYTES
			|| &packet[..PACKET_MAGIC.len()] != PACKET_MAGIC
		{
			return Err(CryptoError::IntegrityUnavailable);
		}
		let aad = binding.aad()?;
		let mut nonce = [0; NONCE_BYTES];
		nonce.copy_from_slice(&packet[PACKET_MAGIC.len()..OUTER_BYTES]);
		let key = self.record_key(binding)?;
		let mut encrypted = Zeroizing::new(packet[OUTER_BYTES..].to_vec());
		let clear = key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::from(&aad),
				&mut encrypted,
			)
			.map_err(|_| CryptoError::IntegrityUnavailable)?;
		if clear.len() < INNER_BYTES || &clear[..INNER_MAGIC.len()] != INNER_MAGIC {
			return Err(CryptoError::IntegrityUnavailable);
		}
		let mut declared = [0; 8];
		declared.copy_from_slice(&clear[8..16]);
		let declared = usize::try_from(u64::from_be_bytes(declared))
			.map_err(|_| CryptoError::IntegrityUnavailable)?;
		let payload = &clear[INNER_BYTES..];
		if declared > MAX_PAYLOAD_BYTES
			|| declared != payload.len()
			|| clear[16..INNER_BYTES] != *digest::digest(&digest::SHA256, payload).as_ref()
		{
			return Err(CryptoError::IntegrityUnavailable);
		}
		Ok(OpenedPayload {
			bytes: Zeroizing::new(payload.to_vec()),
		})
	}
}

/// Decrypted bytes are intentionally accessible for owned paging, but accidental
/// Debug formatting must never print original outputs, errors, or embedded secrets.
pub(crate) struct OpenedPayload {
	bytes: Zeroizing<Vec<u8>>,
}
impl OpenedPayload {
	pub(crate) fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}
}
impl fmt::Debug for OpenedPayload {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("OpenedPayload([redacted])")
	}
}

#[cfg(test)]
#[path = "operation_crypto_tests.rs"]
mod tests;
