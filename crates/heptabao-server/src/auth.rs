//! Durable authentication and a deliberately bounded, fail-closed ACL dialect.
//!
//! Every public service request owns one affine principal and durably commits any
//! finite-use decrement before dispatch. Raw authorization remains crate-internal.
use crate::federated_auth::{JwtAlgorithm, JwtVerifier, TrustPolicy, VerificationKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest, hmac, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_TTL: u64 = 3600;
const MAX_TTL: u64 = 32 * 24 * 3600;
const PASSWORD_ROUNDS: u32 = 600_000;
const MFA_SEED_BYTES: usize = 32;
const MFA_PERIOD_SECONDS: u64 = 30;
const MFA_DIGITS: usize = 6;
const MFA_DRIFT_STEPS: u64 = 1;
const MAX_EXTERNAL_REPLAY_ENTRIES: usize = 32_000;
const CAPABILITIES: &[&str] = &[
    "create", "read", "update", "delete", "list", "patch", "sudo", "deny",
];

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthState {
    tokens: BTreeMap<String, Token>,
    policies: BTreeMap<String, BTreeMap<String, Policy>>,
    users: BTreeMap<String, BTreeMap<String, User>>,
    roles: BTreeMap<String, BTreeMap<String, Role>>,
    // The original fixed mounts retain their exact persisted representation.
    // Custom mounts add a structural dimension; namespace strings are never
    // concatenated with mount names to manufacture storage keys.
    #[serde(default)]
    mounted_users: BTreeMap<String, BTreeMap<String, BTreeMap<String, User>>>,
    #[serde(default)]
    mounted_roles: BTreeMap<String, BTreeMap<String, BTreeMap<String, Role>>>,
    #[serde(default)]
    auth_mounts: BTreeMap<String, BTreeMap<String, AuthMount>>,
    #[serde(default)]
    jwt_mounts: BTreeMap<String, BTreeMap<String, JwtMountState>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtKeyRecord {
    algorithm: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtConfig {
    issuer: String,
    audiences: BTreeSet<String>,
    required_namespace: Option<String>,
    clock_skew_seconds: u64,
    maximum_token_lifetime_seconds: u64,
    keys: BTreeMap<String, JwtKeyRecord>,
}

impl JwtConfig {
    fn verifier(&self) -> Result<JwtVerifier, AuthError> {
        let policy = TrustPolicy::new(
            self.issuer.clone(),
            self.audiences.clone(),
            self.required_namespace
                .clone()
                .filter(|value| !value.is_empty()),
            self.clock_skew_seconds,
            self.maximum_token_lifetime_seconds,
        )
        .map_err(|_| bad("invalid JWT trust policy"))?;
        let mut keys = Vec::with_capacity(self.keys.len());
        for (key_id, record) in &self.keys {
            let algorithm = match record.algorithm.as_str() {
                "EdDSA" => JwtAlgorithm::Ed25519,
                "ES256" => JwtAlgorithm::Es256,
                _ => return Err(bad("unsupported JWT algorithm")),
            };
            keys.push(
                VerificationKey::new(key_id.clone(), algorithm, record.bytes.clone())
                    .map_err(|_| bad("invalid JWT verification key"))?,
            );
        }
        JwtVerifier::new(policy, keys).map_err(|_| bad("invalid JWT verifier configuration"))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct JwtRole {
    bound_groups: BTreeSet<String>,
    #[serde(default)]
    bound_subject: Option<String>,
    #[serde(default)]
    bound_audiences: BTreeSet<String>,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct ExternalIdentity {
    issuer: String,
    subject: String,
    namespace: String,
    groups: BTreeSet<String>,
    last_seen: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct JwtMountState {
    config: Option<JwtConfig>,
    roles: BTreeMap<String, JwtRole>,
    identities: BTreeMap<String, ExternalIdentity>,
    replay: BTreeMap<String, u64>,
    // Once expired replay records are pruned, a clock rollback must not revive
    // them. This watermark commits atomically with replay and issued tokens.
    last_admission_time: u64,
}

impl Drop for JwtMountState {
    fn drop(&mut self) {
        for (mut fingerprint, _) in std::mem::take(&mut self.replay) {
            fingerprint.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct AuthMount {
    kind: String,
    description: String,
}

#[derive(Clone, Copy)]
struct AuthScope<'a> {
    namespace: &'a str,
    mount: &'a str,
}

impl AuthMount {
    fn new(kind: &str, description: &str) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
        }
    }

    fn descriptor(&self) -> Value {
        json!({
            "type": self.kind,
            "description": self.description,
            "local": false,
            "seal_wrap": false,
            "options": {},
            "config": {
                "default_lease_ttl": 0,
                "max_lease_ttl": 0,
                "force_no_cache": false
            }
        })
    }
}

fn legacy_auth_mounts() -> BTreeMap<String, AuthMount> {
    BTreeMap::from([
        (
            "token".into(),
            AuthMount::new("token", "token based credentials"),
        ),
        (
            "userpass".into(),
            AuthMount::new("userpass", "username and password credentials"),
        ),
        (
            "approle".into(),
            AuthMount::new("approle", "machine role credentials"),
        ),
    ])
}

impl Drop for AuthState {
    fn drop(&mut self) {
        for (mut verifier, _) in std::mem::take(&mut self.tokens) {
            verifier.zeroize();
        }
        // Nested User and Role destructors clear their owned verifier buffers.
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Token {
    accessor: String,
    namespace: String,
    policies: BTreeSet<String>,
    root: bool,
    parent: Option<String>,
    created_at: u64,
    expires_at: Option<u64>,
    max_expires_at: Option<u64>,
    period: u64,
    renewable: bool,
    uses_remaining: Option<u64>,
    display_name: String,
    /// Authentication mount provenance, inherited by derived tokens. Old
    /// snapshots lack it and require conservative revocation on legacy unmount.
    #[serde(default)]
    auth_mount: Option<String>,
    #[serde(default)]
    auth_origin_known: bool,
}

impl Drop for Token {
    fn drop(&mut self) {
        if let Some(parent) = &mut self.parent {
            parent.zeroize();
        }
    }
}

/// An affine capability owned by exactly one service dispatcher invocation.
/// It is non-cloneable, non-serializable and never crosses the public API.
pub(super) struct Principal {
    digest: String,
    token: Token,
    #[cfg(test)]
    request_time: u64,
}

impl Drop for Principal {
    fn drop(&mut self) {
        self.digest.zeroize();
    }
}

impl Principal {
    pub(super) fn is_root(&self) -> bool {
        self.token.root
    }
    fn policies(&self) -> &BTreeSet<String> {
        &self.token.policies
    }
    pub(super) fn consumed_use(&self) -> bool {
        self.token.uses_remaining.is_some()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Policy {
    source: String,
    rules: Vec<Rule>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rule {
    path: String,
    capabilities: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    salt: Vec<u8>,
    verifier: Vec<u8>,
    rounds: u32,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
    #[serde(default)]
    mfa: Option<TotpEnrollment>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpEnrollment {
    secret: Vec<u8>,
    period_seconds: u64,
    digits: u8,
    last_accepted_counter: Option<u64>,
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for User {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.verifier.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Role {
    role_id: String,
    policies: BTreeSet<String>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_num_uses: u64,
    secret_id_ttl: u64,
    secret_id_num_uses: u64,
    secret_ids: BTreeMap<String, SecretId>,
}

impl Drop for Role {
    fn drop(&mut self) {
        for (mut verifier, _) in std::mem::take(&mut self.secret_ids) {
            verifier.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SecretId {
    accessor: String,
    expires_at: Option<u64>,
    uses_remaining: Option<u64>,
}

pub struct AuthResponse {
    pub status: u16,
    pub body: Value,
    pub mutated: bool,
}

#[derive(Clone, Debug)]
pub struct AuthError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for AuthError {}

fn err(status: u16, message: &str) -> AuthError {
    AuthError {
        status,
        message: message.into(),
    }
}
fn bad(message: &str) -> AuthError {
    err(400, message)
}
fn denied() -> AuthError {
    err(403, "permission denied")
}
fn response(data: Value, mutated: bool) -> AuthResponse {
    AuthResponse {
        status: 200,
        body: json!({"data": data}),
        mutated,
    }
}
fn empty(mutated: bool) -> AuthResponse {
    AuthResponse {
        status: 204,
        body: Value::Null,
        mutated,
    }
}
fn random_bytes(len: usize) -> Result<Vec<u8>, AuthError> {
    let mut bytes = vec![0; len];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| err(500, "secure randomness unavailable"))?;
    Ok(bytes)
}
fn random_id(prefix: &str) -> Result<String, AuthError> {
    let bytes = Zeroizing::new(random_bytes(32)?);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    Ok(format!("{prefix}{}", encoded.as_str()))
}
fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, value.as_bytes()).as_ref())
}
fn checked_expiry(now: u64, ttl: u64) -> Result<u64, AuthError> {
    now.checked_add(ttl)
        .ok_or_else(|| bad("TTL overflows timestamp"))
}
fn unlimited_zero(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

fn validate_namespace(namespace: &str) -> Result<(), AuthError> {
    if namespace.is_empty() {
        return Ok(());
    }
    if namespace.len() > 512 || namespace.split('/').any(|s| !valid_name(s)) {
        return Err(bad("invalid namespace"));
    }
    Ok(())
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
fn validate_path(path: &str, pattern: bool) -> Result<(), AuthError> {
    if path.is_empty()
        || path.len() > 2048
        || path.starts_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|b| b < 0x21 || b == 0x7f || b == b'\\' || b == b'%')
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return Err(bad("invalid ACL path"));
    }
    if pattern {
        if path.contains("{{")
            || path.contains("${")
            || path.matches('*').count() > 1
            || path.contains('*') && !path.ends_with('*')
            || path.split('/').any(|s| s.contains('+') && s != "+")
        {
            return Err(bad(
                "only whole-segment + and terminal * ACL wildcards are supported",
            ));
        }
    } else if path.contains('*') || path.contains('+') {
        return Err(bad("wildcards are not permitted in request paths"));
    }
    Ok(())
}

fn string_field<'a>(body: &'a Value, field: &str) -> Result<&'a str, AuthError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| bad("required string field missing or invalid"))
}
fn number(body: &Value, field: &str, default: u64) -> Result<u64, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| bad("expected nonnegative integer")),
    }
}
fn boolean(body: &Value, field: &str, default: bool) -> Result<bool, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) => value.as_bool().ok_or_else(|| bad("expected boolean")),
    }
}
fn duration(body: &Value, field: &str, default: u64) -> Result<u64, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(value) if value.is_u64() => value.as_u64().ok_or_else(|| bad("invalid duration")),
        Some(Value::String(value)) => {
            if let Ok(seconds) = value.parse::<u64>() {
                return Ok(seconds);
            }
            let (digits, multiplier) = match value.as_bytes().last() {
                Some(b's') => (&value[..value.len() - 1], 1),
                Some(b'm') => (&value[..value.len() - 1], 60),
                Some(b'h') => (&value[..value.len() - 1], 3600),
                Some(b'd') => (&value[..value.len() - 1], 86400),
                _ => return Err(bad("duration must be whole seconds or integer s/m/h/d")),
            };
            digits
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(multiplier))
                .ok_or_else(|| bad("invalid duration"))
        }
        _ => Err(bad("invalid duration")),
    }
}
fn reject_unknown(body: &Value, allowed: &[&str]) -> Result<(), AuthError> {
    let object = body
        .as_object()
        .ok_or_else(|| bad("request body must be an object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(bad("unsupported request field"));
    }
    Ok(())
}
fn policies(
    body: &Value,
    field: &str,
    default: &BTreeSet<String>,
    add_default: bool,
) -> Result<BTreeSet<String>, AuthError> {
    let mut result = match body.get(field) {
        None => default.clone(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| bad("policies must contain strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("policies must be an array or comma-separated string")),
    };
    if result.iter().any(|name| !valid_name(name)) {
        return Err(bad("invalid policy name"));
    }
    if add_default && !result.contains("root") {
        result.insert("default".into());
    }
    Ok(result)
}

fn claim_values(body: &Value, name: &str) -> Result<BTreeSet<String>, AuthError> {
    let values: Vec<&str> = match body.get(name) {
        None => Vec::new(),
        Some(Value::String(value)) => value.split(',').map(str::trim).collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("claim bindings must be strings"))
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("claim bindings must be a string or array")),
    };
    if values.len() > 64
        || values.iter().any(|value| {
            value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control)
        })
    {
        return Err(bad(
            "claim bindings exceed bounds or contain invalid strings",
        ));
    }
    Ok(values.into_iter().map(str::to_owned).collect())
}

impl AuthState {
    pub(super) fn bootstrap(now: u64) -> Result<(Self, String), AuthError> {
        let mut state = Self {
            tokens: BTreeMap::new(),
            policies: BTreeMap::new(),
            users: BTreeMap::new(),
            roles: BTreeMap::new(),
            mounted_users: BTreeMap::new(),
            mounted_roles: BTreeMap::new(),
            auth_mounts: BTreeMap::new(),
            jwt_mounts: BTreeMap::new(),
        };
        let token = Token {
            accessor: random_id("a.")?,
            namespace: String::new(),
            policies: BTreeSet::from(["root".into()]),
            root: true,
            parent: None,
            created_at: now,
            expires_at: None,
            max_expires_at: None,
            period: 0,
            renewable: false,
            uses_remaining: None,
            display_name: "root".into(),
            auth_mount: None,
            auth_origin_known: true,
        };
        let raw = random_id("hvs.")?;
        state.tokens.insert(hash(&raw), token);
        Ok((state, raw))
    }

    fn active_token(&self, id: &str, now: u64, consume_check: bool) -> Result<&Token, AuthError> {
        let token = self.tokens.get(id).ok_or_else(denied)?;
        if token.expires_at.is_some_and(|t| now >= t)
            || consume_check && token.uses_remaining == Some(0)
        {
            return Err(denied());
        }
        let mut seen = BTreeSet::new();
        seen.insert(id.to_owned());
        let mut parent = token.parent.as_deref();
        while let Some(parent_id) = parent {
            if !seen.insert(parent_id.to_owned()) {
                return Err(denied());
            }
            let ancestor = self.tokens.get(parent_id).ok_or_else(denied)?;
            if ancestor.expires_at.is_some_and(|t| now >= t) || ancestor.uses_remaining == Some(0) {
                return Err(denied());
            }
            parent = ancestor.parent.as_deref();
        }
        Ok(token)
    }

    pub(super) fn authenticate(&mut self, raw: &str, now: u64) -> Result<Principal, AuthError> {
        if raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(denied());
        }
        let id = hash(raw);
        self.active_token(&id, now, true)?;
        let token = self.tokens.get_mut(&id).ok_or_else(denied)?;
        if let Some(remaining) = &mut token.uses_remaining {
            *remaining -= 1;
        }
        Ok(Principal {
            digest: id,
            token: token.clone(),
            #[cfg(test)]
            request_time: now,
        })
    }

    fn check_principal<'a>(
        &'a self,
        principal: &Principal,
        namespace: &str,
        now: u64,
    ) -> Result<&'a Token, AuthError> {
        validate_namespace(namespace)?;
        let token = self.active_token(&principal.digest, now, false)?;
        if token.accessor != principal.token.accessor || !token.root && token.namespace != namespace
        {
            return Err(denied());
        }
        Ok(token)
    }

    pub(super) fn authorize_request(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        validate_path(path, false)?;
        if !CAPABILITIES.contains(&capability) || capability == "deny" {
            return Err(denied());
        }
        let token = self.check_principal(principal, namespace, now)?;
        if token.root {
            return Ok(());
        }
        let mut granted = false;
        for policy_name in &token.policies {
            let explicit = self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(policy_name));
            if let Some(policy) = explicit {
                for rule in &policy.rules {
                    if path_matches(&rule.path, path) {
                        if rule.capabilities.contains("deny") {
                            return Err(denied());
                        }
                        granted |= rule.capabilities.contains(capability);
                    }
                }
            } else if policy_name == "default" && default_grants(path, capability) {
                granted = true;
            }
        }
        if granted { Ok(()) } else { Err(denied()) }
    }

    #[cfg(test)]
    fn authorize_for_unit_test(
        &self,
        principal: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
    ) -> Result<(), AuthError> {
        self.authorize_request(
            principal,
            namespace,
            path,
            capability,
            principal.request_time,
        )
    }

    fn permission<'principal>(
        &self,
        principal: Option<&'principal Principal>,
        namespace: &str,
        path: &str,
        cap: &str,
        now: u64,
    ) -> Result<&'principal Principal, AuthError> {
        let principal = principal.ok_or_else(denied)?;
        self.authorize_request(principal, namespace, path, cap, now)?;
        Ok(principal)
    }

    fn prepare_issue(token: Token, now: u64) -> Result<(String, Token, AuthResponse), AuthError> {
        let raw = Zeroizing::new(random_id("hvs.")?);
        let token_id = hash(&raw);
        let result = AuthResponse {
            status: 200,
            mutated: true,
            body: json!({"auth": {
                "client_token": raw.as_str(), "accessor": token.accessor, "policies": token.policies,
                "token_policies": token.policies, "metadata": {}, "lease_duration": token.expires_at.map(|expiry| expiry.saturating_sub(now)).unwrap_or(0),
                "renewable": token.renewable, "token_type": "service", "orphan": token.parent.is_none(), "num_uses": token.uses_remaining.unwrap_or(0)
            }}),
        };
        Ok((token_id, token, result))
    }

    fn issue(&mut self, token: Token, now: u64) -> Result<AuthResponse, AuthError> {
        let (token_id, token, result) = Self::prepare_issue(token, now)?;
        self.tokens.insert(token_id, token);
        Ok(result)
    }

    fn revoke(&mut self, id: &str) {
        let mut removed = BTreeSet::from([id.to_owned()]);
        loop {
            let children: Vec<String> = self
                .tokens
                .iter()
                .filter(|(_, token)| token.parent.as_ref().is_some_and(|p| removed.contains(p)))
                .map(|(id, _)| id.clone())
                .collect();
            let old_len = removed.len();
            removed.extend(children);
            if removed.len() == old_len {
                break;
            }
        }
        for mut id in removed {
            if let Some((mut stored_id, _)) = self.tokens.remove_entry(&id) {
                stored_id.zeroize();
            }
            id.zeroize();
        }
    }

    fn effective_auth_mounts(&self, namespace: &str) -> BTreeMap<String, AuthMount> {
        self.auth_mounts
            .get(namespace)
            .cloned()
            .unwrap_or_else(legacy_auth_mounts)
    }

    fn users_at(&self, scope: AuthScope<'_>) -> Option<&BTreeMap<String, User>> {
        if scope.mount == "userpass" {
            self.users.get(scope.namespace)
        } else {
            self.mounted_users.get(scope.namespace)?.get(scope.mount)
        }
    }

    fn users_at_mut(&mut self, scope: AuthScope<'_>) -> &mut BTreeMap<String, User> {
        if scope.mount == "userpass" {
            self.users.entry(scope.namespace.into()).or_default()
        } else {
            self.mounted_users
                .entry(scope.namespace.into())
                .or_default()
                .entry(scope.mount.into())
                .or_default()
        }
    }

    fn roles_at(&self, scope: AuthScope<'_>) -> Option<&BTreeMap<String, Role>> {
        if scope.mount == "approle" {
            self.roles.get(scope.namespace)
        } else {
            self.mounted_roles.get(scope.namespace)?.get(scope.mount)
        }
    }

    fn roles_at_mut(&mut self, scope: AuthScope<'_>) -> &mut BTreeMap<String, Role> {
        if scope.mount == "approle" {
            self.roles.entry(scope.namespace.into()).or_default()
        } else {
            self.mounted_roles
                .entry(scope.namespace.into())
                .or_default()
                .entry(scope.mount.into())
                .or_default()
        }
    }

    fn disable_auth_mount(&mut self, scope: AuthScope<'_>) {
        self.users_at_mut(scope).clear();
        self.roles_at_mut(scope).clear();
        if let Some(mounts) = self.jwt_mounts.get_mut(scope.namespace) {
            mounts.remove(scope.mount);
        }
        let revoke: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, token)| {
                token.namespace == scope.namespace
                    && !token.root
                    && (token.auth_mount.as_deref() == Some(scope.mount)
                        || (!token.auth_origin_known
                            && matches!(scope.mount, "userpass" | "approle")))
            })
            .map(|(digest, _)| digest.clone())
            .collect();
        for digest in revoke {
            self.revoke(&digest);
        }
    }

    fn jwt_at(&self, scope: AuthScope<'_>) -> Option<&JwtMountState> {
        self.jwt_mounts.get(scope.namespace)?.get(scope.mount)
    }

    fn jwt_at_mut(&mut self, scope: AuthScope<'_>) -> &mut JwtMountState {
        self.jwt_mounts
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default()
    }

    fn admit_external_replay(
        &mut self,
        scope: AuthScope<'_>,
        fingerprint: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), AuthError> {
        let state = self.jwt_at_mut(scope);
        if expires_at <= now || now < state.last_admission_time {
            return Err(denied());
        }
        let mut key = URL_SAFE_NO_PAD.encode(fingerprint);
        if state.replay.get(&key).is_some_and(|expiry| *expiry > now) {
            key.zeroize();
            return Err(denied());
        }
        if state
            .replay
            .values()
            .filter(|expiry| **expiry > now)
            .count()
            >= MAX_EXTERNAL_REPLAY_ENTRIES
        {
            key.zeroize();
            return Err(err(503, "external replay registry capacity exhausted"));
        }
        // All fallible checks precede the mutation, including randomness for
        // token creation at the caller; Service owns the durable transaction.
        let mut retained = BTreeMap::new();
        for (mut id, expiry) in std::mem::take(&mut state.replay) {
            if expiry > now {
                retained.insert(id, expiry);
            } else {
                id.zeroize();
            }
        }
        retained.insert(key, expires_at);
        state.replay = retained;
        state.last_admission_time = now;
        Ok(())
    }

    #[cfg(test)]
    fn auth_mount_enabled(&self, namespace: &str, mount: &str, kind: &str) -> bool {
        self.auth_mounts.get(namespace).map_or_else(
            || {
                legacy_auth_mounts()
                    .get(mount)
                    .is_some_and(|entry| entry.kind == kind)
            },
            |entries| entries.get(mount).is_some_and(|entry| entry.kind == kind),
        )
    }

    fn auth_mount_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/auth")
            .ok_or_else(|| bad("invalid auth mount path"))?;
        if suffix.is_empty() || suffix == "/" {
            if !matches!(method, "GET" | "LIST") {
                return Err(err(405, "method not allowed"));
            }
            self.permission(principal, namespace, "sys/auth", "read", now)?;
            reject_unknown(body, &[])?;
            let entries = self
                .effective_auth_mounts(namespace)
                .into_iter()
                .map(|(name, mount)| (format!("{name}/"), mount.descriptor()))
                .collect();
            return Ok(response(Value::Object(entries), false));
        }
        let mount = suffix.trim_start_matches('/').trim_end_matches('/');
        if mount.is_empty() || mount.len() > 256 || !mount.split('/').all(valid_name) {
            return Err(bad("auth mount path must contain canonical segments"));
        }
        let route = format!("sys/auth/{mount}");
        match method {
            "GET" => {
                self.permission(principal, namespace, &route, "read", now)?;
                reject_unknown(body, &[])?;
                let entry = self
                    .effective_auth_mounts(namespace)
                    .get(mount)
                    .cloned()
                    .ok_or_else(|| err(404, "auth mount not found"))?;
                Ok(response(entry.descriptor(), false))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &["type", "description"])?;
                let kind = body
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("auth mount type is required"))?;
                if !matches!(kind, "userpass" | "approle" | "jwt") {
                    return Err(err(501, "auth method type is not implemented"));
                }
                let description = body
                    .get("description")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("description must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("");
                if description.len() > 512 || description.chars().any(char::is_control) {
                    return Err(bad("invalid auth mount description"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                if mount == "token" || entries.get(mount).is_some_and(|old| old.kind != kind) {
                    return Err(bad("auth mount is already in use by another method"));
                }
                if entries.keys().any(|name| {
                    name != mount
                        && (name.starts_with(&format!("{mount}/"))
                            || mount.starts_with(&format!("{name}/")))
                }) {
                    return Err(bad("auth mount paths cannot overlap"));
                }
                let next = AuthMount::new(kind, description);
                let mutated = entries.get(mount) != Some(&next);
                entries.insert(mount.into(), next);
                self.auth_mounts.insert(namespace.into(), entries);
                Ok(empty(mutated))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &[])?;
                if mount == "token" {
                    return Err(bad("the built-in token auth method cannot be disabled"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                let mutated = entries.remove(mount).is_some();
                self.auth_mounts.insert(namespace.into(), entries);
                if mutated {
                    self.disable_auth_mount(AuthScope { namespace, mount });
                    Ok(empty(true))
                } else {
                    Err(err(404, "auth mount not found"))
                }
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    /// Returns None only for routes owned by another service subsystem.
    pub(super) fn handle(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        if path == "sys/auth" || path.starts_with("sys/auth/") {
            return self
                .auth_mount_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        if let Some(auth_path) = path.strip_prefix("auth/") {
            let mounts = self.effective_auth_mounts(namespace);
            let (mount, entry, suffix) = mounts
                .iter()
                .find_map(|(mount, entry)| {
                    auth_path
                        .strip_prefix(&format!("{mount}/"))
                        .map(|suffix| (mount, entry, suffix))
                })
                .ok_or_else(|| err(404, "auth mount not found"))?;
            let scope = AuthScope { namespace, mount };
            let result = match entry.kind.as_str() {
                "token" if mount == "token" => {
                    self.token_route(principal, namespace, method, path, body, now)
                }
                "userpass" if suffix.starts_with("login/") => {
                    self.login_userpass(scope, method, &suffix[6..], body, now)
                }
                "userpass" if suffix == "users" || suffix.starts_with("users/") => {
                    self.user_route(principal, scope, method, path, body, now)
                }
                "approle" if suffix == "login" => self.login_approle(scope, method, body, now),
                "approle" if suffix == "tidy/secret-id" => {
                    self.tidy_secret_ids(principal, scope, method, path, body, now)
                }
                "approle" if suffix == "role" || suffix.starts_with("role/") => {
                    self.role_route(principal, scope, method, path, body, now)
                }
                "jwt" => self.jwt_route(principal, scope, method, path, body, now),
                _ => Err(err(404, "unsupported auth route")),
            };
            return result.map(Some);
        }
        if path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path == "sys/policy"
            || path.starts_with("sys/policy/")
        {
            return self
                .policy_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        Ok(None)
    }

    fn jwt_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if path == format!("auth/{mount}/config") {
            return self.jwt_config_route(principal, scope, method, body, now);
        }
        if path == format!("auth/{mount}/login") {
            if !matches!(method, "POST" | "PUT") {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &["role", "jwt"])?;
            let role_name = string_field(body, "role")?;
            if !valid_name(role_name) {
                return Err(bad("invalid JWT role name"));
            }
            let jwt = string_field(body, "jwt")?;
            let config = self
                .jwt_at(scope)
                .and_then(|state| state.config.as_ref())
                .cloned()
                .ok_or_else(|| err(503, "JWT auth is not configured"))?;
            let role = self
                .jwt_at(scope)
                .map(|state| &state.roles)
                .and_then(|roles| roles.get(role_name))
                .cloned()
                .ok_or_else(denied)?;
            let verified = config.verifier()?.verify(jwt, now).map_err(|_| denied())?;
            let claimed_namespace = verified.namespace.as_deref().unwrap_or("");
            if claimed_namespace != namespace
                || !role.bound_groups.is_subset(&verified.groups)
                || role
                    .bound_subject
                    .as_ref()
                    .is_some_and(|subject| subject != &verified.subject)
                || !role.bound_audiences.is_empty()
                    && role.bound_audiences.is_disjoint(&verified.audiences)
                || role.policies.contains("root")
            {
                return Err(denied());
            }
            let remaining = verified.expires_at.saturating_sub(now);
            if remaining == 0 {
                return Err(denied());
            }
            let ttl = role.token_ttl.min(remaining).max(1);
            let max_ttl = role.token_max_ttl.min(remaining).max(ttl);
            let fingerprint = verified.replay_fingerprint();
            let identity_key = hash(&format!("{}\0{}", verified.issuer, verified.subject));
            let identity = ExternalIdentity {
                issuer: verified.issuer.clone(),
                subject: verified.subject.clone(),
                namespace: namespace.into(),
                groups: verified.groups.clone(),
                last_seen: now,
            };
            let display_hash = hash(&verified.subject);
            let display_suffix = display_hash.get(..16).unwrap_or(display_hash.as_str());
            let token = Token {
                accessor: random_id("a.")?,
                namespace: namespace.into(),
                policies: role.policies,
                root: false,
                parent: None,
                created_at: now,
                expires_at: Some(checked_expiry(now, ttl)?),
                max_expires_at: Some(checked_expiry(now, max_ttl)?),
                period: 0,
                renewable: true,
                uses_remaining: unlimited_zero(role.token_num_uses),
                display_name: format!("jwt-{display_suffix}"),
                auth_mount: Some(mount.into()),
                auth_origin_known: true,
            };
            let (token_id, token, mut response) = Self::prepare_issue(token, now)?;
            if let Err(error) =
                self.admit_external_replay(scope, fingerprint, verified.expires_at, now)
            {
                crate::service::erase_json(&mut response.body);
                return Err(error);
            }
            self.jwt_at_mut(scope)
                .identities
                .insert(identity_key, identity);
            self.tokens.insert(token_id, token);
            return Ok(response);
        }
        if path == format!("auth/{mount}/role") {
            if !matches!(method, "GET" | "LIST") {
                return Err(err(405, "method not allowed"));
            }
            self.permission(principal, namespace, path, "list", now)?;
            reject_unknown(body, &[])?;
            let keys: Vec<&str> = self
                .jwt_at(scope)
                .map(|state| &state.roles)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if let Some(name) = path.strip_prefix(&format!("auth/{mount}/role/")) {
            if !valid_name(name) {
                return Err(bad("invalid JWT role name"));
            }
            return self.jwt_role_route(principal, scope, method, name, body, now);
        }
        Err(err(404, "JWT auth path is not implemented"))
    }

    fn jwt_config_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let path = format!("auth/{mount}/config");
        let path = path.as_str();
        match method {
            "GET" => {
                self.permission(principal, namespace, path, "read", now)?;
                reject_unknown(body, &[])?;
                let config = self
                    .jwt_at(scope)
                    .and_then(|state| state.config.as_ref())
                    .ok_or_else(|| err(404, "JWT auth is not configured"))?;
                let keys: Vec<Value> = config
                    .keys
                    .iter()
                    .map(|(kid, key)| json!({"kid": kid, "algorithm": key.algorithm}))
                    .collect();
                Ok(response(
                    json!({
                        "issuer": config.issuer,
                        "audiences": config.audiences,
                        "required_namespace": config.required_namespace,
                        "clock_skew_seconds": config.clock_skew_seconds,
                        "maximum_token_lifetime_seconds": config.maximum_token_lifetime_seconds,
                        "keys": keys
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, path, "update", now)?;
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "issuer",
                        "audiences",
                        "required_namespace",
                        "clock_skew_seconds",
                        "maximum_token_lifetime_seconds",
                        "keys",
                    ],
                )?;
                let issuer = string_field(body, "issuer")?.to_owned();
                let audiences = claim_values(body, "audiences")?;
                let required_namespace = body
                    .get("required_namespace")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("required_namespace must be a string"))
                    })
                    .transpose()?
                    .map(str::to_owned);
                if required_namespace
                    .as_deref()
                    .is_some_and(|value| value != namespace)
                {
                    return Err(bad(
                        "required_namespace must equal the configured auth namespace",
                    ));
                }
                let clock_skew_seconds = number(body, "clock_skew_seconds", 30)?;
                let maximum_token_lifetime_seconds =
                    number(body, "maximum_token_lifetime_seconds", 3600)?;
                let key_values = body
                    .get("keys")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("JWT keys must be an array"))?;
                if key_values.is_empty() || key_values.len() > 64 {
                    return Err(bad("JWT key count is outside bounds"));
                }
                let mut keys = BTreeMap::new();
                for value in key_values {
                    reject_unknown(value, &["kid", "algorithm", "key_base64"])?;
                    let kid = string_field(value, "kid")?;
                    if kid.is_empty()
                        || kid.len() > 1024
                        || kid.chars().any(char::is_control)
                        || keys.contains_key(kid)
                    {
                        return Err(bad("invalid or duplicate JWT key id"));
                    }
                    let algorithm = string_field(value, "algorithm")?;
                    if !matches!(algorithm, "EdDSA" | "ES256") {
                        return Err(bad("unsupported JWT algorithm"));
                    }
                    let bytes = URL_SAFE_NO_PAD
                        .decode(string_field(value, "key_base64")?)
                        .map_err(|_| bad("invalid JWT key encoding"))?;
                    if bytes.is_empty() || bytes.len() > 16 * 1024 {
                        return Err(bad("JWT key is outside bounds"));
                    }
                    keys.insert(
                        kid.into(),
                        JwtKeyRecord {
                            algorithm: algorithm.into(),
                            bytes,
                        },
                    );
                }
                let config = JwtConfig {
                    issuer,
                    audiences,
                    required_namespace,
                    clock_skew_seconds,
                    maximum_token_lifetime_seconds,
                    keys,
                };
                config.verifier()?;
                let mutated =
                    self.jwt_at(scope).and_then(|state| state.config.as_ref()) != Some(&config);
                self.jwt_at_mut(scope).config = Some(config);
                Ok(empty(mutated))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn jwt_role_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let path = format!("auth/{mount}/role/{name}");
        match method {
            "GET" => {
                self.permission(principal, namespace, &path, "read", now)?;
                reject_unknown(body, &[])?;
                let role = self
                    .jwt_at(scope)
                    .map(|state| &state.roles)
                    .and_then(|roles| roles.get(name))
                    .ok_or_else(|| err(404, "JWT role not found"))?;
                Ok(response(
                    json!({
                        "bound_groups": role.bound_groups,
                        "bound_subject": role.bound_subject,
                        "bound_audiences": role.bound_audiences,
                        "policies": role.policies,
                        "token_ttl": role.token_ttl,
                        "token_max_ttl": role.token_max_ttl,
                        "token_num_uses": role.token_num_uses
                    }),
                    false,
                ))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &path, "update", now)?;
                self.authorize_request(actor, namespace, &path, "sudo", now)?;
                reject_unknown(
                    body,
                    &[
                        "bound_groups",
                        "bound_subject",
                        "bound_audiences",
                        "policies",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_num_uses",
                    ],
                )?;
                let bound_groups = claim_values(body, "bound_groups")?;
                let bound_audiences = claim_values(body, "bound_audiences")?;
                let bound_subject = body
                    .get("bound_subject")
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|value| {
                                !value.is_empty()
                                    && value.len() <= 1024
                                    && !value.chars().any(char::is_control)
                            })
                            .map(str::to_owned)
                            .ok_or_else(|| bad("invalid bound subject"))
                    })
                    .transpose()?;
                reject_alias_pair(body, "policies", "token_policies")?;
                let role_policies = policies(
                    body,
                    if body.get("token_policies").is_some() {
                        "token_policies"
                    } else {
                        "policies"
                    },
                    &BTreeSet::new(),
                    true,
                )?;
                self.validate_assignment(actor, &role_policies)?;
                let token_ttl = duration(body, "token_ttl", DEFAULT_TTL)?;
                let token_max_ttl = duration(body, "token_max_ttl", token_ttl)?;
                let token_num_uses = number(body, "token_num_uses", 0)?;
                if token_ttl == 0
                    || token_ttl > MAX_TTL
                    || token_max_ttl < token_ttl
                    || token_max_ttl > MAX_TTL
                {
                    return Err(bad("JWT role token TTL is outside bounds"));
                }
                let role = JwtRole {
                    bound_groups,
                    bound_subject,
                    bound_audiences,
                    policies: role_policies,
                    token_ttl,
                    token_max_ttl,
                    token_num_uses,
                };
                let roles = &mut self.jwt_at_mut(scope).roles;
                let mutated = roles.get(name) != Some(&role);
                roles.insert(name.into(), role);
                Ok(empty(mutated))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &path, "update", now)?;
                self.authorize_request(actor, namespace, &path, "sudo", now)?;
                reject_unknown(body, &[])?;
                let removed = self.jwt_at_mut(scope).roles.remove(name);
                if removed.is_some() {
                    Ok(empty(true))
                } else {
                    Err(err(404, "JWT role not found"))
                }
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    fn tidy_secret_ids(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &[])?;
        let actor = self.permission(principal, scope.namespace, path, "update", now)?;
        self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
        let mut removed = 0;
        for role in self.roles_at_mut(scope).values_mut() {
            let stale: Vec<String> = role
                .secret_ids
                .iter()
                .filter(|(_, secret)| {
                    secret.uses_remaining == Some(0)
                        || secret.expires_at.is_some_and(|expiry| expiry <= now)
                })
                .map(|(id, _)| id.clone())
                .collect();
            for mut id in stale {
                if let Some((mut stored_id, _)) = role.secret_ids.remove_entry(&id) {
                    stored_id.zeroize();
                    removed += 1;
                }
                id.zeroize();
            }
        }
        Ok(response(
            json!({"removed_secret_ids": removed}),
            removed > 0,
        ))
    }

    fn token_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let operation = path
            .strip_prefix("auth/token/")
            .ok_or_else(|| bad("invalid token path"))?;
        let allowed_method = match operation {
            "lookup-self" => matches!(method, "GET" | "POST"),
            "lookup" | "lookup-accessor" => matches!(method, "GET" | "POST"),
            "accessors" => matches!(method, "LIST" | "GET"),
            _ => matches!(method, "POST" | "PUT"),
        };
        if !allowed_method {
            return Err(err(405, "method not allowed"));
        }
        let capability = match operation {
            "lookup-self" | "lookup" | "lookup-accessor" => "read",
            "accessors" => "list",
            _ => "update",
        };
        let actor = self.permission(principal, namespace, path, capability, now)?;
        match operation {
            "create" | "create-orphan" => self.create_token(
                actor,
                namespace,
                path,
                body,
                now,
                operation == "create-orphan",
            ),
            "lookup-self" => {
                reject_unknown(body, &[])?;
                let token = self.tokens.get(&actor.digest).ok_or_else(denied)?;
                Ok(response(token_info(token, now), false))
            }
            "lookup" | "lookup-accessor" => {
                reject_unknown(
                    body,
                    if operation == "lookup" {
                        &["token"]
                    } else {
                        &["accessor"]
                    },
                )?;
                let id = self.target_token(namespace, body, operation.ends_with("accessor"))?;
                let token = self.active_token(&id, now, true)?;
                Ok(response(token_info(token, now), false))
            }
            "accessors" => {
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                let keys: Vec<&str> = self
                    .tokens
                    .values()
                    .filter(|t| t.namespace == namespace && !t.expires_at.is_some_and(|e| e <= now))
                    .map(|t| t.accessor.as_str())
                    .collect();
                Ok(response(json!({"keys": keys}), false))
            }
            "tidy" => {
                reject_unknown(body, &[])?;
                self.authorize_request(actor, namespace, path, "sudo", now)?;
                let stale: Vec<String> = self
                    .tokens
                    .iter()
                    .filter(|(id, token)| {
                        token.namespace == namespace && self.active_token(id, now, true).is_err()
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                let removed = stale.len();
                for mut id in stale {
                    if let Some((mut stored_id, _)) = self.tokens.remove_entry(&id) {
                        stored_id.zeroize();
                    }
                    id.zeroize();
                }
                Ok(response(json!({"removed_tokens": removed}), removed > 0))
            }
            "revoke-self" => {
                reject_unknown(body, &[])?;
                self.revoke(&actor.digest);
                Ok(empty(true))
            }
            "revoke" | "revoke-accessor" => {
                reject_unknown(
                    body,
                    if operation == "revoke" {
                        &["token"]
                    } else {
                        &["accessor"]
                    },
                )?;
                let id = self.target_token(namespace, body, operation.ends_with("accessor"))?;
                self.revoke(&id);
                Ok(empty(true))
            }
            "renew-self" | "renew" | "renew-accessor" => {
                let id = if operation == "renew-self" {
                    reject_unknown(body, &["increment"])?;
                    actor.digest.clone()
                } else {
                    reject_unknown(
                        body,
                        if operation == "renew" {
                            &["token", "increment"]
                        } else {
                            &["accessor", "increment"]
                        },
                    )?;
                    self.target_token(namespace, body, operation.ends_with("accessor"))?
                };
                self.active_token(&id, now, false)?;
                let mut ancestor_limit: Option<u64> = None;
                let mut parent_id = self
                    .tokens
                    .get(&id)
                    .and_then(|token| token.parent.as_deref());
                while let Some(parent) = parent_id {
                    let ancestor = self.tokens.get(parent).ok_or_else(denied)?;
                    if let Some(expiry) = ancestor.expires_at {
                        ancestor_limit = Some(
                            ancestor_limit
                                .map(|limit| limit.min(expiry))
                                .unwrap_or(expiry),
                        );
                    }
                    parent_id = ancestor.parent.as_deref();
                }
                let increment = duration(body, "increment", DEFAULT_TTL)?;
                let token = self.tokens.get_mut(&id).ok_or_else(denied)?;
                if !token.renewable {
                    return Err(bad("token is not renewable"));
                }
                let ttl = if token.period > 0 {
                    token.period
                } else if increment == 0 {
                    DEFAULT_TTL
                } else {
                    increment.min(MAX_TTL)
                };
                let proposed = checked_expiry(now, ttl)?;
                let expires_at = token
                    .max_expires_at
                    .map(|max| proposed.min(max))
                    .unwrap_or(proposed);
                let expires_at = ancestor_limit
                    .map(|limit| expires_at.min(limit))
                    .unwrap_or(expires_at);
                if expires_at <= now {
                    return Err(denied());
                }
                token.expires_at = Some(expires_at);
                Ok(AuthResponse {
                    status: 200,
                    mutated: true,
                    body: json!({"auth": {
                        "accessor": token.accessor, "policies": token.policies, "token_policies": token.policies,
                        "lease_duration": expires_at - now, "renewable": true, "token_type": "service"
                    }}),
                })
            }
            _ => Err(err(404, "unsupported token operation")),
        }
    }

    fn target_token(
        &self,
        namespace: &str,
        body: &Value,
        accessor: bool,
    ) -> Result<String, AuthError> {
        let id = if accessor {
            let wanted = string_field(body, "accessor")?;
            self.tokens
                .iter()
                .find(|(_, t)| t.namespace == namespace && t.accessor == wanted)
                .map(|(id, _)| id.clone())
                .ok_or_else(denied)?
        } else {
            hash(string_field(body, "token")?)
        };
        if self
            .tokens
            .get(&id)
            .is_none_or(|token| token.namespace != namespace)
        {
            return Err(denied());
        }
        Ok(id)
    }

    fn create_token(
        &mut self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        body: &Value,
        now: u64,
        force_orphan: bool,
    ) -> Result<AuthResponse, AuthError> {
        reject_unknown(
            body,
            &[
                "policies",
                "ttl",
                "explicit_max_ttl",
                "period",
                "num_uses",
                "renewable",
                "no_parent",
                "no_default_policy",
                "display_name",
                "type",
            ],
        )?;
        if body
            .get("type")
            .is_some_and(|value| value.as_str() != Some("service"))
        {
            return Err(bad("only service tokens are supported"));
        }
        let parent = self.check_principal(actor, namespace, now)?.clone();
        if parent.uses_remaining.is_some() {
            return Err(bad("limited-use tokens cannot create child tokens"));
        }
        let add_default = !boolean(body, "no_default_policy", false)?;
        let requested = policies(body, "policies", &parent.policies, add_default)?;
        if !parent.root && (!requested.is_subset(&parent.policies) || requested.contains("root")) {
            return Err(denied());
        }
        let root = requested.contains("root");
        if root && (requested.len() != 1 || !namespace.is_empty()) {
            return Err(bad("root policy must be exclusive and in root namespace"));
        }
        let no_parent = force_orphan || boolean(body, "no_parent", false)?;
        let period = duration(body, "period", 0)?;
        if no_parent || period > 0 {
            self.authorize_request(actor, namespace, path, "sudo", now)?;
        }
        if period > MAX_TTL {
            return Err(bad("period exceeds maximum TTL"));
        }
        let ttl = duration(body, "ttl", DEFAULT_TTL)?;
        let ttl = if period > 0 {
            period
        } else if ttl == 0 && !root {
            DEFAULT_TTL
        } else {
            ttl
        };
        if ttl > MAX_TTL {
            return Err(bad("TTL exceeds maximum"));
        }
        let explicit_max = duration(body, "explicit_max_ttl", 0)?;
        if explicit_max > MAX_TTL {
            return Err(bad("explicit maximum TTL exceeds service maximum"));
        }
        let max_expires_at = if explicit_max > 0 {
            Some(checked_expiry(now, explicit_max)?)
        } else if period == 0 && !(root && ttl == 0) {
            Some(checked_expiry(now, MAX_TTL)?)
        } else {
            None
        };
        let mut expires_at = if root && ttl == 0 {
            None
        } else {
            Some(checked_expiry(now, ttl)?)
        };
        if let (Some(expiry), Some(max)) = (expires_at, max_expires_at) {
            expires_at = Some(expiry.min(max));
        }
        if !no_parent && let Some(parent_expiry) = parent.expires_at {
            expires_at = Some(
                expires_at
                    .map(|e| e.min(parent_expiry))
                    .unwrap_or(parent_expiry),
            );
        }
        let display_name = body
            .get("display_name")
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| bad("display name must be a string"))
            })
            .transpose()?
            .unwrap_or("token");
        if display_name.len() > 128 {
            return Err(bad("display name too long"));
        }
        self.issue(
            Token {
                accessor: random_id("a.")?,
                namespace: namespace.into(),
                policies: requested,
                root,
                parent: if no_parent {
                    None
                } else {
                    Some(actor.digest.clone())
                },
                created_at: now,
                expires_at,
                max_expires_at,
                period,
                renewable: boolean(body, "renewable", true)? && expires_at.is_some(),
                uses_remaining: unlimited_zero(number(body, "num_uses", 0)?),
                display_name: display_name.into(),
                auth_mount: parent.auth_mount.clone(),
                auth_origin_known: parent.root || parent.auth_origin_known,
            },
            now,
        )
    }

    fn policy_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/policies/acl")
            .or_else(|| path.strip_prefix("sys/policy"))
            .ok_or_else(|| bad("invalid policy route"))?;
        let name = suffix.strip_prefix('/').unwrap_or(suffix);
        let capability = match method {
            "GET" if name.is_empty() => "list",
            "GET" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Err(err(405, "method not allowed")),
        };
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() {
            if capability != "list" {
                return Err(bad("policy name required"));
            }
            let mut keys: BTreeSet<String> = self
                .policies
                .get(namespace)
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default();
            keys.insert("default".into());
            if namespace.is_empty() {
                keys.insert("root".into());
            }
            return Ok(response(json!({"keys": keys, "policies": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid policy name"));
        }
        if name == "root" {
            return Err(bad("root policy cannot be read, changed, or deleted"));
        }
        if capability == "read" {
            let source = match self
                .policies
                .get(namespace)
                .and_then(|entries| entries.get(name))
            {
                Some(policy) => policy.source.clone(),
                None if name == "default" => default_policy_source(),
                None => return Err(err(404, "policy not found")),
            };
            return Ok(response(
                json!({"name": name, "policy": source, "rules": source}),
                false,
            ));
        }
        self.authorize_request(actor, namespace, path, "sudo", now)?;
        if capability == "delete" {
            if name == "default" {
                return Err(bad("default policy cannot be deleted"));
            }
            if let Some(entries) = self.policies.get_mut(namespace) {
                entries.remove(name);
            }
            return Ok(empty(true));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["policy"])?;
        let input = body
            .get("policy")
            .ok_or_else(|| bad("policy is required"))?;
        let policy = parse_policy(input)?;
        self.policies
            .entry(namespace.into())
            .or_default()
            .insert(name.into(), policy);
        Ok(empty(true))
    }

    fn user_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let suffix = path
            .strip_prefix(&format!("auth/{mount}/users"))
            .ok_or_else(|| bad("invalid user route"))?
            .trim_start_matches('/');
        let (name, subpath) = suffix.split_once('/').unwrap_or((suffix, ""));
        let capability = route_capability(method, suffix.is_empty())?;
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() && capability == "list" {
            let keys: Vec<&str> = self
                .users_at(scope)
                .map(|users| users.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) || !["", "password", "policies", "mfa"].contains(&subpath) {
            return Err(bad("invalid user route"));
        }
        let existing = self
            .users_at(scope)
            .and_then(|users| users.get(name))
            .cloned();
        if subpath == "mfa" {
            let mut user = existing.ok_or_else(|| err(404, "user not found"))?;
            match capability {
                "read" => {
                    reject_unknown(body, &[])?;
                    let enrollment = user
                        .mfa
                        .as_ref()
                        .ok_or_else(|| err(404, "MFA enrollment not found"))?;
                    return Ok(response(
                        json!({
                            "enabled": true,
                            "type": "totp",
                            "algorithm": "SHA256",
                            "digits": enrollment.digits,
                            "period": enrollment.period_seconds,
                            "last_counter_present": enrollment.last_accepted_counter.is_some()
                        }),
                        false,
                    ));
                }
                "delete" => {
                    reject_unknown(body, &[])?;
                    self.authorize_request(actor, namespace, path, "sudo", now)?;
                    let changed = user.mfa.take().is_some();
                    self.users_at_mut(scope).insert(name.into(), user);
                    return Ok(empty(changed));
                }
                "update" => {
                    reject_unknown(body, &["regenerate"])?;
                    self.authorize_request(actor, namespace, path, "sudo", now)?;
                    let regenerate = boolean(body, "regenerate", false)?;
                    if user.mfa.is_some() && !regenerate {
                        return Err(bad(
                            "MFA is already enrolled; explicit regenerate=true is required",
                        ));
                    }
                    let secret = random_bytes(MFA_SEED_BYTES)?;
                    let secret_base32 = Zeroizing::new(base32_no_padding(&secret));
                    user.mfa = Some(TotpEnrollment {
                        secret,
                        period_seconds: MFA_PERIOD_SECONDS,
                        digits: u8::try_from(MFA_DIGITS)
                            .map_err(|_| err(500, "invalid MFA digit configuration"))?,
                        last_accepted_counter: None,
                    });
                    self.users_at_mut(scope).insert(name.into(), user);
                    return Ok(response(
                        json!({
                            "enabled": true,
                            "type": "totp",
                            "algorithm": "SHA256",
                            "digits": MFA_DIGITS,
                            "period": MFA_PERIOD_SECONDS,
                            "secret_base32": secret_base32.as_str()
                        }),
                        true,
                    ));
                }
                _ => return Err(err(405, "method not allowed")),
            }
        }
        if capability == "read" && subpath.is_empty() {
            let user = existing.ok_or_else(|| err(404, "user not found"))?;
            return Ok(response(
                json!({"policies": user.policies, "token_policies": user.policies, "token_ttl": user.token_ttl, "token_max_ttl": user.token_max_ttl, "token_num_uses": user.token_num_uses}),
                false,
            ));
        }
        if capability == "delete" && subpath.is_empty() {
            self.users_at_mut(scope).remove(name);
            return Ok(empty(true));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(
            body,
            &[
                "password",
                "policies",
                "token_policies",
                "ttl",
                "max_ttl",
                "token_ttl",
                "token_max_ttl",
                "token_num_uses",
            ],
        )?;
        if subpath == "password"
            && (body.as_object().is_none_or(|o| o.len() != 1) || body.get("password").is_none())
        {
            return Err(bad("password endpoint accepts only password"));
        }
        if subpath == "policies"
            && body
                .as_object()
                .is_some_and(|o| o.keys().any(|k| k != "policies" && k != "token_policies"))
        {
            return Err(bad("policies endpoint accepts only policy fields"));
        }
        let mut user = existing.clone().unwrap_or(User {
            salt: vec![],
            verifier: vec![],
            rounds: PASSWORD_ROUNDS,
            policies: BTreeSet::from(["default".into()]),
            token_ttl: DEFAULT_TTL,
            token_max_ttl: MAX_TTL,
            token_num_uses: 0,
            mfa: None,
        });
        if let Some(password) = body.get("password") {
            let password = password
                .as_str()
                .ok_or_else(|| bad("password must be a string"))?;
            if password.len() < 12 || password.len() > 1024 {
                return Err(bad("password must be 12 to 1024 bytes"));
            }
            user.salt.zeroize();
            user.verifier.zeroize();
            user.salt = random_bytes(32)?;
            user.verifier = vec![0; digest::SHA256_OUTPUT_LEN];
            user.rounds = PASSWORD_ROUNDS;
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(PASSWORD_ROUNDS)
                    .ok_or_else(|| err(500, "invalid password parameters"))?,
                &user.salt,
                password.as_bytes(),
                &mut user.verifier,
            );
        } else if existing.is_none() {
            return Err(bad("password is required for new user"));
        }
        reject_alias_pair(body, "policies", "token_policies")?;
        reject_alias_pair(body, "ttl", "token_ttl")?;
        reject_alias_pair(body, "max_ttl", "token_max_ttl")?;
        user.policies = policies(
            body,
            if body.get("token_policies").is_some() {
                "token_policies"
            } else {
                "policies"
            },
            &user.policies,
            true,
        )?;
        self.validate_assignment(actor, &user.policies)?;
        user.token_ttl = duration(
            body,
            if body.get("token_ttl").is_some() {
                "token_ttl"
            } else {
                "ttl"
            },
            user.token_ttl,
        )?;
        user.token_max_ttl = duration(
            body,
            if body.get("token_max_ttl").is_some() {
                "token_max_ttl"
            } else {
                "max_ttl"
            },
            user.token_max_ttl,
        )?;
        normalize_ttl(&mut user.token_ttl, &mut user.token_max_ttl)?;
        user.token_num_uses = number(body, "token_num_uses", user.token_num_uses)?;
        self.users_at_mut(scope).insert(name.into(), user);
        Ok(empty(true))
    }

    fn validate_assignment(
        &self,
        actor: &Principal,
        requested: &BTreeSet<String>,
    ) -> Result<(), AuthError> {
        if requested.contains("root") || !actor.is_root() && !requested.is_subset(actor.policies())
        {
            return Err(denied());
        }
        Ok(())
    }

    fn login_userpass(
        &mut self,
        scope: AuthScope<'_>,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        if !valid_name(name) {
            return Err(denied());
        }
        reject_unknown(body, &["password", "totp_code"])?;
        let password = string_field(body, "password")?;
        if password.len() > 1024 {
            return Err(denied());
        }
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(name))
            .cloned();
        // A nonexistent account still performs the same password KDF.
        let dummy_salt = [0u8; 32];
        let dummy_verifier = [0u8; 32];
        let (rounds, salt, verifier) = user
            .as_ref()
            .map(|u| (u.rounds, u.salt.as_slice(), u.verifier.as_slice()))
            .unwrap_or((PASSWORD_ROUNDS, &dummy_salt, &dummy_verifier));
        let rounds = NonZeroU32::new(rounds).ok_or_else(denied)?;
        let verified = pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            salt,
            password.as_bytes(),
            verifier,
        )
        .is_ok();
        let mut user = user.filter(|_| verified).ok_or_else(denied)?;
        let accepted_counter = match user.mfa.as_ref() {
            Some(enrollment) => Some(verify_totp(
                enrollment,
                body.get("totp_code")
                    .and_then(Value::as_str)
                    .ok_or_else(denied)?,
                now,
            )?),
            None => {
                if body.get("totp_code").is_some() {
                    return Err(bad("MFA is not configured for this user"));
                }
                None
            }
        };
        let mut token = login_token(
            namespace,
            user.policies.clone(),
            user.token_ttl,
            user.token_max_ttl,
            user.token_num_uses,
            format!("userpass-{name}"),
            now,
        )?;
        token.auth_mount = Some(mount.into());
        let (token_id, token, response) = Self::prepare_issue(token, now)?;
        if let Some(counter) = accepted_counter {
            let enrollment = user
                .mfa
                .as_mut()
                .ok_or_else(|| err(500, "MFA enrollment disappeared during login"))?;
            enrollment.last_accepted_counter = Some(counter);
        }
        self.users_at_mut(scope).insert(name.into(), user);
        self.tokens.insert(token_id, token);
        Ok(response)
    }

    fn role_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        let suffix = path
            .strip_prefix(&format!("auth/{mount}/role"))
            .ok_or_else(|| bad("invalid role route"))?
            .trim_start_matches('/');
        let (name, operation) = suffix.split_once('/').unwrap_or((suffix, ""));
        let capability = route_capability(
            method,
            suffix.is_empty() || operation == "secret-id" && method == "LIST",
        )?;
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() && capability == "list" {
            let keys: Vec<&str> = self
                .roles_at(scope)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid role name"));
        }
        let existing = self
            .roles_at(scope)
            .and_then(|roles| roles.get(name))
            .cloned();
        if operation.is_empty() {
            if capability == "read" {
                let role = existing.ok_or_else(|| err(404, "role not found"))?;
                return Ok(response(
                    json!({"bind_secret_id": true, "token_policies": role.policies, "token_ttl": role.token_ttl,
                    "token_max_ttl": role.token_max_ttl, "token_num_uses": role.token_num_uses, "secret_id_ttl": role.secret_id_ttl, "secret_id_num_uses": role.secret_id_num_uses}),
                    false,
                ));
            }
            if capability == "delete" {
                self.roles_at_mut(scope).remove(name);
                return Ok(empty(true));
            }
            if capability != "update" {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(
                body,
                &[
                    "bind_secret_id",
                    "policies",
                    "token_policies",
                    "token_ttl",
                    "token_max_ttl",
                    "token_num_uses",
                    "secret_id_ttl",
                    "secret_id_num_uses",
                ],
            )?;
            if !boolean(body, "bind_secret_id", true)? {
                return Err(bad("AppRole requires secret_id binding"));
            }
            reject_alias_pair(body, "policies", "token_policies")?;
            let mut role = existing.unwrap_or(Role {
                role_id: random_id("role.")?,
                policies: BTreeSet::from(["default".into()]),
                token_ttl: DEFAULT_TTL,
                token_max_ttl: MAX_TTL,
                token_num_uses: 0,
                secret_id_ttl: DEFAULT_TTL,
                secret_id_num_uses: 1,
                secret_ids: BTreeMap::new(),
            });
            role.policies = policies(
                body,
                if body.get("token_policies").is_some() {
                    "token_policies"
                } else {
                    "policies"
                },
                &role.policies,
                true,
            )?;
            self.validate_assignment(actor, &role.policies)?;
            role.token_ttl = duration(body, "token_ttl", role.token_ttl)?;
            role.token_max_ttl = duration(body, "token_max_ttl", role.token_max_ttl)?;
            normalize_ttl(&mut role.token_ttl, &mut role.token_max_ttl)?;
            role.token_num_uses = number(body, "token_num_uses", role.token_num_uses)?;
            role.secret_id_ttl = duration(body, "secret_id_ttl", role.secret_id_ttl)?;
            if role.secret_id_ttl > MAX_TTL {
                return Err(bad("secret_id TTL exceeds maximum"));
            }
            role.secret_id_num_uses = number(body, "secret_id_num_uses", role.secret_id_num_uses)?;
            self.roles_at_mut(scope).insert(name.into(), role);
            return Ok(empty(true));
        }
        let mut role = existing.ok_or_else(|| err(404, "role not found"))?;
        match (operation, capability) {
            ("role-id", "read") => Ok(response(json!({"role_id": role.role_id}), false)),
            ("role-id", "update") => {
                reject_unknown(body, &["role_id"])?;
                let value = string_field(body, "role_id")?;
                if value.is_empty()
                    || value.len() > 256
                    || self.roles_at(scope).is_some_and(|roles| {
                        roles
                            .iter()
                            .any(|(other, role)| other != name && role.role_id == value)
                    })
                {
                    return Err(bad("invalid or duplicate role_id"));
                }
                role.role_id = value.into();
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            ("secret-id", "list") => {
                let keys: Vec<&str> = role
                    .secret_ids
                    .values()
                    .filter(|secret| {
                        !secret.expires_at.is_some_and(|t| t <= now)
                            && secret.uses_remaining != Some(0)
                    })
                    .map(|secret| secret.accessor.as_str())
                    .collect();
                Ok(response(json!({"keys": keys}), false))
            }
            ("secret-id", "update") => {
                reject_unknown(body, &["ttl", "num_uses"])?;
                let ttl = duration(body, "ttl", role.secret_id_ttl)?;
                let num_uses = number(body, "num_uses", role.secret_id_num_uses)?;
                if ttl > MAX_TTL
                    || role.secret_id_ttl > 0 && (ttl == 0 || ttl > role.secret_id_ttl)
                    || role.secret_id_num_uses > 0
                        && (num_uses == 0 || num_uses > role.secret_id_num_uses)
                {
                    return Err(bad("secret_id constraints exceed role limits"));
                }
                let raw = Zeroizing::new(random_id("secret.")?);
                let accessor = random_id("sa.")?;
                let expires_at = if ttl == 0 {
                    None
                } else {
                    Some(checked_expiry(now, ttl)?)
                };
                role.secret_ids.insert(
                    hash(&raw),
                    SecretId {
                        accessor: accessor.clone(),
                        expires_at,
                        uses_remaining: unlimited_zero(num_uses),
                    },
                );
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(response(
                    json!({"secret_id": raw.as_str(), "secret_id_accessor": accessor, "secret_id_ttl": ttl, "secret_id_num_uses": num_uses}),
                    true,
                ))
            }
            ("secret-id/lookup", "update")
            | ("secret-id-accessor/lookup", "update")
            | ("secret-id/destroy", "update")
            | ("secret-id-accessor/destroy", "update") => {
                let by_accessor = operation.starts_with("secret-id-accessor/");
                reject_unknown(
                    body,
                    if by_accessor {
                        &["secret_id_accessor"]
                    } else {
                        &["secret_id"]
                    },
                )?;
                let id = if by_accessor {
                    let wanted = string_field(body, "secret_id_accessor")?;
                    role.secret_ids
                        .iter()
                        .find(|(_, secret)| secret.accessor == wanted)
                        .map(|(id, _)| id.clone())
                        .ok_or_else(|| err(404, "secret_id not found"))?
                } else {
                    hash(string_field(body, "secret_id")?)
                };
                let secret = role
                    .secret_ids
                    .get(&id)
                    .ok_or_else(|| err(404, "secret_id not found"))?;
                if operation.ends_with("/lookup") {
                    return Ok(response(
                        json!({"secret_id_accessor": secret.accessor, "secret_id_num_uses": secret.uses_remaining.unwrap_or(0), "expiration_time_unix": secret.expires_at}),
                        false,
                    ));
                }
                if let Some((mut stored_id, _)) = role.secret_ids.remove_entry(&id) {
                    stored_id.zeroize();
                }
                self.roles_at_mut(scope).insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(err(404, "unsupported AppRole operation")),
        }
    }

    fn login_approle(
        &mut self,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let AuthScope { namespace, mount } = scope;
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["role_id", "secret_id"])?;
        let role_id = string_field(body, "role_id")?;
        let secret_id = string_field(body, "secret_id")?;
        if role_id.len() > 256 || secret_id.len() > 256 {
            return Err(denied());
        }
        let (name, mut role) = self
            .roles_at(scope)
            .and_then(|roles| roles.iter().find(|(_, role)| role.role_id == role_id))
            .map(|(name, role)| (name.clone(), role.clone()))
            .ok_or_else(denied)?;
        let id = hash(secret_id);
        let secret = role.secret_ids.get_mut(&id).ok_or_else(denied)?;
        if secret.expires_at.is_some_and(|expiry| now >= expiry) || secret.uses_remaining == Some(0)
        {
            return Err(denied());
        }
        if let Some(remaining) = &mut secret.uses_remaining {
            *remaining -= 1;
        }
        let mut token = login_token(
            namespace,
            role.policies.clone(),
            role.token_ttl,
            role.token_max_ttl,
            role.token_num_uses,
            format!("approle-{name}"),
            now,
        )?;
        token.auth_mount = Some(mount.into());
        let issued = self.issue(token, now)?;
        self.roles_at_mut(scope).insert(name, role);
        Ok(issued)
    }
}

fn base32_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
            output.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
        output.push(char::from(ALPHABET[index]));
    }
    output
}

fn totp_code(secret: &[u8], counter: u64) -> [u8; MFA_DIGITS] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = usize::from(bytes[bytes.len() - 1] & 0x0f);
    let binary = (u32::from(bytes[offset]) & 0x7f) << 24
        | u32::from(bytes[offset + 1]) << 16
        | u32::from(bytes[offset + 2]) << 8
        | u32::from(bytes[offset + 3]);
    let mut value = binary % 1_000_000;
    let mut code = [b'0'; MFA_DIGITS];
    for position in (0..MFA_DIGITS).rev() {
        code[position] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
    }
    code
}

fn verify_totp(enrollment: &TotpEnrollment, supplied: &str, now: u64) -> Result<u64, AuthError> {
    if enrollment.secret.len() != MFA_SEED_BYTES
        || enrollment.period_seconds != MFA_PERIOD_SECONDS
        || usize::from(enrollment.digits) != MFA_DIGITS
        || supplied.len() != MFA_DIGITS
        || !supplied.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(denied());
    }
    let current = now / enrollment.period_seconds;
    let start = current.saturating_sub(MFA_DRIFT_STEPS);
    let end = current.saturating_add(MFA_DRIFT_STEPS);
    let mut accepted = None;
    for counter in start..=end {
        if enrollment
            .last_accepted_counter
            .is_some_and(|last| counter <= last)
        {
            continue;
        }
        let expected = totp_code(&enrollment.secret, counter);
        let comparison_key = hmac::Key::new(hmac::HMAC_SHA256, &enrollment.secret);
        let expected_tag = hmac::sign(&comparison_key, &expected);
        if hmac::verify(&comparison_key, supplied.as_bytes(), expected_tag.as_ref()).is_ok() {
            accepted = Some(accepted.map_or(counter, |found: u64| found.max(counter)));
        }
    }
    accepted.ok_or_else(denied)
}

fn route_capability(method: &str, collection: bool) -> Result<&'static str, AuthError> {
    match method {
        "GET" if collection => Ok("list"),
        "GET" => Ok("read"),
        "LIST" => Ok("list"),
        "POST" | "PUT" => Ok("update"),
        "DELETE" => Ok("delete"),
        _ => Err(err(405, "method not allowed")),
    }
}
fn reject_alias_pair(body: &Value, a: &str, b: &str) -> Result<(), AuthError> {
    if body.get(a).is_some() && body.get(b).is_some() {
        return Err(bad("conflicting aliases"));
    }
    Ok(())
}
fn normalize_ttl(ttl: &mut u64, max_ttl: &mut u64) -> Result<(), AuthError> {
    if *ttl == 0 {
        *ttl = DEFAULT_TTL;
    }
    if *max_ttl == 0 {
        *max_ttl = MAX_TTL;
    }
    if *ttl > *max_ttl || *max_ttl > MAX_TTL {
        return Err(bad("invalid token TTL limits"));
    }
    Ok(())
}
fn login_token(
    namespace: &str,
    policies: BTreeSet<String>,
    ttl: u64,
    max_ttl: u64,
    uses: u64,
    display_name: String,
    now: u64,
) -> Result<Token, AuthError> {
    if policies.contains("root") {
        return Err(denied());
    }
    Ok(Token {
        accessor: random_id("a.")?,
        namespace: namespace.into(),
        policies,
        root: false,
        parent: None,
        created_at: now,
        expires_at: Some(checked_expiry(now, ttl)?),
        max_expires_at: Some(checked_expiry(now, max_ttl)?),
        period: 0,
        renewable: true,
        uses_remaining: unlimited_zero(uses),
        display_name,
        auth_mount: None,
        auth_origin_known: true,
    })
}
fn token_info(token: &Token, now: u64) -> Value {
    json!({"accessor": token.accessor, "policies": token.policies, "display_name": token.display_name,
        "creation_time": token.created_at, "ttl": token.expires_at.map(|t| t.saturating_sub(now)).unwrap_or(0),
        "expire_time_unix": token.expires_at, "explicit_max_ttl": token.max_expires_at.map(|t| t.saturating_sub(token.created_at)).unwrap_or(0),
        "period": token.period, "num_uses": token.uses_remaining.unwrap_or(0), "renewable": token.renewable,
        "orphan": token.parent.is_none(), "type": "service", "namespace": token.namespace})
}

fn default_grants(path: &str, capability: &str) -> bool {
    matches!(
        (path, capability),
        ("auth/token/lookup-self", "read")
            | ("auth/token/renew-self", "update")
            | ("auth/token/revoke-self", "update")
    )
}
fn default_policy_source() -> String {
    "path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }\npath \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n".into()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let prefix = pattern.strip_suffix('*');
    let pattern = prefix.unwrap_or(pattern);
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    if prefix.is_none() && pattern_parts.len() != path_parts.len() {
        return false;
    }
    if path_parts.len() < pattern_parts.len() {
        return false;
    }
    for (index, segment) in pattern_parts.iter().enumerate() {
        let Some(actual) = path_parts.get(index) else {
            return false;
        };
        if prefix.is_some() && index + 1 == pattern_parts.len() {
            if *segment == "+" {
                return !actual.is_empty();
            }
            return actual.starts_with(segment);
        }
        if *segment == "+" {
            if actual.is_empty() {
                return false;
            }
        } else if segment != actual {
            return false;
        }
    }
    true
}

/// Decode JSON without permitting duplicate object keys at any depth. The
/// caller owns clearing a successful Value; partial values clear on parse errors.
pub(crate) fn parse_strict_json(bytes: &[u8]) -> Result<Value, AuthError> {
    let mut parsed = serde_json::from_slice::<StrictJson>(bytes)
        .map_err(|_| bad("invalid JSON or duplicate object key"))?;
    Ok(std::mem::take(&mut parsed.0))
}

struct StrictJson(Value);
impl Drop for StrictJson {
    fn drop(&mut self) {
        erase_parsed_json(&mut self.0);
    }
}
fn erase_parsed_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                erase_parsed_json(value);
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                erase_parsed_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> serde::de::Visitor<'de> for JsonVisitor {
            type Value = StrictJson;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON number"))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value.into())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = StrictJson(Value::Array(Vec::new()));
                let values = result
                    .0
                    .as_array_mut()
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON array"))?;
                while let Some(mut value) = seq.next_element::<StrictJson>()? {
                    values.push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = StrictJson(Value::Object(serde_json::Map::new()));
                let values = result
                    .0
                    .as_object_mut()
                    .ok_or_else(|| serde::de::Error::custom("invalid JSON object"))?;
                while let Some(key) = map.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    if values.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let mut value = map.next_value::<StrictJson>()?;
                    values.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse_policy(input: &Value) -> Result<Policy, AuthError> {
    let source = if let Some(source) = input.as_str() {
        source.to_owned()
    } else {
        serde_json::to_string(input).map_err(|_| bad("invalid policy"))?
    };
    if source.len() > 256 * 1024 {
        return Err(bad("policy too large"));
    }
    let trimmed = source.trim();
    let rules = if trimmed.starts_with('{') {
        let parsed = parse_strict_json(trimmed.as_bytes())?;
        reject_unknown(&parsed, &["path"])?;
        let paths = parsed
            .get("path")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("policy path object is required"))?;
        let mut rules = Vec::new();
        for (path, config) in paths {
            reject_unknown(config, &["capabilities"])?;
            let caps = config
                .get("capabilities")
                .and_then(Value::as_array)
                .ok_or_else(|| bad("capabilities array is required"))?;
            let caps = caps
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| bad("capability must be a string"))
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            rules.push(rule(path.clone(), caps)?);
        }
        rules
    } else {
        let tokens = lex_hcl(trimmed)?;
        let mut cursor = 0;
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        while cursor < tokens.len() {
            take(&tokens, &mut cursor, Lex::Word("path".into()))?;
            let path = take_string(&tokens, &mut cursor)?;
            if !seen.insert(path.clone()) {
                return Err(bad("duplicate ACL path"));
            }
            take(&tokens, &mut cursor, Lex::Symbol('{'))?;
            take(&tokens, &mut cursor, Lex::Word("capabilities".into()))?;
            take(&tokens, &mut cursor, Lex::Symbol('='))?;
            take(&tokens, &mut cursor, Lex::Symbol('['))?;
            let mut caps = BTreeSet::new();
            if tokens.get(cursor) != Some(&Lex::Symbol(']')) {
                loop {
                    caps.insert(take_string(&tokens, &mut cursor)?);
                    if tokens.get(cursor) != Some(&Lex::Symbol(',')) {
                        break;
                    }
                    cursor += 1;
                    if tokens.get(cursor) == Some(&Lex::Symbol(']')) {
                        break;
                    }
                }
            }
            take(&tokens, &mut cursor, Lex::Symbol(']'))?;
            take(&tokens, &mut cursor, Lex::Symbol('}'))?;
            rules.push(rule(path, caps)?);
        }
        rules
    };
    if rules.len() > 4096 {
        return Err(bad("too many policy rules"));
    }
    Ok(Policy { source, rules })
}
fn rule(path: String, capabilities: BTreeSet<String>) -> Result<Rule, AuthError> {
    validate_path(&path, true)?;
    if capabilities
        .iter()
        .any(|capability| !CAPABILITIES.contains(&capability.as_str()))
    {
        return Err(bad("unsupported ACL capability"));
    }
    Ok(Rule { path, capabilities })
}

#[derive(Clone, PartialEq)]
enum Lex {
    Word(String),
    String(String),
    Symbol(char),
}
fn take(tokens: &[Lex], cursor: &mut usize, wanted: Lex) -> Result<(), AuthError> {
    if tokens.get(*cursor) != Some(&wanted) {
        return Err(bad("unsupported or malformed HCL policy"));
    }
    *cursor += 1;
    Ok(())
}
fn take_string(tokens: &[Lex], cursor: &mut usize) -> Result<String, AuthError> {
    if let Some(Lex::String(value)) = tokens.get(*cursor) {
        *cursor += 1;
        Ok(value.clone())
    } else {
        Err(bad("quoted string required in HCL policy"))
    }
}
fn lex_hcl(source: &str) -> Result<Vec<Lex>, AuthError> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut result = Vec::new();
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'#' || bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(bad("unterminated HCL comment"));
            }
            index += 2;
            continue;
        }
        if b"{}[]=,".contains(&bytes[index]) {
            result.push(Lex::Symbol(bytes[index] as char));
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                if bytes[index] == b'"' && !escaped {
                    break;
                }
                escaped = bytes[index] == b'\\' && !escaped;
                index += 1;
            }
            if index >= bytes.len() {
                return Err(bad("unterminated HCL string"));
            }
            index += 1;
            let value: String = serde_json::from_str(&source[start..index])
                .map_err(|_| bad("invalid HCL string escape"))?;
            result.push(Lex::String(value));
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            result.push(Lex::Word(source[start..index].into()));
            continue;
        }
        return Err(bad("unsupported character in HCL policy"));
    }
    Ok(result)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
