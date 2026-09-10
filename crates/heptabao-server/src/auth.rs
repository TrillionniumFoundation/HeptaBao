//! Durable authentication and a deliberately bounded, fail-closed ACL dialect.
//!
//! Every public service request owns one affine principal and durably commits any
//! finite-use decrement before dispatch. Raw authorization remains crate-internal.
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
const CAPABILITIES: &[&str] = &[
    "create", "read", "update", "delete", "list", "patch", "sudo", "deny",
];

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthState {
    tokens: BTreeMap<String, Token>,
    policies: BTreeMap<String, BTreeMap<String, Policy>>,
    users: BTreeMap<String, BTreeMap<String, User>>,
    roles: BTreeMap<String, BTreeMap<String, Role>>,
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

impl AuthState {
    pub(super) fn bootstrap(now: u64) -> Result<(Self, String), AuthError> {
        let mut state = Self {
            tokens: BTreeMap::new(),
            policies: BTreeMap::new(),
            users: BTreeMap::new(),
            roles: BTreeMap::new(),
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
        if path == "auth/approle/login" {
            return self.login_approle(namespace, method, body, now).map(Some);
        }
        if path == "auth/approle/tidy/secret-id" {
            if !matches!(method, "POST" | "PUT") {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &[])?;
            let actor = self.permission(principal, namespace, path, "update", now)?;
            self.authorize_request(actor, namespace, path, "sudo", now)?;
            let mut removed = 0;
            if let Some(roles) = self.roles.get_mut(namespace) {
                for role in roles.values_mut() {
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
            }
            return Ok(Some(response(
                json!({"removed_secret_ids": removed}),
                removed > 0,
            )));
        }
        if let Some(name) = path.strip_prefix("auth/userpass/login/") {
            return self
                .login_userpass(namespace, method, name, body, now)
                .map(Some);
        }
        if path.starts_with("auth/token/") {
            return self
                .token_route(principal, namespace, method, path, body, now)
                .map(Some);
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
        if path == "auth/userpass/users" || path.starts_with("auth/userpass/users/") {
            return self
                .user_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        if path == "auth/approle/role" || path.starts_with("auth/approle/role/") {
            return self
                .role_route(principal, namespace, method, path, body, now)
                .map(Some);
        }
        Ok(None)
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
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("auth/userpass/users")
            .ok_or_else(|| bad("invalid user route"))?
            .trim_start_matches('/');
        let (name, subpath) = suffix.split_once('/').unwrap_or((suffix, ""));
        let capability = route_capability(method, suffix.is_empty())?;
        let actor = self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() && capability == "list" {
            let keys: Vec<&str> = self
                .users
                .get(namespace)
                .map(|users| users.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) || !["", "password", "policies", "mfa"].contains(&subpath) {
            return Err(bad("invalid user route"));
        }
        let existing = self
            .users
            .get(namespace)
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
                    self.users
                        .entry(namespace.into())
                        .or_default()
                        .insert(name.into(), user);
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
                    self.users
                        .entry(namespace.into())
                        .or_default()
                        .insert(name.into(), user);
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
            if let Some(users) = self.users.get_mut(namespace) {
                users.remove(name);
            }
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
        self.users
            .entry(namespace.into())
            .or_default()
            .insert(name.into(), user);
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
        namespace: &str,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
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
            .users
            .get(namespace)
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
        let token = login_token(
            namespace,
            user.policies.clone(),
            user.token_ttl,
            user.token_max_ttl,
            user.token_num_uses,
            format!("userpass-{name}"),
            now,
        )?;
        let (token_id, token, response) = Self::prepare_issue(token, now)?;
        if let Some(counter) = accepted_counter {
            let enrollment = user
                .mfa
                .as_mut()
                .ok_or_else(|| err(500, "MFA enrollment disappeared during login"))?;
            enrollment.last_accepted_counter = Some(counter);
        }
        self.users
            .entry(namespace.into())
            .or_default()
            .insert(name.into(), user);
        self.tokens.insert(token_id, token);
        Ok(response)
    }

    fn role_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("auth/approle/role")
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
                .roles
                .get(namespace)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys": keys}), false));
        }
        if !valid_name(name) {
            return Err(bad("invalid role name"));
        }
        let existing = self
            .roles
            .get(namespace)
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
                if let Some(roles) = self.roles.get_mut(namespace) {
                    roles.remove(name);
                }
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
            self.roles
                .entry(namespace.into())
                .or_default()
                .insert(name.into(), role);
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
                    || self.roles.get(namespace).is_some_and(|roles| {
                        roles
                            .iter()
                            .any(|(other, role)| other != name && role.role_id == value)
                    })
                {
                    return Err(bad("invalid or duplicate role_id"));
                }
                role.role_id = value.into();
                self.roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(name.into(), role);
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
                self.roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(name.into(), role);
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
                self.roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(name.into(), role);
                Ok(empty(true))
            }
            _ => Err(err(404, "unsupported AppRole operation")),
        }
    }

    fn login_approle(
        &mut self,
        namespace: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
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
            .roles
            .get(namespace)
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
        let token = login_token(
            namespace,
            role.policies.clone(),
            role.token_ttl,
            role.token_max_ttl,
            role.token_num_uses,
            format!("approle-{name}"),
            now,
        )?;
        let issued = self.issue(token, now)?;
        self.roles
            .entry(namespace.into())
            .or_default()
            .insert(name, role);
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
