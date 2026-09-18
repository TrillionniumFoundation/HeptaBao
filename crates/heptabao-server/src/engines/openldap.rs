//! Bounded OpenLDAP dynamic-credential state.
//!
//! The engine owns encrypted configuration, strict single-entry LDIF templates,
//! durable provider intents and leases. Network I/O is executed by Service after
//! the pending intent has been committed and the global writer is released.

use super::*;
use crate::{auth::LeaseIssuer, crypto, outbound::Target};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

const MAX_ROLES: usize = 64;
const MAX_PENDING: usize = 64;
const MAX_LEASES: usize = 1024;
const MIN_TTL: u64 = 60;
const MAX_TTL: u64 = 24 * 60 * 60;
const DEFAULT_TTL: u64 = 3600;
const DEFAULT_MAX_TTL: u64 = 24 * 60 * 60;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    url: String,
    binddn: String,
    bindpass: SecretString,
    userdn: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    creation_ldif: String,
    deletion_ldif: String,
    rollback_ldif: String,
    default_ttl: u64,
    max_ttl: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    PendingIssue,
    Active,
    PendingRevoke,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    role: String,
    username: String,
    dn: String,
    password: SecretString,
    owner: String,
    issued_at: u64,
    expires_at: u64,
    max_expires_at: u64,
    phase: Phase,
    config_digest: String,
    request_digest: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenLdap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config: Option<Config>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    roles: BTreeMap<String, Role>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    leases: BTreeMap<String, Lease>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum EffectAction {
    Issue,
    Revoke,
}

#[derive(Clone)]
pub(crate) struct LdapEntry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

#[derive(Clone)]
pub(crate) struct EffectPlan {
    pub namespace: String,
    pub mount: String,
    pub lease_id: String,
    pub action: EffectAction,
    pub provider_url: String,
    pub bind_dn: String,
    pub bind_password: SecretString,
    pub dn: String,
    pub username: String,
    pub password: SecretString,
    pub entry: Option<LdapEntry>,
    pub request_digest: String,
    pub config_digest: String,
}

pub(crate) enum Dispatch {
    Immediate(EngineResponse),
    External(Box<EffectPlan>),
}

fn err(status: u16, message: &str) -> EngineError {
    EngineError {
        status,
        message: message.into(),
    }
}
fn empty(mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 204,
        body: Value::Null,
        mutated,
    }
}
fn ok(body: Value, mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 200,
        body,
        mutated,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
fn valid_dn(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.is_ascii()
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
        && !value.contains('\n')
        && !value.contains('\r')
}
fn valid_attr(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}
fn duration(value: Option<&Value>, default: u64) -> std::result::Result<u64, EngineError> {
    let Some(value) = value else {
        return Ok(default);
    };
    if let Some(seconds) = value.as_u64() {
        return Ok(seconds);
    }
    let text = value
        .as_str()
        .ok_or_else(|| err(400, "LDAP TTL must be seconds or a bounded duration"))?;
    if text.is_empty() || text.len() > 32 {
        return Err(err(400, "invalid LDAP TTL"));
    }
    let mut total = 0_u64;
    let mut number = 0_u64;
    let mut digits = false;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| err(400, "LDAP TTL overflow"))?;
            digits = true;
            continue;
        }
        if !digits {
            return Err(err(400, "invalid LDAP TTL"));
        }
        let multiplier = match byte {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            _ => return Err(err(400, "LDAP TTL supports s, m and h")),
        };
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| err(400, "LDAP TTL overflow"))?,
            )
            .ok_or_else(|| err(400, "LDAP TTL overflow"))?;
        number = 0;
        digits = false;
    }
    if digits {
        total = total
            .checked_add(number)
            .ok_or_else(|| err(400, "LDAP TTL overflow"))?;
    }
    Ok(total)
}
fn config_digest(config: &Config) -> std::result::Result<String, EngineError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(config).map_err(|_| err(500, "LDAP config encoding failed"))?,
    );
    Ok(hex(&crypto::digest(&bytes)))
}
fn request_digest(
    role: &str,
    username: &str,
    dn: &str,
    ttl: u64,
    config_digest: &str,
) -> std::result::Result<String, EngineError> {
    let bytes = serde_json::to_vec(&json!({
        "role": role,
        "username": username,
        "dn": dn,
        "ttl": ttl,
        "config_digest": config_digest,
    }))
    .map_err(|_| err(500, "LDAP request encoding failed"))?;
    Ok(hex(&crypto::digest(&bytes)))
}

fn validate_template(
    source: &str,
    expect_delete: bool,
) -> std::result::Result<(), EngineError> {
    if source.is_empty() || source.len() > 32 * 1024 || source.contains('\r') {
        return Err(err(400, "LDAP LDIF template is outside the bounded profile"));
    }
    let mut dn = None;
    let mut change = None;
    let mut attributes = 0usize;
    for line in source.lines() {
        if line.is_empty() {
            return Err(err(400, "LDAP dynamic profile supports exactly one LDIF entry"));
        }
        if line.starts_with(' ') || line.starts_with('\t') || line.contains("::") {
            return Err(err(400, "LDAP folded/base64 LDIF is outside the bounded profile"));
        }
        let Some((name, value)) = line.split_once(": ") else {
            return Err(err(400, "invalid bounded LDAP LDIF line"));
        };
        if name.eq_ignore_ascii_case("dn") {
            if dn.replace(value).is_some() || !valid_dn(value) {
                return Err(err(400, "invalid LDAP LDIF distinguished name"));
            }
        } else if name.eq_ignore_ascii_case("changetype") {
            if change.replace(value).is_some() {
                return Err(err(400, "duplicate LDAP LDIF changetype"));
            }
        } else {
            if expect_delete || !valid_attr(name) || value.len() > 4096 || !value.is_ascii() {
                return Err(err(400, "unsupported LDAP LDIF attribute"));
            }
            attributes += 1;
        }
    }
    let dn = dn.ok_or_else(|| err(400, "LDAP LDIF dn is required"))?;
    let change = change.ok_or_else(|| err(400, "LDAP LDIF changetype is required"))?;
    if !dn.contains("{{.Username}}") || dn.contains("{{.Password}}") {
        return Err(err(400, "LDAP LDIF dn must bind the generated username"));
    }
    if dn.matches("{{").count() != 1 || dn.matches("}}").count() != 1 {
        return Err(err(400, "unsupported LDAP LDIF template expression"));
    }
    if expect_delete {
        if change != "delete" || attributes != 0 {
            return Err(err(400, "LDAP deletion/rollback LDIF must be one delete entry"));
        }
    } else if change != "add" || attributes == 0 || !source.contains("{{.Password}}") {
        return Err(err(400, "LDAP creation LDIF must add an entry and bind generated password"));
    }
    let stripped = source
        .replace("{{.Username}}", "")
        .replace("{{.Password}}", "");
    if stripped.contains("{{") || stripped.contains("}}") {
        return Err(err(400, "unsupported LDAP LDIF template expression"));
    }
    Ok(())
}

fn render_template(
    source: &str,
    username: &str,
    password: &str,
    user_dn: &str,
    expect_delete: bool,
) -> std::result::Result<LdapEntry, EngineError> {
    validate_template(source, expect_delete)?;
    let rendered = source
        .replace("{{.Username}}", username)
        .replace("{{.Password}}", password);
    let mut dn = String::new();
    let mut attrs = BTreeMap::<String, Vec<String>>::new();
    for line in rendered.lines() {
        let (name, value) = line
            .split_once(": ")
            .ok_or_else(|| err(500, "rendered LDAP LDIF is invalid"))?;
        if name.eq_ignore_ascii_case("dn") {
            dn = value.to_owned();
        } else if name.eq_ignore_ascii_case("changetype") {
        } else {
            attrs.entry(name.to_owned()).or_default().push(value.to_owned());
        }
    }
    if !valid_dn(&dn)
        || !(dn.eq_ignore_ascii_case(user_dn)
            || dn
                .to_ascii_lowercase()
                .ends_with(&format!(",{}", user_dn.to_ascii_lowercase())))
    {
        return Err(err(400, "LDAP dynamic entry escapes configured userdn"));
    }
    Ok(LdapEntry {
        dn,
        attributes: attrs.into_iter().collect(),
    })
}

impl OpenLdap {
    pub(crate) fn has_unresolved(&self) -> bool {
        !self.leases.is_empty()
    }

    pub(crate) fn validate(&self) -> std::result::Result<(), EngineError> {
        if self.roles.len() > MAX_ROLES || self.leases.len() > MAX_LEASES {
            return Err(err(503, "OpenLDAP secrets state exceeds bounded capacity"));
        }
        if self
            .leases
            .values()
            .filter(|lease| lease.phase != Phase::Active)
            .count()
            > MAX_PENDING
        {
            return Err(err(503, "OpenLDAP pending-effect capacity exhausted"));
        }
        if let Some(config) = &self.config {
            let target =
                Target::parse(&config.url, "ldaps").map_err(|_| err(503, "invalid LDAPS URL"))?;
            if target.origin != config.url
                || target.path != "/"
                || !valid_dn(&config.binddn)
                || !valid_dn(&config.userdn)
                || config.bindpass.expose().is_empty()
                || config.bindpass.expose().len() > 1024
            {
                return Err(err(503, "invalid OpenLDAP provider configuration"));
            }
        }
        for (name, role) in &self.roles {
            if !valid_name(name)
                || !(MIN_TTL..=MAX_TTL).contains(&role.default_ttl)
                || role.max_ttl < role.default_ttl
                || role.max_ttl > MAX_TTL
                || validate_template(&role.creation_ldif, false).is_err()
                || validate_template(&role.deletion_ldif, true).is_err()
                || (!role.rollback_ldif.is_empty()
                    && validate_template(&role.rollback_ldif, true).is_err())
            {
                return Err(err(503, "invalid OpenLDAP dynamic role state"));
            }
        }
        for (id, lease) in &self.leases {
            if !id.starts_with("ldap/") && !id.contains("/creds/") {
                return Err(err(503, "invalid OpenLDAP lease identity"));
            }
            if !valid_name(&lease.role)
                || !valid_name(&lease.username)
                || !valid_dn(&lease.dn)
                || lease.password.expose().is_empty()
                || lease.password.expose().len() > 256
                || lease.owner.len() != 64
                || lease.config_digest.len() != 64
                || lease.request_digest.len() != 64
                || lease.issued_at == 0
                || lease.expires_at < lease.issued_at
                || lease.max_expires_at < lease.expires_at
            {
                return Err(err(503, "invalid OpenLDAP lease state"));
            }
        }
        Ok(())
    }

    pub(crate) fn dispatch(
        &mut self,
        service_namespace: &str,
        mount: &str,
        method: &str,
        relative: &str,
        body: &Value,
        now: u64,
        issuer: Option<&LeaseIssuer>,
    ) -> std::result::Result<Dispatch, EngineError> {
        let object = body
            .as_object()
            .ok_or_else(|| err(400, "OpenLDAP request body must be an object"))?;
        if relative == "config" {
            return match method {
                "GET" | "HEAD" => {
                    if !object.is_empty() {
                        return Err(err(400, "OpenLDAP config read accepts an empty body"));
                    }
                    let config = self
                        .config
                        .as_ref()
                        .ok_or_else(|| err(404, "OpenLDAP secrets engine is not configured"))?;
                    Ok(Dispatch::Immediate(ok(
                        json!({"data":{
                            "url":config.url,
                            "binddn":config.binddn,
                            "bindpass_set":true,
                            "userdn":config.userdn,
                            "schema":"openldap"
                        }}),
                        false,
                    )))
                }
                "DELETE" => {
                    if self.has_unresolved() {
                        return Err(err(409, "OpenLDAP config is fenced while leases exist"));
                    }
                    let changed = self.config.take().is_some();
                    Ok(Dispatch::Immediate(empty(changed)))
                }
                "POST" | "PUT" => {
                    if object.keys().any(|key| {
                        !matches!(key.as_str(), "url" | "binddn" | "bindpass" | "userdn" | "schema")
                    }) {
                        return Err(err(400, "unsupported OpenLDAP config field"));
                    }
                    if self.has_unresolved() {
                        return Err(err(409, "OpenLDAP config is frozen while leases exist"));
                    }
                    if body
                        .get("schema")
                        .and_then(Value::as_str)
                        .is_some_and(|schema| schema != "openldap")
                    {
                        return Err(err(501, "only the OpenLDAP schema is implemented"));
                    }
                    let url = body
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "url is required"))?
                        .to_owned();
                    let target =
                        Target::parse(&url, "ldaps").map_err(|_| err(400, "invalid LDAPS URL"))?;
                    if target.origin != url || target.path != "/" {
                        return Err(err(400, "url must be a canonical LDAPS origin"));
                    }
                    let binddn = body
                        .get("binddn")
                        .and_then(Value::as_str)
                        .filter(|value| valid_dn(value))
                        .ok_or_else(|| err(400, "valid binddn is required"))?
                        .to_owned();
                    let bindpass = body
                        .get("bindpass")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty() && value.len() <= 1024)
                        .ok_or_else(|| err(400, "bounded bindpass is required"))?
                        .to_owned();
                    let userdn = body
                        .get("userdn")
                        .and_then(Value::as_str)
                        .filter(|value| valid_dn(value))
                        .ok_or_else(|| err(400, "valid userdn is required"))?
                        .to_owned();
                    self.config = Some(Config {
                        url,
                        binddn,
                        bindpass: SecretString(bindpass),
                        userdn,
                    });
                    self.validate()?;
                    Ok(Dispatch::Immediate(empty(true)))
                }
                _ => Err(err(405, "unsupported OpenLDAP config method")),
            };
        }

        if matches!(relative, "role" | "role/") {
            if !object.is_empty() {
                return Err(err(400, "OpenLDAP role list accepts an empty body"));
            }
            if !matches!(method, "LIST" | "SCAN" | "GET") {
                return Err(err(405, "OpenLDAP role list requires LIST"));
            }
            return Ok(Dispatch::Immediate(ok(
                json!({"data":{"keys":self.roles.keys().cloned().collect::<Vec<_>>()}}),
                false,
            )));
        }
        if let Some(role_name) = relative.strip_prefix("role/") {
            if role_name.contains('/') || !valid_name(role_name) {
                return Err(err(400, "invalid OpenLDAP role name"));
            }
            return match method {
                "GET" | "HEAD" => {
                    if !object.is_empty() {
                        return Err(err(400, "OpenLDAP role read accepts an empty body"));
                    }
                    let role = self
                        .roles
                        .get(role_name)
                        .ok_or_else(|| err(404, "OpenLDAP role not found"))?;
                    Ok(Dispatch::Immediate(ok(
                        json!({"data":{
                            "creation_ldif":role.creation_ldif,
                            "deletion_ldif":role.deletion_ldif,
                            "rollback_ldif":role.rollback_ldif,
                            "default_ttl":role.default_ttl,
                            "max_ttl":role.max_ttl
                        }}),
                        false,
                    )))
                }
                "DELETE" => {
                    if self.leases.values().any(|lease| lease.role == role_name) {
                        return Err(err(409, "OpenLDAP role is fenced while leases exist"));
                    }
                    Ok(Dispatch::Immediate(empty(self.roles.remove(role_name).is_some())))
                }
                "POST" | "PUT" => {
                    if object.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "creation_ldif"
                                | "deletion_ldif"
                                | "rollback_ldif"
                                | "default_ttl"
                                | "max_ttl"
                        )
                    }) {
                        return Err(err(400, "unsupported OpenLDAP role field"));
                    }
                    if self.roles.len() >= MAX_ROLES && !self.roles.contains_key(role_name) {
                        return Err(err(507, "OpenLDAP role capacity exhausted"));
                    }
                    if self.leases.values().any(|lease| lease.role == role_name) {
                        return Err(err(409, "OpenLDAP role is frozen while leases exist"));
                    }
                    let creation_ldif = body
                        .get("creation_ldif")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "creation_ldif is required"))?
                        .to_owned();
                    let deletion_ldif = body
                        .get("deletion_ldif")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "deletion_ldif is required"))?
                        .to_owned();
                    let rollback_ldif = body
                        .get("rollback_ldif")
                        .and_then(Value::as_str)
                        .unwrap_or(&deletion_ldif)
                        .to_owned();
                    validate_template(&creation_ldif, false)?;
                    validate_template(&deletion_ldif, true)?;
                    validate_template(&rollback_ldif, true)?;
                    let default_ttl = duration(body.get("default_ttl"), DEFAULT_TTL)?;
                    let max_ttl = duration(body.get("max_ttl"), DEFAULT_MAX_TTL)?;
                    if !(MIN_TTL..=MAX_TTL).contains(&default_ttl)
                        || max_ttl < default_ttl
                        || max_ttl > MAX_TTL
                    {
                        return Err(err(400, "OpenLDAP TTL is outside bounded profile"));
                    }
                    self.roles.insert(
                        role_name.to_owned(),
                        Role {
                            creation_ldif,
                            deletion_ldif,
                            rollback_ldif,
                            default_ttl,
                            max_ttl,
                        },
                    );
                    self.validate()?;
                    Ok(Dispatch::Immediate(empty(true)))
                }
                _ => Err(err(405, "unsupported OpenLDAP role method")),
            };
        }

        if let Some(role_name) = relative.strip_prefix("creds/") {
            if role_name.contains('/') || !valid_name(role_name) {
                return Err(err(400, "invalid OpenLDAP role name"));
            }
            if !matches!(method, "GET" | "POST" | "PUT") || !object.is_empty() {
                return Err(err(405, "OpenLDAP dynamic credentials use an empty read/write request"));
            }
            let issuer = issuer.ok_or_else(|| err(403, "OpenLDAP credentials require a live issuer"))?;
            let config = self
                .config
                .as_ref()
                .ok_or_else(|| err(503, "OpenLDAP secrets engine is not configured"))?
                .clone();
            let role = self
                .roles
                .get(role_name)
                .ok_or_else(|| err(404, "OpenLDAP role not found"))?
                .clone();
            if self.leases.len() >= MAX_LEASES
                || self
                    .leases
                    .values()
                    .filter(|lease| lease.phase != Phase::Active)
                    .count()
                    >= MAX_PENDING
            {
                return Err(err(507, "OpenLDAP lease or pending-effect capacity exhausted"));
            }
            let entropy = hex(
                &crypto::random::<8>()
                    .map_err(|_| err(503, "operating system randomness unavailable"))?,
            );
            let username = format!("v_{}_{}_{}", role_name, entropy, now);
            if !valid_name(&username) {
                return Err(err(500, "generated OpenLDAP username is invalid"));
            }
            let password = hex(
                &crypto::random::<24>()
                    .map_err(|_| err(503, "operating system randomness unavailable"))?,
            );
            let entry = render_template(
                &role.creation_ldif,
                &username,
                &password,
                &config.userdn,
                false,
            )?;
            let deletion = render_template(
                &role.deletion_ldif,
                &username,
                &password,
                &config.userdn,
                true,
            )?;
            if deletion.dn != entry.dn {
                return Err(err(400, "OpenLDAP creation/deletion LDIF target different DNs"));
            }
            let rollback = render_template(
                &role.rollback_ldif,
                &username,
                &password,
                &config.userdn,
                true,
            )?;
            if rollback.dn != entry.dn {
                return Err(err(400, "OpenLDAP rollback LDIF targets a different DN"));
            }
            let ttl = issuer
                .expires_at
                .map_or(role.default_ttl, |limit| limit.saturating_sub(now).min(role.default_ttl));
            if ttl < MIN_TTL {
                return Err(err(403, "OpenLDAP issuer lifetime is too short for a new lease"));
            }
            let expires_at = now
                .checked_add(ttl)
                .ok_or_else(|| err(400, "OpenLDAP lease expiry overflow"))?;
            let max_expires_at = now
                .checked_add(role.max_ttl)
                .ok_or_else(|| err(400, "OpenLDAP maximum lease expiry overflow"))?;
            let digest = config_digest(&config)?;
            let request = request_digest(role_name, &username, &entry.dn, ttl, &digest)?;
            let lease_id = format!("{mount}creds/{role_name}/{entropy}");
            self.leases.insert(
                lease_id.clone(),
                Lease {
                    role: role_name.to_owned(),
                    username: username.clone(),
                    dn: entry.dn.clone(),
                    password: SecretString(password.clone()),
                    owner: issuer.digest.clone(),
                    issued_at: now,
                    expires_at,
                    max_expires_at,
                    phase: Phase::PendingIssue,
                    config_digest: digest.clone(),
                    request_digest: request.clone(),
                },
            );
            self.validate()?;
            return Ok(Dispatch::External(Box::new(EffectPlan {
                namespace: service_namespace.to_owned(),
                mount: mount.to_owned(),
                lease_id,
                action: EffectAction::Issue,
                provider_url: config.url,
                bind_dn: config.binddn,
                bind_password: config.bindpass,
                dn: entry.dn.clone(),
                username,
                password: SecretString(password),
                entry: Some(entry),
                request_digest: request,
                config_digest: digest,
            })));
        }

        Err(err(404, "unsupported OpenLDAP secrets path"))
    }

    pub(crate) fn stage_revoke(
        &mut self,
        service_namespace: &str,
        mount: &str,
        lease_id: &str,
    ) -> std::result::Result<EffectPlan, EngineError> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| err(503, "OpenLDAP secrets engine is not configured"))?
            .clone();
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| err(404, "OpenLDAP lease not found"))?;
        lease.phase = Phase::PendingRevoke;
        let plan = EffectPlan {
            namespace: service_namespace.to_owned(),
            mount: mount.to_owned(),
            lease_id: lease_id.to_owned(),
            action: EffectAction::Revoke,
            provider_url: config.url,
            bind_dn: config.binddn,
            bind_password: config.bindpass,
            dn: lease.dn.clone(),
            username: lease.username.clone(),
            password: lease.password.clone(),
            entry: None,
            request_digest: lease.request_digest.clone(),
            config_digest: lease.config_digest.clone(),
        };
        self.validate()?;
        Ok(plan)
    }

    pub(crate) fn renew(
        &mut self,
        lease_id: &str,
        increment: u64,
        now: u64,
    ) -> std::result::Result<EngineResponse, EngineError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| err(404, "OpenLDAP lease not found"))?;
        if lease.phase != Phase::Active {
            return Err(err(409, "OpenLDAP lease is not active"));
        }
        let requested = now
            .checked_add(increment)
            .ok_or_else(|| err(400, "OpenLDAP renewal overflow"))?;
        lease.expires_at = requested.min(lease.max_expires_at);
        if lease.expires_at <= now {
            return Err(err(400, "OpenLDAP lease cannot be renewed beyond its maximum TTL"));
        }
        Ok(ok(
            json!({
                "lease_id":lease_id,
                "lease_duration":lease.expires_at.saturating_sub(now),
                "renewable":true
            }),
            true,
        ))
    }

    pub(crate) fn finalize(
        &mut self,
        plan: &EffectPlan,
    ) -> std::result::Result<EngineResponse, EngineError> {
        let lease = self
            .leases
            .get(&plan.lease_id)
            .ok_or_else(|| err(503, "OpenLDAP durable intent disappeared after provider entry"))?
            .clone();
        if lease.request_digest != plan.request_digest
            || lease.config_digest != plan.config_digest
            || lease.dn != plan.dn
            || lease.username != plan.username
        {
            return Err(err(503, "OpenLDAP durable intent changed after provider entry"));
        }
        let current_config = self
            .config
            .as_ref()
            .ok_or_else(|| err(503, "OpenLDAP provider configuration disappeared"))?;
        if config_digest(current_config)? != plan.config_digest {
            return Err(err(503, "OpenLDAP provider configuration changed after provider entry"));
        }
        match plan.action {
            EffectAction::Issue => {
                if lease.phase != Phase::PendingIssue {
                    return Err(err(503, "OpenLDAP issue intent is no longer pending"));
                }
                self.leases
                    .get_mut(&plan.lease_id)
                    .ok_or_else(|| err(503, "OpenLDAP lease disappeared"))?
                    .phase = Phase::Active;
                self.validate()?;
                Ok(ok(
                    json!({
                        "lease_id":plan.lease_id,
                        "lease_duration":lease.expires_at.saturating_sub(lease.issued_at),
                        "renewable":true,
                        "data":{
                            "username":lease.username,
                            "password":lease.password.expose(),
                            "distinguished_names":[lease.dn]
                        }
                    }),
                    true,
                ))
            }
            EffectAction::Revoke => {
                if lease.phase != Phase::PendingRevoke {
                    return Err(err(503, "OpenLDAP revoke intent is no longer pending"));
                }
                self.leases.remove(&plan.lease_id);
                self.validate()?;
                Ok(empty(true))
            }
        }
    }
}
