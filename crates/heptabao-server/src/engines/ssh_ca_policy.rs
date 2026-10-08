//! SSH CA role policy from the pinned OpenBao 2.7 signing producer.
//! This module grants no Service, actor, issuer, clock or publication authority.
use super::{Result, bad, error};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ssh_key::{EcdsaCurve, PublicKey, certificate::CertType, public::KeyData};
use std::collections::{BTreeMap, BTreeSet};

const MAX_DURATION: u64 = i64::MAX as u64 / 1_000_000_000;
const MAX_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaRole {
    default_user: String,
    default_user_template: bool,
    allowed_users: String,
    allowed_users_template: bool,
    allowed_domains: String,
    allowed_domains_template: bool,
    ttl: u64,
    max_ttl: u64,
    allowed_critical_options: String,
    allowed_extensions: String,
    default_critical_options: BTreeMap<String, String>,
    default_extensions: BTreeMap<String, String>,
    default_extensions_template: bool,
    allow_user_certificates: bool,
    allow_host_certificates: bool,
    allow_bare_domains: bool,
    allow_subdomains: bool,
    allow_user_key_ids: bool,
    key_id_format: String,
    allowed_user_key_lengths: BTreeMap<String, Vec<i64>>,
    algorithm_signer: String,
    not_before_duration: u64,
    allow_commas_in_identity_templates: bool,
    allow_empty_principals: bool,
    issuer_ref: String,
}

// These are policy inputs, not actor or publication capabilities.
pub(super) struct SigningContext<'a> {
    pub(super) role_name: &'a str,
    pub(super) display_name: &'a str,
    pub(super) now: u64,
    pub(super) default_ttl: u64,
    pub(super) max_ttl: u64,
}

pub(super) struct SigningPolicy {
    pub(super) kind: CertType,
    pub(super) principals: Vec<String>,
    pub(super) key_id: String,
    pub(super) valid_after: u64,
    pub(super) valid_before: u64,
    pub(super) critical_options: BTreeMap<String, String>,
    pub(super) extensions: BTreeMap<String, String>,
    pub(super) issuer_ref: String,
    pub(super) algorithm_signer: String,
}

impl CaRole {
    pub(super) fn parse(body: &Value) -> Result<Self> {
        if !body.is_object() {
            return Err(bad("SSH role body must be an object"));
        }
        if !text(body, "key_type", "")?.eq_ignore_ascii_case("ca") {
            return Err(bad("SSH CA role requires key_type ca"));
        }
        let mut algorithm_signer = text(body, "algorithm_signer", "default")?;
        if algorithm_signer.is_empty() {
            algorithm_signer = "default".into();
        }
        let mut issuer_ref = text(body, "issuer_ref", "default")?;
        if issuer_ref.is_empty() {
            issuer_ref = "default".into();
        }
        let role = Self {
            default_user: text(body, "default_user", "")?,
            default_user_template: boolean(body, "default_user_template")?,
            allowed_users: text(body, "allowed_users", "")?,
            allowed_users_template: boolean(body, "allowed_users_template")?,
            allowed_domains: text(body, "allowed_domains", "")?,
            allowed_domains_template: boolean(body, "allowed_domains_template")?,
            ttl: duration(body, "ttl", 0)?,
            max_ttl: duration(body, "max_ttl", 0)?,
            allowed_critical_options: text(body, "allowed_critical_options", "")?,
            allowed_extensions: text(body, "allowed_extensions", "")?,
            default_critical_options: string_map(body, "default_critical_options")?,
            default_extensions: string_map(body, "default_extensions")?,
            default_extensions_template: boolean(body, "default_extensions_template")?,
            allow_user_certificates: boolean(body, "allow_user_certificates")?,
            allow_host_certificates: boolean(body, "allow_host_certificates")?,
            allow_bare_domains: boolean(body, "allow_bare_domains")?,
            allow_subdomains: boolean(body, "allow_subdomains")?,
            allow_user_key_ids: boolean(body, "allow_user_key_ids")?,
            key_id_format: text(body, "key_id_format", "")?,
            allowed_user_key_lengths: key_lengths(body)?,
            algorithm_signer,
            not_before_duration: duration(body, "not_before_duration", 30)?,
            allow_commas_in_identity_templates: boolean(
                body,
                "allow_commas_in_identity_templates",
            )?,
            allow_empty_principals: boolean(body, "allow_empty_principals")?,
            issuer_ref,
        };
        role.validate()?;
        Ok(role)
    }

    pub(super) fn issuer_ref(&self) -> &str {
        &self.issuer_ref
    }

    pub(super) fn descriptor(&self) -> Value {
        // The endpoint exposes durations as seconds, not stored Go duration strings.
        let mut value = json!(self);
        if let Some(fields) = value.as_object_mut() {
            fields.insert("key_type".into(), json!("ca"));
        }
        value
    }

    pub(super) fn validate(&self) -> Result<()> {
        if !self.allow_user_certificates && !self.allow_host_certificates {
            return Err(bad(
                "Either allow_user_certificates or allow_host_certificates must be true",
            ));
        }
        if self.ttl > MAX_DURATION
            || self.max_ttl > MAX_DURATION
            || self.not_before_duration > MAX_DURATION
            || self.ttl != 0 && self.max_ttl != 0 && self.ttl > self.max_ttl
        {
            return Err(bad("invalid SSH CA role duration"));
        }
        if !matches!(
            self.algorithm_signer.as_str(),
            "default" | "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512"
        ) || self.issuer_ref.is_empty()
        {
            return Err(bad("invalid SSH CA issuer or signing algorithm"));
        }
        let encoded = serde_json::to_vec(self).map_err(|_| bad("invalid SSH CA role"))?;
        if encoded.len() > MAX_POLICY_BYTES {
            return Err(bad("SSH CA role exceeds the policy size bound"));
        }
        Ok(())
    }

    pub(super) fn signing_policy(
        &self,
        body: &Value,
        public: &PublicKey,
        context: &SigningContext<'_>,
    ) -> Result<SigningPolicy> {
        let now = context.now;
        self.validate()?;
        if !body.is_object() {
            return Err(bad("SSH signing body must be an object"));
        }
        // No identity values are inferred from principal or display-name strings.
        if self.default_user_template
            || self.allowed_users_template
            || self.allowed_domains_template
            || self.default_extensions_template
        {
            return Err(error(
                501,
                "SSH CA identity templates require an authenticated identity context",
            ));
        }
        if self.algorithm_signer == "ssh-rsa" {
            return Err(error(501, "SSH CA SHA1 signing is not implemented"));
        }
        self.validate_public_key(public)?;
        let kind = match text(body, "cert_type", "user")?.as_str() {
            "user" if self.allow_user_certificates => CertType::User,
            "host" if self.allow_host_certificates => CertType::Host,
            "user" | "host" => return Err(bad("certificate type is not allowed by this role")),
            _ => return Err(bad("invalid certificate type")),
        };
        let principals = self.principals(body, kind)?;
        let ttl = self.resolve_ttl(body, context.default_ttl, context.max_ttl)?;
        let valid_after = now
            .checked_sub(self.not_before_duration)
            .ok_or_else(|| bad("SSH CA not-before time precedes the supported epoch"))?;
        let valid_before = now
            .checked_add(ttl)
            .ok_or_else(|| bad("SSH CA expiry overflow"))?;
        Ok(SigningPolicy {
            kind,
            principals,
            key_id: self.key_id(body, public, context.role_name, context.display_name)?,
            valid_after,
            valid_before,
            critical_options: options(
                body,
                "critical_options",
                &self.default_critical_options,
                &self.allowed_critical_options,
                false,
            )?,
            extensions: options(
                body,
                "extensions",
                &self.default_extensions,
                &self.allowed_extensions,
                true,
            )?,
            issuer_ref: self.issuer_ref.clone(),
            // The issuer's key type determines how "default" is resolved by the signer.
            algorithm_signer: self.algorithm_signer.clone(),
        })
    }

    fn principals(&self, body: &Value, kind: CertType) -> Result<Vec<String>> {
        let requested = text(body, "valid_principals", "")?;
        let default = if kind == CertType::User {
            self.default_user.as_str()
        } else {
            ""
        };
        // FieldData.GetOk distinguishes an explicit empty value from omission.
        let principals = csv(if body.get("valid_principals").is_some() {
            &requested
        } else {
            default
        });
        let allowed = if kind == CertType::User {
            &self.allowed_users
        } else {
            &self.allowed_domains
        };
        // The primary only treats the entire literal "*" as a wildcard.
        if principals.is_empty() {
            if self.allow_empty_principals || allowed == "*" {
                return Ok(principals);
            }
            return Err(bad("empty valid principals are not allowed by this role"));
        }
        if allowed == "*" {
            return Ok(principals);
        }
        let permitted = csv(allowed);
        if principals.iter().any(|principal| {
            !permitted.iter().any(|entry| {
                if kind == CertType::User {
                    principal == entry
                } else {
                    self.allow_bare_domains && principal == entry
                        || self.allow_subdomains && principal.ends_with(&format!(".{entry}"))
                }
            })
        }) {
            return Err(bad("valid principal is not allowed by this role"));
        }
        Ok(principals)
    }

    fn resolve_ttl(&self, body: &Value, default_ttl: u64, max_ttl: u64) -> Result<u64> {
        let explicit = body.get("ttl").is_some();
        let mut ttl = if explicit {
            duration(body, "ttl", 0)?
        } else {
            self.ttl
        };
        if ttl == 0 {
            ttl = default_ttl;
        }
        let maximum = if self.max_ttl != 0 {
            self.max_ttl
        } else {
            max_ttl
        };
        if ttl > maximum {
            if explicit {
                return Err(bad("ttl is larger than the maximum permitted by this role"));
            }
            ttl = maximum;
        }
        if ttl > MAX_DURATION {
            return Err(bad("SSH CA TTL exceeds the supported duration"));
        }
        Ok(ttl)
    }

    fn key_id(
        &self,
        body: &Value,
        public: &PublicKey,
        role_name: &str,
        display_name: &str,
    ) -> Result<String> {
        let override_id = text(body, "key_id", "")?;
        if !override_id.is_empty() {
            if !self.allow_user_key_ids {
                return Err(bad("setting key_id is not allowed by this role"));
            }
            return Ok(override_id);
        }
        let wire = public
            .to_bytes()
            .map_err(|_| bad("invalid SSH public key encoding"))?;
        let hash: String = ring::digest::digest(&ring::digest::SHA256, &wire)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let template = if !self.key_id_format.is_empty() {
            self.key_id_format.as_str()
        } else if display_name.is_empty() {
            "vault-{{public_key_hash}}"
        } else {
            "vault-{{token_display_name}}-{{public_key_hash}}"
        };
        // One pass prevents a substituted display-name string becoming a template.
        Ok(substitute_key_id(template, role_name, display_name, &hash))
    }

    fn validate_public_key(&self, public: &PublicKey) -> Result<()> {
        if self.allowed_user_key_lengths.is_empty() {
            return Ok(());
        }
        let (aliases, bits): (Vec<&str>, i64) = match public.key_data() {
            KeyData::Rsa(key) => (vec!["rsa", "ssh-rsa"], positive_bits(&key.n)?),
            KeyData::Dsa(key) => (vec!["dsa", "ssh-dss"], positive_bits(&key.p)?),
            KeyData::Ecdsa(key) => match key.curve() {
                EcdsaCurve::NistP256 => (vec!["ecdsa", "ec", "ecdsa-sha2-nistp256"], 256),
                EcdsaCurve::NistP384 => (vec!["ecdsa", "ec", "ecdsa-sha2-nistp384"], 384),
                EcdsaCurve::NistP521 => (vec!["ecdsa", "ec", "ecdsa-sha2-nistp521"], 521),
            },
            KeyData::Ed25519(_) => (vec!["ed25519", "ssh-ed25519"], 0),
            _ => return Err(bad("public key type does not satisfy the role key policy")),
        };
        let mut present = false;
        for alias in aliases {
            if let Some(lengths) = self.allowed_user_key_lengths.get(alias) {
                present = true;
                if lengths
                    .iter()
                    .any(|length| bits == 0 || alias.starts_with("ecdsa-sha2-") || *length == bits)
                {
                    return Ok(());
                }
            }
        }
        Err(bad(if present {
            "public key size does not satisfy the role key policy"
        } else {
            "public key type does not satisfy the role key policy"
        }))
    }
}

fn positive_bits(value: &ssh_key::Mpint) -> Result<i64> {
    let bytes = value
        .as_positive_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| bad("SSH key contains an invalid positive integer"))?;
    let bits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(bytes[0].leading_zeros() as usize))
        .ok_or_else(|| bad("SSH public key size overflow"))?;
    i64::try_from(bits).map_err(|_| bad("SSH public key size overflow"))
}

fn text(body: &Value, field: &str, default: &str) -> Result<String> {
    match body.get(field) {
        None => Ok(default.into()),
        Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.to_string()),
        Some(Value::Bool(value)) => Ok(if *value { "1" } else { "0" }.into()),
        _ => Err(bad("invalid SSH string field")),
    }
}

fn boolean(body: &Value, field: &str) -> Result<bool> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::String(value)) => match value.as_str() {
            "true" | "TRUE" | "True" | "1" | "t" | "T" => Ok(true),
            "false" | "FALSE" | "False" | "0" | "f" | "F" => Ok(false),
            _ => Err(bad("invalid SSH boolean field")),
        },
        Some(Value::Number(value)) => value
            .as_i64()
            .map(|value| value != 0)
            .ok_or_else(|| bad("invalid SSH boolean field")),
        _ => Err(bad("invalid SSH boolean field")),
    }
}

fn duration(body: &Value, field: &str, default: u64) -> Result<u64> {
    if body.get(field).is_none() {
        return Ok(default);
    }
    crate::auth::framework_duration_seconds(body, field)
        .map_err(|_| bad("invalid SSH duration field"))
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn display(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(display).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values.iter().collect();
            format!(
                "map[{}]",
                sorted
                    .into_iter()
                    .map(|(key, value)| format!("{key}:{}", display(value)))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

fn string_map(body: &Value, field: &str) -> Result<BTreeMap<String, String>> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(values)) => Ok(values
            .iter()
            .map(|(key, value)| (key.clone(), display(value)))
            .collect()),
        _ => Err(bad("invalid SSH options map")),
    }
}

fn options(
    body: &Value,
    field: &str,
    defaults: &BTreeMap<String, String>,
    allowed: &str,
    extension: bool,
) -> Result<BTreeMap<String, String>> {
    let values = string_map(body, field)?;
    if values.is_empty() {
        return Ok(defaults.clone());
    }
    if !extension && allowed.is_empty() || extension && allowed == "*" {
        return Ok(values);
    }
    if values
        .keys()
        .any(|key| !allowed.split(',').any(|entry| entry == key))
    {
        return Err(bad(
            "certificate option override is not allowed by this role",
        ));
    }
    Ok(values)
}

fn key_lengths(body: &Value) -> Result<BTreeMap<String, Vec<i64>>> {
    let Some(value) = body.get("allowed_user_key_lengths") else {
        return Ok(BTreeMap::new());
    };
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    let values = value
        .as_object()
        .ok_or_else(|| bad("invalid allowed_user_key_lengths"))?;
    values
        .iter()
        .map(|(key, value)| {
            let parse = |value: &Value| -> Result<i64> {
                match value {
                    Value::Number(value) => {
                        value.as_i64().ok_or_else(|| bad("invalid SSH key length"))
                    }
                    Value::String(value) if value.is_empty() => Ok(0),
                    Value::String(value) => {
                        value.parse().map_err(|_| bad("invalid SSH key length"))
                    }
                    _ => Err(bad("invalid SSH key length")),
                }
            };
            let lengths = match value {
                Value::Null => Vec::new(),
                Value::Array(values) => values.iter().map(parse).collect::<Result<Vec<_>>>()?,
                Value::String(value) if value.contains(',') => value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.parse().map_err(|_| bad("invalid SSH key length")))
                    .collect::<Result<Vec<_>>>()?,
                _ => vec![parse(value)?],
            };
            Ok((key.clone(), lengths))
        })
        .collect()
}

fn substitute_key_id(template: &str, role: &str, display_name: &str, hash: &str) -> String {
    let mut result = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(end) = rest.find("}}") else { break };
        let token = &rest[..end + 2];
        result.push_str(match token {
            "{{role_name}}" => role,
            "{{token_display_name}}" => display_name,
            "{{public_key_hash}}" => hash,
            _ => token,
        });
        rest = &rest[end + 2..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_role(body: Value) -> Result<CaRole> {
        let mut base = json!({"key_type":"ca","allow_user_certificates":true,"allowed_users":"*"});
        base.as_object_mut()
            .ok_or_else(|| bad("test role"))?
            .extend(body.as_object().ok_or_else(|| bad("test fields"))?.clone());
        CaRole::parse(&base)
    }

    fn public() -> PublicKey {
        ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([42; 32])).into()
    }

    #[test]
    fn ssh_ca_policy_user_host_principals_do_not_share_domain_wildcards() -> Result<()> {
        let user = make_role(json!({"allowed_users":"bob,alice,bob","default_user":"alice"}))?;
        assert_eq!(
            user.principals(
                &json!({"valid_principals":" bob,alice,bob "}),
                CertType::User
            )?,
            vec!["alice", "bob"]
        );
        assert!(
            user.principals(&json!({"valid_principals":"sub.alice"}), CertType::User)
                .is_err()
        );
        assert_eq!(user.principals(&json!({}), CertType::User)?, vec!["alice"]);
        assert!(
            user.principals(&json!({"valid_principals":""}), CertType::User)
                .is_err()
        );
        let host = make_role(
            json!({"allow_host_certificates":true,"allowed_domains":"example.com",
            "allow_subdomains":true}),
        )?;
        assert!(
            host.principals(&json!({"valid_principals":"example.com"}), CertType::Host)
                .is_err()
        );
        assert_eq!(
            host.principals(&json!({"valid_principals":"a.example.com"}), CertType::Host)?,
            vec!["a.example.com"]
        );
        assert!(
            host.principals(
                &json!({"valid_principals":"badexample.com"}),
                CertType::Host
            )
            .is_err()
        );
        assert!(user.principals(&json!({}), CertType::Host).is_err());
        assert!(
            make_role(json!({}))?
                .principals(&json!({}), CertType::User)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn ssh_ca_policy_default_ttl_clamps_but_explicit_ttl_is_rejected() -> Result<()> {
        let role = make_role(json!({"ttl":0,"max_ttl":"30s"}))?;
        assert_eq!(role.resolve_ttl(&json!({}), 60, 120)?, 30);
        assert!(role.resolve_ttl(&json!({"ttl":0}), 60, 120).is_err());
        assert_eq!(role.resolve_ttl(&json!({"ttl":0}), 20, 120)?, 20);
        assert_eq!(role.resolve_ttl(&json!({"ttl":"20s"}), 60, 120)?, 20);
        assert!(role.resolve_ttl(&json!({"ttl":31}), 60, 120).is_err());
        assert!(
            CaRole::parse(&json!({"key_type":"ca","allow_user_certificates":true,
            "ttl":31,"max_ttl":30}))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn ssh_ca_policy_critical_and_extension_overrides_have_distinct_empty_allowlists() -> Result<()>
    {
        let role = make_role(json!({"default_critical_options":{"force-command":"safe"},
            "default_extensions":{"permit-pty":""}}))?;
        assert_eq!(
            options(
                &json!({}),
                "critical_options",
                &role.default_critical_options,
                "",
                false
            )?,
            role.default_critical_options
        );
        assert_eq!(
            options(
                &json!({"critical_options":{"source-address":"10.0.0.1"}}),
                "critical_options",
                &role.default_critical_options,
                "",
                false
            )?
            .len(),
            1
        );
        assert!(
            options(
                &json!({"extensions":{"permit-agent-forwarding":""}}),
                "extensions",
                &role.default_extensions,
                "",
                true
            )
            .is_err()
        );
        assert!(
            options(
                &json!({"critical_options":{"source-address":"10.0.0.1"}}),
                "critical_options",
                &role.default_critical_options,
                "*",
                false
            )
            .is_err()
        );
        assert_eq!(
            options(
                &json!({"extensions":{}}),
                "extensions",
                &role.default_extensions,
                "",
                true
            )?,
            role.default_extensions
        );
        Ok(())
    }

    #[test]
    fn ssh_ca_policy_key_type_constraints_keyid_wire_hash_and_original_time() -> Result<()> {
        let key = public();
        let role = make_role(json!({"allowed_user_key_lengths":{"ssh-ed25519":[0]},
            "key_id_format":"{{role_name}}-{{token_display_name}}-{{public_key_hash}}",
            "not_before_duration":30}))?;
        let policy = role.signing_policy(
            &json!({"valid_principals":"alice","ttl":60}),
            &key,
            &SigningContext {
                role_name: "ops",
                display_name: "real-display",
                now: 1000,
                default_ttl: 90,
                max_ttl: 120,
            },
        )?;
        assert_eq!((policy.valid_after, policy.valid_before), (970, 1060));
        assert_eq!(policy.kind, CertType::User);
        assert_eq!(policy.principals, vec!["alice"]);
        assert_eq!(policy.issuer_ref, "default");
        assert_eq!(policy.algorithm_signer, "default");
        assert_eq!(
            policy.key_id,
            format!(
                "ops-real-display-{}",
                ring::digest::digest(
                    &ring::digest::SHA256,
                    &key.to_bytes().map_err(|_| bad("test key"))?
                )
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
            )
        );
        assert!(
            role.key_id(&json!({"key_id":"override"}), &key, "ops", "display")
                .is_err()
        );
        assert!(
            make_role(json!({"allowed_user_key_lengths":{"rsa":[2048]}}))?
                .validate_public_key(&key)
                .is_err()
        );
        assert!(
            make_role(json!({"allowed_user_key_lengths":{"ssh-ed25519":[]}}))?
                .validate_public_key(&key)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn ssh_ca_policy_template_and_sha1_requests_are_explicitly_unimplemented() -> Result<()> {
        for fields in [
            json!({"allowed_users_template":true}),
            json!({"algorithm_signer":"ssh-rsa"}),
        ] {
            let role = make_role(fields)?;
            let error = role
                .signing_policy(
                    &json!({"valid_principals":"alice"}),
                    &public(),
                    &SigningContext {
                        role_name: "ops",
                        display_name: "display",
                        now: 1000,
                        default_ttl: 60,
                        max_ttl: 120,
                    },
                )
                .err()
                .ok_or_else(|| bad("expected rejection"))?;
            assert_eq!(error.status, 501);
        }
        let value = make_role(json!({}))?.descriptor();
        assert_eq!(value["key_type"], "ca");
        let mut durable =
            serde_json::to_value(make_role(json!({}))?).map_err(|_| bad("test role encoding"))?;
        durable
            .as_object_mut()
            .ok_or_else(|| bad("test role fields"))?
            .insert("unexpected".into(), json!(true));
        assert!(serde_json::from_value::<CaRole>(durable).is_err());
        Ok(())
    }
}
