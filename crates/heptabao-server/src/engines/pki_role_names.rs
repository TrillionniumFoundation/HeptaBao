//! Captured role name authorization and non-storage policy. Historical None
//! retains the earlier candidate permission and original certificate encoding.
use super::*;

pub(super) const ROLE_NAME_FIELDS: &[&str] = &[
    "signature_bits",
    "use_pss",
    "allowed_domains_template",
    "allowed_uri_sans_template",
    "allow_globs_in_identity_templates",
    "use_csr_common_name",
    "use_csr_sans",
    "allow_localhost",
    "require_cn",
    "enforce_hostnames",
    "cn_validations",
    "allow_glob_domains",
    "allowed_ip_sans_cidr",
    "allowed_uri_sans",
    "no_store",
    "allowed_serial_numbers",
    "allowed_user_ids",
    "allowed_other_sans",
    "policy_identifiers",
];

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleNamePolicy {
    #[serde(default, skip_serializing_if = "signature_zero")]
    pub(super) signature_bits: i64,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) use_pss: bool,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) allowed_domains_template: bool,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) allowed_uri_sans_template: bool,
    #[serde(default, skip_serializing_if = "role_false")]
    pub(super) allow_globs_in_identity_templates: bool,
    #[serde(
        default = "role_csr::default_true",
        skip_serializing_if = "role_csr::is_true"
    )]
    pub(super) use_csr_common_name: bool,
    #[serde(
        default = "role_csr::default_true",
        skip_serializing_if = "role_csr::is_true"
    )]
    pub(super) use_csr_sans: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) allowed_serial_numbers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) allowed_user_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) allowed_other_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) policy_identifiers: Vec<String>,
    pub(super) allow_localhost: bool,
    pub(super) require_cn: bool,
    pub(super) enforce_hostnames: bool,
    pub(super) cn_validations: Vec<String>,
    pub(super) allow_glob_domains: bool,
    pub(super) allowed_ip_sans_cidr: Vec<String>,
    pub(super) allowed_uri_sans: Vec<String>,
    pub(super) no_store: bool,
}

impl Default for RoleNamePolicy {
    fn default() -> Self {
        Self {
            signature_bits: 0,
            use_pss: false,
            allowed_domains_template: false,
            allowed_uri_sans_template: false,
            allow_globs_in_identity_templates: false,
            use_csr_common_name: true,
            use_csr_sans: true,
            allowed_serial_numbers: Vec::new(),
            allowed_user_ids: Vec::new(),
            allowed_other_sans: Vec::new(),
            policy_identifiers: Vec::new(),
            allow_localhost: true,
            require_cn: true,
            enforce_hostnames: true,
            cn_validations: vec!["email".into(), "hostname".into()],
            allow_glob_domains: false,
            allowed_ip_sans_cidr: Vec::new(),
            allowed_uri_sans: Vec::new(),
            no_store: false,
        }
    }
}

impl RoleNamePolicy {
    pub(super) fn from_body(body: &Value) -> Result<Self> {
        let mut policy = Self {
            signature_bits: role_signatures::signature_bits(body)?,
            ..Self::default()
        };
        for (name, target) in [
            ("use_pss", &mut policy.use_pss),
            (
                "allowed_domains_template",
                &mut policy.allowed_domains_template,
            ),
            (
                "allowed_uri_sans_template",
                &mut policy.allowed_uri_sans_template,
            ),
            (
                "allow_globs_in_identity_templates",
                &mut policy.allow_globs_in_identity_templates,
            ),
            ("use_csr_common_name", &mut policy.use_csr_common_name),
            ("use_csr_sans", &mut policy.use_csr_sans),
            ("allow_localhost", &mut policy.allow_localhost),
            ("require_cn", &mut policy.require_cn),
            ("enforce_hostnames", &mut policy.enforce_hostnames),
            ("allow_glob_domains", &mut policy.allow_glob_domains),
            ("no_store", &mut policy.no_store),
        ] {
            if let Some(value) = role_optional_bool(body, name)? {
                *target = value;
            }
        }
        for (name, target) in [
            ("cn_validations", &mut policy.cn_validations),
            ("allowed_ip_sans_cidr", &mut policy.allowed_ip_sans_cidr),
            ("allowed_uri_sans", &mut policy.allowed_uri_sans),
        ] {
            if let Some(value) = body.get(name) {
                *target = role_leaf_profile::weak_comma_list(name, value)?;
            }
        }
        for (name, target) in [
            ("allowed_serial_numbers", &mut policy.allowed_serial_numbers),
            ("allowed_user_ids", &mut policy.allowed_user_ids),
            ("allowed_other_sans", &mut policy.allowed_other_sans),
        ] {
            if let Some(value) = body.get(name) {
                *target = role_leaf_profile::weak_comma_list(name, value)?;
            }
        }
        if let Some(value) = body.get("policy_identifiers") {
            policy.policy_identifiers = role_subjects::policy_strings(value)?;
        }
        if policy.cn_validations.is_empty() {
            policy.cn_validations = Self::default().cn_validations;
        }
        for value in &mut policy.cn_validations {
            *value = value.to_ascii_lowercase();
        }
        for value in &mut policy.allowed_ip_sans_cidr {
            *value = Cidr::parse(value)?.canonical();
        }
        policy.validate()?;
        Ok(policy)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.validate_subject_policy()?;
        let mut seen = BTreeSet::new();
        for value in &self.cn_validations {
            if !matches!(value.as_str(), "disabled" | "email" | "hostname") {
                return Err(bad(&format!(
                    "cn_validations value incorrect: unknown type: `{value}`"
                )));
            }
            if !seen.insert(value) {
                return Err(bad(&format!(
                    "cn_validations value incorrect: `{value}` specified multiple times"
                )));
            }
        }
        if seen.is_empty() {
            return Err(bad(
                "cn_validations value incorrect: must specify a value (`email` and/or `hostname`) or `disabled`",
            ));
        }
        if self.cn_validations.iter().any(|value| value == "disabled") && seen.len() != 1 {
            return Err(bad(
                "cn_validations value incorrect: cannot specify `disabled` along with `email` or `hostname`",
            ));
        }
        if self.allowed_ip_sans_cidr.len() > 64
            || self.allowed_uri_sans.len() > 64
            || self
                .allowed_uri_sans
                .iter()
                .any(|value| !bounded_name(value))
        {
            return Err(bad("PKI role name policy is outside bounds"));
        }
        for value in &self.allowed_ip_sans_cidr {
            if Cidr::parse(value)?.canonical() != *value {
                return Err(bad("noncanonical PKI IP SAN network"));
            }
        }
        Ok(())
    }

    pub(super) fn descriptor(&self) -> Value {
        json!({"signature_bits":self.signature_bits,"use_pss":self.use_pss,
            "allowed_domains_template":self.allowed_domains_template,
            "allowed_uri_sans_template":self.allowed_uri_sans_template,
            "allow_globs_in_identity_templates":self.allow_globs_in_identity_templates,
            "use_csr_common_name":self.use_csr_common_name,"use_csr_sans":self.use_csr_sans,"allow_localhost":self.allow_localhost,"require_cn":self.require_cn,
            "enforce_hostnames":self.enforce_hostnames,"cn_validations":self.cn_validations,
            "allow_glob_domains":self.allow_glob_domains,"allowed_ip_sans_cidr":self.allowed_ip_sans_cidr,
            "allowed_uri_sans":self.allowed_uri_sans,"no_store":self.no_store,
            "allowed_serial_numbers":self.allowed_serial_numbers,"allowed_user_ids":self.allowed_user_ids,
            "allowed_other_sans":self.allowed_other_sans,"policy_identifiers":self.policy_identifiers})
    }

    pub(super) fn valid_domain_entry(&self, value: &str) -> bool {
        // Role writes store permitted patterns independently of enabling glob
        // matching. Issue authorization applies the actual flag later.
        bounded_subject(value)
    }

    pub(super) fn allows_common_name(&self, role: &Role, value: &str) -> bool {
        if !bounded_subject(value) {
            return false;
        }
        if self.cn_validations == ["disabled"] {
            return true;
        }
        self.allows_name(role, value)
            && self.cn_validations.iter().any(|kind| {
                kind == if value.contains('@') {
                    "email"
                } else {
                    "hostname"
                }
            })
    }

    pub(super) fn allows_name(&self, role: &Role, value: &str) -> bool {
        if !bounded_name(value) {
            return false;
        }
        let reduced = if let Some((local, domain)) = value.split_once('@') {
            if local.is_empty() || domain.contains('@') || domain.contains('*') {
                return false;
            }
            domain
        } else {
            value
        };
        if reduced.contains('*')
            && (role.allow_wildcard_certificates != Some(true) || wildcard_name(reduced).is_none())
        {
            return false;
        }
        if self.enforce_hostnames && !valid_common_name(reduced) {
            return false;
        }
        if role.allow_any_name {
            return true;
        }
        let name = reduced.to_ascii_lowercase();
        if self.allow_localhost
            && (["localhost", "localdomain"].contains(&name.as_str())
                || role.allow_subdomains
                    && ["localhost", "localdomain"].iter().any(|base| {
                        name.ends_with(&format!(".{base}"))
                            || wildcard_name(&name).is_some_and(|(_, reduced)| reduced == *base)
                    }))
        {
            return true;
        }
        role.allows(value)
            || role.allowed_domains.iter().any(|domain| {
                let domain = domain.to_ascii_lowercase();
                role.allow_bare_domains.unwrap_or(true) && name == domain
                    || role.allow_subdomains
                        && (name.ends_with(&format!(".{domain}"))
                            || wildcard_name(&name).is_some_and(|(_, reduced)| reduced == domain))
                    || self.allow_glob_domains && glob_match(&domain, &name)
            })
    }

    pub(super) fn validate_sans(&self, ip_sans: &[IpAddr], uri_sans: &[String]) -> Result<()> {
        self.validate_sans_from(ip_sans, uri_sans, false, !self.allowed_uri_sans.is_empty())
    }

    pub(super) fn validate_sans_from(
        &self,
        ip_sans: &[IpAddr],
        uri_sans: &[String],
        from_csr: bool,
        declared_uri_patterns: bool,
    ) -> Result<()> {
        let source = if from_csr { "CSR" } else { "the API" };
        for ip in ip_sans {
            if !self.allowed_ip_sans_cidr.is_empty()
                && !self
                    .allowed_ip_sans_cidr
                    .iter()
                    .any(|value| Cidr::parse(value).is_ok_and(|network| network.contains(*ip)))
            {
                return Err(bad(&format!(
                    "the IP address \"{ip}\" is not allowed in this role"
                )));
            }
        }
        if !uri_sans.is_empty() && !declared_uri_patterns {
            return Err(bad(&format!(
                "URI Subject Alternative Names are not allowed in this role, but were provided via {source}",
            )));
        }
        for uri in uri_sans {
            if !self
                .allowed_uri_sans
                .iter()
                .any(|pattern| glob_match(pattern, uri))
            {
                return Err(bad(&format!(
                    "URI Subject Alternative Names were provided via {source} which are not valid for this role",
                )));
            }
            if !bounded_name(uri)
                || uri.bytes().any(|byte| byte.is_ascii_whitespace())
                || uri.as_bytes().windows(1).enumerate().any(|(index, byte)| {
                    byte == b"%"
                        && (index + 2 >= uri.len()
                            || !uri.as_bytes()[index + 1..index + 3]
                                .iter()
                                .all(u8::is_ascii_hexdigit))
                })
            {
                return Err(bad(&format!(
                    "the provided URI Subject Alternative Name {} is not a valid URI",
                    serde_json::to_string(uri).unwrap_or_default()
                )));
            }
        }
        Ok(())
    }
}

pub(super) fn bounded_subject(value: &str) -> bool {
    value.len() <= 2048 && !value.chars().any(char::is_control)
}
pub(super) fn bounded_name(value: &str) -> bool {
    !value.is_empty() && bounded_subject(value)
}

// OpenBao's go-glob uses only '*' and permits it to cross separators.
pub(super) fn glob_match(pattern: &str, value: &str) -> bool {
    let mut remaining = value;
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(rest) = remaining.strip_prefix(first) else {
        return false;
    };
    remaining = rest;
    let parts: Vec<_> = parts.collect();
    if parts.is_empty() {
        return remaining.is_empty();
    }
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            return remaining.ends_with(part);
        }
        let Some(offset) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[offset + part.len()..];
    }
    true
}

struct Cidr {
    network: IpAddr,
    prefix: u8,
}
impl Cidr {
    fn parse(value: &str) -> Result<Self> {
        let invalid = || {
            bad(&format!(
                "error parsing allowed_ip_sans_cidr: invalid CIDR address: {value}"
            ))
        };
        let (ip, prefix) = value.split_once('/').ok_or_else(invalid)?;
        let ip: IpAddr = ip.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        let network = match ip {
            IpAddr::V4(ip) if prefix <= 32 => IpAddr::V4(
                (u32::from(ip)
                    & if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    })
                .into(),
            ),
            IpAddr::V6(ip) if prefix <= 128 => IpAddr::V6(
                (u128::from(ip)
                    & if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    })
                .into(),
            ),
            _ => return Err(invalid()),
        };
        Ok(Self { network, prefix })
    }
    fn canonical(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
    fn contains(&self, ip: IpAddr) -> bool {
        Self::parse(&format!("{ip}/{}", self.prefix))
            .is_ok_and(|parsed| parsed.network == self.network)
    }
}

impl Pki {
    pub(in crate::engines) fn has_role_names_state(&self) -> bool {
        self.roles.values().any(|role| {
            role.role_name_policy.is_some()
                || role
                    .role_leaf_profile
                    .as_ref()
                    .is_some_and(|profile| profile.leaf_subject_evidence.is_some())
        }) || self.issued.values().any(|issued| {
            issued.role_names_owned
                || issued.role_leaf_profile.as_ref().is_some_and(|evidence| {
                    evidence.role_name_policy.is_some()
                        || evidence.profile.leaf_subject_evidence.is_some()
                        || !evidence.email_sans.is_empty()
                        || !evidence.uri_sans.is_empty()
                })
        }) || self.has_external_role_names_state()
    }
}

fn signature_zero(value: &i64) -> bool {
    *value == 0
}
