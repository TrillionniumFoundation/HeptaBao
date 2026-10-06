//! Pending orders and authorizations retain the original protocol/account owner.
//! Public JWS proves that account; it never constructs an administrative actor.
use super::acme_state::{AccountStatus, Binding, Protocol, valid_directory, valid_identifier};
use super::*;
use crate::auth::Timestamp;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const MAX_ORDERS: usize = 4096;
const MAX_IDENTIFIERS: usize = 100;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IdentifierType {
    Dns,
    Ip,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identifier {
    pub kind: IdentifierType,
    pub original: String,
    pub value: String,
    pub wildcard: bool,
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    pub kind: String,
    pub status: ChallengeStatus,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated: Option<Validated>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Validation {
    pub initiated: Timestamp,
    pub retry_after: Timestamp,
    pub retry_count: u8,
    pub error: Option<String>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Validated {
    pub at: Timestamp,
    pub expires: Timestamp,
    pub public_at: String,
    pub public_expires: String,
}
impl Challenge {
    pub(crate) fn descriptor(&self, base: &str, auth_id: &str) -> Value {
        let mut body = json!({"type":self.kind,"url":format!("{base}challenge/{auth_id}/{}",self.kind),"status":match self.status { ChallengeStatus::Pending=>"pending",ChallengeStatus::Processing=>"processing",ChallengeStatus::Valid=>"valid",ChallengeStatus::Invalid=>"invalid"},"token":self.token});
        if let Some(validated) = &self.validated {
            body["validated"] = json!(validated.public_at);
        }
        if let Some(detail) = self.validation.as_ref().and_then(|v| v.error.as_ref()) {
            body["error"] = json!({"type":"urn:ietf:params:acme:error:incorrectResponse","detail":detail,"status":400,"subproblems":[]});
        }
        body
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authorization {
    pub id: String,
    pub owner: Binding,
    pub account: String,
    pub account_thumbprint: String,
    pub directory: String,
    pub created: Timestamp,
    pub deactivated: Option<Timestamp>,
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub challenges: Vec<Challenge>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Order {
    pub id: String,
    pub owner: Binding,
    pub account: String,
    pub account_thumbprint: String,
    pub directory: String,
    pub created: Timestamp,
    pub expires: Timestamp,
    // Retain the public creation-zone rendering across encrypted process reopen.
    pub public_expires: String,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
}

pub(crate) fn uuid() -> Result<String> {
    let mut bytes = crate::crypto::random::<16>()
        .map_err(|_| error(503, "ACME identifier generation unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn malformed(detail: &str) -> EngineError {
    bad(&format!("{detail}: the request message was malformed"))
}
pub(crate) fn go_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "float64",
        Value::String(_) => "string",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
    }
}
impl Identifier {
    pub(crate) fn parse(kind: &str, original: &str) -> Result<Self> {
        if original.is_empty() {
            return Err(malformed(
                "value argument for value in 'identifiers' can not be blank",
            ));
        }
        if original.len() > 253 || !original.is_ascii() || original.chars().any(char::is_control) {
            return Err(malformed(&format!(
                "value argument ({original}) failed validation"
            )));
        }
        match kind {
            "ip" => {
                original.parse::<IpAddr>().map_err(|_| {
                    malformed(&format!(
                        "value argument ({original}) failed validation: failed parsing as IP"
                    ))
                })?;
                Ok(Self {
                    kind: IdentifierType::Ip,
                    original: original.into(),
                    value: original.into(),
                    wildcard: false,
                })
            }
            "dns" => {
                let wildcard = original.starts_with("*.");
                let value = original.strip_prefix("*.").unwrap_or(original);
                if original.contains('*') && (!wildcard || value.is_empty() || value.contains('*'))
                {
                    return Err(malformed(&format!(
                        "value argument ({original}) failed validation: invalid wildcard: wildcard must be entire left-most label"
                    )));
                }
                if value.parse::<IpAddr>().is_ok() {
                    return Err(malformed(&format!(
                        "refusing to accept argument ({original}) as DNS type identifier: parsed OK as IP address"
                    )));
                }
                // The registration route accepts ASCII certificate names only.
                // Registration IDNA conversion must round-trip; network proof remains separate.
                let converted = idna::uts46::Uts46::new()
                    .to_ascii(
                        value.as_bytes(),
                        idna::AsciiDenyList::STD3,
                        idna::uts46::Hyphens::Check,
                        idna::uts46::DnsLength::Verify,
                    )
                    .map_err(|_| {
                        malformed(&format!("value argument ({original}) failed validation"))
                    })?
                    .to_string();
                if converted != value
                    || value.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    })
                {
                    return Err(malformed(&format!(
                        "value argument ({original}) failed IDNA round-tripping to ASCII"
                    )));
                }
                Ok(Self {
                    kind: IdentifierType::Dns,
                    original: original.into(),
                    value: value.into(),
                    wildcard,
                })
            }
            _ => Err(bad(&format!(
                "unsupported identifier type {kind}: an identifier is of an unsupported type"
            ))),
        }
    }
    fn validate(&self) -> Result<()> {
        let kind = match self.kind {
            IdentifierType::Dns => "dns",
            IdentifierType::Ip => "ip",
        };
        if Self::parse(kind, &self.original)? != *self {
            return Err(error(503, "ACME identifier binding rejected"));
        }
        Ok(())
    }
    fn descriptor(&self, original: bool) -> Value {
        json!({"type": match self.kind { IdentifierType::Dns => "dns", IdentifierType::Ip => "ip" }, "value":if original { &self.original } else { &self.value }})
    }
    fn challenge_kinds(&self) -> &'static [&'static str] {
        if self.kind == IdentifierType::Ip {
            &["http-01"]
        } else if self.wildcard {
            &["dns-01"]
        } else {
            &["http-01", "dns-01", "tls-alpn-01"]
        }
    }
}
pub(crate) fn parse_identifiers(payload: &Value) -> Result<Vec<Identifier>> {
    let raw = payload
        .get("identifiers")
        .ok_or_else(|| malformed("missing required identifiers argument"))?;
    let values = raw.as_array().ok_or_else(|| {
        malformed(&format!(
            "invalid type ({}) for field 'identifiers'",
            go_type(raw)
        ))
    })?;
    if values.len() > MAX_IDENTIFIERS {
        return Err(malformed("too many ACME identifiers"));
    }
    let mut result = Vec::new();
    for raw in values {
        let object = raw.as_object().ok_or_else(|| {
            malformed(&format!(
                "invalid type ({}) for value in 'identifiers'",
                go_type(raw)
            ))
        })?;
        let kind = object
            .get("type")
            .ok_or_else(|| malformed("missing type argument for value in 'identifiers'"))?
            .as_str()
            .ok_or_else(|| {
                malformed("invalid type for type argument (string) for value in 'identifiers'")
            })?;
        let value = object
            .get("value")
            .ok_or_else(|| malformed("missing value argument for value in 'identifiers'"))?
            .as_str()
            .ok_or_else(|| {
                malformed("invalid type for value argument (string) for value in 'identifiers'")
            })?;
        result.push(Identifier::parse(kind, value)?);
    }
    for name in ["notBefore", "notAfter"] {
        if let Some(raw) = payload.get(name) {
            let value = raw.as_str().ok_or_else(|| {
                malformed(&format!(
                    "invalid type ({}) for field '{name}'",
                    go_type(raw)
                ))
            })?;
            chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| malformed(&format!("failed parsing field '{name}'")))?;
            return Err(bad(
                "the request message was malformed: NotBefore and NotAfter are not supported",
            ));
        }
    }
    Ok(result)
}
impl Authorization {
    pub(crate) fn descriptor(&self, base: &str) -> Value {
        let mut body = json!({"identifier":self.identifier.descriptor(false), "status": match self.status {AuthorizationStatus::Pending=>"pending", AuthorizationStatus::Valid=>"valid", AuthorizationStatus::Invalid=>"invalid", AuthorizationStatus::Deactivated=>"deactivated"}, "wildcard":self.identifier.wildcard,
            "challenges":self.challenges.iter().map(|c|c.descriptor(base,&self.id)).collect::<Vec<_>>()});
        if let Some(validated) = self.challenges.iter().find_map(|c| c.validated.as_ref()) {
            body["expires"] = json!(validated.public_expires);
        }
        body
    }
}
impl Order {
    pub(crate) fn descriptor(&self, protocol: &Protocol, base: &str, now: Timestamp) -> Value {
        let invalid = now > self.expires
            || self.authorizations.iter().any(|id| {
                protocol.authorizations.get(id).is_none_or(|a| {
                    matches!(
                        a.status,
                        AuthorizationStatus::Invalid | AuthorizationStatus::Deactivated
                    ) || a
                        .challenges
                        .iter()
                        .any(|c| c.validated.as_ref().is_some_and(|v| now > v.expires))
                })
            });
        let authorizations: Vec<_> = if invalid {
            Vec::new()
        } else {
            self.authorizations
                .iter()
                .map(|id| format!("{base}authorization/{id}"))
                .collect()
        };
        json!({"status":if invalid {"invalid"} else if !self.authorizations.is_empty() && self.authorizations.iter().all(|id|protocol.authorizations.get(id).is_some_and(|a|a.status==AuthorizationStatus::Valid)){"ready"} else {"pending"},"expires":self.public_expires,"identifiers":if self.identifiers.is_empty(){Value::Null}else{json!(self.identifiers.iter().map(|i|i.descriptor(true)).collect::<Vec<_>>())},"authorizations":if authorizations.is_empty(){Value::Null}else{json!(authorizations)},"finalize":format!("{base}order/{}/finalize",self.id)})
    }
}
impl Protocol {
    pub(crate) fn validate_orders(&self) -> Result<()> {
        if self.orders.len() > MAX_ORDERS
            || self.authorizations.len() > MAX_ORDERS * MAX_IDENTIFIERS
        {
            return Err(error(503, "ACME order capacity rejected"));
        }
        let mut references = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        for (id, order) in &self.orders {
            let account = self
                .accounts
                .get(&order.account)
                .ok_or_else(|| error(503, "ACME order account owner unavailable"))?;
            if id != &order.id
                || !valid_identifier(id)
                || order.owner != self.owner
                || !valid_directory(&order.directory)
                || order.directory != account.directory
                || order.account_thumbprint != account.thumbprint
                || order.created < account.created
                || order.created > self.clock
                || order.expires <= order.created
                || order.expires.seconds().checked_sub(order.created.seconds()) != Some(86400)
                || order.expires.duration_since_epoch().subsec_nanos()
                    != order.created.duration_since_epoch().subsec_nanos()
                || order.identifiers.len() > MAX_IDENTIFIERS
                || order.authorizations.len() != order.identifiers.len()
                || !chrono::DateTime::parse_from_rfc3339(&order.public_expires).is_ok_and(|at| {
                    u64::try_from(at.timestamp()).ok() == Some(order.expires.seconds())
                        && at.timestamp_subsec_nanos() == 0
                })
            {
                return Err(error(503, "ACME durable order owner rejected"));
            }
            for (identifier, auth_id) in order.identifiers.iter().zip(&order.authorizations) {
                identifier.validate()?;
                let authorization = self
                    .authorizations
                    .get(auth_id)
                    .ok_or_else(|| error(503, "ACME order authorization unavailable"))?;
                if !references.insert(auth_id)
                    || authorization.identifier != *identifier
                    || authorization.account != order.account
                    || authorization.directory != order.directory
                    || authorization.created != order.created
                {
                    return Err(error(503, "ACME authorization order binding rejected"));
                }
            }
        }
        if references.len() != self.authorizations.len() {
            return Err(error(503, "ACME orphan authorization rejected"));
        }
        for (id, a) in &self.authorizations {
            let account = self
                .accounts
                .get(&a.account)
                .ok_or_else(|| error(503, "ACME authorization account unavailable"))?;
            a.identifier.validate()?;
            if id != &a.id
                || !valid_identifier(id)
                || a.owner != self.owner
                || a.account_thumbprint != account.thumbprint
                || a.directory != account.directory
                || a.created < account.created
                || a.created > self.clock
                || (a.status == AuthorizationStatus::Deactivated) != a.deactivated.is_some()
                || a.deactivated
                    .is_some_and(|t| t < a.created || t > self.clock)
                || a.challenges.len() != a.identifier.challenge_kinds().len()
            {
                return Err(error(503, "ACME durable authorization owner rejected"));
            }
            let active = a
                .challenges
                .iter()
                .filter(|c| {
                    matches!(
                        c.status,
                        ChallengeStatus::Processing | ChallengeStatus::Valid
                    )
                })
                .count();
            if active > 1 || (a.status == AuthorizationStatus::Valid && active != 1) {
                return Err(error(503, "ACME challenge active ownership rejected"));
            }
            for (c, kind) in a.challenges.iter().zip(a.identifier.challenge_kinds()) {
                if c.kind != *kind
                    || match a.status {
                        AuthorizationStatus::Pending => !matches!(
                            c.status,
                            ChallengeStatus::Pending | ChallengeStatus::Processing
                        ),
                        AuthorizationStatus::Valid => {
                            !matches!(c.status, ChallengeStatus::Pending | ChallengeStatus::Valid)
                        }
                        AuthorizationStatus::Invalid | AuthorizationStatus::Deactivated => {
                            c.status != ChallengeStatus::Invalid
                        }
                    }
                    || (c.status == ChallengeStatus::Processing && c.validation.is_none())
                    || (c.status == ChallengeStatus::Pending
                        && (c.validation.is_some() || c.validated.is_some()))
                    || (c.status == ChallengeStatus::Valid
                        && (c.validated.is_none() || c.validation.is_none()))
                    || c.validation.as_ref().is_some_and(|v| {
                        v.initiated < a.created
                            || v.initiated > self.clock
                            || v.retry_after < v.initiated
                            || v.retry_count > 7
                            || v.error
                                .as_ref()
                                .is_some_and(|e| e.len() > 4096 || e.chars().any(char::is_control))
                    })
                    || c.validated.as_ref().is_some_and(|v| {
                        v.at < a.created
                            || c.validation.as_ref().is_none_or(|q| v.at < q.initiated)
                            || v.at > self.clock
                            || v.expires.seconds().checked_sub(v.at.seconds()) != Some(15 * 86400)
                            || v.expires.duration_since_epoch().subsec_nanos()
                                != v.at.duration_since_epoch().subsec_nanos()
                            || ![(&v.public_at, v.at), (&v.public_expires, v.expires)]
                                .iter()
                                .all(|(text, time)| {
                                    chrono::DateTime::parse_from_rfc3339(text).is_ok_and(|parsed| {
                                        u64::try_from(parsed.timestamp()).ok()
                                            == Some(time.seconds())
                                            && parsed.timestamp_subsec_nanos() == 0
                                    })
                                })
                    })
                    || !URL_SAFE_NO_PAD
                        .decode(&c.token)
                        .is_ok_and(|b| b.len() == 21 && URL_SAFE_NO_PAD.encode(&b) == c.token)
                    || !tokens.insert(&c.token)
                {
                    return Err(error(503, "ACME durable challenge binding rejected"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn insert_order(
        &mut self,
        account_id: &str,
        directory: &str,
        identifiers: Vec<Identifier>,
        at: Timestamp,
    ) -> Result<String> {
        let account = self
            .by_id(account_id, directory)
            .filter(|a| a.status == AccountStatus::Valid)
            .ok_or_else(|| error(401, "the client lacks sufficient authorization"))?;
        if self.orders.len() >= MAX_ORDERS {
            return Err(error(507, "ACME order capacity exhausted"));
        }
        let account_thumbprint = account.thumbprint.clone();
        let id = uuid()?;
        if self.orders.contains_key(&id) {
            return Err(error(503, "ACME order identifier collision"));
        }
        let seconds = at
            .seconds()
            .checked_add(86400)
            .ok_or_else(|| error(503, "ACME order expiry overflow"))?;
        let expires = Timestamp::checked(seconds, at.duration_since_epoch().subsec_nanos())
            .map_err(|_| error(503, "ACME order expiry overflow"))?;
        let public_expires = expires
            .truncate_seconds()
            .local_rfc3339()
            .map_err(|_| error(503, "ACME order expiry rendering unavailable"))?;
        let mut authorizations = Vec::new();
        // Generate all public challenges before mutating the admitted candidate.
        let mut prepared = Vec::new();
        for identifier in &identifiers {
            let auth_id = uuid()?;
            if self.authorizations.contains_key(&auth_id) || authorizations.contains(&auth_id) {
                return Err(error(503, "ACME authorization identifier collision"));
            }
            let challenges = identifier
                .challenge_kinds()
                .iter()
                .map(|kind| {
                    Ok(Challenge {
                        kind: (*kind).into(),
                        status: ChallengeStatus::Pending,
                        validation: None,
                        validated: None,
                        token: URL_SAFE_NO_PAD.encode(
                            crate::crypto::random::<21>()
                                .map_err(|_| error(503, "ACME challenge token unavailable"))?,
                        ),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            prepared.push(Authorization {
                id: auth_id.clone(),
                owner: self.owner.clone(),
                account: account_id.into(),
                account_thumbprint: account_thumbprint.clone(),
                directory: directory.into(),
                created: at,
                deactivated: None,
                identifier: identifier.clone(),
                status: AuthorizationStatus::Pending,
                challenges,
            });
            authorizations.push(auth_id);
        }
        for a in prepared {
            self.authorizations.insert(a.id.clone(), a);
        }
        self.orders.insert(
            id.clone(),
            Order {
                id: id.clone(),
                owner: self.owner.clone(),
                account: account_id.into(),
                account_thumbprint,
                directory: directory.into(),
                created: at,
                expires,
                public_expires,
                identifiers,
                authorizations,
            },
        );
        Ok(id)
    }
    pub(crate) fn validate_order_successor(&self, previous: &Self) -> Result<()> {
        for (id, old) in &previous.orders {
            let next = self
                .orders
                .get(id)
                .ok_or_else(|| error(503, "ACME order cannot disappear"))?;
            if old != next {
                return Err(error(503, "ACME order owner cannot change"));
            }
        }
        for (id, old) in &previous.authorizations {
            let next = self
                .authorizations
                .get(id)
                .ok_or_else(|| error(503, "ACME authorization cannot disappear"))?;
            if old.owner != next.owner
                || old.account != next.account
                || old.account_thumbprint != next.account_thumbprint
                || old.directory != next.directory
                || old.identifier != next.identifier
                || old.created != next.created
                || old.challenges.len() != next.challenges.len()
                || old.challenges.iter().zip(&next.challenges).any(|(a, b)| {
                    a.kind != b.kind
                        || a.token != b.token
                        || a.validated
                            .as_ref()
                            .is_some_and(|v| b.validated.as_ref() != Some(v))
                        || a.validation.as_ref().is_some_and(|v| {
                            b.validation.as_ref().is_none_or(|n| {
                                n.initiated != v.initiated
                                    || n.retry_count < v.retry_count
                                    || n.retry_after < v.retry_after
                            })
                        })
                        || (a.status == ChallengeStatus::Valid
                            && !matches!(
                                b.status,
                                ChallengeStatus::Valid | ChallengeStatus::Invalid
                            ))
                        || (a.status == ChallengeStatus::Invalid
                            && b.status != ChallengeStatus::Invalid)
                })
                || old.status == AuthorizationStatus::Valid
                    && !matches!(
                        next.status,
                        AuthorizationStatus::Valid | AuthorizationStatus::Deactivated
                    )
                || old.status == AuthorizationStatus::Invalid
                    && next.status != AuthorizationStatus::Invalid
                || old.status == AuthorizationStatus::Deactivated
                    && (next.status != old.status || next.deactivated != old.deactivated)
            {
                return Err(error(
                    503,
                    "ACME authorization owner or deactivation regressed",
                ));
            }
        }
        Ok(())
    }
}
