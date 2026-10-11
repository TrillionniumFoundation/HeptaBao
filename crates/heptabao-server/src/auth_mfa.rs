//! Identity MFA owns enrollment and never retains an issued bearer.
//! All state enters the existing encrypted Auth owner and its schema129 floor.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};

#[path = "auth_mfa_issuance.rs"]
mod issuance;
pub(crate) use issuance::{MfaJanitorHead, NativeMfaBinding, PendingServiceGrant};
#[path = "auth_mfa_janitor_custody.rs"]
mod janitor_custody;

pub(crate) const STATE_SCHEMA: u32 = 129;
const FORMAT: u32 = 1;
const MAX_METHODS: usize = 1024;
const MAX_ENFORCEMENTS: usize = 1024;
const MAX_ENROLLMENTS: usize = 16384;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretKey(Vec<u8>);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl SecretKey {
    fn new(size: usize) -> Result<Self, AuthError> {
        let mut secret = Zeroizing::new(vec![0; size]);
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| err(503, "MFA system entropy unavailable"))?;
        Ok(Self(secret.to_vec()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registry {
    format: u32,
    key: SecretKey,
    clock: Timestamp,
    mutation_epoch: u64,
    namespaces: BTreeMap<String, NamespaceOwner>,
    retired: BTreeMap<String, u64>,
    closed_references: BTreeMap<String, ClosedReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    janitor_custody: Option<janitor_custody::Custody>,
    // A detached typed parcel is not yet an authenticated ciphertext owner.
    // Only actual finish_with_owner may sign and publish these projections.
    #[serde(skip)]
    janitor_drafts: BTreeMap<String, janitor_custody::Capture>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedReference {
    namespace_id: String,
    incarnation: u64,
    method_ids: BTreeSet<String>,
    owner_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_digest: Option<[u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceOwner {
    namespace: String,
    namespace_id: String,
    incarnation: u64,
    methods: BTreeMap<String, Method>,
    enforcements: BTreeMap<String, Enforcement>,
    enrollments: BTreeMap<String, BTreeMap<String, Enrollment>>,
    challenges: BTreeMap<String, issuance::Challenge>,
    issued: u64,
    terminal: BTreeSet<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Method {
    id: String,
    namespace: String,
    namespace_id: String,
    generation: u64,
    name: String,
    settings: TotpSettings,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpSettings {
    issuer: String,
    algorithm: String,
    digits: u32,
    key_size: u32,
    max_validation_attempts: u32,
    period: u64,
    qr_size: u32,
    skew: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enforcement {
    id: String,
    name: String,
    namespace: String,
    namespace_id: String,
    generation: u64,
    auth_method_accessors: BTreeSet<String>,
    auth_method_types: BTreeSet<String>,
    identity_entity_ids: BTreeSet<String>,
    identity_group_ids: BTreeSet<String>,
    mfa_method_ids: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    secret: SecretKey,
    generation: u64,
    attempts: u32,
    last_accepted_counter: Option<u64>,
    last_attempt_at: Option<Timestamp>,
}
impl NamespaceOwner {
    fn reference_method_ids(&self) -> BTreeSet<String> {
        self.enforcements
            .values()
            .flat_map(|rule| rule.mfa_method_ids.iter().cloned())
            .chain(
                self.enrollments
                    .values()
                    .flat_map(|entries| entries.keys().cloned()),
            )
            .collect()
    }
}
impl Registry {
    fn new() -> Result<Self, AuthError> {
        Ok(Self {
            format: FORMAT,
            key: SecretKey::new(32)?,
            clock: Timestamp::whole(0).map_err(|_| err(503, "MFA initial clock unavailable"))?,
            mutation_epoch: 0,
            namespaces: BTreeMap::new(),
            retired: BTreeMap::new(),
            closed_references: BTreeMap::new(),
            janitor_custody: None,
            janitor_drafts: BTreeMap::new(),
        })
    }
    fn advance_mutation(&mut self) -> Result<(), AuthError> {
        self.mutation_epoch = self
            .mutation_epoch
            .checked_add(1)
            .ok_or_else(|| err(503, "MFA mutation epoch exhausted"))?;
        Ok(())
    }
    // Partitioning changes the representation, not the native business state.
    // A closed parcel contributes its exact authenticated owner digest here.
    fn semantic_digest(&self) -> Result<[u8; 32], AuthError> {
        let mut owners = self
            .closed_references
            .iter()
            .map(|(namespace, index)| {
                (
                    namespace.clone(),
                    (index.owner_digest, index.method_ids.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (namespace, owner) in &self.namespaces {
            if owners
                .insert(
                    namespace.clone(),
                    (owner_digest(owner)?, owner.reference_method_ids()),
                )
                .is_some()
            {
                return Err(err(503, "MFA semantic owner collision"));
            }
        }
        let encoded = match &self.janitor_custody {
            Some(custody) if !custody.terminal.is_empty() || !custody.applied.is_empty() => {
                crate::secret_serde::to_vec(
                    &(
                        FORMAT,
                        &self.key,
                        self.clock,
                        &self.retired,
                        owners,
                        &custody.terminal,
                        &custody.applied,
                    ),
                    crate::MAX_APPLICATION_STATE_BYTES,
                )
            }
            _ => crate::secret_serde::to_vec(
                &(FORMAT, &self.key, self.clock, &self.retired, owners),
                crate::MAX_APPLICATION_STATE_BYTES,
            ),
        }
        .map_err(|_| err(503, "MFA semantic custody serialization unavailable"))?;
        Ok(crate::crypto::digest(&encoded))
    }
    fn owner_mut(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
    ) -> Result<&mut NamespaceOwner, AuthError> {
        if self
            .retired
            .get(namespace)
            .is_some_and(|old| *old >= incarnation)
        {
            return Err(err(503, "MFA namespace incarnation retired"));
        }
        let owner = self
            .namespaces
            .entry(namespace.to_owned())
            .or_insert_with(|| NamespaceOwner {
                namespace: namespace.to_owned(),
                namespace_id: namespace_id.to_owned(),
                incarnation,
                methods: BTreeMap::new(),
                enforcements: BTreeMap::new(),
                enrollments: BTreeMap::new(),
                challenges: BTreeMap::new(),
                issued: 0,
                terminal: BTreeSet::new(),
            });
        if owner.namespace_id != namespace_id || owner.incarnation != incarnation {
            return Err(err(503, "MFA native namespace owner changed"));
        }
        Ok(owner)
    }
    fn method(&self, namespace: &str, id: &str) -> Option<&Method> {
        self.namespaces
            .iter()
            .filter(|(owner, _)| ancestor(owner, namespace))
            .find_map(|(_, owner)| owner.methods.get(id))
    }
    fn method_mut(&mut self, namespace: &str, id: &str) -> Option<&mut Method> {
        self.namespaces.get_mut(namespace)?.methods.get_mut(id)
    }
    fn validate(&self) -> Result<(), AuthError> {
        if !(self.format == FORMAT && self.janitor_custody.is_none()
            || self.format == janitor_custody::FORMAT && self.janitor_custody.is_some())
            || self.key.0.len() != 32
            || self.mutation_epoch == 0
        {
            return Err(err(503, "invalid MFA reader floor or private key"));
        }
        if self.closed_references.iter().any(|(namespace, index)| {
            namespace.is_empty()
                || self.namespaces.contains_key(namespace)
                || index.namespace_id.is_empty()
                || index.incarnation == 0
                || index.owner_digest == [0; 32]
                || index.queue_digest.is_some() && self.janitor_custody.is_none()
                || index.method_ids.iter().any(|id| !uuid_valid(id))
        }) {
            return Err(err(503, "MFA closed reference index rejected"));
        }
        let mut method_ids = BTreeSet::new();
        for (namespace, owner) in &self.namespaces {
            if owner.namespace != *namespace
                || owner.namespace_id.is_empty()
                || (!namespace.is_empty() && owner.incarnation == 0)
                || owner.methods.len() > MAX_METHODS
                || owner.enforcements.len() > MAX_ENFORCEMENTS
                || owner.enrollments.len() > MAX_ENROLLMENTS
                || self
                    .retired
                    .get(namespace)
                    .is_some_and(|old| *old >= owner.incarnation)
            {
                return Err(err(503, "invalid MFA namespace owner"));
            }
            for (id, method) in &owner.methods {
                if method.id != *id
                    || !uuid_valid(id)
                    || !method_ids.insert(id)
                    || method.namespace != *namespace
                    || method.namespace_id != owner.namespace_id
                    || method.generation == 0
                {
                    return Err(err(503, "invalid MFA method binding"));
                }
                method.settings.validate()?;
            }
            for (name, enforcement) in &owner.enforcements {
                if enforcement.name != *name
                    || enforcement.namespace != *namespace
                    || enforcement.namespace_id != owner.namespace_id
                    || enforcement.generation == 0
                    || !uuid_valid(&enforcement.id)
                    || !enforcement.identity_entity_ids.is_empty()
                    || !enforcement.identity_group_ids.is_empty()
                    || enforcement
                        .auth_method_types
                        .iter()
                        .any(|kind| kind != "userpass")
                    || enforcement.auth_method_accessors.len() > 1024
                    || enforcement.auth_method_accessors.iter().any(|accessor| {
                        accessor.is_empty()
                            || accessor.len() > 1024
                            || accessor.chars().any(char::is_control)
                    })
                    || enforcement.auth_method_types.is_empty()
                        && enforcement.auth_method_accessors.is_empty()
                    || enforcement.mfa_method_ids.is_empty()
                    || enforcement
                        .mfa_method_ids
                        .iter()
                        .any(|id| self.method(namespace, id).is_none())
                {
                    return Err(err(503, "invalid MFA enforcement binding"));
                }
            }
            for (entity, enrollments) in &owner.enrollments {
                if entity.is_empty() || entity.len() > 256 {
                    return Err(err(503, "invalid MFA entity owner"));
                }
                for (id, enrollment) in enrollments {
                    if self.method(namespace, id).is_none()
                        || enrollment.generation == 0
                        || !(10..=128).contains(&enrollment.secret.0.len())
                    {
                        return Err(err(503, "invalid MFA enrollment binding"));
                    }
                }
            }
            self.validate_challenges(owner)?;
        }
        self.validate_janitor_custody()?;
        Ok(())
    }
}
impl TotpSettings {
    fn defaults() -> Self {
        Self {
            issuer: String::new(),
            algorithm: "SHA1".into(),
            digits: 6,
            key_size: 20,
            max_validation_attempts: 5,
            period: 30,
            qr_size: 200,
            skew: 1,
        }
    }
    fn validate(&self) -> Result<(), AuthError> {
        if self.issuer.is_empty() {
            return Err(bad("issuer must be set"));
        }
        if self.issuer.len() > 256 || self.issuer.chars().any(char::is_control) {
            return Err(bad("invalid issuer"));
        }
        if !matches!(self.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
            return Err(bad("unrecognized algorithm"));
        }
        if !matches!(self.digits, 6 | 8) {
            return Err(bad("digits can only be 6 or 8"));
        }
        if self.skew > 1 {
            return Err(bad("skew must be 0 or 1"));
        }
        if !(10..=128).contains(&self.key_size)
            || self.period == 0
            || self.period > 86400
            || self.qr_size > 4096
            || self.max_validation_attempts == 0
            || self.max_validation_attempts > 1000
        {
            return Err(bad("MFA TOTP configuration exceeds native bounds"));
        }
        Ok(())
    }
    fn updated(&self, body: &Value) -> Result<Self, AuthError> {
        reject_unknown(
            body,
            &[
                "issuer",
                "algorithm",
                "digits",
                "key_size",
                "max_validation_attempts",
                "period",
                "qr_size",
                "skew",
                "method_name",
            ],
        )?;
        let mut value = self.clone();
        if let Some(v) = body.get("issuer") {
            value.issuer = v
                .as_str()
                .ok_or_else(|| bad("issuer must be a string"))?
                .to_owned();
        }
        if let Some(v) = body.get("algorithm") {
            value.algorithm = v
                .as_str()
                .ok_or_else(|| bad("algorithm must be a string"))?
                .to_owned();
        }
        macro_rules! u32_field {
            ($field:ident) => {
                if let Some(v) = body.get(stringify!($field)) {
                    value.$field = u32::try_from(v.as_u64().ok_or_else(|| {
                        bad(concat!(
                            stringify!($field),
                            " must be a nonnegative integer"
                        ))
                    })?)
                    .map_err(|_| bad(concat!(stringify!($field), " is too large")))?;
                }
            };
        }
        u32_field!(digits);
        u32_field!(key_size);
        u32_field!(max_validation_attempts);
        u32_field!(qr_size);
        for (field, target) in [("period", &mut value.period), ("skew", &mut value.skew)] {
            if let Some(v) = body.get(field) {
                *target = v
                    .as_u64()
                    .ok_or_else(|| bad("MFA field must be a nonnegative integer"))?;
            }
        }
        value.validate()?;
        Ok(value)
    }
}
impl Method {
    fn descriptor(&self) -> Value {
        let s = &self.settings;
        json!({"id":self.id,"name":self.name,"type":"totp",
            "namespace_id":self.namespace_id,"namespace_path":namespace_path(&self.namespace),
            "issuer":s.issuer,"algorithm":s.algorithm,"digits":s.digits,"key_size":s.key_size,
            "max_validation_attempts":s.max_validation_attempts,"period":s.period,
            "qr_size":s.qr_size,"skew":s.skew})
    }
}
impl Enforcement {
    fn descriptor(&self) -> Value {
        json!({"id":self.id,"name":self.name,"namespace_id":self.namespace_id,
            "namespace_path":namespace_path(&self.namespace),
            "auth_method_accessors":self.auth_method_accessors,"auth_method_types":self.auth_method_types,
            "identity_entity_ids":self.identity_entity_ids,"identity_group_ids":self.identity_group_ids,
            "mfa_method_ids":self.mfa_method_ids})
    }
}
fn namespace_path(namespace: &str) -> String {
    if namespace.is_empty() {
        String::new()
    } else {
        format!("{namespace}/")
    }
}
fn ancestor(owner: &str, namespace: &str) -> bool {
    owner.is_empty()
        || owner == namespace
        || namespace
            .strip_prefix(owner)
            .is_some_and(|rest| rest.starts_with('/'))
}
fn uuid_valid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
fn uuid() -> Result<String, AuthError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| err(503, "MFA system entropy unavailable"))?;
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
fn missing() -> AuthResponse {
    let mut r = empty(false);
    r.status = 404;
    r.body = json!({"errors":[]});
    r
}
fn list_response(rows: BTreeMap<String, Value>) -> AuthResponse {
    if rows.is_empty() {
        return missing();
    }
    response(
        json!({"keys":rows.keys().collect::<Vec<_>>(),"key_info":rows}),
        false,
    )
}
fn field_strings(body: &Value, name: &str) -> Result<BTreeSet<String>, AuthError> {
    let Some(value) = body.get(name) else {
        return Ok(BTreeSet::new());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| bad("MFA selectors must be arrays"))?;
    if rows.len() > 1024 {
        return Err(bad("MFA selector bound exceeded"));
    }
    let mut values = BTreeSet::new();
    for row in rows {
        let value = row
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 1024 && !v.chars().any(char::is_control))
            .ok_or_else(|| bad("invalid MFA selector"))?;
        if !values.insert(value.to_owned()) {
            return Err(bad("duplicate MFA selector"));
        }
    }
    Ok(values)
}
fn owner_digest(owner: &NamespaceOwner) -> Result<[u8; 32], AuthError> {
    let encoded = crate::secret_serde::to_vec(owner, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "MFA private owner serialization unavailable"))?;
    Ok(crate::crypto::digest(&encoded))
}
impl AuthState {
    fn mfa_owned_mutation(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<AuthResponse, AuthError>,
    ) -> Result<AuthResponse, AuthError> {
        let original = self.identity_mfa.clone();
        let result = operation(self);
        match result {
            Ok(reply) if reply.mutated => {
                let advance = self
                    .identity_mfa
                    .as_mut()
                    .ok_or_else(|| err(503, "MFA mutation owner unavailable"))
                    .and_then(Registry::advance_mutation);
                match advance {
                    Ok(()) => Ok(reply),
                    Err(error) => {
                        self.identity_mfa = original;
                        Err(error)
                    }
                }
            }
            Ok(reply) => {
                self.identity_mfa = original;
                Ok(reply)
            }
            Err(error) => {
                self.identity_mfa = original;
                Err(error)
            }
        }
    }
    pub(crate) fn has_identity_mfa_state(&self) -> bool {
        self.identity_mfa.is_some()
    }
    pub(crate) fn validate_identity_mfa_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(Self::has_identity_mfa_state) && self.identity_mfa.is_none() {
            return Err(err(503, "MFA reader floor cannot be removed"));
        }
        if let Some(registry) = &self.identity_mfa {
            registry.validate()?;
            if registry
                .namespaces
                .values()
                .flat_map(|owner| owner.enforcements.values())
                .any(|rule| {
                    rule.auth_method_accessors.iter().any(|accessor| {
                        self.identity_alias_mount(&rule.namespace, accessor)
                            .is_some_and(|(_, kind)| kind != "userpass")
                    })
                })
            {
                return Err(err(
                    503,
                    "MFA enforcement references an unadmitted native auth accessor",
                ));
            }
            if let Some(old) = previous.and_then(|state| state.identity_mfa.as_ref()) {
                if registry.key.0 != old.key.0 {
                    return Err(err(503, "MFA private owner key changed"));
                }
                registry.validate_successor(old)?;
            }
        }
        Ok(())
    }
    fn mfa_registry_mut(&mut self) -> Result<&mut Registry, AuthError> {
        if self.identity_mfa.is_none() {
            self.identity_mfa = Some(Registry::new()?);
        }
        self.identity_mfa
            .as_mut()
            .ok_or_else(|| err(503, "MFA owner unavailable"))
    }
    pub(crate) fn mfa_method_route(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<AuthResponse, AuthError> {
        self.mfa_owned_mutation(|candidate| {
            candidate.mfa_method_route_inner(
                namespace,
                namespace_id,
                incarnation,
                method,
                path,
                body,
            )
        })
    }
    fn mfa_method_route_inner(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<AuthResponse, AuthError> {
        let rest = path
            .strip_prefix("identity/mfa/method")
            .ok_or_else(|| bad("invalid MFA method route"))?;
        let rest = rest.trim_start_matches('/');
        let list = method == "LIST"
            || method == "GET" && body.get("list").and_then(Value::as_bool) == Some(true);
        if rest.is_empty() || rest == "totp" {
            if list {
                let rows = self
                    .identity_mfa
                    .as_ref()
                    .map(|r| {
                        r.namespaces
                            .iter()
                            .filter(|(owner, _)| ancestor(owner, namespace))
                            .flat_map(|(_, owner)| {
                                owner
                                    .methods
                                    .iter()
                                    .map(|(id, m)| (id.clone(), m.descriptor()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return Ok(list_response(rows));
            }
            if rest != "totp" || !matches!(method, "POST" | "PUT") {
                return Err(err(405, "method not allowed"));
            }
            let settings = TotpSettings::defaults().updated(body)?;
            let name = body
                .get("method_name")
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| bad("method_name must be a string"))
                })
                .transpose()?
                .unwrap_or("")
                .to_owned();
            if name.len() > 256 || name.chars().any(char::is_control) {
                return Err(bad("invalid MFA method name"));
            }
            let id = uuid()?;
            let owner = self
                .mfa_registry_mut()?
                .owner_mut(namespace, namespace_id, incarnation)?;
            if owner.methods.len() >= MAX_METHODS {
                return Err(err(507, "MFA method capacity exhausted"));
            }
            owner.methods.insert(
                id.clone(),
                Method {
                    id: id.clone(),
                    namespace: namespace.to_owned(),
                    namespace_id: namespace_id.to_owned(),
                    generation: 1,
                    name,
                    settings,
                },
            );
            return Ok(response(json!({"method_id":id}), true));
        }
        let (typed, id) = match rest.split_once('/') {
            Some((kind, id)) => (Some(kind), id),
            None => (None, rest),
        };
        if typed.is_some_and(|kind| kind != "totp") {
            return Err(err(
                501,
                "MFA provider login and configuration are not yet implemented",
            ));
        }
        let Some(found) = self
            .identity_mfa
            .as_ref()
            .and_then(|r| r.method(namespace, id))
            .cloned()
        else {
            return Ok(if method == "DELETE" {
                empty(false)
            } else {
                missing()
            });
        };
        if method == "GET" {
            return Ok(response(found.descriptor(), false));
        }
        if found.namespace != namespace {
            return Err(denied());
        }
        match method {
            "POST" | "PUT" | "PATCH" => {
                let settings = found.settings.updated(body)?;
                let name = body
                    .get("method_name")
                    .map(|v| {
                        v.as_str()
                            .ok_or_else(|| bad("method_name must be a string"))
                    })
                    .transpose()?
                    .unwrap_or(&found.name)
                    .to_owned();
                if name.len() > 256 || name.chars().any(char::is_control) {
                    return Err(bad("invalid MFA method name"));
                }
                let method = self
                    .identity_mfa
                    .as_mut()
                    .and_then(|r| r.method_mut(namespace, id))
                    .ok_or_else(|| err(503, "MFA method changed"))?;
                method.settings = settings;
                method.name = name;
                method.generation = method
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| err(503, "MFA method generation exhausted"))?;
                Ok(empty(true))
            }
            "DELETE" => {
                let registry = self
                    .identity_mfa
                    .as_ref()
                    .ok_or_else(|| err(503, "MFA owner missing"))?;
                if registry
                    .closed_references
                    .values()
                    .any(|index| index.method_ids.contains(id))
                    || registry.namespaces.values().any(|n| {
                        n.enforcements
                            .values()
                            .any(|e| e.mfa_method_ids.contains(id))
                    })
                {
                    return Err(err(
                        500,
                        "methodID is still used by an enforcement configuration",
                    ));
                }
                let owner = self
                    .identity_mfa
                    .as_mut()
                    .and_then(|r| r.namespaces.get_mut(namespace))
                    .ok_or_else(|| err(503, "MFA owner missing"))?;
                owner.methods.remove(id);
                let registry = self
                    .identity_mfa
                    .as_mut()
                    .ok_or_else(|| err(503, "MFA owner missing"))?;
                for owner in registry.namespaces.values_mut() {
                    for enrolled in owner.enrollments.values_mut() {
                        enrolled.remove(id);
                    }
                    owner.enrollments.retain(|_, entries| !entries.is_empty());
                    owner.retire_method_challenges(id);
                }
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
    pub(crate) fn mfa_enforcement_route(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<AuthResponse, AuthError> {
        self.mfa_owned_mutation(|candidate| {
            candidate.mfa_enforcement_route_inner(
                namespace,
                namespace_id,
                incarnation,
                method,
                path,
                body,
            )
        })
    }
    fn mfa_enforcement_route_inner(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<AuthResponse, AuthError> {
        let name = path
            .strip_prefix("identity/mfa/login-enforcement")
            .ok_or_else(|| bad("invalid MFA enforcement route"))?
            .trim_start_matches('/');
        let list = method == "LIST"
            || method == "GET" && body.get("list").and_then(Value::as_bool) == Some(true);
        if name.is_empty() {
            if !list {
                return Err(err(405, "method not allowed"));
            }
            let rows = self
                .identity_mfa
                .as_ref()
                .map(|r| {
                    r.namespaces
                        .iter()
                        .filter(|(owner, _)| ancestor(owner, namespace))
                        .flat_map(|(_, owner)| {
                            owner
                                .enforcements
                                .iter()
                                .map(|(name, e)| (name.clone(), e.descriptor()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            return Ok(list_response(rows));
        }
        if name.contains('/') || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(bad("invalid MFA enforcement name"));
        }
        let previous = self
            .identity_mfa
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
            .and_then(|o| o.enforcements.get(name))
            .cloned();
        match method {
            "GET" => Ok(previous.map_or_else(missing, |e| response(e.descriptor(), false))),
            "DELETE" => {
                if let Some(owner) = self
                    .identity_mfa
                    .as_mut()
                    .and_then(|r| r.namespaces.get_mut(namespace))
                {
                    let changed = owner.enforcements.remove(name).is_some();
                    if changed {
                        owner.retire_enforcement_challenges(name);
                    }
                    return Ok(empty(changed));
                }
                Ok(empty(false))
            }
            "POST" | "PUT" | "PATCH" => {
                reject_unknown(
                    body,
                    &[
                        "auth_method_accessors",
                        "auth_method_types",
                        "identity_entity_ids",
                        "identity_group_ids",
                        "mfa_method_ids",
                    ],
                )?;
                let ids = field_strings(body, "mfa_method_ids")?;
                if ids.is_empty() {
                    return Err(bad("missing method ids"));
                }
                if ids.iter().any(|id| {
                    self.identity_mfa
                        .as_ref()
                        .and_then(|r| r.method(namespace, id))
                        .is_none()
                }) {
                    return Err(bad("invalid MFA method ID"));
                }
                let accessors = field_strings(body, "auth_method_accessors")?;
                let types = field_strings(body, "auth_method_types")?;
                if types.iter().any(|kind| {
                    !matches!(
                        kind.as_str(),
                        "userpass"
                            | "ldap"
                            | "approle"
                            | "jwt"
                            | "oidc"
                            | "kubernetes"
                            | "cert"
                            | "radius"
                            | "kerberos"
                            | "plugin"
                            | "token"
                    )
                }) {
                    return Err(bad("one of the auth method types provided is invalid"));
                }
                if accessors
                    .iter()
                    .any(|a| self.identity_alias_mount(namespace, a).is_none())
                {
                    return Err(bad("one of the auth method accessors provided is invalid"));
                }
                let entities = field_strings(body, "identity_entity_ids")?;
                let groups = field_strings(body, "identity_group_ids")?;
                // Initial native MFA admission is only implemented at the
                // userpass service-token producer. Configuration cannot turn
                // another first-factor issuer into a silently bypassed rule.
                if types.iter().any(|kind| kind != "userpass")
                    || accessors.iter().any(|accessor| {
                        self.identity_alias_mount(namespace, accessor)
                            .is_none_or(|(_, kind)| kind != "userpass")
                    })
                    || !entities.is_empty()
                    || !groups.is_empty()
                {
                    return Err(err(
                        501,
                        "MFA selector requires an unadmitted native issuance owner",
                    ));
                }
                if accessors.is_empty()
                    && types.is_empty()
                    && entities.is_empty()
                    && groups.is_empty()
                {
                    return Err(bad("missing MFA enforcement selector"));
                }
                let id = previous
                    .as_ref()
                    .map(|e| e.id.clone())
                    .map(Ok)
                    .unwrap_or_else(uuid)?;
                let generation = previous
                    .as_ref()
                    .map_or(Some(1), |e| e.generation.checked_add(1))
                    .ok_or_else(|| err(503, "MFA enforcement generation exhausted"))?;
                let owner =
                    self.mfa_registry_mut()?
                        .owner_mut(namespace, namespace_id, incarnation)?;
                if previous.is_none() && owner.enforcements.len() >= MAX_ENFORCEMENTS {
                    return Err(err(507, "MFA enforcement capacity exhausted"));
                }
                owner.retire_enforcement_challenges(name);
                owner.enforcements.insert(
                    name.into(),
                    Enforcement {
                        id,
                        name: name.into(),
                        namespace: namespace.into(),
                        namespace_id: namespace_id.into(),
                        generation,
                        auth_method_accessors: accessors,
                        auth_method_types: types,
                        identity_entity_ids: entities,
                        identity_group_ids: groups,
                        mfa_method_ids: ids,
                    },
                );
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
    pub(crate) fn mfa_generate(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        entity: &str,
        method_id: &str,
        destroy: bool,
    ) -> Result<AuthResponse, AuthError> {
        self.mfa_owned_mutation(|candidate| {
            candidate.mfa_generate_inner(
                namespace,
                namespace_id,
                incarnation,
                entity,
                method_id,
                destroy,
            )
        })
    }
    fn mfa_generate_inner(
        &mut self,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        entity: &str,
        method_id: &str,
        destroy: bool,
    ) -> Result<AuthResponse, AuthError> {
        let method = self
            .identity_mfa
            .as_ref()
            .and_then(|r| r.method(namespace, method_id))
            .cloned()
            .ok_or_else(|| bad("invalid MFA method ID"))?;
        if destroy {
            let changed = self
                .identity_mfa
                .as_mut()
                .and_then(|r| r.namespaces.get_mut(namespace))
                .and_then(|o| o.enrollments.get_mut(entity))
                .is_some_and(|e| e.remove(method_id).is_some());
            let mut changed = changed;
            if let Some(owner) = self
                .identity_mfa
                .as_mut()
                .and_then(|r| r.namespaces.get_mut(namespace))
            {
                let old_enrollments = owner.enrollments.len();
                owner.enrollments.retain(|_, entries| !entries.is_empty());
                changed |= old_enrollments != owner.enrollments.len();
                let old = owner.challenges.len();
                owner.retire_enrollment_challenges(entity, method_id);
                changed |= old != owner.challenges.len();
            }
            return Ok(empty(changed));
        }
        if self
            .identity_mfa
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
            .and_then(|o| o.enrollments.get(entity))
            .is_some_and(|e| e.contains_key(method_id))
        {
            let mut reply = response(Value::Null, false);
            reply.body = json!({"data":null,"warnings":["TOTP secret already exists for this entity and method"]});
            return Ok(reply);
        }
        let secret = SecretKey::new(method.settings.key_size as usize)?;
        let (url, barcode) = crate::engines::mfa_totp_enrollment(
            &secret.0,
            &method.settings.issuer,
            entity,
            &method.settings.algorithm,
            method.settings.digits,
            method.settings.period,
            method.settings.qr_size,
        )
        .map_err(|_| err(503, "native MFA TOTP enrollment unavailable"))?;
        let owner = self
            .mfa_registry_mut()?
            .owner_mut(namespace, namespace_id, incarnation)?;
        if !owner.enrollments.contains_key(entity) && owner.enrollments.len() >= MAX_ENROLLMENTS {
            return Err(err(507, "MFA enrollment capacity exhausted"));
        }
        owner.enrollments.entry(entity.into()).or_default().insert(
            method_id.into(),
            Enrollment {
                secret,
                generation: 1,
                attempts: 0,
                last_accepted_counter: None,
                last_attempt_at: None,
            },
        );
        Ok(response(
            json!({"url":url.as_str(),"barcode":barcode.as_str()}),
            true,
        ))
    }
}

/// The global signing key remains in the root Auth owner; only this exact
/// namespace's private enrollment/challenge owner enters its encrypted parcel.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Parcel {
    key_digest: [u8; 32],
    owner: NamespaceOwner,
}
impl Parcel {
    pub(crate) fn validate_namespace(&self, actual: &str) -> Result<(), AuthError> {
        if actual.is_empty()
            || self.owner.namespace != actual
            || self.owner.incarnation == 0
            || self.owner.namespace_id.is_empty()
        {
            return Err(err(503, "MFA namespace parcel rejected"));
        }
        Ok(())
    }
}
impl AuthState {
    pub(crate) fn mfa_known_namespaces(&self) -> BTreeSet<String> {
        self.identity_mfa
            .as_ref()
            .map(|r| {
                r.namespaces
                    .keys()
                    .filter(|ns| !ns.is_empty())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    pub(crate) fn mfa_namespace_has_assets(&self, namespace: &str) -> bool {
        self.identity_mfa
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
            .is_some_and(|owner| {
                !owner.methods.is_empty()
                    || !owner.enforcements.is_empty()
                    || !owner.enrollments.is_empty()
                    || !owner.challenges.is_empty()
            })
    }
    pub(crate) fn detach_mfa_namespace(
        &mut self,
        namespace: &str,
    ) -> Result<Option<Parcel>, AuthError> {
        let Some(registry) = self.identity_mfa.as_mut() else {
            return Ok(None);
        };
        let Some(owner) = registry.namespaces.get(namespace) else {
            return Ok(None);
        };
        let digest = owner_digest(owner)?;
        let draft = janitor_custody::Capture::from_owner(
            owner,
            digest,
            registry.mutation_epoch,
            &registry.key.0,
        )?;
        if let Some(draft) = draft {
            registry.janitor_drafts.insert(namespace.to_owned(), draft);
        }
        let queue_digest = None;
        let owner = registry
            .namespaces
            .remove(namespace)
            .ok_or_else(|| err(503, "MFA namespace owner disappeared"))?;
        let refs = owner.reference_method_ids();
        registry.closed_references.insert(
            namespace.to_owned(),
            ClosedReference {
                namespace_id: owner.namespace_id.clone(),
                incarnation: owner.incarnation,
                method_ids: refs,
                owner_digest: digest,
                queue_digest,
            },
        );
        Ok(Some(Parcel {
            key_digest: crate::crypto::digest(&registry.key.0),
            owner,
        }))
    }
    pub(crate) fn mfa_namespace_attach_preflight(
        &self,
        namespace: &str,
        parcel: Option<&Parcel>,
    ) -> Result<(), AuthError> {
        let Some(parcel) = parcel else {
            return Ok(());
        };
        parcel.validate_namespace(namespace)?;
        let registry = self
            .identity_mfa
            .as_ref()
            .ok_or_else(|| err(503, "MFA parcel global reader floor missing"))?;
        if registry.namespaces.contains_key(namespace)
            || parcel.key_digest != crate::crypto::digest(&registry.key.0)
        {
            return Err(err(503, "MFA parcel key or owner collision"));
        }
        let refs = parcel.owner.reference_method_ids();
        let actual_digest = owner_digest(&parcel.owner)?;
        if registry
            .closed_references
            .get(namespace)
            .is_none_or(|index| {
                index.method_ids != refs
                    || actual_digest != index.owner_digest
                    || index.namespace_id != parcel.owner.namespace_id
                    || index.incarnation != parcel.owner.incarnation
            })
        {
            return Err(err(
                503,
                "MFA closed reference index does not match authenticated parcel",
            ));
        }
        let mut candidate = registry.clone();
        candidate.closed_references.remove(namespace);
        candidate
            .namespaces
            .insert(namespace.to_owned(), parcel.owner.clone());
        candidate.validate()
    }
    pub(crate) fn attach_mfa_namespace(
        &mut self,
        namespace: &str,
        parcel: Option<Parcel>,
    ) -> Result<(), AuthError> {
        let Some(parcel) = parcel else {
            return Ok(());
        };
        self.mfa_namespace_attach_preflight(namespace, Some(&parcel))?;
        let registry = self
            .identity_mfa
            .as_mut()
            .ok_or_else(|| err(503, "MFA namespace owner unavailable"))?;
        registry.closed_references.remove(namespace);
        registry.janitor_drafts.remove(namespace);
        registry
            .namespaces
            .insert(namespace.to_owned(), parcel.owner);
        Ok(())
    }
    pub(crate) fn retire_mfa_pending_delivery(&mut self, namespace: &str) -> Result<(), AuthError> {
        if let Some(owner) = self
            .identity_mfa
            .as_mut()
            .and_then(|r| r.namespaces.get_mut(namespace))
        {
            let changed = !owner.challenges.is_empty();
            owner.retire_matching(|_| true);
            if changed {
                self.identity_mfa
                    .as_mut()
                    .ok_or_else(|| err(503, "MFA owner unavailable"))?
                    .advance_mutation()?;
            }
        }
        Ok(())
    }
    pub(crate) fn retire_closed_mfa_namespace(
        &mut self,
        binding: &crate::namespace_custody::Binding,
        cluster: &str,
    ) -> Result<(), AuthError> {
        let namespace = binding.namespace();
        if namespace.is_empty() {
            return Err(err(503, "root MFA owner cannot retire"));
        }
        let Some(registry) = self.identity_mfa.as_mut() else {
            return Ok(());
        };
        if registry.namespaces.contains_key(namespace) {
            return Err(err(503, "MFA retirement requires the actual closed owner"));
        }
        let Some(index) = registry.closed_references.get(namespace) else {
            return Ok(());
        };
        let expected = crate::namespace_custody::Binding::new(
            cluster.into(),
            namespace.into(),
            index.namespace_id.clone(),
            index.incarnation,
        )
        .map_err(|_| err(503, "MFA closed retirement binding unavailable"))?;
        if binding != &expected {
            return Err(err(503, "MFA closed retirement binding rejected"));
        }
        registry.closed_references.remove(namespace);
        if let Some(book) = &mut registry.janitor_custody {
            book.remove_namespace_locator(namespace);
        }
        registry.janitor_drafts.remove(namespace);
        registry
            .retired
            .entry(namespace.to_owned())
            .and_modify(|old| *old = (*old).max(binding.incarnation()))
            .or_insert(binding.incarnation());
        registry.advance_mutation()
    }
    pub(crate) fn retire_mfa_namespace(
        &mut self,
        namespace: &str,
        incarnation: u64,
    ) -> Result<(), AuthError> {
        if namespace.is_empty() || incarnation == 0 {
            return Err(err(503, "MFA namespace retirement unavailable"));
        }
        let Some(registry) = self.identity_mfa.as_mut() else {
            return Ok(());
        };
        if registry.closed_references.contains_key(namespace) {
            return Err(err(409, "MFA namespace owner is independently closed"));
        }
        if let Some(owner) = registry.namespaces.get(namespace) {
            if owner.incarnation != incarnation
                || !owner.methods.is_empty()
                || !owner.enforcements.is_empty()
                || !owner.enrollments.is_empty()
                || !owner.challenges.is_empty()
            {
                return Err(err(
                    409,
                    "MFA namespace still owns configuration or enrollments",
                ));
            }
        }
        let changed = registry.namespaces.contains_key(namespace)
            || registry
                .retired
                .get(namespace)
                .is_none_or(|old| *old < incarnation);
        registry.namespaces.remove(namespace);
        if let Some(book) = &mut registry.janitor_custody {
            book.remove_namespace_locator(namespace);
        }
        registry.janitor_drafts.remove(namespace);
        registry
            .retired
            .entry(namespace.to_owned())
            .and_modify(|old| *old = (*old).max(incarnation))
            .or_insert(incarnation);
        if changed {
            registry.advance_mutation()?;
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn validate_identity_mfa_bindings(
        &self,
        cluster: &str,
        mut live: impl FnMut(&str) -> Option<(String, u64)>,
        mut retired: impl FnMut(&str) -> Option<u64>,
        mut closed: impl FnMut(&str) -> bool,
    ) -> Result<(), AuthError> {
        let Some(registry) = &self.identity_mfa else {
            return Ok(());
        };
        for (namespace, owner) in &registry.namespaces {
            if live(namespace) != Some((owner.namespace_id.clone(), owner.incarnation)) {
                return Err(err(503, "MFA live namespace binding rejected"));
            }
            if owner
                .challenges
                .values()
                .any(|challenge| challenge.cluster() != cluster)
            {
                return Err(err(503, "MFA challenge cluster binding rejected"));
            }
        }
        registry.validate_janitor_custody()?;
        for (namespace, index) in &registry.closed_references {
            if closed(namespace)
                && live(namespace) == Some((index.namespace_id.clone(), index.incarnation))
            {
                continue;
            }
            // Hidden catalog metadata must be the exact signed original owner
            // projection under an ACTUAL visible enclosing ciphertext binding.
            let locator = registry
                .janitor_custody
                .as_ref()
                .and_then(|book| book.current.get(namespace))
                .ok_or_else(|| {
                    err(
                        503,
                        "MFA reference index has no real closed namespace owner",
                    )
                })?;
            locator.capture.verify(&registry.key.0)?;
            let visible = locator
                .enclosures
                .last()
                .or(locator.capture.ciphertext.as_ref())
                .ok_or_else(|| err(503, "MFA hidden namespace capsule unavailable"))?;
            let boundary = visible.binding.namespace();
            let (id, incarnation) = live(boundary)
                .ok_or_else(|| err(503, "MFA visible capsule catalog unavailable"))?;
            let actual = crate::namespace_custody::Binding::new(
                cluster.into(),
                boundary.into(),
                id,
                incarnation,
            )
            .map_err(|_| err(503, "MFA visible capsule binding rejected"))?;
            if !closed(boundary)
                || visible.binding != actual
                || locator.capture.namespace != *namespace
                || locator.capture.namespace_id != index.namespace_id
                || locator.capture.incarnation != index.incarnation
                || locator.capture.owner_digest != index.owner_digest
                || index.queue_digest != Some(locator.capture.core_digest()?)
            {
                return Err(err(503, "MFA hidden namespace original binding rejected"));
            }
        }
        for (namespace, floor) in &registry.retired {
            if retired(namespace).is_none_or(|actual| actual < *floor) {
                return Err(err(503, "MFA actual namespace retirement floor rejected"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_mfa_tests.rs"]
mod tests;
