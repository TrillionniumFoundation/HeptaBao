//! Durable SSH CA issuers, policy roles, and actual certificate transactions.
//! The enclosing namespace/mount cell owns all private material.
use super::*;
use super::{
    ssh_ca_crypto as crypto_key,
    ssh_ca_policy::{CaRole, SigningContext},
};
use ssh_key::{PublicKey, certificate::Builder};

const MAX_ISSUERS: usize = 32;
pub(super) const MAX_CA_ROLES: usize = 128;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issuer {
    id: String,
    name: String,
    public: String,
    private: crypto_key::PrivateMaterial,
}
impl Issuer {
    fn descriptor(&self) -> Value {
        json!({"issuer_id":self.id,"issuer_name":self.name,"public_key":self.public})
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct CaState {
    issuers: BTreeMap<String, Issuer>,
    default_issuer: Option<String>,
    roles: BTreeMap<String, CaRole>,
    signatures: u64,
}
fn named(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "default"
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
fn text<'a>(body: &'a Value, key: &str, default: &'a str) -> Result<&'a str> {
    body.get(key)
        .map(|v| v.as_str().ok_or_else(|| bad("SSH field must be a string")))
        .transpose()
        .map(|v| v.unwrap_or(default))
}
fn boolean(body: &Value, key: &str, default: bool) -> Result<bool> {
    body.get(key)
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| bad("SSH field must be a boolean"))
        })
        .transpose()
        .map(|v| v.unwrap_or(default))
}
fn bits(body: &Value) -> Result<u32> {
    body.get("key_bits")
        .map(|v| {
            v.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| bad("invalid SSH key bits"))
        })
        .transpose()
        .map(|v| v.unwrap_or(0))
}
fn encode_public(key: &PublicKey) -> Result<String> {
    let mut text = key
        .to_openssh()
        .map_err(|_| error(503, "SSH public key encoding failed"))?;
    text.push('\n');
    Ok(text)
}
fn signing_public_key(text: &str) -> Result<PublicKey> {
    let public = PublicKey::from_openssh(text).map_err(|_| bad("invalid SSH public key"))?;
    // OpenBao's x/crypto parser accepts these known plain key types and rejects unknowns.
    // ssh-key also accepts opaque Other keys, which must not enter either certificate builder.
    match public.key_data() {
        ssh_key::public::KeyData::Dsa(_)
        | ssh_key::public::KeyData::Ecdsa(_)
        | ssh_key::public::KeyData::Ed25519(_)
        | ssh_key::public::KeyData::Rsa(_)
        | ssh_key::public::KeyData::SkEcdsaSha2NistP256(_)
        | ssh_key::public::KeyData::SkEd25519(_) => Ok(public),
        _ => Err(bad("unsupported SSH public key algorithm")),
    }
}

impl CaState {
    pub(super) fn roles(&self) -> impl Iterator<Item = &String> {
        self.roles.keys()
    }
    pub(super) fn role_count(&self) -> usize {
        self.roles.len()
    }
    pub(super) fn contains_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }
    pub(super) fn remove_role(&mut self, name: &str) -> bool {
        self.roles.remove(name).is_some()
    }
    pub(super) fn put_role(&mut self, name: &str, body: &Value) -> Result<EngineResponse> {
        let role = CaRole::parse(body)?;
        if !self.roles.contains_key(name) && self.roles.len() >= MAX_CA_ROLES {
            return Err(error(507, "SSH role capacity exhausted"));
        }
        self.roles.insert(name.into(), role);
        Ok(empty(true))
    }
    pub(super) fn role_descriptor(&self, name: &str) -> Result<EngineResponse> {
        Ok(ok(
            self.roles.get(name).ok_or_else(not_found)?.descriptor(),
            false,
        ))
    }
    fn resolve(&self, reference: &str) -> Result<String> {
        if reference.is_empty() || reference == "default" {
            return self
                .default_issuer
                .clone()
                .ok_or_else(|| bad("SSH default issuer is not configured"));
        }
        if self.issuers.contains_key(reference) {
            return Ok(reference.into());
        }
        self.issuers
            .values()
            .find(|issuer| issuer.name == reference)
            .map(|issuer| issuer.id.clone())
            .ok_or_else(|| bad("SSH issuer reference was not found"))
    }
    pub(super) fn public_key(&self, reference: &str) -> Result<&str> {
        let id = self.resolve(reference)?;
        Ok(&self.issuers.get(&id).ok_or_else(not_found)?.public)
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.issuers.len() > MAX_ISSUERS || self.roles.len() > MAX_CA_ROLES {
            return Err(bad("SSH CA state exceeds bound"));
        }
        let mut names = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for (id, issuer) in &self.issuers {
            if !uuid(id)
                || id != &issuer.id
                || (!issuer.name.is_empty()
                    && (!named(&issuer.name) || !names.insert(&issuer.name)))
            {
                return Err(bad("invalid SSH issuer identity"));
            }
            issuer.private.validate()?;
            let actual = encode_public(&issuer.private.public()?)?;
            if issuer.public != actual || !public_keys.insert(&issuer.public) {
                return Err(bad("invalid SSH issuer key binding"));
            }
        }
        if self
            .default_issuer
            .as_ref()
            .is_some_and(|id| !self.issuers.contains_key(id))
        {
            return Err(bad("invalid SSH default issuer binding"));
        }
        for (name, role) in &self.roles {
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(bad("invalid SSH CA role name"));
            }
            role.validate()?;
        }
        Ok(())
    }
    fn submit(
        &mut self,
        body: &Value,
        configured_default: bool,
        path_name: Option<&str>,
    ) -> Result<EngineResponse> {
        reject_unknown(
            body,
            &[
                "private_key",
                "public_key",
                "generate_signing_key",
                "key_type",
                "key_bits",
                "issuer_name",
                "set_default",
            ],
        )?;
        let name = if configured_default {
            ""
        } else {
            text(body, "issuer_name", path_name.unwrap_or(""))?
        };
        if path_name.is_some_and(|path| body.get("issuer_name").is_some() && name != path) {
            return Err(bad("SSH issuer name disagrees with path"));
        }
        if !name.is_empty() && !named(name) {
            return Err(bad("invalid SSH issuer name"));
        }
        let generate = boolean(body, "generate_signing_key", true)?;
        let set_default = configured_default || boolean(body, "set_default", false)?;
        let private = text(body, "private_key", "")?;
        let public = text(body, "public_key", "")?;
        let material = if generate {
            if !private.is_empty() || !public.is_empty() {
                return Err(bad(
                    "provided key material conflicts with SSH key generation",
                ));
            }
            crypto_key::generate(text(body, "key_type", "ssh-rsa")?, bits(body)?)?
        } else {
            if private.is_empty() || public.is_empty() {
                return Err(bad(
                    "SSH private_key and public_key are required when generation is disabled",
                ));
            }
            crypto_key::import(private)?
        };
        let derived = material.public()?;
        if !public.is_empty() {
            let submitted =
                PublicKey::from_openssh(public).map_err(|_| bad("invalid SSH public key"))?;
            if submitted.key_data() != derived.key_data() {
                return Err(bad("SSH private and public keys do not match"));
            }
        }
        let encoded = encode_public(&derived)?;
        if let Some(old) = self
            .issuers
            .values()
            .find(|issuer| issuer.public == encoded)
        {
            let id = old.id.clone();
            let data = old.descriptor();
            let changed = set_default && self.default_issuer.as_ref() != Some(&id);
            if changed {
                self.default_issuer = Some(id);
            }
            let mut response = ok(data, changed);
            response.body["warnings"] = json!([
                "An issuer with the provided public key already exists, returning the existing issuer"
            ]);
            return Ok(response);
        }
        if !name.is_empty() && self.issuers.values().any(|issuer| issuer.name == name) {
            return Err(bad("SSH issuer name already exists"));
        }
        if self.issuers.len() >= MAX_ISSUERS {
            return Err(error(507, "SSH issuer capacity exhausted"));
        }
        let id = crate::crypto::uuid_from_bytes(
            &crate::crypto::random::<16>()
                .map_err(|_| error(503, "secure randomness unavailable"))?,
        );
        if self.issuers.contains_key(&id) {
            return Err(error(503, "SSH issuer identity collision"));
        }
        let issuer = Issuer {
            id: id.clone(),
            name: name.into(),
            public: encoded,
            private: material,
        };
        let data = issuer.descriptor();
        self.issuers.insert(id.clone(), issuer);
        if set_default || self.default_issuer.is_none() {
            self.default_issuer = Some(id);
        }
        crypto_key::deadline()?;
        Ok(ok(data, true))
    }
    pub(super) fn handle_admin(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<EngineResponse>> {
        if path == "config/ca" {
            return match method {
                "POST" | "PUT" => self.submit(body, true, None).map(Some),
                "GET" => {
                    reject_unknown(body, &[])?;
                    let id = self.resolve("default")?;
                    Ok(Some(ok(
                        self.issuers.get(&id).ok_or_else(not_found)?.descriptor(),
                        false,
                    )))
                }
                "DELETE" => {
                    reject_unknown(body, &[])?;
                    let deleted = self.issuers.len();
                    let changed = deleted > 0 || self.default_issuer.is_some();
                    self.issuers.clear();
                    self.default_issuer = None;
                    let mut response = empty(changed);
                    if deleted > 0 {
                        response.status = 200;
                        response.body = json!({"warnings":[format!("Deleted {deleted} issuers, including default issuer if configured.")]});
                    }
                    Ok(Some(response))
                }
                _ => Err(unsupported()),
            };
        }
        if path == "issuers/import" || path.starts_with("issuers/import/") {
            if !write_method(method) {
                return Err(unsupported());
            }
            let name = path.strip_prefix("issuers/import/");
            if name == Some("") {
                return Err(bad("invalid SSH issuer name"));
            }
            return self.submit(body, false, name).map(Some);
        }
        if path == "issuers" || path == "issuers/" {
            if method != "LIST" {
                return Err(unsupported());
            }
            reject_unknown(body, &["after", "limit"])?;
            let after = text(body, "after", "")?;
            let limit = body
                .get("limit")
                .map(|v| {
                    v.as_u64()
                        .ok_or_else(|| bad("invalid SSH issuer page limit"))
                })
                .transpose()?
                .unwrap_or(0);
            if limit > MAX_ISSUERS as u64 {
                return Err(bad("SSH issuer page exceeds bound"));
            }
            let count = if limit == 0 {
                MAX_ISSUERS
            } else {
                limit as usize
            };
            let entries: Vec<_> = self
                .issuers
                .iter()
                .filter(|(id, _)| id.as_str() > after)
                .take(count)
                .collect();
            let keys: Vec<_> = entries.iter().map(|(id, _)| (*id).clone()).collect();
            let info:BTreeMap<_,_>=entries.into_iter().map(|(id,v)|(id.clone(),json!({"issuer_name":v.name,"is_default":self.default_issuer.as_ref()==Some(id),"public_key":v.public}))).collect();
            return Ok(Some(ok(json!({"keys":keys,"key_info":info}), false)));
        }
        if path == "config/issuers" {
            return match method {
                "GET" => {
                    reject_unknown(body, &[])?;
                    Ok(Some(ok(
                        json!({"default":self.default_issuer.clone().unwrap_or_default()}),
                        false,
                    )))
                }
                "POST" | "PUT" => {
                    reject_unknown(body, &["default"])?;
                    let id = self.resolve(text(body, "default", "")?)?;
                    let changed = self.default_issuer.as_ref() != Some(&id);
                    self.default_issuer = Some(id.clone());
                    Ok(Some(ok(json!({"default":id}), changed)))
                }
                _ => Err(unsupported()),
            };
        }
        if let Some(reference) = path.strip_prefix("issuer/") {
            if reference.is_empty() || reference.contains('/') {
                return Err(not_found());
            }
            let id = match self.resolve(reference) {
                Ok(id) => id,
                Err(_) if method == "DELETE" && !reference.is_empty() && reference != "default" => {
                    reject_unknown(body, &[])?;
                    return Ok(Some(empty(false)));
                }
                Err(error) => return Err(error),
            };
            return match method {
                "GET" => {
                    reject_unknown(body, &[])?;
                    Ok(Some(ok(
                        self.issuers.get(&id).ok_or_else(not_found)?.descriptor(),
                        false,
                    )))
                }
                "DELETE" => {
                    reject_unknown(body, &[])?;
                    let issuer = self.issuers.get(&id).ok_or_else(not_found)?;
                    let mut warnings = Vec::new();
                    let mut referenced = |reference: &str| {
                        let count = self
                            .roles
                            .values()
                            .filter(|role| role.issuer_ref() == reference)
                            .count();
                        if count > 0 {
                            warnings.push(format!("{count} roles reference '{reference}'"));
                        }
                    };
                    if !issuer.name.is_empty() {
                        referenced(&issuer.name);
                    }
                    referenced(&id);
                    let was_default = self.default_issuer.as_ref() == Some(&id);
                    if was_default {
                        warnings.push(format!("Deleted issuer {id} (via issuer_ref {reference}); this was configured as the default issuer. Operations without an explicit issuer will not work until a new default is configured."));
                        let count = self
                            .roles
                            .values()
                            .filter(|role| role.issuer_ref() == "default")
                            .count();
                        if count > 0 {
                            warnings.push(format!("{count} roles reference 'default'"));
                        }
                    }
                    self.issuers.remove(&id);
                    if was_default {
                        self.default_issuer = None;
                    }
                    let mut response = empty(true);
                    if !warnings.is_empty() {
                        response.status = 200;
                        response.body = json!({"warnings":warnings});
                    }
                    Ok(Some(response))
                }
                "POST" | "PUT" => {
                    reject_unknown(body, &["issuer_name"])?;
                    let name = text(body, "issuer_name", "")?;
                    if !name.is_empty()
                        && (!named(name)
                            || self.issuers.values().any(|v| v.id != id && v.name == name))
                    {
                        return Err(bad("invalid or duplicate SSH issuer name"));
                    }
                    let issuer = self.issuers.get_mut(&id).ok_or_else(not_found)?;
                    let changed = issuer.name != name;
                    issuer.name = name.into();
                    Ok(Some(ok(issuer.descriptor(), changed)))
                }
                _ => Err(unsupported()),
            };
        }
        Ok(None)
    }
    pub(super) fn sign(
        &mut self,
        body: &Value,
        context: &SigningContext<'_>,
        issue: bool,
    ) -> Result<EngineResponse> {
        crypto_key::deadline()?;
        let role = self.roles.get(context.role_name).ok_or_else(not_found)?;
        let issued_key = if issue {
            Some(crypto_key::generate(
                text(body, "key_type", "rsa")?,
                bits(body)?,
            )?)
        } else {
            None
        };
        let public = match &issued_key {
            Some(key) => key.public()?,
            None => {
                let text = string(body, "public_key")?;
                if text.is_empty() || text.len() > 16384 {
                    return Err(bad("invalid SSH public key"));
                }
                signing_public_key(text)?
            }
        };
        let policy = role.signing_policy(body, &public, context)?;
        let id = self.resolve(&policy.issuer_ref)?;
        let issuer = self.issuers.get(&id).ok_or_else(not_found)?;
        let signer = crypto_key::CaSigner::new(&issuer.private, &policy.algorithm_signer)?;
        let serial = u64::from_be_bytes(
            crate::crypto::random::<8>()
                .map_err(|_| error(503, "secure randomness unavailable"))?,
        );
        let nonce = crate::crypto::random::<32>()
            .map_err(|_| error(503, "secure randomness unavailable"))?;
        let mut builder = Builder::new(
            nonce.to_vec(),
            public.key_data().clone(),
            policy.valid_after,
            policy.valid_before,
        )
        .map_err(|_| bad("invalid SSH certificate validity"))?;
        builder
            .serial(serial)
            .map_err(|_| bad("invalid SSH certificate serial"))?;
        builder
            .cert_type(policy.kind)
            .map_err(|_| bad("invalid SSH certificate type"))?;
        builder
            .key_id(policy.key_id)
            .map_err(|_| bad("invalid SSH certificate key ID"))?;
        if policy.principals.is_empty() {
            builder
                .all_principals_valid()
                .map_err(|_| bad("invalid empty SSH principal policy"))?;
        } else {
            for principal in policy.principals {
                builder
                    .valid_principal(principal)
                    .map_err(|_| bad("invalid SSH principal"))?;
            }
        }
        for (k, v) in policy.critical_options {
            builder
                .critical_option(k, v)
                .map_err(|_| bad("invalid SSH critical option"))?;
        }
        for (k, v) in policy.extensions {
            builder
                .extension(k, v)
                .map_err(|_| bad("invalid SSH extension"))?;
        }
        let cert = builder
            .sign(&signer)
            .map_err(|_| error(503, "SSH certificate signing failed"))?;
        let mut signed = cert
            .to_openssh()
            .map_err(|_| error(503, "SSH certificate encoding failed"))?;
        signed.push('\n');
        crypto_key::deadline()?;
        self.signatures = self
            .signatures
            .checked_add(1)
            .ok_or_else(|| error(507, "SSH signature publication capacity exhausted"))?;
        let mut data =
            json!({"serial_number":format!("{serial:x}"),"signed_key":signed,"issuer_id":id});
        if let Some(key) = issued_key {
            data["private_key"] = json!(key.issued_pem()?.as_str());
            data["private_key_type"] = json!(text(body, "key_type", "rsa")?);
        }
        Ok(ok(data, true))
    }
    pub(super) fn needs_authenticated_request(&self, name: &str) -> bool {
        self.roles
            .get(name)
            .is_some_and(CaRole::needs_authenticated_request)
    }
    pub(super) fn authenticated_template_sources(
        &self,
        name: &str,
        body: &Value,
    ) -> Result<Vec<String>> {
        self.roles
            .get(name)
            .ok_or_else(not_found)?
            .authenticated_template_sources(body)
    }

    pub(super) fn sign_authenticated(
        &mut self,
        body: &Value,
        context: &SigningContext<'_>,
        issue: bool,
        identity: &super::ssh_templates::RequestIdentity,
    ) -> Result<EngineResponse> {
        crypto_key::deadline()?;
        let role = self.roles.get(context.role_name).ok_or_else(not_found)?;
        let issued_key = if issue {
            Some(crypto_key::generate(
                text(body, "key_type", "rsa")?,
                bits(body)?,
            )?)
        } else {
            None
        };
        let public = match &issued_key {
            Some(key) => key.public()?,
            None => {
                let text = string(body, "public_key")?;
                if text.is_empty() || text.len() > 16384 {
                    return Err(bad("invalid SSH public key"));
                }
                signing_public_key(text)?
            }
        };
        let (policy, template_warning) =
            role.signing_policy_authenticated(body, &public, context, identity)?;
        let id = self.resolve(&policy.issuer_ref)?;
        let issuer = self.issuers.get(&id).ok_or_else(not_found)?;
        let serial = u64::from_be_bytes(
            crate::crypto::random::<8>()
                .map_err(|_| error(503, "secure randomness unavailable"))?,
        );
        let nonce = crate::crypto::random::<32>()
            .map_err(|_| error(503, "secure randomness unavailable"))?;
        let mut signed = if policy.algorithm_signer == "ssh-rsa" {
            super::ssh_ca_legacy::sign(&issuer.private, &public, &policy, serial, &nonce)?
        } else {
            let signer = crypto_key::CaSigner::new(&issuer.private, &policy.algorithm_signer)?;
            let mut builder = Builder::new(
                nonce.to_vec(),
                public.key_data().clone(),
                policy.valid_after,
                policy.valid_before,
            )
            .map_err(|_| bad("invalid SSH certificate validity"))?;
            builder
                .serial(serial)
                .map_err(|_| bad("invalid SSH certificate serial"))?;
            builder
                .cert_type(policy.kind)
                .map_err(|_| bad("invalid SSH certificate type"))?;
            builder
                .key_id(policy.key_id)
                .map_err(|_| bad("invalid SSH certificate key ID"))?;
            if policy.principals.is_empty() {
                builder
                    .all_principals_valid()
                    .map_err(|_| bad("invalid empty SSH principal policy"))?;
            } else {
                for principal in policy.principals {
                    builder
                        .valid_principal(principal)
                        .map_err(|_| bad("invalid SSH principal"))?;
                }
            }
            for (k, v) in policy.critical_options {
                builder
                    .critical_option(k, v)
                    .map_err(|_| bad("invalid SSH critical option"))?;
            }
            for (k, v) in policy.extensions {
                builder
                    .extension(k, v)
                    .map_err(|_| bad("invalid SSH extension"))?;
            }
            let cert = builder
                .sign(&signer)
                .map_err(|_| error(503, "SSH certificate signing failed"))?;
            cert.to_openssh()
                .map_err(|_| error(503, "SSH certificate encoding failed"))?
        };
        signed.push('\n');
        crypto_key::deadline()?;
        self.signatures = self
            .signatures
            .checked_add(1)
            .ok_or_else(|| error(507, "SSH signature publication capacity exhausted"))?;
        let mut data =
            json!({"serial_number":format!("{serial:x}"),"signed_key":signed,"issuer_id":id});
        if let Some(key) = issued_key {
            data["private_key"] = json!(key.issued_pem()?.as_str());
            data["private_key_type"] = json!(text(body, "key_type", "rsa")?);
        }
        let mut response = ok(data, true);
        if template_warning {
            response.body["warnings"] = json!([
                "default_extension templating enabled with at least one extension requiring identity templating. However, this request lacked identity entity information, causing one or more extensions to be skipped from the generated certificate."
            ]);
        }
        Ok(response)
    }
}

/// Only the real, validated SSH mount selects this response-only public transport.
pub(crate) struct SshPublicKeyTransport {
    logical: Value,
}
impl SshPublicKeyTransport {
    pub(crate) fn logical_response(&self) -> &Value {
        &self.logical
    }
}
impl Drop for SshPublicKeyTransport {
    fn drop(&mut self) {
        wipe_json(&mut self.logical);
    }
}
impl EngineState {
    pub(crate) fn is_public_ssh_key_read(&self, namespace: &str, method: &str, path: &str) -> bool {
        if method != "GET" {
            return false;
        }
        let Some((mount, value)) = self.namespaces.get(namespace).and_then(|ns| {
            ns.mounts
                .iter()
                .filter(|(mount, _)| path.starts_with(mount.as_str()))
                .max_by_key(|(mount, _)| mount.len())
        }) else {
            return false;
        };
        if !matches!(&value.backend, Backend::Ssh(_)) {
            return false;
        }
        let Some(relative) = path.strip_prefix(mount) else {
            return false;
        };
        relative == "public_key"
            || relative
                .strip_prefix("issuer/")
                .and_then(|tail| tail.strip_suffix("/public_key"))
                .is_some_and(|reference| !reference.is_empty() && !reference.contains('/'))
    }
    pub(crate) fn capture_public_ssh_key(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<SshPublicKeyTransport>> {
        if !self.is_public_ssh_key_read(namespace, method, path) {
            return Ok(None);
        }
        reject_unknown(body, &[])?;
        let ns = self.namespaces.get(namespace).ok_or_else(not_found)?;
        let (mount, value) = ns
            .mounts
            .iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .max_by_key(|(mount, _)| mount.len())
            .ok_or_else(not_found)?;
        let Backend::Ssh(engine) = &value.backend else {
            return Err(not_found());
        };
        let relative = path.strip_prefix(mount).ok_or_else(not_found)?;
        let reference = if relative == "public_key" {
            "default"
        } else {
            relative
                .strip_prefix("issuer/")
                .and_then(|tail| tail.strip_suffix("/public_key"))
                .ok_or_else(not_found)?
        };
        let public = engine.public_ca_key(reference)?;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        Ok(Some(SshPublicKeyTransport {
            logical: json!({"data":{
                "http_content_type":"text/plain","http_status_code":200,
                "http_raw_body":STANDARD.encode(public.as_bytes())
            }}),
        }))
    }
}

#[cfg(test)]
#[path = "ssh_ca_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ssh_ca_known_keys_tests.rs"]
mod known_key_tests;
