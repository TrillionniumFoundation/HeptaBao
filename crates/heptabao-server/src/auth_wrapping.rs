//! Opaque, single-use response wrapping. This is part of the authoritative
//! AuthState transaction, not an in-memory side store or a second secret server.
use super::*;

const MAX_WRAPPED_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_LIVE_WRAPPERS: usize = 256;

fn bounded_wrapped_response(response: &Value) -> bool {
    // Both issuance and durable admission count encoded bytes without a
    // second plaintext JSON buffer containing bearer tokens or secrets.
    struct BoundedCount(usize);
    impl std::io::Write for BoundedCount {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_WRAPPED_RESPONSE_BYTES)
                .ok_or_else(|| std::io::Error::other("wrapped response exceeds bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    response.is_object() && serde_json::to_writer(&mut BoundedCount(0), response).is_ok()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WrappedResponse {
    response: Value,
    creation_path: String,
    creation_ttl: u64,
    wrapped_accessor: Option<String>,
}
impl Drop for WrappedResponse {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.response);
    }
}

impl AuthState {
    pub(crate) fn has_live_wrappers(&self) -> bool {
        self.tokens.values().any(|token| token.wrapping.is_some())
    }

    pub(crate) fn has_wrapping_state(&self) -> bool {
        self.wrapping_clock != 0 || self.tokens.values().any(|token| token.wrapping.is_some())
    }

    pub(crate) fn is_wrapping_token(&self, raw: &str) -> bool {
        raw.len() <= 256
            && self
                .tokens
                .get(&hash(raw))
                .is_some_and(|token| token.wrapping.is_some())
    }

    /// Called only with service-owned time, after request audit and HA ReadIndex.
    /// Persist the resulting state before authentication can reject or consume.
    pub(crate) fn advance_wrapping_clock(&mut self, now: u64) -> bool {
        if !self.has_wrapping_state() || now <= self.wrapping_clock {
            return false;
        }
        self.wrapping_clock = now;
        for token in self.tokens.values_mut() {
            if token.wrapping.is_some() && token.expires_at.is_some_and(|expiry| now >= expiry) {
                token.wrapping = None;
                token.uses_remaining = Some(0);
            }
        }
        true
    }

    pub(crate) fn validate_wrapping_state(&self) -> Result<(), AuthError> {
        let mut count = 0;
        for token in self.tokens.values() {
            let Some(wrapped) = token.wrapping.as_ref() else {
                continue;
            };
            count += 1;
            if token.root
                || token.parent.is_some()
                || token.entity_id.is_some()
                || token.renewable
                || token.period != 0
                || token.uses_remaining != Some(1)
                || token.policies != BTreeSet::from(["response-wrapping".into()])
                || wrapped.creation_ttl == 0
                || wrapped.creation_ttl > MAX_TTL
                || token.created_at > self.wrapping_clock
                || token.created_at.checked_add(wrapped.creation_ttl) != token.expires_at
                || token.expires_at != token.max_expires_at
                || !bounded_wrapped_response(&wrapped.response)
            {
                return Err(bad("invalid authoritative wrapping state"));
            }
            validate_namespace(&token.namespace)?;
            validate_path(&wrapped.creation_path, false)?;
        }
        if count > MAX_LIVE_WRAPPERS {
            return Err(bad("wrapping state exceeds capacity"));
        }
        Ok(())
    }

    pub(crate) fn wrap_response(
        &mut self,
        namespace: &str,
        path: &str,
        ttl: u64,
        response: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        if ttl == 0 || ttl > MAX_TTL {
            return Err(bad("wrapping TTL exceeds supported bounds"));
        }
        let now = now.max(self.wrapping_clock);
        let expiry = checked_expiry(now, ttl)?;
        if !bounded_wrapped_response(response) {
            return Err(err(413, "wrapped response exceeds supported bounds"));
        }
        if self
            .tokens
            .values()
            .filter(|t| t.wrapping.is_some())
            .count()
            >= MAX_LIVE_WRAPPERS
        {
            return Err(err(503, "wrapping capacity exhausted"));
        }
        let raw = Zeroizing::new(random_id("hvs.")?);
        let id = hash(&raw);
        if self.tokens.contains_key(&id) {
            return Err(err(503, "wrapping identity collision"));
        }
        let accessor = random_id("a.")?;
        let wrapped_accessor = response
            .get("auth")
            .and_then(|a| a.get("accessor"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let wrapped = WrappedResponse {
            response: response.clone(),
            creation_path: path.into(),
            creation_ttl: ttl,
            wrapped_accessor: wrapped_accessor.clone(),
        };
        let token = Token {
            token_api_lease_ttl: None,
            bound_cidrs: Vec::new(),
            wrapping: Some(wrapped),
            entity_id: None,
            cubbyhole: cubbyhole::TokenCubbyhole::default(),
            accessor: accessor.clone(),
            namespace: namespace.into(),
            policies: BTreeSet::from(["response-wrapping".into()]),
            root: false,
            parent: None,
            created_at: now,
            expires_at: Some(expiry),
            max_expires_at: Some(expiry),
            period: 0,
            renewable: false,
            uses_remaining: Some(1),
            display_name: "response-wrapping".into(),
            auth_mount: None,
            auth_origin_known: true,
            auth_cert_role: None,
            auth_cert_sha256: None,
            auth_provenance: None,
        };
        let mut info = json!({"token":raw.as_str(),"accessor":accessor,"ttl":ttl,
            "creation_time":crate::engines::timestamp(now),"creation_path":path});
        if let Some(accessor) = wrapped_accessor {
            info["wrapped_accessor"] = json!(accessor);
        }
        let result = AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"request_id":"","lease_id":"","lease_duration":0,"renewable":false,
                "data":null,"auth":null,"warnings":null,"wrap_info":info}),
        };
        self.wrapping_clock = now;
        self.tokens.insert(id, token);
        Ok(result)
    }

    fn wrapping_target(&self, raw: &str, namespace: &str, now: u64) -> Result<&Token, AuthError> {
        let invalid = || bad("wrapping token is not valid or does not exist");
        if raw.is_empty() || raw.len() > 256 || !raw.starts_with("hvs.") {
            return Err(invalid());
        }
        let token = self
            .active_token(&hash(raw), now.max(self.wrapping_clock), true)
            .map_err(|_| invalid())?;
        if token.namespace != namespace || token.wrapping.is_none() {
            return Err(invalid());
        }
        Ok(token)
    }

    pub(crate) fn lookup_wrapping_request(
        &self,
        header_token: &str,
        namespace: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        validate_namespace(namespace)?;
        if !matches!(method, "GET" | "POST") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["token"])?;
        let raw = match body.get("token") {
            Some(Value::String(token)) if !token.is_empty() => token.as_str(),
            None => header_token,
            _ => return Err(bad("wrapping token must be a nonempty string")),
        };
        let token = self.wrapping_target(raw, namespace, now)?;
        let wrapped = token
            .wrapping
            .as_ref()
            .ok_or_else(|| bad("wrapping response unavailable"))?;
        Ok(response(
            json!({"creation_path":wrapped.creation_path,
            "creation_time":crate::engines::timestamp(token.created_at),"creation_ttl":wrapped.creation_ttl}),
            false,
        ))
    }

    fn take_wrapping_target(
        &mut self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<WrappedResponse, AuthError> {
        self.wrapping_target(raw, namespace, now)?;
        let token = self
            .tokens
            .get_mut(&hash(raw))
            .ok_or_else(|| bad("wrapping response unavailable"))?;
        let wrapped = token
            .wrapping
            .take()
            .ok_or_else(|| bad("wrapping response unavailable"))?;
        token.uses_remaining = Some(0);
        Ok(wrapped)
    }

    pub(crate) fn wrapping_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        if !matches!(
            path,
            "sys/wrapping/wrap" | "sys/wrapping/unwrap" | "sys/wrapping/rewrap"
        ) {
            return Err(err(404, "unsupported wrapping path"));
        }
        if method != "POST" {
            return Err(err(405, "method not allowed"));
        }
        let actor = self.permission(principal, namespace, path, "update", now)?;
        if path == "sys/wrapping/wrap" {
            if !body.is_object() {
                return Err(bad("wrapping payload must be a JSON object"));
            }
            // The dispatcher wraps this result inside the same domain transaction.
            return Ok(response(body.clone(), false));
        }
        reject_unknown(body, &["token"])?;
        let wrapped = if let Some(wrapped) = actor
            .service_token()
            .and_then(|token| token.wrapping.as_ref())
        {
            // A wrapping token may only unwrap itself, never consume a second token.
            if body.get("token").is_some() {
                return Err(bad("wrapping token cannot also be supplied in the body"));
            }
            if path != "sys/wrapping/unwrap" {
                return Err(denied());
            }
            // Already durably consumed at Service admission; only the affine
            // Principal retains this final-use view. No secret-bearing retry.
            wrapped.clone()
        } else {
            let raw = string_field(body, "token")?;
            self.take_wrapping_target(raw, namespace, now)?
        };
        if path == "sys/wrapping/rewrap" {
            // Same payload, origin and original TTL; no plaintext in the result.
            return self.wrap_response(
                namespace,
                &wrapped.creation_path,
                wrapped.creation_ttl,
                &wrapped.response,
                now,
            );
        }
        Ok(AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: wrapped.response.clone(),
        })
    }
}
