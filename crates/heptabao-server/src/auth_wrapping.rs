//! Opaque, single-use response wrapping. This is part of the authoritative
//! AuthState transaction, not an in-memory side store or a second secret server.
use super::*;

/// Private, response-only origin. Local construction occurs only after an
/// actual wrapper was consumed, including the admitted affine final-use view.
/// Neither user JSON, a header, an SDK response nor the URL constructs it.
#[path = "auth_wrapped_reply110.rs"]
mod raw_reply;
pub(crate) use raw_reply::{
    IngressReplyContext, IngressReplyScope, LexicalJson, StoredWrappedReply, current_ingress,
    encode_http_envelope, logical_envelope,
};
pub(super) use raw_reply::{RawReplyReaderFloor, RawReplyTokenCustody};

enum WorkflowOutputFailure {
    Local(Box<crate::workflow_runtime::FailedOutput>),
    Completed { output_digest: [u8;32], logical_digest: [u8;32] },
}
impl WorkflowOutputFailure {
    fn digests(&self) -> ([u8;32],[u8;32]) {
        match self {
            Self::Local(value) => value.digests(),
            Self::Completed {output_digest,logical_digest} => (*output_digest,*logical_digest),
        }
    }
    fn matches(&self, logical: &Value) -> bool {
        match self {
            Self::Local(value) => value.matches(logical),
            Self::Completed {logical_digest,..} =>
                logical == &crate::workflow_runtime::FailedOutput::logical()
                && serde_json::to_vec(logical).is_ok_and(|bytes| crate::crypto::digest(&bytes)==*logical_digest),
        }
    }
}
pub(crate) struct UnwrappedJson {
    // Keep the secret-bearing owner affine without inflating every Response result.
    // Box destruction still runs StoredWrappedReply's zeroizing destructor.
    stored_reply: Option<Box<StoredWrappedReply>>,
    // Private response-only bytes bound by the final actual unwrap ingress.
    selected_json_http: Option<Zeroizing<Vec<u8>>>,
    // Prepared from the actual consumed owner before mandatory response audit.
    selected_response: Option<Box<raw_reply::SelectedResponseProjection>>,
    workflow_output_failure: Option<WorkflowOutputFailure>,
    workflow_failure_audited: bool,
}
impl UnwrappedJson {
    pub(crate) fn from_workflow_output_failure(value: crate::workflow_runtime::FailedOutput) -> Self {
        Self {
            stored_reply: None, selected_json_http: None, selected_response: None,
            workflow_output_failure: Some(WorkflowOutputFailure::Local(Box::new(value))),
            workflow_failure_audited: false,
        }
    }
    pub(crate) fn workflow_value(&self) -> Option<&crate::workflow_runtime::Value> {
        match &self.workflow_output_failure {
            Some(WorkflowOutputFailure::Local(value)) => Some(value.value()),
            _ => None,
        }
    }
    pub(crate) fn framing_wire(&self,logical:&Value)
        -> Result<crate::ha_forward::UnwrapFramingWire,AuthError> {
        if let Some(value)=&self.workflow_output_failure {
            if self.stored_reply.is_some() || !value.matches(logical) {
                return Err(bad("workflow private output projection differs"));
            }
            let (output_digest,logical_digest)=value.digests();
            return Ok(crate::ha_forward::UnwrapFramingWire::WorkflowJsonFailure {output_digest,logical_digest});
        }
        if let Some(stored)=&self.stored_reply { stored.validate(logical)?; }
        Ok(crate::ha_forward::UnwrapFramingWire::StoredJson)
    }

    // The owning SSH mount, rather than caller JSON or a route string, is the
    // sole producer. Reuse the existing authenticated GeneralRawHttp wire kind.
    pub(crate) fn from_native_ssh_public_key(
        transport: &crate::engines::SshPublicKeyTransport,
        context: &IngressReplyContext,
        path: &str,
    ) -> Result<Self, AuthError> {
        let stored = StoredWrappedReply::capture(transport.logical_response(), context, path)?;
        if stored.raw_http_transport(transport.logical_response())? != Some((200, "text/plain")) {
            return Err(bad("SSH public key native projection rejected"));
        }
        Ok(Self {
            stored_reply: Some(Box::new(stored)),
            selected_json_http: None,
            selected_response: None,
            workflow_output_failure: None,
            workflow_failure_audited: false,
        })
    }
    pub(crate) fn from_completed_raw_forward(
        receipt: &crate::ha_forward_completion::CompletedForwardReceipt,
        response: &crate::ha_forward::ForwardResponse,
    ) -> Result<Self, String> {
        if std::time::Instant::now() >= receipt.deadline || !receipt.wire_response_matches(response)
        {
            return Err("HA stored reply completion does not match".into());
        }
        if let Some(stored) = &response.raw_wrapped_reply {
            stored
                .validate(&response.body)
                .map_err(|_| "HA stored reply projection rejected")?;
        }
        let workflow_output_failure = match response.unwrapped_json {
            Some(crate::ha_forward::UnwrapFramingWire::WorkflowJsonFailure {output_digest,logical_digest}) => {
                let value = WorkflowOutputFailure::Completed {output_digest,logical_digest};
                if response.status != 200 || response.raw_wrapped_reply.is_some() || !value.matches(&response.body) {
                    return Err("HA workflow output failure completion differs".into());
                }
                Some(value)
            }
            _ => None,
        };
        Ok(Self {
            stored_reply: response.raw_wrapped_reply.clone().map(Box::new),
            selected_json_http: None,
            selected_response: None,
            workflow_output_failure,
            workflow_failure_audited: false,
        })
    }
    pub(crate) fn has_native_http_projection(&self) -> bool {
        self.has_stored_reply() || self.workflow_output_failure.is_some()
    }
    pub(crate) fn has_stored_reply(&self) -> bool {
        self.stored_reply.is_some()
    }
    pub(crate) fn stored_reply(&self) -> Option<&StoredWrappedReply> {
        self.stored_reply.as_deref()
    }
    pub(crate) fn raw_error_header(
        &self,
        logical: &Value,
    ) -> Result<Option<&'static str>, AuthError> {
        self.stored_reply
            .as_ref()
            .map(|stored| stored.raw_error_header(logical))
            .transpose()
            .map(Option::flatten)
    }
    pub(crate) fn raw_http_transport<'a>(
        &'a self,
        logical: &Value,
    ) -> Result<Option<(u16, &'a str)>, AuthError> {
        if let Some(value)=&self.workflow_output_failure {
            if !value.matches(logical) { return Err(bad("workflow private output projection differs")); }
            return Ok(Some((200,"application/json")));
        }
        self.stored_reply
            .as_ref()
            .map(|stored| stored.raw_http_transport(logical))
            .transpose()
            .map(Option::flatten)
    }
    pub(crate) fn selected_response_audit_binding(
        &mut self,
        logical: &Value,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError> {
        if let Some(value)=&self.workflow_output_failure {
            if !value.matches(logical) || self.workflow_failure_audited {
                return Err(bad("workflow output mandatory audit projection differs"));
            }
            let binding = match value {
                WorkflowOutputFailure::Local(value) => value.audit_binding()
                    .map_err(|_|bad("workflow output audit binding exceeds bounds"))?,
                WorkflowOutputFailure::Completed {output_digest,logical_digest} =>
                    Zeroizing::new(serde_json::to_vec(&("workflow-output-json-failure",output_digest,logical_digest))
                        .map_err(|_|bad("workflow output audit binding unavailable"))?),
            };
            self.workflow_failure_audited=true;
            return Ok(Some(binding));
        }
        let Some(stored) = &self.stored_reply else {
            return Ok(None);
        };
        if self.selected_response.is_some() {
            return Err(bad(
                "selected response mandatory audit was already prepared",
            ));
        }
        let Some(prepared) = stored.selected_response_for_audit(logical)? else {
            return Ok(None);
        };
        let binding = prepared.audit_binding()?;
        self.selected_response = Some(Box::new(prepared));
        Ok(Some(binding))
    }
    pub(crate) fn bind_selected_http_ingress(
        &mut self,
        logical: &Value,
        actual_ingress: &[u8; 16],
    ) -> Result<(), AuthError> {
        if self.selected_json_http.is_some() {
            return Err(bad("selected JSON ingress was already bound"));
        }
        if let Some(value)=&self.workflow_output_failure {
            if !value.matches(logical) || !self.workflow_failure_audited {
                return Err(bad("workflow output lacks mandatory audited ingress"));
            }
            // Existing HTTP boundary supplies the actual ingress. The private
            // native producer owns zero bytes after failed JSON serialization.
            let _ = actual_ingress;
            self.selected_json_http=Some(Zeroizing::new(Vec::new()));
            return Ok(());
        }
        if let Some(stored) = &self.stored_reply {
            if stored.uses_selected_json_ingress() {
                let prepared = self.selected_response.as_deref().ok_or_else(|| {
                    bad("selected JSON lacks mandatory response audit projection")
                })?;
                self.selected_json_http =
                    stored.selected_json_for_ingress(logical, actual_ingress, prepared)?;
            }
        }
        Ok(())
    }
    pub(crate) fn raw_bytes<'a>(&'a self, logical: &Value) -> Result<Option<&'a [u8]>, AuthError> {
        if let Some(value)=&self.workflow_output_failure {
            if !value.matches(logical) || !self.workflow_failure_audited {
                return Err(bad("workflow output lacks mandatory audit"));
            }
            return self.selected_json_http.as_deref().map(Vec::as_slice).map(Some)
                .ok_or_else(||bad("workflow output lacks actual HTTP ingress"));
        }
        let Some(stored) = &self.stored_reply else {
            return Ok(None);
        };
        stored.validate(logical)?;
        if stored.uses_selected_json_ingress() {
            return self
                .selected_json_http
                .as_deref()
                .map(Vec::as_slice)
                .map(Some)
                .ok_or_else(|| bad("selected JSON lacks actual HTTP ingress projection"));
        }
        stored.bytes(logical).map(Some)
    }
}

const MAX_WRAPPED_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_LIVE_WRAPPERS: usize = 256;

pub(crate) fn validate_sdk_wrap_ttl(ttl: u64) -> Result<(), AuthError> {
    if ttl == 0 || ttl > MAX_TTL {
        return Err(bad("wrapping TTL exceeds supported bounds"));
    }
    Ok(())
}

/// Opaque wrapping credentials can release or discard only their own response.
/// Keep execution and capability introspection on the same exact-path contract.
pub(super) fn allows_token_operation(path: &str, capability: &str) -> bool {
    capability == "update" && matches!(path, "sys/wrapping/unwrap" | "auth/token/revoke-self")
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creation_stamp: Option<public_origin::CreationStamp>,
    #[serde(deserialize_with = "heptabao_domain::json::deserialize")]
    response: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stored_reply: Option<StoredWrappedReply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sdk_format: Option<sdk::advanced::Format>,
    creation_path: String,
    creation_ttl: u64,
    wrapped_accessor: Option<String>,
}
impl WrappedResponse {
    pub(super) fn has_sdk_origin(&self) -> bool { self.sdk_format.is_some() }
    pub(super) fn has_creation_stamp(&self) -> bool {
        self.creation_stamp.is_some()
    }
    pub(super) fn validate_creation_stamp(&self, created_at: u64) -> Result<(), AuthError> {
        if let Some(stamp) = &self.creation_stamp {
            stamp.validate_since(created_at)?;
        }
        Ok(())
    }
    fn creation_time(&self, created_at: u64) -> Result<String, AuthError> {
        self.creation_stamp.as_ref().map_or_else(
            || Ok(crate::engines::timestamp(created_at)),
            public_origin::CreationStamp::render,
        )
    }
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
                if let Some(custody) = &mut token.raw_wrapped_reply_custody {
                    custody.consume();
                }
            }
        }
        true
    }

    pub(crate) fn validate_wrapping_state(&self) -> Result<(), AuthError> {
        self.validate_raw_wrapped_reply_state()?;
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
        // Historical/direct Value-only producer cannot claim original HTTP bytes.
        self.wrap_response_with_stored(namespace, path, ttl, response, now, None)
    }

    /// Closed JSON producer call sites select this after actual logical dispatch.
    /// Raw PKI transports use their sealed actual producer proof below.
    pub(crate) fn wrap_logical_response(
        &mut self,
        namespace: &str,
        path: &str,
        ttl: u64,
        response: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let stored_reply = current_ingress()
            .map(|context| StoredWrappedReply::capture(response, &context, path))
            .transpose()?;
        self.wrap_response_with_stored(namespace, path, ttl, response, now, stored_reply)
    }

    pub(crate) fn wrap_sdk_response(
        &mut self, namespace: &str, path: &str, ttl: u64, response: &Value, now: u64,
        context: Option<&IngressReplyContext>,
    ) -> Result<AuthResponse, AuthError> {
        let stored = context.map(|context| StoredWrappedReply::capture(response, context, path))
            .transpose()?;
        let response = self.wrap_response_with_stored(namespace, path, ttl, response, now, stored)?;
        let raw = response.body["wrap_info"]["token"].as_str()
            .ok_or_else(|| err(503, "SDK wrapper producer missing native token"))?;
        let token = self.tokens.get_mut(&hash(raw)).ok_or_else(|| err(503, "SDK wrapper producer missing native owner"))?;
        token.wrapping.as_mut().ok_or_else(|| err(503, "SDK wrapper producer missing response owner"))?
            .sdk_format = Some(sdk::advanced::Format::V1);
        self.mark_sdk_advanced_state();
        Ok(response)
    }
    pub(crate) fn sdk_wrapped_auth_token<'a>(
        &'a self, raw: &str, namespace: &str, path: &str, time: AuthorityTime,
    ) -> Result<Option<&'a str>, AuthError> {
        if !self.has_sdk_advanced_state() { return Err(denied()); }
        let token = self.active_token_observed(&hash(raw), time, false)?;
        let wrapped = token.wrapping.as_ref().ok_or_else(denied)?;
        if token.namespace != namespace || wrapped.creation_path != path || !wrapped.has_sdk_origin() {
            return Err(denied());
        }
        if let Some(stored) = &wrapped.stored_reply {
            stored.validate_owner(&wrapped.response, path)?;
        }
        Ok(wrapped.response.get("auth").and_then(|auth| auth.get("client_token"))
            .and_then(Value::as_str))
    }

    /// A sealed actual PKI producer supplies the HTTP special logical fields.
    /// The private ingress carrier captures the dedicated raw HTTP variant once;
    /// historical callers keep their original Value-only representation.
    pub(crate) fn wrap_pki_raw_response(
        &mut self,
        namespace: &str,
        path: &str,
        ttl: u64,
        historical_response: &Value,
        transport: &crate::engines::PkiWrappedTransport,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let Some(context) = current_ingress() else {
            return self.wrap_response(namespace, path, ttl, historical_response, now);
        };
        let logical = transport.logical_response();
        let stored = StoredWrappedReply::capture_pki(transport, &context, path)?;
        self.wrap_response_with_stored(namespace, path, ttl, logical, now, Some(stored))
    }

    fn wrap_response_with_stored(
        &mut self,
        namespace: &str,
        path: &str,
        ttl: u64,
        response: &Value,
        now: u64,
        stored_reply: Option<StoredWrappedReply>,
    ) -> Result<AuthResponse, AuthError> {
        if let Some(stored) = &stored_reply {
            stored.validate_owner(response, path)?;
        }
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
        let creation_stamp = public_origin::CreationStamp::capture(now)?;
        let wrapped = WrappedResponse {
            creation_stamp: creation_stamp.clone(),
            response: response.clone(),
            stored_reply,
            sdk_format: None,
            creation_path: path.into(),
            creation_ttl: ttl,
            wrapped_accessor: wrapped_accessor.clone(),
        };
        let mut token = Token {
            token_api_precision: None,
            public_origin: None,
            issue_stamp: creation_stamp,
            token_api_lease_ttl: None,
            token_role: None,
            bound_cidrs: Vec::new(),
            wrapping: Some(wrapped),
            raw_wrapped_reply_custody: None,
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
            "creation_time":token.wrapping.as_ref().ok_or_else(|| err(503,"wrapping owner missing"))?.creation_time(now)?,"creation_path":path});
        if let Some(accessor) = wrapped_accessor {
            info["wrapped_accessor"] = json!(accessor);
        }
        let result = AuthResponse {
            unwrapped_json: None,
            approle_secret_consumption: None,
            pending_batch: None,
            pending_service: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"request_id":"","lease_id":"","lease_duration":0,"renewable":false,
                "data":null,"auth":null,"warnings":null,"wrap_info":info}),
        };
        if token
            .wrapping
            .as_ref()
            .is_some_and(|w| w.stored_reply.is_some())
        {
            token.raw_wrapped_reply_custody = Some(RawReplyTokenCustody::live(&token)?);
        }
        self.wrapping_clock = now;
        if token
            .wrapping
            .as_ref()
            .is_some_and(|w| w.stored_reply.is_some())
        {
            self.raw_wrapped_reply_floor.observe(
                token
                    .wrapping
                    .as_ref()
                    .and_then(|wrapped| wrapped.stored_reply.as_ref())
                    .is_some_and(StoredWrappedReply::is_pki_raw_http),
                token
                    .wrapping
                    .as_ref()
                    .and_then(|wrapped| wrapped.stored_reply.as_ref())
                    .is_some_and(StoredWrappedReply::is_general_reply),
            );
        }
        self.store_token(id, token);
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
        self.lookup_wrapping_request_observed(
            header_token,
            namespace,
            method,
            body,
            AuthorityTime::Coarse(now),
        )
    }
    pub(crate) fn lookup_wrapping_request_observed(
        &self,
        header_token: &str,
        namespace: &str,
        method: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<AuthResponse, AuthError> {
        let now = time.seconds();
        validate_namespace(namespace)?;
        if !matches!(method, "GET" | "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["token"])?;
        let raw = match body.get("token") {
            Some(Value::String(token)) if !token.is_empty() => token.as_str(),
            None => header_token,
            _ => return Err(bad("wrapping token must be a nonempty string")),
        };
        if let Some(owner) = self.control_group_target_observed(raw, namespace, time)? {
            return Ok(response(
                json!({"creation_path":owner.path, "creation_time":owner.creation_time,
                "creation_ttl":owner.wire_ttl()}),
                false,
            ));
        }
        let token = self.wrapping_target(raw, namespace, now)?;
        let wrapped = token
            .wrapping
            .as_ref()
            .ok_or_else(|| bad("wrapping response unavailable"))?;
        Ok(response(
            json!({"creation_path":wrapped.creation_path,
            "creation_time":wrapped.creation_time(token.created_at)?,"creation_ttl":wrapped.creation_ttl}),
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
        if let Some(custody) = &mut token.raw_wrapped_reply_custody {
            custody.consume();
        }
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
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        let actor = self.permission(principal, namespace, path, "update", now)?;
        // Wrappers keep their existing whole-second owner. Only the actor's
        // original clock refreshes the time used to resolve a body target.
        let now = self
            .principal_token_api_time(actor, AuthorityTime::Coarse(now))?
            .seconds();
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
            return self.wrap_response_with_stored(
                namespace,
                &wrapped.creation_path,
                wrapped.creation_ttl,
                &wrapped.response,
                now,
                wrapped.stored_reply.clone(),
            );
        }
        Ok(AuthResponse {
            unwrapped_json: Some(UnwrappedJson {
                selected_json_http: None,
                selected_response: None,
            workflow_output_failure: None,
            workflow_failure_audited: false,
                stored_reply: wrapped.stored_reply.clone().map(Box::new),
            }),
            approle_secret_consumption: None,
            pending_batch: None,
            pending_service: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: wrapped.response.clone(),
        })
    }
}

#[cfg(test)]
#[path = "auth_wrapping_270_tests.rs"]
mod openbao270_tests;

impl WrappedResponse {
    pub(super) fn has_lossless_json_state(&self) -> bool {
        heptabao_domain::json::requires_lossless_format(&self.response)
    }
}
