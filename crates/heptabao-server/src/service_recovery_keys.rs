//! Authenticated root recovery rotation and derived public-index reconciliation.
//! The encrypted Auth owner commits the authority switch; seal.json never does.
use super::*;
use crate::auth::{RecoveryAttempt, RecoveryCommitIntent, RecoveryCredential, RecoveryDelivery};

pub(super) struct AdmittedRecoverySeal(pub(super) Option<SealMetadata>);
// No public caller can construct legacy authority or activate it through request data.
enum RecoveryAuthorization<'a> {
    Sudo(&'a Principal),
    LegacyExistingKeys,
}
pub(super) fn legacy_recovery_path(path: &str) -> Option<&'static str> {
    match path {
        "sys/rekey-recovery-key/init" => Some("sys/rotate/recovery/init"),
        "sys/rekey-recovery-key/update" => Some("sys/rotate/recovery/update"),
        "sys/rekey-recovery-key/verify" => Some("sys/rotate/recovery/verify"),
        "sys/rekey-recovery-key/backup" => Some("sys/rotate/recovery/backup"),
        _ => None,
    }
}

fn live(deadline: Option<std::time::Instant>) -> Result<(), Response> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        Err(Response::error(
            503,
            "recovery operation deadline expired; inspect durable state before retry",
        ))
    } else {
        Ok(())
    }
}
fn required_recovery_counts(body: &Value) -> Result<(u8, u8), Response> {
    if body.get("secret_shares").is_none() || body.get("secret_threshold").is_none() {
        return Err(Response::error(
            400,
            "secret_shares and secret_threshold are required",
        ));
    }
    let shares = bounded_u8_field(body, "secret_shares", 0)
        .map_err(|message| Response::error(400, message))?;
    let threshold = bounded_u8_field(body, "secret_threshold", 0)
        .map_err(|message| Response::error(400, message))?;
    if shares == 0 || threshold == 0 || threshold > shares {
        return Err(Response::error(400, "invalid recovery rotation counts"));
    }
    Ok((shares, threshold))
}
fn decode_intent_seal(bytes: &[u8]) -> Result<SealMetadata, Response> {
    let seal: SealMetadata = serde_json::from_slice(bytes)
        .map_err(|_| Response::error(503, "invalid encrypted recovery seal intent"))?;
    seal.validate()
        .map_err(|_| Response::error(503, "invalid recovery seal intent metadata"))?;
    let canonical = owner_store::serialize_owner(&seal).map_err(state_serialization_error)?;
    if canonical.as_slice() != bytes {
        return Err(Response::error(503, "noncanonical recovery seal intent"));
    }
    Ok(seal)
}
fn matches_credential(
    seal: &SealMetadata,
    credential: Option<&RecoveryCredential>,
) -> Result<bool, Response> {
    if !seal.is_wrapper() {
        return Ok(credential.is_none());
    }
    let public = openbao_wrapper::barrier::recovery_public(seal)
        .map_err(|_| Response::error(503, "invalid Wrapper recovery index"))?;
    Ok(public == credential.map(RecoveryCredential::public))
}
// Pure structural admission used before disk repair; this never publishes state.
fn recovery_intent_target(
    state: &State,
    current: &SealMetadata,
) -> Result<Option<SealMetadata>, Response> {
    current
        .validate()
        .map_err(|_| Response::error(503, "invalid public recovery index"))?;
    state
        .auth
        .validate_recovery_credential(&state.cluster_id)
        .map_err(|_| Response::error(503, "invalid encrypted recovery authority"))?;
    let Some(intent) = state.auth.recovery_intent.as_ref() else {
        if !matches_credential(current, state.auth.recovery_credential.as_ref())? {
            return Err(Response::error(
                503,
                "public and protected recovery configuration differ",
            ));
        }
        return Ok(None);
    };
    let credential = state
        .auth
        .recovery_credential
        .as_ref()
        .ok_or_else(|| Response::error(503, "recovery intent lacks committed credential"))?;
    intent
        .validate(crypto::digest(state.cluster_id.as_bytes()), credential)
        .map_err(|_| Response::error(503, "recovery commit intent binding failed"))?;
    let source = decode_intent_seal(&intent.source_seal)?;
    let target = decode_intent_seal(&intent.target_seal)?;
    if !source.is_wrapper()
        || !target.is_wrapper()
        || !matches_credential(&source, intent.source_credential.as_ref())?
        || !matches_credential(&target, Some(credential))?
        || !openbao_wrapper::barrier::same_provider_material(&source, &target)
            .map_err(|_| Response::error(503, "recovery intent provider envelope invalid"))?
        || current != &source && current != &target
    {
        return Err(Response::error(
            503,
            "recovery intent does not admit this exact public index",
        ));
    }
    Ok(Some(target))
}
fn legacy_recovery_admission(
    disabled: bool,
    namespace: &str,
    path: &str,
    credential: Option<&RecoveryCredential>,
) -> Result<&'static str, Response> {
    if disabled {
        return Err(Response::error(
            404,
            "legacy unauthenticated recovery rekey disabled by listener",
        ));
    }
    if !namespace.is_empty() {
        return Err(Response::error(
            403,
            "legacy recovery rekey is root namespace only",
        ));
    }
    let credential = credential.ok_or_else(|| {
        Response::error(400, "legacy recovery rekey requires existing recovery keys")
    })?;
    credential
        .validate()
        .map_err(|_| Response::error(503, "invalid existing recovery credential"))?;
    legacy_recovery_path(path).ok_or_else(|| Response::error(404, "unknown legacy recovery path"))
}
impl Service {
    pub(crate) fn install_recovery_listener_policy(
        &mut self,
        disabled: bool,
    ) -> Result<(), String> {
        if self.state.is_some() || self.openbao_wrapper_owner.is_some() {
            return Err(
                "recovery listener policy must be installed before provider/state admission".into(),
            );
        }
        self.disable_unauthed_rekey_endpoints = disabled;
        Ok(())
    }
    pub(super) fn legacy_recovery_route(
        &mut self,
        state: State,
        method: &str,
        path: &str,
        namespace: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        let route = match legacy_recovery_admission(
            self.disable_unauthed_rekey_endpoints,
            namespace,
            path,
            state.auth.recovery_credential.as_ref(),
        ) {
            Ok(route) => route,
            Err(error) => return error,
        };
        if route.ends_with("/backup") {
            return Response::error(
                501,
                "PGP recovery backup requires a real encryption consumer",
            );
        }
        self.recovery_route_with_authority(
            state,
            RecoveryAuthorization::LegacyExistingKeys,
            method,
            route,
            namespace,
            body,
            now,
        )
    }
    pub(super) fn reconcile_recovery_seal(
        &self,
        state: &State,
        deadline: Option<std::time::Instant>,
    ) -> Result<AdmittedRecoverySeal, Response> {
        live(deadline)?;
        let Some(current) = self.seal.as_ref() else {
            if state.auth.has_recovery_state()
                || !matches!(load_seal_metadata(&self.data_dir), Ok(None))
            {
                return Err(Response::error(
                    503,
                    "recovery seal index absent or changed",
                ));
            }
            return Ok(AdmittedRecoverySeal(None));
        };
        if !current.is_wrapper() && state.auth.has_recovery_state() {
            return Err(Response::error(503, "recovery state requires Wrapper seal"));
        }
        if load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(current) {
            return Err(Response::error(
                503,
                "recovery seal index changed before reconciliation",
            ));
        }
        let Some(target) = recovery_intent_target(state, current)? else {
            return Ok(AdmittedRecoverySeal(Some(current.clone())));
        };
        live(deadline)?;
        if current != &target && persist_seal_metadata(&self.data_dir, &target).is_err() {
            return Err(Response::error(
                503,
                "committed recovery authority requires public-index repair; outcome unknown",
            ));
        }
        live(deadline)?;
        if load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(&target) {
            return Err(Response::error(
                503,
                "recovery index reconciliation re-read failed",
            ));
        }
        Ok(AdmittedRecoverySeal(Some(target)))
    }
    pub(super) fn fence_recovery_delivery(&mut self) {
        self.fence_openbao_wrapper();
        self.state = None;
        self.state_digest = None;
        self.ha_activation = None;
        self.record_root = None;
        self.record_writes_since_gc = 0;
        self.ha_read_cache = None;
        self.durable = None;
        self.barrier_key = None;
        self.recovery_required = true;
    }
    fn publish_recovery_owner(
        &mut self,
        mut state: State,
        deadline: Option<std::time::Instant>,
    ) -> Result<State, Response> {
        live(deadline)?;
        state.schema = state.writer_schema();
        if let Err(error) = self.commit_state(&state) {
            if self.recovery_required {
                self.fence_recovery_delivery();
            }
            return Err(error);
        }
        // commit_state has updated durable/record identity. Install ONLY this committed candidate.
        self.state = Some(state.clone());
        if let Err(error) = live(deadline) {
            self.fence_recovery_delivery();
            return Err(error);
        }
        Ok(state)
    }
    fn finish_recovery_commit(
        &mut self,
        mut state: State,
        attempt: &RecoveryAttempt,
        target: RecoveryCredential,
        deadline: Option<std::time::Instant>,
    ) -> Result<State, Response> {
        let source = self
            .seal
            .clone()
            .ok_or_else(|| Response::error(503, "recovery source seal absent"))?;
        if state.auth.recovery_credential.as_ref() != attempt.source.as_ref()
            || load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(&source)
            || !matches_credential(&source, attempt.source.as_ref())?
        {
            return Err(Response::error(
                409,
                "recovery source generation changed before commit",
            ));
        }
        let target_seal = openbao_wrapper::barrier::seal_with_recovery(&source, &target)
            .map_err(|_| Response::error(503, "cannot derive public recovery target"))?;
        let source_bytes =
            owner_store::serialize_owner(&source).map_err(state_serialization_error)?;
        let target_bytes =
            owner_store::serialize_owner(&target_seal).map_err(state_serialization_error)?;
        let intent = RecoveryCommitIntent::new(
            attempt,
            &target,
            source_bytes.to_vec(),
            target_bytes.to_vec(),
        )
        .map_err(|_| Response::error(503, "invalid recovery commit intent"))?;
        state.auth.recovery_credential = Some(target);
        state.auth.recovery_attempt = None;
        state.auth.recovery_intent = Some(intent);
        // This ONE encrypted owner commit switches credential authority AND installs repair intent.
        let committed = self.publish_recovery_owner(state, deadline)?;
        let admitted = match self.reconcile_recovery_seal(&committed, deadline) {
            Ok(admitted) => admitted,
            Err(error) => {
                self.fence_recovery_delivery();
                return Err(error);
            }
        };
        self.seal = admitted.0;
        let mut clean = committed;
        clean.auth.recovery_intent = None;
        // Cleanup may fail after the new credential is already authoritative. Never restore old auth.
        match self.publish_recovery_owner(clean, deadline) {
            Ok(clean) => Ok(clean),
            Err(error) => {
                self.fence_recovery_delivery();
                Err(error)
            }
        }
    }
    fn recovery_status(state: &State, verification: bool) -> Response {
        let attempt = state.auth.recovery_attempt.as_ref();
        if verification {
            let candidate = attempt.and_then(|attempt| attempt.candidate.as_ref());
            return Response::ok(
                json!({"nonce": attempt.and_then(|attempt| attempt.verification_nonce.as_deref()).unwrap_or(""),
                "n": candidate.map_or(0, RecoveryCredential::shares), "t": candidate.map_or(0, RecoveryCredential::threshold),
                "progress": if candidate.is_some() { attempt.map_or(0, RecoveryAttempt::progress) } else { 0 }}),
            );
        }
        Response::ok(json!({"started": attempt.is_some(),
            "nonce": attempt.map_or("", |attempt| attempt.nonce.as_str()),
            "n": attempt.map_or(0, |attempt| attempt.shares), "t": attempt.map_or(0, |attempt| attempt.threshold),
            "progress": attempt.filter(|attempt| attempt.candidate.is_none()).map_or(0, RecoveryAttempt::progress),
            "required": state.auth.recovery_credential.as_ref().map_or(0, RecoveryCredential::threshold),
            "pgp_fingerprints": [], "backup": false,
            "verification_required": attempt.is_some_and(|attempt| attempt.require_verification)}))
    }
    fn recovery_keys_response(
        attempt: &RecoveryAttempt,
        keys: &[String],
        keys_base64: &[String],
    ) -> Response {
        Response::ok(
            json!({"started": false, "complete": true, "nonce": attempt.nonce,
            "keys": keys, "keys_base64": keys_base64,
            "pgp_fingerprints": [], "backup": false,
            "verification_required": attempt.require_verification,
            "verification_nonce": attempt.verification_nonce.as_deref().unwrap_or("")}),
        )
    }
    fn recovery_candidate(
        &mut self,
        mut state: State,
        mut attempt: RecoveryAttempt,
        deadline: Option<std::time::Instant>,
    ) -> Response {
        let (credential, fragments) = match attempt.generate_candidate() {
            Ok(candidate) => candidate,
            Err(_) => return Response::error(503, "cannot create recovery candidate"),
        };
        let mut keys = Zeroizing::new(Vec::<String>::new());
        let mut keys_base64 = Zeroizing::new(Vec::<String>::new());
        for fragment in fragments {
            let encoded = match credential.encode_share(&fragment) {
                Ok(encoded) => Zeroizing::new(encoded),
                Err(_) => return Response::error(503, "recovery share codec rejected delivery"),
            };
            keys.push(hex(&encoded));
            keys_base64.push(STANDARD.encode(encoded.as_slice()));
        }
        if let Some(key) = &attempt.delivery_key {
            let delivery = match RecoveryDelivery::new(
                key,
                &credential,
                &attempt,
                keys.to_vec(),
                keys_base64.to_vec(),
            ) {
                Ok(delivery) => delivery,
                Err(_) => return Response::error(503, "cannot prepare private recovery delivery"),
            };
            state.auth.recovery_delivery = Some(delivery);
        }
        let result = if attempt.require_verification {
            state.auth.recovery_attempt = Some(attempt.clone());
            self.publish_recovery_owner(state, deadline)
        } else {
            self.finish_recovery_commit(state, &attempt, credential, deadline)
        };
        match result {
            Ok(_) => Self::recovery_keys_response(&attempt, &keys, &keys_base64),
            Err(error) => error,
        }
    }
    pub(super) fn recovery_route(
        &mut self,
        state: State,
        principal: Option<&Principal>,
        method: &str,
        path: &str,
        namespace: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        self.recovery_route_with_authority(
            state,
            RecoveryAuthorization::Sudo(principal),
            method,
            path,
            namespace,
            body,
            now,
        )
    }
    fn recovery_route_with_authority(
        &mut self,
        mut state: State,
        authorization: RecoveryAuthorization<'_>,
        method: &str,
        path: &str,
        namespace: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        if let RecoveryAuthorization::Sudo(principal) = authorization {
            let permission = match method {
                "GET" => "read",
                "DELETE" => "delete",
                _ => "update",
            };
            if let Err(error) = state
                .auth
                .authorize_sudo_request(principal, namespace, path, permission, now)
            {
                return Response::error(error.status, &error.message);
            }
        }
        if !namespace.is_empty() {
            return Response::error(
                501,
                "sealable namespace recovery rotation requires its owning credential consumer",
            );
        }
        if self.ha.is_some() || self.postgres_durable.is_some() {
            return Response::error(
                501,
                "recovery public-index publication on HA/PostgreSQL requires its backend consumer",
            );
        }
        if !self.seal.as_ref().is_some_and(SealMetadata::is_wrapper) {
            return Response::error(400, "recovery rotation requires a Wrapper seal");
        }
        match initialization_recovery_pending(&self.data_dir) {
            Ok(false) => {}
            Ok(true) => {
                return Response::error(
                    409,
                    "acknowledge initialization response before recovery rotation",
                );
            }
            Err(_) => {
                return Response::error(503, "initialization response delivery state unavailable");
            }
        }
        let deadline = crate::request_deadline::current();
        if let Err(error) = live(deadline) {
            return error;
        }
        if state.auth.recovery_intent.is_some() {
            let admitted = match self.reconcile_recovery_seal(&state, deadline) {
                Ok(admitted) => admitted,
                Err(error) => {
                    self.fence_recovery_delivery();
                    return error;
                }
            };
            self.seal = admitted.0;
            state.auth.recovery_intent = None;
            state = match self.publish_recovery_owner(state, deadline) {
                Ok(state) => state,
                Err(error) => {
                    self.fence_recovery_delivery();
                    return error;
                }
            };
        }
        if path == "sys/internal/recovery-key-delivery" {
            if !matches!(method, "POST" | "DELETE") {
                return Response::error(405, "private recovery delivery requires POST or DELETE");
            }
            if body
                .as_object()
                .is_none_or(|object| object.keys().any(|key| key != "delivery_nonce"))
            {
                return Response::error(
                    400,
                    "private recovery delivery accepts only delivery_nonce",
                );
            }
            let secret = match body.get("delivery_nonce").map(decode_initialization_secret) {
                Some(Ok(secret)) => secret,
                _ => return Response::error(400, "private delivery nonce required"),
            };
            let Some(delivery) = state.auth.recovery_delivery.as_ref() else {
                return Response::error(404, "private recovery delivery absent");
            };
            if delivery.authorize(&secret).is_err() {
                return Response::error(403, "private recovery delivery authentication failed");
            }
            if method == "POST" {
                return Response::ok(json!({"nonce": delivery.nonce, "keys": delivery.keys,
                    "keys_base64": delivery.keys_base64, "verification_nonce": delivery.verification_nonce.as_deref().unwrap_or("")}));
            }
            state.auth.recovery_delivery = None;
            return match self.publish_recovery_owner(state, deadline) {
                Ok(_) => Response {
                    consistency_index: None,
                    status: 204,
                    body: Value::Null,
                },
                Err(error) => error,
            };
        }
        if path == "sys/rotate/recovery/init" {
            if method == "GET" {
                return Self::recovery_status(&state, false);
            }
            if method == "DELETE" {
                if state
                    .auth
                    .recovery_attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt.candidate.is_some())
                {
                    state.auth.recovery_delivery = None;
                }
                state.auth.recovery_attempt = None;
                return match self.publish_recovery_owner(state, deadline) {
                    Ok(_) => Response {
                        consistency_index: None,
                        status: 204,
                        body: Value::Null,
                    },
                    Err(error) => error,
                };
            }
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "recovery init method unavailable");
            }
            if state.auth.recovery_attempt.is_some() || state.auth.recovery_delivery.is_some() {
                return Response::error(
                    409,
                    "cancel active ceremony or acknowledge private delivery before a new attempt",
                );
            }
            if body.as_object().is_none_or(|object| {
                object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "secret_shares"
                            | "secret_threshold"
                            | "require_verification"
                            | "backup"
                            | "delivery_nonce"
                    )
                })
            }) {
                return Response::error(400, "unsupported recovery rotation options");
            }
            match body.get("backup") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => {
                    return Response::error(
                        501,
                        "PGP recovery backup requires a real encryption consumer",
                    );
                }
                Some(_) => return Response::error(400, "backup must be boolean"),
            }
            let (shares, threshold) = match required_recovery_counts(body) {
                Ok(counts) => counts,
                Err(error) => return error,
            };
            let verification = match body.get("require_verification") {
                None => false,
                Some(Value::Bool(value)) => *value,
                _ => return Response::error(400, "require_verification must be boolean"),
            };
            let delivery_secret = match body.get("delivery_nonce") {
                None => None,
                Some(value) => match decode_initialization_secret(value) {
                    Ok(secret) => Some(secret),
                    Err(error) => return Response::error(400, error),
                },
            };
            let mut attempt = match RecoveryAttempt::new(
                crypto::digest(state.cluster_id.as_bytes()),
                state.auth.recovery_credential.as_ref(),
                shares,
                threshold,
                verification,
            ) {
                Ok(attempt) => attempt,
                Err(crate::auth::RecoveryCeremonyError::RandomnessUnavailable) => {
                    return Response::error(503, "recovery challenge randomness unavailable");
                }
                Err(_) => return Response::error(400, "invalid recovery rotation configuration"),
            };
            if let Some(secret) = delivery_secret.as_ref() {
                if attempt.bind_delivery(secret).is_err() {
                    return Response::error(400, "invalid private recovery delivery binding");
                }
            }
            if attempt.source.is_none() {
                return self.recovery_candidate(state, attempt, deadline);
            }
            state.auth.recovery_attempt = Some(attempt);
            return match self.publish_recovery_owner(state, deadline) {
                Ok(state) => Self::recovery_status(&state, false),
                Err(error) => error,
            };
        }
        let verification = path == "sys/rotate/recovery/verify";
        if !verification && path != "sys/rotate/recovery/update" {
            return Response::error(404, "unsupported recovery rotation path");
        }
        if verification && method == "GET" {
            return Self::recovery_status(&state, true);
        }
        let Some(mut attempt) = state.auth.recovery_attempt.take() else {
            return Response::error(400, "recovery rotation is not in progress");
        };
        if verification && method == "DELETE" {
            if attempt.reset_verification().is_err() {
                return Response::error(400, "recovery verification is not in progress");
            }
            if let Some(delivery) = state.auth.recovery_delivery.as_mut() {
                delivery.verification_nonce = attempt.verification_nonce.clone();
            }
            state.auth.recovery_attempt = Some(attempt);
            return match self.publish_recovery_owner(state, deadline) {
                Ok(state) => Self::recovery_status(&state, true),
                Err(error) => error,
            };
        }
        if !matches!(method, "POST" | "PUT") {
            return Response::error(405, "recovery share update method unavailable");
        }
        if body.as_object().is_none_or(|object| {
            object
                .keys()
                .any(|key| !matches!(key.as_str(), "key" | "nonce"))
        }) {
            return Response::error(400, "recovery update accepts only key and nonce");
        }
        let nonce = match body.get("nonce").and_then(Value::as_str) {
            Some(nonce) => nonce,
            None => return Response::error(400, "recovery challenge nonce required"),
        };
        let encoded = match body
            .get("key")
            .and_then(Value::as_str)
            .map(decode_key_material)
        {
            Some(Ok(encoded)) => Zeroizing::new(encoded),
            _ => return Response::error(400, "recovery share required"),
        };
        let authorized = attempt.submit(
            state.auth.recovery_credential.as_ref(),
            nonce,
            &encoded,
            verification,
        );
        match authorized {
            Ok(true) if verification => {
                let target = match attempt.candidate.clone() {
                    Some(target) => target,
                    None => return Response::error(503, "missing verified recovery candidate"),
                };
                return match self.finish_recovery_commit(state, &attempt, target, deadline) {
                    Ok(_) => Response::ok(json!({"complete": true, "nonce": nonce})),
                    Err(error) => error,
                };
            }
            Ok(true) => return self.recovery_candidate(state, attempt, deadline),
            Ok(false) => {
                state.auth.recovery_attempt = Some(attempt);
                return match self.publish_recovery_owner(state, deadline) {
                    Ok(state) => Self::recovery_status(&state, verification),
                    Err(error) => error,
                };
            }
            Err(_) => {
                // Persist failed-quorum erasure as well; unrelated shares cannot linger after a full wrong set.
                state.auth.recovery_attempt = Some(attempt);
                return match self.publish_recovery_owner(state, deadline) {
                    Ok(_) => Response::error(400, "recovery share or challenge rejected"),
                    Err(error) => error,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn failure(_: Response) -> std::io::Error {
        std::io::Error::other("recovery admission rejected")
    }
    fn metadata(blob: u8) -> Result<SealMetadata, serde_json::Error> {
        // Structural protobuf fixture only; it is never executed as a provider.
        let wire = [0x0a, 1, blob];
        Ok(SealMetadata { schema: 2, generation: 7, share_format: "wrapper-v1".into(),
            secret_shares: 0, secret_threshold: 0, wrapped_barrier_key: STANDARD.encode(serde_json::to_vec(&json!({
                "schema": 1, "seal_generation": 7, "deployment_binding": "11".repeat(32), "blobinfo": STANDARD.encode(wire),
            }))?) })
    }
    fn committed() -> Result<(State, SealMetadata, SealMetadata), Box<dyn std::error::Error>> {
        let (auth, _) =
            AuthState::bootstrap(1).map_err(|_| std::io::Error::other("bootstrap failed"))?;
        let mut state = State {
            schema: INDEXED_RECOVERY_WIRE_STATE_SCHEMA,
            cluster_id: "journal-test-cluster".into(),
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: EngineState::initialized_empty().into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
        };
        let mut attempt = RecoveryAttempt::new(
            crypto::digest(state.cluster_id.as_bytes()),
            None,
            3,
            2,
            false,
        )
        .map_err(|_| std::io::Error::other("challenge generation failed"))?;
        let (target_credential, _) = attempt
            .generate_candidate()
            .map_err(|_| std::io::Error::other("credential generation failed"))?;
        let source = metadata(7)?;
        let target = openbao_wrapper::barrier::seal_with_recovery(&source, &target_credential)
            .map_err(std::io::Error::other)?;
        let intent = RecoveryCommitIntent::new(
            &attempt,
            &target_credential,
            owner_store::serialize_owner(&source)?.to_vec(),
            owner_store::serialize_owner(&target)?.to_vec(),
        )
        .map_err(|_| std::io::Error::other("intent construction failed"))?;
        state.auth.recovery_credential = Some(target_credential);
        state.auth.recovery_intent = Some(intent);
        Ok((state, source, target))
    }
    #[test]
    fn encrypted_intent_admits_only_exact_source_or_target_before_repair() -> TestResult {
        let (state, source, target) = committed()?;
        assert!(state.validate_format().is_ok());
        assert!(recovery_intent_target(&state, &source).map_err(failure)? == Some(target.clone()));
        assert!(recovery_intent_target(&state, &target).map_err(failure)? == Some(target.clone()));
        assert!(recovery_intent_target(&state, &metadata(8)?).is_err());
        let mut clean = state.clone();
        clean.auth.recovery_intent = None;
        assert!(recovery_intent_target(&clean, &source).is_err());
        assert!(
            recovery_intent_target(&clean, &target)
                .map_err(failure)?
                .is_none()
        );
        Ok(())
    }
    #[test]
    fn encrypted_intent_rejects_noncanonical_metadata_and_provider_substitution() -> TestResult {
        let (state, source, target) = committed()?;
        let mut noncanonical = state.clone();
        noncanonical
            .auth
            .recovery_intent
            .as_mut()
            .ok_or("intent missing")?
            .target_seal
            .push(b' ');
        assert!(recovery_intent_target(&noncanonical, &source).is_err());
        let credential = state
            .auth
            .recovery_credential
            .as_ref()
            .ok_or("credential missing")?;
        let other_target = openbao_wrapper::barrier::seal_with_recovery(&metadata(8)?, credential)
            .map_err(std::io::Error::other)?;
        let mut substituted = state.clone();
        substituted
            .auth
            .recovery_intent
            .as_mut()
            .ok_or("intent missing")?
            .target_seal = owner_store::serialize_owner(&other_target)?.to_vec();
        assert!(recovery_intent_target(&substituted, &source).is_err());
        assert!(recovery_intent_target(&substituted, &target).is_err());
        Ok(())
    }
    #[test]
    fn required_rotation_counts_are_not_defaulted_and_use_full_byte_domain() {
        for body in [
            json!({}),
            json!({"secret_shares": 5}),
            json!({"secret_threshold": 3}),
            json!({"secret_shares": 256, "secret_threshold": 3}),
            json!({"secret_shares": 2, "secret_threshold": 3}),
            json!({"secret_shares": 0, "secret_threshold": 0}),
            json!({"secret_shares": true, "secret_threshold": 1}),
        ] {
            assert!(required_recovery_counts(&body).is_err());
        }
        assert!(
            required_recovery_counts(&json!({"secret_shares": 255, "secret_threshold": 1})).is_ok()
        );
        assert!(
            required_recovery_counts(&json!({"secret_shares": 255, "secret_threshold": 255}))
                .is_ok()
        );
    }
    #[test]
    fn verification_status_projects_its_own_challenge_and_progress() -> TestResult {
        let (mut state, _, _) = committed()?;
        state.auth.recovery_intent = None;
        let (source, fragments) =
            RecoveryCredential::generate(crypto::digest(state.cluster_id.as_bytes()), 1, 3, 2)
                .map_err(|_| std::io::Error::other("credential generation failed"))?;
        state.auth.recovery_credential = Some(source.clone());
        let mut attempt = RecoveryAttempt::new(
            crypto::digest(state.cluster_id.as_bytes()),
            Some(&source),
            5,
            3,
            true,
        )
        .map_err(|_| std::io::Error::other("challenge generation failed"))?;
        let admission_nonce = attempt.nonce.clone();
        for share in &fragments[..2] {
            let encoded = Zeroizing::new(
                source
                    .encode_share(share)
                    .map_err(|_| std::io::Error::other("encoding failed"))?,
            );
            attempt
                .submit(Some(&source), &admission_nonce, &encoded, false)
                .map_err(|_| std::io::Error::other("quorum failed"))?;
        }
        attempt
            .generate_candidate()
            .map_err(|_| std::io::Error::other("candidate generation failed"))?;
        let old_nonce = attempt.nonce.clone();
        let verification_nonce = attempt
            .verification_nonce
            .clone()
            .ok_or("verification nonce missing")?;
        state.auth.recovery_attempt = Some(attempt);
        assert!(state.validate_format().is_ok());
        let init = Service::recovery_status(&state, false);
        let verify = Service::recovery_status(&state, true);
        assert_eq!(init.body["nonce"], old_nonce);
        assert_eq!(verify.body["nonce"], verification_nonce);
        assert_eq!(verify.body["n"], 5);
        assert_eq!(verify.body["t"], 3);
        assert_eq!(verify.body["progress"], 0);
        assert_eq!(verify.body.as_object().ok_or("status missing")?.len(), 4);
        Ok(())
    }

    #[test]
    fn legacy_listener_alias_never_bootstraps_without_existing_keys_or_uses_child_keys()
    -> TestResult {
        let (state, _, _) = committed()?;
        let credential = state
            .auth
            .recovery_credential
            .as_ref()
            .ok_or("missing credential")?;
        assert_eq!(
            legacy_recovery_admission(true, "", "sys/rekey-recovery-key/init", Some(credential))
                .map_err(|error| error.status),
            Err(404)
        );
        assert_eq!(
            legacy_recovery_admission(false, "", "sys/rekey-recovery-key/init", None)
                .map_err(|error| error.status),
            Err(400)
        );
        assert_eq!(
            legacy_recovery_admission(
                false,
                "team",
                "sys/rekey-recovery-key/init",
                Some(credential)
            )
            .map_err(|error| error.status),
            Err(403)
        );
        for (old, new) in [("init", "init"), ("update", "update"), ("verify", "verify")] {
            let old = format!("sys/rekey-recovery-key/{old}");
            let new = format!("sys/rotate/recovery/{new}");
            assert_eq!(
                legacy_recovery_admission(false, "", &old, Some(credential)).map_err(failure)?,
                new
            );
        }
        assert!(
            legacy_recovery_admission(
                false,
                "",
                "sys/rekey-recovery-key/init/extra",
                Some(credential)
            )
            .is_err()
        );
        Ok(())
    }
}

// Insert after the production impl Service in service_recovery_keys.rs.
// This private cfg(test) entry consumes real stored ceremony state and one
// genuine final verification share. It publishes through commit_state and
// deliberately returns before public-index repair. No synthetic provider is
// admitted and no flags, nonce, schema or credential are fabricated.
#[cfg(test)]
pub(super) struct RecoveryOwnerCut {
    pub(super) committed: State,
    pub(super) source_public: SealMetadata,
    pub(super) target_public: SealMetadata,
    pub(super) committed_identity: crate::state_record_root::StateIdentity,
}

#[cfg(test)]
impl Service {
    pub(super) fn fixture_require_live_recovery_wrapper(&self) -> Result<(), Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "fixture requires live state"))?;
        let seal = self
            .seal
            .as_ref()
            .ok_or_else(|| Response::error(503, "fixture requires actual seal"))?;
        if self.ha.is_some()
            || self.postgres_durable.is_some()
            || self.recovery_required
            || self.audit_failed
            || self.barrier_key.is_none()
            || self.durable.is_none()
            || self.openbao_wrapper_owner.is_none()
            || !seal.is_wrapper()
            || state.auth.recovery_credential.is_none()
            || load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(seal)
            || !matches_credential(seal, state.auth.recovery_credential.as_ref())?
        {
            return Err(Response::error(
                503,
                "fixture requires genuine admitted local Wrapper recovery state",
            ));
        }
        state
            .auth
            .validate_recovery_credential(&state.cluster_id)
            .map_err(|_| Response::error(503, "fixture protected recovery authority invalid"))?;
        Ok(())
    }

    pub(super) fn fixture_commit_owner_before_public_repair(
        &mut self,
        principal: &Principal,
        final_nonce: &str,
        final_encoded_share: &[u8],
        now: u64,
        deadline: Option<std::time::Instant>,
    ) -> Result<RecoveryOwnerCut, Response> {
        self.fixture_require_live_recovery_wrapper()?;
        live(deadline)?;
        if !matches!(initialization_recovery_pending(&self.data_dir), Ok(false)) {
            return Err(Response::error(
                409,
                "fixture requires acknowledged initialization",
            ));
        }
        let mut state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?
            .clone();
        state
            .auth
            .authorize_sudo_request(principal, "", "sys/rotate/recovery/verify", "update", now)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if state.auth.recovery_intent.is_some() {
            return Err(Response::error(
                409,
                "fixture refuses an existing interrupted intent",
            ));
        }
        let mut attempt = state.auth.recovery_attempt.take().ok_or_else(|| {
            Response::error(400, "fixture requires a real in-progress recovery ceremony")
        })?;
        if attempt.source.is_none()
            || !attempt.require_verification
            || !attempt.old_authorized
            || attempt.new_authorized
            || attempt.verification_nonce.as_deref() != Some(final_nonce)
        {
            return Err(Response::error(
                400,
                "fixture requires old quorum and pending new quorum",
            ));
        }
        if !attempt
            .submit(
                state.auth.recovery_credential.as_ref(),
                final_nonce,
                final_encoded_share,
                true,
            )
            .map_err(|_| Response::error(400, "fixture final genuine recovery share rejected"))?
        {
            return Err(Response::error(
                400,
                "fixture final share did not complete the new quorum",
            ));
        }
        let target = attempt
            .candidate
            .clone()
            .ok_or_else(|| Response::error(503, "missing verified recovery candidate"))?;
        // Production finish_recovery_commit prefix, byte-for-byte expressions.
        let source = self
            .seal
            .clone()
            .ok_or_else(|| Response::error(503, "recovery source seal absent"))?;
        if state.auth.recovery_credential.as_ref() != attempt.source.as_ref()
            || load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(&source)
            || !matches_credential(&source, attempt.source.as_ref())?
        {
            return Err(Response::error(
                409,
                "recovery source generation changed before commit",
            ));
        }
        let target_seal = openbao_wrapper::barrier::seal_with_recovery(&source, &target)
            .map_err(|_| Response::error(503, "cannot derive public recovery target"))?;
        let source_bytes =
            owner_store::serialize_owner(&source).map_err(state_serialization_error)?;
        let target_bytes =
            owner_store::serialize_owner(&target_seal).map_err(state_serialization_error)?;
        let intent = RecoveryCommitIntent::new(
            &attempt,
            &target,
            source_bytes.to_vec(),
            target_bytes.to_vec(),
        )
        .map_err(|_| Response::error(503, "invalid recovery commit intent"))?;
        state.auth.recovery_credential = Some(target);
        state.auth.recovery_attempt = None;
        state.auth.recovery_intent = Some(intent);
        let committed = self.publish_recovery_owner(state, deadline)?;
        // Deliberate durable checkpoint: no reconcile, cleanup, rollback or
        // public seal write. ROOT must close this isolated lifecycle and reopen
        // the SAME durable directory with the SAME genuine provider binding.
        let committed_identity = self
            .current_state_identity()
            .map_err(|_| Response::error(503, "fixture committed identity unavailable"))?;
        if load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(&source)
            || committed.auth.recovery_intent.is_none()
            || committed.auth.recovery_credential.as_ref() != attempt.candidate.as_ref()
        {
            return Err(Response::error(
                503,
                "fixture genuine pre-public-repair checkpoint failed",
            ));
        }
        Ok(RecoveryOwnerCut {
            committed,
            source_public: source,
            target_public: target_seal,
            committed_identity,
        })
    }
}

// Insert into service_recovery_keys.rs for the private Linux cfg(test) runner.
// ROOT must first admit a genuine newly built candidate, immutable provider
// configuration, private store, and owned lifecycle. These methods derive no
// command, config, release, cluster identifier or provider from a proposal.
#[cfg(all(test, target_os = "linux"))]
pub(super) struct FreshWrapperFixture {
    pub(super) service: Service,
    pub(super) init_attempted: bool,
    pub(super) initialization: Response,
}

#[cfg(all(test, target_os = "linux"))]
impl Service {
    pub(super) fn fixture_start_genuine_recovery_wrapper(
        data_dir: PathBuf,
        audit_path: &Path,
        actual_config: openbao_wrapper::OpenBaoWrapperConfig,
        actual_initialization_body: Value,
        now: u64,
    ) -> Result<FreshWrapperFixture, String> {
        if !actual_config.seal_barrier {
            return Err("fixture requires a real explicit Wrapper seal provider".into());
        }
        let shares = actual_initialization_body
            .get("recovery_shares")
            .and_then(Value::as_u64);
        let threshold = actual_initialization_body
            .get("recovery_threshold")
            .and_then(Value::as_u64);
        if !matches!((shares, threshold), (Some(n), Some(t)) if n > 0 && n <= 255 && t > 0 && t <= n)
        {
            return Err("fixture requires explicit positive real recovery counts".into());
        }
        let mut service = Service::new(data_dir, audit_path).map_err(str::to_owned)?;
        if service.initialized() || service.state.is_some() || service.seal.is_some() {
            return Err("fixture refuses an initialized or recovered store".into());
        }
        let launch = service
            .install_openbao_wrapper(Some(actual_config))?
            .ok_or("genuine Wrapper launch plan missing")?;
        launch.execute().map_err(|error| error.to_string())?;
        // Exactly one initialization. A non-200/unknown outcome is returned
        // with init_attempted=true and can never be reset by this adapter.
        let initialization =
            service.handle_at("PUT", "sys/init", "", "", actual_initialization_body, now);
        Ok(FreshWrapperFixture {
            service,
            init_attempted: true,
            initialization,
        })
    }

    pub(super) fn fixture_reopen_same_genuine_wrapper(
        same_data_dir: PathBuf,
        same_audit_path: &Path,
        same_actual_config: openbao_wrapper::OpenBaoWrapperConfig,
    ) -> Result<Service, String> {
        if !same_actual_config.seal_barrier {
            return Err("fixture restart requires the same real Wrapper provider".into());
        }
        let mut service = Service::new(same_data_dir, same_audit_path).map_err(str::to_owned)?;
        if !service.initialized()
            || service.state.is_some()
            || !service.seal.as_ref().is_some_and(SealMetadata::is_wrapper)
        {
            return Err(
                "fixture restart refuses absent, changed, or non-Wrapper public seal".into(),
            );
        }
        let launch = service
            .install_openbao_wrapper(Some(same_actual_config))?
            .ok_or("genuine restart Wrapper launch plan missing")?;
        launch.execute().map_err(|error| error.to_string())?;
        let activation = service
            .prepare_wrapper_barrier_activation()?
            .ok_or("genuine sealed-store activation plan missing")?;
        service.finish_wrapper_barrier_activation(activation.execute())?;
        service
            .fixture_require_live_recovery_wrapper()
            .map_err(|_| {
                "actual provider/decrypted recovery authority admission failed".to_owned()
            })?;
        Ok(service)
    }

    pub(super) fn fixture_check_reopened_committed_cut(
        &self,
        cut: &RecoveryOwnerCut,
    ) -> Result<(), Response> {
        self.fixture_require_live_recovery_wrapper()?;
        let actual = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "fixture live reopened state absent"))?;
        if self.current_state_identity()? != cut.committed_identity
            || actual.cluster_id != cut.committed.cluster_id
            || actual.auth.recovery_credential != cut.committed.auth.recovery_credential
            || self.seal.as_ref() != Some(&cut.target_public)
            || load_seal_metadata(&self.data_dir).ok().flatten().as_ref()
                != Some(&cut.target_public)
        {
            return Err(Response::error(
                503,
                "fixture restart did not admit the actual encrypted committed generation and repaired target",
            ));
        }
        Ok(())
    }
}

// Real Linux tests: inputs are independently admitted immutable provider config
// and initialization bytes. Missing inputs FAIL UNQUALIFIED; no fake provider,
// cluster id, recovery share, state or archive is constructed by these tests.
#[cfg(all(test, target_os = "linux"))]
mod source825_real_recovery_fixture_tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("real clock")
            .as_secs()
    }
    fn meta9(a: &fs::Metadata, b: &fs::Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.uid() == b.uid()
            && a.nlink() == b.nlink()
            && a.mode() == b.mode()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    fn private_raw(var: &str, expected_var: &str, uid: u32) -> Vec<u8> {
        let p = PathBuf::from(
            std::env::var(var).expect("UNQUALIFIED: actual private input path missing"),
        );
        assert!(p.is_absolute(), "UNQUALIFIED: absolute input required");
        let before = fs::symlink_metadata(&p).expect("actual input first9");
        assert!(
            before.is_file()
                && !before.file_type().is_symlink()
                && before.uid() == uid
                && before.nlink() == 1
                && before.mode() & 0o077 == 0
                && before.len() <= 2 * 1024 * 1024,
            "UNQUALIFIED: private input metadata"
        );
        let mut fd = fs::File::from(
            rustix::fs::open(
                &p,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .expect("actual input descriptor"),
        );
        assert!(meta9(&before, &fd.metadata().expect("input descriptor9")));
        let mut raw = Vec::new();
        Read::by_ref(&mut fd)
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)
            .expect("input bytes");
        assert_eq!(raw.len() as u64, before.len());
        let expected =
            std::env::var(expected_var).expect("UNQUALIFIED: actual expected SHA missing");
        assert_eq!(
            hex(&crypto::digest(&raw)),
            expected,
            "UNQUALIFIED: actual raw SHA mismatch"
        );
        assert!(
            meta9(&before, &fd.metadata().expect("terminal fd9"))
                && meta9(&before, &fs::symlink_metadata(&p).expect("input terminal9"))
        );
        raw
    }
    fn save(p: &Path, raw: &[u8]) {
        let mut fd = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)
            .expect("fresh private evidence");
        fd.write_all(raw).expect("complete evidence bytes");
        fd.sync_all().expect("durable evidence");
    }
    fn response(dir: &Path, label: &str, r: &Response) {
        save(
            &dir.join(format!("{label}.json")),
            &serde_json::to_vec(&json!({"status":r.status,"body":r.body}))
                .expect("actual response"),
        );
    }
    struct Case {
        root: PathBuf,
        data: PathBuf,
        audit: PathBuf,
        config: Vec<u8>,
        init: Value,
        service: Option<Service>,
        token: String,
        old_keys: Vec<String>,
    }
    impl Drop for Case {
        fn drop(&mut self) {
            if let Some(service) = self.service.as_ref() {
                service.fence_openbao_wrapper();
            }
        }
    }
    fn start(name: &str) -> Case {
        assert_eq!(
            std::env::var("HEPTABAO_RECOVERY_FIXTURE_LIFECYCLE_AUTHORIZED")
                .ok()
                .as_deref(),
            Some("source825-private-genuine-wrapper-recovery-r01"),
            "UNQUALIFIED: isolated real lifecycle not authorized"
        );
        let root = PathBuf::from(
            std::env::var("HEPTABAO_RECOVERY_FIXTURE_ROOT")
                .expect("UNQUALIFIED: actual fresh fixture root missing"),
        );
        assert!(root.is_absolute());
        let m = fs::symlink_metadata(&root).expect("admitted fixture parent");
        assert!(m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o077 == 0);
        let config = private_raw(
            "HEPTABAO_RECOVERY_FIXTURE_CONFIG",
            "HEPTABAO_RECOVERY_FIXTURE_CONFIG_SHA256",
            m.uid(),
        );
        let init_raw = private_raw(
            "HEPTABAO_RECOVERY_FIXTURE_INIT_BODY",
            "HEPTABAO_RECOVERY_FIXTURE_INIT_BODY_SHA256",
            m.uid(),
        );
        let init: Value = serde_json::from_slice(&init_raw).expect("actual initialization bytes");
        let root = root.join(name);
        fs::create_dir(&root).expect("UNQUALIFIED: case must be fresh; no reset or replay");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("case private");
        let data = root.join("data");
        // The real initialization transaction creates and atomically publishes
        // this private store. Pre-creating its target would make initialization
        // reject safely before any durable publication.
        assert!(
            !data.exists(),
            "actual initialization target must be absent"
        );
        let audit = root.join("audit.jsonl");
        save(&root.join("provider-config.original.json"), &config);
        save(&root.join("initialization-body.original.json"), &init_raw);
        let f = Service::fixture_start_genuine_recovery_wrapper(
            data.clone(),
            &audit,
            serde_json::from_slice(&config).expect("real production wrapper config"),
            init.clone(),
            now(),
        )
        .unwrap_or_else(|error| {
            save(&root.join("startup-error.private.txt"), error.as_bytes());
            panic!("UNQUALIFIED: genuine provider startup failed")
        });
        let mut c = Case {
            root,
            data,
            audit,
            config,
            init,
            service: Some(f.service),
            token: String::new(),
            old_keys: Vec::new(),
        };
        // The owned provider is now fenced even when any following assertion panics.
        assert!(f.init_attempted);
        response(&c.root, "initialization-once", &f.initialization);
        assert_eq!(
            f.initialization.status, 200,
            "UNQUALIFIED: initialization unknown/failed; never retry"
        );
        c.token = f.initialization.body["root_token"]
            .as_str()
            .expect("actual root token")
            .to_owned();
        c.old_keys = f.initialization.body["recovery_keys"]
            .as_array()
            .expect("actual recovery keys")
            .iter()
            .map(|v| v.as_str().expect("real recovery encoding").to_owned())
            .collect::<Vec<_>>();
        assert!(!c.old_keys.is_empty());
        let ack = c.service.as_mut().expect("live fixture").handle_at(
            "POST",
            "sys/init/ack",
            "",
            &c.token,
            json!({}),
            now(),
        );
        response(&c.root, "initialization-ack", &ack);
        assert_eq!(ack.status, 204);
        assert!(
            c.service
                .as_ref()
                .expect("live fixture")
                .fixture_require_live_recovery_wrapper()
                .is_ok(),
            "UNQUALIFIED: true decrypted Recovery authority missing"
        );
        c
    }

    fn principal(c: &Case) -> Principal {
        c.service
            .as_ref()
            .expect("live fixture")
            .state
            .as_ref()
            .expect("live state")
            .auth
            .authenticate_read_only(&c.token, now())
            .unwrap_or_else(|_| panic!("actual root admission failed"))
            .expect("actual unlimited root")
    }
    fn pending_final(c: &mut Case) -> (String, String) {
        let r = c.service.as_mut().expect("live fixture").handle_at(
            "POST",
            "sys/rotate/recovery/init",
            "",
            &c.token,
            json!({"secret_shares":3,"secret_threshold":2,"require_verification":true}),
            now(),
        );
        response(&c.root, "rotation-init", &r);
        assert_eq!(r.status, 200);
        let nonce = r.body["nonce"]
            .as_str()
            .expect("actual challenge")
            .to_owned();
        let t = c.init["recovery_threshold"]
            .as_u64()
            .expect("actual old threshold") as usize;
        assert!(t > 0 && t <= c.old_keys.len());
        let mut last = None;
        for (i, key) in c.old_keys.iter().take(t).enumerate() {
            let r = c.service.as_mut().expect("live fixture").handle_at(
                "POST",
                "sys/rotate/recovery/update",
                "",
                &c.token,
                json!({"nonce":nonce,"key":key}),
                now(),
            );
            response(&c.root, &format!("old-quorum-{i}"), &r);
            assert_eq!(r.status, 200);
            last = Some(r);
        }
        let delivered = last.expect("real old quorum");
        assert_eq!(delivered.body["verification_required"], true);
        let nonce = delivered.body["verification_nonce"]
            .as_str()
            .expect("actual verification challenge")
            .to_owned();
        let keys = delivered.body["keys"]
            .as_array()
            .expect("actual new recovery keys");
        assert_eq!(keys.len(), 3);
        let first = keys[0].as_str().expect("first real share").to_owned();
        let final_share = keys[1].as_str().expect("second real share").to_owned();
        let r = c.service.as_mut().expect("live fixture").handle_at(
            "POST",
            "sys/rotate/recovery/verify",
            "",
            &c.token,
            json!({"nonce":nonce,"key":first}),
            now(),
        );
        response(&c.root, "new-quorum-before-final", &r);
        assert_eq!(r.status, 200);
        assert_ne!(r.body["complete"], true);
        (nonce, final_share)
    }
    fn close(c: &Case) {
        c.service
            .as_ref()
            .expect("live fixture")
            .fence_openbao_wrapper();
    }
    #[test]
    #[ignore = "requires ROOT-admitted real provider, fresh private store and built candidate; missing inputs UNQUALIFIED"]
    fn genuine_wrapper_bootstrap_and_recovery_capability() {
        let c = start("genuine-wrapper-bootstrap");
        assert!(
            c.service
                .as_ref()
                .expect("live fixture")
                .fixture_require_live_recovery_wrapper()
                .is_ok()
        );
        close(&c);
    }
    #[test]
    #[ignore = "requires real durable store/provider; no simulated state"]
    fn genuine_owner_commit_cut_then_same_store_restart() {
        let mut c = start("genuine-owner-cut-restart");
        let (nonce, share) = pending_final(&mut c);
        let actor = principal(&c);
        let encoded = decode_key_material(&share).expect("actual recovery share codec");
        let cut = c
            .service
            .as_mut()
            .expect("live fixture")
            .fixture_commit_owner_before_public_repair(&actor, &nonce, &encoded, now(), None)
            .unwrap_or_else(|_| panic!("genuine owner durable commit checkpoint failed"));
        assert!(cut.source_public != cut.target_public);
        assert!(
            load_seal_metadata(&c.data)
                .expect("actual physical seal")
                .as_ref()
                == Some(&cut.source_public)
        );
        close(&c);
        drop(c.service.take().expect("owned old provider"));
        let restarted = Service::fixture_reopen_same_genuine_wrapper(
            c.data.clone(),
            &c.audit,
            serde_json::from_slice(&c.config).expect("identical actual provider bytes"),
        )
        .unwrap_or_else(|_| panic!("same-store real provider restart failed"));
        c.service = Some(restarted);
        assert!(
            c.service
                .as_ref()
                .expect("real reopened provider")
                .fixture_check_reopened_committed_cut(&cut)
                .is_ok()
        );
        close(&c);
    }
    fn native_race(name: &str, isolate_floor: bool) {
        let mut c = start(name);
        let (nonce, share) = pending_final(&mut c);
        let req = ServiceRequest::new(
            "GET",
            "sys/storage/raft/snapshot",
            "",
            &c.token,
            Value::Null,
        );
        let mut pending = match c
            .service
            .as_mut()
            .expect("live fixture")
            .begin_native_snapshot_before(req, Instant::now() + Duration::from_secs(30))
        {
            snapshot_transfer::NativeSnapshotAdmission::Execute(RequestExecution::External(v)) => {
                *v
            }
            _ => panic!("UNQUALIFIED: genuine native export admission failed"),
        };
        let (observed, file) = pending.execute_snapshot_transfer(&mut std::io::empty());
        let mut file = file.expect("actual native archive descriptor");
        file.rewind_checked().expect("actual archive rewind");
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(crate::snapshot_file::MAX_NATIVE_ARCHIVE + 1)
            .read_to_end(&mut raw)
            .expect("actual archive bytes");
        assert!(raw.len() as u64 <= crate::snapshot_file::MAX_NATIVE_ARCHIVE && !raw.is_empty());
        save(&c.root.join("native-before-final.snap"), &raw);
        drop(file);
        let result = c
            .service
            .as_mut()
            .expect("live fixture")
            .finish_external_request(pending, observed);
        response(&c.root, "native-export", &result);
        assert_eq!(result.status, 200);
        let req = ServiceRequest::new(
            "POST",
            "sys/storage/raft/snapshot",
            "",
            &c.token,
            Value::Null,
        );
        let mut pending = c
            .service
            .as_mut()
            .expect("live fixture")
            .fixture_begin_native_snapshot_upload(req, Instant::now() + Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("genuine native upload admission failed"));
        let (observed, file) = pending.execute_snapshot_transfer(&mut std::io::Cursor::new(&raw));
        assert!(file.is_none());
        let verified = c
            .service
            .as_mut()
            .expect("live fixture")
            .fixture_prepare_verified_native_restore(pending, observed)
            .unwrap_or_else(|_| panic!("actual native archive authentication/preparation failed"));
        let actor = principal(&c);
        let body = Value::Null;
        let request = RequestView {
            method: "POST",
            path: "sys/storage/raft/snapshot",
            namespace: "",
            token: &c.token,
            body: &body,
            now: now(),
            admission_started: Instant::now(),
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        };
        let result = c
            .service
            .as_mut()
            .expect("live fixture")
            .fixture_native_restore_after_real_recovery_commit(
                verified,
                &actor,
                &request,
                &c.token,
                json!({"nonce":nonce,"key":share}),
                now(),
                isolate_floor,
            )
            .unwrap_or_else(|_| panic!("real same-schema old-authority native final gate failed"));
        response(&c.root, "native-final-gate", &result);
        assert_eq!(result.status, if isolate_floor { 409 } else { 503 });
        close(&c);
    }
    #[test]
    #[ignore = "requires actual native export/import and real interleaved Recovery commit"]
    fn genuine_native_restore_rejects_changed_authority() {
        native_race("native-actual-authority-race", false);
    }
    #[test]
    #[ignore = "requires authenticated native archive; isolates only the final protected floor"]
    fn genuine_native_restore_same_schema_old_auth_protected_floor() {
        native_race("native-same-schema-old-auth", true);
    }
}
