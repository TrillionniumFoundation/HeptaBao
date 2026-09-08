#![forbid(unsafe_code)]

//! Admission-to-durability adapter for the HeptaBao repository candidate.
//!
//! `RuntimeService` owns its durable writer and exposes no mutable bypass. Every
//! mutation must authenticate, authorize, and append a pre-dispatch audit event
//! before it can enter the durable intent journal. Once durable entry may have
//! happened, failure is never translated into an automatic retry signal.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use std::fmt;

use heptabao_durable_service::{
    Barrier, DeleteRequest, DurableService, Failpoint, MutationOutcome, PutRequest,
    ReconciliationStatus, Secret, ServiceError,
};

const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_FIELD_BYTES: usize = 4 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct Credential(Vec<u8>);

impl Drop for Credential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Credential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(RuntimeError::InvalidRequest);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Put,
    Delete,
    Read,
    List,
}

#[derive(Clone, Eq, PartialEq)]
pub enum InboundOperation {
    Put(Secret),
    Delete,
}

impl InboundOperation {
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        match self {
            Self::Put(_) => OperationKind::Put,
            Self::Delete => OperationKind::Delete,
        }
    }
}

impl fmt::Debug for InboundOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put(_) => formatter.write_str("Put([REDACTED])"),
            Self::Delete => formatter.write_str("Delete"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InboundMutation {
    credential: Credential,
    namespace: String,
    request_id: String,
    resource: String,
    operation: InboundOperation,
}

impl InboundMutation {
    pub fn new(
        credential: Credential,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        resource: impl Into<String>,
        operation: InboundOperation,
    ) -> Result<Self, RuntimeError> {
        let request = Self {
            credential,
            namespace: namespace.into(),
            request_id: request_id.into(),
            resource: resource.into(),
            operation,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        validate_field(&self.namespace)?;
        validate_field(&self.request_id)?;
        validate_field(&self.resource)?;
        Ok(())
    }
}

impl fmt::Debug for InboundMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundMutation")
            .field("credential", &self.credential)
            .field("namespace", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("operation", &self.operation)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedPrincipal(String);

impl AuthenticatedPrincipal {
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {
        let value = value.into();
        validate_principal(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthenticatedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPrincipal([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorizationDigest([u8; 32]);

impl AuthorizationDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, RuntimeError> {
        if value == [0; 32] {
            return Err(RuntimeError::AuthorizationDenied);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for AuthorizationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationDigest([REDACTED])")
    }
}

pub trait Authenticator {
    fn authenticate(
        &mut self,
        credential: &Credential,
    ) -> Result<AuthenticatedPrincipal, AuthenticationFailure>;
}

pub trait Authorizer {
    fn authorize(
        &mut self,
        principal: &AuthenticatedPrincipal,
        namespace: &str,
        resource: &str,
        operation: OperationKind,
    ) -> Result<AuthorizationDigest, AuthorizationFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditStage {
    AcceptedBeforeEntry,
    Committed,
    Duplicate,
    OutcomeUnknown,
    ReadCompleted,
    ListCompleted,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditEvent {
    stage: AuditStage,
    request_fingerprint: [u8; 32],
    generation: Option<u64>,
}

impl AuditEvent {
    /// Stable binary fingerprint for a controlled, durable audit sink.
    #[must_use]
    pub const fn request_fingerprint(&self) -> &[u8; 32] {
        &self.request_fingerprint
    }

    #[must_use]
    pub const fn stage(&self) -> AuditStage {
        self.stage
    }

    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        self.generation
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("stage", &self.stage)
            .field("request_fingerprint", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

pub trait AuditSink {
    fn append(&mut self, event: &AuditEvent) -> Result<(), AuditFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutcome {
    Committed {
        generation: u64,
        recovery_reference: String,
    },
    Duplicate {
        generation: u64,
        recovery_reference: String,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidRequest,
    AuthenticationDenied,
    AuthorizationDenied,
    AuditUnavailableBeforeEntry,
    AuditUnavailableAfterRead,
    RecoveryRequired,
    OutcomeUnknown { recovery_reference: String },
    DurableRejected,
    DurableCorrupt,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("invalid inbound mutation"),
            Self::AuthenticationDenied => formatter.write_str("authentication denied"),
            Self::AuthorizationDenied => formatter.write_str("authorization denied"),
            Self::AuditUnavailableBeforeEntry => {
                formatter.write_str("pre-entry audit is unavailable")
            }
            Self::AuditUnavailableAft²È="24ˆ°€‰Í¡…É•µ¥ˆ°€‰Í•É•Ð½ˆˆ°ˆ‰ˆˆ¤ü¤ü°(€€€€€€€€€€€IÕ¹Ñ¥µ•=ÕÑ½µ”èé½µµ¥ÑÑ•ì•¹•É…Ñ¥½¸è€È°€¸¸ô(€€€€€€€€¤¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡ÉÕ¹Ñ¥µ”¹É•Ñ…¥¹•‘}É•ÅÕ•ÍÑ}½Õ¹Ð ¤°€È¤ì(€€€€€€€=¬  ¤¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÁÉ•}•¹ÑÉå}…Õ‘¥Ñ}™…¥±ÕÉ•}ÁÉ•Ù•¹ÑÍ}‘ÕÉ…‰±•}‘¥ÍÁ…Ñ  ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ½½Ð€ôI½½Ðèé¹•Ü ‰…Õ‘¥Ðµ‰•™½É”ˆ¤üì(€€€€€€€±•Ð…Õ‘¥Ð€ôQ•ÍÑÕ‘¥Ðì(€€€€€€€€€€€™…¥±}½¹}…±°èM½µ” Ä¤°(€€€€€€€€€€€€¸¹Q•ÍÑÕ‘¥Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì(€€€€€€€±•ÐµÕÐÉÕ¹Ñ¥µ”€ôÍ•ÉÙ¥” ™É½½Ð°Q•ÍÑÕÑ¡½É¥é•Èì…±±½ÜèÑÉÕ”ô°…Õ‘¥Ð¤üì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡¥¹‰½Õ¹ (€€€€€€€€€€€€€€€ˆ‰Ñ½­•¸µ„ˆ°(€€€€€€€€€€€€€€€€‰É•ÅÕ•ÍÐµ…Õ‘¥Ðˆ°(€€€€€€€€€€€€€€€€‰Í•É•Ð½…ÁÀˆ°(€€€€€€€€€€€€€€€ˆ‰Ù…±Õ”ˆ(€€€€€€€€€€€€¤ü¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕ‘¥ÑU¹…Ù…¥±…‰±•	•™½É•¹ÑÉä¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡ÉÕ¹Ñ¥µ”¹•¹•É…Ñ¥½¸ ¤°€À¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡ÉÕ¹Ñ¥µ”¹É•Ñ…¥¹•‘}É•ÅÕ•ÍÑ}½Õ¹Ð ¤°€À¤ì(€€€€€€€=¬  ¤¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸Á½ÍÑ}½µµ¥Ñ}…Õ‘¥Ñ}™…¥±ÕÉ•}¥Í}É•½¹¥±•}½¹±ä ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ½½Ð€ôI½½Ðèé¹•Ü ‰…Õ‘¥Ðµ…™Ñ•Èˆ¤üì(€€€€€€€±•Ð…Õ‘¥Ð€ôQ•ÍÑÕ‘¥Ðì(€€€€€€€€€€€™…¥±}½¹}…±°èM½µ” È¤°(€€€€€€€€€€€€¸¹Q•ÍÑÕ‘¥Ðèé‘•™…Õ±Ð ¤(€€€€€€€ôì(€€€€€€€±•ÐµÕÐÉÕ¹Ñ¥µ”€ôÍ•ÉÙ¥” ™É½½Ð°Q•ÍÑÕÑ¡½É¥é•Èì…±±½ÜèÑÉÕ”ô°…Õ‘¥Ð¤üì(€€€€€€€±•ÐÉ•ÅÕ•ÍÐ€ô¥¹‰½Õ¹¡ˆ‰Ñ½­•¸µ„ˆ°€‰É•ÅÕ•ÍÐµÁ½ÍÐµ…Õ‘¥Ðˆ°€‰Í•É•Ð½…ÁÀˆ°ˆ‰Ù…±Õ”ˆ¤üì(€€€€€€€±•ÐÉ•½Ù•Éå}É•™•É•¹”€ôµ…Ñ ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡É•ÅÕ•ÍÐ¹±½¹” ¤¤ì(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½Èèé=ÕÑ½µ•U¹­¹½Ý¸ìÉ•½Ù•Éå}É•™•É•¹”ô¤€ôøÉ•½Ù•Éå}É•™•É•¹”°(€€€€€€€€€€€½Ñ¡•È€ôøÉ•ÑÕÉ¸½Ñ¡•È¹µ…À¡ñ}ð€ ¤¤¹…¹¡ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤¤°(€€€€€€€ôì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•½¹¥±” ™É•½Ù•Éå}É•™•É•¹”¤°(€€€€€€€€€€€I•½¹¥±¥…Ñ¥½¹MÑ…ÑÕÌèé½µµ¥ÑÑ•ì•¹•É…Ñ¥½¸è€Äô(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„¡µ…Ñ¡•Ì„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡É•ÅÕ•ÍÐ¤ü°(€€€€€€€€€€€IÕ¹Ñ¥µ•=ÕÑ½µ”èéÕÁ±¥…Ñ”ì•¹•É…Ñ¥½¸è€Ä°€¸¸ô(€€€€€€€€¤¤ì(€€€€€€€=¬  ¤¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸‘ÕÉ…‰±•}Õ¹­¹½Ý¹}ÍÕÉÙ¥Ù•Í}É•ÍÑ…ÉÑ}…¹‘}É•½¹¥±•Ì ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ½½Ð€ôI½½Ðèé¹•Ü ‰É•ÍÑ…ÉÐˆ¤üì(€€€€€€€±•Ð‰…ÉÉ¥•È€ôQ•ÍÑ	…ÉÉ¥•Èèé¹•Ü ¤ì(€€€€€€€±•Ð‘ÕÉ…‰±”€ô(€€€€€€€€€€€ÕÉ…‰±•M•ÉÙ¥”èéÉ•…Ñ•}¹•Ü ™É½½Ð¸À°‰…ÉÉ¥•È¹±½¹” ¤°€ÌÈ¤¹µ…Á}•ÉÈ¡µ…Á}‘ÕÉ…‰±•}•ÉÉ½È¤üì(€€€€€€€±•ÐÉ•ÅÕ•ÍÐ€ô¥¹‰½Õ¹¡ˆ‰Ñ½­•¸µ„ˆ°€‰É•ÅÕ•ÍÐµÉ•ÍÑ…ÉÐˆ°€‰Í•É•Ð½…ÁÀˆ°ˆ‰Ù…±Õ”ˆ¤üì(€€€€€€€±•ÐÉ•½Ù•Éå}É•™•É•¹”€ôµ…Ñ ÉÕ¹Ñ¥µ”(€€€€€€€€€€€€¹¡…¹‘±•}Ý¥Ñ¡}™…¥±Á½¥¹Ð¡É•ÅÕ•ÍÐ¹±½¹” ¤°…¥±Á½¥¹Ðèé™Ñ•ÉM¹…ÁÍ¡½ÑAÕ‰±¥…Ñ¥½¸¤(€€€€€€€ì(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½Èèé=ÕÑ½µ•U¹­¹½Ý¸ìÉ•½Ù•Éå}É•™•É•¹”ô¤€ôøÉ•½Ù•Éå}É•™•É•¹”°(€€€€€€€€€€€½Ñ¡•È€ôøÉ•ÑÕÉ¸½Ñ¡•È¹µ…À¡ñ}ð€ ¤¤¹…¹¡ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤¤°(€€€€€€€ôì(€€€€€€€‘É½À¡ÉÕ¹Ñ¥µ”¤ì((€€€€€€€±•ÐÉ•½Á•¹•€ôÕÉ…‰±•M•ÉÙ¥”èéÉ•½Á•¸ ™É½½Ð¸À°‰…ÉÉ¥•È°€ÌÈ¤¹µ…Á}•ÉÈ¡µ…Á}‘ÕÉ…‰±•}•ÉÉ½È¤üì(€€€€€€€±•ÐµÕÐÉÕ¹Ñ¥µ”€ôIÕ¹Ñ¥µ•M•ÉÙ¥”èé¹•Ü (€€€€€€€€€€€Q•ÍÑÕÑ¡•¹Ñ¥…Ñ½È°(€€€€€€€€€€€Q•ÍÑÕÑ¡½É¥é•Èì…±±½ÜèÑÉÕ”ô°(€€€€€€€€€€€Q•ÍÑÕ‘¥Ðèé‘•™…Õ±Ð ¤°(€€€€€€€€€€€É•½Á•¹•°(€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•½¹¥±” ™É•½Ù•Éå}É•™•É•¹”¤°(€€€€€€€€€€€I•½¹¥±¥…Ñ¥½¹MÑ…ÑÕÌèé½µµ¥ÑÑ•ì•¹•É…Ñ¥½¸è€Äô(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„¡µ…Ñ¡•Ì„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡É•ÅÕ•ÍÐ¤ü°(€€€€€€€€€€€IÕ¹Ñ¥µ•=ÕÑ½µ”èéÕÁ±¥…Ñ”ì•¹•É…Ñ¥½¸è€Ä°€¸¸ô(€€€€€€€€¤¤ì(€€€€€€€=¬  ¤¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸‘•‰Õ}½ÕÑÁÕÑ}É•‘…ÑÍ}É•‘•¹Ñ¥…±Í}Á…Ñ¡Í}…¹‘}Í•É•Ð ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ•ÅÕ•ÍÐ€ô¥¹‰½Õ¹ (€€€€€€€€€€€ˆ‰Ñ½­•¸µ„ˆ°(€€€€€€€€€€€€‰É•ÅÕ•ÍÐµÉ•‘…Ñ•ˆ°(€€€€€€€€€€€€‰Í•É•Ð½¡¥ µÙ…±Õ”ˆ°(€€€€€€€€€€€ˆ‰¹•Ù•ÈµÁÉ¥¹Ðµµ”ˆ°(€€€€€€€€¤üì(€€€€€€€±•ÐÉ•¹‘•É•€ô™½Éµ…Ð„ ‰íÉ•ÅÕ•ÍÐèýôˆ¤ì(€€€€€€€™½ÈÍ•É•Ð¥¸l(€€€€€€€€€€€€‰Ñ½­•¸µ„ˆ°(€€€€€€€€€€€€‰É•ÅÕ•ÍÐµÉ•‘…Ñ•ˆ°(€€€€€€€€€€€€‰Í•É•Ð½¡¥ µÙ…±Õ”ˆ°(€€€€€€€€€€€€‰¹•Ù•ÈµÁÉ¥¹Ðµµ”ˆ°(€€€€€€€tì(€€€€€€€€€€€…ÍÍ•ÉÐ„ …É•¹‘•É•¹½¹Ñ…¥¹Ì¡Í•É•Ð¤¤ì(€€€€€€€ô(€€€€€€€=¬  ¤¤(€€€ô(€€€€mÑ•ÍÑt(€€€™¸…ÑÕ…±}¥½}™…¥±ÕÉ•}¥Í}¹•Ù•É}µ…ÁÁ•‘}Ñ½}É•©•Ñ¥½¸ ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ½½Ð€ôI½½Ðèé¹•Ü ‰…ÑÕ…°µ¥¼ˆ¤üì(€€€€€€€±•ÐµÕÐÉÕ¹Ñ¥µ”€ôÍ•ÉÙ¥” ™É½½Ð°Q•ÍÑÕÑ¡½É¥é•Èì…±±½ÜèÑÉÕ”ô°Q•ÍÑÕ‘¥Ðèé‘•™…Õ±Ð ¤¤üì(€€€€€€€™ÌèéÉ•…Ñ•}‘¥È¡É½½Ð¸À¹©½¥¸ ‰±•‘•È¹ÑµÀˆ¤¤¹µ…Á}•ÉÈ¡ñ}ðIÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤üì(€€€€€€€±•ÐÉ•™•É•¹”€ô(€€€€€€€€€€€µ…Ñ ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡¥¹‰½Õ¹¡ˆ‰Ñ½­•¸µ„ˆ°€‰É•ÅÕ•ÍÐµ¥¼ˆ°€‰Í•É•Ð½…ÁÀˆ°ˆ‰Í•É•Ðˆ¤ü¤ì(€€€€€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½Èèé=ÕÑ½µ•U¹­¹½Ý¸ìÉ•½Ù•Éå}É•™•É•¹”ô¤€ôøÉ•½Ù•Éå}É•™•É•¹”°(€€€€€€€€€€€€€€€|€ôøÉ•ÑÕÉ¸ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤°(€€€€€€€€€€€ôì(€€€€€€€…ÍÍ•ÉÐ„¡ÉÕ¹Ñ¥µ”¹É•½Ù•Éå}É•ÅÕ¥É• ¤¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•… (€€€€€€€€€€€€€€€€™É•‘•¹Ñ¥…°èé¹•Ü¡ˆ‰Ñ½­•¸µ„ˆ¹Ñ½}Ù•Œ ¤¤ü°(€€€€€€€€€€€€€€€€‰É½½Ð½Ñ•…´µ„ˆ°(€€€€€€€€€€€€€€€€‰Í•É•Ð½…ÁÀˆ°(€€€€€€€€€€€€€€€€‰É•…µÕ¹­¹½Ý¸ˆ(€€€€€€€€€€€€¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéI•½Ù•ÉåI•ÅÕ¥É•¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”(€€€€€€€€€€€€€€€€¹…Õ‘¥Ð(€€€€€€€€€€€€€€€€¹•Ù•¹ÑÌ(€€€€€€€€€€€€€€€€¹¥Ñ•È ¤(€€€€€€€€€€€€€€€€¹…¹ä¡ñ•ð”¹ÍÑ…” ¤€ôôÕ‘¥ÑMÑ…”èé=ÕÑ½µ•U¹­¹½Ý¸¤(€€€€€€€€¤ì(€€€€€€€‘É½À¡ÉÕ¹Ñ¥µ”¤ì(€€€€€€€™ÌèéÉ•µ½Ù•}‘¥È¡É½½Ð¸À¹©½¥¸ ‰±•‘•È¹ÑµÀˆ¤¤¹µ…Á}•ÉÈ¡ñ}ðIÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤üì(€€€€€€€±•Ð‘ÕÉ…‰±”€ô(€€€€€€€€€€€ÕÉ…‰±•M•ÉÙ¥”èéÉ•½Á•¸ ™É½½Ð¸À°Q•ÍÑ	…ÉÉ¥•Èèé¹•Ü ¤°€ÌÈ¤¹µ…Á}•ÉÈ¡µ…Á}‘ÕÉ…‰±•}•ÉÉ½È¤üì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€‘ÕÉ…‰±”¹É•½¹¥±” ™É•™•É•¹”¤°(€€€€€€€€€€€I•½¹¥±¥…Ñ¥½¹MÑ…ÑÕÌèé½µµ¥ÑÑ•ì•¹•É…Ñ¥½¸è€Äô(€€€€€€€€¤ì(€€€€€€€=¬  ¤¤(€€€ô((€€€€mÑ•ÍÑt(€€€™¸É•…‘}…¹‘}±¥ÍÑ}É•ÅÕ¥É•}…‘µ¥ÍÍ¥½¹}…¹‘}É•ÍÕ±Ñ}…Õ‘¥Ð ¤€´øI•ÍÕ±Ðð ¤°IÕ¹Ñ¥µ•ÉÉ½Èøì(€€€€€€€±•ÐÉ½½Ð€ôI½½Ðèé¹•Ü ‰ÅÕ•Éäµ…‘µ¥ÍÍ¥½¸ˆ¤üì(€€€€€€€±•ÐµÕÐÉÕ¹Ñ¥µ”€ôÍ•ÉÙ¥” ™É½½Ð°Q•ÍÑÕÑ¡½É¥é•Èì…±±½ÜèÑÉÕ”ô°Q•ÍÑÕ‘¥Ðèé‘•™…Õ±Ð ¤¤üì(€€€€€€€ÉÕ¹Ñ¥µ”¹¡…¹‘±”¡¥¹‰½Õ¹¡ˆ‰Ñ½­•¸µ„ˆ°€‰Í••ˆ°€‰Í•É•Ð½…ÁÀˆ°ˆ‰Í•É•Ðˆ¤ü¤üì(€€€€€€€±•ÐÙ…±¥€ôÉ•‘•¹Ñ¥…°èé¹•Ü¡ˆ‰Ñ½­•¸µ„ˆ¹Ñ½}Ù•Œ ¤¤üì(€€€€€€€±•Ð¥¹Ù…±¥€ôÉ•‘•¹Ñ¥…°èé¹•Ü¡ˆ‰¥¹Ù…±¥ˆ¹Ñ½}Ù•Œ ¤¤üì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•… ™¥¹Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð½…ÁÀˆ°€‰‘•¹¥•µÉ•…ˆ¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÑ¡•¹Ñ¥…Ñ¥½¹•¹¥•¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹±¥ÍÐ ™¥¹Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð¼ˆ°€‰‘•¹¥•µ±¥ÍÐˆ¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÑ¡•¹Ñ¥…Ñ¥½¹•¹¥•¤(€€€€€€€€¤ì(€€€€€€€ÉÕ¹Ñ¥µ”¹…ÕÑ¡½É¥é•È¹…±±½Ü€ô™…±Í”ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•… ™Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð½…ÁÀˆ°€‰Á½±¥äµÉ•…ˆ¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÑ¡½É¥é…Ñ¥½¹•¹¥•¤(€€€€€€€€¤ì(€€€€€€€ÉÕ¹Ñ¥µ”¹…ÕÑ¡½É¥é•È¹…±±½Ü€ôÑÉÕ”ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”(€€€€€€€€€€€€€€€€¹É•… ™Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð½…ÁÀˆ°€‰É•…ˆ¤ü(€€€€€€€€€€€€€€€€¹µ…À¡ñÍðÌ¹•áÁ½Í” ¤¹Ñ½}Ù•Œ ¤¤°(€€€€€€€€€€€M½µ”¡ˆ‰Í•É•Ðˆ¹Ñ½}Ù•Œ ¤¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹±¥ÍÐ ™Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð¼ˆ°€‰±¥ÍÐˆ¤ü°(€€€€€€€€€€€Ù•Œ…l‰…ÁÀ‰t(€€€€€€€€¤ì(€€€€€€€±•Ð•Ù•¹Ð€ôÉÕ¹Ñ¥µ”(€€€€€€€€€€€€¹…Õ‘¥Ð(€€€€€€€€€€€€¹•Ù•¹ÑÌ(€€€€€€€€€€€€¹±…ÍÐ ¤(€€€€€€€€€€€€¹½­}½È¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕÉ…‰±•I•©•Ñ•¤üì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡•Ù•¹Ð¹ÍÑ…” ¤°Õ‘¥ÑMÑ…”èé1¥ÍÑ½µÁ±•Ñ•¤ì(€€€€€€€…ÍÍ•ÉÑ}¹”„¡•Ù•¹Ð¹É•ÅÕ•ÍÑ}™¥¹•ÉÁÉ¥¹Ð ¤°€™lÀì€ÌÉt¤ì(€€€€€€€…ÍÍ•ÉÐ„ …™½Éµ…Ð„ ‰í•Ù•¹Ðèýôˆ¤¹½¹Ñ…¥¹Ì ™™½Éµ…Ð„ ‰ìèýôˆ°•Ù•¹Ð¹É•ÅÕ•ÍÑ}™¥¹•ÉÁÉ¥¹Ð ¤¤¤¤ì(€€€€€€€ÉÕ¹Ñ¥µ”¹…Õ‘¥Ð¹™…¥±}½¹}…±°€ôM½µ”¡ÉÕ¹Ñ¥µ”¹…Õ‘¥Ð¹…±±Ì€¬€È¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€ÉÕ¹Ñ¥µ”¹É•… ™Ù…±¥°€‰É½½Ð½Ñ•…´µ„ˆ°€‰Í•É•Ð½…ÁÀˆ°€‰¹¼µÉ•±•…Í”ˆ¤°(€€€€€€€€€€€ÉÈ¡IÕ¹Ñ¥µ•ÉÉ½ÈèéÕ‘¥ÑU¹…Ù…¥±…‰±•™Ñ•ÉI•…¤(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡ÉÕ¹Ñ¥µ”¹•¹•É…Ñ¥½¸ ¤°€Ä¤ì(€€€€€€€=¬  ¤¤(€€€ô)ô(