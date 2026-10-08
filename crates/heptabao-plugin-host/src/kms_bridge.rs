//! Closed transport DTO for the genuine OpenBao KMS adapter.
//! This module supplies no HTTP authority. A Service plan must separately retain
//! the admitted provider, actor, original clock, record root and original HA role.
use super::{PluginHost, PluginHostError, PluginOperation, SandboxRunner, SecretEnvironment};
use heptabao_domain::SecretValue;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

const MAXIMUM: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Metadata,
    ValidateConfig,
    ValidateKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    ExportPublic,
}
impl Operation {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::ValidateConfig => "validate_config",
            Self::ValidateKey => "validate_key",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::ExportPublic => "export_public",
        }
    }
}
struct ErasedJson(Value);
impl Drop for ErasedJson {
    fn drop(&mut self) {
        erase_value(&mut self.0);
    }
}
fn erase_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(erase_value),
        Value::Object(m) => m.values_mut().for_each(erase_value),
        _ => {}
    }
    *v = Value::Null;
}
pub struct Invocation {
    operation: Operation,
    nonce: String,
    request: SecretValue,
}
impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}
impl Invocation {
    /// Input is copied from an already-authorized private Service plan.
    /// Deployment executable/library/environment data is not accepted here.
    pub fn new(operation: Operation, input: &SecretValue) -> Result<Self, PluginHostError> {
        let mut v = ErasedJson(
            serde_json::from_slice(input.expose())
                .map_err(|_| PluginHostError::MalformedResponse)?,
        );
        let m =
            v.0.as_object_mut()
                .ok_or(PluginHostError::MalformedResponse)?;
        if m.keys().any(|key| {
            !matches!(
                key.as_str(),
                "config"
                    | "key"
                    | "data"
                    | "aad"
                    | "signature"
                    | "hash"
                    | "prehashed"
                    | "scheme"
                    | "salt_length"
                    | "ed_context"
                    | "marshaling"
            )
        }) {
            return Err(PluginHostError::MalformedResponse);
        }
        if operation != Operation::Metadata && !m.get("config").is_some_and(Value::is_object) {
            return Err(PluginHostError::MalformedResponse);
        }
        if !matches!(operation, Operation::Metadata | Operation::ValidateConfig)
            && !m.get("key").is_some_and(Value::is_object)
        {
            return Err(PluginHostError::MalformedResponse);
        }
        let mut bytes = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| PluginHostError::SandboxUnavailable)?;
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        bytes.zeroize();
        m.insert("version".into(), json!(1));
        m.insert("nonce".into(), json!(nonce));
        m.insert("operation".into(), json!(operation.wire()));
        let mut b = Zeroizing::new(
            serde_json::to_vec(&v.0).map_err(|_| PluginHostError::MalformedResponse)?,
        );
        if b.len() > MAXIMUM {
            return Err(PluginHostError::RequestTooLarge);
        }
        let request = SecretValue::new(std::mem::take(&mut *b)).map_err(PluginHostError::Domain)?;
        Ok(Self {
            operation,
            nonce,
            request,
        })
    }
    /// A result can originate only from the actual admitted host invocation.
    pub fn invoke<R: SandboxRunner>(
        &self,
        host: &mut PluginHost<R>,
        environment: &SecretEnvironment,
    ) -> Result<ProviderResult, PluginHostError> {
        let reply = host.invoke(PluginOperation::Read, &self.request, environment)?;
        self.decode(&reply)
    }
    fn decode(&self, reply: &SecretValue) -> Result<ProviderResult, PluginHostError> {
        let v = ErasedJson(
            serde_json::from_slice(reply.expose())
                .map_err(|_| PluginHostError::MalformedResponse)?,
        );
        let m = v.0.as_object().ok_or(PluginHostError::MalformedResponse)?;
        if m.len() != 7
            || m.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "version" | "nonce" | "operation" | "status" | "phase" | "result" | "lifecycle"
                )
            })
            || m.get("version").and_then(Value::as_u64) != Some(1)
            || m.get("nonce").and_then(Value::as_str) != Some(self.nonce.as_str())
            || m.get("operation").and_then(Value::as_str) != Some(self.operation.wire())
        {
            return Err(PluginHostError::MalformedResponse);
        }
        let life = m
            .get("lifecycle")
            .and_then(Value::as_object)
            .ok_or(PluginHostError::MalformedResponse)?;
        let life_fields = [
            "started",
            "pid",
            "birth",
            "pgid",
            "sid",
            "original_wait",
            "exit_code",
            "identity_gap",
            "signal_error",
            "forced",
            "group_retired",
            "pins_unchanged",
            "qualified",
        ];
        if life.len() != life_fields.len()
            || life.keys().any(|k| !life_fields.contains(&k.as_str()))
            || [
                "started",
                "original_wait",
                "group_retired",
                "pins_unchanged",
                "qualified",
            ]
            .iter()
            .any(|k| life.get(*k).and_then(Value::as_bool) != Some(true))
            || ["identity_gap", "signal_error", "forced"]
                .iter()
                .any(|k| life.get(*k).and_then(Value::as_bool) != Some(false))
            || life.get("exit_code").and_then(Value::as_i64) != Some(0)
            || !life
                .get("pid")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
            || life.get("pid") != life.get("pgid")
            || !life
                .get("sid")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
            || !life
                .get("birth")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(PluginHostError::ProcessOutcomeUnknown);
        }
        match m.get("status").and_then(Value::as_str) {
            Some("completed") => {}
            Some("not_implemented") if m.get("result") == Some(&Value::Null) => {
                return Ok(ProviderResult::NotImplemented);
            }
            Some("provider_error") if m.get("result") == Some(&Value::Null) => {
                return Ok(ProviderResult::Rejected);
            }
            _ => return Err(PluginHostError::ProcessOutcomeUnknown),
        }
        let phase = match self.operation {
            Operation::Metadata => "metadata",
            Operation::ValidateConfig => "open",
            Operation::ValidateKey => "key",
            _ => "crypto",
        };
        if m.get("phase").and_then(Value::as_str) != Some(phase) {
            return Err(PluginHostError::MalformedResponse);
        }
        let result = m
            .get("result")
            .and_then(Value::as_object)
            .ok_or(PluginHostError::MalformedResponse)?;
        match self.operation {
            Operation::Metadata => {
                if result.len() != 2 {
                    return Err(PluginHostError::MalformedResponse);
                }
                Ok(ProviderResult::Metadata(Metadata {
                    config: fields(result.get("sensitive_kms_fields"))?,
                    key: fields(result.get("sensitive_key_fields"))?,
                }))
            }
            Operation::ValidateConfig => {
                if result.len() != 1 || result.get("opened").and_then(Value::as_bool) != Some(true)
                {
                    return Err(PluginHostError::MalformedResponse);
                }
                Ok(ProviderResult::ConfigOpened)
            }
            Operation::ValidateKey => {
                if result.len() != 1
                    || result.get("key_resolved").and_then(Value::as_bool) != Some(true)
                {
                    return Err(PluginHostError::MalformedResponse);
                }
                Ok(ProviderResult::KeyResolved)
            }
            Operation::Verify => {
                if result.len() != 1 {
                    return Err(PluginHostError::MalformedResponse);
                }
                Ok(ProviderResult::Verified(
                    result
                        .get("valid")
                        .and_then(Value::as_bool)
                        .ok_or(PluginHostError::MalformedResponse)?,
                ))
            }
            operation => {
                let key = match operation {
                    Operation::Encrypt => "ciphertext",
                    Operation::Decrypt => "plaintext",
                    Operation::Sign => "signature",
                    Operation::ExportPublic => "public_key",
                    _ => return Err(PluginHostError::MalformedResponse),
                };
                let encoded = result
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or(PluginHostError::MalformedResponse)?;
                if result.len() != 1 || !canonical_base64(encoded) {
                    return Err(PluginHostError::MalformedResponse);
                }
                Ok(ProviderResult::Bytes {
                    operation,
                    // Only encoded provider bytes; Service chooses its real wire presentation.
                    encoded: SecretValue::new(encoded.as_bytes().to_vec())
                        .map_err(PluginHostError::Domain)?,
                })
            }
        }
    }
}
fn fields(value: Option<&Value>) -> Result<BTreeSet<String>, PluginHostError> {
    value
        .and_then(Value::as_array)
        .ok_or(PluginHostError::MalformedResponse)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(PluginHostError::MalformedResponse)
        })
        .collect()
}
fn canonical_base64(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return true;
    }
    if b.len() % 4 != 0 {
        return false;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return false;
    }
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if b[..b.len() - pad].iter().any(|&c| sextet(c).is_none()) {
        return false;
    }
    let last = sextet(b[b.len() - pad - 1]).unwrap_or(0);
    pad == 0 || pad == 1 && last & 3 == 0 || pad == 2 && last & 15 == 0
}
pub struct Metadata {
    config: BTreeSet<String>,
    key: BTreeSet<String>,
}
impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metadata").finish_non_exhaustive()
    }
}
impl Metadata {
    /// Exact field presence only. Metadata cannot replace registry values or mint authority.
    pub fn redact(&self, values: &mut Value, config: bool) -> Result<(), PluginHostError> {
        let m = values
            .as_object_mut()
            .ok_or(PluginHostError::MalformedResponse)?;
        for key in if config { &self.config } else { &self.key } {
            if let Some(v) = m.get_mut(key) {
                erase_value(v);
                *v = Value::String("(redacted)".into());
            }
        }
        Ok(())
    }
}
pub enum ProviderResult {
    Metadata(Metadata),
    ConfigOpened,
    KeyResolved,
    Bytes {
        operation: Operation,
        encoded: SecretValue,
    },
    Verified(bool),
    Rejected,
    NotImplemented,
}
impl std::fmt::Debug for ProviderResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderResult([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn secret(v: Value) -> Result<SecretValue, PluginHostError> {
        SecretValue::new(serde_json::to_vec(&v).map_err(|_| PluginHostError::MalformedResponse)?)
            .map_err(PluginHostError::Domain)
    }
    fn reply(inv: &Invocation, result: Value) -> Value {
        json!({"version":1,"nonce":inv.nonce,"operation":inv.operation.wire(),"status":"completed",
            "phase":if inv.operation==Operation::Metadata {"metadata"} else {"crypto"},"result":result,"lifecycle":{"started":true,"pid":42,"birth":"123",
            "pgid":42,"sid":41,"original_wait":true,"exit_code":0,"identity_gap":false,
            "signal_error":false,"forced":false,"group_retired":true,"pins_unchanged":true,"qualified":true}})
    }
    #[test]
    fn genuine_kms_crypto_result_cannot_be_replaced_by_verification_ack()
    -> Result<(), PluginHostError> {
        let inv = Invocation::new(
            Operation::Encrypt,
            &secret(json!({"config":{},"key":{},"data":"YQ=="}))?,
        )?;
        assert!(
            inv.decode(&secret(reply(&inv, json!({"verified":true})))?)
                .is_err()
        );
        assert!(matches!(
            inv.decode(&secret(reply(&inv, json!({"ciphertext":"YQ=="})))?)?,
            ProviderResult::Bytes {
                operation: Operation::Encrypt,
                ..
            }
        ));
        Ok(())
    }
    #[test]
    fn genuine_kms_metadata_requires_original_nonce_and_completed_owned_wait()
    -> Result<(), PluginHostError> {
        let inv = Invocation::new(Operation::Metadata, &secret(json!({}))?)?;
        let positive = reply(
            &inv,
            json!({"sensitive_kms_fields":["custom\nfield"],"sensitive_key_fields":[]}),
        );
        let ProviderResult::Metadata(meta) = inv.decode(&secret(positive.clone())?)? else {
            return Err(PluginHostError::MalformedResponse);
        };
        let mut values =
            json!({"custom\nfield":"opaque","token":"retained","tls_client_key":"retained"});
        meta.redact(&mut values, true)?;
        assert!(
            values
                == json!({"custom\nfield":"(redacted)","token":"retained","tls_client_key":"retained"})
        );
        let mut wrong = positive.clone();
        wrong["nonce"] = json!("00");
        assert!(inv.decode(&secret(wrong)?).is_err());
        let mut gap = positive;
        gap["lifecycle"]["original_wait"] = json!(false);
        assert!(inv.decode(&secret(gap)?).is_err());
        Ok(())
    }
    #[test]
    fn genuine_kms_request_cannot_select_operator_image_library_or_rpc_timeout()
    -> Result<(), PluginHostError> {
        for forbidden in [
            "provider",
            "image",
            "image_sha256",
            "libraries",
            "env",
            "timeout_ms",
            "deadline_monotonic_ns",
            "nonce",
        ] {
            let mut input = json!({});
            input[forbidden] = json!("client-chosen");
            assert!(Invocation::new(Operation::Metadata, &secret(input)?).is_err());
        }
        Ok(())
    }
    #[test]
    fn genuine_kms_crypto_scope_rejects_wrong_operation_phase_and_foreign_fields()
    -> Result<(), PluginHostError> {
        let inv = Invocation::new(
            Operation::Encrypt,
            &secret(json!({"config":{},"key":{},"data":"YQ=="}))?,
        )?;
        let positive = reply(&inv, json!({"ciphertext":"YQ=="}));
        for (key, value) in [
            ("operation", json!("verify")),
            ("phase", json!("key")),
            ("nonce", json!("foreign")),
        ] {
            let mut bad = positive.clone();
            bad[key] = value;
            assert!(inv.decode(&secret(bad)?).is_err());
        }
        let mut extra = positive.clone();
        extra["result"]["verified"] = json!(true);
        assert!(inv.decode(&secret(extra)?).is_err());
        for (key, value) in [
            ("exit_code", json!(1)),
            ("identity_gap", json!(true)),
            ("signal_error", json!(true)),
            ("forced", json!(true)),
            ("group_retired", json!(false)),
            ("pins_unchanged", json!(false)),
        ] {
            let mut bad = positive.clone();
            bad["lifecycle"][key] = value;
            assert!(inv.decode(&secret(bad)?).is_err());
        }
        Ok(())
    }
}
