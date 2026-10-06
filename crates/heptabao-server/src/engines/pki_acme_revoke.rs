//! Public ACME revocation retains the admitted proof and original certificate.
//! Neither an account JWS nor leaf-key possession becomes a Vault principal.
use super::acme_jws::{Jwk, VerifiedJws};
use super::acme_state::{AccountStatus, Binding, Protocol};
use super::*;
use crate::auth::{LeaseOwner, RequestClock, Timestamp};
use openssl::pkey::PKey;

pub(crate) struct Request<'a> {
    pub key: &'a Jwk,
    pub proof: &'a VerifiedJws,
    pub kid: Option<&'a str>,
    pub at: Timestamp,
    pub clock: Option<RequestClock>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Proof {
    Account {
        account: String,
        thumbprint: String,
    },
    Possession {
        jwk: Jwk,
    },
    Administrative {
        issuer: LeaseOwner,
        expires_at: Option<u64>,
        precise_expires_at: Option<Timestamp>,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revocation {
    pub owner: Binding,
    pub issuer: String,
    pub serial: String,
    pub certificate: Vec<u8>,
    pub at: Timestamp,
    pub proof: Proof,
}
fn malformed(detail: &str) -> EngineError {
    bad(&format!("{detail}: the request message was malformed"))
}
fn parse_certificate(payload: &Value) -> Result<Vec<u8>> {
    let value = payload
        .get("certificate")
        .ok_or_else(|| malformed("bad request was lacking required field 'certificate'"))?;
    let text = value.as_str().ok_or_else(|| {
        malformed(&format!(
            "invalid type ({}; expected string) for field 'certificate'",
            acme_orders::go_type(value)
        ))
    })?;
    if text.len() > 90 * 1024 {
        return Err(malformed("certificate exceeds bounds"));
    }
    let cleaned: String = text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    let decoder = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let raw = decoder.decode(&cleaned).map_err(|_| {
        let index = text
            .bytes()
            .position(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'\r' | b'\n'))
            .unwrap_or(text.len().saturating_sub(1));
        malformed(&format!(
            "failed to base64 decode certificate: illegal base64 data at input byte {index}"
        ))
    })?;
    let (rest, _) = x509_parser::parse_x509_certificate(&raw)
        .map_err(|_| malformed("failed to parse certificate: x509: malformed certificate"))?;
    if !rest.is_empty() {
        return Err(malformed(
            "failed to parse certificate: x509: trailing data",
        ));
    }
    if let Some(reason) = payload.get("reason") {
        let reason = reason.as_f64().ok_or_else(|| {
            malformed(&format!(
                "invalid type ({}; expected float64) for field 'reason'",
                acme_orders::go_type(reason)
            ))
        })?;
        let integral = reason as i64;
        if integral != 0 {
            return Err(bad(&format!(
                "OpenBao does not support revocation reasons (got {integral}; expected omitted or 0/unspecified): the revocation reason provided is not allowed by the server"
            )));
        }
    }
    Ok(raw)
}
impl Revocation {
    fn validate(&self, protocol: &Protocol, clock: Timestamp) -> Result<()> {
        let (rest, cert) = x509_parser::parse_x509_certificate(&self.certificate)
            .map_err(|_| bad("invalid ACME revoked certificate DER"))?;
        if !rest.is_empty()
            || self.owner != protocol.owner
            || self.issuer.is_empty()
            || self.issuer.len() > 256
            || normalize_serial(&self.serial)? != self.serial
            || der(2, cert.raw_serial()) != integer(&serial_bytes(&self.serial)?)
            || self.at > clock
            || cert.validity().not_after.timestamp()
                < i64::try_from(self.at.seconds())
                    .map_err(|_| bad("invalid ACME revocation timestamp"))?
            || cert.signature_value.unused_bits != 0
            || cert.signature_algorithm != cert.tbs_certificate.signature
        {
            return Err(bad("ACME durable revocation owner rejected"));
        }
        match &self.proof {
            Proof::Account {
                account,
                thumbprint,
            } => {
                let account = protocol
                    .accounts
                    .get(account)
                    .filter(|a| {
                        a.thumbprint == *thumbprint
                            && a.created <= self.at
                            && a.deactivated.is_none_or(|retired| self.at <= retired)
                    })
                    .ok_or_else(|| bad("ACME revocation account owner rejected"))?;
                if !protocol.orders.values().any(|o| {
                    o.account == account.id
                        && o.account_thumbprint == *thumbprint
                        && o.certificate.as_ref().is_some_and(|c| {
                            c.der == self.certificate
                                && c.serial == self.serial
                                && c.issuer == self.issuer
                                && c.created <= self.at
                        })
                }) {
                    return Err(bad("ACME revocation certificate account rejected"));
                }
            }
            Proof::Administrative {
                issuer,
                expires_at,
                precise_expires_at,
            } => {
                issuer
                    .validate_scope(
                        &protocol.owner.namespace,
                        crate::auth::ServiceOwnerProfile::DigestAlphabet,
                    )
                    .map_err(|_| bad("ACME administrative revocation owner rejected"))?;
                if precise_expires_at
                    .is_some_and(|end| *expires_at != end.ceil_seconds().ok() || self.at > end)
                    || precise_expires_at.is_none()
                        && expires_at.is_some_and(|end| self.at.seconds() >= end)
                    || issuer.batch_claims().is_some_and(|claims| {
                        self.at.seconds() < claims.issued_at()
                            || self.at.seconds() > claims.expires_at()
                    })
                {
                    return Err(bad(
                        "ACME administrative revocation original actor window rejected",
                    ));
                }
            }
            Proof::Possession { jwk } => {
                let public = PKey::public_key_from_der(cert.public_key().raw)
                    .map_err(|_| bad("invalid ACME revoked public key"))?;
                if !jwk.public_key()?.public_eq(&public) {
                    return Err(bad("ACME revocation possession owner rejected"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn descriptor(&self) -> Value {
        json!({"revocation_time":self.at.seconds(),"revocation_time_rfc3339":self.at.rfc3339(),"state":"revoked"})
    }
}
impl Protocol {
    pub(crate) fn validate_revocations(&self) -> Result<()> {
        if self.revocations.len() > 8192 {
            return Err(bad("ACME revocation capacity rejected"));
        }
        for (serial, revoked) in &self.revocations {
            if serial != &revoked.serial {
                return Err(bad("ACME revocation serial owner rejected"));
            }
            revoked.validate(self, self.clock)?;
        }
        Ok(())
    }
}
impl Pki {
    pub(super) fn acme_revocation(&self, serial: &str) -> Option<&Revocation> {
        self.acme_protocol.as_ref()?.revocations.get(serial)
    }
    pub(super) fn acme_administrative_revocation_owners(
        &self,
    ) -> impl Iterator<Item = &LeaseOwner> {
        self.acme_protocol
            .iter()
            .flat_map(|p| p.revocations.values())
            .filter_map(|r| match &r.proof {
                Proof::Administrative { issuer, .. } => Some(issuer),
                _ => None,
            })
    }

    pub(in crate::engines) fn revoke_acme_by_operator(
        &mut self,
        body: &Value,
        context: crate::engines::PkiRequestContext<'_>,
        before_effect: &mut impl FnMut() -> Result<()>,
    ) -> Result<Option<EngineResponse>> {
        reject_unknown(body, &["serial_number"])?;
        let serial = self.resolve_certificate_serial(string(body, "serial_number")?)?;
        let Some(cert) = self.acme_certificate_for_serial(&serial)? else {
            return Ok(None);
        };
        if let Some(prior) = self.acme_revocation(&serial) {
            return Ok(Some(ok(prior.descriptor(), false)));
        }
        let actor = context
            .owner
            .ok_or_else(|| error(403, "administrative PKI revocation requires actual caller"))?;
        let observed = context.observed_time(0)?;
        let at = observed
            .exact()
            .or_else(|| Timestamp::whole(observed.seconds()).ok())
            .ok_or_else(|| {
                error(
                    503,
                    "administrative ACME revocation original clock unavailable",
                )
            })?;
        let floor = self
            .acme_protocol
            .as_ref()
            .ok_or_else(|| error(503, "ACME administrative protocol unavailable"))?
            .clock
            .max(at);
        let at = context
            .clock
            .map(|c| c.with_timestamp_floor(floor).observed_at())
            .transpose()
            .map_err(|_| {
                error(
                    503,
                    "administrative ACME revocation original clock unavailable",
                )
            })?
            .unwrap_or(floor);
        if actor.precise_expires_at.is_some_and(|end| at > end)
            || actor.precise_expires_at.is_none()
                && actor.expires_at.is_some_and(|end| at.seconds() >= end)
        {
            return Err(error(
                403,
                "administrative PKI original caller expired before signing",
            ));
        }
        if cert.expires < at.seconds().saturating_add(2) && !self.local_expired_revocation_allowed()
        {
            return Ok(Some(EngineResponse {
                status: 200,
                body: json!({"warnings":["certificate already expired; refusing to add to CRL"]}),
                mutated: false,
            }));
        }
        let protocol = self
            .acme_protocol
            .as_ref()
            .ok_or_else(|| error(503, "ACME administrative protocol unavailable"))?;
        let revoked = Revocation {
            owner: protocol.owner.clone(),
            issuer: cert.issuer.clone(),
            serial: serial.clone(),
            certificate: cert.der.clone(),
            at,
            proof: Proof::Administrative {
                issuer: actor.owner.clone(),
                expires_at: actor.expires_at,
                precise_expires_at: actor.precise_expires_at,
            },
        };
        revoked.validate(protocol, at)?;
        before_effect()?;
        self.local_issuer(&revoked.issuer)?.local_key()?;
        let response = revoked.descriptor();
        let protocol = self
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME administrative protocol unavailable"))?;
        protocol.observe_time(at);
        protocol.revocations.insert(serial, revoked);
        self.local_revocation_changed_guarded(at.seconds(), &mut || {
            before_effect()?;
            let observed = context
                .clock
                .map(|c| c.with_timestamp_floor(at).observed_at())
                .transpose()
                .map_err(|_| {
                    error(
                        503,
                        "administrative ACME revocation original clock unavailable",
                    )
                })?
                .unwrap_or(at);
            if actor.precise_expires_at.is_some_and(|end| observed > end)
                || actor.precise_expires_at.is_none()
                    && actor
                        .expires_at
                        .is_some_and(|end| observed.seconds() >= end)
            {
                return Err(error(
                    403,
                    "administrative PKI original caller expired before signing",
                ));
            }
            Ok(())
        })?;
        self.validate_acme_revocations()?;
        Ok(Some(ok(response, true)))
    }

    pub(super) fn acme_revoked_for_issuer(&self, issuer: &str) -> BTreeMap<String, u64> {
        self.acme_protocol
            .iter()
            .flat_map(|p| p.revocations.values())
            .filter(|r| r.issuer == issuer)
            .map(|r| (r.serial.clone(), r.at.seconds()))
            .collect()
    }
    pub(super) fn validate_acme_revocations(&self) -> Result<()> {
        for revoked in self
            .acme_protocol
            .iter()
            .flat_map(|p| p.revocations.values())
        {
            if let Some(cert) = self.acme_certificate_for_serial(&revoked.serial)? {
                if cert.der != revoked.certificate
                    || cert.issuer != revoked.issuer
                    || cert.created > revoked.at
                {
                    return Err(bad("ACME revocation signed asset changed"));
                }
            } else {
                let cert = self
                    .issued
                    .get(&revoked.serial)
                    .ok_or_else(|| bad("ACME revoked global certificate missing"))?;
                if cert.certificate_der != revoked.certificate
                    || cert.local_issuer_id != revoked.issuer
                    || cert.revoked_at != Some(revoked.at.seconds())
                    || cert.issued > revoked.at.seconds()
                    || cert.external_issuer_owner.is_some()
                    || self.profile_leaf_is_external(&revoked.serial)
                {
                    return Err(bad("ACME global revocation certificate owner rejected"));
                }
            }
        }
        Ok(())
    }
    pub(in crate::engines) fn acme_revoke_certificate(
        &mut self,
        key: &Jwk,
        proof: &VerifiedJws,
        account: Option<&str>,
        at: Timestamp,
        clock: Option<RequestClock>,
        mut before_effect: impl FnMut() -> Result<()>,
    ) -> Result<Value> {
        if key.thumbprint()? != proof.key_thumbprint() {
            return Err(error(401, "the client lacks sufficient authorization"));
        }
        let empty = json!({});
        let raw = parse_certificate(proof.payload().unwrap_or(&empty))?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&raw)
            .map_err(|_| malformed("failed to parse certificate: x509: malformed certificate"))?;
        let expires = u64::try_from(parsed.validity().not_after.timestamp())
            .map_err(|_| malformed("refusing to revoke expired certificate"))?;
        if Timestamp::whole(expires).map_err(|_| malformed("invalid certificate expiry"))? < at {
            return Err(malformed("refusing to revoke expired certificate"));
        }
        let serial =
            self.resolve_certificate_serial(&canonical_serial_bytes(parsed.raw_serial()))?;
        let (stored, issuer, prior) = if let Some(cert) =
            self.acme_certificate_for_serial(&serial)?
        {
            (
                &cert.der,
                cert.issuer.clone(),
                self.acme_revocation(&serial).is_some(),
            )
        } else if let Some(cert) = self.issued.get(&serial) {
            if cert.external_issuer_owner.is_some() || self.profile_leaf_is_external(&serial) {
                return Err(error(
                    501,
                    "external ACME revocation requires a qualified provider signing lane",
                ));
            }
            (
                &cert.certificate_der,
                cert.local_issuer_id.clone(),
                cert.revoked_at.is_some(),
            )
        } else {
            return Err(error(
                500,
                "unable to revoke certificate: no global cert entry found: the server experienced an internal error",
            ));
        };
        if stored != &raw {
            return Err(malformed(
                "unable to revoke certificate: supplied certificate does not match CA's stored value",
            ));
        }
        if prior {
            return Err(bad(
                "unable to revoke certificate: the request specified a certificate to be revoked that has already been revoked",
            ));
        }
        let protocol = self
            .acme_protocol
            .as_ref()
            .ok_or_else(|| error(503, "ACME revocation protocol unavailable"))?;
        let authorization = if let Some(id) = account {
            let account = protocol
                .accounts
                .get(id)
                .filter(|a| {
                    a.status == AccountStatus::Valid && a.thumbprint == proof.key_thumbprint()
                })
                .ok_or_else(|| error(401, "the client lacks sufficient authorization"))?;
            if !protocol.orders.values().any(|o| {
                o.account == id
                    && o.certificate
                        .as_ref()
                        .is_some_and(|c| c.serial == serial && c.der == raw)
            }) {
                return Err(malformed(
                    "unable to revoke certificate: no certificate with this serial was issued for this account",
                ));
            }
            Proof::Account {
                account: id.to_owned(),
                thumbprint: account.thumbprint.clone(),
            }
        } else {
            let public = PKey::public_key_from_der(parsed.public_key().raw).map_err(|_| {
                malformed("unable to revoke certificate: unable to parse certificate public key")
            })?;
            if !key.public_key()?.public_eq(&public) {
                return Err(malformed(
                    "unable to revoke certificate: unable to verify proof of possession of private key provided by proxy: provided private key does not match certificate's public key",
                ));
            }
            Proof::Possession { jwk: key.clone() }
        };
        let at = clock
            .map(|c| c.with_timestamp_floor(at).observed_at())
            .transpose()
            .map_err(|_| error(503, "ACME revocation original clock unavailable"))?
            .unwrap_or(at);
        if Timestamp::whole(expires).map_err(|_| malformed("invalid certificate expiry"))? < at {
            return Err(malformed("refusing to revoke expired certificate"));
        }
        let revoked = Revocation {
            owner: protocol.owner.clone(),
            issuer,
            serial: serial.clone(),
            certificate: raw,
            at,
            proof: authorization,
        };
        revoked.validate(protocol, at)?;
        before_effect()?;
        // Prove the selected issuer remains local before any durable mutation.
        self.local_issuer(&revoked.issuer)?.local_key()?;
        if let Some(cert) = self.issued.get_mut(&serial) {
            cert.revoked_at = Some(at.seconds());
        }
        let response = revoked.descriptor();
        let protocol = self
            .acme_protocol
            .as_mut()
            .ok_or_else(|| error(503, "ACME revocation protocol unavailable"))?;
        protocol.observe_time(at);
        protocol.revocations.insert(serial, revoked);
        self.local_revocation_changed_guarded(at.seconds(), &mut before_effect)?;
        self.validate_acme_revocations()?;
        Ok(response)
    }
}
