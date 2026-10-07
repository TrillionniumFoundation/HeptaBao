//! Private PKI comparisons retain RFC3339 nanoseconds and signed dates. X.509
//! encoding and the public expiration projection remain integer seconds.
use super::*;
use crate::auth::{AuthorityTime, RequestClock, Timestamp};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct PkiInstant {
    seconds: i64,
    nanos: u32,
}
impl PkiInstant {
    pub(super) fn whole(seconds: u64) -> Result<Self> {
        Ok(Self {
            seconds: role_time::signed_epoch(seconds)?,
            nanos: 0,
        })
    }
    pub(super) fn authority(time: AuthorityTime) -> Result<Self> {
        let span = time.exact().map(Timestamp::duration_since_epoch);
        Ok(Self {
            seconds: role_time::signed_epoch(time.seconds())?,
            nanos: span.map_or(0, |span| span.subsec_nanos()),
        })
    }
    pub(super) fn absolute(value: &str, field: &str) -> Result<Self> {
        let seconds = root_fields::rfc3339_signed_seconds(value)
            .map_err(|_| bad(&format!("invalid PKI {field}")))?;
        let bytes = value.as_bytes();
        let nanos = if bytes.get(19) == Some(&b'.') {
            let end = bytes[20..]
                .iter()
                .position(|b| !b.is_ascii_digit())
                .map(|end| end + 20)
                .ok_or_else(|| bad("invalid PKI timestamp fraction"))?;
            let fraction = &value[20..end];
            fraction
                .parse::<u32>()
                .map_err(|_| bad("invalid PKI timestamp fraction"))?
                * 10u32.pow(
                    u32::try_from(9 - fraction.len())
                        .map_err(|_| bad("invalid PKI timestamp fraction"))?,
                )
        } else {
            0
        };
        Ok(Self { seconds, nanos })
    }
    pub(super) fn seconds(self) -> i64 {
        self.seconds
    }
    pub(super) fn positive_seconds(self) -> Result<u64> {
        u64::try_from(self.seconds).map_err(|_| bad("invalid PKI not_after"))
    }
    pub(super) fn add(self, seconds: u64) -> Result<Self> {
        let seconds = self
            .seconds
            .checked_add(role_time::signed_epoch(seconds)?)
            .filter(|seconds| *seconds <= 253_402_300_799)
            .ok_or_else(|| bad("PKI lease TTL overflow"))?;
        Ok(Self { seconds, ..self })
    }
    pub(super) fn backdate(self, seconds: u64, signed: bool) -> Result<Self> {
        let seconds = self
            .seconds
            .checked_sub(role_time::signed_epoch(seconds)?)
            .filter(|seconds| *seconds >= -62_167_219_200)
            .ok_or_else(|| bad("PKI timestamp exceeds supported calendar"))?;
        Ok(Self {
            seconds: if signed { seconds } else { seconds.max(0) },
            ..self
        })
    }
    pub(super) fn render(self) -> String {
        let whole = role_time::signed_timestamp(self.seconds);
        if self.nanos == 0 {
            return whole;
        }
        let fraction = format!("{:09}", self.nanos);
        format!(
            "{}.{}Z",
            whole.trim_end_matches('Z'),
            fraction.trim_end_matches('0')
        )
    }
}

pub(in crate::engines) fn observe(
    time: AuthorityTime,
    clock: Option<RequestClock>,
    floor: u64,
) -> Result<AuthorityTime> {
    let time = time
        .with_seconds_floor(floor)
        .map_err(|_| error(503, "trusted PKI clock is unavailable"))?;
    let Some(clock) = clock else {
        return Ok(time);
    };
    let clock = clock
        .with_seconds_floor(time.seconds())
        .map_err(|_| error(503, "trusted PKI clock is unavailable"))?;
    let clock = time
        .exact()
        .map_or(clock, |at| clock.with_timestamp_floor(at));
    clock
        .observed_at()
        .map(AuthorityTime::Precise)
        .map_err(|_| error(503, "trusted PKI clock is unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
        x509::{X509, X509NameBuilder, X509Req},
    };
    use std::time::{Duration, Instant};
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn real_root(now: u64) -> Result<Pki> {
        let mut pki = Pki::default();
        pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({"common_name":"ca.example.test","key_type":"ec","ttl":"4h"}),
            now,
        )?;
        pki.tune(&json!({"default_lease_ttl":"5m","max_lease_ttl":"10m"}))?;
        Ok(pki)
    }
    fn role(pki: &mut Pki, fields: Value, now: u64) -> Result<()> {
        let mut body = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","key_bits":256,"ttl":"5m","max_ttl":"10m"});
        body.as_object_mut()
            .ok_or_else(|| bad("test role"))?
            .extend(
                fields
                    .as_object()
                    .ok_or_else(|| bad("test role fields"))?
                    .clone(),
            );
        pki.handle_admin("POST", "roles/time", &body, now)?;
        Ok(())
    }
    fn owner() -> TestResultOwner {
        Ok(LeaseOwner::service(&base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            crate::crypto::digest(b"actual nano PKI owner fixture"),
        ))?)
    }
    type TestResultOwner = std::result::Result<LeaseOwner, Box<dyn std::error::Error>>;
    fn csr() -> std::result::Result<String, openssl::error::ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "api.example.test")?;
        let mut request = X509Req::builder()?;
        request.set_subject_name(&name.build())?;
        request.set_pubkey(&key)?;
        request.sign(&key, openssl::hash::MessageDigest::sha256())?;
        Ok(String::from_utf8_lossy(&request.build().to_pem()?).into_owned())
    }

    #[test]
    fn pki_nano_native_fraction_boundaries_real_local_issue_and_csr_sign() -> TestResult {
        let now = 1_700_000_000;
        let mut pki = real_root(now)?;
        let owner = owner()?;
        let clock = RequestClock::anchored(Duration::new(now, 500_000_000), Instant::now())?;
        let future = role_time::signed_timestamp(i64::try_from(now + 1200)?);
        let prefix = future.trim_end_matches('Z');
        let low = format!("{prefix}.25Z");
        let high = format!("{prefix}.75Z");
        let csr = csr()?;
        for (policy, fields, status, error_hint) in [
            (
                json!({"not_after_bound":low}),
                json!({"not_after":high}),
                400,
                ".75Z that is beyond",
            ),
            (
                json!({"not_after_bound":low}),
                json!({"not_after":low}),
                200,
                "",
            ),
            (
                json!({"not_after_bound":high}),
                json!({"not_after":low}),
                200,
                "",
            ),
            (
                json!({"not_after":high,"not_after_bound":low}),
                json!({"not_after":format!("{prefix}.1Z")}),
                400,
                ".75Z that is beyond",
            ),
            (
                json!({"not_before":high,"not_after":low}),
                json!({}),
                400,
                ".75Z) is later",
            ),
            (
                json!({"not_before":low,"not_after":high}),
                json!({}),
                200,
                "",
            ),
        ] {
            role(&mut pki, policy, now)?;
            for sign in [false, true] {
                let mut body = json!({"common_name":"api.example.test"});
                body.as_object_mut()
                    .ok_or("test leaf body")?
                    .extend(fields.as_object().ok_or("test fields")?.clone());
                if sign {
                    body["csr"] = json!(csr);
                }
                let before = pki.issued.len();
                let response = pki.issue_route(
                    "pki/",
                    if sign { "sign/time" } else { "issue/time" },
                    &body,
                    LeafAuthority {
                        owner: &owner,
                        owner_expires: None,
                        precise_owner_expires: None,
                        time: AuthorityTime::Precise(clock.observed_at()?),
                        clock: Some(clock),
                        identity_templates: None,
                    },
                );
                if status == 400 {
                    let rejected = response
                        .err()
                        .ok_or("fractional bound unexpectedly issued")?;
                    assert_eq!(rejected.status, 400);
                    assert!(rejected.message.contains(error_hint));
                    assert_eq!(pki.issued.len(), before);
                } else {
                    let issued = response?;
                    assert_eq!(issued.body["data"]["expiration"], now + 1200);
                    let pem = issued.body["data"]["certificate"]
                        .as_str()
                        .ok_or("real issued PEM")?;
                    let cert = X509::from_pem(pem.as_bytes())?;
                    let ca =
                        X509::from_der(&pki.root.as_ref().ok_or("real issuer")?.certificate_der)?;
                    let issuer_public = ca.public_key()?;
                    assert!(cert.verify(&issuer_public)?);
                    if sign {
                        assert!(issued.body["data"].get("private_key").is_none());
                    }
                }
            }
        }
        role(
            &mut pki,
            json!({"not_before_duration":"30s","not_before_bound":"duration"}),
            now,
        )?;
        let before = role_time::signed_timestamp(i64::try_from(now - 30)?);
        let request = json!({"common_name":"api.example.test","not_before":format!("{}.001Z",before.trim_end_matches('Z'))});
        let rejected = pki
            .issue_route(
                "pki/",
                "issue/time",
                &request,
                LeafAuthority {
                    owner: &owner,
                    owner_expires: None,
                    precise_owner_expires: None,
                    time: AuthorityTime::Precise(clock.observed_at()?),
                    clock: Some(clock),
                    identity_templates: None,
                },
            )
            .err()
            .ok_or("duration bound")?;
        assert!(rejected.message.contains(".001Z that is older"));
        Ok(())
    }

    #[test]
    fn pki_nano_original_affine_clock_withholds_expired_signed_der_without_ceil_extension()
    -> TestResult {
        let now = 1_700_000_000;
        let mut pki = real_root(now)?;
        role(&mut pki, json!({}), now)?;
        let owner = owner()?;
        let clock = RequestClock::anchored(Duration::new(now, 100_000_000), Instant::now())?;
        let exact_expiry = Timestamp::checked(now + 2, 900_000_000)?;
        let body = json!({"common_name":"api.example.test"});
        let authority = |time| LeafAuthority {
            owner: &owner,
            owner_expires: Some(now + 3),
            precise_owner_expires: Some(exact_expiry),
            time,
            clock: Some(clock),
            identity_templates: None,
        };
        let issued = pki.issue_route(
            "pki/",
            "issue/time",
            &body,
            authority(AuthorityTime::Precise(clock.observed_at()?)),
        )?;
        assert_eq!(
            issued.body["data"]["expiration"],
            now + 2,
            "actual expiry floors the public DER instead of using ceil owner projection"
        );
        let cert = X509::from_pem(
            issued.body["data"]["certificate"]
                .as_str()
                .ok_or("actual certificate")?
                .as_bytes(),
        )?;
        let issuer = X509::from_der(&pki.root.as_ref().ok_or("actual issuer")?.certificate_der)?;
        let issuer_public = issuer.public_key()?;
        assert!(cert.verify(&issuer_public)?);
        let prepared = pki.prepare_leaf_route(
            IssuanceRoute {
                mount: "pki/",
                role: "time",
                explicit_issuer: None,
                sign: false,
            },
            &body,
            authority(AuthorityTime::Precise(clock.observed_at()?)),
        )?;
        let before = pki.issued.len();
        std::thread::sleep(Duration::from_millis(2050));
        assert_eq!(
            prepared
                .validate_publication(now)
                .err()
                .ok_or("expired original plan")?
                .status,
            403
        );
        assert_eq!(
            pki.issue_route(
                "pki/",
                "issue/time",
                &body,
                authority(AuthorityTime::Precise(clock.observed_at()?))
            )
            .err()
            .ok_or("expired original actor")?
            .status,
            403
        );
        assert_eq!(
            pki.issued.len(),
            before,
            "late effects never publish another private leaf"
        );
        Ok(())
    }

    #[test]
    fn pki_nano_precise_actor_cannot_acquire_authority_from_coarse_fallback() -> TestResult {
        let now = 1_700_000_000;
        let mut pki = real_root(now)?;
        role(&mut pki, json!({}), now)?;
        let owner = owner()?;
        let error = pki
            .issue_route(
                "pki/",
                "issue/time",
                &json!({"common_name":"api.example.test"}),
                LeafAuthority {
                    owner: &owner,
                    owner_expires: Some(now + 601),
                    precise_owner_expires: Some(Timestamp::checked(now + 600, 750_000_000)?),
                    time: AuthorityTime::Coarse(now),
                    clock: None,
                    identity_templates: None,
                },
            )
            .err()
            .ok_or("coarse fallback acquired precise owner")?;
        assert_eq!(error.status, 403);
        assert!(pki.issued.is_empty());
        Ok(())
    }
}
