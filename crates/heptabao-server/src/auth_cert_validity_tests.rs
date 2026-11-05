use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// The signed fixture has a two-minute interval on 2026-10-13. Do not choose
// test time independently of its actual DER validity fields.
const NOT_BEFORE: u64 = 1_791_849_600;
const NOT_AFTER: u64 = NOT_BEFORE + 120;
const LEAF: &[u8] = include_bytes!("../testdata/cert-validity-boundary.der");

fn precise(seconds: u64, nanoseconds: u32) -> TestResult<AuthorityTime> {
    Ok(AuthorityTime::Precise(Timestamp::checked(
        seconds,
        nanoseconds,
    )?))
}
fn fixture() -> TestResult<(AuthState, Principal)> {
    let now = NOT_BEFORE - 5;
    let (mut state, raw) = AuthState::bootstrap(now)?;
    let root = state.authenticate(&raw, now)?;
    state
        .handle(
            Some(&root),
            "",
            "POST",
            "sys/auth/cert",
            &json!({"type":"cert"}),
            now,
        )?
        .ok_or("missing cert mount response")?;
    state
        .handle(
            Some(&root),
            "",
            "POST",
            "auth/cert/certs/operator",
            &json!({"certificate_sha256":certificate_sha256(LEAF),
                "token_ttl":300,"token_max_ttl":600}),
            now,
        )?
        .ok_or("missing cert role response")?;
    Ok((state, root))
}
fn login(state: &mut AuthState, time: AuthorityTime) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_connection_observed(
            None,
            "",
            "POST",
            "auth/cert/login",
            &json!({"name":"operator"}),
            time,
            Some(&[LEAF.to_vec()]),
            None,
        )?
        .ok_or_else(denied)
}
fn saved(state: &AuthState) -> TestResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(state)?))
}

#[test]
fn cert_validity_signed_der_observes_inclusive_endpoints_and_subsecond_expiry() -> TestResult {
    let (_, certificate) = parse_x509_certificate(LEAF).map_err(|_| "fixture DER")?;
    assert_eq!(
        certificate.validity().not_before.timestamp(),
        i64::try_from(NOT_BEFORE)?
    );
    assert_eq!(
        certificate.validity().not_after.timestamp(),
        i64::try_from(NOT_AFTER)?
    );
    for (seconds, nanos, accepted) in [
        (NOT_BEFORE - 1, 999_999_999, false),
        (NOT_BEFORE, 0, true),
        (NOT_BEFORE, 1, true),
        (NOT_AFTER - 1, 999_999_999, true),
        (NOT_AFTER, 0, true),
        (NOT_AFTER, 1, false),
    ] {
        let result = cert_validity::validate(LEAF, precise(seconds, nanos)?);
        if accepted {
            result?;
        } else {
            assert!(matches!(result, Err(error) if error.status == 403));
        }
    }
    assert!(cert_validity::validate(LEAF, AuthorityTime::Coarse(NOT_BEFORE - 1)).is_err());
    cert_validity::validate(LEAF, AuthorityTime::Coarse(NOT_BEFORE))?;
    cert_validity::validate(LEAF, AuthorityTime::Coarse(NOT_AFTER))?;
    assert!(cert_validity::validate(LEAF, AuthorityTime::Coarse(NOT_AFTER + 1)).is_err());
    Ok(())
}

#[test]
fn cert_validity_legacy_test_clock_requires_real_valid_der_without_exceptions() -> TestResult {
    let wide = include_bytes!("../testdata/cert-selector.der");
    cert_validity::validate(wide, AuthorityTime::Coarse(100))?;
    cert_validity::validate(wide, AuthorityTime::Coarse(NOT_BEFORE + 60))?;
    assert!(cert_validity::validate(LEAF, AuthorityTime::Coarse(100)).is_err());
    assert!(cert_validity::validate(b"opaque leaf", AuthorityTime::Coarse(100)).is_err());
    let mut trailing = LEAF.to_vec();
    trailing.push(0);
    assert!(cert_validity::validate(&trailing, AuthorityTime::Coarse(NOT_BEFORE)).is_err());
    Ok(())
}

#[test]
fn cert_login_checks_request_time_before_issuing_any_token() -> TestResult {
    let (baseline, _) = fixture()?;
    for time in [
        precise(NOT_BEFORE - 1, 999_999_999)?,
        precise(NOT_AFTER, 1)?,
        AuthorityTime::Coarse(NOT_AFTER + 1),
    ] {
        let mut state = baseline.clone();
        let before = saved(&state)?;
        let result = login(&mut state, time);
        assert!(matches!(result, Err(error) if error.status == 403));
        assert!(before.as_slice() == saved(&state)?.as_slice());
    }
    let mut state = baseline;
    assert_eq!(login(&mut state, precise(NOT_BEFORE, 0)?)?.status, 200);
    let before = saved(&state)?;
    let result = login(&mut state, precise(NOT_AFTER, 1)?);
    assert!(matches!(result, Err(error) if error.status == 403));
    assert!(before.as_slice() == saved(&state)?.as_slice());
    Ok(())
}

#[test]
fn cert_three_renewal_entries_recheck_current_leaf_validity_without_mutation() -> TestResult {
    let (mut baseline, root) = fixture()?;
    let issued = login(&mut baseline, precise(NOT_AFTER - 1, 0)?)?;
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let actor = baseline.authenticate(&raw, NOT_AFTER - 1)?;
    let accessor = baseline.tokens[&hash(&raw)].accessor.clone();
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let body = match operation {
            "renew" => json!({"token":raw}),
            "renew-accessor" => json!({"accessor":accessor}),
            _ => json!({}),
        };
        let principal = if operation == "renew-self" {
            &actor
        } else {
            &root
        };
        let mut inclusive = baseline.clone();
        let response = inclusive
            .handle_with_connection_observed(
                Some(principal),
                "",
                "POST",
                &format!("auth/token/{operation}"),
                &body,
                precise(NOT_AFTER, 0)?,
                Some(&[LEAF.to_vec()]),
                None,
            )?
            .ok_or("renewal response")?;
        assert_eq!(response.status, 200);
        let mut expired = baseline.clone();
        let before = saved(&expired)?;
        let result = expired.handle_with_connection_observed(
            Some(principal),
            "",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            precise(NOT_AFTER, 1)?,
            Some(&[LEAF.to_vec()]),
            None,
        );
        assert!(matches!(result, Err(error) if error.status == 403));
        assert!(before.as_slice() == saved(&expired)?.as_slice());
    }
    Ok(())
}
