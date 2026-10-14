//! Read-only certificate selection shared with login. No token or lease effects.
use super::*;
pub(super) struct Resolution<'a> {
    pub(super) name: &'a str,
    pub(super) role: &'a CertRole,
    pub(super) presented: PresentedCertificate,
    pub(super) attributes: Option<CertificateAttributes>,
}
pub(super) fn resolve<'a>(
    state: &'a AuthState,
    scope: AuthScope<'_>,
    requested: Option<&str>,
    time: AuthorityTime,
    chain: &[Vec<u8>],
) -> Result<Resolution<'a>, AuthError> {
    let presented = parse_presented_certificate(chain, time)?;
    let roles = state
        .cert_roles
        .get(scope.namespace)
        .and_then(|mounts| mounts.get(scope.mount))
        .ok_or_else(denied)?;
    let attributes = chain
        .first()
        .and_then(|leaf| parse_certificate_attributes(leaf));
    let (name, role) = match requested {
        Some(name) => roles
            .get_key_value(name)
            .filter(|(_, role)| matches_cert_role(&presented, attributes.as_ref(), role))
            .ok_or_else(denied)?,
        None => roles
            .iter()
            .find(|(_, role)| matches_cert_role(&presented, attributes.as_ref(), role))
            .ok_or_else(denied)?,
    };
    Ok(Resolution {
        name,
        role,
        presented,
        attributes,
    })
}
