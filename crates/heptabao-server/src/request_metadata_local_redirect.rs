//! A local HTTP routing preference. It grants no actor, storage or retry authority.
use super::*;
use zeroize::Zeroizing;

pub(crate) const NO_FORWARD_HEADER: &str = "x-vault-no-request-forwarding";

#[derive(Clone)]
pub(crate) struct CheckedLocalRedirectTarget(Zeroizing<String>);

impl CheckedLocalRedirectTarget {
    // The HTTP parser separately admits route/query/body semantics. This type
    // preserves the admitted origin-relative target without taking authority
    // from Host, forwarded headers, a response body or an SDK Location field.
    pub(crate) fn checked(target: &str) -> Result<Self, &'static str> {
        if !target.starts_with("/v1/")
            || target.len() > 8192
            || !target.bytes().all(|byte| (33..=126).contains(&byte))
            || target.contains('#')
        {
            return Err("invalid local redirect target");
        }
        Ok(Self(Zeroizing::new(target.to_owned())))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub(crate) struct LocalRedirectProfile {
    target: CheckedLocalRedirectTarget,
    binding: [u8; 32],
    ingress: [u8; 16],
}

impl LocalRedirectProfile {
    pub(super) fn validate_binding(&self, digest: [u8; 32]) -> Result<(), &'static str> {
        if self.binding != digest
            || crate::auth::current_ingress()
                .is_none_or(|ingress| ingress.attempt_id() != self.ingress)
        {
            return Err("local redirect belongs to another HTTP ingress");
        }
        Ok(())
    }

    pub(crate) fn matches_current(&self) -> bool {
        DATA.with(|slot| {
            let slot = slot.borrow();
            let Some(bound) = slot.as_ref() else {
                return false;
            };
            let Some(original) = bound.frame.local_redirect.as_ref() else {
                return false;
            };
            bound.frame.no_request_forwarding()
                && self.validate_binding(bound.digest).is_ok()
                && original.binding == self.binding
                && original.ingress == self.ingress
                && original.target.as_str() == self.target.as_str()
        })
    }

    pub(crate) fn into_target(self) -> CheckedLocalRedirectTarget {
        self.target
    }
}

impl DataFrame {
    // Go Header.Get selects the first field value and only tests nonemptiness.
    // In particular, the strings "false" and "0" both disable forwarding.
    pub(crate) fn no_request_forwarding(&self) -> bool {
        self.headers
            .get(NO_FORWARD_HEADER)
            .and_then(|values| values.first())
            .is_some_and(|value| !value.is_empty())
    }

    pub(crate) fn bind_local_redirect(
        &mut self,
        target: CheckedLocalRedirectTarget,
        request: (&str, &str, &str, &Value),
        ingress: &[u8; 16],
    ) -> Result<(), &'static str> {
        if !self.no_request_forwarding() || self.local_redirect.is_some() {
            return Err("local redirect requires the original nonempty HTTP preference");
        }
        let profile = LocalRedirectProfile {
            target,
            binding: binding(request.0, request.1, request.2, request.3)?,
            ingress: *ingress,
        };
        profile.validate_binding(profile.binding)?;
        self.local_redirect = Some(profile);
        Ok(())
    }
}
