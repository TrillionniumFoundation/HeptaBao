//! Eligibility for the local signer profile. This does not grant an operation:
//! native request/maintenance capsules own every actual domain invocation.
use super::*;

impl Pki {
    pub(in crate::engines) fn native_local_profile(&self) -> bool {
        self.external.is_empty()
            && !self.has_external_signer_history()
            && self.root.as_ref().is_none_or(|root| !root.is_external())
            && self.acme_protocol.is_none()
            && AcmeConfig::is_default(&self.acme)
    }

    pub(in crate::engines) fn native_local_route(path: &str) -> bool {
        // The domain has only local effects under the profile above. ACME and
        // KMS selectors retain their separate provider/actor owners; neither
        // route text nor local key ownership can grant those effects here.
        path != "config/acme"
            && path != "acme"
            && path != "eab"
            && !path.starts_with("eab/")
            && !path.starts_with("acme/")
            && !path.contains("/acme/")
            && !matches!(
                path,
                "root/generate/kms" | "intermediate/generate/kms" | "keys/generate/kms"
            )
    }
}
