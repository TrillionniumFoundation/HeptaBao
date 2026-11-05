//! Public URL configuration and immutable issuance projections. These values
//! never create issuer, actor or provider authority; the original signing lane
//! still owns every private effect. Historical None fields remain omitted.
use super::*;
use x509_parser::prelude::FromDer;

pub(super) const AIA_WARNING: &str = "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information.";
const FIELDS: &[&str] = &[
    "issuing_certificates",
    "crl_distribution_points",
    "delta_crl_distribution_points",
    "ocsp_servers",
    "enable_templating",
];
const MAX_URLS: usize = 64;
const MAX_URL: usize = 4096;

#[derive(Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct UrlEntries {
    issuing_certificates: Vec<String>,
    crl_distribution_points: Vec<String>,
    delta_crl_distribution_points: Vec<String>,
    ocsp_servers: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct PkiUrls {
    entries: UrlEntries,
    enable_templating: bool,
}

fn valid_url(value: &str) -> bool {
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str().is_some()
        && uri.authority().is_some_and(|a| !a.host().is_empty())
        && !["{{issuer_id}}", "{{cluster_path}}", "{{cluster_aia_path}}"]
            .iter()
            .any(|item| value.contains(item))
}
fn values(value: &Value) -> Result<Vec<String>> {
    let list = string_list(Some(value))?;
    if list.len() > MAX_URLS
        || list
            .iter()
            .any(|v| v.len() > MAX_URL || !v.is_ascii() || v.chars().any(char::is_control))
    {
        return Err(bad("PKI URL list exceeds bounds"));
    }
    Ok(list)
}
impl UrlEntries {
    fn fields(&self) -> [(&str, &Vec<String>); 4] {
        [
            ("issuing_certificates", &self.issuing_certificates),
            ("crl_distribution_points", &self.crl_distribution_points),
            (
                "delta_crl_distribution_points",
                &self.delta_crl_distribution_points,
            ),
            ("ocsp_servers", &self.ocsp_servers),
        ]
    }
    pub(super) fn validate(&self) -> Result<()> {
        for (_, list) in self.fields() {
            if list.len() > MAX_URLS || list.iter().any(|v| v.len() > MAX_URL || !valid_url(v)) {
                return Err(bad("invalid captured PKI URL entries"));
            }
        }
        Ok(())
    }
    pub(super) fn aia_empty(&self) -> bool {
        self.issuing_certificates.is_empty()
            && self.crl_distribution_points.is_empty()
            && self.ocsp_servers.is_empty()
    }
    fn distribution_points(values: &[String]) -> Vec<u8> {
        // The Go certificate producer emits one DistributionPoint per URI.
        let points: Vec<_> = values
            .iter()
            .map(|v| {
                seq(&[context_explicit(
                    0,
                    &der(0xa0, &context_primitive(6, v.as_bytes())),
                )])
            })
            .collect();
        seq(&points)
    }
    pub(super) fn freshest_extension(&self) -> Option<Vec<u8>> {
        (!self.delta_crl_distribution_points.is_empty()).then(|| {
            extension(
                &[0x55, 0x1d, 0x2e],
                false,
                &Self::distribution_points(&self.delta_crl_distribution_points),
            )
        })
    }
    pub(super) fn certificate_extensions(&self) -> Result<Vec<Vec<u8>>> {
        self.validate()?;
        let mut extensions = Vec::new();
        if !self.ocsp_servers.is_empty() || !self.issuing_certificates.is_empty() {
            let mut access = Vec::new();
            for (method, urls) in [(1u8, &self.ocsp_servers), (2u8, &self.issuing_certificates)] {
                let oid = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, method];
                access.extend(
                    urls.iter()
                        .map(|url| seq(&[der(0x06, &oid), context_primitive(6, url.as_bytes())])),
                );
            }
            extensions.push(extension(
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01],
                false,
                &seq(&access),
            ));
        }
        if !self.crl_distribution_points.is_empty() {
            extensions.push(extension(
                &[0x55, 0x1d, 0x1f],
                false,
                &Self::distribution_points(&self.crl_distribution_points),
            ));
        }
        if let Some(freshest) = self.freshest_extension() {
            extensions.push(freshest);
        }
        Ok(extensions)
    }
    pub(super) fn validate_certificate(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        let (_, certificate) = x509_parser::prelude::X509Certificate::from_der(bytes)
            .map_err(|_| bad("invalid URL-owned certificate"))?;
        let expected = self.certificate_extensions()?;
        let captured: Vec<_> = certificate
            .extensions()
            .iter()
            .filter(|e| {
                matches!(
                    e.oid.to_id_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31" | "2.5.29.46"
                )
            })
            .map(|e| extension(e.oid.as_bytes(), e.critical, e.value))
            .collect();
        if expected != captured {
            return Err(bad("PKI certificate URL projection differs"));
        }
        Ok(())
    }
}
impl PkiUrls {
    fn validate(&self) -> Result<()> {
        for (field, list) in self.entries.fields() {
            if list.len() > MAX_URLS
                || list
                    .iter()
                    .any(|v| v.len() > MAX_URL || !v.is_ascii() || v.chars().any(char::is_control))
            {
                return Err(bad("PKI URL configuration exceeds bounds"));
            }
            if !self.enable_templating
                && let Some(bad_url) = list.iter().find(|v| !valid_url(v))
            {
                return Err(bad(&format!(
                    "invalid URL found in Authority Information Access (AIA) parameter {field}: {bad_url}"
                )));
            }
        }
        Ok(())
    }
    pub(super) fn aia_empty(&self) -> bool {
        self.entries.aia_empty()
    }
    fn descriptor(&self) -> Value {
        json!({"issuing_certificates":self.entries.issuing_certificates,"crl_distribution_points":self.entries.crl_distribution_points,"delta_crl_distribution_points":self.entries.delta_crl_distribution_points,"ocsp_servers":self.entries.ocsp_servers,"enable_templating":self.enable_templating})
    }
    fn render(&self, issuer: &str, cluster: &str, aia: &str) -> Result<UrlEntries> {
        let mut entries = self.entries.clone();
        if self.enable_templating {
            for list in [
                &mut entries.issuing_certificates,
                &mut entries.crl_distribution_points,
                &mut entries.delta_crl_distribution_points,
                &mut entries.ocsp_servers,
            ] {
                for url in list {
                    if url.contains("{{issuer_id}}") && issuer.is_empty()
                        || url.contains("{{cluster_path}}") && cluster.is_empty()
                        || url.contains("{{cluster_aia_path}}") && aia.is_empty()
                    {
                        return Err(bad(
                            "PKI AIA template requires the selected issuer and configured cluster paths",
                        ));
                    }
                    *url = url
                        .replace("{{issuer_id}}", issuer)
                        .replace("{{cluster_path}}", cluster)
                        .replace("{{cluster_aia_path}}", aia);
                }
            }
        }
        for (field, urls) in entries.fields() {
            if let Some(uri) = urls.iter().find(|url| !valid_url(url)) {
                return Err(bad(&format!(
                    "error validating templated {field}; invalid URI: {uri}"
                )));
            }
        }
        entries.validate()?;
        Ok(entries)
    }
}
impl Pki {
    #[cfg(test)]
    pub(in crate::engines) fn remove_root_url_capture_for_test(&mut self) -> Result<()> {
        self.root.as_mut().ok_or_else(not_found)?.url_entries = None;
        Ok(())
    }
    pub(in crate::engines) fn has_url_state(&self) -> bool {
        self.urls.is_some()
            || self.local_roots().any(|root| root.url_entries.is_some())
            || self.local_keys().any(|root| root.url_entries.is_some())
            || self.issued.values().any(|leaf| leaf.url_entries.is_some())
            || self.has_external_url_state()
            || self.has_local_intermediate_url_state()
            || self.has_local_crl_url_state()
    }
    pub(super) fn capture_root_urls(&self) -> Result<(Option<UrlEntries>, Vec<String>)> {
        match self.capture_urls("") {
            Ok(entries) => Ok((entries, Vec::new())),
            Err(_) if self.capture_urls("empty-issuer-id").is_ok() => Ok((Some(UrlEntries::default()), vec!["When generating root CA, found global AIA configuration with issuer_id template unsuitable for root generation. This AIA configuration has been ignored. To include AIA on this root CA, set the global AIA configuration to not include issuer_id and instead to refer to a static issuer name.".into()])),
            Err(e) => Err(e),
        }
    }
    pub(super) fn capture_urls(&self, issuer: &str) -> Result<Option<UrlEntries>> {
        self.urls
            .as_ref()
            .map(|config| config.render(issuer, &self.cluster_path, &self.aia_path).map_err(|cause| {
                error(500, &format!("1 error occurred:\n\t* error fetching CA certificate: unable to fetch AIA URL information: {}\n\n", cause.message))
            }))
            .transpose()
    }
    pub(super) fn validate_urls(&self) -> Result<()> {
        if let Some(config) = &self.urls {
            config.validate()?;
        }
        for root in self.local_roots().chain(self.local_keys()) {
            if let Some(urls) = &root.url_entries {
                urls.validate_certificate(&root.certificate_der)?;
            } else if !root.certificate_der.is_empty()
                && !root.is_external()
                && root.local_chain.is_none()
            {
                // Historical locally generated certificates carried no URL
                // extensions. Public imported chains retain their own DER.
                UrlEntries::default().validate_certificate(&root.certificate_der)?;
            }
        }
        for leaf in self.issued.values() {
            leaf.url_entries
                .clone()
                .unwrap_or_default()
                .validate_certificate(&leaf.certificate_der)?;
        }
        Ok(())
    }
    pub(super) fn handle_urls(&mut self, method: &str, body: &Value) -> Result<EngineResponse> {
        if method == "GET" {
            reject_unknown(body, &[])?;
            return Ok(ok(
                self.urls.clone().unwrap_or_default().descriptor(),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, FIELDS)?;
        let mut next = self.urls.clone().unwrap_or_default();
        for (field, target) in [
            (
                "issuing_certificates",
                &mut next.entries.issuing_certificates,
            ),
            (
                "crl_distribution_points",
                &mut next.entries.crl_distribution_points,
            ),
            (
                "delta_crl_distribution_points",
                &mut next.entries.delta_crl_distribution_points,
            ),
            ("ocsp_servers", &mut next.entries.ocsp_servers),
        ] {
            if let Some(value) = body.get(field) {
                *target = values(value)?;
            }
        }
        if let Some(value) = role_optional_bool(body, "enable_templating")? {
            next.enable_templating = value;
        }
        next.validate()?;
        let mut response = ok(next.descriptor(), true);
        if next.enable_templating
            && let Some((issuer, _, _)) = self.public_issuer_metadata()
            && let Err(cause) = next.render(issuer, &self.cluster_path, &self.aia_path)
        {
            response.body["warnings"] = json!([format!(
                "issuance may fail: {}\n\nConsider setting the cluster-local address if it is not already set.",
                cause.message
            )]);
        }
        self.urls = Some(next); // Some(default) retains the irreversible format97 owner.
        Ok(response)
    }
}
