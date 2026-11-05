//! Closed public projections retain their original issuer and namespace owner.
//! Projection handling is immutable; Service owns required clock maintenance.
use super::*;

pub(in crate::engines) enum CertificateFormat {
    Der,
    Pem,
    Chain,
}
pub(in crate::engines) enum PkiPublicRead<'a> {
    Ocsp(bool, Option<&'a str>),
    Ca,
    Certificate(&'a str),
    RawCa(CertificateFormat),
    RawCertificate(&'a str, CertificateFormat),
    Chain,
    FullCrl,
    ExternalCrl(&'a str),
    LocalCrl(bool, IssuerCrlFormat),
    Issuers,
    DefaultIssuer,
    IssuerCertificate(&'a str, CertificateFormat),
    IssuerJson(&'a str),
    IssuerCrl(&'a str, bool, IssuerCrlFormat),
}

pub(in crate::engines) enum IssuerCrlFormat {
    Json,
    Der,
    Pem,
}

pub(super) fn stored_pem(label: &str, der: &[u8]) -> String {
    let mut encoded = pem(label, der);
    // The public stored-certificate projection omits exactly its final LF.
    if encoded.ends_with('\n') {
        encoded.pop();
    }
    encoded
}

// The primary public full-chain projection trims each generated PEM before
// joining, then trims the complete chain. Stored issuer PEM arrays keep their
// original representation; this is only the public full-chain presentation.
fn public_chain_pem(chain: &[String]) -> String {
    chain
        .iter()
        .map(|certificate| certificate.trim())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn raw_certificate(der: &[u8], format: CertificateFormat) -> Result<EngineResponse> {
    if der.len() > 64 * 1024 {
        return Err(error(503, "public certificate exceeds bounds"));
    }
    let (bytes, mode) = match format {
        CertificateFormat::Der => (der.to_vec(), "der"),
        CertificateFormat::Pem => (stored_pem("CERTIFICATE", der).into_bytes(), "pem"),
        CertificateFormat::Chain => (stored_pem("CERTIFICATE", der).into_bytes(), "chain"),
    };
    Ok(EngineResponse {
        status: 200,
        body: json!({"__heptabao_pki_certificate":BASE64.encode(bytes),"format":mode}),
        mutated: false,
    })
}

/// A private proof selected by the actual PKI mount and closed public producer.
/// HTTP special logical fields retain Go []byte/nil semantics in private custody;
/// the dedicated stored variant releases their original raw HTTP entity.
pub(crate) struct PkiWrappedTransport {
    logical_response: Value,
}
impl PkiWrappedTransport {
    fn new(media: &'static str, body: Value, status: u16) -> Self {
        Self {
            logical_response: json!({"data":{
                "http_content_type":media,
                "http_raw_body":body,
                "http_status_code":status
            }}),
        }
    }
    pub(crate) fn logical_response(&self) -> &Value {
        &self.logical_response
    }
}
impl Drop for PkiWrappedTransport {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.logical_response);
    }
}
fn canonical_transport_base64<'a>(body: &'a Value, marker: &str, bound: usize) -> Option<&'a str> {
    let text = body.get(marker)?.as_str()?;
    if text.len() > bound.div_ceil(3).checked_mul(4)? {
        return None;
    }
    let bytes = BASE64.decode(text).ok()?;
    (bytes.len() <= bound && BASE64.encode(&bytes) == text).then_some(text)
}

impl Pki {
    /// This is called only after dispatch by the longest actual PKI owner.
    /// Route, response status, canonical bytes and producer-specific format must
    /// agree. A SDK/client object with similar keys does not select this proof.
    pub(in crate::engines) fn wrapping_public_transport(
        &self,
        method: &str,
        path: &str,
        status: u16,
        body: &Value,
    ) -> Option<PkiWrappedTransport> {
        let route = self.public_read_route(method, path)?;
        match route {
            PkiPublicRead::Ocsp(..) => {
                let bytes = super::local_ocsp::raw_response(status, body)?;
                Some(PkiWrappedTransport::new(
                    "application/ocsp-response",
                    json!(BASE64.encode(bytes)),
                    status,
                ))
            }
            PkiPublicRead::RawCa(format)
            | PkiPublicRead::RawCertificate(_, format)
            | PkiPublicRead::IssuerCertificate(_, format) => {
                if status != 200 || body.as_object()?.len() != 2 {
                    return None;
                }
                let (mode, media) = match format {
                    CertificateFormat::Der => ("der", "application/pkix-cert"),
                    CertificateFormat::Pem => ("pem", "application/pem-certificate-chain"),
                    CertificateFormat::Chain => ("chain", "application/pkix-cert"),
                };
                if body.get("format")?.as_str()? != mode {
                    return None;
                }
                let text =
                    canonical_transport_base64(body, "__heptabao_pki_certificate", 128 * 1024)?;
                Some(PkiWrappedTransport::new(media, json!(text), status))
            }
            PkiPublicRead::LocalCrl(_, format) | PkiPublicRead::IssuerCrl(_, _, format) => {
                if matches!(format, IssuerCrlFormat::Json) {
                    return None;
                }
                let pem = matches!(format, IssuerCrlFormat::Pem);
                // The actual rootless LocalCrl producer returns Go's nil
                // certificate slice. Empty base64 alone never proves nilness.
                let nil_local_crl = status == 204
                    && self.root.is_none()
                    && matches!(
                        self.public_read_route(method, path),
                        Some(PkiPublicRead::LocalCrl(..))
                    );
                Self::wrapping_crl_transport(status, body, pem, nil_local_crl)
            }
            PkiPublicRead::ExternalCrl(path) if !path.starts_with("cert/") => {
                Self::wrapping_crl_transport(status, body, path.ends_with("/pem"), false)
            }
            _ => None,
        }
    }
    fn wrapping_crl_transport(
        status: u16,
        body: &Value,
        pem: bool,
        nil_local_crl: bool,
    ) -> Option<PkiWrappedTransport> {
        if body.as_object()?.len() != 2 || body.get("pem")?.as_bool()? != pem {
            return None;
        }
        let text = canonical_transport_base64(body, "__heptabao_pki_crl", 512 * 1024)?;
        let raw_body = match status {
            200 => json!(text),
            204 if nil_local_crl && text.is_empty() => Value::Null,
            _ => return None,
        };
        Some(PkiWrappedTransport::new(
            if pem {
                "application/x-pem-file"
            } else {
                "application/pkix-crl"
            },
            raw_body,
            status,
        ))
    }

    pub(in crate::engines) fn wrapping_uses_raw_public_transport(
        &self,
        method: &str,
        path: &str,
    ) -> bool {
        match self.public_read_route(method, path) {
            Some(
                PkiPublicRead::Ocsp(..)
                | PkiPublicRead::RawCa(..)
                | PkiPublicRead::RawCertificate(..)
                | PkiPublicRead::IssuerCertificate(..),
            ) => true,
            Some(PkiPublicRead::LocalCrl(_, format) | PkiPublicRead::IssuerCrl(_, _, format)) => {
                !matches!(format, IssuerCrlFormat::Json)
            }
            Some(PkiPublicRead::ExternalCrl(path)) => !path.starts_with("cert/"),
            _ => false,
        }
    }
    fn local_crl_response(der: &[u8], format: IssuerCrlFormat) -> Result<EngineResponse> {
        if matches!(format, IssuerCrlFormat::Json) {
            return Ok(ok(json!({"crl":pem("X509 CRL",der)}), false));
        }
        let is_pem = matches!(format, IssuerCrlFormat::Pem);
        let bytes = if is_pem {
            stored_pem("X509 CRL", der).into_bytes()
        } else {
            der.to_vec()
        };
        if bytes.len() > 512 * 1024 {
            return Err(error(503, "public CRL exceeds bounds"));
        }
        Ok(EngineResponse {
            status: 200,
            body: json!({"__heptabao_pki_crl":BASE64.encode(bytes),"pem":is_pem}),
            mutated: false,
        })
    }

    pub(in crate::engines) fn public_read_route<'a>(
        &self,
        method: &str,
        path: &'a str,
    ) -> Option<PkiPublicRead<'a>> {
        if path.contains('?') {
            return None;
        }
        if matches!(method, "POST" | "PUT") && path == "ocsp" {
            return Some(PkiPublicRead::Ocsp(false, None));
        }
        if method == "GET" {
            if path == "ocsp" {
                return Some(PkiPublicRead::Ocsp(true, None));
            }
            if let Some(suffix) = path.strip_prefix("ocsp/") {
                return Some(PkiPublicRead::Ocsp(true, Some(suffix)));
            }
        }
        if method == "LIST" && path == "issuers" {
            return Some(PkiPublicRead::Issuers);
        }
        if method != "GET" {
            return None;
        }
        match path {
            "cert/ca" => Some(PkiPublicRead::Ca),
            "ca" => Some(PkiPublicRead::RawCa(CertificateFormat::Der)),
            "ca/pem" => Some(PkiPublicRead::RawCa(CertificateFormat::Pem)),
            "ca_chain" => Some(PkiPublicRead::RawCa(CertificateFormat::Chain)),
            "cert/ca_chain" => Some(PkiPublicRead::Chain),
            "cert/crl" => Some(PkiPublicRead::FullCrl),
            "issuer/default/json"
                if self.public_issuer_metadata().is_some()
                    && !self.has_public_default_override() =>
            {
                Some(PkiPublicRead::DefaultIssuer)
            }
            "cert/delta-crl" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                Some(PkiPublicRead::LocalCrl(true, IssuerCrlFormat::Json))
            }
            "crl" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                Some(PkiPublicRead::LocalCrl(false, IssuerCrlFormat::Der))
            }
            "crl/pem" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                Some(PkiPublicRead::LocalCrl(false, IssuerCrlFormat::Pem))
            }
            "crl/delta" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                Some(PkiPublicRead::LocalCrl(true, IssuerCrlFormat::Der))
            }
            "crl/delta/pem" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                Some(PkiPublicRead::LocalCrl(true, IssuerCrlFormat::Pem))
            }
            "cert/delta-crl" | "crl" | "crl/pem" | "crl/delta" | "crl/delta/pem"
                if self.root.as_ref().is_some_and(|root| root.is_external()) =>
            {
                Some(PkiPublicRead::ExternalCrl(path))
            }
            _ => {
                if let Some(selected) = path.strip_prefix("issuer/") {
                    let (reference, suffix) = selected.split_once('/')?;
                    if reference.is_empty() || reference.len() > 128 {
                        return None;
                    }
                    return match suffix {
                        "json" => Some(PkiPublicRead::IssuerJson(reference)),
                        "der" => Some(PkiPublicRead::IssuerCertificate(
                            reference,
                            CertificateFormat::Der,
                        )),
                        "pem" => Some(PkiPublicRead::IssuerCertificate(
                            reference,
                            CertificateFormat::Pem,
                        )),
                        "crl" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            false,
                            IssuerCrlFormat::Json,
                        )),
                        "crl/der" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            false,
                            IssuerCrlFormat::Der,
                        )),
                        "crl/pem" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            false,
                            IssuerCrlFormat::Pem,
                        )),
                        "crl/delta" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            true,
                            IssuerCrlFormat::Json,
                        )),
                        "crl/delta/der" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            true,
                            IssuerCrlFormat::Der,
                        )),
                        "crl/delta/pem" => Some(PkiPublicRead::IssuerCrl(
                            reference,
                            true,
                            IssuerCrlFormat::Pem,
                        )),
                        _ => None,
                    };
                }
                let selected = path.strip_prefix("cert/")?;
                if let Some(serial) = selected.strip_suffix("/raw/pem") {
                    normalize_serial(serial).ok()?;
                    Some(PkiPublicRead::RawCertificate(
                        serial,
                        CertificateFormat::Pem,
                    ))
                } else if let Some(serial) = selected.strip_suffix("/raw") {
                    normalize_serial(serial).ok()?;
                    Some(PkiPublicRead::RawCertificate(
                        serial,
                        CertificateFormat::Der,
                    ))
                } else {
                    normalize_serial(selected).ok()?;
                    Some(PkiPublicRead::Certificate(selected))
                }
            }
        }
    }

    pub(in crate::engines::pki) fn require_public_issuer(&self, reference: &str) -> Result<()> {
        if !self.root.as_ref().is_some_and(RootCa::is_external) {
            self.local_issuer(reference)?;
            return Ok(());
        }
        self.external_issuer_key(reference).map(|_| ())
    }

    pub(in crate::engines) fn handle_public_read(
        &self,
        route: PkiPublicRead<'_>,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if let PkiPublicRead::Ocsp(get, suffix) = route {
            return self.local_ocsp(get, suffix, body, now);
        }
        reject_unknown(body, &[])?;
        match route {
            PkiPublicRead::Ocsp(_, _) => Err(bad("invalid OCSP dispatch")),
            PkiPublicRead::Ca => {
                if let Some((der, _)) = self.public_imported_ca("default") {
                    return Ok(ok(
                        json!({"certificate":stored_pem("CERTIFICATE",der),"revocation_time":0,"revocation_time_rfc3339":""}),
                        false,
                    ));
                }
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                let root = self.root.as_ref().ok_or_else(not_found)?;
                Ok(ok(
                    json!({"certificate":stored_pem("CERTIFICATE", &root.certificate_der),"revocation_time":0,"revocation_time_rfc3339":""}),
                    false,
                ))
            }
            PkiPublicRead::RawCa(format) => {
                if let Some((der, chain)) = self.public_imported_ca("default") {
                    if matches!(format, CertificateFormat::Chain) {
                        return Ok(EngineResponse {
                            status: 200,
                            body: json!({"__heptabao_pki_certificate":BASE64.encode(public_chain_pem(&chain).as_bytes()),"format":"chain"}),
                            mutated: false,
                        });
                    }
                    return raw_certificate(der, format);
                }
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                let root = self.root.as_ref().ok_or_else(not_found)?;
                if matches!(format, CertificateFormat::Chain)
                    && (root.local_chain.is_some() || root.is_external())
                {
                    let bytes = public_chain_pem(&self.external_ca_chain_pem(root)?).into_bytes();
                    return Ok(EngineResponse {
                        status: 200,
                        body: json!({"__heptabao_pki_certificate":BASE64.encode(bytes),"format":"chain"}),
                        mutated: false,
                    });
                }
                raw_certificate(&root.certificate_der, format)
            }
            PkiPublicRead::Certificate(serial) => {
                let serial = self.resolve_certificate_serial(serial)?;
                if let Some(der) = self.local_certificate(&serial) {
                    let revoked_at = self.signed_ca_revocation_time(&serial);
                    return Ok(ok(
                        json!({"certificate":stored_pem("CERTIFICATE",der),"revocation_time":revoked_at.unwrap_or(0),"revocation_time_rfc3339":revoked_at.map(timestamp).unwrap_or_default()}),
                        false,
                    ));
                }
                if let Some(cert) = self.acme_certificate_for_serial(&serial)? {
                    let mut projection = json!({"certificate":stored_pem("CERTIFICATE", &cert.der),"revocation_time":self.acme_revocation(&serial).map_or(0,|r|r.at.seconds()),"revocation_time_rfc3339":self.acme_revocation(&serial).map(|r|r.at.rfc3339()).unwrap_or_default()});
                    if let Some(revoked) = self.acme_revocation(&serial) {
                        projection["issuer_id"] = json!(revoked.issuer);
                    }
                    return Ok(ok(projection, false));
                }
                let Some(certificate) = self.issued.get(&serial) else {
                    return Ok(EngineResponse {
                        status: 404,
                        body: json!({"errors":[]}),
                        mutated: false,
                    });
                };
                let mut projection = json!({"certificate":stored_pem("CERTIFICATE", &certificate.certificate_der),"revocation_time":certificate.revoked_at.unwrap_or(0),"revocation_time_rfc3339":self.ordinary_revocation(&serial).map(|r|r.at.rfc3339()).or_else(||self.acme_revocation(&serial).map(|r|r.at.rfc3339())).unwrap_or_else(||certificate.revoked_at.map(timestamp).unwrap_or_default())});
                if let Some(revoked) = self.acme_revocation(&serial) {
                    projection["issuer_id"] = json!(revoked.issuer);
                }
                Ok(ok(projection, false))
            }
            PkiPublicRead::RawCertificate(serial, format) => {
                let serial = self.resolve_certificate_serial(serial)?;
                if let Some(der) = self.local_certificate(&serial) {
                    return raw_certificate(der, format);
                }
                if let Some(cert) = self.acme_certificate_for_serial(&serial)? {
                    return raw_certificate(&cert.der, format);
                }
                let certificate = self.issued.get(&serial).ok_or_else(not_found)?;
                raw_certificate(&certificate.certificate_der, format)
            }
            PkiPublicRead::Chain => {
                if let Some((_, chain)) = self.public_imported_ca("default") {
                    let certificate = public_chain_pem(&chain);
                    return Ok(ok(
                        json!({"ca_chain":certificate,"certificate":certificate,"revocation_time":0,"revocation_time_rfc3339":""}),
                        false,
                    ));
                }
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let certificate = public_chain_pem(&self.external_ca_chain_pem(root)?);
                Ok(ok(
                    json!({"ca_chain":certificate,"certificate":certificate,"revocation_time":0,"revocation_time_rfc3339":""}),
                    false,
                ))
            }
            PkiPublicRead::FullCrl => {
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                if let Some(response) = self.external_crl_read("cert/crl", now)? {
                    return Ok(response);
                }
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let der = self.crl_der(root, now)?;
                Ok(ok(
                    json!({"certificate":stored_pem("X509 CRL",&der),"revocation_time":0,"revocation_time_rfc3339":""}),
                    false,
                ))
            }
            PkiPublicRead::LocalCrl(delta, format) => {
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                let Some(root) = self.root.as_ref() else {
                    if matches!(format, IssuerCrlFormat::Json) {
                        return Err(not_found());
                    }
                    return Ok(EngineResponse {
                        status: 204,
                        body: json!({"__heptabao_pki_crl":"","pem":matches!(format,IssuerCrlFormat::Pem)}),
                        mutated: false,
                    });
                };
                let der = self.cached_local_crl(root, delta)?;
                if matches!(format, IssuerCrlFormat::Json) {
                    return Ok(ok(
                        json!({"certificate":stored_pem("X509 CRL",der),"revocation_time":0,"revocation_time_rfc3339":""}),
                        false,
                    ));
                }
                Self::local_crl_response(der, format)
            }
            PkiPublicRead::ExternalCrl(path) => {
                self.external_crl_read(path, now)?.ok_or_else(not_found)
            }
            PkiPublicRead::Issuers => {
                if !self.root.as_ref().is_some_and(RootCa::is_external) {
                    let mut info = serde_json::Map::new();
                    for root in self.local_roots() {
                        let name = root
                            .local_fields
                            .as_ref()
                            .map_or("", |fields| fields.issuer_name.as_str());
                        info.insert(root.issuer_id.clone(),json!({"is_default":self.selected_local_issuer_id()==root.issuer_id,"issuer_name":name,"key_id":root.key_id,"serial_number":external::formatted_serial(&root.serial)}));
                    }
                    self.append_public_issuers(&mut info)?;
                    if info.is_empty() {
                        return Ok(EngineResponse {
                            status: 404,
                            body: json!({"errors":[]}),
                            mutated: false,
                        });
                    }
                    return Ok(ok(
                        json!({"keys":info.keys().collect::<Vec<_>>(),"key_info":info}),
                        false,
                    ));
                }
                Ok(self.external_issuers_descriptor())
            }
            PkiPublicRead::IssuerCertificate(reference, format) => {
                if let Some((der, _)) = self.public_imported_ca(reference) {
                    return raw_certificate(der, format);
                }
                let root = self.selected_issuer(reference)?;
                if root.certificate_der.len() > 64 * 1024 {
                    return Err(error(503, "public certificate exceeds bounds"));
                }
                match format {
                    CertificateFormat::Der => raw_certificate(&root.certificate_der, format),
                    CertificateFormat::Pem => {
                        // Issuer-specific PEM has one final LF; legacy public
                        // CA and serial projections retain their no-LF encoding.
                        let bytes = pem("CERTIFICATE", &root.certificate_der).into_bytes();
                        Ok(EngineResponse {
                            status: 200,
                            body: json!({"__heptabao_pki_certificate":BASE64.encode(bytes),"format":"pem"}),
                            mutated: false,
                        })
                    }
                    CertificateFormat::Chain => Err(bad("issuer format is unavailable")),
                }
            }
            PkiPublicRead::IssuerJson(reference) => {
                if let Some((der, chain)) = self.public_imported_ca(reference) {
                    return Ok(ok(
                        json!({"certificate":pem("CERTIFICATE",der),"ca_chain":chain,"issuer_id":self.imported_ca_id(reference).ok_or_else(not_found)?,"issuer_name":""}),
                        false,
                    ));
                }
                let root = self.selected_issuer(reference)?;
                let name = if root.is_external() {
                    self.external_issuer_key(reference)?.issuer_name.as_str()
                } else {
                    root.local_fields
                        .as_ref()
                        .map_or("", |fields| fields.issuer_name.as_str())
                };
                let issuer = if root.is_external() {
                    self.external_issuer_key(reference)?.issuer_id.as_str()
                } else {
                    root.issuer_id.as_str()
                };
                let certificate = pem("CERTIFICATE", &root.certificate_der);
                Ok(ok(
                    json!({"certificate":certificate,"ca_chain":self.issuer_management_ca_chain_pem(root)?,"issuer_id":issuer,"issuer_name":name}),
                    false,
                ))
            }
            PkiPublicRead::IssuerCrl(reference, delta, format) => {
                let root = self.selected_issuer(reference)?;
                let owned_der = if root.is_external() {
                    self.external_issuer_crl_der(reference, delta, now)?
                        .to_vec()
                } else {
                    self.cached_local_crl(root, delta)?.to_vec()
                };
                let der = owned_der.as_slice();
                match format {
                    IssuerCrlFormat::Json => Ok(ok(json!({"crl":pem("X509 CRL",der)}), false)),
                    IssuerCrlFormat::Der | IssuerCrlFormat::Pem => {
                        let is_pem = matches!(format, IssuerCrlFormat::Pem);
                        let bytes = if is_pem {
                            pem("X509 CRL", der).into_bytes()
                        } else {
                            der.to_vec()
                        };
                        if bytes.len() > 512 * 1024 {
                            return Err(error(503, "public CRL exceeds bounds"));
                        }
                        Ok(EngineResponse {
                            status: 200,
                            body: json!({"__heptabao_pki_crl":BASE64.encode(bytes),"pem":is_pem}),
                            mutated: false,
                        })
                    }
                }
            }
            PkiPublicRead::DefaultIssuer => {
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let (issuer, _, name) = self.public_issuer_metadata().ok_or_else(not_found)?;
                let certificate = pem("CERTIFICATE", &root.certificate_der);
                Ok(ok(
                    json!({"certificate":certificate,"ca_chain":self.issuer_management_ca_chain_pem(root)?,"issuer_id":issuer,"issuer_name":name}),
                    false,
                ))
            }
        }
    }
}

#[cfg(test)]
mod public_chain_framing_tests {
    use super::public_chain_pem;

    #[test]
    fn raw112_public_full_chain_trims_each_boundary_and_keeps_internal_pem_lines() {
        let first = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----";
        let second = "-----BEGIN CERTIFICATE-----\nQg==\n-----END CERTIFICATE-----";
        assert_eq!(public_chain_pem(&[format!("\r\n\t {first} \r\n")]), first);
        assert_eq!(
            public_chain_pem(&[format!("\r\n {first}\r\n"), format!("\t{second} \n\n"),]),
            format!("{first}\n{second}")
        );
        assert_eq!(public_chain_pem(&[]), "");
        assert_eq!(public_chain_pem(&[" \t\r\n".to_owned()]), "");
        assert_eq!(public_chain_pem(&[format!("{first}\n"), "".into()]), first);
        let interior = "-----BEGIN CERTIFICATE-----\r\nQQ==\r\n-----END CERTIFICATE-----";
        assert_eq!(public_chain_pem(&[format!(" \n{interior}\n ")]), interior);
    }
}
