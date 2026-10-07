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

impl Pki {
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
                            body: json!({"__heptabao_pki_certificate":BASE64.encode(chain.join("\n").as_bytes()),"format":"chain"}),
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
                    let bytes = self.external_ca_chain_pem(root)?.join("\n").into_bytes();
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
                    let certificate = chain.join("\n").trim_end().to_owned();
                    return Ok(ok(
                        json!({"ca_chain":certificate,"certificate":certificate,"revocation_time":0,"revocation_time_rfc3339":""}),
                        false,
                    ));
                }
                if self.has_public_default_override() {
                    return Err(not_found());
                }
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let certificate = self
                    .external_ca_chain_pem(root)?
                    .join("\n")
                    .trim_end()
                    .to_owned();
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
