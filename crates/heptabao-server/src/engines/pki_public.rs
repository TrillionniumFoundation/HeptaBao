//! Closed public projections retain their original issuer and namespace owner.
//! Projection handling is immutable; Service owns required clock maintenance.
use super::*;

pub(in crate::engines) enum CertificateFormat {
    Der,
    Pem,
    Chain,
}
pub(in crate::engines) enum PkiPublicRead<'a> {
    Ca,
    Certificate(&'a str),
    RawCa(CertificateFormat),
    RawCertificate(&'a str, CertificateFormat),
    Chain,
    FullCrl,
    ExternalCrl(&'a str),
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
    pub(in crate::engines) fn public_read_route<'a>(
        &self,
        method: &str,
        path: &'a str,
    ) -> Option<PkiPublicRead<'a>> {
        if path.contains('?') {
            return None;
        }
        if method == "LIST" && path == "issuers" && self.public_issuer_metadata().is_some() {
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
            "issuer/default/json" if self.public_issuer_metadata().is_some() => {
                Some(PkiPublicRead::DefaultIssuer)
            }
            "cert/delta-crl" | "crl" | "crl/pem" | "crl/delta" | "crl/delta/pem"
                if self.root.as_ref().is_some_and(|root| root.pkcs8.is_empty()) =>
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

    fn require_public_issuer(&self, reference: &str) -> Result<()> {
        let (id, _, name) = self
            .public_issuer_metadata()
            .ok_or_else(|| error(500, "issuer reference is unavailable"))?;
        if reference == "default" || reference == id || (!name.is_empty() && reference == name) {
            Ok(())
        } else {
            // The pinned public 2.7 alias probe returns 500 for unknown names
            // and IDs. Never turn an unknown reference into the default issuer.
            Err(error(500, "issuer reference is unavailable"))
        }
    }

    pub(in crate::engines) fn handle_public_read(
        &self,
        route: PkiPublicRead<'_>,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        match route {
            PkiPublicRead::Ca => {
                let root = self.root.as_ref().ok_or_else(not_found)?;
                Ok(ok(
                    json!({"certificate":stored_pem("CERTIFICATE", &root.certificate_der),"revocation_time":0,"revocation_time_rfc3339":""}),
                    false,
                ))
            }
            PkiPublicRead::RawCa(format) => {
                let root = self.root.as_ref().ok_or_else(not_found)?;
                raw_certificate(&root.certificate_der, format)
            }
            PkiPublicRead::Certificate(serial) => {
                let serial = normalize_serial(serial)?;
                let certificate = self.issued.get(&serial).ok_or_else(not_found)?;
                let mut projection = json!({"certificate":stored_pem("CERTIFICATE", &certificate.certificate_der),"revocation_time":certificate.revoked_at.unwrap_or(0),"revocation_time_rfc3339":certificate.revoked_at.map(timestamp).unwrap_or_default()});
                if let Some((issuer, _, _)) = self.public_issuer_metadata() {
                    projection["issuer_id"] = json!(issuer);
                }
                Ok(ok(projection, false))
            }
            PkiPublicRead::RawCertificate(serial, format) => {
                let serial = normalize_serial(serial)?;
                let certificate = self.issued.get(&serial).ok_or_else(not_found)?;
                raw_certificate(&certificate.certificate_der, format)
            }
            PkiPublicRead::Chain => {
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let certificate = stored_pem("CERTIFICATE", &root.certificate_der);
                Ok(ok(
                    json!({"ca_chain":certificate,"certificate":certificate,"revocation_time":0,"revocation_time_rfc3339":""}),
                    false,
                ))
            }
            PkiPublicRead::FullCrl => {
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
            PkiPublicRead::ExternalCrl(path) => {
                self.external_crl_read(path, now)?.ok_or_else(not_found)
            }
            PkiPublicRead::Issuers => {
                let root = self.root.as_ref().ok_or_else(not_found)?;
                let (issuer, key, name) = self.public_issuer_metadata().ok_or_else(not_found)?;
                Ok(ok(
                    json!({"keys":[issuer],"key_info":{issuer:{"is_default":true,"issuer_name":name,"key_id":key,"serial_number":external::formatted_serial(&root.serial)}}}),
                    false,
                ))
            }
            PkiPublicRead::IssuerCertificate(reference, format) => {
                self.require_public_issuer(reference)?;
                let root = self.root.as_ref().ok_or_else(not_found)?;
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
                self.require_public_issuer(reference)?;
                self.handle_public_read(PkiPublicRead::DefaultIssuer, body, now)
            }
            PkiPublicRead::IssuerCrl(reference, delta, format) => {
                self.require_public_issuer(reference)?;
                let der = self.external_crl_der(delta, now)?.ok_or_else(not_found)?;
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
                    json!({"certificate":certificate,"ca_chain":[certificate],"issuer_id":issuer,"issuer_name":name}),
                    false,
                ))
            }
        }
    }
}
