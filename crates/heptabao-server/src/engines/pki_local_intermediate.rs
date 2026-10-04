//! Owned pending CSR keys and imported CA chains. A public CA has no signing
//! authority until its actual SPKI matches a locally owned key. Certificate
//! subjects, issuer DNs and constraints remain the signed certificate's values.
use super::*;
use openssl::{
    pkey::PKey,
    x509::{X509, X509Req},
};
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    prelude::{FromDer, X509Certificate},
};

const MAX_PENDING_KEYS: usize = 256;
const MAX_CHAIN: usize = 16;
const MAX_CA_BUNDLE: usize = 512 * 1024;
const CSR_FIELDS: &[&str] = &[
    "common_name",
    "key_type",
    "key_bits",
    "key_name",
    "format",
    "private_key_format",
    "alt_names",
    "ip_sans",
    "uri_sans",
    "exclude_cn_from_sans",
    "ou",
    "organization",
    "country",
    "locality",
    "province",
    "street_address",
    "postal_code",
    "serial_number",
];
const SIGN_FIELDS: &[&str] = &[
    "csr",
    "common_name",
    "ttl",
    "format",
    "use_csr_values",
    "alt_names",
    "ip_sans",
    "uri_sans",
    "exclude_cn_from_sans",
    "ou",
    "organization",
    "country",
    "locality",
    "province",
    "street_address",
    "postal_code",
    "serial_number",
    "not_before_duration",
    "not_after",
    "max_path_length",
    "permitted_dns_domains",
];

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalIntermediateState {
    pending: BTreeMap<String, PendingCsr>,
    public_issuers: BTreeMap<String, ImportedCa>,
    first_pending_key_id: String,
    signed_certificates: BTreeMap<String, SignedCa>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCsr {
    material: LocalPrivateMaterial,
    csr_der: Vec<u8>,
    key_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedCa {
    certificate_der: Vec<u8>,
    parents: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCa {
    certificate_der: Vec<u8>,
    parents: Vec<Vec<u8>>,
    issuer_id: String,
    issued: u64,
    expires: u64,
    revoked_at: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalCaChain {
    csr_der: Vec<u8>,
    parents: Vec<Vec<u8>>,
}

fn invalid<T>(_: T) -> EngineError {
    bad("invalid local PKI CSR or CA chain")
}

fn certificate(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(bad("CA certificate is outside bounds"));
    }
    let (rest, cert) = X509Certificate::from_der(bytes).map_err(invalid)?;
    if !rest.is_empty()
        || cert.signature_value.unused_bits != 0
        || cert.signature_algorithm != cert.tbs_certificate.signature
        || !cert
            .basic_constraints()
            .map_err(invalid)?
            .is_some_and(|c| c.value.ca)
        || cert
            .key_usage()
            .map_err(invalid)?
            .is_some_and(|u| !u.value.key_cert_sign())
    {
        return Err(bad("invalid signing CA certificate"));
    }
    Ok(cert)
}

fn certificate_signed_by(bytes: &[u8], parent: &[u8]) -> Result<()> {
    let cert = certificate(bytes)?;
    let issuer = certificate(parent)?;
    if cert.issuer() != issuer.subject() {
        return Err(bad("CA issuer DN does not match parent"));
    }
    let public = LocalPublicKey::from_spki(issuer.public_key().raw)?;
    let verified = match (
        X509::from_der(bytes),
        PKey::public_key_from_der(issuer.public_key().raw),
    ) {
        (Ok(cert), Ok(key)) => cert.verify(&key).map_err(invalid)?,
        _ => {
            let algorithm = public.kind().signature_algorithm();
            let (rest, parsed) =
                x509_parser::x509::AlgorithmIdentifier::from_der(&algorithm).map_err(invalid)?;
            rest.is_empty()
                && cert.signature_algorithm == parsed
                && public.verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)?
        }
    };
    if !verified {
        return Err(bad("CA chain signature invalid"));
    }
    Ok(())
}

fn validate_chain(leaf: &[u8], parents: &[Vec<u8>]) -> Result<()> {
    if parents.len() > MAX_CHAIN || parents.iter().map(Vec::len).sum::<usize>() > MAX_CA_BUNDLE {
        return Err(bad("CA chain exceeds bounds"));
    }
    let mut current = leaf;
    let mut seen = BTreeSet::new();
    seen.insert(crypto_digest(leaf));
    for parent in parents {
        if !seen.insert(crypto_digest(parent)) {
            return Err(bad("CA chain repeats a certificate"));
        }
        certificate_signed_by(current, parent)?;
        current = parent;
    }
    certificate_signed_by(current, current)
}

fn crypto_digest(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn parse_csr(bytes: &[u8]) -> Result<X509CertificationRequest<'_>> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(bad("CSR exceeds bounds"));
    }
    let (rest, csr) = X509CertificationRequest::from_der(bytes).map_err(invalid)?;
    if !rest.is_empty()
        || csr.certification_request_info.version.0 != 0
        || csr.signature_value.unused_bits != 0
    {
        return Err(bad("invalid CSR encoding"));
    }
    let public = LocalPublicKey::from_spki(csr.certification_request_info.subject_pki.raw)?;
    let valid = match (
        X509Req::from_der(bytes),
        PKey::public_key_from_der(&public.spki()?),
    ) {
        (Ok(request), Ok(key)) => {
            request.to_der().map_err(invalid)? == bytes && request.verify(&key).map_err(invalid)?
        }
        _ => {
            let algorithm = public.kind().signature_algorithm();
            let (rest, parsed) =
                x509_parser::x509::AlgorithmIdentifier::from_der(&algorithm).map_err(invalid)?;
            rest.is_empty()
                && parsed == csr.signature_algorithm
                && public.verify(
                    csr.certification_request_info.raw,
                    &csr.signature_value.data,
                )?
        }
    };
    if !valid {
        return Err(bad("request signature invalid"));
    }
    csr.certification_request_info
        .attributes_map()
        .map_err(invalid)?;
    Ok(csr)
}

fn pem_blocks(input: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    if input.len() > MAX_CA_BUNDLE || input.is_empty() {
        return Err(bad("PEM input exceeds bounds"));
    }
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = input.trim();
    let mut values = Vec::new();
    while !rest.is_empty() {
        if values.len() >= MAX_CHAIN + 1 {
            return Err(bad("PEM bundle exceeds bounds"));
        }
        let payload = rest
            .strip_prefix(&begin)
            .ok_or_else(|| bad("invalid PEM input"))?;
        let (encoded, next) = payload
            .split_once(&end)
            .ok_or_else(|| bad("unterminated PEM input"))?;
        let encoded: String = encoded
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let decoded = BASE64.decode(encoded).map_err(invalid)?;
        if decoded.is_empty() || decoded.len() > 64 * 1024 {
            return Err(bad("PEM object exceeds bounds"));
        }
        values.push(decoded);
        rest = next.trim();
    }
    Ok(values)
}

fn csr_from_body(body: &Value) -> Result<Vec<u8>> {
    let text = string(body, "csr")?;
    let mut values = pem_blocks(text, "CERTIFICATE REQUEST")?;
    if values.len() != 1 {
        return Err(bad("one CSR is required"));
    }
    let bytes = values.remove(0);
    parse_csr(&bytes)?;
    Ok(bytes)
}

fn common_name(subject: &x509_parser::x509::X509Name<'_>) -> Result<String> {
    let value = subject
        .iter_common_name()
        .next()
        .map(|name| name.as_str().map(str::to_owned))
        .transpose()
        .map_err(invalid)?
        .unwrap_or_default();
    if !external::common_name_valid(&value) {
        return Err(bad("invalid CA common name"));
    }
    Ok(value)
}

fn sans(fields: &RootFields, common_name: &str) -> Vec<u8> {
    let mut values = Vec::new();
    if !fields.exclude_cn {
        values.push(context_primitive(2, common_name.as_bytes()));
    }
    values.extend(
        fields
            .dns_sans
            .iter()
            .map(|n| context_primitive(2, n.as_bytes())),
    );
    values.extend(
        fields
            .email_sans
            .iter()
            .map(|n| context_primitive(1, n.as_bytes())),
    );
    values.extend(fields.ip_sans.iter().map(|n| {
        context_primitive(
            7,
            &match n {
                IpAddr::V4(n) => n.octets().to_vec(),
                IpAddr::V6(n) => n.octets().to_vec(),
            },
        )
    }));
    values.extend(
        fields
            .uri_sans
            .iter()
            .map(|n| context_primitive(6, n.as_bytes())),
    );
    if values.is_empty() {
        Vec::new()
    } else {
        vec![extension(&[0x55, 0x1d, 0x11], false, &seq(&values))].concat()
    }
}

fn csr_der(
    material: &LocalPrivateMaterial,
    fields: &RootFields,
    common_name: &str,
) -> Result<Vec<u8>> {
    let extensions = sans(fields, common_name);
    let attributes = if extensions.is_empty() {
        Vec::new()
    } else {
        seq(&[
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 14]),
            set(&[der(0x30, &extensions)]),
        ])
    };
    let info = seq(&[
        integer(&[0]),
        fields.subject_der.clone(),
        material.public()?.spki()?,
        der(0xa0, &attributes),
    ]);
    let signature = material.sign(&info)?;
    let bytes = seq(&[
        info,
        material.kind().signature_algorithm(),
        bit_string(&signature, 0),
    ]);
    parse_csr(&bytes)?;
    Ok(bytes)
}

impl LocalCaChain {
    pub(super) fn validate(&self, certificate_der: &[u8], public: &LocalPublicKey) -> Result<()> {
        let csr = parse_csr(&self.csr_der)?;
        let cert = certificate(certificate_der)?;
        if csr.certification_request_info.subject_pki.raw != public.spki()?
            || cert.public_key().raw != public.spki()?
        {
            return Err(bad("CA certificate or CSR does not match its owned key"));
        }
        validate_chain(certificate_der, &self.parents)
    }
}

impl RootCa {
    pub(super) fn validate_local_certificate(&self) -> Result<()> {
        let public = self.local_key()?.public()?;
        match &self.local_chain {
            None => public.validate_certificate(&self.certificate_der),
            Some(chain) => {
                chain.validate(&self.certificate_der, &public)?;
                let cert = certificate(&self.certificate_der)?;
                if common_name(cert.subject())? != self.common_name
                    || normalize_serial(&cert.raw_serial_as_string())? != self.serial
                    || u64::try_from(cert.validity().not_before.timestamp()).ok()
                        != Some(self.not_before)
                    || u64::try_from(cert.validity().not_after.timestamp()).ok()
                        != Some(self.not_after)
                {
                    return Err(bad("owned CA certificate metadata changed"));
                }
                Ok(())
            }
        }
    }

    pub(super) fn local_ca_chain_pem(&self) -> Vec<String> {
        let mut chain = vec![pem("CERTIFICATE", &self.certificate_der)];
        if let Some(value) = &self.local_chain {
            chain.extend(value.parents.iter().map(|der| pem("CERTIFICATE", der)));
        }
        chain
    }
}

impl Pki {
    pub(in crate::engines) fn has_local_intermediate_state(&self) -> bool {
        self.local_intermediate.is_some() || self.has_archived_local_ca_chain()
    }

    pub(super) fn delete_intermediate_material(&mut self) -> bool {
        let Some(state) = &mut self.local_intermediate else {
            return false;
        };
        let changed = !state.pending.is_empty() || !state.public_issuers.is_empty();
        state.pending.clear();
        state.public_issuers.clear();
        state.first_pending_key_id.clear();
        changed
    }

    pub(super) fn intermediate_certificate(&self, serial: &str) -> Option<&[u8]> {
        self.local_intermediate
            .as_ref()?
            .signed_certificates
            .get(serial)
            .map(|ca| ca.certificate_der.as_slice())
    }

    pub(super) fn signed_ca_revocation_time(&self, serial: &str) -> Option<u64> {
        self.local_intermediate
            .as_ref()?
            .signed_certificates
            .get(serial)?
            .revoked_at
    }

    pub(super) fn signed_ca_serials(&self) -> impl Iterator<Item = &String> {
        self.local_intermediate
            .iter()
            .flat_map(|state| state.signed_certificates.keys())
    }

    pub(super) fn signed_ca_revocations(&self, issuer: &RootCa) -> BTreeMap<String, u64> {
        self.local_intermediate
            .iter()
            .flat_map(|s| s.signed_certificates.iter())
            .filter_map(|(serial, ca)| {
                ca.revoked_at
                    .filter(|_| ca.issuer_id == issuer.issuer_id)
                    .map(|at| (serial.clone(), at))
            })
            .collect()
    }

    pub(super) fn revoke_signed_ca(
        &mut self,
        serial: &str,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        let Some(ca) = self
            .local_intermediate
            .as_ref()
            .and_then(|s| s.signed_certificates.get(serial))
        else {
            return Ok(None);
        };
        if ca.revoked_at.is_none()
            && ca.expires < now.saturating_add(2)
            && !self.local_expired_revocation_allowed()
        {
            return Ok(Some(EngineResponse {
                status: 200,
                body: json!({"warnings":["certificate already expired; refusing to add to CRL"]}),
                mutated: false,
            }));
        }
        let ca = self
            .local_intermediate
            .as_mut()
            .and_then(|s| s.signed_certificates.get_mut(serial))
            .ok_or_else(not_found)?;
        let changed = ca.revoked_at.is_none();
        if changed {
            ca.revoked_at = Some(now.max(ca.issued));
        }
        let at = ca.revoked_at.unwrap_or(0);
        if changed {
            self.local_revocation_changed(now)?;
        }
        Ok(Some(ok(
            json!({"revocation_time":at,"revocation_time_rfc3339":timestamp(at),"state":"revoked"}),
            changed,
        )))
    }

    pub(super) fn pending_key_default(&self) -> &str {
        self.local_intermediate
            .as_ref()
            .map_or("", |state| state.first_pending_key_id.as_str())
    }

    pub(super) fn append_pending_keys(
        &self,
        info: &mut serde_json::Map<String, Value>,
        default: &str,
    ) {
        if let Some(state) = &self.local_intermediate {
            for (id, key) in &state.pending {
                info.insert(
                    id.clone(),
                    json!({"key_name":key.key_name,"is_default":id==default}),
                );
            }
        }
    }

    pub(super) fn append_public_issuers(
        &self,
        info: &mut serde_json::Map<String, Value>,
    ) -> Result<()> {
        if let Some(state) = &self.local_intermediate {
            for (id, ca) in &state.public_issuers {
                let cert = certificate(&ca.certificate_der)?;
                info.insert(id.clone(),json!({"issuer_name":"","is_default":false,"key_id":"","serial_number":external::formatted_serial(&normalize_serial(&cert.raw_serial_as_string())?)}));
            }
        }
        Ok(())
    }

    pub(super) fn public_imported_ca(&self, reference: &str) -> Option<(&[u8], Vec<String>)> {
        let ca = self
            .local_intermediate
            .as_ref()?
            .public_issuers
            .get(reference)?;
        let mut chain = vec![pem("CERTIFICATE", &ca.certificate_der)];
        chain.extend(ca.parents.iter().map(|der| pem("CERTIFICATE", der)));
        Some((&ca.certificate_der, chain))
    }

    pub(super) fn validate_local_intermediate(&self, clock: u64) -> Result<()> {
        let Some(state) = &self.local_intermediate else {
            if self.has_archived_local_ca_chain() {
                return Err(bad("CA chain state marker missing"));
            }
            return Ok(());
        };
        if state.pending.len() > MAX_PENDING_KEYS
            || state.public_issuers.len() > MAX_ISSUED
            || state.signed_certificates.len() > MAX_ISSUED
        {
            return Err(bad("intermediate state exceeds bounds"));
        }
        let mut names: BTreeSet<_> = self
            .local_keys()
            .filter_map(|key| key.local_fields.as_ref().map(|fields| &fields.key_name))
            .filter(|name| !name.is_empty())
            .collect();
        for (id, pending) in &state.pending {
            if !valid_pki_id(id)
                || id.is_empty()
                || self.local_keys().any(|key| key.key_id == *id)
                || !pending.key_name.is_empty() && !names.insert(&pending.key_name)
            {
                return Err(bad("invalid pending CA key identity"));
            }
            let fields = LocalRootMetadata {
                issuer_name: String::new(),
                key_name: pending.key_name.clone(),
            };
            fields.validate()?;
            let csr = parse_csr(&pending.csr_der)?;
            if csr.certification_request_info.subject_pki.raw
                != pending.material.public()?.spki()?
            {
                return Err(bad("pending CSR key changed"));
            }
        }
        if !state.first_pending_key_id.is_empty()
            && !state.pending.contains_key(&state.first_pending_key_id)
            && !self
                .local_keys()
                .any(|key| key.key_id == state.first_pending_key_id)
        {
            return Err(bad("pending key default lost ownership"));
        }
        for (id, ca) in &state.public_issuers {
            if !valid_pki_id(id)
                || id.is_empty()
                || self.local_roots().any(|root| root.issuer_id == *id)
            {
                return Err(bad("invalid public CA identity"));
            }
            validate_chain(&ca.certificate_der, &ca.parents)?;
        }
        for (serial, ca) in &state.signed_certificates {
            let cert = certificate(&ca.certificate_der)?;
            if normalize_serial(&cert.raw_serial_as_string())? != *serial
                || !valid_pki_id(&ca.issuer_id)
                || ca.issuer_id.is_empty()
                || ca.parents.is_empty()
                || ca.issued > clock
                || ca.issued >= ca.expires
                || ca.expires - ca.issued > MAX_TTL
                || ca.revoked_at.is_some_and(|at| at < ca.issued || at > clock)
                || u64::try_from(cert.validity().not_after.timestamp()).ok() != Some(ca.expires)
                || cert.validity().not_before.timestamp()
                    > i64::try_from(ca.issued).map_err(invalid)?
                || self.issued.contains_key(serial)
                || self.local_issuer_certificate_by_id(&ca.issuer_id)
                    != ca.parents.first().map(Vec::as_slice)
            {
                return Err(bad("signed CA issuer ownership changed"));
            }
            validate_chain(&ca.certificate_der, &ca.parents)?;
        }
        Ok(())
    }

    pub(super) fn handle_local_intermediate(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        if method == "DELETE"
            && let Some(reference) = path.strip_prefix("issuer/")
            && !reference.contains('/')
            && self.public_imported_ca(reference).is_some()
        {
            reject_unknown(body, &[])?;
            self.local_intermediate
                .as_mut()
                .ok_or_else(not_found)?
                .public_issuers
                .remove(reference);
            return Ok(Some(ok(Value::Null, true)));
        }
        let response = match path {
            "config/keys" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                self.local_key_config(method, body)?
            }
            "intermediate/generate/internal" | "intermediate/generate/exported" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.generate_local_csr(body, path.ends_with("exported"))?
            }
            "intermediate/set-signed" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.import_local_ca(body, now)?
            }
            "root/sign-intermediate" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.sign_local_intermediate("default", body, now)?
            }
            _ => {
                if let Some(reference) = path
                    .strip_prefix("issuer/")
                    .and_then(|p| p.strip_suffix("/sign-intermediate"))
                {
                    if reference.is_empty() || reference.contains('/') {
                        return Err(not_found());
                    }
                    if !write_method(method) {
                        return Err(unsupported());
                    }
                    self.sign_local_intermediate(reference, body, now)?
                } else {
                    return Ok(None);
                }
            }
        };
        Ok(Some(response))
    }

    fn local_key_config(&mut self, method: &str, body: &Value) -> Result<EngineResponse> {
        if method == "GET" {
            reject_unknown(body, &[])?;
            return Ok(ok(json!({"default":self.default_local_key_id()}), false));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["default"])?;
        let reference = string(body, "default")?;
        if reference.is_empty() || reference == "default" {
            return Err(bad("default key must be specified"));
        }
        let selected = self
            .local_keys()
            .find(|key| key.key_id == reference)
            .or_else(|| {
                self.local_keys().find(|key| {
                    key.local_fields.as_ref().is_some_and(|fields| {
                        !fields.key_name.is_empty() && fields.key_name == reference
                    })
                })
            })
            .map(|key| key.key_id.clone())
            .or_else(|| {
                self.local_intermediate.as_ref().and_then(|state| {
                    state
                        .pending
                        .iter()
                        .find(|(id, key)| {
                            *id == reference
                                || !key.key_name.is_empty() && key.key_name == reference
                        })
                        .map(|(id, _)| id.clone())
                })
            })
            .ok_or_else(|| bad("default key reference is unavailable"))?;
        let changed = selected != self.default_local_key_id();
        if changed {
            self.local_intermediate
                .get_or_insert_with(Box::default)
                .first_pending_key_id = selected;
        }
        Ok(ok(json!({"default":self.default_local_key_id()}), changed))
    }

    fn generate_local_csr(&mut self, body: &Value, exported: bool) -> Result<EngineResponse> {
        reject_unknown(body, CSR_FIELDS)?;
        let common_name = string(body, "common_name")?;
        if !external::common_name_valid(common_name) {
            return Err(bad("invalid CSR common name"));
        }
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(bad("local CSR cannot borrow external authority"));
        }
        if self
            .local_intermediate
            .as_ref()
            .is_some_and(|s| s.pending.len() >= MAX_PENDING_KEYS)
        {
            return Err(error(507, "pending CA key capacity exhausted"));
        }
        let fields = RootFields::from_body(body, common_name)?;
        self.admit_local_root_names(&fields)?;
        if matches!(
            body.get("private_key_format"),
            Some(Value::Array(_) | Value::Object(_))
        ) {
            return Err(bad("invalid PKI private key format"));
        }
        let name = fields
            .metadata
            .as_ref()
            .map_or("", |m| m.key_name.as_str())
            .to_owned();
        if !name.is_empty()
            && self
                .local_intermediate
                .as_ref()
                .is_some_and(|s| s.pending.values().any(|k| k.key_name == name))
        {
            return Err(bad("PKI key name already exists"));
        }
        let material = LocalPrivateMaterial::generate(LocalKeyKind::from_body(body)?)?;
        let csr = csr_der(&material, &fields, common_name)?;
        let id = random_pki_id()?;
        if self.local_keys().any(|key| key.key_id == id)
            || self
                .local_intermediate
                .as_ref()
                .is_some_and(|s| s.pending.contains_key(&id))
        {
            return Err(error(503, "PKI key identifier collision"));
        }
        let format = RootOutputFormat::from_body(body)?;
        let mut data = json!({"csr":match format {RootOutputFormat::Der=>BASE64.encode(&csr),_=>pem("CERTIFICATE REQUEST",&csr)},"key_id":id});
        if exported {
            let (key, label) = material.root_export_der(
                matches!(body.get("private_key_format"),Some(Value::String(v))if v=="pkcs8"),
            )?;
            let encoded = Zeroizing::new(if matches!(format, RootOutputFormat::Der) {
                BASE64.encode(key.as_slice())
            } else {
                pem(label, key.as_slice())
            });
            data["private_key"] = json!(encoded.as_str());
            data["private_key_type"] = json!(material.kind().key_type());
            if matches!(format, RootOutputFormat::PemBundle) {
                data["csr"] = json!(format!(
                    "{}\n{}",
                    encoded.as_str(),
                    pem("CERTIFICATE REQUEST", &csr)
                ));
            }
        }
        let previous_default = self.default_local_key_id().to_owned();
        let state = self.local_intermediate.get_or_insert_with(Box::default);
        if state.first_pending_key_id.is_empty() {
            state.first_pending_key_id = if previous_default.is_empty() {
                id.clone()
            } else {
                previous_default
            };
        }
        state.pending.insert(
            id,
            PendingCsr {
                material,
                csr_der: csr,
                key_name: name,
            },
        );
        Ok(ok(data, true))
    }

    fn sign_local_intermediate(
        &mut self,
        reference: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, SIGN_FIELDS)?;
        let bytes = csr_from_body(body)?;
        let csr = parse_csr(&bytes)?;
        self.promote_default_associations()?;
        let root = self.local_issuer(reference)?;
        if self
            .local_intermediate
            .as_ref()
            .is_some_and(|s| s.signed_certificates.len() >= MAX_ISSUED)
        {
            return Err(error(507, "signed CA certificate capacity exhausted"));
        }
        if now >= root.not_after {
            return Err(error(503, "PKI issuer has expired"));
        }
        let cname = body
            .get("common_name")
            .map(|v| v.as_str().ok_or_else(|| bad("invalid CA common name")))
            .transpose()?
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .unwrap_or(common_name(&csr.certification_request_info.subject)?);
        let mut fields = RootFields::from_body(body, &cname)?;
        if optional_bool(body, "use_csr_values")?.unwrap_or(false) {
            fields.subject_der = csr.certification_request_info.subject.as_raw().to_vec();
            fields.dns_sans.clear();
            fields.email_sans.clear();
            fields.ip_sans.clear();
            fields.uri_sans.clear();
            fields.exclude_cn = true;
            if let Some(extensions) = csr.requested_extensions() {
                for extension in extensions {
                    if let ParsedExtension::SubjectAlternativeName(names) = extension {
                        for name in &names.general_names {
                            match name {
                                GeneralName::DNSName(v) => fields.dns_sans.push((*v).to_owned()),
                                GeneralName::RFC822Name(v) => {
                                    fields.email_sans.push((*v).to_owned())
                                }
                                GeneralName::URI(v) => fields.uri_sans.push((*v).to_owned()),
                                GeneralName::IPAddress(v) => {
                                    let ip = if v.len() == 4 {
                                        IpAddr::V4(std::net::Ipv4Addr::from(
                                            <[u8; 4]>::try_from(*v).map_err(invalid)?,
                                        ))
                                    } else {
                                        IpAddr::V6(std::net::Ipv6Addr::from(
                                            <[u8; 16]>::try_from(*v).map_err(invalid)?,
                                        ))
                                    };
                                    fields.ip_sans.push(ip);
                                }
                                _ => return Err(bad("unsupported CSR SAN kind")),
                            }
                        }
                    }
                }
            }
        }
        let (_, parent) = X509Certificate::from_der(&root.certificate_der).map_err(invalid)?;
        if !body
            .as_object()
            .is_some_and(|v| v.contains_key("max_path_length"))
        {
            fields.max_path_length = parent
                .basic_constraints()
                .map_err(invalid)?
                .and_then(|v| v.value.path_len_constraint.map(|n| n.saturating_sub(1)));
        }
        if parent
            .basic_constraints()
            .map_err(invalid)?
            .is_some_and(|v| v.value.path_len_constraint == Some(0))
        {
            return Err(bad("issuer max path length is zero"));
        }
        let permitted = string_list(body.get("permitted_dns_domains"))?;
        if permitted.len() > 64
            || permitted
                .iter()
                .any(|d| !valid_domain(d.strip_prefix('.').unwrap_or(d)))
        {
            return Err(bad("invalid permitted DNS domains"));
        }
        let public = LocalPublicKey::from_spki(csr.certification_request_info.subject_pki.raw)?;
        let material = root.local_key()?;
        let serial = random_serial()?;
        let expires = root_fields::root_expiration(body, now, self.max_ttl, self.default_ttl)?;
        let ski = root_fields::certificate_key_identifier(&root.certificate_der)?;
        let issuer_name = root_fields::certificate_subject(&root.certificate_der)?;
        let cert = certificate_der_local(
            &material,
            &public,
            CertificateSpec {
                serial: &serial,
                issuer_cn: &root.common_name,
                subject_cn: &cname,
                issuer_name_der: Some(&issuer_name),
                subject_name_der: Some(&fields.subject_der),
                public_key: &[],
                authority_key_id: ski.as_deref(),
                not_before: now.saturating_sub(fields.backdate),
                not_after: expires,
                is_ca: true,
                alt_names: &fields.dns_sans,
                email_sans: &fields.email_sans,
                ip_sans: &fields.ip_sans,
                uri_sans: &fields.uri_sans,
                exclude_cn_from_sans: fields.exclude_cn,
                max_path_length: fields.max_path_length,
                permitted_dns_domains: &permitted,
            },
        )?;
        certificate_signed_by(&cert, &root.certificate_der)?;
        let format = RootOutputFormat::from_body(body)?;
        let mut chain = vec![pem("CERTIFICATE", &cert)];
        chain.extend(root.local_ca_chain_pem());
        let issuing = pem("CERTIFICATE", &root.certificate_der);
        let certificate = if matches!(format, RootOutputFormat::PemBundle) {
            chain.join("\n")
        } else {
            format.certificate(&cert)
        };
        let issuer_id = root.issuer_id.clone();
        let parents: Vec<_> = std::iter::once(root.certificate_der.clone())
            .chain(
                root.local_chain
                    .iter()
                    .flat_map(|chain| chain.parents.clone()),
            )
            .collect();
        if self.intermediate_certificate(&serial).is_some()
            || self.local_certificate(&serial).is_some()
            || self.issued.contains_key(&serial)
        {
            return Err(error(503, "signed CA serial collision"));
        }
        self.local_intermediate
            .get_or_insert_with(Box::default)
            .signed_certificates
            .insert(
                serial.clone(),
                SignedCa {
                    certificate_der: cert,
                    parents,
                    issuer_id,
                    issued: now,
                    expires,
                    revoked_at: None,
                },
            );
        let mut response = ok(
            json!({"certificate":certificate,"issuing_ca":issuing,"ca_chain":chain,"serial_number":external::formatted_serial(&serial),"expiration":expires}),
            true,
        );
        if fields.max_path_length == Some(0) {
            response.body["warnings"] = json!([
                "Max path length of the signed certificate is zero. This certificate cannot be used to issue intermediate CA certificates."
            ]);
        }
        Ok(response)
    }

    fn import_local_ca(&mut self, body: &Value, now: u64) -> Result<EngineResponse> {
        let mut candidate = self.clone();
        let response = candidate.import_local_ca_inner(body, now)?;
        *self = candidate;
        Ok(response)
    }

    fn import_local_ca_inner(&mut self, body: &Value, now: u64) -> Result<EngineResponse> {
        reject_unknown(body, &["certificate"])?;
        let objects = pem_blocks(string(body, "certificate")?, "CERTIFICATE")?;
        for der in &objects {
            certificate(der)?;
        }
        let mut planned = Vec::new();
        for der in &objects {
            let cert = certificate(der)?;
            let mut parents = Vec::new();
            let mut current = der.as_slice();
            loop {
                let c = certificate(current)?;
                if c.subject() == c.issuer() {
                    certificate_signed_by(current, current)?;
                    break;
                }
                if parents.len() >= MAX_CHAIN {
                    return Err(bad("CA chain exceeds bounds"));
                }
                let next = objects
                    .iter()
                    .find(|p| certificate(p).is_ok_and(|p| p.subject() == c.issuer()))
                    .ok_or_else(|| bad("CA chain parent missing"))?;
                certificate_signed_by(current, next)?;
                if parents.iter().any(|p| p == next) {
                    return Err(bad("CA chain cycle"));
                }
                parents.push(next.clone());
                current = next;
            }
            validate_chain(der, &parents)?;
            if let Some(existing) = self.local_roots().find(|r| r.certificate_der == *der) {
                planned.push((
                    existing.issuer_id.clone(),
                    existing.key_id.clone(),
                    false,
                    None,
                ));
                continue;
            }
            if let Some((id, _)) = self.local_intermediate.as_ref().and_then(|s| {
                s.public_issuers
                    .iter()
                    .find(|(_, ca)| ca.certificate_der == *der)
            }) {
                planned.push((id.clone(), String::new(), false, None));
                continue;
            }
            let matched = self
                .local_intermediate
                .as_ref()
                .and_then(|state| {
                    state.pending.iter().find(|(_, p)| {
                        p.material
                            .public()
                            .is_ok_and(|k| k.spki().is_ok_and(|spki| spki == cert.public_key().raw))
                    })
                })
                .map(|(id, _)| id.clone());
            planned.push((
                random_pki_id()?,
                matched.unwrap_or_default(),
                true,
                Some((der.clone(), parents)),
            ));
        }
        if self.local_roots().count() + planned.iter().filter(|p| p.2 && !p.1.is_empty()).count()
            > 256
            || self
                .local_intermediate
                .as_ref()
                .map_or(0, |s| s.public_issuers.len())
                + planned.iter().filter(|p| p.2 && p.1.is_empty()).count()
                > MAX_ISSUED
        {
            return Err(error(507, "CA import capacity exhausted"));
        }
        let mut mapping = serde_json::Map::new();
        let mut imported = Vec::new();
        let mut existing = Vec::new();
        for (id, key, new, object) in planned {
            mapping.insert(id.clone(), json!(key));
            if !new {
                existing.push(id);
                continue;
            }
            imported.push(id.clone());
            let (der, parents) = object.ok_or_else(|| bad("CA import plan changed"))?;
            if key.is_empty() {
                self.local_intermediate
                    .get_or_insert_with(Box::default)
                    .public_issuers
                    .insert(
                        id,
                        ImportedCa {
                            certificate_der: der,
                            parents,
                        },
                    );
            } else {
                let pending = self
                    .local_intermediate
                    .as_mut()
                    .and_then(|s| s.pending.remove(&key))
                    .ok_or_else(|| bad("owned CSR key changed"))?;
                let cert = certificate(&der)?;
                let common_name = common_name(cert.subject())?;
                let serial = normalize_serial(&cert.raw_serial_as_string())?;
                let not_before =
                    u64::try_from(cert.validity().not_before.timestamp()).map_err(invalid)?;
                let not_after =
                    u64::try_from(cert.validity().not_after.timestamp()).map_err(invalid)?;
                let kind = pending.material.kind();
                let pkcs8 = if kind == LocalKeyKind::Ed25519 {
                    pending.material.private_der()?.to_vec()
                } else {
                    Vec::new()
                };
                let material = if kind == LocalKeyKind::Ed25519 {
                    None
                } else {
                    Some(pending.material)
                };
                let root = RootCa {
                    common_name,
                    issuer_id: id,
                    key_id: key,
                    local_fields: Some(Box::new(LocalRootMetadata {
                        issuer_name: String::new(),
                        key_name: pending.key_name,
                    })),
                    pkcs8,
                    local_material: material,
                    local_chain: Some(Box::new(LocalCaChain {
                        csr_der: pending.csr_der,
                        parents,
                    })),
                    certificate_der: der,
                    serial,
                    not_before,
                    not_after,
                };
                root.validate_local_certificate()?;
                self.publish_local_root(root)?;
            }
        }
        self.maintain_local_crl(now)?;
        Ok(ok(
            json!({"mapping":mapping,"imported_keys":Value::Null,"existing_keys":Value::Null,"imported_issuers":if imported.is_empty(){Value::Null}else{json!(imported)},"existing_issuers":if existing.is_empty(){Value::Null}else{json!(existing)}}),
            true,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::public::PkiPublicRead;
    use super::*;
    use openssl::{
        stack::Stack,
        x509::{X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
    };
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    const NOW: u64 = 1_700_000_000;

    fn root() -> Result<Pki> {
        let mut p = Pki::default();
        p.handle_admin("POST","root/generate/internal",&json!({"common_name":"root.example.test","key_type":"ec","key_bits":384,"ttl":"72h","max_path_length":2}),NOW)?;
        Ok(p)
    }

    fn setup() -> Result<(Pki, Pki)> {
        let mut root = root()?;
        let mut intermediate = Pki::default();
        let csr=intermediate.handle_admin("POST","intermediate/generate/internal",&json!({"common_name":"inter.example.test","key_type":"ec","key_bits":256,"key_name":"owned-key","organization":["Intermediate Organization"],"alt_names":"csr.example.test,csr@example.test","uri_sans":"spiffe://example.test/ca"}),NOW)?;
        assert!(intermediate.root.is_none());
        assert!(
            intermediate.local_key_list(&json!({}))?.body["data"]["keys"]
                .as_array()
                .is_some_and(|v| v.len() == 1)
        );
        let response=root.handle_admin("POST","root/sign-intermediate",&json!({"csr":csr.body["data"]["csr"],"ttl":"36h","use_csr_values":true,"permitted_dns_domains":["example.test"],"max_path_length":1}),NOW)?;
        let bundle = response.body["data"]["ca_chain"]
            .as_array()
            .ok_or_else(|| bad("test chain"))?
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        intermediate.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":bundle}),
            NOW,
        )?;
        intermediate.validate("", "pki/", NOW)?;
        Ok((root, intermediate))
    }

    #[test]
    fn real_owned_csr_signed_intermediate_leaf_chain_constraints_and_reopen() -> TestResult {
        let (root, mut p) = setup()?;
        p.handle_admin("POST","roles/web",&json!({"allowed_domains":["example.test","invalid"],"allow_subdomains":true,"key_type":"ec","max_ttl":"2h"}),NOW)?;
        let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
        let inside = p.issue(
            "pki/",
            "web",
            &json!({"common_name":"inside.example.test"}),
            &owner,
            None,
            NOW + 1,
        )?;
        let outside = p.issue(
            "pki/",
            "web",
            &json!({"common_name":"outside.invalid"}),
            &owner,
            None,
            NOW + 1,
        )?;
        assert_eq!(
            inside.body["data"]["ca_chain"]
                .as_array()
                .ok_or("chain")?
                .len(),
            2
        );
        let mut trust = X509StoreBuilder::new()?;
        trust.add_cert(X509::from_der(
            &root.root.as_ref().ok_or("root")?.certificate_der,
        )?)?;
        let mut parameters = X509VerifyParam::new()?;
        parameters.set_time(NOW as _);
        trust.set_param(&parameters)?;
        let trust = trust.build();
        let mut untrusted = Stack::new()?;
        untrusted.push(X509::from_der(
            &p.root.as_ref().ok_or("intermediate")?.certificate_der,
        )?)?;
        for (leaf, expected) in [(&inside, true), (&outside, false)] {
            let cert = X509::from_pem(
                leaf.body["data"]["certificate"]
                    .as_str()
                    .ok_or("leaf")?
                    .as_bytes(),
            )?;
            let mut context = X509StoreContext::new()?;
            assert_eq!(
                context.init(&trust, &cert, &untrusted, |c| c.verify_cert())?,
                expected,
                "real verifier applies persisted NameConstraints"
            );
        }
        let raw = Zeroizing::new(serde_json::to_vec(&p)?);
        let mut p: Pki = serde_json::from_slice(&raw)?;
        p.validate("", "pki/", NOW + 1)?;
        p.issue(
            "pki/",
            "web",
            &json!({"common_name":"reopened.example.test"}),
            &owner,
            None,
            NOW + 2,
        )?;
        p.validate("", "pki/", NOW + 2)?;
        p.handle_admin("DELETE", "root", &json!({}), NOW + 3)?;
        assert!(p.has_local_intermediate_state());
        p.validate("", "pki/", NOW + 3)?;
        Ok(())
    }

    #[test]
    fn invalid_csr_and_ca_chain_never_rebind_owned_key_and_public_import_has_no_authority()
    -> TestResult {
        let (mut root, p) = setup()?;
        let mut other = Pki::default();
        let response = other.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"other.example.test","key_type":"ec","key_name":"other-key"}),
            NOW,
        )?;
        let mut csr = pem_blocks(
            response.body["data"]["csr"].as_str().ok_or("csr")?,
            "CERTIFICATE REQUEST",
        )?
        .remove(0);
        let last = csr.last_mut().ok_or("CSR byte")?;
        *last ^= 1;
        let before = Zeroizing::new(serde_json::to_vec(&root)?);
        assert!(
            root.handle_admin(
                "POST",
                "root/sign-intermediate",
                &json!({"csr":pem("CERTIFICATE REQUEST",&csr)}),
                NOW
            )
            .is_err()
        );
        assert_eq!(*before, serde_json::to_vec(&root)?);
        let bundle = p
            .root
            .as_ref()
            .ok_or("owned")?
            .local_ca_chain_pem()
            .join("\n");
        let keys = other.local_key_list(&json!({}))?.body.clone();
        let imported = other.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":bundle}),
            NOW,
        )?;
        assert!(
            imported.body["data"]["mapping"]
                .as_object()
                .ok_or("mapping")?
                .values()
                .all(|id| id == "")
        );
        assert!(other.root.is_none());
        assert_eq!(other.local_key_list(&json!({}))?.body, keys);
        assert!(other.local_issuer("default").is_err());
        other.validate("", "pki/", NOW)?;
        let mut forged = serde_json::to_value(&p)?;
        let parents = forged
            .pointer_mut("/root/local_chain/parents")
            .and_then(Value::as_array_mut)
            .ok_or("parents")?;
        let last = parents[0]
            .as_array_mut()
            .ok_or("certificate")?
            .last_mut()
            .ok_or("signature")?;
        *last = json!(last.as_u64().ok_or("octet")? ^ 1);
        let forged: Pki = serde_json::from_value(forged)?;
        assert!(forged.validate("", "pki/", NOW).is_err());
        Ok(())
    }

    #[test]
    fn actual_csr_signatures_all_eleven_owned_key_kinds_and_export_roundtrip() -> TestResult {
        use ml_dsa::{
            Keypair as _, MlDsa44, MlDsa65, MlDsa87, SigningKey,
            pkcs8::{DecodePrivateKey as _, EncodePublicKey as _},
        };
        let mut p = Pki::default();
        for (kind, bits) in [
            ("rsa", 2048),
            ("rsa", 3072),
            ("rsa", 4096),
            ("ec", 224),
            ("ec", 256),
            ("ec", 384),
            ("ec", 521),
            ("ed25519", 0),
            ("mldsa", 44),
            ("mldsa", 65),
            ("mldsa", 87),
        ] {
            let response=p.handle_admin("POST","intermediate/generate/exported",&json!({"common_name":format!("{kind}-{bits}.example.test"),"key_type":kind,"key_bits":bits,"key_name":format!("key-{kind}-{bits}"),"private_key_format":"pkcs8"}),NOW)?;
            let bytes = pem_blocks(
                response.body["data"]["csr"].as_str().ok_or("csr")?,
                "CERTIFICATE REQUEST",
            )?
            .remove(0);
            let parsed = parse_csr(&bytes)?;
            assert!(
                response.body["data"]["private_key"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("-----BEGIN PRIVATE KEY-----"))
            );
            let exported = Zeroizing::new(
                pem_blocks(
                    response.body["data"]["private_key"]
                        .as_str()
                        .ok_or("private")?,
                    "PRIVATE KEY",
                )?
                .remove(0),
            );
            let actual_public = if kind == "mldsa" {
                match bits {
                    44 => SigningKey::<MlDsa44>::from_pkcs8_der(&exported)?
                        .verifying_key()
                        .to_public_key_der()?
                        .as_bytes()
                        .to_vec(),
                    65 => SigningKey::<MlDsa65>::from_pkcs8_der(&exported)?
                        .verifying_key()
                        .to_public_key_der()?
                        .as_bytes()
                        .to_vec(),
                    87 => SigningKey::<MlDsa87>::from_pkcs8_der(&exported)?
                        .verifying_key()
                        .to_public_key_der()?
                        .as_bytes()
                        .to_vec(),
                    _ => return Err("unexpected MLDSA kind".into()),
                }
            } else {
                PKey::private_key_from_der(&exported)?.public_key_to_der()?
            };
            assert_eq!(
                actual_public, parsed.certification_request_info.subject_pki.raw,
                "actual exported private key owns CSR SPKI"
            );
        }
        assert!(p.root.is_none());
        p.validate("", "pki/", NOW)?;
        let raw = Zeroizing::new(serde_json::to_vec(&p)?);
        let p: Pki = serde_json::from_slice(&raw)?;
        p.validate("", "pki/", NOW)?;
        assert!(p.has_local_intermediate_state());
        Ok(())
    }

    #[test]
    fn signed_ca_index_public_read_revocation_real_crl_and_owned_history_are_durable() -> TestResult
    {
        let (mut root, intermediate) = setup()?;
        let serial = intermediate.root.as_ref().ok_or("CA")?.serial.clone();
        root.validate("", "pki/", NOW)?;
        let response =
            root.handle_admin("POST", "revoke", &json!({"serial_number":serial}), NOW + 1)?;
        assert_eq!(response.body["data"]["state"], "revoked");
        root.validate("", "pki/", NOW + 1)?;
        let issuer = root.root.as_ref().ok_or("issuer")?;
        let der = root.cached_local_crl(issuer, false)?;
        let (rest, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(der)?;
        assert!(rest.is_empty());
        assert_eq!(crl.iter_revoked_certificates().count(), 1);
        assert_eq!(
            normalize_serial(
                &crl.iter_revoked_certificates()
                    .next()
                    .ok_or("revoked")?
                    .raw_serial_as_string()
            )?,
            serial
        );
        assert!(
            X509::from_der(&issuer.certificate_der)?
                .public_key()
                .is_ok_and(|key| openssl::x509::X509Crl::from_der(der)
                    .is_ok_and(|crl| crl.verify(&key).unwrap_or(false)))
        );
        let before = Zeroizing::new(serde_json::to_vec(&root)?);
        let read =
            root.handle_public_read(PkiPublicRead::Certificate(&serial), &json!({}), NOW + 1)?;
        assert_eq!(read.body["data"]["revocation_time"], NOW + 1);
        assert_eq!(*before, serde_json::to_vec(&root)?);
        let mut reopened: Pki = serde_json::from_slice(&before)?;
        reopened.validate("", "pki/", NOW + 1)?;
        assert_eq!(
            reopened
                .handle_public_read(PkiPublicRead::Certificate(&serial), &json!({}), NOW + 1)?
                .body,
            read.body
        );
        for field in ["issuer_id", "issued", "expires", "revoked_at"] {
            let mut value = serde_json::to_value(&reopened)?;
            let ca = value["local_intermediate"]["signed_certificates"][&serial]
                .as_object_mut()
                .ok_or("indexed CA")?;
            ca.insert(
                field.to_owned(),
                match field {
                    "issuer_id" => json!("00000000-0000-0000-0000-000000000000"),
                    "issued" | "revoked_at" => json!(NOW + 2),
                    _ => json!(NOW + 99),
                },
            );
            let forged: Pki = serde_json::from_value(value)?;
            assert!(
                forged.validate("", "pki/", NOW + 1).is_err(),
                "indexed CA field {field} remains owned"
            );
        }
        reopened.handle_admin("DELETE", "root", &json!({}), NOW + 2)?;
        reopened.validate("", "pki/", NOW + 2)?;
        assert!(reopened.has_local_intermediate_state());
        assert!(reopened.local_certificate(&serial).is_some());
        Ok(())
    }

    #[test]
    fn real_three_ca_chain_uses_each_owned_key_and_pending_default_selection_survives_reopen()
    -> TestResult {
        let (root, mut intermediate) = setup()?;
        let mut child = Pki::default();
        let generated = child.handle_admin("POST", "intermediate/generate/internal", &json!({"common_name":"third.example.test","key_type":"ed25519","key_name":"child-one"}), NOW)?;
        let first = generated.body["data"]["key_id"]
            .as_str()
            .ok_or("key")?
            .to_owned();
        let second = child.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"spare.example.test","key_type":"ec","key_name":"child-two"}),
            NOW,
        )?;
        let second = second.body["data"]["key_id"]
            .as_str()
            .ok_or("key")?
            .to_owned();
        child.handle_admin("POST", "config/keys", &json!({"default":"child-two"}), NOW)?;
        assert_eq!(
            child
                .handle_admin("GET", "config/keys", &json!({}), NOW)?
                .body["data"]["default"],
            second
        );
        let raw = Zeroizing::new(serde_json::to_vec(&child)?);
        let mut child: Pki = serde_json::from_slice(&raw)?;
        child.validate("", "pki/", NOW)?;
        let signed = intermediate.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":generated.body["data"]["csr"],"ttl":"6h"}),
            NOW,
        )?;
        let bundle = signed.body["data"]["ca_chain"]
            .as_array()
            .ok_or("chain")?
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            signed.body["data"]["ca_chain"]
                .as_array()
                .ok_or("chain")?
                .len(),
            3
        );
        child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":bundle}),
            NOW,
        )?;
        child.validate("", "pki/", NOW)?;
        assert_eq!(child.root.as_ref().ok_or("child CA")?.key_id, first);
        assert_eq!(child.default_local_key_id(), second);
        assert_eq!(
            certificate(&child.root.as_ref().ok_or("child")?.certificate_der)?
                .basic_constraints()?
                .ok_or("constraints")?
                .value
                .path_len_constraint,
            Some(0)
        );
        child.handle_admin(
            "POST",
            "roles/web",
            &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec"}),
            NOW,
        )?;
        let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
        let issued = child.issue(
            "pki/",
            "web",
            &json!({"common_name":"three.example.test"}),
            &owner,
            None,
            NOW + 1,
        )?;
        assert_eq!(
            issued.body["data"]["ca_chain"]
                .as_array()
                .ok_or("leaf chain")?
                .len(),
            3
        );
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(X509::from_der(
            &root.root.as_ref().ok_or("root")?.certificate_der,
        )?)?;
        let mut param = X509VerifyParam::new()?;
        param.set_time(NOW as _);
        store.set_param(&param)?;
        let store = store.build();
        let mut untrusted = Stack::new()?;
        untrusted.push(X509::from_der(
            &child.root.as_ref().ok_or("child")?.certificate_der,
        )?)?;
        untrusted.push(X509::from_der(
            &intermediate
                .root
                .as_ref()
                .ok_or("intermediate")?
                .certificate_der,
        )?)?;
        let leaf = X509::from_pem(
            issued.body["data"]["certificate"]
                .as_str()
                .ok_or("leaf")?
                .as_bytes(),
        )?;
        assert!(
            X509StoreContext::new()?
                .init(&store, &leaf, &untrusted, |context| context.verify_cert())?
        );
        Ok(())
    }
}
