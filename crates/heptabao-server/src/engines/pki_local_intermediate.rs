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
    "key_ref",
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    default_key_unset: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_default_issuer_id: Option<String>,
    signed_certificates: BTreeMap<String, SignedCa>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// A generated CSR and a separately imported/generated key share the same
// unbound-key owner. Empty CSR bytes mean no CSR has ever been generated.
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

pub(super) fn certificate(bytes: &[u8]) -> Result<X509Certificate<'_>> {
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

pub(super) fn certificate_signed_by(bytes: &[u8], parent: &[u8]) -> Result<()> {
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

fn validate_available_chain(leaf: &[u8], parents: &[Vec<u8>]) -> Result<()> {
    if parents.len() > MAX_CHAIN || parents.iter().map(Vec::len).sum::<usize>() > MAX_CA_BUNDLE {
        return Err(bad("CA chain exceeds bounds"));
    }
    certificate(leaf)?;
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
    Ok(())
}

pub(super) fn validate_chain(leaf: &[u8], parents: &[Vec<u8>]) -> Result<()> {
    validate_available_chain(leaf, parents)?;
    let terminal = parents.last().map_or(leaf, Vec::as_slice);
    let cert = certificate(terminal)?;
    if cert.subject() == cert.issuer() {
        certificate_signed_by(terminal, terminal)?;
    }
    Ok(())
}

pub(super) fn available_ca_chain(leaf: &[u8], certificates: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut parents = Vec::new();
    let mut current = leaf;
    let mut seen = BTreeSet::from([crypto_digest(leaf)]);
    loop {
        let cert = certificate(current)?;
        if cert.subject() == cert.issuer() && certificate_signed_by(current, current).is_ok() {
            break;
        }
        let next = certificates.iter().find(|candidate| {
            !seen.contains(&crypto_digest(candidate))
                && certificate_signed_by(current, candidate).is_ok()
        });
        let Some(next) = next else { break };
        if parents.len() >= MAX_CHAIN {
            return Err(bad("CA chain exceeds bounds"));
        }
        seen.insert(crypto_digest(next));
        parents.push(next.clone());
        current = next;
    }
    validate_available_chain(leaf, &parents)?;
    Ok(parents)
}

fn crypto_digest(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

pub(super) fn parse_csr(bytes: &[u8]) -> Result<X509CertificationRequest<'_>> {
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

pub(super) fn pem_blocks(input: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    if input.len() > MAX_CA_BUNDLE || input.is_empty() {
        return Err(bad("PEM input exceeds bounds"));
    }
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = input.trim();
    let mut values = Vec::new();
    while !rest.is_empty() {
        if values.len() > MAX_CHAIN {
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

pub(super) fn csr_from_body(body: &Value) -> Result<Vec<u8>> {
    let bytes = csr_bytes_from_body(body)?;
    parse_csr(&bytes)?;
    Ok(bytes)
}

pub(super) fn csr_bytes_from_body(body: &Value) -> Result<Vec<u8>> {
    let text = string(body, "csr")?;
    let mut values = pem_blocks(text, "CERTIFICATE REQUEST")?;
    if values.len() != 1 {
        return Err(bad("one CSR is required"));
    }
    Ok(values.remove(0))
}

pub(super) fn common_name(subject: &x509_parser::x509::X509Name<'_>) -> Result<String> {
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
        extension(&[0x55, 0x1d, 0x11], false, &seq(&values))
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
        let cert = certificate(certificate_der)?;
        let spki = public.spki()?;
        if !self.csr_der.is_empty()
            && parse_csr(&self.csr_der)?
                .certification_request_info
                .subject_pki
                .raw
                != spki
            || cert.public_key().raw != spki
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
                    || der(0x02, cert.raw_serial()) != integer(&serial_bytes(&self.serial)?)
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
        state.public_default_issuer_id = None;
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

    pub(super) fn signed_ca_owner(&self, serial: &str) -> Option<(&str, u64, u64, Option<u64>)> {
        let ca = self
            .local_intermediate
            .as_ref()?
            .signed_certificates
            .get(serial)?;
        Some((&ca.issuer_id, ca.issued, ca.expires, ca.revoked_at))
    }

    pub(super) fn external_signed_ca_revocations(
        &self,
        issuer: &str,
        now: u64,
    ) -> BTreeMap<String, u64> {
        self.local_intermediate
            .iter()
            .flat_map(|state| state.signed_certificates.iter())
            .filter_map(|(serial, ca)| {
                ca.revoked_at
                    .filter(|_| ca.issuer_id == issuer && ca.expires > now)
                    .map(|at| (serial.clone(), at))
            })
            .collect()
    }

    pub(super) fn publish_external_signed_ca_revocation(
        &mut self,
        serial: &str,
        issuer: &str,
        issuer_der: &[u8],
        at: u64,
    ) -> Result<()> {
        let ca = self
            .local_intermediate
            .as_mut()
            .and_then(|state| state.signed_certificates.get_mut(serial))
            .ok_or_else(not_found)?;
        if ca.issuer_id != issuer
            || ca.parents.first().map(Vec::as_slice) != Some(issuer_der)
            || at < ca.issued
            || ca.revoked_at.is_some_and(|original| original != at)
        {
            return Err(bad("signed CA original external issuer changed"));
        }
        ca.revoked_at = Some(at);
        Ok(())
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

    pub(super) fn signed_ca_revocation_for_serial(&self, serial: &str) -> Option<(&str, u64)> {
        self.local_intermediate
            .as_ref()?
            .signed_certificates
            .iter()
            .find(|(stored, _)| stored.trim_start_matches('0') == serial.trim_start_matches('0'))
            .and_then(|(_, ca)| ca.revoked_at.map(|at| (ca.issuer_id.as_str(), at)))
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

    pub(super) fn has_unbound_owned_keys(&self) -> bool {
        self.local_intermediate
            .as_ref()
            .is_some_and(|s| !s.pending.is_empty())
    }

    pub(super) fn local_default_key_unset(&self) -> bool {
        self.local_intermediate
            .as_ref()
            .is_some_and(|s| s.default_key_unset)
    }

    pub(super) fn set_local_key_default(&mut self, id: &str) {
        let state = self.local_intermediate.get_or_insert_with(Box::default);
        state.first_pending_key_id = id.to_owned();
        state.default_key_unset = false;
        if let Some(state) = &mut self.local_issuers {
            state.default_key_id = id.to_owned();
        }
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
                info.insert(id.clone(),json!({"issuer_name":"","is_default":id==self.selected_local_issuer_id(),"key_id":"","serial_number":external::formatted_serial(&normalize_serial(&cert.raw_serial_as_string())?)}));
            }
        }
        Ok(())
    }

    pub(super) fn selected_local_issuer_id(&self) -> &str {
        if let Some(id) = self
            .local_intermediate
            .as_ref()
            .and_then(|s| s.public_default_issuer_id.as_deref())
        {
            id
        } else {
            self.root.as_ref().map_or("", |r| r.issuer_id.as_str())
        }
    }

    pub(super) fn has_public_default_override(&self) -> bool {
        self.local_intermediate
            .as_ref()
            .is_some_and(|s| s.public_default_issuer_id.is_some())
    }

    pub(super) fn public_default_issuer_id(&self) -> &str {
        self.local_intermediate
            .as_ref()
            .and_then(|s| s.public_default_issuer_id.as_deref())
            .unwrap_or("")
    }

    pub(super) fn set_public_default_issuer(&mut self, id: &str) {
        self.local_intermediate
            .get_or_insert_with(Box::default)
            .public_default_issuer_id = Some(id.to_owned());
    }

    pub(super) fn clear_public_default_override(&mut self) {
        if let Some(state) = &mut self.local_intermediate {
            state.public_default_issuer_id = None;
        }
    }

    pub(super) fn imported_ca_id<'a>(&'a self, reference: &'a str) -> Option<&'a str> {
        let id = if reference == "default" {
            self.public_default_issuer_id()
        } else {
            reference
        };
        self.local_intermediate
            .as_ref()?
            .public_issuers
            .contains_key(id)
            .then_some(id)
    }

    pub(super) fn public_imported_ca(&self, reference: &str) -> Option<(&[u8], Vec<String>)> {
        let id = self.imported_ca_id(reference)?;
        let ca = self.local_intermediate.as_ref()?.public_issuers.get(id)?;
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
        if state.default_key_unset
            && (!state.first_pending_key_id.is_empty()
                || self
                    .local_issuers
                    .as_ref()
                    .is_some_and(|s| !s.default_key_id.is_empty()))
        {
            return Err(bad(
                "explicitly unset PKI default key has conflicting ownership",
            ));
        }
        if state
            .public_default_issuer_id
            .as_deref()
            .is_some_and(|id| !id.is_empty() && !state.public_issuers.contains_key(id))
        {
            return Err(bad("public PKI default issuer lost ownership"));
        }
        let mut public_owners = BTreeMap::new();
        for key in self.local_keys() {
            public_owners.insert(key.local_key()?.public()?.spki()?, key.key_id.as_str());
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
            let public = pending.material.public()?;
            if public_owners
                .insert(public.spki()?, id.as_str())
                .is_some_and(|previous| previous != id.as_str())
            {
                return Err(bad("pending PKI public key has conflicting identities"));
            }
            if !pending.csr_der.is_empty()
                && parse_csr(&pending.csr_der)?
                    .certification_request_info
                    .subject_pki
                    .raw
                    != public.spki()?
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
            validate_available_chain(&ca.certificate_der, &ca.parents)?;
        }
        for (serial, ca) in &state.signed_certificates {
            let cert = certificate(&ca.certificate_der)?;
            if der(0x02, cert.raw_serial()) != integer(&serial_bytes(serial)?)
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
                || self
                    .local_issuer_certificate_by_id(&ca.issuer_id)
                    .or_else(|| self.external_ca_owner_certificate(&ca.issuer_id))
                    != ca.parents.first().map(Vec::as_slice)
            {
                return Err(bad("signed CA issuer ownership changed"));
            }
            validate_chain(&ca.certificate_der, &ca.parents)?;
        }
        Ok(())
    }

    pub(super) fn local_issuer_management_read(
        &self,
        reference: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &[])?;
        let (id, key, name, certificate, chain, behavior) =
            if let Some((der, chain)) = self.public_imported_ca(reference) {
                (
                    self.imported_ca_id(reference).ok_or_else(not_found)?,
                    "",
                    "",
                    pem("CERTIFICATE", der),
                    chain,
                    IssuerLeafNotAfterBehavior::Err,
                )
            } else {
                let root = self.selected_issuer(reference)?;
                let (id, key, name) = if root.is_external() {
                    let key = self.external_issuer_key(reference)?;
                    (
                        key.issuer_id.as_str(),
                        key.key_id.as_str(),
                        key.issuer_name.as_str(),
                    )
                } else {
                    (
                        root.issuer_id.as_str(),
                        root.key_id.as_str(),
                        root.local_fields
                            .as_ref()
                            .map_or("", |m| m.issuer_name.as_str()),
                    )
                };
                (
                    id,
                    key,
                    name,
                    pem("CERTIFICATE", &root.certificate_der),
                    self.issuer_management_ca_chain_pem(root)?,
                    root.leaf_not_after_behavior.unwrap_or_default(),
                )
            };
        // Actual certificate and selected issuer policy, independent of the leaf owner history.
        Ok(ok(
            json!({"issuer_id":id,"key_id":key,"issuer_name":name,"certificate":certificate,
            "ca_chain":chain,"manual_chain":Value::Null,"leaf_not_after_behavior":behavior.label(),
            "usage":"crl-signing,issuing-certificates,ocsp-signing,read-only","revoked":false,
            "revocation_signature_algorithm":"","issuing_certificates":[],"crl_distribution_points":[],
            "delta_crl_distribution_points":[],"ocsp_servers":[]}),
            false,
        ))
    }

    pub(super) fn handle_local_intermediate(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        if write_method(method)
            && let Some(reference) = path.strip_prefix("issuer/")
            && !reference.is_empty()
            && !reference.contains('/')
        {
            return self.issuer_leaf_time_update(reference, body).map(Some);
        }
        if method == "GET"
            && let Some(reference) = path.strip_prefix("issuer/")
            && !reference.is_empty()
            && !reference.contains('/')
        {
            return self.local_issuer_management_read(reference, body).map(Some);
        }
        if method == "DELETE"
            && let Some(reference) = path.strip_prefix("issuer/")
            && !reference.contains('/')
            && self.public_imported_ca(reference).is_some()
        {
            reject_unknown(body, &[])?;
            let id = self
                .imported_ca_id(reference)
                .ok_or_else(not_found)?
                .to_owned();
            let state = self.local_intermediate.as_mut().ok_or_else(not_found)?;
            state.public_issuers.remove(&id);
            if state.public_default_issuer_id.as_deref() == Some(id.as_str()) {
                state.public_default_issuer_id = Some(String::new());
            }
            return Ok(Some(ok(Value::Null, true)));
        }
        if let Some(reference) = path.strip_prefix("key/") {
            if reference.is_empty() || reference.contains('/') {
                return Err(not_found());
            }
            return self
                .owned_local_key_operation(method, reference, body)
                .map(Some);
        }
        let response = match path {
            "config/keys" if !self.root.as_ref().is_some_and(RootCa::is_external) => {
                self.local_key_config(method, body)?
            }
            "keys/import" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.import_owned_local_key(body, now)?
            }
            "keys/generate/internal" | "keys/generate/exported" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.generate_owned_local_key(body, path.ends_with("exported"))?
            }
            "intermediate/generate/existing" => {
                if !write_method(method) {
                    return Err(unsupported());
                }
                self.generate_existing_local_csr(body)?
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
            self.set_local_key_default(&selected);
        }
        Ok(ok(json!({"default":self.default_local_key_id()}), changed))
    }

    pub(super) fn owned_key(
        &self,
        reference: &str,
    ) -> Result<(String, String, LocalPrivateMaterial)> {
        let reference = if reference == "default" {
            self.default_local_key_id()
        } else {
            reference
        };
        if let Some(root) = self.local_keys().find(|root| {
            root.key_id == reference
                || root
                    .local_fields
                    .as_ref()
                    .is_some_and(|m| !m.key_name.is_empty() && m.key_name == reference)
        }) {
            return Ok((
                root.key_id.clone(),
                root.local_fields
                    .as_ref()
                    .map_or("", |m| m.key_name.as_str())
                    .to_owned(),
                root.local_key()?,
            ));
        }
        self.local_intermediate
            .as_ref()
            .and_then(|s| {
                s.pending.iter().find(|(id, key)| {
                    *id == reference || !key.key_name.is_empty() && key.key_name == reference
                })
            })
            .map(|(id, key)| (id.clone(), key.key_name.clone(), key.material.clone()))
            .ok_or_else(|| error(500, "PKI key reference is unavailable"))
    }

    fn new_key_name(&self, name: &str, current: Option<&str>) -> Result<()> {
        LocalRootMetadata {
            issuer_name: String::new(),
            key_name: name.to_owned(),
        }
        .validate()?;
        if !name.is_empty()
            && (self.local_keys().any(|key| {
                Some(key.key_id.as_str()) != current
                    && key
                        .local_fields
                        .as_ref()
                        .is_some_and(|m| m.key_name == name)
            }) || self.local_intermediate.as_ref().is_some_and(|s| {
                s.pending
                    .iter()
                    .any(|(id, key)| Some(id.as_str()) != current && key.key_name == name)
            }))
        {
            return Err(bad("key name already in use"));
        }
        Ok(())
    }

    fn key_projection(id: &str, name: &str, kind: LocalKeyKind, mutated: bool) -> EngineResponse {
        ok(
            json!({"key_id":id,"key_name":name,"key_type":kind.key_type()}),
            mutated,
        )
    }

    fn publish_unbound_key(
        &mut self,
        material: LocalPrivateMaterial,
        name: &str,
    ) -> Result<String> {
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(bad("local key cannot borrow external issuer authority"));
        }
        self.new_key_name(name, None)?;
        if self.local_keys().count()
            + self
                .local_intermediate
                .as_ref()
                .map_or(0, |s| s.pending.len())
            >= MAX_PENDING_KEYS
        {
            return Err(error(507, "owned PKI key capacity exhausted"));
        }
        let id = random_pki_id()?;
        if self.owned_key(&id).is_ok() {
            return Err(error(503, "PKI key identifier collision"));
        }
        let previous_default = self.default_local_key_id().to_owned();
        let state = self.local_intermediate.get_or_insert_with(Box::default);
        if previous_default.is_empty() {
            state.first_pending_key_id = id.clone();
            state.default_key_unset = false;
        }
        state.pending.insert(
            id.clone(),
            PendingCsr {
                material,
                csr_der: Vec::new(),
                key_name: name.to_owned(),
            },
        );
        Ok(id)
    }

    fn generate_owned_local_key(&mut self, body: &Value, exported: bool) -> Result<EngineResponse> {
        reject_unknown(body, &["key_type", "key_bits", "key_name"])?;
        let name = body
            .get("key_name")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("PKI key name must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        self.new_key_name(name, None)?;
        let material = LocalPrivateMaterial::generate(LocalKeyKind::from_body(body)?)?;
        let mut candidate = self.clone();
        let id = candidate.publish_unbound_key(material.clone(), name)?;
        let mut response = Self::key_projection(&id, name, material.kind(), true);
        if exported {
            let (key, label) = material.root_export_der(false)?;
            let encoded = Zeroizing::new(pem(label, key.as_slice()));
            response.body["data"]["private_key"] = json!(encoded.as_str());
        }
        *self = candidate;
        Ok(response)
    }

    fn import_owned_local_key(&mut self, body: &Value, now: u64) -> Result<EngineResponse> {
        reject_unknown(body, &["pem_bundle", "key_name"])?;
        let name = body
            .get("key_name")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("PKI key name must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        self.new_key_name(name, None)?;
        let text = string(body, "pem_bundle")?;
        let trimmed = text.trim_start();
        let label = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
            .into_iter()
            .find(|label| trimmed.starts_with(&format!("-----BEGIN {label}-----")))
            .ok_or_else(|| bad("invalid unencrypted PKI private key PEM"))?;
        if text.len() > 128 * 1024 {
            return Err(bad("PKI private key PEM exceeds bounds"));
        }
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let payload = text
            .trim()
            .strip_prefix(&begin)
            .ok_or_else(|| bad("invalid private key PEM header"))?;
        let (payload, trailing) = payload
            .split_once(&end)
            .ok_or_else(|| bad("invalid private key PEM ending"))?;
        if !trailing.trim().is_empty() {
            return Err(bad("exactly one PKI private key must be imported"));
        }
        let encoded = Zeroizing::new(payload.split_whitespace().collect::<String>());
        let bytes = Zeroizing::new(
            BASE64
                .decode(encoded.as_bytes())
                .map_err(|_| bad("invalid private key PEM data"))?,
        );
        let material = LocalPrivateMaterial::import_der(label, bytes.as_slice())?;
        let public = material.public()?.spki()?;
        let existing = self
            .local_keys()
            .find(|key| {
                key.local_key()
                    .and_then(|k| k.public())
                    .is_ok_and(|p| p.spki().is_ok_and(|p| p == public))
            })
            .map(|key| key.key_id.clone())
            .or_else(|| {
                self.local_intermediate.as_ref().and_then(|s| {
                    s.pending
                        .iter()
                        .find(|(_, key)| {
                            key.material
                                .public()
                                .is_ok_and(|p| p.spki().is_ok_and(|p| p == public))
                        })
                        .map(|(id, _)| id.clone())
                })
            });
        if let Some(id) = existing {
            let (_, name, key) = self.owned_key(&id)?;
            let mut response = Self::key_projection(&id, &name, key.kind(), false);
            response.body["warnings"] =
                json!(["Key already imported, use key/ endpoint to update name."]);
            return Ok(response);
        }
        let mut candidate = self.clone();
        let id = candidate.publish_unbound_key(material, name)?;
        let matched: Vec<_> = candidate
            .local_intermediate
            .iter()
            .flat_map(|s| s.public_issuers.iter())
            .filter(|(_, ca)| {
                certificate(&ca.certificate_der).is_ok_and(|c| c.public_key().raw == public)
            })
            .map(|(issuer, ca)| (issuer.clone(), ca.clone()))
            .collect();
        for (issuer, ca) in matched {
            candidate.bind_public_ca_to_owned_key(&issuer, &ca, &id)?;
        }
        candidate.maintain_local_crl(now)?;
        let (_, _, key) = candidate.owned_key(&id)?;
        let response = Self::key_projection(&id, name, key.kind(), true);
        *self = candidate;
        Ok(response)
    }

    fn bind_public_ca_to_owned_key(
        &mut self,
        issuer: &str,
        ca: &ImportedCa,
        key_id: &str,
    ) -> Result<()> {
        let (_, name, material) = self.owned_key(key_id)?;
        let cert = certificate(&ca.certificate_der)?;
        let root = RootCa {
            leaf_not_after_behavior: None,
            common_name: common_name(cert.subject())?,
            issuer_id: issuer.to_owned(),
            key_id: key_id.to_owned(),
            local_fields: Some(Box::new(LocalRootMetadata {
                issuer_name: String::new(),
                key_name: name,
            })),
            pkcs8: if material.kind() == LocalKeyKind::Ed25519 {
                material.private_der()?.to_vec()
            } else {
                Vec::new()
            },
            local_material: if material.kind() == LocalKeyKind::Ed25519 {
                None
            } else {
                Some(material)
            },
            local_chain: Some(Box::new(LocalCaChain {
                csr_der: Vec::new(),
                parents: ca.parents.clone(),
            })),
            certificate_der: ca.certificate_der.clone(),
            serial: normalize_serial(&cert.raw_serial_as_string())?,
            not_before: u64::try_from(cert.validity().not_before.timestamp()).map_err(invalid)?,
            not_after: u64::try_from(cert.validity().not_after.timestamp()).map_err(invalid)?,
        };
        root.validate_local_certificate()?;
        self.publish_local_root(root)?;
        let was_default = self.public_default_issuer_id() == issuer;
        let state = self.local_intermediate.as_mut().ok_or_else(not_found)?;
        state.public_issuers.remove(issuer);
        state.pending.remove(key_id);
        if was_default {
            self.select_local_owned_default(issuer)?;
        }
        Ok(())
    }

    fn owned_local_key_operation(
        &mut self,
        method: &str,
        reference: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        let (id, name, material) = self.owned_key(reference)?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let identifier = root_fields::subject_key_identifier(&material.public()?.spki()?)?;
                let formatted = identifier
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                let mut response = Self::key_projection(&id, &name, material.kind(), false);
                response.body["data"]["subject_key_id"] = json!(formatted);
                Ok(response)
            }
            "POST" | "PUT" => {
                reject_unknown(body, &["key_name"])?;
                let new_name = string(body, "key_name")?;
                self.new_key_name(new_name, Some(&id))?;
                let changed = new_name != name;
                for key in self.root.iter_mut().chain(
                    self.local_issuers
                        .iter_mut()
                        .flat_map(|s| s.other.values_mut().chain(s.orphan_keys.values_mut())),
                ) {
                    if key.key_id == id {
                        key.local_fields
                            .get_or_insert_with(|| {
                                Box::new(LocalRootMetadata {
                                    issuer_name: String::new(),
                                    key_name: String::new(),
                                })
                            })
                            .key_name = new_name.to_owned();
                    }
                }
                if let Some(key) = self
                    .local_intermediate
                    .as_mut()
                    .and_then(|s| s.pending.get_mut(&id))
                {
                    key.key_name = new_name.to_owned();
                }
                Ok(Self::key_projection(
                    &id,
                    new_name,
                    material.kind(),
                    changed,
                ))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                if self.local_roots().any(|r| r.key_id == id) {
                    return Err(bad("PKI key remains in use by an issuer"));
                }
                let selected = self.default_local_key_id() == id;
                if let Some(state) = &mut self.local_intermediate {
                    state.pending.remove(&id);
                    if selected {
                        state.first_pending_key_id.clear();
                    }
                }
                if let Some(state) = &mut self.local_issuers {
                    state.orphan_keys.remove(&id);
                    if selected {
                        state.default_key_id.clear();
                    }
                }
                if selected {
                    let state = self.local_intermediate.get_or_insert_with(Box::default);
                    state.default_key_unset = true;
                    Ok(EngineResponse {
                        status: 200,
                        body: json!({"warnings":[format!("Deleted key {id} (via key_ref {reference}); this was configured as the default key. Operations without an explicit key will not work until a new default is configured.")]}),
                        mutated: true,
                    })
                } else {
                    Ok(empty(true))
                }
            }
            _ => Err(unsupported()),
        }
    }

    fn csr_response(data: Value, mutated: bool) -> EngineResponse {
        let mut response = ok(data, mutated);
        response.body["warnings"] = json!([
            "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information. Since this certificate is an intermediate, it might be useful to regenerate this certificate after fixing this problem for the root mount."
        ]);
        response
    }

    fn generate_existing_local_csr(&mut self, body: &Value) -> Result<EngineResponse> {
        reject_unknown(body, CSR_FIELDS)?;
        if body.get("key_type").is_some() || body.get("key_bits").is_some() {
            return Err(bad(
                "invalid parameter for the kms/existing path parameter, key_type nor key_bits arguments can be set in this mode",
            ));
        }
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(bad("local CSR cannot borrow external authority"));
        }
        let reference = body
            .get("key_ref")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("PKI key reference must be a string"))
            })
            .transpose()?
            .unwrap_or("default");
        if reference.is_empty() {
            return Err(bad(
                "failed to lookup public key from existing key: missing argument key_ref for existing type",
            ));
        }
        let common_name = string(body, "common_name")?;
        if !external::common_name_valid(common_name) {
            return Err(bad("invalid CSR common name"));
        }
        let fields = RootFields::from_body(body, common_name)?;
        self.admit_local_root_names(&fields)?;
        let name = fields.metadata.as_ref().map_or("", |m| m.key_name.as_str());
        self.new_key_name(name, None)?;
        if matches!(
            body.get("private_key_format"),
            Some(Value::Array(_) | Value::Object(_))
        ) {
            return Err(bad("invalid PKI private key format"));
        }
        let format = RootOutputFormat::from_body(body)?;
        let legacy = self
            .root
            .as_ref()
            .is_some_and(|r| r.issuer_id.is_empty() || r.key_id.is_empty());
        let mut candidate = self.clone();
        if legacy {
            candidate.promote_default_associations()?;
        }
        if reference == "default" && candidate.default_local_key_id().is_empty() {
            return Err(bad(
                "failed to lookup public key from existing key: no default key currently configured",
            ));
        }
        let (id, _, material) = candidate.owned_key(reference).map_err(|_| {
            bad("failed to lookup public key from existing key: key reference is unavailable")
        })?;
        let csr = csr_der(&material, &fields, common_name)?;
        let data = json!({"csr":match format {RootOutputFormat::Der=>BASE64.encode(&csr),_=>pem("CERTIFICATE REQUEST",&csr)},"key_id":id});
        // Existing private material already owns this key. Do not insert a
        // second pending key, invent a CA, replace a CSR proof, or rename it.
        if legacy {
            *self = candidate;
        }
        Ok(Self::csr_response(data, legacy))
    }

    fn generate_local_csr(&mut self, body: &Value, exported: bool) -> Result<EngineResponse> {
        self.generate_local_csr_with_material(body, exported, None)
    }

    pub(super) fn generate_local_csr_with_material(
        &mut self,
        body: &Value,
        exported: bool,
        prepared: Option<LocalPrivateMaterial>,
    ) -> Result<EngineResponse> {
        reject_unknown(body, CSR_FIELDS)?;
        let common_name = string(body, "common_name")?;
        if !external::common_name_valid(common_name) {
            return Err(bad("invalid CSR common name"));
        }
        if prepared.is_none() && self.root.as_ref().is_some_and(RootCa::is_external) {
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
            return Err(bad("key name already in use"));
        }
        let kind = LocalKeyKind::from_body(body)?;
        let material = match prepared {
            Some(material) => {
                if material.kind() != kind {
                    return Err(bad("native CSR prepared key type changed"));
                }
                material
            }
            None => LocalPrivateMaterial::generate(kind)?,
        };
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
                state.default_key_unset = false;
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
        Ok(Self::csr_response(data, true))
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
                not_before: role_time::signed_epoch(now.saturating_sub(fields.backdate))?,
                not_after: expires,
                is_ca: true,
                alt_names: &fields.dns_sans,
                email_sans: &fields.email_sans,
                ip_sans: &fields.ip_sans,
                uri_sans: &fields.uri_sans,
                exclude_cn_from_sans: fields.exclude_cn,
                max_path_length: fields.max_path_length,
                permitted_dns_domains: &permitted,
                role_leaf_profile: None,
            },
        )?;
        certificate_signed_by(&cert, &root.certificate_der)?;
        let format = RootOutputFormat::from_body(body)?;
        let mut chain = vec![public::stored_pem("CERTIFICATE", &cert)];
        let mut parent_chain = root.local_ca_chain_pem();
        for pem in &mut parent_chain {
            if pem.ends_with('\n') {
                pem.pop();
            }
        }
        chain.extend(parent_chain);
        let issuing = public::stored_pem("CERTIFICATE", &root.certificate_der);
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
        // The currently admitted issuer profile has no configured AIA URLs.
        // Keep the native warning order: AIA before the zero-path warning.
        let mut warnings = vec![
            "This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information.",
        ];
        if fields.max_path_length == Some(0) {
            warnings.push("Max path length of the signed certificate is zero. This certificate cannot be used to issue intermediate CA certificates.");
        }
        response.body["warnings"] = json!(warnings);
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
        if self.root.as_ref().is_some_and(RootCa::is_external) {
            return Err(bad("local CA import cannot borrow external authority"));
        }
        let objects = pem_blocks(string(body, "certificate")?, "CERTIFICATE")?;
        for der in &objects {
            certificate(der)?;
        }
        let mut available = objects.clone();
        available.extend(self.local_roots().map(|r| r.certificate_der.clone()));
        available.extend(self.local_intermediate.iter().flat_map(|s| {
            s.public_issuers
                .values()
                .map(|ca| ca.certificate_der.clone())
        }));
        let follows_latest = self
            .local_issuers
            .as_ref()
            .is_some_and(|s| s.default_follows_latest_issuer);
        if let Some(state) = &mut self.local_issuers {
            state.default_follows_latest_issuer = false;
        }
        let mut owned_imported = Vec::new();
        let mut mapping = serde_json::Map::new();
        let mut imported = Vec::new();
        let mut existing = Vec::new();
        for der in objects {
            let cert = certificate(&der)?;
            let old = self
                .local_roots()
                .find(|r| r.certificate_der == der)
                .map(|r| (r.issuer_id.clone(), r.key_id.clone()))
                .or_else(|| {
                    self.local_intermediate.as_ref().and_then(|s| {
                        s.public_issuers
                            .iter()
                            .find(|(_, ca)| ca.certificate_der == der)
                            .map(|(id, _)| (id.clone(), String::new()))
                    })
                });
            if let Some((id, key)) = old {
                mapping.insert(id.clone(), json!(key));
                existing.push(id);
                continue;
            }
            let pending = self
                .local_intermediate
                .as_ref()
                .and_then(|s| {
                    s.pending.iter().find(|(_, p)| {
                        p.material
                            .public()
                            .is_ok_and(|k| k.spki().is_ok_and(|spki| spki == cert.public_key().raw))
                    })
                })
                .map(|(id, p)| (id.clone(), p.clone()));
            let owned = self
                .local_keys()
                .find(|key| {
                    key.local_key()
                        .and_then(|k| k.public())
                        .is_ok_and(|k| k.spki().is_ok_and(|spki| spki == cert.public_key().raw))
                })
                .cloned();
            let id = random_pki_id()?;
            let parents = available_ca_chain(&der, &available)?;
            let (key, key_name, material, csr) = if let Some((key, pending)) = pending {
                (
                    key,
                    pending.key_name,
                    Some(pending.material),
                    pending.csr_der,
                )
            } else if let Some(root) = owned {
                (
                    root.key_id.clone(),
                    root.local_fields
                        .as_ref()
                        .map_or("", |m| m.key_name.as_str())
                        .to_owned(),
                    Some(root.local_key()?),
                    root.local_chain
                        .as_ref()
                        .map_or_else(Vec::new, |c| c.csr_der.clone()),
                )
            } else {
                (String::new(), String::new(), None, Vec::new())
            };
            if material.is_none() {
                if self
                    .local_intermediate
                    .as_ref()
                    .map_or(0, |s| s.public_issuers.len())
                    >= MAX_ISSUED
                {
                    return Err(error(507, "CA import capacity exhausted"));
                }
                self.local_intermediate
                    .get_or_insert_with(Box::default)
                    .public_issuers
                    .insert(
                        id.clone(),
                        ImportedCa {
                            certificate_der: der,
                            parents,
                        },
                    );
            } else {
                if self.local_roots().count() >= 256 {
                    return Err(error(507, "CA import capacity exhausted"));
                }
                let material = material.ok_or_else(|| bad("owned CA key changed"))?;
                let kind = material.kind();
                let root = RootCa {
                    leaf_not_after_behavior: None,
                    common_name: common_name(cert.subject())?,
                    issuer_id: id.clone(),
                    key_id: key.clone(),
                    local_fields: Some(Box::new(LocalRootMetadata {
                        issuer_name: String::new(),
                        key_name,
                    })),
                    pkcs8: if kind == LocalKeyKind::Ed25519 {
                        material.private_der()?.to_vec()
                    } else {
                        Vec::new()
                    },
                    local_material: if kind == LocalKeyKind::Ed25519 {
                        None
                    } else {
                        Some(material)
                    },
                    local_chain: Some(Box::new(LocalCaChain {
                        csr_der: csr,
                        parents,
                    })),
                    serial: normalize_serial(&cert.raw_serial_as_string())?,
                    not_before: u64::try_from(cert.validity().not_before.timestamp())
                        .map_err(invalid)?,
                    not_after: u64::try_from(cert.validity().not_after.timestamp())
                        .map_err(invalid)?,
                    certificate_der: der,
                };
                root.validate_local_certificate()?;
                self.publish_local_root(root)?;
                owned_imported.push(id.clone());
                if let Some(state) = &mut self.local_intermediate {
                    state.pending.remove(&key);
                }
            }
            mapping.insert(id.clone(), json!(key));
            imported.push(id);
        }
        // Chains reflect every currently imported issuer, including a parent
        // imported after its child. Available edges require true signatures;
        // a missing parent leaves a bounded partial chain without inventing trust.
        self.rebuild_available_ca_chains(&available)?;
        if let Some(state) = &mut self.local_issuers {
            state.default_follows_latest_issuer = follows_latest;
        }
        let mut warnings = Vec::new();
        if follows_latest {
            if owned_imported.len() == 1 {
                self.select_local_owned_default(&owned_imported[0])?;
            } else if owned_imported.len() > 1 {
                warnings.push("Default issuer left unchanged: could not select new issuer automatically as multiple imported issuers had key material in Vault.");
            }
        }
        // config/urls and per-issuer AIA overrides are not supported by this finite local profile yet.
        warnings.push("This mount hasn't configured any authority information access (AIA) fields; this may make it harder for systems to find missing certificates in the chain or to validate revocation status of certificates. Consider updating /config/urls or the newly generated issuer with this information.");
        self.maintain_local_crl(now)?;
        let mut response = ok(
            json!({"mapping":mapping,"imported_keys":Value::Null,"existing_keys":Value::Null,"imported_issuers":if imported.is_empty(){Value::Null}else{json!(imported)},"existing_issuers":if existing.is_empty(){Value::Null}else{json!(existing)}}),
            true,
        );
        response.body["warnings"] = json!(warnings);
        Ok(response)
    }

    fn rebuild_available_ca_chains(&mut self, available: &[Vec<u8>]) -> Result<()> {
        for root in self.root.iter_mut().chain(
            self.local_issuers
                .iter_mut()
                .flat_map(|s| s.other.values_mut()),
        ) {
            if let Some(chain) = &mut root.local_chain {
                chain.parents = available_ca_chain(&root.certificate_der, available)?;
            }
        }
        if let Some(state) = &mut self.local_intermediate {
            for ca in state.public_issuers.values_mut() {
                ca.parents = available_ca_chain(&ca.certificate_der, available)?;
            }
        }
        Ok(())
    }
}

impl Pki {
    pub(super) fn has_external_signed_ca_issuer_reference(
        &self,
        id: &str,
        issuer_der: &[u8],
    ) -> Result<bool> {
        for ca in self
            .local_intermediate
            .iter()
            .flat_map(|state| state.signed_certificates.values())
        {
            if ca.issuer_id == id
                && ca
                    .parents
                    .first()
                    .is_some_and(|parent| parent == issuer_der)
            {
                certificate_signed_by(&ca.certificate_der, issuer_der)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(super) type ExternalPublicCaPlan = (String, Vec<u8>, Vec<Vec<u8>>);
pub(super) type ExternalPublicCaPlans = Vec<ExternalPublicCaPlan>;

impl Pki {
    pub(super) fn prepare_external_public_parents(
        &self,
        objects: &[Vec<u8>],
        child: &[u8],
    ) -> Result<(ExternalPublicCaPlans, Vec<String>)> {
        let mut imported = Vec::new();
        let mut existing = Vec::new();
        let mut seen = BTreeSet::new();
        for der in objects.iter().filter(|der| der.as_slice() != child) {
            certificate(der)?;
            if !seen.insert(crypto_digest(der)) {
                continue;
            }
            if let Some((id, _)) = self
                .local_intermediate
                .iter()
                .flat_map(|s| &s.public_issuers)
                .find(|(_, ca)| ca.certificate_der == *der)
            {
                existing.push(id.clone());
                continue;
            }
            if self
                .local_intermediate
                .as_ref()
                .map_or(0, |s| s.public_issuers.len())
                + imported.len()
                >= MAX_ISSUED
            {
                return Err(error(507, "public CA import capacity exhausted"));
            }
            imported.push((
                random_pki_id()?,
                der.clone(),
                available_ca_chain(der, objects)?,
            ));
        }
        Ok((imported, existing))
    }
    pub(super) fn publish_external_public_parents(
        &mut self,
        objects: &[ExternalPublicCaPlan],
    ) -> Result<()> {
        for (id, der, parents) in objects {
            if !valid_pki_id(id) || id.is_empty() {
                return Err(bad("invalid public CA import identity"));
            }
            validate_chain(der, parents)?;
            let state = self.local_intermediate.get_or_insert_with(Box::default);
            if state.public_issuers.contains_key(id) || state.public_issuers.len() >= MAX_ISSUED {
                return Err(error(503, "public CA import changed before publication"));
            }
            state.public_issuers.insert(
                id.clone(),
                ImportedCa {
                    certificate_der: der.clone(),
                    parents: parents.clone(),
                },
            );
        }
        Ok(())
    }
}

impl Pki {
    pub(super) fn publish_external_signed_ca(
        &mut self,
        certificate_der: Vec<u8>,
        parents: Vec<Vec<u8>>,
        issuer_id: String,
        serial: String,
        issued: u64,
        expires: u64,
    ) -> Result<()> {
        if self.intermediate_certificate(&serial).is_some()
            || self.local_certificate(&serial).is_some()
            || self.issued.contains_key(&serial)
            || self
                .local_intermediate
                .as_ref()
                .is_some_and(|s| s.signed_certificates.len() >= MAX_ISSUED)
        {
            return Err(error(
                503,
                "signed CA publication changed or exceeds bounds",
            ));
        }
        validate_chain(&certificate_der, &parents)?;
        self.local_intermediate
            .get_or_insert_with(Box::default)
            .signed_certificates
            .insert(
                serial,
                SignedCa {
                    certificate_der,
                    parents,
                    issuer_id,
                    issued,
                    expires,
                    revoked_at: None,
                },
            );
        Ok(())
    }
}

#[cfg(test)]
impl Pki {
    pub(in crate::engines) fn canonical_serial_http_fixture(now: u64) -> Result<Self> {
        let mut pki = Self::default();
        pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({"common_name":"actual historical parent","key_type":"ed25519","ttl":"4h"}),
            now,
        )?;
        for serial in [
            "000123456789abcdef112233445566778899aabbcc",
            "008123456789abcdef112233445566778899aabbcc",
        ] {
            let parent = pki
                .root
                .as_ref()
                .ok_or_else(|| bad("fixture parent missing"))?
                .clone();
            let material = parent.local_key()?;
            let child = LocalPrivateMaterial::generate(LocalKeyKind::Ed25519)?.public()?;
            let issuer_name = root_fields::certificate_subject(&parent.certificate_der)?;
            let issuer_ski = root_fields::certificate_key_identifier(&parent.certificate_der)?;
            let certificate = certificate_der_local(
                &material,
                &child,
                CertificateSpec {
                    serial,
                    issuer_cn: &parent.common_name,
                    subject_cn: "actual signed child",
                    issuer_name_der: Some(&issuer_name),
                    subject_name_der: None,
                    public_key: &[],
                    authority_key_id: issuer_ski.as_deref(),
                    not_before: role_time::signed_epoch(now - 30)?,
                    not_after: now + 3600,
                    is_ca: true,
                    alt_names: &[],
                    email_sans: &[],
                    ip_sans: &[],
                    uri_sans: &[],
                    exclude_cn_from_sans: true,
                    max_path_length: Some(0),
                    permitted_dns_domains: &[],
                    role_leaf_profile: None,
                },
            )?;
            certificate_signed_by(&certificate, &parent.certificate_der)?;
            pki.publish_external_signed_ca(
                certificate.clone(),
                vec![parent.certificate_der.clone()],
                parent.issuer_id.clone(),
                serial.into(),
                now,
                now + 3600,
            )?;
        }
        pki.validate("", "parent/", now)?;
        Ok(pki)
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
    fn signed_ca_original_zero_prefix_map_key_matches_exact_der_integer_and_revoke() -> TestResult {
        let mut pki = Pki::default();
        pki.handle_admin(
            "POST",
            "root/generate/internal",
            &json!({"common_name":"actual parent","key_type":"ed25519","ttl":"4h"}),
            NOW,
        )?;
        let parent = pki.root.as_ref().ok_or("parent")?.clone();
        let material = parent.local_key()?;
        let child = LocalPrivateMaterial::generate(LocalKeyKind::Ed25519)?.public()?;
        let serial = "000123456789abcdef";
        let issuer_name = root_fields::certificate_subject(&parent.certificate_der)?;
        let issuer_ski = root_fields::certificate_key_identifier(&parent.certificate_der)?;
        let certificate = certificate_der_local(
            &material,
            &child,
            CertificateSpec {
                serial,
                issuer_cn: &parent.common_name,
                subject_cn: "actual signed child",
                issuer_name_der: Some(&issuer_name),
                subject_name_der: None,
                public_key: &[],
                authority_key_id: issuer_ski.as_deref(),
                not_before: role_time::signed_epoch(NOW - 30)?,
                not_after: NOW + 3600,
                is_ca: true,
                alt_names: &[],
                email_sans: &[],
                ip_sans: &[],
                uri_sans: &[],
                exclude_cn_from_sans: true,
                max_path_length: Some(0),
                permitted_dns_domains: &[],
                role_leaf_profile: None,
            },
        )?;
        certificate_signed_by(&certificate, &parent.certificate_der)?;
        assert_ne!(
            normalize_serial(&super::certificate(&certificate)?.raw_serial_as_string())?,
            serial
        );
        pki.publish_external_signed_ca(
            certificate.clone(),
            vec![parent.certificate_der.clone()],
            parent.issuer_id.clone(),
            serial.into(),
            NOW,
            NOW + 3600,
        )?;
        pki.validate("", "pki/", NOW)?;
        assert_eq!(
            pki.intermediate_certificate(serial),
            Some(certificate.as_slice())
        );
        let canonical = canonical_serial_bytes(super::certificate(&certificate)?.raw_serial());
        assert_ne!(canonical, serial);
        let read = pki.handle_admin("GET", &format!("cert/{canonical}"), &json!({}), NOW)?;
        assert_eq!(
            read.body["data"]["certificate"],
            public::stored_pem("CERTIFICATE", &certificate)
        );
        assert_eq!(
            pki.handle_admin(
                "POST",
                "revoke",
                &json!({"serial_number":canonical}),
                NOW + 1
            )?
            .status,
            200
        );
        pki.validate("", "pki/", NOW + 1)?;
        let encoded = serde_json::to_vec(&pki)?;
        let reopened: Pki = serde_json::from_slice(&encoded)?;
        reopened.validate("", "pki/", NOW + 1)?;
        assert_eq!(
            reopened.intermediate_certificate(serial),
            Some(certificate.as_slice())
        );
        assert_eq!(reopened.signed_ca_revocation_time(serial), Some(NOW + 1));
        let mut ambiguous = reopened.clone();
        let original = ambiguous
            .local_intermediate
            .as_ref()
            .ok_or("owner")?
            .signed_certificates
            .get(serial)
            .ok_or("record")?
            .clone();
        ambiguous
            .local_intermediate
            .as_mut()
            .ok_or("owner")?
            .signed_certificates
            .insert(format!("00{serial}"), original);
        assert!(
            matches!(ambiguous.resolve_certificate_serial(&canonical), Err(e) if e.status==400)
        );
        let mut wrong = reopened.clone();
        let record = wrong
            .local_intermediate
            .as_mut()
            .ok_or("owner")?
            .signed_certificates
            .remove(serial)
            .ok_or("record")?;
        wrong
            .local_intermediate
            .as_mut()
            .ok_or("owner")?
            .signed_certificates
            .insert("000223456789abcdef".into(), record);
        assert!(
            wrong.validate("", "pki/", NOW + 1).is_err(),
            "different DER serial cannot borrow the original owner"
        );
        Ok(())
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
            &json!({"common_name":"three.example.test","ttl":"1h"}),
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
    #[test]
    fn standalone_ca_partial_chain_late_parent_and_repeated_bundle_follow_actual_oracle()
    -> TestResult {
        let mut parent = root()?;
        let mut child = Pki::default();
        let generated = child.handle_admin("POST", "intermediate/generate/internal", &json!({"common_name":"standalone.example.test","key_type":"ec","key_name":"shared-owned"}), NOW)?;
        let signed = parent.handle_admin("POST", "root/sign-intermediate", &json!({"csr":generated.body["data"]["csr"],"use_csr_values":true,"ttl":"12h","max_path_length":1}), NOW)?;
        let ca = signed.body["data"]["certificate"].as_str().ok_or("CA")?;
        child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":ca}),
            NOW,
        )?;
        assert_eq!(
            child
                .root
                .as_ref()
                .ok_or("owned CA")?
                .local_ca_chain_pem()
                .len(),
            1
        );
        child.validate("", "pki/", NOW)?;
        child.handle_admin(
            "POST",
            "roles/web",
            &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec"}),
            NOW,
        )?;
        let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
        let leaf = child.issue(
            "pki/",
            "web",
            &json!({"common_name":"standalone-leaf.example.test","ttl":"1h"}),
            &owner,
            None,
            NOW + 1,
        )?;
        let parsed = X509::from_pem(
            leaf.body["data"]["certificate"]
                .as_str()
                .ok_or("leaf")?
                .as_bytes(),
        )?;
        let issuer_key = PKey::public_key_from_der(
            &child
                .root
                .as_ref()
                .ok_or("issuer")?
                .local_key()?
                .public()?
                .spki()?,
        )?;
        assert!(parsed.verify(&issuer_key)?);
        assert_eq!(
            leaf.body["data"]["ca_chain"]
                .as_array()
                .ok_or("chain")?
                .len(),
            1
        );
        let raw = Zeroizing::new(serde_json::to_vec(&child)?);
        let mut child: Pki = serde_json::from_slice(&raw)?;
        child.validate("", "pki/", NOW + 1)?;
        let root_pem = pem(
            "CERTIFICATE",
            &parent.root.as_ref().ok_or("root")?.certificate_der,
        );
        child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":root_pem}),
            NOW + 2,
        )?;
        assert_eq!(
            child
                .root
                .as_ref()
                .ok_or("owned CA")?
                .local_ca_chain_pem()
                .len(),
            2
        );
        let repeated = child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":format!("{ca}\n{ca}\n{root_pem}\n{root_pem}")}),
            NOW + 3,
        )?;
        assert_eq!(
            repeated.body["data"]["mapping"]
                .as_object()
                .ok_or("mapping")?
                .len(),
            2
        );
        assert_eq!(
            repeated.body["data"]["existing_issuers"]
                .as_array()
                .ok_or("existing")?
                .len(),
            4
        );
        assert!(repeated.body["data"]["imported_issuers"].is_null());
        let mut public = Pki::default();
        let new_repeated = public.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":format!("{ca}\n{ca}\n{root_pem}")}),
            NOW,
        )?;
        assert_eq!(
            new_repeated.body["data"]["imported_issuers"]
                .as_array()
                .ok_or("new")?
                .len(),
            2
        );
        assert_eq!(
            new_repeated.body["data"]["existing_issuers"]
                .as_array()
                .ok_or("existing")?
                .len(),
            1
        );
        assert!(public.root.is_none());
        child.validate("", "pki/", NOW + 3)?;
        public.validate("", "pki/", NOW)?;
        // A lower CA can also hold only its immediate signer. Its supplied
        // edge is still cryptographically verified without inventing a root.
        let mut grandchild = Pki::default();
        let csr = grandchild.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"partial.example.test","key_type":"ec"}),
            NOW + 4,
        )?;
        let signed = child.handle_admin("POST", "root/sign-intermediate", &json!({"csr":csr.body["data"]["csr"],"use_csr_values":true,"ttl":"1h","max_path_length":0}), NOW+4)?;
        let lower = signed.body["data"]["certificate"]
            .as_str()
            .ok_or("lower CA")?;
        grandchild.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":format!("{lower}\n{ca}")}),
            NOW + 4,
        )?;
        assert_eq!(
            grandchild
                .root
                .as_ref()
                .ok_or("lower issuer")?
                .local_ca_chain_pem()
                .len(),
            2
        );
        grandchild.validate("", "pki/", NOW + 4)?;
        let reopened: Pki =
            serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&grandchild)?))?;
        reopened.validate("", "pki/", NOW + 4)?;
        assert_eq!(
            reopened
                .root
                .as_ref()
                .ok_or("reopened issuer")?
                .local_ca_chain_pem()
                .len(),
            2
        );
        Ok(())
    }

    #[test]
    fn multiple_ca_certificates_share_exact_owned_key_without_duplicate_keys_or_aliases()
    -> TestResult {
        let mut parent = root()?;
        let mut child = Pki::default();
        let generated = child.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"first.example.test","key_type":"ec","key_name":"one-owned-key"}),
            NOW,
        )?;
        let key = generated.body["data"]["key_id"]
            .as_str()
            .ok_or("key ID")?
            .to_owned();
        for name in ["first.example.test", "second.example.test"] {
            let signed = parent.handle_admin("POST", "root/sign-intermediate", &json!({"csr":generated.body["data"]["csr"],"common_name":name,"ttl":"12h","max_path_length":1}), NOW)?;
            let imported = child.handle_admin(
                "POST",
                "intermediate/set-signed",
                &json!({"certificate":signed.body["data"]["certificate"]}),
                NOW,
            )?;
            assert!(
                imported.body["data"]["mapping"]
                    .as_object()
                    .ok_or("mapping")?
                    .values()
                    .all(|id| id == &key)
            );
        }
        assert_eq!(child.local_roots().count(), 2);
        assert_eq!(child.local_keys().count(), 1);
        assert_eq!(
            child.local_key_list(&json!({}))?.body["data"]["keys"]
                .as_array()
                .ok_or("keys")?
                .len(),
            1
        );
        child.validate("", "pki/", NOW)?;
        let reopened: Pki = serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&child)?))?;
        reopened.validate("", "pki/", NOW)?;
        assert_eq!(reopened.local_roots().count(), 2);
        assert_eq!(reopened.local_keys().count(), 1);
        let second = child
            .local_issuers
            .as_ref()
            .ok_or("other")?
            .other
            .keys()
            .next()
            .ok_or("issuer")?
            .clone();
        for field in ["key_id", "local_fields/key_name"] {
            let mut forged = serde_json::to_value(&child)?;
            *forged
                .pointer_mut(&format!("/local_issuers/other/{second}/{field}"))
                .ok_or("owned field")? = json!(if field == "key_id" {
                random_pki_id()?
            } else {
                "different-alias".to_owned()
            });
            let forged: Pki = serde_json::from_value(forged)?;
            assert!(forged.validate("", "pki/", NOW).is_err());
        }
        let mut removed = reopened;
        removed.handle_admin("DELETE", &format!("issuer/{second}"), &json!({}), NOW)?;
        removed.validate("", "pki/", NOW)?;
        assert_eq!(removed.local_keys().count(), 1);
        assert_eq!(removed.local_roots().count(), 1);
        Ok(())
    }
    #[test]
    fn eleven_real_unbound_key_exports_imports_and_default_delete_follow_official_contract()
    -> TestResult {
        let mut pki = Pki::default();
        let mut ids = Vec::new();
        for (key_type, bits) in [
            ("ed25519", 0),
            ("rsa", 2048),
            ("rsa", 3072),
            ("rsa", 4096),
            ("ec", 224),
            ("ec", 256),
            ("ec", 384),
            ("ec", 521),
            ("mldsa", 44),
            ("mldsa", 65),
            ("mldsa", 87),
        ] {
            let generated = pki.handle_admin("POST", "keys/generate/exported", &json!({"key_type":key_type,"key_bits":bits,"key_name":format!("{key_type}{bits}")}), NOW)?;
            let id = generated.body["data"]["key_id"]
                .as_str()
                .ok_or("key ID")?
                .to_owned();
            let key_pem = generated.body["data"]["private_key"]
                .as_str()
                .ok_or("exported key")?;
            let imported =
                pki.handle_admin("POST", "keys/import", &json!({"pem_bundle":key_pem}), NOW)?;
            assert_eq!(imported.body["data"]["key_id"], id);
            assert!(!imported.mutated);
            assert_eq!(imported.body["data"]["key_type"], key_type);
            let (_, _, material) = pki.owned_key(&id)?;
            let signature = material.sign(b"independent key ownership roundtrip")?;
            assert!(
                material
                    .public()?
                    .verify(b"independent key ownership roundtrip", &signature)?
            );
            let read = pki.handle_admin("GET", &format!("key/{id}"), &json!({}), NOW)?;
            assert!(read.body["data"].get("private_key").is_none());
            assert_eq!(read.body["data"]["key_type"], key_type);
            ids.push(id);
        }
        assert_eq!(
            pki.local_key_list(&json!({}))?.body["data"]["keys"]
                .as_array()
                .ok_or("keys")?
                .len(),
            11
        );
        assert!(
            pki.local_intermediate
                .as_ref()
                .ok_or("key owner")?
                .pending
                .values()
                .all(|key| key.csr_der.is_empty())
        );
        pki.validate("", "pki/", NOW)?;
        let before = Zeroizing::new(serde_json::to_vec(&pki)?);
        let (_, _, material) = pki.owned_key(&ids[10])?;
        let (private, label) = material.root_export_der(false)?;
        assert!(
            pki.handle_admin(
                "POST",
                "keys/import",
                &json!({"pem_bundle":pem(label,private.as_slice()),"key_name":"mldsa87"}),
                NOW
            )
            .is_err()
        );
        assert_eq!(*before, serde_json::to_vec(&pki)?);
        let removed = pki.handle_admin("DELETE", &format!("key/{}", ids[0]), &json!({}), NOW)?;
        assert_eq!(removed.status, 200);
        assert!(
            removed.body["warnings"]
                .as_array()
                .is_some_and(|w| !w.is_empty())
        );
        assert_eq!(pki.default_local_key_id(), "");
        pki.validate("", "pki/", NOW)?;
        assert!(matches!(pki.owned_key(&ids[0]), Err(e) if e.status == 500));
        pki.handle_admin("POST", "config/keys", &json!({"default":ids[1]}), NOW)?;
        pki.handle_admin("DELETE", &format!("key/{}", ids[1]), &json!({}), NOW)?;
        assert_eq!(pki.default_local_key_id(), "");
        let reopened: Pki = serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&pki)?))?;
        reopened.validate("", "pki/", NOW)?;
        assert_eq!(reopened.default_local_key_id(), "");
        let generated = pki.handle_admin(
            "POST",
            "keys/generate/internal",
            &json!({"key_type":"ec","key_name":"after-deleted-default"}),
            NOW,
        )?;
        assert_eq!(generated.body["data"]["key_id"], pki.default_local_key_id());
        assert!(generated.body["data"].get("private_key").is_none());
        pki.validate("", "pki/", NOW)?;
        Ok(())
    }

    #[test]
    fn private_key_import_before_or_after_public_ca_preserves_actual_issuer_and_signs() -> TestResult
    {
        let mut parent = root()?;
        let mut source = Pki::default();
        let generated = source.handle_admin("POST", "intermediate/generate/exported", &json!({"common_name":"imported.example.test","key_type":"ec","private_key_format":"pkcs8"}), NOW)?;
        let signed = parent.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":generated.body["data"]["csr"],"use_csr_values":true,"ttl":"12h"}),
            NOW,
        )?;
        let ca = signed.body["data"]["certificate"]
            .as_str()
            .ok_or("signed CA")?;
        let private_pem = generated.body["data"]["private_key"]
            .as_str()
            .ok_or("key")?;
        for late in [false, true] {
            let mut imported = Pki::default();
            let mut original_issuer = None;
            if late {
                let public = imported.handle_admin(
                    "POST",
                    "intermediate/set-signed",
                    &json!({"certificate":ca}),
                    NOW,
                )?;
                original_issuer = public.body["data"]["imported_issuers"][0]
                    .as_str()
                    .map(str::to_owned);
                assert!(imported.root.is_none());
                assert_eq!(imported.default_local_key_id(), "");
            }
            let key = imported.handle_admin(
                "POST",
                "keys/import",
                &json!({"pem_bundle":private_pem,"key_name":"owned-imported"}),
                NOW,
            )?;
            let key_id = key.body["data"]["key_id"]
                .as_str()
                .ok_or("key ID")?
                .to_owned();
            if !late {
                imported.handle_admin(
                    "POST",
                    "intermediate/set-signed",
                    &json!({"certificate":ca}),
                    NOW,
                )?;
            }
            let issuer = imported.root.as_ref().ok_or("private owner bound")?;
            assert_eq!(issuer.key_id, key_id);
            if let Some(id) = original_issuer {
                assert_eq!(issuer.issuer_id, id);
            }
            assert_eq!(
                issuer.certificate_der,
                pem_blocks(ca, "CERTIFICATE")?.remove(0)
            );
            assert!(
                issuer
                    .local_chain
                    .as_ref()
                    .ok_or("imported key chain")?
                    .csr_der
                    .is_empty()
            );
            assert_eq!(imported.default_local_key_id(), key_id);
            let before = Zeroizing::new(serde_json::to_vec(&imported)?);
            let repeat = imported.handle_admin(
                "POST",
                "keys/import",
                &json!({"pem_bundle":private_pem,"key_name":"unused-new-name"}),
                NOW,
            )?;
            assert_eq!(repeat.body["data"]["key_id"], key_id);
            assert_eq!(repeat.body["data"]["key_name"], "owned-imported");
            assert!(!repeat.mutated);
            assert_eq!(*before, serde_json::to_vec(&imported)?);
            imported.handle_admin("POST", "roles/web", &json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec"}), NOW)?;
            let owner = serde_json::from_value::<LeaseOwner>(json!("a".repeat(43)))?;
            let leaf = imported.issue(
                "pki/",
                "web",
                &json!({"common_name":"owned-imported.example.test","ttl":"1h"}),
                &owner,
                None,
                NOW + 1,
            )?;
            let cert = X509::from_pem(
                leaf.body["data"]["certificate"]
                    .as_str()
                    .ok_or("leaf")?
                    .as_bytes(),
            )?;
            let public =
                PKey::public_key_from_der(&imported.owned_key(&key_id)?.2.public()?.spki()?)?;
            assert!(cert.verify(&public)?);
            imported.validate("", "pki/", NOW + 1)?;
            let reopened: Pki =
                serde_json::from_slice(&Zeroizing::new(serde_json::to_vec(&imported)?))?;
            reopened.validate("", "pki/", NOW + 1)?;
            assert_eq!(
                reopened.root.as_ref().ok_or("reopened issuer")?.key_id,
                key_id
            );
        }
        Ok(())
    }

    #[test]
    fn key_rename_shared_issuers_and_in_use_delete_keep_authority_until_last_issuer_removed()
    -> TestResult {
        let mut parent = root()?;
        let mut child = Pki::default();
        let csr = child.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"first.example.test","key_type":"ec","key_name":"shared-old"}),
            NOW,
        )?;
        let id = csr.body["data"]["key_id"]
            .as_str()
            .ok_or("key ID")?
            .to_owned();
        for cn in ["first.example.test", "second.example.test"] {
            let signed = parent.handle_admin(
                "POST",
                "root/sign-intermediate",
                &json!({"csr":csr.body["data"]["csr"],"common_name":cn,"ttl":"12h"}),
                NOW,
            )?;
            child.handle_admin(
                "POST",
                "intermediate/set-signed",
                &json!({"certificate":signed.body["data"]["certificate"]}),
                NOW,
            )?;
        }
        child.handle_admin(
            "POST",
            "key/shared-old",
            &json!({"key_name":"shared-new"}),
            NOW,
        )?;
        assert!(child.local_roots().all(|r| {
            r.local_fields
                .as_ref()
                .is_some_and(|m| m.key_name == "shared-new")
        }));
        assert_eq!(child.owned_key("shared-new")?.0, id);
        let before = Zeroizing::new(serde_json::to_vec(&child)?);
        assert!(
            matches!(child.handle_admin("DELETE", &format!("key/{id}"), &json!({}), NOW), Err(e) if e.status == 400)
        );
        assert_eq!(*before, serde_json::to_vec(&child)?);
        let issuers: Vec<_> = child.local_roots().map(|r| r.issuer_id.clone()).collect();
        for issuer in issuers {
            child.handle_admin("DELETE", &format!("issuer/{issuer}"), &json!({}), NOW)?;
        }
        child.validate("", "pki/", NOW)?;
        assert_eq!(child.local_keys().count(), 1);
        child.handle_admin("DELETE", &format!("key/{id}"), &json!({}), NOW)?;
        child.validate("", "pki/", NOW)?;
        assert_eq!(child.local_keys().count(), 0);
        assert_eq!(child.default_local_key_id(), "");
        assert!(
            child.certificate_list(&json!({}))?.body["data"]["keys"]
                .as_array()
                .ok_or("archived public certificates")?
                .len()
                >= 2
        );
        Ok(())
    }
    #[test]
    fn actual_bundle_default_policy_and_import_warnings_survive_reopen() -> TestResult {
        let (mut parent, mut child) = setup()?;
        let original = child.selected_local_issuer_id().to_owned();
        let csr_a = pem(
            "CERTIFICATE REQUEST",
            &child
                .root
                .as_ref()
                .ok_or("owned")?
                .local_chain
                .as_ref()
                .ok_or("chain")?
                .csr_der,
        );
        child.handle_admin(
            "POST",
            "config/issuers",
            &json!({"default":original,"default_follows_latest_issuer":true}),
            NOW,
        )?;
        let b = child.handle_admin(
            "POST",
            "intermediate/generate/internal",
            &json!({"common_name":"b.example.test","key_type":"ec"}),
            NOW,
        )?;
        let csr_b = b.body["data"]["csr"].as_str().ok_or("csr b")?.to_owned();
        let a2 = parent.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":csr_a,"common_name":"a-second.example.test","ttl":"12h"}),
            NOW,
        )?;
        let b1 = parent.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":csr_b,"common_name":"b.example.test","ttl":"12h"}),
            NOW,
        )?;
        let bundle = format!(
            "{}\n{}",
            a2.body["data"]["certificate"].as_str().ok_or("a2")?,
            b1.body["data"]["certificate"].as_str().ok_or("b")?
        );
        let imported = child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":bundle}),
            NOW,
        )?;
        assert_eq!(child.selected_local_issuer_id(), original);
        assert_eq!(
            imported.body["warnings"][0],
            "Default issuer left unchanged: could not select new issuer automatically as multiple imported issuers had key material in Vault."
        );
        assert_eq!(
            imported.body["warnings"]
                .as_array()
                .ok_or("warnings")?
                .len(),
            2
        );
        assert!(
            child.local_issuer_config("GET", &json!({}))?.body["data"]["default_follows_latest_issuer"]
                == true
        );
        let b2 = parent.handle_admin(
            "POST",
            "root/sign-intermediate",
            &json!({"csr":csr_b,"common_name":"b-second.example.test","ttl":"12h"}),
            NOW,
        )?;
        let imported = child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":b2.body["data"]["certificate"]}),
            NOW,
        )?;
        assert_eq!(
            child.selected_local_issuer_id(),
            imported.body["data"]["imported_issuers"][0]
                .as_str()
                .ok_or("new")?
        );
        assert_eq!(
            imported.body["warnings"]
                .as_array()
                .ok_or("warnings")?
                .len(),
            1
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&child)?);
        let reopened: Pki = serde_json::from_slice(&bytes)?;
        reopened.validate("", "pki/", NOW)?;
        assert_eq!(
            reopened.selected_local_issuer_id(),
            child.selected_local_issuer_id()
        );
        Ok(())
    }

    #[test]
    fn public_default_is_real_certificate_identity_and_late_key_keeps_it() -> TestResult {
        let parent = root()?;
        let owned = parent.root.as_ref().ok_or("root")?;
        let cert = pem("CERTIFICATE", &owned.certificate_der);
        let mut child = Pki::default();
        let imported = child.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":cert}),
            NOW,
        )?;
        let id = imported.body["data"]["imported_issuers"][0]
            .as_str()
            .ok_or("id")?
            .to_owned();
        child.handle_admin("POST", "config/issuers", &json!({"default":id}), NOW)?;
        assert_eq!(child.selected_local_issuer_id(), id);
        let metadata = child.handle_admin("GET", "issuer/default", &json!({}), NOW)?;
        assert_eq!(metadata.body["data"]["issuer_id"], id);
        assert_eq!(metadata.body["data"]["key_id"], "");
        assert_eq!(
            metadata.body["data"].as_object().ok_or("metadata")?.len(),
            14
        );
        assert!(child.public_read_route("GET", "issuer/default").is_none());
        assert!(child.root.is_none());
        assert!(child.local_issuer("default").is_err());
        assert_eq!(
            child
                .handle_public_read(PkiPublicRead::IssuerJson("default"), &json!({}), NOW)?
                .body["data"]["issuer_id"],
            id
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&child)?);
        let mut child: Pki = serde_json::from_slice(&bytes)?;
        child.validate("", "pki/", NOW)?;
        let (private, label) = owned.local_key()?.root_export_der(false)?;
        let encoded = Zeroizing::new(pem(label, &private));
        child.handle_admin(
            "POST",
            "keys/import",
            &json!({"pem_bundle":encoded.as_str()}),
            NOW,
        )?;
        assert_eq!(child.selected_local_issuer_id(), id);
        assert_eq!(child.local_issuer("default")?.issuer_id, id);
        let metadata = child.handle_admin("GET", "issuer/default", &json!({}), NOW)?;
        assert_eq!(
            metadata.body["data"]["key_id"],
            child.default_local_key_id()
        );
        child.validate("", "pki/", NOW)?;
        let original_der = owned.certificate_der.clone();
        let mut damaged_der = original_der.clone();
        *damaged_der.last_mut().ok_or("signature")? ^= 1;
        let damaged = X509::from_der(&damaged_der)?;
        let public = PKey::public_key_from_der(&owned.local_key()?.public()?.spki()?)?;
        assert!(!damaged.verify(&public)?);
        let mut public_only = Pki::default();
        public_only.handle_admin(
            "POST",
            "intermediate/set-signed",
            &json!({"certificate":pem("CERTIFICATE",&damaged_der)}),
            NOW,
        )?;
        public_only.validate("", "pki/", NOW)?;
        assert!(public_only.root.is_none());
        assert_eq!(public_only.local_keys().count(), 0);
        let cert_id = public_only
            .local_intermediate
            .as_ref()
            .ok_or("public")?
            .public_issuers
            .keys()
            .next()
            .ok_or("public id")?
            .clone();
        assert_eq!(
            public_only.public_imported_ca(&cert_id).ok_or("read")?.0,
            damaged_der
        );
        Ok(())
    }
    #[test]
    fn public_default_follow_keep_and_cleared_selection_use_real_new_root() -> TestResult {
        let public_parent = root()?;
        let public_cert = public_parent
            .root
            .as_ref()
            .ok_or("public")?
            .certificate_der
            .clone();
        for mode in ["follow", "clear", "keep"] {
            let mut pki = Pki::default();
            pki.handle_admin(
                "POST",
                "root/generate/internal",
                &json!({"common_name":"old.example.test","key_type":"ec","ttl":"24h"}),
                NOW,
            )?;
            let imported = pki.handle_admin(
                "POST",
                "intermediate/set-signed",
                &json!({"certificate":pem("CERTIFICATE",&public_cert)}),
                NOW,
            )?;
            let public_id = imported.body["data"]["imported_issuers"][0]
                .as_str()
                .ok_or("public id")?
                .to_owned();
            pki.handle_admin(
                "POST",
                "config/issuers",
                &json!({"default":public_id,"default_follows_latest_issuer":mode=="follow"}),
                NOW,
            )?;
            let route = pki
                .public_read_route("GET", "issuer/default/json")
                .ok_or("public route")?;
            let read = pki.handle_public_read(route, &json!({}), NOW)?;
            assert_eq!(read.body["data"]["issuer_id"], public_id);
            assert_eq!(
                read.body["data"]["certificate"],
                pem("CERTIFICATE", &public_cert)
            );
            assert!(pki.local_issuer("default").is_err());
            if mode == "clear" {
                pki.handle_admin("DELETE", &format!("issuer/{public_id}"), &json!({}), NOW)?;
                assert_eq!(pki.selected_local_issuer_id(), "");
                assert!(pki.local_issuer("default").is_err());
                assert!(
                    pki.handle_public_read(PkiPublicRead::Ca, &json!({}), NOW)
                        .is_err()
                );
            }
            let generated = pki.handle_admin(
                "POST",
                "root/generate/internal",
                &json!({"common_name":"new.example.test","key_type":"ec","ttl":"24h"}),
                NOW,
            )?;
            let new_id = generated.body["data"]["issuer_id"]
                .as_str()
                .ok_or("new id")?;
            if mode == "keep" {
                assert_eq!(pki.selected_local_issuer_id(), public_id);
                assert!(pki.local_issuer("default").is_err());
            } else {
                assert_eq!(pki.selected_local_issuer_id(), new_id);
                assert_eq!(pki.local_issuer("default")?.issuer_id, new_id);
            }
            let bytes = Zeroizing::new(serde_json::to_vec(&pki)?);
            let reopened: Pki = serde_json::from_slice(&bytes)?;
            reopened.validate("", "pki/", NOW)?;
            assert_eq!(
                reopened.selected_local_issuer_id(),
                pki.selected_local_issuer_id()
            );
        }
        Ok(())
    }
    #[test]
    fn existing_csr_reuses_all_eleven_true_owned_keys_without_state_or_alias_changes() -> TestResult
    {
        let mut pki = Pki::default();
        let missing = pki.handle_admin(
            "POST",
            "intermediate/generate/existing",
            &json!({"common_name":"reuse.example.test"}),
            NOW,
        );
        assert!(matches!(missing, Err(e) if e.status==400));
        for (kind, bits) in [
            ("ed25519", 0),
            ("rsa", 2048),
            ("rsa", 3072),
            ("rsa", 4096),
            ("ec", 224),
            ("ec", 256),
            ("ec", 384),
            ("ec", 521),
            ("mldsa", 44),
            ("mldsa", 65),
            ("mldsa", 87),
        ] {
            let generated = pki.handle_admin(
                "POST",
                "keys/generate/internal",
                &json!({"key_type":kind,"key_bits":bits,"key_name":format!("reuse-{kind}{bits}")}),
                NOW,
            )?;
            let id = generated.body["data"]["key_id"]
                .as_str()
                .ok_or("key id")?
                .to_owned();
            let before = Zeroizing::new(serde_json::to_vec(&pki)?);
            let response = pki.handle_admin(
                "POST",
                "intermediate/generate/existing",
                &json!({"common_name":"reuse.example.test","key_ref":id,"key_name":"unused-name"}),
                NOW,
            )?;
            assert!(!response.mutated);
            assert_eq!(*before, serde_json::to_vec(&pki)?);
            assert_eq!(response.body["data"]["key_id"], id);
            assert_eq!(response.body["data"].as_object().ok_or("data")?.len(), 2);
            let bytes = pem_blocks(
                response.body["data"]["csr"].as_str().ok_or("csr")?,
                "CERTIFICATE REQUEST",
            )?
            .remove(0);
            let csr = parse_csr(&bytes)?;
            let material = pki.owned_key(&id)?.2;
            assert_eq!(
                csr.certification_request_info.subject_pki.raw,
                material.public()?.spki()?
            );
            let read = pki.handle_admin("GET", &format!("key/{id}"), &json!({}), NOW)?;
            assert_eq!(read.body["data"].as_object().ok_or("metadata")?.len(), 4);
            assert_eq!(
                read.body["data"]["subject_key_id"]
                    .as_str()
                    .ok_or("identifier")?
                    .len(),
                59
            );
            assert_eq!(pki.owned_key(&id)?.1, format!("reuse-{kind}{bits}"));
            assert!(
                matches!(pki.handle_admin("POST", "intermediate/generate/existing", &json!({"common_name":"reuse.example.test","key_ref":id,"key_type":"rsa","key_bits":4096}), NOW),Err(e)if e.status==400)
            );
            assert_eq!(*before, serde_json::to_vec(&pki)?);
        }
        pki.handle_admin("POST", "root/generate/internal", &json!({"common_name":"bound.example.test","key_type":"ec","key_name":"bound-owner","ttl":"24h"}), NOW)?;
        let id = pki.owned_key("bound-owner")?.0;
        let before = Zeroizing::new(serde_json::to_vec(&pki)?);
        let response = pki.handle_admin(
            "POST",
            "intermediate/generate/existing",
            &json!({"common_name":"bound-reuse.example.test","key_ref":"bound-owner"}),
            NOW,
        )?;
        assert_eq!(response.body["data"]["key_id"], id);
        assert_eq!(*before, serde_json::to_vec(&pki)?);
        let reopened: Pki = serde_json::from_slice(&before)?;
        reopened.validate("", "pki/", NOW)?;
        Ok(())
    }
}
