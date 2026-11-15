//! Test-only ACME cryptographic inputs shared by the independent local and external suites.
use super::super::{Response, Value, json};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    x509::{X509NameBuilder, X509Req, extension::SubjectAlternativeName},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(in crate::service) fn key() -> TestResult<(PKey<Private>, Value)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&group)?;
    let mut x = openssl::bn::BigNum::new()?;
    let mut y = openssl::bn::BigNum::new()?;
    let mut context = BigNumContext::new()?;
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)?;
    let jwk = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(x.to_vec_padded(32)?),"y":URL_SAFE_NO_PAD.encode(y.to_vec_padded(32)?)});
    Ok((PKey::from_ec_key(ec)?, jwk))
}

pub(in crate::service) fn signed(
    key: &PKey<Private>,
    jwk: &Value,
    nonce: &str,
    url: &str,
    kid: Option<&str>,
    payload: Option<Value>,
) -> TestResult<Value> {
    let mut header = json!({"alg":"ES256","nonce":nonce,"url":url});
    match kid {
        Some(kid) => header["kid"] = json!(kid),
        None => header["jwk"] = jwk.clone(),
    }
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = payload
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let message = format!("{protected}.{payload}");
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(message.as_bytes())?;
    let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    let mut raw = signature.r().to_vec_padded(32)?;
    raw.extend(signature.s().to_vec_padded(32)?);
    Ok(json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(raw)}))
}

pub(in crate::service) fn header(response: &Response, name: &str) -> TestResult<String> {
    let h = serde_json::to_value(&response.response_headers)?;
    Ok(h[name][0]
        .as_str()
        .ok_or("actual filtered ACME header")?
        .to_owned())
}

pub(in crate::service) fn csr(domain: &str) -> TestResult<(PKey<Private>, Vec<u8>)> {
    let (private, _) = key()?;
    let request = csr_with_key(domain, &private)?;
    Ok((private, request))
}

pub(in crate::service) fn csr_with_key(
    domain: &str,
    private: &PKey<Private>,
) -> TestResult<Vec<u8>> {
    let mut request = X509Req::builder()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, domain)?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "UntrustedSubjectMustBeIgnored")?;
    request.set_subject_name(&name.build())?;
    request.set_pubkey(private)?;
    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(
        SubjectAlternativeName::new()
            .dns(domain)
            .build(&request.x509v3_context(None))?,
    )?;
    request.add_extensions(&extensions)?;
    request.sign(private, MessageDigest::sha256())?;
    let request = request.build();
    assert!(request.verify(private)?);
    Ok(request.to_der()?)
}
