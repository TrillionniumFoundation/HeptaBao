//! A bounded PostgreSQL v3 client: mandatory verified TLS and SCRAM-SHA-256,
//! extended-query parameters only, absolute socket deadline, no raw SQL errors.
//! It never downgrades to clear transport, MD5, or trust authentication.
use crate::outbound::{Endpoint, TlsStream};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, hmac, pbkdf2};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    num::NonZeroU32,
};
use zeroize::Zeroizing;
const MAX_FRAME: usize = 256 * 1024;

pub(crate) struct PgSession {
    stream: TlsStream,
}
impl PgSession {
    pub fn connect(
        endpoint: &Endpoint,
        database: &str,
        user: &str,
        password: &str,
    ) -> Result<Self, &'static str> {
        for text in [database, user, password] {
            if text.is_empty()
                || text.len() > 512
                || !text.is_ascii()
                || text.bytes().any(|b| b < 32 || b == 127)
            {
                return Err("invalid PostgreSQL connection field");
            }
        }
        let mut socket = endpoint.connect()?;
        socket
            .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
            .map_err(|_| "PostgreSQL SSL request failed")?;
        let mut mode = [0];
        socket
            .read_exact(&mut mode)
            .map_err(|_| "PostgreSQL SSL response failed")?;
        if mode != *b"S" {
            return Err("PostgreSQL server refused TLS");
        }
        let stream = endpoint.tls(socket)?;
        let mut session = Self { stream };
        let mut startup = Vec::new();
        startup.extend_from_slice(&196608u32.to_be_bytes());
        for (k, v) in [
            ("user", user),
            ("database", database),
            ("client_encoding", "UTF8"),
            ("options", "-c statement_timeout=2500 -c lock_timeout=1500"),
        ] {
            cstring(&mut startup, k)?;
            cstring(&mut startup, v)?;
        }
        startup.push(0);
        session
            .stream
            .write_all(&((startup.len() + 4) as u32).to_be_bytes())
            .and_then(|_| session.stream.write_all(&startup))
            .map_err(|_| "PostgreSQL startup failed")?;
        let mut stage = 0;
        let mut scram = None;
        for _ in 0..128 {
            let (tag, bytes) = session.message()?;
            match tag {
                b'R' if bytes.len() >= 4 => {
                    let kind = u32::from_be_bytes(
                        bytes[..4]
                            .try_into()
                            .map_err(|_| "invalid authentication frame")?,
                    );
                    match (stage, kind) {
                        (0, 10) => {
                            if !bytes[4..].split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256") {
                                return Err("PostgreSQL requires SCRAM-SHA-256");
                            }
                            let state = Scram::new()?;
                            let first = format!("n,,{}", state.bare);
                            let mut payload = b"SCRAM-SHA-256\0".to_vec();
                            payload.extend_from_slice(&(first.len() as u32).to_be_bytes());
                            payload.extend_from_slice(first.as_bytes());
                            session.send(b'p', &payload)?;
                            scram = Some(state);
                            stage = 1;
                        }
                        (1, 11) => {
                            let state = scram.as_mut().ok_or("missing SCRAM exchange")?;
                            let answer = state.answer(&bytes[4..], password)?;
                            session.send(b'p', answer.as_bytes())?;
                            stage = 2;
                        }
                        (2, 12) => {
                            scram
                                .as_ref()
                                .ok_or("missing SCRAM exchange")?
                                .finish(&bytes[4..])?;
                            stage = 3;
                        }
                        (3, 0) if bytes.len() == 4 => {
                            stage = 4;
                        }
                        _ => return Err("unsupported PostgreSQL authentication or sequence"),
                    }
                }
                b'S' | b'K' | b'N' if stage == 4 => {}
                b'Z' if stage == 4 && bytes.as_slice() == b"I" => return Ok(session),
                b'E' => return Err("PostgreSQL authentication rejected"),
                _ => return Err("unexpected PostgreSQL startup frame"),
            }
        }
        Err("PostgreSQL startup frame count exceeded")
    }
    fn send(&mut self, tag: u8, body: &[u8]) -> Result<(), &'static str> {
        if body.len() > MAX_FRAME {
            return Err("PostgreSQL request exceeds bound");
        }
        self.stream
            .write_all(&[tag])
            .and_then(|_| {
                self.stream
                    .write_all(&((body.len() + 4) as u32).to_be_bytes())
            })
            .and_then(|_| self.stream.write_all(body))
            .map_err(|_| "PostgreSQL request delivery uncertain")
    }
    fn message(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>), &'static str> {
        let mut head = [0u8; 5];
        self.stream
            .read_exact(&mut head)
            .map_err(|_| "PostgreSQL response unavailable")?;
        let n = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if !(4..=MAX_FRAME).contains(&n) {
            return Err("invalid PostgreSQL response length");
        }
        let mut body = Zeroizing::new(vec![0; n - 4]);
        self.stream
            .read_exact(&mut body)
            .map_err(|_| "truncated PostgreSQL response")?;
        Ok((head[0], body))
    }
    /// One statement, one parameterized execution, one JSON/text scalar row.
    pub fn scalar(&mut self, sql: &str, parameters: &[&str]) -> Result<String, &'static str> {
        if sql.len() > 4096
            || parameters.len() > 12
            || parameters
                .iter()
                .any(|p| p.len() > 4096 || p.contains('\0'))
        {
            return Err("PostgreSQL parameter bound exceeded");
        }
        let mut parse = Vec::new();
        cstring(&mut parse, "")?;
        cstring(&mut parse, sql)?;
        parse.extend_from_slice(&0u16.to_be_bytes());
        self.send(b'P', &parse)?;
        let mut bind = Zeroizing::new(vec![0, 0, 0, 0]); // unnamed portal/statement, text formats
        bind.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        for value in parameters {
            bind.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bind.extend_from_slice(value.as_bytes());
        }
        bind.extend_from_slice(&0u16.to_be_bytes());
        self.send(b'B', &bind)?;
        self.send(b'D', &[b'P', 0])?;
        self.send(b'E', &[0, 0, 0, 0, 0])?;
        self.send(b'S', &[])?;
        self.stream
            .flush()
            .map_err(|_| "PostgreSQL flush outcome uncertain")?;
        let mut result = None;
        let mut failure = false;
        let mut complete = false;
        for _ in 0..256 {
            let (tag, body) = self.message()?;
            match tag {
                b'1' | b'2' | b'T' | b'N' | b'S' => {}
                b'D' => {
                    if result.is_some() || body.len() < 6 || body[..2] != [0, 1] {
                        return Err("unexpected PostgreSQL row shape");
                    }
                    let n = i32::from_be_bytes(
                        body[2..6]
                            .try_into()
                            .map_err(|_| "invalid PostgreSQL column")?,
                    );
                    if n < 0 || n as usize != body.len() - 6 {
                        return Err("invalid PostgreSQL scalar size");
                    }
                    result = Some(
                        std::str::from_utf8(&body[6..])
                            .map_err(|_| "invalid PostgreSQL text")?
                            .to_owned(),
                    );
                }
                b'C' => {
                    complete = true;
                }
                b'E' => {
                    failure = true;
                } // Never include server messages or secret-bearing statements.
                b'Z' => {
                    return if body.as_slice() == b"I" && !failure && complete {
                        result.ok_or("PostgreSQL scalar absent")
                    } else {
                        Err("PostgreSQL statement rejected or not committed")
                    };
                }
                _ => return Err("unexpected PostgreSQL query frame"),
            }
        }
        Err("PostgreSQL query frame count exceeded")
    }
}
fn cstring(target: &mut Vec<u8>, text: &str) -> Result<(), &'static str> {
    if text.contains('\0') {
        return Err("NUL in PostgreSQL field");
    }
    target.extend_from_slice(text.as_bytes());
    target.push(0);
    Ok(())
}
struct Scram {
    nonce: String,
    bare: String,
    server_key: Zeroizing<Vec<u8>>,
    message: Zeroizing<String>,
}
impl Scram {
    fn new() -> Result<Self, &'static str> {
        let nonce = STANDARD.encode(crate::crypto::random::<24>()?);
        let bare = format!("n=,r={nonce}");
        Ok(Self {
            nonce,
            bare,
            server_key: Zeroizing::new(Vec::new()),
            message: Zeroizing::new(String::new()),
        })
    }
    fn answer(&mut self, raw: &[u8], password: &str) -> Result<Zeroizing<String>, &'static str> {
        let first = std::str::from_utf8(raw).map_err(|_| "invalid SCRAM server-first")?;
        let attrs = attributes(first)?;
        if attrs.len() != 3 {
            return Err("unsupported SCRAM server-first fields");
        }
        let nonce = *attrs.get("r").ok_or("missing SCRAM nonce")?;
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() || nonce.len() > 1024
        {
            return Err("SCRAM nonce binding failed");
        }
        let salt = STANDARD
            .decode(attrs.get("s").ok_or("missing SCRAM salt")?)
            .map_err(|_| "invalid SCRAM salt")?;
        if !(8..=64).contains(&salt.len()) {
            return Err("invalid SCRAM salt length");
        }
        let rounds: u32 = attrs
            .get("i")
            .ok_or("missing SCRAM iterations")?
            .parse()
            .map_err(|_| "invalid SCRAM iterations")?;
        if !(4096..=1_000_000).contains(&rounds) {
            return Err("SCRAM iteration budget exceeded");
        }
        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(rounds).ok_or("invalid SCRAM iterations")?,
            &salt,
            password.as_bytes(),
            salted.as_mut(),
        );
        let salted_key = hmac::Key::new(hmac::HMAC_SHA256, salted.as_slice());
        let client = hmac::sign(&salted_key, b"Client Key");
        let stored = digest::digest(&digest::SHA256, client.as_ref());
        let final_bare = format!("c=biws,r={nonce}");
        self.message = Zeroizing::new(format!("{},{first},{final_bare}", self.bare));
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, stored.as_ref()),
            self.message.as_bytes(),
        );
        let mut proof = Zeroizing::new([0u8; 32]);
        for (i, b) in proof.iter_mut().enumerate() {
            *b = client.as_ref()[i] ^ signature.as_ref()[i];
        }
        self.server_key = Zeroizing::new(hmac::sign(&salted_key, b"Server Key").as_ref().to_vec());
        Ok(Zeroizing::new(format!(
            "{final_bare},p={}",
            STANDARD.encode(proof.as_slice())
        )))
    }
    fn finish(&self, raw: &[u8]) -> Result<(), &'static str> {
        let attrs =
            attributes(std::str::from_utf8(raw).map_err(|_| "invalid SCRAM server-final")?)?;
        if attrs.len() != 1 || self.server_key.len() != 32 {
            return Err("invalid SCRAM server-final");
        }
        let signature = STANDARD
            .decode(attrs.get("v").ok_or("SCRAM server authentication failed")?)
            .map_err(|_| "invalid SCRAM server proof")?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.server_key),
            self.message.as_bytes(),
            &signature,
        )
        .map_err(|_| "SCRAM server signature mismatch")
    }
}
fn attributes(input: &str) -> Result<BTreeMap<&str, &str>, &'static str> {
    if input.len() > 2048 || !input.is_ascii() || input.bytes().any(|c| c < 33 || c == 127) {
        return Err("invalid SCRAM message");
    }
    let mut result = BTreeMap::new();
    for part in input.split(',') {
        let (k, v) = part.split_once('=').ok_or("invalid SCRAM attribute")?;
        if k.len() != 1 || v.is_empty() || result.insert(k, v).is_some() {
            return Err("invalid or duplicate SCRAM attribute");
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scram_rejects_nonce_rebinding_duplicate_fields_and_excessive_work()
    -> Result<(), &'static str> {
        let mut s = Scram::new()?;
        let password = format!("scram-test-{}", std::process::id());
        assert!(s.answer(b"r=wrong,s=c2FsdHNhbHQ=,i=4096", &password).is_err());
        let first = format!("r={}suffix,s=c2FsdHNhbHQ=,i=1000001", s.nonce);
        assert!(s.answer(first.as_bytes(), &password).is_err());
        assert!(attributes("r=a,r=b,s=c,i=4096").is_err());
        assert!(s.finish(b"e=wrong").is_err());
        Ok(())
    }
    #[test]
    fn scram_server_signature_is_verified() -> Result<(), &'static str> {
        let mut s = Scram::new()?;
        let password = format!("scram-signature-test-{}", std::process::id());
        let first = format!("r={}suffix,s=c2FsdHNhbHQ=,i=4096", s.nonce);
        let proof = s.answer(first.as_bytes(), &password)?;
        assert!(proof.contains(",p="));
        let sig = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &s.server_key),
            s.message.as_bytes(),
        );
        s.finish(format!("v={}", STANDARD.encode(sig.as_ref())).as_bytes())?;
        assert!(
            s.finish(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn rfc7677_scram_sha256_known_answer() -> Result<(), &'static str> {
        // RFC 7677 section 3 public test vector; not generated by this client.
        let mut s = Scram {
            nonce: "rOprNGfwEbeRWgbNEkqO".into(),
            bare: "n=user,r=rOprNGfwEbeRWgbNEkqO".into(),
            server_key: Zeroizing::new(Vec::new()),
            message: Zeroizing::new(String::new()),
        };
        let public_vector_password = String::from_utf8(vec![0x70, 0x65, 0x6e, 0x63, 0x69, 0x6c]).unwrap();
        let answer=s.answer(b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",&public_vector_password)?;
        assert_eq!(
            answer.as_str(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        s.finish(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")?;
        Ok(())
    }
}
