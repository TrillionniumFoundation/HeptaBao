//! Real remote HeptaBao Transit over verified HTTPS. Crypto is performed by a
//! separate Service's normal AES Transit owner, not a provider verification ack.
use super::tests::{Root, bootstrap, call, limited_token};
use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn typed_signing_options_contract(
    remote: &RemoteTransit,
    service: &mut Service,
    admin: &str,
    input: &str,
    retained: &str,
) -> TestResult {
    let contexts = vec![
        (Value::Null, 200),
        (json!(1234), 200),
        (json!(12345678), 200),
        (json!(10000000000000000000u64), 200),
        (json!(1234.0), 400),
        (json!(1e19), 400),
        (json!(true), 400),
        (json!(false), 400),
        (json!([]), 400),
        (json!({}), 400),
        (json!("YWJj"), 200),
        (json!(""), 200),
        (json!("%%%%"), 400),
    ];
    let salts = vec![
        (Value::Null, 400),
        (json!("auto"), 200),
        (json!("hash"), 200),
        (json!("AUTO"), 200),
        (json!("HASH"), 200),
        (json!(true), 200),
        (json!(false), 200),
        (json!(0), 200),
        (json!(1), 200),
        (json!(17), 200),
        (json!(-1), 200),
        (json!("17"), 200),
        (json!("-1"), 200),
        (json!("+17"), 200),
        (json!(""), 400),
        (json!("ignored"), 400),
        (json!(-2), 400),
        (json!(-3), 400),
        (json!("-2"), 400),
        (json!("-3"), 400),
        (json!(2.0), 400),
        (json!(2.5), 400),
        (json!([]), 400),
        (json!({}), 400),
        (json!(" 17 "), 400),
    ];
    for (field, cases) in [("context", contexts), ("salt_length", salts)] {
        for (value, status) in cases {
            let mut body = json!({"input":input});
            body[field] = value;
            let before = remote.calls()?;
            let signed = call(service, "POST", "consumer/sign/local", admin, body.clone());
            assert_eq!(signed.status, status, "{field}");
            body["signature"] = if status == 200 {
                signed.body["data"]["signature"].clone()
            } else {
                json!(retained)
            };
            let verified = call(service, "POST", "consumer/verify/local", admin, body);
            assert_eq!(verified.status, status, "{field}");
            if status == 200 {
                assert_eq!(verified.body["data"], json!({"valid":true}));
            } else {
                assert_eq!(remote.calls()?, before);
            }
        }
    }
    Ok(())
}

#[test]
fn external_transit270_signing_registry_grant_rejection_is_500_before_provider_entry() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let input = BASE64.encode(b"grant-bound signature");
    let signed = call(
        &mut service,
        "POST",
        "consumer/sign/local",
        &admin,
        json!({"input":input}),
    );
    assert_eq!(signed.status, 200);
    let signature = signed.body["data"]["signature"].clone();
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let before = remote.calls()?;
    for operation in ["sign", "verify"] {
        let denied = call(
            &mut service,
            "POST",
            &format!("consumer/{operation}/local"),
            &admin,
            if operation == "sign" {
                json!({"input":input})
            } else {
                json!({"input":input,"signature":signature})
            },
        );
        assert_eq!(denied.status, 500, "{operation}");
        assert!(denied.body.get("data").is_none());
    }
    assert_eq!(remote.calls()?, before);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let verified = call(
        &mut service,
        "POST",
        "consumer/verify/local",
        &admin,
        json!({"input":input,"signature":signature}),
    );
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["data"], json!({"valid":true}));
    Ok(())
}

#[test]
fn external_transit270_sign_verify_original_last_use_principal_and_strict_input_bounds()
-> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let input = BASE64.encode(b"last-use signature input");
    let token = limited_token(
        &mut service,
        &admin,
        "path \"consumer/sign/local\" { capabilities = [\"update\"] }",
    )?;
    let signed = call(
        &mut service,
        "POST",
        "consumer/sign/local",
        &token,
        json!({"input":input}),
    );
    assert_eq!(signed.status, 200);
    let signature = signed.body["data"]["signature"].clone();
    let before = remote.calls()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/sign/local",
            &token,
            json!({"input":input})
        )
        .status,
        403
    );
    assert_eq!(remote.calls()?, before);
    let token = limited_token(
        &mut service,
        &admin,
        "path \"consumer/verify/local\" { capabilities = [\"update\"] }",
    )?;
    let verified = call(
        &mut service,
        "POST",
        "consumer/verify/local",
        &token,
        json!({"input":input,"signature":signature}),
    );
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["data"], json!({"valid":true}));
    let before = remote.calls()?;
    for body in [
        json!({"input":BASE64.encode(vec![0;65537])}),
        json!({"input":"%%"}),
        json!({"input":input,"context":"%%"}),
        json!({"input":input,"prehashed":"not-a-boolean"}),
        json!({"input":input,"hash_algorithm":"invalid"}),
    ] {
        assert!(call(&mut service, "POST", "consumer/sign/local", &admin, body).status >= 400);
    }
    assert_eq!(remote.calls()?, before);
    let pending = staged_path(
        &mut service,
        &admin,
        "consumer/sign/local",
        json!({"input":input}),
    )?;
    let result = pending.execute();
    assert!(matches!(
        &result,
        ExternalEffectResult::ExternalTransit(Ok(_))
    ));
    fs::remove_file(_root.path.join("audit.jsonl"))?;
    fs::create_dir(_root.path.join("audit.jsonl"))?;
    let response = service.finish_external_request(pending, result);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn external_transit270_optional_host_sign_verify_grants_are_explicit_and_independent() -> TestResult
{
    let remote = RemoteTransit::new_kind("ed25519")?;
    let input = BASE64.encode(b"explicit external signing capabilities");
    let signature = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "POST",
        "transit/sign/remote",
        &remote.admin,
        json!({"input":input,"key_version":1}),
    );
    let signature = signature.body["data"]["signature"].clone();
    for capabilities in [
        vec!["wrap".into(), "unwrap".into()],
        vec!["sign".into()],
        vec!["verify".into()],
    ] {
        let can_sign = capabilities.iter().any(|value| value == "sign");
        let can_verify = capabilities.iter().any(|value| value == "verify");
        let (_root, mut service, _unseal, admin) =
            remote.fixture_kms_capabilities(Some(true), Some(capabilities))?;
        let before = remote.calls()?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "consumer/sign/local",
                &admin,
                json!({"input":input})
            )
            .status,
            if can_sign { 200 } else { 403 }
        );
        let verified = call(
            &mut service,
            "POST",
            "consumer/verify/local",
            &admin,
            json!({"input":input,"signature":signature}),
        );
        assert_eq!(verified.status, if can_verify { 200 } else { 403 });
        if can_verify {
            assert_eq!(verified.body["data"], json!({"valid":true}));
        }
        assert_eq!(
            remote.calls()? - before,
            usize::from(can_sign) + usize::from(can_verify)
        );
    }
    Ok(())
}

#[test]
fn external_transit270_real_remote_sign_verify_all_mldsa_ed25519_and_prehashing() -> TestResult {
    use sha2::{Digest, Sha256, Sha512};
    let message = b"real external cryptographic signing and readback";
    let input = BASE64.encode(message);
    for kind in ["ed25519", "mldsa-44", "mldsa-65", "mldsa-87"] {
        let remote = RemoteTransit::new_kind(kind)?;
        let (root, mut service, unseal, admin) = remote.fixture()?;
        let mut retained = String::new();
        assert_eq!(
            call(
                &mut service,
                "GET",
                "consumer/keys/local",
                &admin,
                json!({})
            )
            .body["data"]["supports_signing"],
            true
        );
        for disable_prehashing in [false, true] {
            assert_eq!(call(&mut service, "POST", "sys/external-keys/configs/remote/keys/v1", &admin,
                json!({"verify":false,"name":"remote","version":2,"disable_prehashing":disable_prehashing})).status,204);
            for algorithm in ["default", "none", "sha2-256", "sha2-512"] {
                let mut body = json!({"input":input});
                if algorithm != "default" {
                    body["hash_algorithm"] = json!(algorithm);
                }
                let signed = call(
                    &mut service,
                    "POST",
                    "consumer/sign/local",
                    &admin,
                    body.clone(),
                );
                assert_eq!(signed.status, 200, "{kind}/{algorithm}");
                assert_eq!(signed.body["data"]["key_version"], 1);
                let signature = signed.body["data"]["signature"]
                    .as_str()
                    .ok_or("signature")?;
                retained = signature.into();
                let payload = signature
                    .strip_prefix("vault:v1:")
                    .ok_or("local signature version")?;
                assert_eq!(
                    BASE64.decode(payload)?.len(),
                    match kind {
                        "ed25519" => 64,
                        "mldsa-44" => 2420,
                        "mldsa-65" => 3309,
                        _ => 4627,
                    }
                );
                let remote_input = if !disable_prehashing && algorithm == "sha2-256" {
                    BASE64.encode(Sha256::digest(message))
                } else if !disable_prehashing && algorithm == "sha2-512" {
                    BASE64.encode(Sha512::digest(message))
                } else {
                    input.clone()
                };
                let direct = call(
                    &mut *remote.service.lock().map_err(|_| "remote lock")?,
                    "POST",
                    "transit/verify/remote",
                    &remote.admin,
                    json!({"input":remote_input,"signature":format!("vault:v2:{payload}")}),
                );
                assert_eq!(direct.status, 200);
                assert_eq!(direct.body["data"], json!({"valid":true}));
                body["signature"] = json!(signature);
                let verified = call(
                    &mut service,
                    "POST",
                    "consumer/verify/local",
                    &admin,
                    body.clone(),
                );
                assert_eq!(verified.status, 200);
                assert_eq!(verified.body["data"], json!({"valid":true}));
                body["input"] = json!(BASE64.encode(b"changed message"));
                let invalid = call(&mut service, "POST", "consumer/verify/local", &admin, body);
                assert_eq!(invalid.status, 200);
                assert_eq!(invalid.body["data"], json!({"valid":false}));
            }
            for prehashed in [json!(true), json!("TRUE")] {
                for algorithm in ["none", "sha2-256", "sha2-512"] {
                    let body = json!({"input":BASE64.encode(Sha256::digest(message)),"prehashed":prehashed,"hash_algorithm":algorithm});
                    let before = remote.calls()?;
                    let signed = call(
                        &mut service,
                        "POST",
                        "consumer/sign/local",
                        &admin,
                        body.clone(),
                    );
                    let rejected = disable_prehashing && algorithm != "none";
                    assert_eq!(signed.status, if rejected { 500 } else { 200 });
                    let signature = if rejected {
                        json!(retained)
                    } else {
                        signed.body["data"]["signature"].clone()
                    };
                    let verified = call(
                        &mut service,
                        "POST",
                        "consumer/verify/local",
                        &admin,
                        json!({"signature":signature,
                        "input":body["input"],"prehashed":body["prehashed"],"hash_algorithm":algorithm}),
                    );
                    assert_eq!(verified.status, if rejected { 500 } else { 200 });
                    if rejected {
                        assert_eq!(remote.calls()?, before);
                    } else {
                        assert_eq!(verified.body["data"], json!({"valid":true}));
                    }
                }
            }
        }
        for hint in [
            json!(0),
            json!(1),
            json!(2),
            json!("2"),
            Value::Null,
            json!(false),
        ] {
            let verified = call(
                &mut service,
                "POST",
                "consumer/verify/local",
                &admin,
                json!({"input":input,"signature":retained,"key_version":hint}),
            );
            assert_eq!(verified.status, 200);
            assert_eq!(verified.body["data"], json!({"valid":true}));
        }
        typed_signing_options_contract(&remote, &mut service, &admin, &input, &retained)?;
        for option in [Value::Null, json!(false), json!(true), json!(17)] {
            let signed = call(
                &mut service,
                "POST",
                "consumer/sign/local",
                &admin,
                json!({"input":input,"signature_algorithm":option}),
            );
            assert_eq!(signed.status, 200);
            let verified = call(
                &mut service,
                "POST",
                "consumer/verify/local",
                &admin,
                json!({"input":input,"signature":signed.body["data"]["signature"],"signature_algorithm":option}),
            );
            assert_eq!(verified.status, 200);
            assert_eq!(verified.body["data"], json!({"valid":true}));
        }
        let jws = call(
            &mut service,
            "POST",
            "consumer/sign/local/none",
            &admin,
            json!({"input":input,"prehashed":"TRUE","marshaling_algorithm":"jws","signature_algorithm":"pkcs1v15","context":BASE64.encode(b"ignored non-derived context")}),
        );
        assert_eq!(jws.status, 200);
        let jws_signature = jws.body["data"]["signature"].clone();
        let verified = call(
            &mut service,
            "POST",
            "consumer/verify/local/none",
            &admin,
            json!({"input":input,"signature":jws_signature,"marshaling_algorithm":"jws"}),
        );
        assert_eq!(verified.status, 200);
        assert_eq!(verified.body["data"], json!({"valid":true}));
        for length in [63, 65] {
            assert_eq!(call(&mut service,"POST","consumer/sign/local",&admin,
                json!({"input":BASE64.encode(vec![0;length]),"hash_algorithm":"mldsa-mu","prehashed":true})).status,500);
        }
        if kind != "ed25519" {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let metadata = call(
                &mut *remote.service.lock().map_err(|_| "remote lock")?,
                "GET",
                "transit/keys/remote",
                &remote.admin,
                json!({}),
            );
            let public = BASE64.decode(
                metadata.body["data"]["keys"]["2"]["public_key"]
                    .as_str()
                    .ok_or("public key")?,
            )?;
            let mut tr_hash = sha3::Shake256::default();
            Update::update(&mut tr_hash, &public);
            let mut tr = [0; 64];
            XofReader::read(&mut tr_hash.finalize_xof(), &mut tr);
            let mut mu_hash = sha3::Shake256::default();
            Update::update(&mut mu_hash, &tr);
            Update::update(&mut mu_hash, &[0, 0]);
            Update::update(&mut mu_hash, message);
            let mut mu = [0; 64];
            XofReader::read(&mut mu_hash.finalize_xof(), &mut mu);
            let before = remote.calls()?;
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "consumer/sign/local",
                    &admin,
                    json!({"input":BASE64.encode(mu),"hash_algorithm":"mldsa-mu","prehashed":true})
                )
                .status,
                500
            );
            assert_eq!(remote.calls()?, before);
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/external-keys/configs/remote/keys/v1",
                    &admin,
                    json!({"verify":false,"name":"remote","version":2,"disable_prehashing":false})
                )
                .status,
                204
            );
            let signed = call(
                &mut service,
                "POST",
                "consumer/sign/local",
                &admin,
                json!({"input":BASE64.encode(mu),"hash_algorithm":"mldsa-mu","prehashed":true}),
            );
            assert_eq!(signed.status, 200);
            let verified = call(
                &mut service,
                "POST",
                "consumer/verify/local",
                &admin,
                json!({"input":input,"signature":signed.body["data"]["signature"]}),
            );
            assert_eq!(verified.status, 200);
            assert_eq!(verified.body["data"], json!({"valid":true}));
            assert_eq!(call(&mut service,"POST","consumer/verify/local",&admin,json!({"input":BASE64.encode(mu),"signature":signed.body["data"]["signature"],"hash_algorithm":"mldsa-mu","prehashed":true})).status,400);
        } else {
            assert_eq!(call(&mut service,"POST","consumer/sign/local",&admin,json!({"input":BASE64.encode([0;64]),"hash_algorithm":"mldsa-mu","prehashed":true})).status,500);
        }
        // Restart verifies the retained raw-mode signature under its original
        // prehash policy, after the separate enabled-prehash mu positive control.
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/external-keys/configs/remote/keys/v1",
                &admin,
                json!({"verify":false,"name":"remote","version":2,"disable_prehashing":true})
            )
            .status,
            204
        );
        drop(service);
        let mut reopened = root.service()?;
        reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
        assert_eq!(
            call(
                &mut reopened,
                "POST",
                "sys/unseal",
                "",
                json!({"key":unseal})
            )
            .status,
            200
        );
        let verified = call(
            &mut reopened,
            "POST",
            "consumer/verify/local",
            &admin,
            json!({"input":input,"signature":retained,"hash_algorithm":"sha2-512"}),
        );
        assert_eq!(verified.status, 200);
        assert_eq!(verified.body["data"], json!({"valid":true}));
        let encoded = serde_json::to_value(&reopened.state.as_ref().ok_or("state")?.engines)?;
        let version = &encoded["namespaces"][""]["mounts"]["consumer/"]["backend"]["Transit"]["keys"]
            ["local"]["versions"]["1"];
        assert_eq!(version["material"], "");
        assert_eq!(version["hmac_material"], "");
        assert!(!fs::read_to_string(root.path.join("audit.jsonl"))?.contains(&input));
    }
    Ok(())
}

#[test]
fn external_transit270_sign_and_verify_delay_share_all_original_authority_fences() -> TestResult {
    let remote = RemoteTransit::new_kind("ed25519")?;
    let input = BASE64.encode(b"actual withheld signing operation");
    let signature = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "POST",
        "transit/sign/remote",
        &remote.admin,
        json!({"input":input,"key_version":1}),
    );
    let signature = signature.body["data"]["signature"]
        .as_str()
        .ok_or("signature")?;
    delayed_result_fences(&remote, "sign", &json!({"input":input}))?;
    delayed_result_fences(
        &remote,
        "verify",
        &json!({"input":input,"signature":signature}),
    )?;
    Ok(())
}

#[test]
fn external_transit270_complete_remote_bad_cipher_and_aad_rejections_are_safe_and_fenced()
-> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let cipher = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":BASE64.encode(b"synthetic rejection input"),"associated_data":BASE64.encode(b"required aad")}),
    );
    let cipher = cipher.body["data"]["ciphertext"].clone();
    for body in [
        json!({"ciphertext":cipher}),
        json!({"ciphertext":cipher,"associated_data":BASE64.encode(b"wrong aad")}),
        json!({"ciphertext":format!("vault:v1:{}",BASE64.encode([0;28]))}),
    ] {
        let response = call(&mut service, "POST", "consumer/decrypt/local", &admin, body);
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body,
            json!({"errors":["external Transit provider rejected request"]})
        );
    }
    let pending = staged_path(
        &mut service,
        &admin,
        "consumer/decrypt/local",
        json!({"ciphertext":cipher}),
    )?;
    let result = pending.execute();
    assert!(matches!(
        &result,
        ExternalEffectResult::ExternalTransit(Ok(_))
    ));
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    let response = service.finish_external_request(pending, result);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    Ok(())
}

struct RemoteTransit {
    _root: Root,
    service: Arc<Mutex<Service>>,
    admin: String,
    address: SocketAddr,
    ca: String,
    stop: Arc<AtomicBool>,
    ack_only: Arc<AtomicBool>,
    ack_at_call: Arc<std::sync::atomic::AtomicUsize>,
    trace: Arc<Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RemoteTransit {
    fn new() -> TestResult<Self> {
        Self::new_kind("aes256-gcm96")
    }
    fn new_kind(kind: &str) -> TestResult<Self> {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, admin) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "transit/keys/remote",
                &admin,
                json!({"type":kind})
            )
            .status,
            200
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "transit/keys/remote/rotate",
                &admin,
                json!({})
            )
            .status,
            200
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "sys/mounts/pki",
                    "",
                    &admin,
                    json!({"type":"pki"}),
                    now
                )
                .status,
            204
        );
        let ca_response = service.handle_at(
            "POST",
            "pki/root/generate/internal",
            "",
            &admin,
            json!({"common_name":"external.test","ttl":"48h"}),
            now,
        );
        assert_eq!(ca_response.status, 200, "fixture CA status");
        let ca = ca_response.body["data"]["certificate"]
            .as_str()
            .ok_or("CA")?
            .to_owned();
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "pki/roles/tls",
                    "",
                    &admin,
                    json!({"allowed_domains":["external.test"],"max_ttl":"24h"}),
                    now
                )
                .status,
            200
        );
        let leaf = service.handle_at(
            "POST",
            "pki/issue/tls",
            "",
            &admin,
            json!({"common_name":"external.test","ttl":"12h"}),
            now,
        );
        assert_eq!(leaf.status, 200, "fixture TLS certificate status");
        let certificates = rustls_pemfile::certs(&mut BufReader::new(
            leaf.body["data"]["certificate"]
                .as_str()
                .ok_or("cert")?
                .as_bytes(),
        ))
        .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(
            leaf.body["data"]["private_key"]
                .as_str()
                .ok_or("key")?
                .as_bytes(),
        ))?
        .ok_or("private key")?;
        let tls = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certificates, key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let service = Arc::new(Mutex::new(service));
        let stop = Arc::new(AtomicBool::new(false));
        let ack_only = Arc::new(AtomicBool::new(false));
        let ack_at_call = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ack_at = Arc::clone(&ack_at_call);
        let trace = Arc::new(Mutex::new(Vec::new()));
        let (remote, stopped, ack, trace_clone) = (
            Arc::clone(&service),
            Arc::clone(&stop),
            Arc::clone(&ack_only),
            Arc::clone(&trace),
        );
        let thread = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok((socket, _)) = listener.accept() else {
                    thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                if socket.set_nonblocking(false).is_err() {
                    continue;
                }
                let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let _ = socket.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                let Ok(connection) = ServerConnection::new(Arc::clone(&tls)) else {
                    continue;
                };
                let mut stream = StreamOwned::new(connection, socket);
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") && head.len() < 48 * 1024 {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    head.push(byte[0]);
                }
                if !head.ends_with(b"\r\n\r\n") {
                    continue;
                }
                let Ok(head) = String::from_utf8(head) else {
                    continue;
                };
                let lines = head.split("\r\n").collect::<Vec<_>>();
                let path = lines
                    .first()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("");
                let method = lines
                    .first()
                    .and_then(|line| line.split_whitespace().next())
                    .unwrap_or("");
                let headers = lines
                    .iter()
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect::<std::collections::BTreeMap<_, _>>();
                let Some(length) = headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|length| *length <= 128 * 1024)
                else {
                    continue;
                };
                let mut bytes = zeroize::Zeroizing::new(vec![0u8; length]);
                if stream.read_exact(&mut bytes).is_err() {
                    continue;
                }
                let parsed = if bytes.is_empty() {
                    Ok(json!({}))
                } else {
                    crate::auth::parse_strict_json(&bytes)
                };
                let Ok(body) = parsed else {
                    continue;
                };
                if let Ok(mut trace) = trace_clone.lock() {
                    trace.push(path.to_owned());
                }
                let call_number = trace_clone.lock().map(|trace| trace.len()).unwrap_or(0);
                let response =
                    if ack.load(Ordering::SeqCst) || ack_at.load(Ordering::SeqCst) == call_number {
                        Response::ok(json!({"verified":true}))
                    } else {
                        let Ok(mut service) = remote.lock() else {
                            continue;
                        };
                        service.handle_at(
                            method,
                            path.strip_prefix("/v1/").unwrap_or(path),
                            headers.get("x-vault-namespace").map_or("", String::as_str),
                            headers.get("x-vault-token").map_or("", String::as_str),
                            body,
                            100,
                        )
                    };
                let Ok(encoded) = serde_json::to_vec(&response.body) else {
                    continue;
                };
                let head = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    encoded.len()
                );
                let _ = stream
                    .write_all(head.as_bytes())
                    .and_then(|()| stream.write_all(&encoded))
                    .and_then(|()| stream.flush());
            }
        });
        Ok(Self {
            _root: root,
            service,
            admin,
            address,
            ca,
            stop,
            ack_only,
            ack_at_call,
            trace,
            thread: Some(thread),
        })
    }
    fn endpoint(&self) -> crate::outbound::EndpointConfig {
        crate::outbound::EndpointConfig {
            origin: self.origin(),
            address: self.address,
            server_name: "external.test".into(),
            ca_pem: self.ca.clone(),
            path_prefix: "/v1/transit/".into(),
            shared_secret: String::new(),
        }
    }
    fn origin(&self) -> String {
        format!("https://external.test:{}", self.address.port())
    }
    fn fixture(&self) -> TestResult<(Root, Service, String, String)> {
        self.fixture_kms(None)
    }
    fn fixture_kms(&self, enabled: Option<bool>) -> TestResult<(Root, Service, String, String)> {
        self.fixture_kms_capabilities(enabled, None)
    }
    fn fixture_kms_capabilities(
        &self,
        enabled: Option<bool>,
        capabilities: Option<Vec<String>>,
    ) -> TestResult<(Root, Service, String, String)> {
        let root = Root::new();
        let mut service = root.service()?;
        service.install_outbound_endpoints(vec![self.endpoint()])?;
        if let Some(enabled) = enabled {
            let mut binding = native_kms_binding(&root, enabled)?;
            if let Some(capabilities) = capabilities {
                binding.capabilities = capabilities;
            }
            service.install_kms_plugins(vec![binding])?;
        }
        let (unseal, admin) = bootstrap(&mut service)?;
        for (path, body, status) in [
            ("sys/mounts/consumer", json!({"type":"transit"}), 204),
            (
                "sys/external-keys/configs/remote",
                json!({"plugin":"transit","verify":false,"address":self.origin(),"token":self.admin,"mount_path":"transit"}),
                204,
            ),
            (
                "sys/external-keys/configs/remote/keys/v1",
                json!({"verify":false,"name":"remote","version":1}),
                204,
            ),
            (
                "sys/external-keys/configs/remote/keys/v1/grants/consumer",
                json!({}),
                204,
            ),
            (
                "consumer/keys/local",
                json!({"type":"external-key","external_key_ref":"remote:v1"}),
                200,
            ),
        ] {
            let response = call(&mut service, "POST", path, &admin, body);
            assert_eq!(response.status, status, "fixture setup: {path}");
        }
        Ok((root, service, unseal, admin))
    }
    fn calls(&self) -> TestResult<usize> {
        Ok(self.trace.lock().map_err(|_| "trace lock")?.len())
    }
}

#[path = "service_external_pki_tests.rs"]
mod external_pki_tests;
impl Drop for RemoteTransit {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn staged(service: &mut Service, token: &str, body: Value) -> TestResult<PendingExternalRequest> {
    staged_path(service, token, "consumer/encrypt/local", body)
}

fn staged_path(
    service: &mut Service,
    token: &str,
    path: &str,
    body: Value,
) -> TestResult<PendingExternalRequest> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => Ok(*pending),
        RequestExecution::Complete(response) => {
            Err(format!("not staged: {} {:?}", response.status, response.body).into())
        }
    }
}

#[test]
fn external_transit270_real_remote_encrypt_decrypt_version_rotation_and_restart() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (root, mut service, unseal, admin) = remote.fixture()?;
    let plaintext = BASE64.encode(b"real remote AES encryption and readback");
    let encrypted = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":plaintext,"associated_data":BASE64.encode(b"aad")}),
    );
    assert_eq!(encrypted.status, 200, "external encryption status");
    let ciphertext = encrypted.body["data"]["ciphertext"]
        .as_str()
        .ok_or("ciphertext")?
        .to_owned();
    assert!(ciphertext.starts_with("vault:v1:"));
    let payload = ciphertext.strip_prefix("vault:v1:").ok_or("prefix")?;
    assert!(BASE64.decode(payload)?.len() >= 28);
    let inner = format!("vault:v1:{payload}");
    let direct = call(
        &mut *remote.service.lock().map_err(|_| "remote lock")?,
        "POST",
        "transit/decrypt/remote",
        &remote.admin,
        json!({"ciphertext":inner,"associated_data":BASE64.encode(b"aad")}),
    );
    assert_eq!(direct.status, 200);
    assert_eq!(direct.body["data"]["plaintext"], plaintext);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/decrypt/local",
            &admin,
            json!({"ciphertext":ciphertext,"associated_data":BASE64.encode(b"aad")})
        )
        .body["data"]["plaintext"],
        plaintext
    );
    for (path, body) in [
        (
            "sys/external-keys/configs/remote/keys/v2",
            json!({"verify":false,"name":"remote","version":2}),
        ),
        (
            "sys/external-keys/configs/remote/keys/v2/grants/consumer",
            json!({}),
        ),
        (
            "consumer/keys/local/rotate",
            json!({"external_key_ref":"remote:v2"}),
        ),
    ] {
        assert!(call(&mut service, "POST", path, &admin, body).status < 300);
    }
    let v2 = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":plaintext}),
    );
    assert_eq!(v2.status, 200);
    assert!(
        v2.body["data"]["ciphertext"]
            .as_str()
            .ok_or("v2")?
            .starts_with("vault:v2:")
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/keys/local/config",
            &admin,
            json!({"min_decryption_version":2})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/decrypt/local",
            &admin,
            json!({"ciphertext":ciphertext})
        )
        .status,
        400
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.install_outbound_endpoints(vec![remote.endpoint()])?;
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "sys/unseal",
            "",
            json!({"key":unseal})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut reopened,
            "POST",
            "consumer/decrypt/local",
            &admin,
            json!({"ciphertext":v2.body["data"]["ciphertext"]})
        )
        .body["data"]["plaintext"],
        plaintext
    );
    let audit = fs::read_to_string(root.path.join("audit.jsonl"))?;
    assert!(!audit.contains(&plaintext));
    assert!(!audit.contains(&remote.admin));
    assert!(remote.calls()? >= 4);
    Ok(())
}

#[test]
fn external_transit270_delayed_results_fence_registry_grant_mount_key_and_policy_changes()
-> TestResult {
    let remote = RemoteTransit::new()?;
    delayed_result_fences(
        &remote,
        "encrypt",
        &json!({"plaintext":BASE64.encode(b"withheld")}),
    )
}

fn delayed_result_fences(remote: &RemoteTransit, operation: &str, body: &Value) -> TestResult {
    for mutation in [
        "grant",
        "mapping",
        "config",
        "mount",
        "key",
        "policy",
        "unrelated",
        "seal",
        "grant-aba",
        "mapping-delete",
        "config-delete",
        "mount-aba",
        "key-aba",
        "key-delete",
    ] {
        let (_root, mut service, _unseal, admin) = remote.fixture()?;
        let pending = staged_path(
            &mut service,
            &admin,
            &format!("consumer/{operation}/local"),
            body.clone(),
        )?;
        let result = pending.execute();
        assert!(
            matches!(&result, ExternalEffectResult::ExternalTransit(Ok(_))),
            "remote crypto execution failed before fence test"
        );
        let response = match mutation {
            "grant" => call(
                &mut service,
                "DELETE",
                "sys/external-keys/configs/remote/keys/v1/grants/consumer",
                &admin,
                json!({}),
            ),
            "mapping" => call(
                &mut service,
                "POST",
                "sys/external-keys/configs/remote/keys/v1",
                &admin,
                json!({"verify":false,"name":"remote","version":2}),
            ),
            "config" => call(
                &mut service,
                "PATCH",
                "sys/external-keys/configs/remote",
                &admin,
                json!({"verify":false,"token":"replacement"}),
            ),
            "mount" => call(
                &mut service,
                "DELETE",
                "sys/mounts/consumer",
                &admin,
                json!({}),
            ),
            "key" => call(
                &mut service,
                "POST",
                "consumer/keys/local/soft-delete",
                &admin,
                json!({}),
            ),
            "policy" => call(
                &mut service,
                "POST",
                "sys/policies/acl/new",
                &admin,
                json!({"policy":"path \"consumer/encrypt/local\" { capabilities = [\"deny\"] }"}),
            ),
            "unrelated" => call(
                &mut service,
                "POST",
                "secret/data/unrelated",
                &admin,
                json!({"data":{"value":"write"}}),
            ),
            "seal" => call(&mut service, "POST", "sys/seal", &admin, json!({})),
            "grant-aba" => {
                assert_eq!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/external-keys/configs/remote/keys/v1/grants/consumer",
                        &admin,
                        json!({})
                    )
                    .status,
                    204
                );
                call(
                    &mut service,
                    "POST",
                    "sys/external-keys/configs/remote/keys/v1/grants/consumer",
                    &admin,
                    json!({}),
                )
            }
            "mapping-delete" => call(
                &mut service,
                "DELETE",
                "sys/external-keys/configs/remote/keys/v1",
                &admin,
                json!({}),
            ),
            "config-delete" => call(
                &mut service,
                "DELETE",
                "sys/external-keys/configs/remote",
                &admin,
                json!({}),
            ),
            "mount-aba" => {
                assert_eq!(
                    call(
                        &mut service,
                        "DELETE",
                        "sys/mounts/consumer",
                        &admin,
                        json!({})
                    )
                    .status,
                    204
                );
                call(
                    &mut service,
                    "POST",
                    "sys/mounts/consumer",
                    &admin,
                    json!({"type":"transit"}),
                )
            }
            "key-aba" => {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "consumer/keys/local/soft-delete",
                        &admin,
                        json!({})
                    )
                    .status,
                    204
                );
                call(
                    &mut service,
                    "POST",
                    "consumer/keys/local/soft-delete-restore",
                    &admin,
                    json!({}),
                )
            }
            "key-delete" => {
                assert_eq!(
                    call(
                        &mut service,
                        "POST",
                        "consumer/keys/local/config",
                        &admin,
                        json!({"deletion_allowed":true})
                    )
                    .status,
                    200
                );
                call(
                    &mut service,
                    "DELETE",
                    "consumer/keys/local",
                    &admin,
                    json!({}),
                )
            }
            _ => return Err("mutation".into()),
        };
        assert!(
            response.status < 300,
            "fixture authority change: {mutation}"
        );
        let response = service.finish_external_request(pending, result);
        assert!(response.status >= 400, "{mutation}");
        assert!(response.body.get("data").is_none(), "{mutation}");
    }
    Ok(())
}

#[test]
fn external_transit270_consumer_acl_namespace_grant_and_egress_are_independent() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let baseline = remote.calls()?;
    let denied = limited_token(
        &mut service,
        &admin,
        "path \"secret/*\" { capabilities = [\"read\"] }",
    )?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &denied,
            json!({"plaintext":BASE64.encode(b"secret")})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &admin,
            json!({"plaintext":BASE64.encode(b"secret")})
        )
        .status,
        400
    );
    assert_eq!(remote.calls()?, baseline);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/external-keys/configs/remote/keys/v1/grants/consumer",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/namespaces/team",
            &admin,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "sys/mounts/consumer",
                "team",
                &admin,
                json!({"type":"transit"}),
                100
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "consumer/keys/local",
                "team",
                &admin,
                json!({"type":"external-key","external_key_ref":"remote:v1"}),
                100
            )
            .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/external-keys/configs/remote",
            &admin,
            json!({"verify":false,"address":"https://unenrolled.test:443"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &admin,
            json!({"plaintext":BASE64.encode(b"secret")})
        )
        .status,
        503
    );
    assert_eq!(remote.calls()?, baseline);
    Ok(())
}

#[test]
fn external_transit270_synthetic_verification_ack_is_never_crypto_success() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    remote.ack_only.store(true, Ordering::SeqCst);
    for (path, body) in [
        (
            "consumer/encrypt/local",
            json!({"plaintext":BASE64.encode(b"secret")}),
        ),
        (
            "consumer/sign/local",
            json!({"input":BASE64.encode(b"sign input")}),
        ),
        (
            "consumer/verify/local",
            json!({"input":"","signature":format!("vault:v1:{}",BASE64.encode([0;64]))}),
        ),
    ] {
        let response = call(&mut service, "POST", path, &admin, body);
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
    }
    assert_eq!(remote.calls()?, 3);
    Ok(())
}

#[test]
fn external_transit270_schema_owner_contains_references_and_no_local_material() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let state = service.state.as_ref().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let encoded = serde_json::to_value(&state.engines)?;
    let version = &encoded["namespaces"][""]["mounts"]["consumer/"]["backend"]["Transit"]["keys"]["local"]
        ["versions"]["1"];
    assert_eq!(version["material"], "");
    assert_eq!(version["hmac_material"], "");
    assert_eq!(version["external_key_ref"], "remote:v1");
    let mut downgraded = state.clone();
    downgraded.schema = 63;
    assert_eq!(
        downgraded
            .validate_format()
            .err()
            .ok_or("schema fence")?
            .status,
        503
    );
    for body in [
        json!({"exportable":true}),
        json!({"auto_rotate_period":"1h"}),
        json!({"allow_plaintext_backup":true}),
    ] {
        assert!(
            call(
                &mut service,
                "POST",
                "consumer/keys/local/config",
                &admin,
                body
            )
            .status
                >= 400
        );
    }
    for (path, body) in [
        ("consumer/export/encryption-key/local", json!({})),
        ("consumer/datakey/plaintext/local", json!({})),
        ("consumer/hmac/local", json!({"input":""})),
    ] {
        assert!(
            call(
                &mut service,
                if path.contains("export") {
                    "GET"
                } else {
                    "POST"
                },
                path,
                &admin,
                body
            )
            .status
                >= 400
        );
    }
    assert_eq!(remote.calls()?, 0);
    Ok(())
}

#[test]
fn external_transit270_last_token_use_is_retained_and_policy_recheck_vetoes() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let policy = "path \"consumer/encrypt/local\" { capabilities = [\"update\"] }";
    let token = limited_token(&mut service, &admin, policy)?;
    let response = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &token,
        json!({"plaintext":BASE64.encode(b"last use")}),
    );
    assert_eq!(response.status, 200, "finite-use external response status");
    let before = remote.calls()?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &token,
            json!({"plaintext":BASE64.encode(b"spent")})
        )
        .status,
        403
    );
    assert_eq!(remote.calls()?, before);
    let token = limited_token(&mut service, &admin, policy)?;
    let pending = staged(
        &mut service,
        &token,
        json!({"plaintext":BASE64.encode(b"veto")}),
    )?;
    let result = pending.execute();
    assert!(matches!(
        &result,
        ExternalEffectResult::ExternalTransit(Ok(_))
    ));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/scoped",
            &admin,
            json!({"policy":"path \"consumer/encrypt/local\" { capabilities = [\"deny\"] }"})
        )
        .status,
        204
    );
    let response = service.finish_external_request(pending, result);
    assert_eq!(response.status, 403);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[test]
fn external_transit270_response_audit_failure_withholds_actual_crypto_result() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let pending = staged(
        &mut service,
        &admin,
        json!({"plaintext":BASE64.encode(b"audit veto")}),
    )?;
    let result = pending.execute();
    assert!(matches!(
        &result,
        ExternalEffectResult::ExternalTransit(Ok(_))
    ));
    service.audit_failed = true;
    let response = service.finish_external_request(pending, result);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(service.recovery_required);
    assert_eq!(remote.calls()?, 1);
    Ok(())
}

#[test]
fn external_transit270_invalid_input_size_tls_override_and_versions_fail_before_io() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    for body in [
        json!({"plaintext":"?"}),
        json!({"plaintext":"","key_version":99}),
        json!({"plaintext":BASE64.encode(vec![0;64*1024+1])}),
        json!({"plaintext":"","associated_data":BASE64.encode(vec![0;4097])}),
        json!({"plaintext":"","batch_input":[{"plaintext":""}]}),
        json!({"plaintext":"","context":"YQ=="}),
    ] {
        assert!(call(&mut service, "POST", "consumer/encrypt/local", &admin, body).status >= 400);
    }
    for ciphertext in [
        "bad",
        "vault:v99:dmF1bHQ6djE6YWJj",
        "vault:v1:dmF1bHQ6djI6YWJj",
    ] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "consumer/decrypt/local",
                &admin,
                json!({"ciphertext":ciphertext})
            )
            .status,
            400
        );
    }
    assert_eq!(
        call(
            &mut service,
            "PATCH",
            "sys/external-keys/configs/remote",
            &admin,
            json!({"verify":false,"tls_skip_verify":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &admin,
            json!({"plaintext":""})
        )
        .status,
        400
    );
    assert_eq!(call(&mut service,"PATCH","sys/external-keys/configs/remote",&admin,json!({"verify":false,"tls_skip_verify":false,"tls_ca_cert_bytes":"registry cannot enlarge trust"})).status,204);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "consumer/encrypt/local",
            &admin,
            json!({"plaintext":""})
        )
        .status,
        501
    );
    assert_eq!(remote.calls()?, 0);
    Ok(())
}

#[test]
fn external_transit270_schema_rejects_hidden_local_material_and_ref_on_local_type() -> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, service, _unseal, _admin) = remote.fixture()?;
    let original = serde_json::to_value(&service.state.as_ref().ok_or("state")?.engines)?;
    for field in [
        "material",
        "hmac_material",
        "external_key_ref",
        "encryptions",
    ] {
        let mut encoded = original.clone();
        let version = &mut encoded["namespaces"][""]["mounts"]["consumer/"]["backend"]["Transit"]["keys"]
            ["local"]["versions"]["1"];
        version[field] = match field {
            "encryptions" => json!(1),
            "external_key_ref" => json!("bad:ref:extra"),
            _ => json!("private key bytes"),
        };
        let engines: EngineState = serde_json::from_value(encoded)?;
        assert!(
            engines.validate_external_transit_state().is_err(),
            "{field}"
        );
    }
    let mut encoded = original;
    encoded["namespaces"][""]["mounts"]["consumer/"]["backend"]["Transit"]["keys"]["local"]["kind"] =
        json!("aes256-gcm96");
    let engines: EngineState = serde_json::from_value(encoded)?;
    assert!(engines.validate_external_transit_state().is_err());
    Ok(())
}

#[test]
fn external_transit270_deadline_and_enrolled_tls_name_are_delivery_and_entry_fences() -> TestResult
{
    let remote = RemoteTransit::new()?;
    let (_root, mut service, _unseal, admin) = remote.fixture()?;
    let scope = crate::request_deadline::RequestDeadlineScope::enter(
        std::time::Instant::now() + std::time::Duration::from_millis(2000),
    );
    let pending = staged(
        &mut service,
        &admin,
        json!({"plaintext":BASE64.encode(b"deadline")}),
    )?;
    let result = pending.execute();
    assert!(matches!(
        &result,
        ExternalEffectResult::ExternalTransit(Ok(_))
    ));
    drop(scope);
    thread::sleep(std::time::Duration::from_millis(2050));
    let response = service.finish_external_request(pending, result);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    let before = remote.calls()?;
    // Only this test seam replaces enrollment while active. Production policy
    // is immutable while unsealed, and a seal/unseal changes activation nonce.
    let mut wrong = remote.endpoint();
    wrong.server_name = "wrong.test".into();
    assert!(crate::outbound::Outbound::new(vec![wrong]).is_err());
    let other = RemoteTransit::new()?;
    let mut wrong = remote.endpoint();
    wrong.ca_pem = other.ca.clone();
    service.outbound = crate::outbound::Outbound::new(vec![wrong])?;
    let response = call(
        &mut service,
        "POST",
        "consumer/encrypt/local",
        &admin,
        json!({"plaintext":""}),
    );
    assert_eq!(response.status, 503);
    assert!(
        response.body["errors"][0]
            .as_str()
            .ok_or("error")?
            .contains("before entry")
    );
    assert_eq!(remote.calls()?, before);
    Ok(())
}

// The native consumer does not invoke this process. The pinned executable and
// sandbox are admitted solely to test the optional deployment KMS authority
// binding; cryptographic results still come from the real remote TLS Service.
fn native_kms_binding(root: &Root, enabled: bool) -> TestResult<PluginKmsConfig> {
    use std::os::unix::fs::PermissionsExt;
    let plugin = root.path.join("native-kms-binding-provider");
    let sandbox = root.path.join("native-kms-binding-sandbox");
    let bytes = b"#!/bin/sh\nexit 0\n";
    for path in [&plugin, &sandbox] {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let checksum = hex(&<sha2::Sha256 as sha2::Digest>::digest(bytes));
    Ok(PluginKmsConfig {
        id: "transit".into(),
        command: plugin.to_string_lossy().into_owned(),
        command_sha256: checksum.clone(),
        sandbox_provider_id: "native_transit_binding".into(),
        sandbox_command: sandbox.to_string_lossy().into_owned(),
        sandbox_command_sha256: checksum,
        sandbox_profile_id: "native_transit_binding".into(),
        key_id: "native_transit_binding".into(),
        key_version: 1,
        capabilities: vec!["wrap".into(), "unwrap".into()],
        enabled,
        maximum_request_bytes: 256 * 1024,
        maximum_response_bytes: 1024 * 1024,
        timeout_ms: 5000,
    })
}

#[cfg(target_os = "linux")]
#[test]
fn external_transit270_optional_kms_disable_and_revocation_cannot_bypass_native_provider_fence()
-> TestResult {
    let remote = RemoteTransit::new()?;
    let (_root, mut disabled, _unseal, admin) = remote.fixture_kms(Some(false))?;
    assert_eq!(
        call(
            &mut disabled,
            "POST",
            "consumer/encrypt/local",
            &admin,
            json!({"plaintext":""})
        )
        .status,
        403
    );
    assert_eq!(remote.calls()?, 0);
    for scenario in ["disable", "revoke", "replace"] {
        let (_root, mut service, _unseal, admin) = remote.fixture_kms(Some(true))?;
        let pending = staged(
            &mut service,
            &admin,
            json!({"plaintext":BASE64.encode(b"provider gate")}),
        )?;
        let result = pending.execute();
        assert!(matches!(
            &result,
            ExternalEffectResult::ExternalTransit(Ok(_))
        ));
        // Runtime changes use the test seam; ordinary deployment installation
        // remains immutable while the server is unsealed.
        match scenario {
            "disable" => {
                service
                    .kms_keys
                    .get_mut("transit")
                    .ok_or("binding")?
                    .enabled = false
            }
            "revoke" => service
                .kms_plugins
                .get("transit")
                .ok_or("host")?
                .lock()
                .map_err(|_| "host lock")?
                .revoke(),
            "replace" => {
                let host = service.kms_plugins.remove("transit").ok_or("host")?;
                service.kms_plugins.insert("replacement".into(), host);
            }
            _ => return Err("scenario".into()),
        }
        let response = service.finish_external_request(pending, result);
        assert_eq!(response.status, 503, "{scenario}");
        assert!(response.body.get("data").is_none());
        let before = remote.calls()?;
        assert!(
            call(
                &mut service,
                "POST",
                "consumer/encrypt/local",
                &admin,
                json!({"plaintext":""})
            )
            .status
                >= 400
        );
        assert_eq!(remote.calls()?, before);
    }
    Ok(())
}
