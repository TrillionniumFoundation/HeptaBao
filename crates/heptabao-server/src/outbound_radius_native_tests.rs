#![allow(clippy::unwrap_used)]
use super::*;

fn options() -> RadiusNativeOptions<'static> {
    RadiusNativeOptions {
        secret: "synthetic-durable-secret",
        nas_port: 10,
        nas_identifier: "",
        dial_timeout: 10,
        read_timeout: 10,
    }
}
fn origin(address: SocketAddr) -> String {
    format!("radius://127.0.0.1:{}", address.port())
}
fn outbound(address: SocketAddr, process_secret: &str) -> Outbound {
    Outbound::new(vec![EndpointConfig {
        origin: origin(address),
        address,
        server_name: "127.0.0.1".into(),
        ca_pem: String::new(),
        path_prefix: "/".into(),
        shared_secret: process_secret.into(),
    }])
    .unwrap()
}
fn attrs(packet: &[u8]) -> Vec<(u8, &[u8])> {
    let mut rows = Vec::new();
    let mut offset = 20;
    while offset < packet.len() {
        let length = usize::from(packet[offset + 1]);
        assert!(length >= 2 && offset + length <= packet.len());
        rows.push((packet[offset], &packet[offset + 2..offset + length]));
        offset += length;
    }
    rows
}
fn signed_response(request: &[u8], secret: &[u8], code: u8) -> Vec<u8> {
    let mut response = vec![code, request[1], 0, 38];
    response.extend_from_slice(&request[4..20]);
    response.extend_from_slice(&[80, 18]);
    response.extend_from_slice(&[0; 16]);
    let signature = hmac_md5(secret, &response);
    response[22..].copy_from_slice(&signature);
    let signature = md5_parts(&[&response[..4], &request[4..20], &response[20..], secret]);
    response[4..20].copy_from_slice(&signature);
    response
}
fn verify_request(request: &[u8], secret: &[u8]) {
    assert_eq!(request[0], 1);
    assert_eq!(
        usize::from(u16::from_be_bytes([request[2], request[3]])),
        request.len()
    );
    let rows = attrs(request);
    assert_eq!(rows.iter().filter(|r| r.0 == 80).count(), 1);
    let mut unsigned = request.to_vec();
    unsigned[request.len() - 16..].fill(0);
    assert_eq!(&request[request.len() - 16..], hmac_md5(secret, &unsigned));
    let encrypted = rows.iter().find(|r| r.0 == 2).unwrap().1;
    let mut clear = Zeroizing::new(Vec::with_capacity(encrypted.len()));
    let mut previous = &request[4..20];
    for chunk in encrypted.as_chunks::<16>().0 {
        let mask = Zeroizing::new(md5_parts(&[secret, previous]));
        clear.extend(chunk.iter().zip(mask.iter()).map(|(a, b)| a ^ b));
        previous = chunk;
    }
    assert_eq!(&clear[..9], b"synthetic");
    assert!(clear[9..].iter().all(|b| *b == 0));
}
fn server() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

#[test]
fn native_config_bounds_and_zero_timeouts_are_explicit() {
    let mut config = options();
    assert!(config.validate_configuration().is_ok());
    config.dial_timeout = 0;
    config.read_timeout = 0;
    assert!(config.validate_configuration().is_ok());
    config.dial_timeout = 60;
    config.read_timeout = 60;
    assert!(config.validate_configuration().is_ok());
    config.read_timeout = 61;
    assert!(config.validate_configuration().is_err());
    config.read_timeout = 10;
    config.dial_timeout = 61;
    assert!(config.validate_configuration().is_err());
    for secret in ["", "synthetic\0secret"] {
        let mut c = options();
        c.secret = secret;
        assert!(c.validate_configuration().is_err());
    }
    let max_secret = "s".repeat(256);
    let mut c = options();
    c.secret = &max_secret;
    assert!(c.validate_configuration().is_ok());
    let long_secret = "s".repeat(257);
    c.secret = &long_secret;
    assert!(c.validate_configuration().is_err());
    let max_nas = "n".repeat(253);
    let mut c = options();
    c.nas_identifier = &max_nas;
    assert!(c.validate_configuration().is_ok());
    let long_nas = "n".repeat(254);
    c.nas_identifier = &long_nas;
    assert!(c.validate_configuration().is_err());
}

#[test]
fn nas_attributes_are_included_in_request_signature_and_integer_cast_is_exact() {
    for (value, expected) in [
        (-1, u32::MAX),
        (4_294_967_296, 0),
        (i64::MIN, 0),
        (i64::MAX, u32::MAX),
        (10, 10),
    ] {
        let packet = radius_access_request_with_nas(
            1,
            &[7; 16],
            b"alice",
            b"synthetic",
            b"secret",
            Some((value, "synthetic-nas")),
        )
        .unwrap();
        verify_request(&packet, b"secret");
        let rows = attrs(&packet);
        assert_eq!(
            rows.iter().find(|r| r.0 == 5).unwrap().1,
            expected.to_be_bytes()
        );
        assert_eq!(rows.iter().find(|r| r.0 == 32).unwrap().1, b"synthetic-nas");
        assert_eq!(
            rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![1, 2, 5, 32, 80]
        );
    }
    let packet = radius_access_request_with_nas(
        1,
        &[7; 16],
        b"alice",
        b"synthetic",
        b"secret",
        Some((0, "")),
    )
    .unwrap();
    assert_eq!(
        attrs(&packet).iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![1, 2, 5, 80]
    );
    let legacy = radius_access_request(1, &[7; 16], b"alice", b"synthetic", b"secret").unwrap();
    assert_eq!(
        attrs(&legacy).iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![1, 2, 80]
    );
}

#[test]
fn maximum_native_packet_is_preallocated_and_out_of_bounds_fields_fail() {
    let user = vec![b'u'; 253];
    let password = vec![b'p'; 128];
    let secret = vec![b's'; 256];
    let nas = "n".repeat(253);
    let packet =
        radius_access_request_with_nas(3, &[7; 16], &user, &password, &secret, Some((10, &nas)))
            .unwrap();
    assert_eq!(packet.len(), 20 + 255 + 130 + 6 + 255 + 18);
    assert!(packet.len() <= 4096);
    assert_eq!(packet.capacity(), packet.len());
    let too_long = "n".repeat(254);
    assert!(
        radius_access_request_with_nas(
            3,
            &[7; 16],
            &user,
            &password,
            &secret,
            Some((10, &too_long))
        )
        .is_err()
    );
}

#[test]
fn empty_process_secret_is_enrolled_but_legacy_cannot_send() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let outbound = outbound(address, "");
    assert!(outbound.radius_endpoint(&origin(address)).is_ok());
    assert!(
        outbound
            .radius_authenticate(&origin(address), "alice", "synthetic")
            .is_err()
    );
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn native_uses_durable_secret_without_process_secret_fallback() {
    for process_secret in ["", "different-process-secret"] {
        let socket = server();
        let address = socket.local_addr().unwrap();
        let outbound = outbound(address, process_secret);
        let worker = std::thread::spawn(move || {
            let mut request = [0; 4096];
            let (size, peer) = socket.recv_from(&mut request).unwrap();
            let request = &request[..size];
            verify_request(request, b"synthetic-durable-secret");
            socket
                .send_to(
                    &signed_response(request, b"synthetic-durable-secret", 2),
                    peer,
                )
                .unwrap();
        });
        let mut config = options();
        config.dial_timeout = 0;
        assert!(
            outbound
                .radius_authenticate_native(&origin(address), &config, false, "alice", "synthetic")
                .unwrap()
        );
        worker.join().unwrap();
    }
}

#[test]
fn native_read_zero_and_invalid_configuration_never_send() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let outbound = outbound(address, "");
    let mut config = options();
    config.read_timeout = 0;
    let start = Instant::now();
    assert!(
        outbound
            .radius_authenticate_native(&origin(address), &config, false, "alice", "synthetic")
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    config.read_timeout = 10;
    config.secret = "";
    assert!(
        outbound
            .radius_authenticate_native(&origin(address), &config, false, "alice", "synthetic")
            .is_err()
    );
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn native_deadline_is_configured_and_never_retries_unknown_outcome() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let outbound = outbound(address, "");
    let mut config = options();
    config.read_timeout = 1;
    let start = Instant::now();
    assert!(
        outbound
            .radius_authenticate_native(&origin(address), &config, false, "alice", "synthetic")
            .is_err()
    );
    assert!(start.elapsed() >= Duration::from_millis(900));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(socket.recv_from(&mut [0; 4096]).is_ok());
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn default_ten_second_budget_accepts_a_response_after_legacy_three_seconds() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let outbound = outbound(address, "");
    let worker = std::thread::spawn(move || {
        let mut request = [0; 4096];
        let (size, peer) = socket.recv_from(&mut request).unwrap();
        std::thread::sleep(Duration::from_secs(4));
        socket
            .send_to(
                &signed_response(&request[..size], b"synthetic-durable-secret", 2),
                peer,
            )
            .unwrap();
    });
    assert!(
        outbound
            .radius_authenticate_native(&origin(address), &options(), false, "alice", "synthetic")
            .unwrap()
    );
    worker.join().unwrap();
}

#[test]
fn native_response_validation_remains_strict_and_reject_is_not_transport_success() {
    for mode in [
        "reject",
        "bad-authenticator",
        "bad-message-authenticator",
        "wrong-id",
        "missing-message-authenticator",
        "oversize",
    ] {
        let socket = server();
        let address = socket.local_addr().unwrap();
        let outbound = outbound(address, "");
        let worker = std::thread::spawn(move || {
            let mut request = [0; 4096];
            let (size, peer) = socket.recv_from(&mut request).unwrap();
            let request = &request[..size];
            let mut reply = signed_response(
                request,
                b"synthetic-durable-secret",
                if mode == "reject" { 3 } else { 2 },
            );
            match mode {
                "bad-authenticator" => reply[4] ^= 1,
                "bad-message-authenticator" => {
                    reply[22] ^= 1;
                    let sig = md5_parts(&[
                        &reply[..4],
                        &request[4..20],
                        &reply[20..],
                        b"synthetic-durable-secret",
                    ]);
                    reply[4..20].copy_from_slice(&sig);
                }
                "wrong-id" => reply[1] ^= 1,
                "missing-message-authenticator" => {
                    reply.truncate(20);
                    reply[3] = 20;
                    let sig =
                        md5_parts(&[&reply[..4], &request[4..20], b"synthetic-durable-secret"]);
                    reply[4..20].copy_from_slice(&sig);
                }
                "oversize" => reply.resize(4097, 0),
                _ => {}
            }
            socket.send_to(&reply, peer).unwrap();
        });
        let result = outbound.radius_authenticate_native(
            &origin(address),
            &options(),
            false,
            "alice",
            "synthetic",
        );
        if mode == "reject" {
            assert!(!result.unwrap());
        } else {
            assert!(result.is_err(), "{mode}");
        }
        worker.join().unwrap();
    }
}

#[test]
fn native_cannot_discover_or_redirect_to_an_unenrolled_origin() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    let outbound = outbound(address, "");
    assert!(
        outbound
            .radius_authenticate_native(
                "radius://unregistered.example:1812",
                &options(),
                false,
                "alice",
                "synthetic"
            )
            .is_err()
    );
    assert!(
        outbound
            .radius_authenticate_native(
                &format!("{}/other", origin(address)),
                &options(),
                false,
                "alice",
                "synthetic"
            )
            .is_err()
    );
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn api_host_and_target_validation_are_pure_and_support_ip_families() {
    for host in [
        "radius.example",
        "RADIUS.EXAMPLE.",
        "localhost",
        "127.0.0.1",
        "::1",
        "2001:db8::1",
    ] {
        assert!(validate_radius_native_host(host).is_ok(), "{host}");
    }
    for host in [
        "",
        "radius://host",
        "host:1812",
        "[::1]",
        "user@host",
        "host/path",
        "host%2f",
        "host?x",
        "host#x",
        "host name",
        "host\n",
        "a..b",
        "-host",
        "host-",
        "host_name",
        "fe80::1%lo0",
        "例子.test",
    ] {
        assert!(validate_radius_native_host(host).is_err(), "{host:?}");
    }
    for (url, host, port) in [
        ("radius://127.0.0.1:1812", "127.0.0.1", 1812),
        ("RADIUS://RADIUS.EXAMPLE.:1/", "radius.example.", 1),
        ("radius://[::1]:1812", "::1", 1812),
        ("radius://[2001:db8::1]:65535/", "2001:db8::1", 65535),
    ] {
        let target = validate_radius_target(url).unwrap();
        assert_eq!(target.host, host);
        assert_eq!(target.port, port);
    }
    for url in [
        "",
        "radius://host",
        "radius://host:0",
        "radius://host:-1",
        "radius://host:65536",
        "radius://host:+1",
        "radius://host:1/path",
        "radius://host:1//",
        "radius://host:1?x",
        "radius://a@host:1",
        "radius://[::1]",
        "radius://[::1]junk:1",
        "radius://[127.0.0.1]:1",
        "radius://::1:1812",
        "ldaps://host:1812",
    ] {
        assert!(validate_radius_target(url).is_err(), "{url:?}");
    }
}

fn assert_api_accepts(socket: UdpSocket, url: String) {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let worker = std::thread::spawn(move || {
        let mut request = [0; 4096];
        let (size, peer) = socket.recv_from(&mut request).unwrap();
        verify_request(&request[..size], b"synthetic-durable-secret");
        socket
            .send_to(
                &signed_response(&request[..size], b"synthetic-durable-secret", 2),
                peer,
            )
            .unwrap();
    });
    assert!(
        Outbound::default()
            .radius_authenticate_native(&url, &options(), true, "alice", "synthetic")
            .unwrap()
    );
    worker.join().unwrap();
}

#[test]
fn api_ipv4_uses_durable_secret_without_process_enrollment() {
    let socket = server();
    let address = socket.local_addr().unwrap();
    assert_eq!(
        Outbound::default().radius_authenticate_native(
            &origin(address),
            &options(),
            false,
            "alice",
            "synthetic"
        ),
        Err("RADIUS endpoint is not host-enrolled")
    );
    assert_api_accepts(socket, origin(address));
}

#[test]
fn api_ipv6_uses_durable_secret_without_process_enrollment() {
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    assert_api_accepts(socket, format!("radius://[::1]:{port}"));
}

#[test]
fn api_dns_selects_one_owned_peer_without_process_enrollment_or_tls_roots() {
    // UDP cannot try another family after a PAP timeout. Listen on the first
    // family returned by this platform's real localhost resolution.
    let resolved = super::super::ldap_transport::resolve_addresses(
        "localhost",
        1812,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let socket = UdpSocket::bind(SocketAddr::new(resolved[0].ip(), 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    assert_api_accepts(socket, format!("radius://localhost:{port}"));
}

#[test]
fn api_read_zero_does_not_parse_target_or_send_packets() {
    let mut config = options();
    config.read_timeout = 0;
    // The deadline check precedes target parsing and thus all DNS/socket work.
    assert_eq!(
        Outbound::default().radius_authenticate_native(
            "not-a-target",
            &config,
            true,
            "alice",
            "synthetic"
        ),
        Err("RADIUS operation deadline exceeded")
    );
    let socket = server();
    let address = socket.local_addr().unwrap();
    assert!(
        Outbound::default()
            .radius_authenticate_native(&origin(address), &config, true, "alice", "synthetic")
            .is_err()
    );
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn post_send_timeout_never_selects_a_second_resolved_address() {
    let first = server();
    let second = server();
    let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(
        authenticate_resolved(
            &addresses,
            &options(),
            "alice",
            "synthetic",
            deadline,
            deadline
        )
        .is_err()
    );
    let mut packet = [0; 4096];
    let (size, _) = first.recv_from(&mut packet).unwrap();
    verify_request(&packet[..size], b"synthetic-durable-secret");
    for socket in [first, second] {
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        assert!(socket.recv_from(&mut packet).is_err());
    }
}

#[test]
fn expired_dial_budget_is_not_replaced_with_remaining_read_budget() {
    let socket = server();
    let addresses = [socket.local_addr().unwrap()];
    let deadline = Instant::now() + Duration::from_secs(1);
    let dial_deadline = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        authenticate_resolved(
            &addresses,
            &options(),
            "alice",
            "synthetic",
            deadline,
            dial_deadline
        ),
        Err("RADIUS operation deadline exceeded")
    );
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    assert!(socket.recv_from(&mut [0; 4096]).is_err());
}

#[test]
fn api_reject_and_invalid_message_authenticator_keep_strict_response_contract() {
    for reject in [true, false] {
        let socket = server();
        let address = socket.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut request = [0; 4096];
            let (size, peer) = socket.recv_from(&mut request).unwrap();
            let request = &request[..size];
            let mut reply = signed_response(
                request,
                b"synthetic-durable-secret",
                if reject { 3 } else { 2 },
            );
            if !reject {
                reply[22] ^= 1;
                let signature = md5_parts(&[
                    &reply[..4],
                    &request[4..20],
                    &reply[20..],
                    b"synthetic-durable-secret",
                ]);
                reply[4..20].copy_from_slice(&signature);
            }
            socket.send_to(&reply, peer).unwrap();
        });
        let result = Outbound::default().radius_authenticate_native(
            &origin(address),
            &options(),
            true,
            "alice",
            "synthetic",
        );
        if reject {
            assert_eq!(result, Ok(false));
        } else {
            assert!(result.is_err());
        }
        worker.join().unwrap();
    }
}
