use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Result<HaProcessConfig, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "node_id": 1, "cluster_id": "upgrade-cluster", "raft_dir": "/private/raft",
        "listen": "127.0.0.1:8201", "ca_file": "/private/ca",
        "cert_file": "/private/cert", "key_file": "/private/key",
        "replication_key_file": "/private/replication",
        "peers": {
            "1": {"node_name":"n1", "address":"127.0.0.1:8201", "server_name":"n1.invalid", "certificate_sha256":"11".repeat(32)},
            "2": {"node_name":"n2", "address":"127.0.0.1:8202", "server_name":"n2.invalid", "certificate_sha256":"22".repeat(32)},
            "3": {"node_name":"n3", "address":"127.0.0.1:8203", "server_name":"n3.invalid", "certificate_sha256":"33".repeat(32)}
        }
    }))
}

#[test]
fn peer_wire_upgrade_sender_policy_preserves_legacy_defaults_and_rejects_unsafe_mode() -> TestResult
{
    let mut config = config()?;
    for accept in [false, true] {
        for emit in [None, Some(false), Some(true)] {
            config.allow_legacy_peer_v1 = accept;
            config.emit_legacy_peer_v1 = emit;
            let expected = emit.unwrap_or(accept);
            assert_eq!(config.outbound_legacy_peer_v1(), expected);
            assert_eq!(validate_config(&config).is_ok(), !expected || accept);
        }
    }
    Ok(())
}

fn frame(source: u64, target: u64, role: u8, legacy: bool) -> RaftWireFrame {
    RaftWireFrame {
        cluster_id: "upgrade-cluster".into(),
        source,
        target,
        role,
        kind: RaftRpcKind::Vote,
        payload: b"bounded-vote".to_vec(),
        legacy_v1: legacy,
    }
}

fn encode(frame: RaftWireFrame) -> Result<Vec<u8>, RemoteRaftError> {
    if frame.legacy_v1 {
        encode_legacy_raft_frame_for_transition(frame)
    } else {
        encode_raft_frame(frame)
    }
}

fn check_topology(accept: [bool; 3], emit: [bool; 3]) -> TestResult {
    for (source, &send_legacy) in emit.iter().enumerate() {
        for (target, &accept_legacy) in accept.iter().enumerate() {
            if source == target {
                continue;
            }
            let request = encode(frame(
                source as u64 + 1,
                target as u64 + 1,
                RAFT_FRAME_REQUEST,
                send_legacy,
            ))?;
            let admitted = decode_raft_frame_for_cluster_compatible(
                &request,
                "upgrade-cluster",
                accept_legacy,
            )?;
            assert_eq!(admitted.legacy_v1, send_legacy);
            // The receiver replies in the admitted request's format, not its
            // own outbound request preference. There is no retry or downgrade.
            let reply = encode(frame(
                target as u64 + 1,
                source as u64 + 1,
                RAFT_FRAME_RESPONSE,
                admitted.legacy_v1,
            ))?;
            let decoded =
                decode_raft_frame_for_cluster_compatible(&reply, "upgrade-cluster", send_legacy)?;
            assert_eq!(decoded.legacy_v1, send_legacy);
            assert_eq!(decoded.source, target as u64 + 1);
            assert_eq!(decoded.target, source as u64 + 1);
            if !send_legacy {
                assert!(
                    decode_raft_frame_for_cluster_compatible(&request, "other-cluster", true)
                        .is_err()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn peer_wire_upgrade_three_phase_pairwise_compatibility_retains_quorum_links() -> TestResult {
    for switched in 0..=3 {
        let emit = std::array::from_fn(|node| node >= switched);
        check_topology([true; 3], emit)?;
    }
    for retired in 0..=3 {
        let accept = std::array::from_fn(|node| node >= retired);
        check_topology(accept, [false; 3])?;
        let legacy = encode(frame(2, 1, RAFT_FRAME_REQUEST, true))?;
        assert_eq!(
            decode_raft_frame_for_cluster_compatible(&legacy, "upgrade-cluster", accept[0]).is_ok(),
            accept[0]
        );
    }
    Ok(())
}

#[test]
fn peer_wire_upgrade_direct_flag_removal_does_not_preserve_legacy_links() {
    assert!(check_topology([false, true, true], [false, true, true]).is_err());
    assert!(check_topology([false, false, true], [false, false, true]).is_err());
}
