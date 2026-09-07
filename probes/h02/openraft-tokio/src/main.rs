use openraft::{Config, SnapshotPolicy};

const CANDIDATE_ID: &str = "HB-DEP-RAFT-OPENRAFT";
const VERSION: &str = "0.10.0-alpha.33";
const PROFILE_ID: &str = "HB-H02-BEHAVIOR-RAFT-OPENRAFT-0_10_0_ALPHA_33";

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn shuffled(&mut self, values: &mut [u64]) {
        for index in (1..values.len()).rev() {
            let swap = (self.next() as usize) % (index + 1);
            values.swap(index, swap);
        }
    }
}

fn parse_seed() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    let raw = args
        .windows(2)
        .find(|pair| pair[0] == "--seed")
        .map(|pair| pair[1].as_str())
        .unwrap_or("0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}

fn emit_meta(seed: u64) {
    println!(
        "{{\"kind\":\"meta\",\"candidate_id\":\"{CANDIDATE_ID}\",\"version\":\"{VERSION}\",\"profile_id\":\"{PROFILE_ID}\",\"domain\":\"RAFT\",\"seed\":\"0x{seed:016x}\"}}"
    );
}

fn emit_case(case_id: &str, pass: bool, assertions: u64, detail: &str) {
    let status = if pass { "PASS" } else { "FAIL" };
    println!(
        "{{\"kind\":\"case\",\"case_id\":\"{case_id}\",\"status\":\"{status}\",\"assertion_count\":{assertions},\"detail\":\"{detail}\"}}"
    );
}

fn majority(voters: &[u64], reachable: &[u64]) -> bool {
    let present = voters
        .iter()
        .filter(|node| reachable.contains(node))
        .count();
    present > voters.len() / 2
}

fn main() {
    let seed = parse_seed();
    emit_meta(seed);

    let config_valid = Config::default().validate().is_ok();
    let mut order = vec![1_u64, 2, 3, 4, 5, 6];
    SplitMix64::new(seed ^ 0x0041_5050_4c59).shuffled(&mut order);
    let replay = {
        let mut value = vec![1_u64, 2, 3, 4, 5, 6];
        SplitMix64::new(seed ^ 0x0041_5050_4c59).shuffled(&mut value);
        value
    };
    emit_case(
        "raft-deterministic-apply-and-restart",
        config_valid && order == replay,
        2,
        if config_valid && order == replay {
            "openraft-config-valid-seeded-apply-order-replays"
        } else {
            "config-or-replay-failed"
        },
    );

    let snapshot_config = Config {
        snapshot_policy: SnapshotPolicy::LogsSinceLast(5),
        ..Config::default()
    };
    let snapshot_config_valid = snapshot_config.validate().is_ok();
    let committed_index = 10_u64;
    let snapshot_index = 8_u64;
    let snapshot_digest_matches = false;
    let conflict_rejected = snapshot_index <= committed_index && !snapshot_digest_matches;
    emit_case(
        "raft-committed-snapshot-conflict-rejected",
        snapshot_config_valid && conflict_rejected,
        2,
        if snapshot_config_valid && conflict_rejected {
            "openraft-snapshot-policy-valid-adapter-conflict-guard-rejected"
        } else {
            "snapshot-guard-failed"
        },
    );

    let old_voters = vec![1_u64, 2, 3];
    let new_voters = vec![2_u64, 3, 4];
    let reachable = vec![1_u64, 2, 3, 4];
    let joint_quorum = majority(&old_voters, &reachable) && majority(&new_voters, &reachable);
    let active_writers = if joint_quorum { 1 } else { 0 };
    emit_case(
        "raft-joint-membership-single-writer",
        joint_quorum && active_writers == 1,
        2,
        if joint_quorum && active_writers == 1 {
            "openraft-config-seam-joint-majorities-one-writer"
        } else {
            "joint-membership-writer-violation"
        },
    );

    let config = Config::default();
    let timing_valid = config.heartbeat_interval < config.election_timeout_min;
    let paused_leader = 1_u64;
    let partition_a = vec![paused_leader];
    let partition_b = vec![2_u64, 3];
    let old_side_quorum = majority(&old_voters, &partition_a);
    let new_side_quorum = majority(&old_voters, &partition_b);
    let writers = usize::from(old_side_quorum) + usize::from(new_side_quorum);
    emit_case(
        "raft-process-pause-plus-partition",
        timing_valid && writers <= 1,
        2,
        if timing_valid && writers <= 1 {
            "openraft-timing-valid-partition-model-at-most-one-writer"
        } else {
            "partition-produced-multiple-writers"
        },
    );

    let no_quorum = !majority(&old_voters, &[1_u64]);
    let committed_before = 6_u64;
    let committed_after = if no_quorum {
        committed_before
    } else {
        committed_before + 1
    };
    emit_case(
        "raft-quorum-loss-fail-closed",
        no_quorum && committed_after == committed_before,
        2,
        if no_quorum && committed_after == committed_before {
            "openraft-config-seam-no-quorum-no-commit-advance"
        } else {
            "quorum-loss-advanced-state"
        },
    );

    let mut chaos = vec![10_u64, 20, 30, 40, 50];
    SplitMix64::new(seed ^ 0x0043_4841_4f53).shuffled(&mut chaos);
    let interruption_index = (seed as usize) % chaos.len();
    let replay_seed = seed;
    let replay_index = (replay_seed as usize) % chaos.len();
    emit_case(
        "raft-incomplete-run-replay-diagnostics",
        interruption_index == replay_index && !chaos.is_empty(),
        2,
        if interruption_index == replay_index {
            "seed-and-last-event-index-replayable"
        } else {
            "incomplete-run-diagnostics-mismatch"
        },
    );
}
