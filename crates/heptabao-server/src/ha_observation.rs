//! Bounded, payload-free diagnostics. These observations never grant authority.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(crate) enum Stage {
    ReadIndex,
    StateRead,
}

struct RateLimit(AtomicU64);
impl RateLimit {
    const fn new() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }
    fn admit(&self, bucket: u64) -> bool {
        let previous = self.0.load(Ordering::Relaxed);
        (previous == u64::MAX || bucket > previous)
            && self
                .0
                .compare_exchange(previous, bucket, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }
}

fn category(error: &str) -> &'static str {
    // Never print the underlying error, including unknown future variants.
    let text = error
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    if text.contains("deadline") || text.contains("timed out") {
        "deadline"
    } else if text.contains("quorum") {
        "quorum"
    } else if text.contains("forwardtoleader")
        || text.contains("forward to leader")
        || text.contains("forward request to")
        || text.contains("not leader")
    {
        "leadership"
    } else if text.starts_with("remote raft consensus failed:") {
        "consensus_other"
    } else if text.starts_with("remote raft transport failed:") {
        "peer_transport"
    } else if text.starts_with("remote raft durable store failed:") {
        "durable_store"
    } else {
        "state_or_other"
    }
}

pub(crate) fn report(stage: Stage, error: &str, elapsed: Duration) {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    static LIMIT: RateLimit = RateLimit::new();
    if !LIMIT.admit(ORIGIN.get_or_init(Instant::now).elapsed().as_secs()) {
        return;
    }
    let stage = match stage {
        Stage::ReadIndex => "read_index",
        Stage::StateRead => "state_read",
    };
    let category = category(error);
    let elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX));
    eprintln!("heptabao-ha-observation: stage={stage} category={category} elapsed_ms={elapsed_ms}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ha_observation_diagnostics_never_echo_untrusted_error_details() {
        for (error, expected) in [
            (
                "remote Raft consensus failed: linearizable read deadline exceeded",
                "deadline",
            ),
            (
                "remote Raft consensus failed: not enough for a quorum: [1,2]",
                "quorum",
            ),
            (
                "remote Raft consensus failed: ForwardToLeader(synthetic-secret)",
                "leadership",
            ),
            (
                "remote Raft transport failed: synthetic-secret",
                "peer_transport",
            ),
            (
                "remote Raft durable store failed: /private/synthetic-secret",
                "durable_store",
            ),
            (
                "remote Raft consensus failed: new-variant synthetic-secret",
                "consensus_other",
            ),
            ("synthetic-secret\nforged-log-line", "state_or_other"),
        ] {
            assert_eq!(category(error), expected);
            assert!(!category(error).contains("synthetic-secret"));
        }
    }
    #[test]
    fn ha_observation_rate_is_bounded_and_does_not_reset_on_clock_regression() {
        let rate = RateLimit::new();
        assert!(rate.admit(0));
        assert!(!rate.admit(0));
        assert!(rate.admit(1));
        assert!(!rate.admit(1));
        assert!(!rate.admit(0));
        assert!(rate.admit(2));
    }
}
