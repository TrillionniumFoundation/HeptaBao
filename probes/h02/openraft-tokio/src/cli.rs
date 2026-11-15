//! Shared argument parsing for this standalone OpenRaft probe package.

pub fn argument(name: &str, default: &str) -> String {
    let args = std::env::args().collect::<Vec<_>>();
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| default.to_owned())
}

pub fn parse_seed() -> u64 {
    let raw = argument("--seed", "0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(&raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}
