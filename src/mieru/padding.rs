//! Segment padding. `pkg/protocol/padding.go`.
//!
//! Two strategies, chosen once per connection from the username. Upstream
//! seeds that choice with its own application version string and derives the
//! ASCII run length from the hostname, so byte-for-byte parity with "the" Go
//! client is not a thing that exists. This reproduces both distributions and
//! seeds independently; see the spec's "Traffic-pattern parity".

use aws_lc_rs::digest;
use rand::{Rng, RngExt};

/// Target probability for the rarer bit. `pkg/protocol/padding.go:31`.
const TARGET_BIT_PROBABILITY: f64 = 0.325;

/// The ASCII run length is drawn from `24 + [0, 17)`.
/// `pkg/protocol/padding.go:30`.
const ASCII_RUN_BASE: usize = 24;
const ASCII_RUN_SPREAD: usize = 17;

/// The printable range upstream forces a run into. `pkg/common/ascii.go`.
const PRINTABLE_FIRST: u8 = 0x20;
const PRINTABLE_LAST: u8 = 0x7e;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    Ascii,
    Entropy,
}

impl PaddingStrategy {
    /// Choose the strategy for a user. Stable for a given username, so a
    /// deployment's traffic keeps one shape rather than alternating.
    pub fn for_user(username: &[u8]) -> Self {
        let digest = digest::digest(&digest::SHA256, username);
        if digest.as_ref()[0] & 1 == 0 {
            PaddingStrategy::Ascii
        } else {
            PaddingStrategy::Entropy
        }
    }

    /// Build padding of at most `max_len` bytes for this strategy.
    ///
    /// `existing` is the segment content the entropy strategy balances
    /// against; the ASCII strategy ignores it.
    pub fn build(&self, max_len: usize, existing: &[u8]) -> Vec<u8> {
        match self {
            PaddingStrategy::Ascii => build_ascii_padding(max_len),
            PaddingStrategy::Entropy => build_entropy_padding(max_len, existing),
        }
    }
}

/// Random bytes with one run forced into printable ASCII, so a segment carries
/// a plausible run of text. `pkg/protocol/padding.go:138-155`.
pub fn build_ascii_padding(max_len: usize) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let run_len = (ASCII_RUN_BASE + rand::rng().random_range(0..ASCII_RUN_SPREAD)).min(max_len);
    let len = rand::rng().random_range(run_len..=max_len);

    let mut padding = vec![0u8; len];
    rand::rng().fill_bytes(&mut padding);

    let begin = if len > run_len {
        rand::rng().random_range(0..len - run_len)
    } else {
        0
    };
    let span = PRINTABLE_LAST - PRINTABLE_FIRST + 1;
    for byte in &mut padding[begin..begin + run_len] {
        *byte = PRINTABLE_FIRST + (*byte % span);
    }
    padding
}

/// Padding sized so the rarer bit reaches the target probability across the
/// segment. `pkg/protocol/padding.go:156-190`.
pub fn build_entropy_padding(max_len: usize, existing: &[u8]) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let total_bits = existing.len() * 8;
    let ones: usize = existing.iter().map(|b| b.count_ones() as usize).sum();
    let zeros = total_bits - ones;
    let rarer_count = ones.min(zeros);
    let rarer_bit_is_one = ones <= zeros;

    // Solve rarer = target * (existing + padding) for padding, in bits.
    let needed_bits = (rarer_count as f64 / TARGET_BIT_PROBABILITY) - total_bits as f64;
    let needed_bytes = if needed_bits <= 0.0 {
        0
    } else {
        (needed_bits.ceil() as usize).div_ceil(8)
    };

    let len = if needed_bytes >= max_len {
        max_len
    } else {
        rand::rng().random_range(needed_bytes..=max_len)
    };
    if len == 0 {
        return Vec::new();
    }

    // Fill with the rarer bit so the padding moves the distribution the way
    // the calculation assumed.
    let mut padding = vec![if rarer_bit_is_one { 0xff } else { 0x00 }; len];
    // Perturb a fraction of the bytes so the padding is not a constant run.
    let perturb = len / 4;
    for _ in 0..perturb {
        let at = rand::rng().random_range(0..len);
        padding[at] = rand::rng().random();
    }
    padding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mieru::MAX_PADDING_LEN;

    #[test]
    fn test_strategy_is_stable_for_a_username() {
        let first = PaddingStrategy::for_user(b"alice");
        for _ in 0..10 {
            assert_eq!(PaddingStrategy::for_user(b"alice"), first);
        }
    }

    /// Both strategies must be reachable, or half the parity work is dead.
    #[test]
    fn test_both_strategies_occur_across_usernames() {
        let mut seen_ascii = false;
        let mut seen_entropy = false;
        for i in 0..200u32 {
            match PaddingStrategy::for_user(format!("user{i}").as_bytes()) {
                PaddingStrategy::Ascii => seen_ascii = true,
                PaddingStrategy::Entropy => seen_entropy = true,
            }
        }
        assert!(seen_ascii && seen_entropy);
    }

    #[test]
    fn test_ascii_padding_stays_within_bounds() {
        for _ in 0..100 {
            let padding = build_ascii_padding(MAX_PADDING_LEN);
            assert!(padding.len() <= MAX_PADDING_LEN);
            assert!(padding.len() >= ASCII_RUN_BASE);
        }
    }

    #[test]
    fn test_ascii_padding_contains_a_printable_run() {
        for _ in 0..100 {
            let padding = build_ascii_padding(MAX_PADDING_LEN);
            let longest = longest_printable_run(&padding);
            assert!(
                longest >= ASCII_RUN_BASE,
                "longest printable run was {longest}, want at least {ASCII_RUN_BASE}"
            );
        }
    }

    #[test]
    fn test_ascii_padding_handles_a_tiny_budget() {
        // maxLen below the run length must not panic; the run is clamped.
        let padding = build_ascii_padding(4);
        assert!(padding.len() <= 4);
    }

    #[test]
    fn test_entropy_padding_stays_within_bounds() {
        let existing = [0u8; 100];
        for _ in 0..100 {
            let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
            assert!(padding.len() <= MAX_PADDING_LEN);
        }
    }

    /// Entropy padding exists to pull the bit distribution toward the target.
    /// Feed it all-zero data and the padding must contain ones.
    #[test]
    fn test_entropy_padding_balances_a_skewed_input() {
        let existing = [0u8; 200];
        let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
        assert!(
            !padding.is_empty(),
            "all-zero data needs padding to balance"
        );
        let ones: u32 = padding.iter().map(|b| b.count_ones()).sum();
        assert!(ones > 0, "the padding must carry the rarer bit");
    }

    #[test]
    fn test_zero_budget_yields_no_padding() {
        assert!(build_ascii_padding(0).is_empty());
        assert!(build_entropy_padding(0, &[0u8; 10]).is_empty());
    }

    fn longest_printable_run(data: &[u8]) -> usize {
        let mut longest = 0;
        let mut current = 0;
        for byte in data {
            if (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(byte) {
                current += 1;
                longest = longest.max(current);
            } else {
                current = 0;
            }
        }
        longest
    }
}
