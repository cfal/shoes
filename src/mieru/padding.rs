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

/// Padding for a data or ack segment: random bytes, uniform length.
///
/// Upstream builds these with a zero-valued `asciiPaddingOpts`
/// (`pkg/protocol/underlay_stream.go:672`), which makes
/// `minConsecutiveASCIILen` zero — so the length is uniform over the whole
/// range and the printable-run transform covers an empty span and does
/// nothing. The per-user strategy applies to session segments only. Using it
/// here would give every packet the same shape, which is a signature.
pub fn build_data_padding(max_len: usize) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let len = rand::rng().random_range(0..=max_len);
    let mut padding = vec![0u8; len];
    rand::rng().fill_bytes(&mut padding);
    padding
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

    // Exclusive upper bound, matching upstream's `mrand.Intn(length - min)`
    // (`pkg/protocol/padding.go:152`). The run therefore never starts at the
    // very last position it would fit. That is a bias, and it is upstream's
    // bias: closing it here would make our traffic differ from the Go
    // client's, which is the opposite of the goal.
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

/// Padding sized and shaped so the combined bit distribution approaches the
/// target probability. `pkg/protocol/padding.go:156-205`.
///
/// Two details matter and are easy to get backwards. The fill is the
/// *opposite* of the rarer bit, and individual **bits** are then flipped
/// toward the rarer value — filling with the rarer bit and perturbing whole
/// bytes leaves a near-constant run of 0x00 or 0xFF, which is a signature
/// rather than obfuscation. And `existing` must describe the bytes that will
/// precede this padding; an empty slice makes every count zero and the whole
/// calculation degenerate.
pub fn build_entropy_padding(max_len: usize, existing: &[u8]) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let total_bits = existing.len() * 8;
    let ones: usize = existing.iter().map(|b| b.count_ones() as usize).sum();
    let zeros = total_bits - ones;

    // Upstream starts at bit 0 and switches only when 1 is strictly rarer, so
    // a tie resolves to 0.
    let (rarer_bit_is_one, rarer_count) = if ones < zeros {
        (true, ones)
    } else {
        (false, zeros)
    };

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

    // How many bits of the padding should carry the rarer value for the
    // combined distribution to land on the target.
    let target_rarer = (((existing.len() + len) * 8) as f64 * TARGET_BIT_PROBABILITY) as isize
        - rarer_count as isize;
    let flip = target_rarer.max(0).min((len * 8) as isize) as usize;

    let mut padding = vec![if rarer_bit_is_one { 0x00 } else { 0xff }; len];
    for _ in 0..flip {
        let bit = rand::rng().random_range(0..len * 8);
        let (index, offset) = (bit / 8, bit % 8);
        if rarer_bit_is_one {
            padding[index] |= 1 << offset;
        } else {
            padding[index] &= !(1 << offset);
        }
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
    /// Feed it all-zero data and the padding must carry ones.
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

    /// Upstream fills with the *opposite* of the rarer bit and then flips
    /// individual bits toward it (`pkg/protocol/padding.go:190-205`). Filling
    /// with the rarer bit instead leaves a near-constant run of 0x00 or 0xFF —
    /// a signature rather than obfuscation.
    #[test]
    fn test_entropy_padding_is_not_a_constant_byte_run() {
        // Random existing data, which is what upstream models: the bytes
        // before the padding are ciphertext, so they look random.
        let mut existing = vec![0u8; 64];
        rand::rng().fill_bytes(&mut existing);

        let mut saw_a_mixed_one = false;
        for _ in 0..100 {
            let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
            if padding.len() < 32 {
                continue;
            }
            let first = padding[0];
            if padding.iter().any(|b| *b != first) {
                saw_a_mixed_one = true;
            }
        }
        assert!(
            saw_a_mixed_one,
            "every sample was a single repeated byte, which is the signature \
             the bit-level flip exists to avoid"
        );
    }

    /// With all-zero input the padding must come back overwhelmingly made of
    /// the rarer bit. Two ways of getting this wrong both survive a weaker
    /// assertion: filling with the rarer bit (a constant 0xFF run, which is a
    /// signature) and flipping whole bytes instead of bits.
    ///
    /// The bound is 0.35, not 0.5, because upstream flips "at most flip bits"
    /// by drawing positions at random with repeats
    /// (`pkg/protocol/padding.go:195-205`). At full saturation that lands near
    /// 1 - 1/e = 63%, and at the longest padding the clamped flip count gives
    /// about 48%. Demanding more would be demanding the Go client's output be
    /// something it is not.
    ///
    /// Paddings under 8 bytes are skipped: with 8 draws over 8 bit positions
    /// the share is a coarse statistic whose tail crosses 0.35 about once in
    /// three thousand runs. That is a flaky test, not a defect being caught.
    #[test]
    fn test_entropy_padding_is_mostly_the_rarer_bit() {
        let existing = [0u8; 256];
        let mut evaluated = 0;
        for _ in 0..200 {
            let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
            if padding.len() < 8 {
                continue;
            }
            evaluated += 1;
            let ones: usize = padding.iter().map(|b| b.count_ones() as usize).sum();
            let share = ones as f64 / (padding.len() * 8) as f64;
            assert!(
                share > 0.35,
                "the padding was only {share:.3} ones over {} bytes, so it is \
                 not carrying the bit it exists to supply",
                padding.len()
            );
        }
        assert!(
            evaluated > 100,
            "only {evaluated} samples were long enough to judge, so this test \
             is no longer measuring what it claims"
        );
    }

    /// And the padding must actually move the combined distribution. It cannot
    /// always reach the 0.325 target - the flip count is clamped to the
    /// padding's own size - but it must not leave the input where it was.
    #[test]
    fn test_entropy_padding_improves_a_skewed_distribution() {
        let existing = [0u8; 256];
        let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
        assert!(!padding.is_empty(), "skewed data needs padding");

        let total_bits = (existing.len() + padding.len()) * 8;
        let ones: usize = existing
            .iter()
            .chain(padding.iter())
            .map(|b| b.count_ones() as usize)
            .sum();
        let after = ones.min(total_bits - ones) as f64 / total_bits as f64;

        // Before the padding the rarer bit is absent entirely.
        assert!(
            after > 0.0,
            "the padding did not move the distribution at all"
        );
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
