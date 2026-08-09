//! Succinct-trie domain matcher, ported from sing's `common/domain`.
//!
//! The trie is held in the shape it has on disk: two bitmaps and a label array.
//! Only rank and select are rebuilt at load time, because the file omits them.

/// Marks a suffix match that ignores label boundaries.
const PREFIX_LABEL: u8 = b'\r';
/// Marks a suffix match anchored at a label boundary.
const ROOT_LABEL: u8 = b'\n';

#[derive(Debug, Clone)]
pub struct DomainMatcher {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// Prefix popcount per word of `label_bitmap`, with a trailing total.
    ranks: Vec<i32>,
    /// Bit index of every 32nd set bit in `label_bitmap`.
    selects: Vec<i32>,
}

/// Bit lookup where a short array means the bit is zero.
///
/// `leaves` is only grown when a bit is set, so trailing non-leaf nodes are
/// legitimately past its end.
#[inline]
fn get_bit_or_false(bm: &[u64], i: i32) -> bool {
    if i < 0 {
        return false;
    }
    bm.get((i >> 6) as usize)
        .is_some_and(|w| w & (1u64 << (i & 63)) != 0)
}

/// Bit lookup where a short array means the file is malformed.
///
/// `label_bitmap` always ends with a set bit, so it is never short.
#[inline]
fn get_bit_checked(bm: &[u64], i: i32) -> Option<bool> {
    if i < 0 {
        return None;
    }
    let w = bm.get((i >> 6) as usize)?;
    Some(w & (1u64 << (i & 63)) != 0)
}

fn build_index(label_bitmap: &[u64]) -> (Vec<i32>, Vec<i32>) {
    let mut ranks = Vec::with_capacity(label_bitmap.len() + 1);
    let mut total = 0i32;
    for word in label_bitmap {
        ranks.push(total);
        total += word.count_ones() as i32;
    }
    ranks.push(total);

    let mut selects = Vec::new();
    let mut ith: i64 = -1;
    for (word_index, word) in label_bitmap.iter().enumerate() {
        let mut w = *word;
        while w != 0 {
            let bit = w.trailing_zeros();
            ith += 1;
            if ith % 32 == 0 {
                selects.push((word_index as i32) * 64 + bit as i32);
            }
            w &= w - 1;
        }
    }
    (selects, ranks)
}

impl DomainMatcher {
    pub fn from_parts(leaves: Vec<u64>, label_bitmap: Vec<u64>, labels: Vec<u8>) -> Self {
        let (selects, ranks) = build_index(&label_bitmap);
        Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
        }
    }

    /// Number of set bits in `label_bitmap` below `i`.
    fn rank(&self, i: i32) -> Option<i32> {
        let word_index = (i >> 6) as usize;
        let base = *self.ranks.get(word_index)?;
        let word = *self.label_bitmap.get(word_index)?;
        let j = (i & 63) as u32;
        // `u64::MAX >> 64` is undefined, so the empty mask is spelled out.
        let mask = if j == 0 { 0 } else { u64::MAX >> (64 - j) };
        Some(base + (word & mask).count_ones() as i32)
    }

    /// Number of unset bits in `label_bitmap` below `i`.
    fn count_zeros(&self, i: i32) -> Option<i32> {
        if i < 0 {
            return None;
        }
        Some(i - self.rank(i)?)
    }

    /// Bit index of the `i`th set bit, zero-based.
    ///
    /// sing implements this with a 2 KB lookup table and nested byte-width
    /// popcounts. Starting from the sampled entry and scanning forward is the
    /// same answer in far less code, and this sits behind the routing LRU.
    fn select_ith_one(&self, i: i32) -> Option<i32> {
        if i < 0 {
            return None;
        }
        let sampled = *self.selects.get((i >> 5) as usize)?;
        let mut word_index = (sampled >> 6) as usize;
        while *self.ranks.get(word_index + 1)? <= i {
            word_index += 1;
        }
        let mut word = *self.label_bitmap.get(word_index)?;
        let skip = i - *self.ranks.get(word_index)?;
        for _ in 0..skip {
            word &= word - 1;
        }
        if word == 0 {
            return None;
        }
        Some((word_index as i32) * 64 + word.trailing_zeros() as i32)
    }

    /// Match a destination hostname against this set.
    ///
    /// The caller is responsible for normalisation; see `normalize_domain`.
    pub fn matches(&self, domain: &str) -> bool {
        // Go reverses runes and re-encodes them; this is the same operation.
        let key: String = domain.chars().rev().collect();
        self.has(key.as_bytes()).unwrap_or(false)
    }

    /// `None` means the structure ran out of bounds, which only a malformed
    /// file can cause. Callers treat it as "no match".
    fn has(&self, key: &[u8]) -> Option<bool> {
        let mut node_id: i32 = 0;
        let mut bm_idx: i32 = 0;

        for &current_char in key {
            loop {
                if get_bit_checked(&self.label_bitmap, bm_idx)? {
                    return Some(false);
                }
                // A negative difference wraps to a huge usize, which `get`
                // rejects; that is the intended bounds behaviour.
                let next_label = *self.labels.get((bm_idx - node_id) as usize)?;
                if next_label == PREFIX_LABEL {
                    return Some(true);
                }
                if next_label == ROOT_LABEL {
                    let next_node_id = self.count_zeros(bm_idx + 1)?;
                    if current_char == b'.' && get_bit_or_false(&self.leaves, next_node_id) {
                        return Some(true);
                    }
                }
                if next_label == current_char {
                    break;
                }
                bm_idx += 1;
            }
            node_id = self.count_zeros(bm_idx + 1)?;
            bm_idx = self.select_ith_one(node_id - 1)? + 1;
        }

        if get_bit_or_false(&self.leaves, node_id) {
            return Some(true);
        }
        loop {
            if get_bit_checked(&self.label_bitmap, bm_idx)? {
                return Some(false);
            }
            let next_label = *self.labels.get((bm_idx - node_id) as usize)?;
            if next_label == PREFIX_LABEL || next_label == ROOT_LABEL {
                return Some(true);
            }
            bm_idx += 1;
        }
    }
}

#[cfg(test)]
impl DomainMatcher {
    /// Build a matcher the way `sing-box rule-set compile` does, for tests.
    ///
    /// Mirrors `domain.NewMatcher` with `generateLegacy = false`, which is what
    /// format versions 2 and above emit.
    pub(crate) fn build(domains: &[&str], domain_suffix: &[&str]) -> Self {
        use std::collections::HashSet;

        let mut keys: Vec<String> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();

        for suffix in domain_suffix {
            if !seen.insert(suffix) {
                continue;
            }
            let marker = if suffix.starts_with('.') {
                PREFIX_LABEL
            } else {
                ROOT_LABEL
            };
            let combined = format!("{}{}", marker as char, suffix);
            keys.push(combined.chars().rev().collect());
        }
        for domain in domains {
            if !seen.insert(domain) {
                continue;
            }
            keys.push(domain.chars().rev().collect());
        }
        keys.sort();
        Self::from_sorted_keys(&keys)
    }

    fn from_sorted_keys(keys: &[String]) -> Self {
        fn set_bit(bm: &mut Vec<u64>, i: usize, value: bool) {
            while i >> 6 >= bm.len() {
                bm.push(0);
            }
            if value {
                bm[i >> 6] |= 1u64 << (i & 63);
            }
        }

        if keys.is_empty() {
            return Self::from_parts(Vec::new(), vec![1], Vec::new());
        }

        let mut leaves: Vec<u64> = Vec::new();
        let mut label_bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut label_index: usize = 0;

        // (start, end, column) over the sorted key list.
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut node = 0usize;
        while node < queue.len() {
            let (mut start, end, column) = queue[node];
            if column == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, node, true);
            }
            let mut i = start;
            while i < end {
                let first = i;
                let label = keys[first].as_bytes()[column];
                while i < end && keys[i].as_bytes()[column] == label {
                    i += 1;
                }
                queue.push((first, i, column + 1));
                labels.push(label);
                set_bit(&mut label_bitmap, label_index, false);
                label_index += 1;
            }
            set_bit(&mut label_bitmap, label_index, true);
            label_index += 1;
            node += 1;
        }

        Self::from_parts(leaves, label_bitmap, labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_index_counts_ranks_and_samples_selects() {
        // bit 0 and bit 3 set in word 0; bit 64 (bit 0 of word 1) set.
        let bitmap = [0b1001u64, 0b1u64];
        let (selects, ranks) = build_index(&bitmap);
        // ranks is a prefix popcount with a trailing total.
        assert_eq!(ranks, vec![0, 2, 3]);
        // Only the 0th set bit is sampled; the 32nd does not exist here.
        assert_eq!(selects, vec![0]);
    }

    #[test]
    fn select_ith_one_finds_each_set_bit() {
        let bitmap = [0b1001u64, 0b1u64];
        let (selects, ranks) = build_index(&bitmap);
        let m = DomainMatcher {
            leaves: Vec::new(),
            label_bitmap: bitmap.to_vec(),
            labels: Vec::new(),
            ranks,
            selects,
        };
        assert_eq!(m.select_ith_one(0), Some(0));
        assert_eq!(m.select_ith_one(1), Some(3));
        assert_eq!(m.select_ith_one(2), Some(64));
        assert_eq!(m.select_ith_one(3), None);
    }

    #[test]
    fn count_zeros_counts_unset_bits_below_the_index() {
        let bitmap = [0b1001u64];
        let (selects, ranks) = build_index(&bitmap);
        let m = DomainMatcher {
            leaves: Vec::new(),
            label_bitmap: bitmap.to_vec(),
            labels: Vec::new(),
            ranks,
            selects,
        };
        // Bits below index 4 are 1,0,0,1 -> two zeros.
        assert_eq!(m.count_zeros(4), Some(2));
        assert_eq!(m.count_zeros(0), Some(0));
    }

    #[test]
    fn exact_domains_match_only_themselves() {
        let m = DomainMatcher::build(&["example.com", "test.org"], &[]);
        assert!(m.matches("example.com"));
        assert!(m.matches("test.org"));
        assert!(!m.matches("example.org"));
        assert!(!m.matches("sub.example.com"));
        assert!(!m.matches("notexample.com"));
    }

    #[test]
    fn bare_suffixes_match_the_domain_and_its_subdomains() {
        let m = DomainMatcher::build(&[], &["example.com"]);
        assert!(m.matches("example.com"));
        assert!(m.matches("sub.example.com"));
        assert!(m.matches("a.b.example.com"));
        assert!(!m.matches("notexample.com"));
        assert!(!m.matches("example.com.evil.net"));
    }

    #[test]
    fn dotted_suffixes_match_subdomains_but_not_the_bare_domain() {
        let m = DomainMatcher::build(&[], &[".example.com"]);
        assert!(m.matches("sub.example.com"));
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn an_empty_matcher_matches_nothing() {
        let m = DomainMatcher::build(&[], &[]);
        assert!(!m.matches("example.com"));
        assert!(!m.matches(""));
    }

    #[test]
    fn a_truncated_trie_does_not_panic() {
        // A label array shorter than the bitmap implies has to walk off the end.
        let m = DomainMatcher::from_parts(vec![0], vec![0], Vec::new());
        assert!(!m.matches("example.com"));
    }
}
