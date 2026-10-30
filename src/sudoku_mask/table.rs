use std::sync::OnceLock;

use aws_lc_rs::digest::{SHA256, digest};
use zeroize::Zeroize;

use super::go_rng::GoRng;

pub(super) struct Core {
    pub tuples: Vec<[u8; 4]>,
    pub offsets: [u32; 289],
    candidates: [[u64; 5]; 65],
}

pub(super) fn core() -> &'static Core {
    static CORE: OnceLock<Core> = OnceLock::new();
    CORE.get_or_init(Core::new)
}

impl Core {
    fn new() -> Self {
        let grids = grids();
        assert_eq!(grids.len(), 288);
        let mut result = Self {
            tuples: Vec::with_capacity(25_728),
            offsets: [0; 289],
            candidates: [[0; 5]; 65],
        };
        for (id, grid) in grids.iter().enumerate() {
            for (position, value) in grid.iter().enumerate() {
                result.candidates[(*value as usize * 16) + position][id / 64] |= 1 << (id % 64);
            }
        }
        for (id, grid) in grids.iter().enumerate() {
            result.offsets[id] = result.tuples.len() as u32;
            for a in 0..13 {
                for b in a + 1..14 {
                    for c in b + 1..15 {
                        for d in c + 1..16 {
                            let tuple = [a, b, c, d].map(|p| (grid[p] << 4) | p as u8);
                            if result.identify(tuple).is_some() {
                                result.tuples.push(tuple);
                            }
                        }
                    }
                }
            }
        }
        result.offsets[288] = result.tuples.len() as u32;
        assert_eq!(result.tuples.len(), 25_728);
        result
    }

    pub fn identify(&self, hints: [u8; 4]) -> Option<usize> {
        let [a, b, c, d] = hints.map(|h| &self.candidates[h as usize]);
        let mut found = None;
        for word in 0..5 {
            let bits = a[word] & b[word] & c[word] & d[word];
            if bits != 0 {
                if found.is_some() || bits & (bits - 1) != 0 {
                    return None;
                }
                found = Some(word * 64 + bits.trailing_zeros() as usize);
            }
        }
        found
    }
}

fn grids() -> Vec<[u8; 16]> {
    fn fill(
        position: usize,
        grid: &mut [u8; 16],
        rows: [u8; 4],
        cols: [u8; 4],
        boxes: [u8; 4],
        result: &mut Vec<[u8; 16]>,
    ) {
        if position == 16 {
            result.push(*grid);
            return;
        }
        let row = position / 4;
        let col = position % 4;
        let quadrant = row / 2 * 2 + col / 2;
        for value in 0..4 {
            let bit = 1 << value;
            if (rows[row] | cols[col] | boxes[quadrant]) & bit != 0 {
                continue;
            }
            grid[position] = value;
            let (mut rows, mut cols, mut boxes) = (rows, cols, boxes);
            rows[row] |= bit;
            cols[col] |= bit;
            boxes[quadrant] |= bit;
            fill(position + 1, grid, rows, cols, boxes, result);
        }
    }
    let mut result = Vec::with_capacity(288);
    fill(0, &mut [0; 16], [0; 4], [0; 4], [0; 4], &mut result);
    result
}

pub(super) struct Mapping {
    pub forward: [u16; 256],
    pub inverse: [u16; 288],
}

impl Mapping {
    pub fn new(password: &str) -> Self {
        // Build shared tables during config preparation, not on the first connection.
        core();
        let hash = digest(&SHA256, password.as_bytes());
        let seed = i64::from_be_bytes(hash.as_ref()[..8].try_into().unwrap());
        let mut order = std::array::from_fn::<_, 288, _>(|i| i as u16);
        GoRng::new(seed).shuffle(&mut order);
        let forward: [u16; 256] = order[..256].try_into().unwrap();
        let mut inverse = [256; 288];
        for (byte, grid) in forward.iter().enumerate() {
            inverse[*grid as usize] = byte as u16;
        }
        Self { forward, inverse }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        self.forward.zeroize();
        self.inverse.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn canonical_core_matches_independent_tuple_frequency_reference() {
        let grids = grids();
        let core = core();
        let mut reference = HashMap::<[u8; 4], Option<usize>>::new();
        for (id, grid) in grids.iter().enumerate() {
            for a in 0..13 {
                for b in a + 1..14 {
                    for c in b + 1..15 {
                        for d in c + 1..16 {
                            let hints = [a, b, c, d].map(|p| grid[p] * 16 + p as u8);
                            reference
                                .entry(hints)
                                .and_modify(|v| *v = None)
                                .or_insert(Some(id));
                        }
                    }
                }
            }
        }
        assert_eq!(reference.values().filter(|v| v.is_some()).count(), 25_728);
        let lengths: Vec<_> = core.offsets.windows(2).map(|r| r[1] - r[0]).collect();
        assert_eq!(lengths.iter().filter(|n| **n == 12).count(), 96);
        assert_eq!(lengths.iter().filter(|n| **n == 128).count(), 192);
        for a in 0..13 {
            for b in a + 1..14 {
                for c in b + 1..15 {
                    for d in c + 1..16 {
                        for values in 0..256u16 {
                            let hints = [a, b, c, d].map(|p| p as u8);
                            let hints = std::array::from_fn(|i| {
                                hints[i] | (((values >> (i * 2)) as u8 & 3) << 4)
                            });
                            assert_eq!(
                                core.identify(hints),
                                reference.get(&hints).copied().flatten()
                            );
                        }
                    }
                }
            }
        }
        for tuple in &core.tuples {
            assert!(core.identify(*tuple).is_some());
            assert_eq!(
                core.identify([tuple[0], tuple[0], tuple[1], tuple[2]]),
                None
            );
            assert_eq!(core.identify([64, tuple[1], tuple[2], tuple[3]]), None);
        }
        assert_eq!(core.identify([0, 16, 1, 2]), None);
    }

    #[test]
    fn password_maps_retain_all_bytes_and_reject_unmapped_grids() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/sudoku/go_rng.json")).unwrap();
        for (index, password) in ["", "example", "not-for-logs", " test password "]
            .into_iter()
            .enumerate()
        {
            let order: Vec<u16> =
                serde_json::from_value(vectors[index + 6]["order"].clone()).unwrap();
            let mapping = Mapping::new(password);
            assert_eq!(mapping.forward.as_slice(), &order[..256]);
            assert_eq!(mapping.inverse.iter().filter(|b| **b == 256).count(), 32);
            for (byte, grid) in mapping.forward.iter().enumerate() {
                assert_eq!(mapping.inverse[*grid as usize] as usize, byte);
                for tuple in &core().tuples[core().offsets[*grid as usize] as usize
                    ..core().offsets[*grid as usize + 1] as usize]
                {
                    assert_eq!(
                        mapping.inverse[core().identify(*tuple).unwrap()] as usize,
                        byte
                    );
                }
            }
        }
    }
}
