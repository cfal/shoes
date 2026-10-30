// Go math/rand compatibility, used only for the password permutation.
// Cooked state and generator contract: Go 1.27.3 src/math/rand/rng.go.
// Copyright 2009 The Go Authors. All rights reserved.
// BSD-3-Clause; full notice in THIRD_PARTY_NOTICES.md.

mod cooked;

pub(super) struct GoRng {
    state: [u64; 607],
    tap: usize,
    feed: usize,
}

impl GoRng {
    pub fn new(seed: i64) -> Self {
        const MODULUS: i64 = (1 << 31) - 1;
        let mut x = seed.rem_euclid(MODULUS);
        if x == 0 {
            x = 89_482_311;
        }
        let mut step = || {
            x = x * 48_271 % MODULUS;
            x as u64
        };
        for _ in 0..20 {
            step();
        }
        let state = std::array::from_fn(|i| {
            (step() << 40) ^ (step() << 20) ^ step() ^ cooked::COOKED[i] as u64
        });
        Self {
            state,
            tap: 0,
            feed: 334,
        }
    }

    fn uint32(&mut self) -> u32 {
        self.tap = if self.tap == 0 { 606 } else { self.tap - 1 };
        self.feed = if self.feed == 0 { 606 } else { self.feed - 1 };
        self.state[self.feed] = self.state[self.feed].wrapping_add(self.state[self.tap]);
        ((self.state[self.feed] & i64::MAX as u64) >> 31) as u32
    }

    pub fn shuffle(&mut self, order: &mut [u16]) {
        for i in (1..order.len()).rev() {
            let j = bounded((i + 1) as u32, || self.uint32());
            order.swap(i, j as usize);
        }
    }
}

fn bounded(n: u32, mut draw: impl FnMut() -> u32) -> u32 {
    let threshold = n.wrapping_neg() % n;
    loop {
        let product = u64::from(draw()) * u64::from(n);
        if product as u32 >= threshold {
            return (product >> 32) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        seed: i64,
        words: Vec<u32>,
        order: Vec<u16>,
    }

    #[test]
    fn legacy_source_and_shuffle_match_go_vectors() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../tests/fixtures/sudoku/go_rng.json")).unwrap();
        for vector in vectors {
            let mut rng = GoRng::new(vector.seed);
            assert_eq!(
                vector.words,
                (0..vector.words.len())
                    .map(|_| rng.uint32())
                    .collect::<Vec<_>>()
            );
            let mut rng = GoRng::new(vector.seed);
            let mut order = std::array::from_fn::<_, 288, _>(|i| i as u16);
            rng.shuffle(&mut order);
            assert_eq!(order.as_slice(), vector.order, "seed {}", vector.seed);
        }
    }

    #[test]
    fn multiply_high_sampling_rejects_low_product() {
        let mut words = [0, 1, u32::MAX].into_iter();
        assert_eq!(bounded(288, || words.next().unwrap()), 0);
        assert_eq!(words.next(), Some(u32::MAX));
        assert_eq!(bounded(288, || u32::MAX), 287);
    }
}
