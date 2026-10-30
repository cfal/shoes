use std::io;

pub(super) const SKIP: u8 = 255;
pub(super) const POISON: u8 = 64;

pub(super) struct Layout {
    pub encode: [u8; 64],
    pub classic: [u8; 256],
    pub packed: [u8; 256],
    pub padding: Vec<u8>,
    pub packed_padding: Vec<u8>,
    pub marker: u8,
}

impl Layout {
    fn new(encode: [u8; 64], hint: impl Fn(u8) -> bool, padding: Vec<u8>, marker: u8) -> Self {
        let mut classic = [SKIP; 256];
        for (byte, class) in classic.iter_mut().enumerate() {
            if hint(byte as u8) {
                *class = POISON;
            }
        }
        for (group, byte) in encode.iter().enumerate() {
            classic[*byte as usize] = group as u8;
        }
        Self {
            encode,
            packed: classic,
            classic,
            packed_padding: padding.iter().copied().filter(|b| *b != marker).collect(),
            padding,
            marker,
        }
    }

    pub fn entropy() -> Self {
        Self::new(
            std::array::from_fn(|g| (((g & 0x30) << 1) | (g & 0xf)) as u8),
            |b| b & 0x90 == 0,
            (0..8).flat_map(|n| [0x80 + n, 0x10 + n]).collect(),
            0x80,
        )
    }

    pub fn ascii() -> Self {
        let mut result = Self::new(
            std::array::from_fn(|g| if g == 63 { b'\n' } else { 0x40 | g as u8 }),
            |b| b & 0x40 != 0 || b == b'\n',
            (0x20..=0x3f).collect(),
            0x3f,
        );
        for (byte, group) in result.packed.iter_mut().enumerate() {
            if byte & 0x40 != 0 {
                *group = byte as u8 & 0x3f;
            }
        }
        result
    }

    pub fn custom(pattern: &str) -> io::Result<Self> {
        if pattern.len() != 8 || pattern.bytes().any(|b| !b"xpv".contains(&b)) {
            return Err(super::invalid(
                "sudoku custom table requires eight x/p/v characters",
            ));
        }
        let bits = |kind| {
            pattern
                .bytes()
                .enumerate()
                .filter_map(move |(i, b)| (b == kind).then_some(7 - i))
                .collect::<Vec<_>>()
        };
        let x = bits(b'x');
        let p = bits(b'p');
        let v = bits(b'v');
        if x.len() != 2 || p.len() != 2 || v.len() != 4 {
            return Err(super::invalid(
                "sudoku custom table requires two x, two p and four v",
            ));
        }
        let mask = (1 << x[0]) | (1 << x[1]);
        let positions: Vec<_> = p.into_iter().chain(v).collect();
        let encode = std::array::from_fn(|group| {
            positions.iter().enumerate().fold(mask, |b, (i, bit)| {
                b | (((group >> (5 - i)) as u8 & 1) << bit)
            })
        });
        let padding: Vec<_> = (0..=255u8)
            .filter(|b| (b & mask).count_ones() == 1 && b.count_ones() >= 5)
            .collect();
        let marker = padding[0];
        Ok(Self::new(encode, |b| b & mask == mask, padding, marker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_preserve_ascii_poison_and_packed_aliases() {
        for layout in [
            Layout::ascii(),
            Layout::entropy(),
            Layout::custom("xpxvvpvv").unwrap(),
        ] {
            for (group, wire) in layout.encode.iter().enumerate() {
                assert_eq!(layout.classic[*wire as usize] as usize, group);
                assert_eq!(layout.packed[*wire as usize] as usize, group);
            }
            assert!(!layout.packed_padding.contains(&layout.marker));
            for byte in layout.padding {
                assert_eq!(layout.classic[byte as usize], SKIP);
            }
        }
        let ascii = Layout::ascii();
        assert_eq!(ascii.classic[b'\n' as usize], 63);
        for byte in std::iter::once(0x7f).chain(0xc0..=0xff) {
            assert_eq!(ascii.classic[byte], POISON);
            assert_eq!(ascii.packed[byte], byte as u8 & 0x3f);
        }
        assert_eq!(ascii.classic[0], SKIP);
    }

    #[test]
    fn all_custom_layouts_have_disjoint_hint_and_padding_pools() {
        let mut count = 0;
        for a in 0..8 {
            for b in a + 1..8 {
                for c in 0..8 {
                    for d in c + 1..8 {
                        if [a, b].contains(&c) || [a, b].contains(&d) {
                            continue;
                        }
                        let mut pattern = [b'v'; 8];
                        pattern[a] = b'x';
                        pattern[b] = b'x';
                        pattern[c] = b'p';
                        pattern[d] = b'p';
                        let layout =
                            Layout::custom(std::str::from_utf8(&pattern).unwrap()).unwrap();
                        assert_eq!(layout.padding.len(), 44);
                        for byte in 0..256 {
                            assert_ne!(layout.classic[byte], POISON);
                            assert_eq!(layout.classic[byte], layout.packed[byte]);
                        }
                        for g in 0..64 {
                            assert_eq!(layout.classic[layout.encode[g] as usize] as usize, g);
                        }
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 420);
    }
}
