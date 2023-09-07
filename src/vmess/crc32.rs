// Copied and modified from rust-snappy
#![allow(dead_code)]

use std::sync::OnceLock;

const POLY: u32 = 0xEDB88320;

/// Returns the CRC32 checksum of `buf` using the Castagnoli polynomial.
pub fn crc32c(buf: &[u8]) -> u32 {
    // I can't measure any difference between slice8 and slice16.
    let ret = crc32c_slice8(buf, !0);
    !ret
}

/// Returns the CRC32 checksum of `buf` using the Castagnoli polynomial.
fn crc32c_slice8(mut buf: &[u8], initial_crc: u32) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    static TABLE16: OnceLock<[[u32; 256]; 16]> = OnceLock::new();

    let tab = TABLE.get_or_init(|| make_table(POLY));
    let tab8 = &TABLE16.get_or_init(|| {
        let mut tab = [[0; 256]; 16];
        tab[0] = make_table(POLY);
        for i in 0..256 {
            let mut crc = tab[0][i];
            for j in 1..16 {
                crc = (crc >> 8) ^ tab[0][crc as u8 as usize];
                tab[j][i] = crc;
            }
        }
        tab
    });

    let mut crc: u32 = initial_crc;
    while buf.len() >= 8 {
        crc ^= u32::from_le_bytes(buf[0..4].try_into().unwrap());
        crc = tab8[0][buf[7] as usize]
            ^ tab8[1][buf[6] as usize]
            ^ tab8[2][buf[5] as usize]
            ^ tab8[3][buf[4] as usize]
            ^ tab8[4][(crc >> 24) as u8 as usize]
            ^ tab8[5][(crc >> 16) as u8 as usize]
            ^ tab8[6][(crc >> 8) as u8 as usize]
            ^ tab8[7][(crc) as u8 as usize];
        buf = &buf[8..];
    }
    for &b in buf {
        crc = tab[((crc as u8) ^ b) as usize] ^ (crc >> 8);
    }
    crc
}

fn make_table(poly: u32) -> [u32; 256] {
    let mut tab = [0; 256];
    let mut rev_tab = [0; 256];
    for i in 0u32..256u32 {
        let mut crc = i;
        let mut rev = i << 24;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }

            if (rev & 0x80000000) != 0 {
                rev = ((rev ^ poly) << 1) | 1;
            } else {
                rev <<= 1;
            }
        }
        tab[i as usize] = crc;
        rev_tab[i as usize] = rev;
    }
    tab
}

fn make_reverse_table(poly: u32) -> [u32; 256] {
    let mut rev_tab = [0; 256];
    for i in 0u32..256u32 {
        let mut rev = i << 24;
        for _ in 0..8 {
            if (rev & 0x80000000) != 0 {
                rev = ((rev ^ poly) << 1) | 1;
            } else {
                rev <<= 1;
            }
        }
        rev_tab[i as usize] = rev;
    }
    rev_tab
}

pub struct CrcBuilder(u32);

impl CrcBuilder {
    pub fn new() -> Self {
        Self(!0)
    }

    pub fn new_with_initial(initial: u32) -> Self {
        Self(initial)
    }

    pub fn update(&mut self, buf: &[u8]) {
        self.0 = crc32c_slice8(buf, self.0);
    }

    pub fn to_crc(&self) -> u32 {
        !self.0
    }
}
