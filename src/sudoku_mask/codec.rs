use std::{io, sync::Arc};

use rand::{RngExt, rngs::StdRng, seq::SliceRandom};

use super::{
    Prepared, Role,
    layout::{POISON, SKIP},
    table::core,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Classic,
    Packed,
}

pub(super) struct Encoder {
    config: Arc<Prepared>,
    mode: Mode,
    layout: usize,
    padding: u8,
    rng: StdRng,
}

impl Encoder {
    pub fn new(config: Arc<Prepared>, role: Role) -> Self {
        let mut rng = rand::make_rng::<StdRng>();
        let padding = rng.random_range(config.padding_min..=config.padding_max);
        Self {
            config,
            mode: match role {
                Role::Client => Mode::Classic,
                Role::Server => Mode::Packed,
            },
            layout: 0,
            padding,
            rng,
        }
    }

    pub fn max_input(&self, capacity: usize) -> usize {
        match (self.mode, self.padding) {
            (Mode::Classic, 0) => capacity / 4,
            (Mode::Classic, _) => capacity.saturating_sub(1) / 9,
            (Mode::Packed, 0) => capacity / 4 * 3,
            (Mode::Packed, _) => capacity.saturating_sub(2) / 8 * 3,
        }
    }

    fn advance(&mut self) {
        self.layout = (self.layout + 1) % self.config.layouts.len();
    }

    fn pad(&mut self, output: &mut [u8], offset: &mut usize) {
        if self.padding == 0
            || (self.padding < 100 && self.rng.random_range(0..100u8) >= self.padding)
        {
            return;
        }
        let layout = &self.config.layouts[self.layout];
        let pool = match self.mode {
            Mode::Classic => &layout.padding,
            Mode::Packed => &layout.packed_padding,
        };
        output[*offset] = pool[self.rng.random_range(0..pool.len())];
        *offset += 1;
    }

    fn group(&mut self, value: u8, output: &mut [u8], offset: &mut usize) {
        self.pad(output, offset);
        output[*offset] = self.config.layouts[self.layout].encode[value as usize];
        *offset += 1;
    }

    pub fn encode(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        if input.is_empty() {
            return 0;
        }
        let mut offset = 0;
        match self.mode {
            Mode::Classic => {
                for byte in input {
                    self.pad(output, &mut offset);
                    let grid = self.config.mapping.forward[*byte as usize] as usize;
                    let range = core().offsets[grid] as usize..core().offsets[grid + 1] as usize;
                    let mut hints = core().tuples[self.rng.random_range(range)];
                    hints.shuffle(&mut self.rng);
                    for group in hints {
                        self.group(group, output, &mut offset);
                    }
                    self.advance();
                }
            }
            Mode::Packed => {
                let mut bits = 0u16;
                let mut count = 0;
                for byte in input {
                    bits = (bits << 8) | u16::from(*byte);
                    count += 8;
                    while count >= 6 {
                        count -= 6;
                        self.group(((bits >> count) & 63) as u8, output, &mut offset);
                        self.advance();
                    }
                    bits &= (1 << count) - 1;
                }
                if count != 0 {
                    self.group((bits << (6 - count)) as u8, output, &mut offset);
                    self.advance();
                    output[offset] = self.config.layouts[self.layout].marker;
                    offset += 1;
                }
            }
        }
        self.pad(output, &mut offset);
        offset
    }
}

pub(super) struct Decoder {
    config: Arc<Prepared>,
    mode: Mode,
    layout: usize,
    hints: [u8; 4],
    count: usize,
    bits: u16,
}

impl Decoder {
    pub fn new(config: Arc<Prepared>, role: Role) -> Self {
        Self {
            config,
            mode: match role {
                Role::Client => Mode::Packed,
                Role::Server => Mode::Classic,
            },
            layout: 0,
            hints: [0; 4],
            count: 0,
            bits: 0,
        }
    }

    pub fn decode(&mut self, byte: u8) -> io::Result<Option<u8>> {
        let layout = &self.config.layouts[self.layout];
        match self.mode {
            Mode::Classic => {
                let group = layout.classic[byte as usize];
                if group == SKIP {
                    return Ok(None);
                }
                self.hints[self.count] = group;
                self.count += 1;
                if self.count < 4 {
                    return Ok(None);
                }
                self.count = 0;
                let decoded = core()
                    .identify(self.hints)
                    .map(|id| self.config.mapping.inverse[id]);
                let Some(decoded) = decoded.filter(|b| *b < 256) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid sudoku hint tuple",
                    ));
                };
                self.layout = (self.layout + 1) % self.config.layouts.len();
                Ok(Some(decoded as u8))
            }
            Mode::Packed => {
                let group = layout.packed[byte as usize];
                if group == SKIP {
                    if byte == layout.marker {
                        self.bits = 0;
                        self.count = 0;
                    }
                    return Ok(None);
                }
                debug_assert!(group < POISON);
                self.layout = (self.layout + 1) % self.config.layouts.len();
                self.bits = (self.bits << 6) | u16::from(group);
                self.count += 6;
                if self.count < 8 {
                    return Ok(None);
                }
                self.count -= 8;
                let result = (self.bits >> self.count) as u8;
                self.bits &= (1 << self.count) - 1;
                Ok(Some(result))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rand::SeedableRng;
    use serde_json::json;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct Sample {
        config: serde_json::Value,
        packed: bool,
        plain: String,
        wire: String,
    }

    #[test]
    fn decodes_pinned_xray_classic_and_packed_samples() {
        let samples: Vec<Sample> =
            serde_json::from_str(include_str!("../../tests/fixtures/sudoku/xray.json")).unwrap();
        assert_eq!(samples.len(), 8);
        for sample in samples {
            let config = super::super::tests::config(sample.config);
            let role = if sample.packed {
                Role::Client
            } else {
                Role::Server
            };
            let mut decoder = Decoder::new(config, role);
            let wire = STANDARD.decode(sample.wire).unwrap();
            let plain = STANDARD.decode(sample.plain).unwrap();
            let decoded: Vec<_> = wire
                .into_iter()
                .filter_map(|b| decoder.decode(b).transpose())
                .collect::<io::Result<_>>()
                .unwrap();
            assert_eq!(decoded, plain);
        }
    }

    #[test]
    #[ignore = "exports Rust wire samples for tests/fixtures/sudoku/xray.go -verify"]
    fn export_rust_wire_samples() {
        let mut samples: Vec<Sample> =
            serde_json::from_str(include_str!("../../tests/fixtures/sudoku/xray.json")).unwrap();
        for sample in &mut samples {
            let config = super::super::tests::config(sample.config.clone());
            let mut encoder = Encoder::new(
                config,
                if sample.packed {
                    Role::Server
                } else {
                    Role::Client
                },
            );
            let plain = STANDARD.decode(&sample.plain).unwrap();
            let mut wire = Vec::new();
            let mut rest = plain.as_slice();
            for size in [1, 2, 3, 13, 14, 256] {
                let mut buffer = vec![0; size * 9 + 8];
                let len = encoder.encode(&rest[..size], &mut buffer);
                wire.extend_from_slice(&buffer[..len]);
                rest = &rest[size..];
            }
            assert!(rest.is_empty());
            sample.wire = STANDARD.encode(wire);
        }
        let path =
            std::env::var_os("SUDOKU_RUST_VECTORS").expect("SUDOKU_RUST_VECTORS is required");
        std::fs::write(path, serde_json::to_vec_pretty(&samples).unwrap()).unwrap();
    }

    #[test]
    fn both_codecs_round_trip_rotating_layouts_across_write_boundaries() {
        for options in [
            json!({}),
            json!({"ascii":"ascii"}),
            json!({"custom_tables":["xpxvvpvv","vxpvxvvp"]}),
            json!({"custom_tables":["","xpxvvpvv"]}),
        ] {
            for padding in [0, 10, 100] {
                let mut options = options.clone();
                options["password"] = json!("example");
                options["padding_min"] = json!(padding);
                options["padding_max"] = json!(padding);
                let config = super::super::tests::config(options);
                for (write, read) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                    let mut encoder = Encoder::new(config.clone(), write);
                    encoder.rng = StdRng::seed_from_u64(42);
                    let mut decoder = Decoder::new(config.clone(), read);
                    for length in [0, 1, 2, 3, 4, 13, 14, 256, 4097] {
                        let input: Vec<_> = (0..length).map(|i| (i * 37) as u8).collect();
                        let mut wire = vec![0; length * 9 + 8];
                        let size = encoder.encode(&input, &mut wire);
                        let output: Vec<_> = wire[..size]
                            .iter()
                            .filter_map(|b| decoder.decode(*b).transpose())
                            .collect::<io::Result<_>>()
                            .unwrap();
                        assert_eq!(input, output);
                        if encoder.mode == Mode::Classic && length != 0 {
                            if padding == 0 {
                                assert_eq!(size, 4 * length);
                            }
                            if padding == 100 {
                                assert_eq!(size, 9 * length + 1);
                            }
                        }
                        if encoder.mode == Mode::Packed && length != 0 {
                            let groups = (length * 4).div_ceil(3);
                            let marker = usize::from(length % 3 != 0);
                            if padding == 0 {
                                assert_eq!(size, groups + marker);
                            }
                            if padding == 100 {
                                assert_eq!(size, 2 * groups + marker + 1);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bounded_chunks_fit_the_wire_buffer() {
        for padding in [0, 100] {
            for role in [Role::Client, Role::Server] {
                let config = super::super::tests::config(
                    json!({"padding_min":padding,"padding_max":padding}),
                );
                let mut encoder = Encoder::new(config, role);
                let n = encoder.max_input(32768);
                let mut wire = [0; 32768];
                assert!(encoder.encode(&vec![255; n], &mut wire) <= wire.len());
                assert_eq!(
                    n,
                    match (role, padding) {
                        (Role::Client, 0) => 8192,
                        (Role::Client, _) => 3640,
                        (Role::Server, 0) => 24576,
                        (Role::Server, _) => 12285,
                    }
                );
            }
        }
    }

    #[test]
    fn classic_rejects_unmapped_grids_and_ascii_poison() {
        let config = super::super::tests::config(json!({"ascii":"ascii"}));
        for grid in 0..288 {
            if config.mapping.inverse[grid] != 256 {
                continue;
            }
            let tuple = core().tuples[core().offsets[grid] as usize];
            let mut decoder = Decoder::new(config.clone(), Role::Server);
            for (i, hint) in tuple.iter().enumerate() {
                let result = decoder.decode(config.layouts[0].encode[*hint as usize]);
                assert_eq!(result.is_err(), i == 3);
            }
        }
        for byte in std::iter::once(0x7f).chain(0xc0..=0xff) {
            let mut decoder = Decoder::new(config.clone(), Role::Server);
            for _ in 0..3 {
                assert_eq!(decoder.decode(byte).unwrap(), None);
            }
            assert!(decoder.decode(byte).is_err());
        }
    }

    #[test]
    fn packed_markers_reset_bits_but_not_layout_position() {
        let config = super::super::tests::config(json!({"custom_tables":["xpxvvpvv","vxpvxvvp"]}));
        let mut encoder = Encoder::new(config.clone(), Role::Server);
        let mut decoder = Decoder::new(config.clone(), Role::Client);
        let mut wire = [0; 16];
        let len = encoder.encode(&[0xab], &mut wire);
        assert_eq!(len, 3);
        assert_eq!(wire[2], config.layouts[0].marker);
        assert_eq!(decoder.decode(wire[0]).unwrap(), None);
        assert_eq!(decoder.decode(wire[1]).unwrap(), Some(0xab));
        assert_eq!(decoder.count, 4);
        decoder.decode(wire[2]).unwrap();
        assert_eq!(decoder.count, 0);
        assert_eq!(decoder.layout, 0);
        let len = encoder.encode(&[0xcd, 0xef], &mut wire);
        assert_eq!(wire[len - 1], config.layouts[1].marker);
    }
}
