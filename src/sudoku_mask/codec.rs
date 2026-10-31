use std::{io, sync::Arc};

use rand::{RngExt, rngs::StdRng};

use super::{
    Prepared, Role,
    layout::{Layout, POISON, SKIP},
    table::core,
};

#[cfg(test)]
#[path = "../../benches/sudoku_measurement.rs"]
mod measurement;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Classic,
    Packed,
}

const PERMUTATIONS: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

fn next_layout(index: usize, count: usize) -> usize {
    if index + 1 == count { 0 } else { index + 1 }
}

fn pad(rng: &mut impl rand::Rng, threshold: u64, pool: &[u8], output: &mut [u8]) -> usize {
    if threshold == 0 || (threshold < (1u64 << 32) && u64::from(rng.random::<u32>()) >= threshold) {
        return 0;
    }
    output[0] = pool[rng.random_range(0..pool.len() as u32) as usize];
    1
}

#[inline(never)]
fn encode_unpadded_chunks(
    layouts: &[Layout],
    index: &mut usize,
    chunks: &[[u8; 3]],
    output: &mut [u8],
) -> usize {
    let written = chunks.len() * 4;
    let output = output[..written].as_chunks_mut::<4>().0;
    if let [layout] = layouts {
        let table = &layout.encode;
        for (&[a, b, c], encoded) in chunks.iter().zip(output) {
            *encoded = [
                table[(a >> 2) as usize],
                table[((a & 3) << 4 | b >> 4) as usize],
                table[((b & 15) << 2 | c >> 6) as usize],
                table[(c & 63) as usize],
            ];
        }
    } else {
        for (&[a, b, c], encoded) in chunks.iter().zip(output) {
            for (group, byte) in [
                a >> 2,
                (a & 3) << 4 | b >> 4,
                (b & 15) << 2 | c >> 6,
                c & 63,
            ]
            .into_iter()
            .zip(encoded)
            {
                *byte = layouts[*index].encode[group as usize];
                *index = next_layout(*index, layouts.len());
            }
        }
    }
    written
}

pub(super) struct Encoder {
    config: Arc<Prepared>,
    mode: Mode,
    layout: usize,
    // Includes 2^32 so 100% padding needs no probability draw.
    padding_threshold: u64,
    rng: StdRng,
}

impl Encoder {
    pub fn new(config: Arc<Prepared>, role: Role) -> Self {
        let mut rng = rand::make_rng::<StdRng>();
        let percent = rng.random_range(config.padding_min..=config.padding_max);
        let padding_threshold = (u64::from(percent) << 32) / 100;
        Self {
            config,
            mode: match role {
                Role::Client => Mode::Classic,
                Role::Server => Mode::Packed,
            },
            layout: 0,
            padding_threshold,
            rng,
        }
    }

    pub fn max_input(&self, capacity: usize) -> usize {
        match (self.mode, self.padding_threshold) {
            (Mode::Classic, 0) => capacity / 4,
            (Mode::Classic, _) => capacity.saturating_sub(1) / 9,
            (Mode::Packed, 0) => capacity / 4 * 3,
            (Mode::Packed, _) => capacity.saturating_sub(2) / 8 * 3,
        }
    }

    pub fn encode(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        if input.is_empty() {
            return 0;
        }
        match self.mode {
            Mode::Classic => self.encode_classic(input, output),
            Mode::Packed => self.encode_packed(input, output),
        }
    }

    // Keeps classic/cache control flow out of the packed encoder's register allocation.
    #[inline(never)]
    fn encode_classic(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        if let Some(alphabet) = self.config.classic_alphabet {
            return self.encode_cached_classic(alphabet.tuples(), input, output);
        }
        self.encode_uncached_classic(input, output)
    }

    #[inline(never)]
    fn encode_uncached_classic(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        let mut offset = 0;
        let layouts = &self.config.layouts;
        let threshold = self.padding_threshold;
        let rng = &mut self.rng;
        let core = core();
        for byte in input {
            let grid = self.config.mapping.forward[*byte as usize] as usize;
            let start = core.offsets[grid];
            let count = core.offsets[grid + 1] - start;
            // One uniform choice covers every tuple and each of its 24 orders.
            let choice = rng.random_range(0..count * 24);
            let hints = core.tuples[(start + choice / 24) as usize];
            let layout = &layouts[self.layout];
            let encoded = PERMUTATIONS[(choice % 24) as usize]
                .map(|index| layout.encode[hints[index] as usize]);
            if threshold == 0 {
                output[offset..offset + 4].copy_from_slice(&encoded);
                offset += 4;
            } else {
                offset += pad(rng, threshold, &layout.padding, &mut output[offset..]);
                for byte in encoded {
                    offset += pad(rng, threshold, &layout.padding, &mut output[offset..]);
                    output[offset] = byte;
                    offset += 1;
                }
            }
            self.layout = next_layout(self.layout, layouts.len());
        }
        offset
            + pad(
                rng,
                threshold,
                &layouts[self.layout].padding,
                &mut output[offset..],
            )
    }

    #[inline(never)]
    fn encode_cached_classic(
        &mut self,
        tuples: &[[u8; 4]],
        input: &[u8],
        output: &mut [u8],
    ) -> usize {
        let core = core();
        let layout = &self.config.layouts[0];
        let threshold = self.padding_threshold;
        let rng = &mut self.rng;
        let mut offset = 0;
        for byte in input {
            let grid = self.config.mapping.forward[*byte as usize] as usize;
            let start = core.offsets[grid];
            let count = core.offsets[grid + 1] - start;
            let choice = rng.random_range(0..count * 24);
            let tuple = tuples[(start + choice / 24) as usize];
            let encoded = PERMUTATIONS[(choice % 24) as usize].map(|index| tuple[index]);
            if threshold == 0 {
                output[offset..offset + 4].copy_from_slice(&encoded);
                offset += 4;
            } else {
                offset += pad(rng, threshold, &layout.padding, &mut output[offset..]);
                for byte in encoded {
                    offset += pad(rng, threshold, &layout.padding, &mut output[offset..]);
                    output[offset] = byte;
                    offset += 1;
                }
            }
        }
        offset + pad(rng, threshold, &layout.padding, &mut output[offset..])
    }

    #[inline(never)]
    fn encode_packed(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        let mut offset = 0;
        let layouts = &self.config.layouts;
        let threshold = self.padding_threshold;
        let rng = &mut self.rng;
        let (chunks, remainder) = input.as_chunks::<3>();
        if threshold == 0 {
            offset = encode_unpadded_chunks(layouts, &mut self.layout, chunks, output);
        } else {
            for &[a, b, c] in chunks {
                for group in [
                    a >> 2,
                    (a & 3) << 4 | b >> 4,
                    (b & 15) << 2 | c >> 6,
                    c & 63,
                ] {
                    let layout = &layouts[self.layout];
                    offset += pad(
                        rng,
                        threshold,
                        &layout.packed_padding,
                        &mut output[offset..],
                    );
                    output[offset] = layout.encode[group as usize];
                    offset += 1;
                    self.layout = next_layout(self.layout, layouts.len());
                }
            }
        }
        let mut bits = 0u16;
        let mut count = 0;
        for byte in remainder {
            bits = (bits << 8) | u16::from(*byte);
            count += 8;
            while count >= 6 {
                count -= 6;
                let layout = &layouts[self.layout];
                offset += pad(
                    rng,
                    threshold,
                    &layout.packed_padding,
                    &mut output[offset..],
                );
                output[offset] = layout.encode[((bits >> count) & 63) as usize];
                offset += 1;
                self.layout = next_layout(self.layout, layouts.len());
            }
            bits &= (1 << count) - 1;
        }
        if count != 0 {
            let layout = &layouts[self.layout];
            offset += pad(
                rng,
                threshold,
                &layout.packed_padding,
                &mut output[offset..],
            );
            output[offset] = layout.encode[(bits << (6 - count)) as usize];
            offset += 1;
            self.layout = next_layout(self.layout, layouts.len());
            output[offset] = layouts[self.layout].marker;
            offset += 1;
        }
        offset
            + pad(
                rng,
                threshold,
                &layouts[self.layout].packed_padding,
                &mut output[offset..],
            )
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

// Keeps the bulk loop independent of framing state and per-group span checks.
#[inline(never)]
fn decode_packed_chunks(table: &[u8; 256], input: &[u8], output: &mut [u8]) -> usize {
    let mut decoded = 0;
    for (wire, plain) in input
        .as_chunks::<4>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<3>().0)
    {
        let [a, b, c, d] = wire.map(|b| table[b as usize]);
        if (a | b | c | d) >= 64 {
            break;
        }
        *plain = [a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d];
        decoded += 1;
    }
    decoded
}

#[derive(Default)]
pub(super) struct Decoded {
    pub consumed: usize,
    pub written: usize,
    // A malformed tuple can follow a successfully decoded prefix in the same chunk.
    pub error: Option<io::Error>,
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

    pub fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Decoded {
        if self.mode == Mode::Classic && self.config.layouts.len() == 1 {
            return self.decode_compacted(input, output);
        }
        let mut result = Decoded::default();
        match self.mode {
            Mode::Classic => {
                let core = core();
                while result.consumed < input.len() && result.written < output.len() {
                    let layout = &self.config.layouts[self.layout];
                    let rest = &input[result.consumed..];
                    if self.count == 0 && rest.len() >= 4 {
                        let hints = [rest[0], rest[1], rest[2], rest[3]]
                            .map(|b| layout.classic[b as usize]);
                        if !hints.contains(&SKIP) {
                            self.hints = hints;
                            self.count = 4;
                            result.consumed += 4;
                        }
                    }
                    if self.count < 4 {
                        let group = layout.classic[input[result.consumed] as usize];
                        result.consumed += 1;
                        if group == SKIP {
                            continue;
                        }
                        self.hints[self.count] = group;
                        self.count += 1;
                        if self.count < 4 {
                            continue;
                        }
                    }
                    self.count = 0;
                    let decoded = core
                        .identify(self.hints)
                        .map(|id| self.config.mapping.inverse[id]);
                    let Some(decoded) = decoded.filter(|b| *b < 256) else {
                        result.error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid sudoku hint tuple",
                        ));
                        break;
                    };
                    output[result.written] = decoded as u8;
                    result.written += 1;
                    self.layout = next_layout(self.layout, self.config.layouts.len());
                }
            }
            Mode::Packed => {
                while result.consumed < input.len() && result.written < output.len() {
                    let layouts = &self.config.layouts;
                    let layout = &layouts[self.layout];
                    let rest = &input[result.consumed..];
                    if self.count == 0
                        && rest.len() >= 4
                        && output.len() - result.written >= 3
                        && layouts.len() == 1
                    {
                        let decoded = decode_packed_chunks(
                            &layout.packed,
                            rest,
                            &mut output[result.written..],
                        );
                        result.consumed += decoded * 4;
                        result.written += decoded * 3;
                        if result.consumed == input.len() || result.written == output.len() {
                            break;
                        }
                    }
                    let byte = input[result.consumed];
                    result.consumed += 1;
                    let group = layout.packed[byte as usize];
                    if group == SKIP {
                        if byte == layout.marker {
                            self.bits = 0;
                            self.count = 0;
                        }
                        continue;
                    }
                    debug_assert!(group < POISON);
                    self.layout = next_layout(self.layout, layouts.len());
                    self.bits = (self.bits << 6) | u16::from(group);
                    self.count += 6;
                    if self.count >= 8 {
                        self.count -= 8;
                        output[result.written] = (self.bits >> self.count) as u8;
                        result.written += 1;
                        self.bits &= (1 << self.count) - 1;
                    }
                }
            }
        }
        result
    }

    #[inline(never)]
    fn decode_compacted(&mut self, input: &[u8], output: &mut [u8]) -> Decoded {
        let mut result = Decoded::default();
        let table = &self.config.layouts[0].classic;
        let core = core();
        let mut hints = [0u8; 256];
        while result.consumed < input.len() && result.written < output.len() {
            let initial = self.count;
            hints[..initial].copy_from_slice(&self.hints[..initial]);
            // Bounds raw lookahead so output saturation cannot consume a trailing byte.
            let limit = ((output.len() - result.written).min(hints.len() / 4) * 4 - initial)
                .min(input.len() - result.consumed);
            let start = result.consumed;
            let mut count = initial;
            for byte in &input[start..start + limit] {
                let hint = table[*byte as usize];
                hints[count] = hint;
                count += usize::from(hint != SKIP);
            }
            for (index, group) in hints[..count].as_chunks::<4>().0.iter().enumerate() {
                self.hints = *group;
                self.count = 0;
                let value = core
                    .identify(*group)
                    .map(|id| self.config.mapping.inverse[id]);
                let Some(value) = value.filter(|b| *b < 256) else {
                    // Recovers the scalar error position without per-hint offset bookkeeping.
                    let needed = (index + 1) * 4 - initial;
                    let mut seen = 0;
                    for (offset, byte) in input[start..start + limit].iter().enumerate() {
                        seen += usize::from(table[*byte as usize] != SKIP);
                        if seen == needed {
                            result.consumed = start + offset + 1;
                            break;
                        }
                    }
                    result.error = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid sudoku hint tuple",
                    ));
                    return result;
                };
                output[result.written] = value as u8;
                result.written += 1;
            }
            self.count = count % 4;
            self.hints[..self.count].copy_from_slice(&hints[count - self.count..count]);
            result.consumed += limit;
        }
        result
    }

    #[cfg(test)]
    pub fn decode_byte(&mut self, byte: u8) -> io::Result<Option<u8>> {
        // Keeps the classic test oracle independent of the bulk compaction algorithm.
        if self.mode == Mode::Classic {
            let hint = self.config.layouts[self.layout].classic[byte as usize];
            if hint == SKIP {
                return Ok(None);
            }
            self.hints[self.count] = hint;
            self.count += 1;
            if self.count != 4 {
                return Ok(None);
            }
            self.count = 0;
            let value = core()
                .identify(self.hints)
                .map(|id| self.config.mapping.inverse[id])
                .filter(|b| *b < 256)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid sudoku hint tuple")
                })?;
            self.layout = next_layout(self.layout, self.config.layouts.len());
            return Ok(Some(value as u8));
        }
        let mut output = [0];
        let result = self.decode(&[byte], &mut output);
        match result.error {
            Some(error) => Err(error),
            None => Ok((result.written != 0).then_some(output[0])),
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

    fn check_chunk_boundaries(config: Arc<Prepared>, role: Role, wire: &[u8]) {
        for input_size in [1, 2, 3, 4, 5, 7, 17, 256, wire.len().max(1)] {
            for output_size in [1, 2, 3, 4, 7, wire.len().max(1)] {
                let mut decoder = Decoder::new(config.clone(), role);
                let mut scalar = Decoder::new(config.clone(), role);
                let mut output = vec![0; output_size];
                'input: for mut input in wire.chunks(input_size) {
                    while !input.is_empty() {
                        let empty = decoder.decode(input, &mut []);
                        assert_eq!((empty.consumed, empty.written), (0, 0));
                        assert!(empty.error.is_none());

                        let mut expected = Vec::new();
                        let mut consumed = 0;
                        let mut error = None;
                        for byte in input {
                            consumed += 1;
                            match scalar.decode_byte(*byte) {
                                Ok(Some(byte)) => expected.push(byte),
                                Ok(None) => {}
                                Err(e) => {
                                    error = Some(e);
                                    break;
                                }
                            }
                            if expected.len() == output_size {
                                break;
                            }
                        }
                        let result = decoder.decode(input, &mut output);
                        assert_eq!(result.consumed, consumed);
                        assert_eq!(&output[..result.written], expected);
                        assert_eq!(
                            result.error.as_ref().map(io::Error::kind),
                            error.as_ref().map(io::Error::kind)
                        );
                        assert_eq!(
                            result.error.as_ref().map(ToString::to_string),
                            error.as_ref().map(ToString::to_string)
                        );
                        assert_eq!(
                            (decoder.layout, decoder.count, decoder.bits),
                            (scalar.layout, scalar.count, scalar.bits)
                        );
                        assert_eq!(decoder.hints, scalar.hints);
                        if error.is_some() {
                            break 'input;
                        }
                        assert!(result.consumed > 0);
                        input = &input[result.consumed..];
                    }
                }
            }
        }
    }

    #[test]
    fn packed_chunks_preserve_sentinels_and_partial_spans() {
        fn check(config: &Arc<Prepared>, wire: &[u8], capacity: usize) {
            let table = &config.layouts[0].packed;
            let expected = wire
                .as_chunks::<4>()
                .0
                .iter()
                .take(capacity / 3)
                .take_while(|chunk| chunk.iter().all(|b| table[*b as usize] < 64))
                .count();
            let mut output = [0xa5; 16];
            assert_eq!(
                decode_packed_chunks(table, wire, &mut output[..capacity]),
                expected
            );
            let mut scalar = Decoder::new(config.clone(), Role::Client);
            let plain: Vec<_> = wire[..expected * 4]
                .iter()
                .filter_map(|b| scalar.decode_byte(*b).unwrap())
                .collect();
            assert_eq!(&output[..expected * 3], plain);
            assert!(output[expected * 3..].iter().all(|b| *b == 0xa5));
            assert_eq!((scalar.layout, scalar.bits, scalar.count), (0, 0, 0));
        }

        for options in [
            json!({}),
            json!({"ascii": "ascii"}),
            json!({"custom_table": "xpxvvpvv"}),
        ] {
            let config = super::super::tests::config(options);
            let valid: Vec<_> = (0..17).map(|i| config.layouts[0].encode[i * 3]).collect();
            for length in 0..=valid.len() {
                for capacity in 0..=16 {
                    check(&config, &valid[..length], capacity);
                }
            }
            for position in 0..16 {
                for byte in 0..=255 {
                    let mut wire = valid.clone();
                    wire[position] = byte;
                    for capacity in 0..=16 {
                        check(&config, &wire, capacity);
                    }
                }
            }
        }
    }

    #[test]
    fn classic_compaction_preserves_windows_errors_and_partial_state() {
        fn check(config: &Arc<Prepared>, wire: &[u8], capacity: usize) {
            let mut bulk = Decoder::new(config.clone(), Role::Server);
            let mut scalar = Decoder::new(config.clone(), Role::Server);
            for mut input in wire.chunks(257) {
                while !input.is_empty() {
                    let state = (bulk.layout, bulk.hints, bulk.count, bulk.bits);
                    let empty = bulk.decode(input, &mut []);
                    assert_eq!((empty.consumed, empty.written), (0, 0));
                    assert!(empty.error.is_none());
                    assert_eq!((bulk.layout, bulk.hints, bulk.count, bulk.bits), state);

                    let mut expected = [0xa5; 258];
                    let mut written = 0;
                    let mut consumed = 0;
                    let mut error = None;
                    for byte in input {
                        consumed += 1;
                        match scalar.decode_byte(*byte) {
                            Ok(Some(byte)) => {
                                expected[written] = byte;
                                written += 1;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                        if written == capacity {
                            break;
                        }
                    }
                    let mut actual = [0xa5; 258];
                    let result = bulk.decode(input, &mut actual[..capacity]);
                    assert_eq!((result.consumed, result.written), (consumed, written));
                    assert_eq!(actual, expected);
                    assert_eq!(
                        result.error.as_ref().map(|e| (e.kind(), e.to_string())),
                        error.as_ref().map(|e| (e.kind(), e.to_string())),
                    );
                    assert_eq!(
                        (bulk.layout, bulk.hints, bulk.count, bulk.bits),
                        (scalar.layout, scalar.hints, scalar.count, scalar.bits),
                    );
                    if error.is_some() {
                        return;
                    }
                    assert!(consumed > 0);
                    input = &input[consumed..];
                }
            }
        }

        for options in [
            json!({}),
            json!({"ascii":"ascii"}),
            json!({"custom_table":"xpxvvpvv"}),
        ] {
            let mut options = options;
            options["padding_min"] = json!(10);
            options["padding_max"] = json!(10);
            let config = super::super::tests::config(options);
            let mut encoder = Encoder::new(config.clone(), Role::Client);
            encoder.rng = StdRng::seed_from_u64(42);
            let plain: Vec<_> = (0..1024).map(|i| (i * 37) as u8).collect();
            let mut wire = vec![0; plain.len() * 9 + 8];
            let n = encoder.encode(&plain, &mut wire);
            wire.truncate(n);
            for position in [0, 1, 2, 3, 4, 7, 15, 255, 256, 257, 511, 1023] {
                let saved = wire[position];
                for byte in 0..=255 {
                    wire[position] = byte;
                    for capacity in [1, 3, 7, 64, 257] {
                        check(&config, &wire, capacity);
                    }
                }
                wire[position] = saved;
            }
            for byte in 0..=255 {
                for capacity in [1, 3, 64] {
                    check(&config, &[byte; 513], capacity);
                }
            }
        }
    }

    #[test]
    fn chunk_decoding_preserves_fragmentation_and_write_boundaries() {
        for options in [
            json!({}),
            json!({"ascii":"ascii"}),
            json!({"custom_table":"xpxvvpvv"}),
            json!({"custom_tables":["xpxvvpvv", "vxpvxvvp", ""]}),
            json!({"custom_tables":["xpxvvpvv", "vxpvxvvp", "", "pxpxvvvv", "vvxxppvv"]}),
        ] {
            for padding in [0, 10, 100] {
                let mut options = options.clone();
                options["padding_min"] = json!(padding);
                options["padding_max"] = json!(padding);
                let config = super::super::tests::config(options);
                for (write, read) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
                    let mut encoder = Encoder::new(config.clone(), write);
                    encoder.rng = StdRng::seed_from_u64(42);
                    let mut wire = Vec::new();
                    let mut plain = Vec::new();
                    for length in (0..=16).chain([255, 4097]) {
                        let input: Vec<_> = (0..length).map(|i| (i * 37) as u8).collect();
                        let mut buffer = vec![0; length * 9 + 8];
                        let written = encoder.encode(&input, &mut buffer);
                        wire.extend_from_slice(&buffer[..written]);
                        plain.extend_from_slice(&input);
                    }
                    let mut decoder = Decoder::new(config.clone(), read);
                    let mut output = vec![0; plain.len() + 1];
                    let result = decoder.decode(&wire, &mut output);
                    assert!(result.error.is_none());
                    assert_eq!(result.consumed, wire.len());
                    assert_eq!(&output[..result.written], plain);
                    check_chunk_boundaries(config.clone(), read, &wire);
                }
            }
        }
    }

    #[test]
    fn chunk_decoding_preserves_aliases_and_error_positions() {
        let config = super::super::tests::config(json!({"ascii":"ascii"}));
        let mut encoder = Encoder::new(config.clone(), Role::Client);
        let mut prefix = [0; 8];
        assert_eq!(encoder.encode(&[42, 17], &mut prefix), 8);
        for position in 0..4 {
            for poison in std::iter::once(0x7f).chain(0xc0..=0xff) {
                let mut wire = prefix.to_vec();
                let mut invalid = prefix[..4].to_vec();
                invalid[position] = poison;
                wire.extend_from_slice(&invalid);
                wire.extend_from_slice(&prefix);
                let mut decoder = Decoder::new(config.clone(), Role::Server);
                let mut output = [0; 16];
                let result = decoder.decode(&wire, &mut output);
                assert_eq!((result.consumed, result.written), (12, 2));
                assert_eq!(&output[..2], &[42, 17]);
                assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidData);
                check_chunk_boundaries(config.clone(), Role::Server, &wire);
            }
        }
        for grid in 0..288 {
            if config.mapping.inverse[grid] != 256 {
                continue;
            }
            let tuple = core().tuples[core().offsets[grid] as usize];
            let wire: Vec<_> = prefix
                .into_iter()
                .chain(tuple.map(|hint| config.layouts[0].encode[hint as usize]))
                .collect();
            check_chunk_boundaries(config.clone(), Role::Server, &wire);
        }
        let aliases: Vec<_> = (0..=255u8).cycle().take(1024).collect();
        check_chunk_boundaries(config.clone(), Role::Client, &aliases);
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..32 {
            let wire: Vec<_> = (0..256).map(|_| rng.random()).collect();
            check_chunk_boundaries(config.clone(), Role::Server, &wire);
        }
    }

    #[test]
    fn cached_classic_encoding_preserves_wire_and_rng_across_writes() {
        for ascii in ["entropy", "ascii"] {
            for padding in [0, 10, 100] {
                for password in ["", "different-mapping"] {
                    let options = json!({
                        "ascii": ascii, "password": password,
                        "padding_min": padding, "padding_max": padding,
                    });
                    let mut config = super::super::tests::config(options.clone());
                    Arc::get_mut(&mut config).unwrap().classic_alphabet = None;
                    let mut original = Encoder::new(config, Role::Client);
                    let mut cached =
                        Encoder::new(super::super::tests::config(options), Role::Client);
                    assert!(cached.config.classic_alphabet.is_some());
                    cached.rng = StdRng::seed_from_u64(42);
                    original.rng = StdRng::seed_from_u64(42);
                    for length in (0..=8).chain([13, 14, 256, 4097]) {
                        let plain: Vec<_> = (0..length).map(|i| (i * 37 + i / 256) as u8).collect();
                        let mut actual = vec![0xa5; length * 9 + 8];
                        let mut expected = actual.clone();
                        let written = cached.encode(&plain, &mut actual);
                        assert_eq!(written, original.encode(&plain, &mut expected));
                        assert_eq!(actual, expected);
                        assert_eq!(cached.layout, original.layout);
                        assert_eq!(
                            cached.rng.random::<[u8; 32]>(),
                            original.rng.random::<[u8; 32]>(),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn padding_thresholds_preserve_probability_boundaries_and_draw_counts() {
        struct Draws(std::collections::VecDeque<u32>);

        impl rand::TryRng for Draws {
            type Error = std::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(self.0.pop_front().expect("unexpected random draw"))
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                panic!("padding uses u32 draws")
            }

            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
                panic!("padding uses u32 draws")
            }
        }

        for percent in 0..=100u64 {
            let config = super::super::tests::config(json!({
                "padding_min":percent, "padding_max":percent,
            }));
            let threshold = Encoder::new(config, Role::Client).padding_threshold;
            let numerator = percent * (u64::from(u32::MAX) + 1);
            assert!(threshold * 100 <= numerator);
            assert!(numerator - threshold * 100 < 100);
            for draw in [
                0,
                threshold.saturating_sub(1),
                threshold,
                u64::from(u32::MAX),
            ] {
                if draw > u64::from(u32::MAX) {
                    continue;
                }
                let should_pad = draw < threshold;
                let mut rng = Draws(std::collections::VecDeque::new());
                if (1..100).contains(&percent) {
                    rng.0.push_back(draw as u32);
                }
                if should_pad {
                    rng.0.push_back(0);
                }
                let mut output = [0xa5; 2];
                assert_eq!(
                    pad(&mut rng, threshold, &[17, 23], &mut output),
                    usize::from(should_pad)
                );
                assert_eq!(output, [if should_pad { 17 } else { 0xa5 }, 0xa5]);
                assert!(rng.0.is_empty());
            }
        }
        assert_eq!(pad(&mut Draws(Default::default()), 0, &[], &mut []), 0);
    }

    #[test]
    fn empty_encoding_preserves_output_rng_and_layout() {
        for options in [
            json!({}),
            json!({"ascii": "ascii"}),
            json!({"custom_tables": ["", "xpxvvpvv", "vxpvxvvp"]}),
        ] {
            for role in [Role::Client, Role::Server] {
                let mut options = options.clone();
                options["padding_min"] = json!(100);
                options["padding_max"] = json!(100);
                let mut encoder = Encoder::new(super::super::tests::config(options), role);
                let mut output = [0; 32];
                encoder.encode(&[42], &mut output);
                let layout = encoder.layout;
                encoder.rng = StdRng::seed_from_u64(42);
                let rng = StdRng::seed_from_u64(42).random::<[u8; 32]>();
                output.fill(0xa5);
                assert_eq!(encoder.encode(&[], &mut []), 0);
                assert_eq!(encoder.encode(&[], &mut output), 0);
                assert_eq!(output, [0xa5; 32]);
                assert_eq!(encoder.layout, layout);
                assert_eq!(encoder.rng.random::<[u8; 32]>(), rng);
            }
        }
    }

    #[test]
    fn classic_encoder_samples_every_tuple_and_permutation() {
        let permutations: std::collections::HashSet<_> = PERMUTATIONS.into_iter().collect();
        assert_eq!(permutations.len(), 24);
        for mut permutation in permutations {
            permutation.sort_unstable();
            assert_eq!(permutation, [0, 1, 2, 3]);
        }
        let config = super::super::tests::config(json!({}));
        for count in [12, 128] {
            let byte = config
                .mapping
                .forward
                .iter()
                .position(|grid| {
                    let grid = *grid as usize;
                    core().offsets[grid + 1] - core().offsets[grid] == count
                })
                .unwrap() as u8;
            let samples = count as usize * 24 * 128;
            let mut encoder = Encoder::new(config.clone(), Role::Client);
            encoder.rng = StdRng::seed_from_u64(42);
            let mut wire = vec![0; samples * 4];
            assert_eq!(encoder.encode(&vec![byte; samples], &mut wire), wire.len());
            let mut seen = std::collections::HashMap::<[u8; 4], usize>::new();
            for tuple in wire.as_chunks::<4>().0 {
                *seen.entry(*tuple).or_default() += 1;
            }
            assert_eq!(seen.len(), count as usize * 24);
            assert!(
                seen.values()
                    .all(|frequency| (64..=192).contains(frequency))
            );
        }
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
                .iter()
                .filter_map(|b| decoder.decode_byte(*b).transpose())
                .collect::<io::Result<_>>()
                .unwrap();
            assert_eq!(decoded, plain);
            check_chunk_boundaries(decoder.config.clone(), role, &wire);
        }
    }

    #[test]
    #[ignore = "exports Rust wire samples for tests/fixtures/sudoku/xray.go -verify"]
    fn export_rust_wire_samples() {
        let mut samples: Vec<Sample> =
            serde_json::from_str(include_str!("../../tests/fixtures/sudoku/xray.json")).unwrap();
        for options in [
            json!({}),
            json!({"ascii":"ascii"}),
            json!({"custom_tables":["xpxvvpvv"]}),
            json!({"custom_tables":["", "xpxvvpvv", "vxpvxvvp"]}),
        ] {
            for padding in [0, 1, 10, 50, 99, 100] {
                let mut config = options.clone();
                config["password"] = json!("threshold-interop");
                config["padding_min"] = json!(padding);
                config["padding_max"] = json!(padding);
                for packed in [false, true] {
                    samples.push(Sample {
                        config: config.clone(),
                        packed,
                        plain: STANDARD
                            .encode((0..289).map(|i| (i * 37) as u8).collect::<Vec<_>>()),
                        wire: String::new(),
                    });
                }
            }
        }
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
                            .filter_map(|b| decoder.decode_byte(*b).transpose())
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
                let result = decoder.decode_byte(config.layouts[0].encode[*hint as usize]);
                assert_eq!(result.is_err(), i == 3);
            }
        }
        for byte in std::iter::once(0x7f).chain(0xc0..=0xff) {
            let mut decoder = Decoder::new(config.clone(), Role::Server);
            for _ in 0..3 {
                assert_eq!(decoder.decode_byte(byte).unwrap(), None);
            }
            assert!(decoder.decode_byte(byte).is_err());
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
        assert_eq!(decoder.decode_byte(wire[0]).unwrap(), None);
        assert_eq!(decoder.decode_byte(wire[1]).unwrap(), Some(0xab));
        assert_eq!(decoder.count, 4);
        decoder.decode_byte(wire[2]).unwrap();
        assert_eq!(decoder.count, 0);
        assert_eq!(decoder.layout, 0);
        let len = encoder.encode(&[0xcd, 0xef], &mut wire);
        assert_eq!(wire[len - 1], config.layouts[1].marker);
    }
}
