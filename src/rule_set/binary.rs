use std::io;

use crate::rules::{Compiler, MAX_ENTRIES, MAX_STRING_BYTES, invalid};

pub(super) const MAX_INFLATED: usize = 256 * 1024 * 1024;

pub(super) fn inflate(bytes: &[u8], budget: &mut Compiler) -> io::Result<Vec<u8>> {
    budget.charge(128 * 1024, 0)?;
    let mut decoder = flate2::Decompress::new(true);
    let mut result = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let input = decoder.total_in() as usize;
        let output = decoder.total_out();
        let status = decoder
            .decompress(&bytes[input..], &mut chunk, flate2::FlushDecompress::None)
            .map_err(|e| invalid(format!("invalid zlib stream: {e}")))?;
        let written = (decoder.total_out() - output) as usize;
        append_inflated(&mut result, &chunk[..written], budget)?;
        if status == flate2::Status::StreamEnd {
            if decoder.total_in() as usize != bytes.len() {
                return Err(invalid("trailing compressed rule-set bytes"));
            }
            return Ok(result);
        }
        if decoder.total_in() as usize == input && written == 0 {
            return Err(invalid("truncated zlib stream"));
        }
    }
}

pub(super) fn append_inflated(
    output: &mut Vec<u8>,
    bytes: &[u8],
    budget: &mut Compiler,
) -> io::Result<()> {
    let len = output
        .len()
        .checked_add(bytes.len())
        .filter(|&len| len <= MAX_INFLATED)
        .ok_or_else(|| invalid("inflated rule-set size limit exceeded"))?;
    if len > output.capacity() {
        let capacity = len.max(output.capacity() * 2).min(MAX_INFLATED);
        // Keep prior capacity charges until source compilation ends, covering
        // old and new buffers during a moving reallocation.
        budget.charge(capacity, 0)?;
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(io::Error::other)?;
    }
    output.extend_from_slice(bytes);
    Ok(())
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    budget: &'a mut Compiler,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], budget: &'a mut Compiler) -> Self {
        Self {
            bytes,
            pos: 0,
            budget,
        }
    }
    pub fn charge(&mut self, bytes: usize) -> io::Result<()> {
        self.budget.charge(bytes, 0)
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if len > self.remaining() {
            return Err(invalid("truncated rule-set payload"));
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
    pub fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn boolean(&mut self) -> io::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid boolean byte")),
        }
    }
    pub fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn varint(&mut self) -> io::Result<u64> {
        let mut value = 0;
        for shift in (0..=63).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return Err(invalid("varint overflow"));
            }
            value |= u64::from(b & 127) << shift;
            if b < 128 {
                return Ok(value);
            }
        }
        Err(invalid("varint overflow"))
    }
    pub fn count(&mut self, fixed: bool, max: usize, width: usize) -> io::Result<usize> {
        let value = if fixed { self.u64()? } else { self.varint()? };
        let value = usize::try_from(value).map_err(|_| invalid("invalid count"))?;
        if value > max || value > self.remaining() / width.max(1) {
            return Err(invalid("negative, oversized or truncated count"));
        }
        Ok(value)
    }
    pub fn strings(&mut self) -> io::Result<Vec<String>> {
        let count = self.count(false, MAX_ENTRIES, 1)?;
        self.budget.charge(count * 32, count)?;
        let mut strings = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.count(false, MAX_STRING_BYTES, 1)?;
            self.charge(len * 2)?;
            let string = String::from_utf8(self.take(len)?.to_vec())
                .map_err(|_| invalid("invalid UTF-8 rule string"))?;
            strings.push(string);
        }
        Ok(strings)
    }
    pub fn end(&self) -> io::Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(invalid("trailing rule-set payload"))
        }
    }

    pub fn domain_keys(&mut self, mrs: bool) -> io::Result<Vec<String>> {
        if self.byte()? != u8::from(mrs) {
            return Err(invalid("unsupported domain-set encoding version"));
        }
        let words = |r: &mut Self| -> io::Result<Vec<u64>> {
            let len = r.count(mrs, MAX_INFLATED / 8, 8)?;
            r.charge(len * 8)?;
            let mut words = Vec::with_capacity(len);
            for _ in 0..len {
                words.push(r.u64()?);
            }
            Ok(words)
        };
        let leaves = words(self)?;
        let bitmap = words(self)?;
        let len = self.count(mrs, MAX_INFLATED / 16, 1)?;
        let labels = self.take(len)?;
        if !labels.is_ascii() {
            return Err(invalid("domain-set keys require ASCII A-label spelling"));
        }
        let nodes = labels.len() + 1;
        if bitmap.len() > (2 * nodes).div_ceil(64) || leaves.len() > nodes.div_ceil(64) {
            return Err(invalid("oversized domain bitmap padding"));
        }
        let bit =
            |words: &[u64], i: usize| words.get(i / 64).is_some_and(|w| w & (1 << (i % 64)) != 0);
        // The wire format numbers nodes breadth-first. Each zero is an edge;
        // each one ends a node's children. No rank/select matcher is needed.
        self.charge(nodes * 4)?;
        let mut parents = vec![0u32; nodes];
        let mut next = 1;
        let mut cursor = 0;
        for parent in 0..nodes {
            if parent >= next {
                return Err(invalid("disconnected domain trie"));
            }
            let mut previous = None;
            loop {
                if cursor >= bitmap.len() * 64 {
                    return Err(invalid("truncated domain bitmap"));
                }
                let terminal = bit(&bitmap, cursor);
                cursor += 1;
                if terminal {
                    break;
                }
                if next >= nodes {
                    return Err(invalid("too many domain edges"));
                }
                let label = labels[next - 1];
                if previous.is_some_and(|p| p >= label) {
                    return Err(invalid("unordered or duplicate domain edges"));
                }
                previous = Some(label);
                parents[next] = parent as u32;
                next += 1;
            }
        }
        if next != nodes
            || (cursor..bitmap.len() * 64).any(|i| bit(&bitmap, i))
            || (nodes..leaves.len() * 64).any(|i| bit(&leaves, i))
        {
            return Err(invalid("inconsistent domain bitmap or terminal padding"));
        }
        let mut keys = Vec::new();
        let mut total = 0usize;
        for node in 0..nodes {
            if !bit(&leaves, node) {
                continue;
            }
            if keys.len() == MAX_ENTRIES {
                return Err(invalid("domain entry limit exceeded"));
            }
            self.budget.charge(576, 1)?;
            let mut key = Vec::new();
            let mut n = node;
            // Walking terminal to root reverses the encoded key, recovering the
            // original ASCII domain (with any source-specific prefix marker).
            while n != 0 {
                if key.len() == 256 {
                    return Err(invalid("oversized domain trie key"));
                }
                key.push(labels[n - 1]);
                n = parents[n] as usize;
            }
            total += key.len();
            if total > MAX_INFLATED {
                return Err(invalid("domain enumeration budget exceeded"));
            }
            keys.push(String::from_utf8(key).map_err(|_| invalid("invalid domain key"))?);
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflation_growth_is_admitted_before_reallocation() {
        let mut budget = Compiler::default();
        budget.charge(512 * 1024 * 1024 - 20 * 1024, 0).unwrap();
        let mut output = Vec::new();
        append_inflated(&mut output, &[0; 8192], &mut budget).unwrap();
        assert_eq!(output.capacity(), 8192);
        assert!(
            append_inflated(&mut output, &[0], &mut budget)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        assert_eq!(output.len(), 8192);
        assert_eq!(output.capacity(), 8192);
    }

    #[test]
    fn counted_strings_allocate_only_the_charged_slots() {
        let mut bytes = vec![9];
        bytes.extend_from_slice(&[1, b'a'].repeat(9));
        let mut budget = Compiler::default();
        let strings = Reader::new(&bytes, &mut budget).strings().unwrap();
        assert_eq!(strings.len(), 9);
        assert_eq!(strings.capacity(), 9);
    }
}
