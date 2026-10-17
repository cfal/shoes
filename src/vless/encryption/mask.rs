use std::io;

use super::crypto::Ctr;

/// Tracks only TLS-looking headers. DIRECT retains this exact state.
pub(crate) struct HeaderMask {
    ctr: Ctr,
    header: [u8; 5],
    filled: usize,
    skip: usize,
}

impl HeaderMask {
    pub(crate) fn new(material: &[u8], iv: &[u8; 16], skip: usize) -> io::Result<Self> {
        Ok(Self {
            ctr: Ctr::new(material, iv)?,
            header: [0; 5],
            filled: 0,
            skip,
        })
    }

    pub(crate) fn apply_write(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.apply(bytes, true)
    }

    pub(crate) fn apply_read(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.apply(bytes, false)
    }

    fn apply(&mut self, mut bytes: &mut [u8], writing: bool) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.skip != 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                bytes = &mut bytes[n..];
                continue;
            }
            let n = (5 - self.filled).min(bytes.len());
            let (header, tail) = bytes.split_at_mut(n);
            if writing {
                self.header[self.filled..self.filled + n].copy_from_slice(header);
            }
            self.ctr.apply(header)?;
            if !writing {
                self.header[self.filled..self.filled + n].copy_from_slice(header);
            }
            self.filled += n;
            if self.filled == 5 {
                // This is intentionally not the strict encrypted-record decoder.
                self.skip = if self.header[..3] == [0x17, 3, 3] {
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize
                } else {
                    0
                };
                self.filled = 0;
            }
            bytes = tail;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_headers_keep_ctr_position_and_skip_bodies() {
        let mut plaintext = vec![7; 16];
        for length in [5u16, 17, 31, 1, 55] {
            plaintext.extend_from_slice(&[0x17, 3, 3]);
            plaintext.extend_from_slice(&length.to_be_bytes());
            plaintext.extend(std::iter::repeat_n(0xa5, length as usize));
        }
        let mut expected = plaintext.clone();
        HeaderMask::new(&[1; 96], &[2; 16], 16)
            .unwrap()
            .apply_write(&mut expected)
            .unwrap();
        assert_eq!(&expected[..16], &plaintext[..16]);
        for split in 0..plaintext.len() {
            let mut actual = plaintext.clone();
            let mut writer = HeaderMask::new(&[1; 96], &[2; 16], 16).unwrap();
            writer.apply_write(&mut actual[..split]).unwrap();
            writer.apply_write(&mut actual[split..]).unwrap();
            assert_eq!(actual, expected);
            let mut reader = HeaderMask::new(&[1; 96], &[2; 16], 16).unwrap();
            for chunk in actual.chunks_mut(1) {
                reader.apply_read(chunk).unwrap();
            }
            assert_eq!(actual, plaintext);
        }
    }

    #[test]
    fn direct_masking_is_permissive() {
        for header in [
            [0x15, 3, 3, 0, 2],
            [0x17, 3, 3, 255, 255],
            [0x17, 3, 3, 0, 5],
        ] {
            let mut expected = header.to_vec();
            expected.extend_from_slice(&[9; 40]);
            for split in 0..expected.len() {
                let mut wire = expected.clone();
                let mut writer = HeaderMask::new(&[4; 96], &[5; 16], 0).unwrap();
                writer.apply_write(&mut wire[..split]).unwrap();
                writer.apply_write(&mut wire[split..]).unwrap();
                let mut reader = HeaderMask::new(&[4; 96], &[5; 16], 0).unwrap();
                for chunk in wire.chunks_mut(3) {
                    reader.apply_read(chunk).unwrap();
                }
                assert_eq!(wire, expected);
            }
        }
    }
}
