use std::fmt;

use bytes::{Buf, BufMut};

use crate::proto::coding::{self, BufExt, BufMutExt};

#[derive(Debug, PartialEq)]
pub enum Error {
    Overflow,
    UnexpectedEnd,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Overflow => write!(f, "value overflow"),
            Error::UnexpectedEnd => write!(f, "unexpected end"),
        }
    }
}

pub fn decode<B: Buf>(size: u8, buf: &mut B) -> Result<(u8, u64), Error> {
    assert!(size <= 8);
    let mut first = buf.get::<u8>()?;

    // NOTE: following casts to u8 intend to trim the most significant bits, they are used as a
    //       workaround for shiftoverflow errors when size == 8.
    let flags = ((first as usize) >> size) as u8;
    let mask = 0xFF >> (8 - size);
    first &= mask;

    // if first < 2usize.pow(size) - 1
    if first < mask {
        return Ok((flags, first as u64));
    }

    let mut value = mask as u64;
    let mut power = 0usize;
    loop {
        let byte = buf.get::<u8>()? as u64;
        value += (byte & 127) << power;
        power += 7;

        if byte & 128 == 0 {
            break;
        }

        if power >= MAX_POWER {
            return Err(Error::Overflow);
        }
    }

    Ok((flags, value))
}

pub fn encode<B: BufMut>(size: u8, flags: u8, value: u64, buf: &mut B) {
    assert!(size <= 8);
    // NOTE: following casts to u8 intend to trim the most significant bits, they are used as a
    //       workaround for shiftoverflow errors when size == 8.
    let mask = !(0xFF << size) as u8;
    let flags = ((flags as usize) << size) as u8;

    // if value < 2usize.pow(size) - 1
    if value < (mask as u64) {
        buf.write(flags | value as u8);
        return;
    }

    buf.write(mask | flags);
    let mut remaining = value - mask as u64;

    while remaining >= 128 {
        let rest = (remaining % 128) as u8;
        buf.write(rest + 128);
        remaining /= 128;
    }
    buf.write(remaining as u8);
}

const MAX_POWER: usize = 9 * 7;

impl From<coding::UnexpectedEnd> for Error {
    fn from(_: coding::UnexpectedEnd) -> Self {
        Error::UnexpectedEnd
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use std::io::Cursor;

    use crate::qpack::prefix_int::Error;

    fn check_codec(size: u8, flags: u8, value: u64, data: &[u8]) {
        let mut buf = Vec::new();
        super::encode(size, flags, value, &mut buf);
        assert_eq!(buf, data);
        let mut read = Cursor::new(&buf);
        assert_eq!((flags, value), super::decode(size, &mut read).unwrap());
    }

    #[test]
    fn codec_5_bits() {
        check_codec(5, 0b101, 10, &[0b1010_1010]);
        check_codec(5, 0b101, 0, &[0b1010_0000]);
        check_codec(5, 0b010, 1337, &[0b0101_1111, 154, 10]);
        check_codec(5, 0b010, 31, &[0b0101_1111, 0]);
        check_codec(
            5,
            0b010,
            0x80_00_00_00_00_00_00_1E,
            &[95, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        );
    }

    #[test]
    fn codec_8_bits() {
        check_codec(8, 0, 42, &[0b0010_1010]);
        check_codec(8, 0, 424_242, &[255, 179, 240, 25]);
        check_codec(
            8,
            0,
            0x80_00_00_00_00_00_00_FE,
            &[255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        );
    }

    #[test]
    #[should_panic]
    fn size_too_big_value() {
        let mut buf = vec![];
        super::encode(9, 1, 1, &mut buf);
    }

    #[test]
    #[should_panic]
    fn size_too_big_of_size() {
        let buf = vec![];
        let mut read = Cursor::new(&buf);
        super::decode(9, &mut read).unwrap();
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn overflow() {
        let buf = vec![255, 128, 254, 255, 255, 255, 255, 255, 255, 255, 255, 1];
        let mut read = Cursor::new(&buf);
        assert!(super::decode(8, &mut read).is_err());
    }

    #[test]
    fn number_never_ends_with_0x80() {
        check_codec(4, 0b0001, 143, &[31, 128, 1]);
    }
    #[test]
    fn overflow2() {
        let buf = vec![95, 225, 255, 255, 255, 255, 255, 255, 255, 255, 1];
        let mut read = Cursor::new(&buf);
        let x = super::decode(5, &mut read);
        assert_matches!(x, Err(Error::Overflow));
    }

    #[test]
    fn allow_62_bit() {
        // This is the maximum value that can be encoded in with a flag size of 7 bits
        // The value is requires more than 62 bits so the spec is fulfilled
        let buf = vec![3, 255, 255, 255, 255, 255, 255, 255, 255, 127];
        let mut read = Cursor::new(&buf);
        let (flag, value) = super::decode(1, &mut read).expect("Value is allowed to be parsed");
        assert_eq!(flag, 1);
        assert_eq!(value, 9223372036854775808);
    }
}
