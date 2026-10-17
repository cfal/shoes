use std::{fmt, io, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, RngExt};
use zeroize::Zeroizing;

const PREFIX: &str = "mlkem768x25519plus";
const DEFAULT_PADDING: &str = "100-111-1111.75-0-111.50-0-3333";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Native,
    Xorpub,
    Random,
}

impl FromStr for Mode {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "xorpub" => Ok(Self::Xorpub),
            "random" => Ok(Self::Random),
            _ => Err(invalid("invalid VLESS encryption mode")),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Xorpub => "xorpub",
            Self::Random => "random",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lifetime {
    Scaled(u16),
    Range(u16, u16),
}

impl FromStr for Lifetime {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        let value = value.strip_suffix('s').unwrap_or(value);
        let number = |s: &str| -> io::Result<u16> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("invalid VLESS ticket lifetime"));
            }
            s.parse()
                .map_err(|_| invalid("VLESS ticket lifetime exceeds 65535 seconds"))
        };
        if let Some((min, max)) = value.split_once('-') {
            let (min, max) = (number(min)?, number(max)?);
            if min > max {
                return Err(invalid("VLESS ticket lifetime range is reversed"));
            }
            Ok(Self::Range(min, max))
        } else {
            Ok(Self::Scaled(number(value)?))
        }
    }
}

impl Lifetime {
    pub(crate) fn maximum(self) -> u16 {
        match self {
            Self::Scaled(max) | Self::Range(_, max) => max,
        }
    }

    pub(crate) fn sample(self, rng: &mut impl Rng) -> u16 {
        match self {
            Self::Scaled(max) => (u32::from(max) * rng.random_range(50..100) / 100) as u16,
            Self::Range(min, max) => sample_range(u32::from(min), u32::from(max), rng) as u16,
        }
    }
}

impl fmt::Display for Lifetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scaled(value) => write!(f, "{value}s"),
            Self::Range(min, max) => write!(f, "{min}-{max}s"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PaddingEntry {
    probability: u32,
    min: u32,
    max: u32,
}

fn sample_range(min: u32, max: u32, rng: &mut impl Rng) -> u32 {
    if max - min <= 1 {
        min
    } else {
        rng.random_range(min..max)
    }
}

impl PaddingEntry {
    fn sample(self, rng: &mut impl Rng) -> u32 {
        // Reference probability zero still selects one of the 100 outcomes.
        if self.probability >= rng.random_range(0..100) {
            sample_range(self.min, self.max, rng)
        } else {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Padding(Vec<PaddingEntry>);

pub(crate) struct PaddingSchedule {
    pub(crate) lengths: Vec<usize>,
    pub(crate) gaps: Vec<Duration>,
    pub(crate) total: usize,
}

impl Padding {
    fn parse(tokens: &[&str]) -> io::Result<Self> {
        let mut entries = Vec::with_capacity(tokens.len());
        let mut max_length = 0u32;
        let mut max_gap = 0u32;
        for (index, token) in tokens.iter().enumerate() {
            let error = || invalid(format!("invalid VLESS padding token {index}"));
            let mut fields = token.split('-');
            let mut next = || -> io::Result<u32> {
                let value = fields.next().ok_or_else(error)?;
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(error());
                }
                value.parse().map_err(|_| error())
            };
            let entry = PaddingEntry {
                probability: next()?,
                min: next()?,
                max: next()?,
            };
            if fields.next().is_some() || entry.probability > 100 || entry.min > entry.max {
                return Err(error());
            }
            if index == 0 && (entry.probability != 100 || entry.min < 35) {
                return Err(invalid(
                    "first VLESS padding length must be at least 35 with probability 100",
                ));
            }
            let total = if index % 2 == 0 {
                &mut max_length
            } else {
                &mut max_gap
            };
            *total = total.checked_add(entry.max).ok_or_else(error)?;
            entries.push(entry);
        }
        if entries.is_empty() || max_length > 65553 || max_gap > 30000 {
            return Err(invalid(
                "VLESS padding exceeds 65553 bytes or 30000 milliseconds",
            ));
        }
        Ok(Self(entries))
    }

    pub(crate) fn sample(&self, rng: &mut impl Rng) -> PaddingSchedule {
        // Sample lengths first, matching the reference's two separate lists.
        let lengths: Vec<usize> = self
            .0
            .iter()
            .step_by(2)
            .map(|e| e.sample(rng) as usize)
            .collect();
        let gaps = self
            .0
            .iter()
            .skip(1)
            .step_by(2)
            .map(|e| Duration::from_millis(u64::from(e.sample(rng))))
            .collect();
        let total = lengths.iter().sum();
        PaddingSchedule {
            lengths,
            gaps,
            total,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Side {
    Client,
    Server,
}

pub(crate) struct ParsedConfig {
    pub(crate) mode: Mode,
    pub(crate) padding: Padding,
    pub(crate) keys: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ParsedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedConfig")
            .field("mode", &self.mode)
            .field("padding", &self.padding)
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl ParsedConfig {
    fn parse(value: &str, side: Side) -> io::Result<(Self, &str)> {
        let tokens: Vec<&str> = value.split('.').collect();
        if tokens.len() < 4 || tokens[0] != PREFIX {
            return Err(invalid("invalid VLESS encryption prefix or missing keys"));
        }
        let mode = tokens[1].parse()?;
        let mut first_key = 3;
        while first_key < tokens.len() && tokens[first_key].len() < 20 {
            first_key += 1;
        }
        let padding = if first_key == 3 {
            Padding::parse(&DEFAULT_PADDING.split('.').collect::<Vec<_>>())?
        } else {
            Padding::parse(&tokens[3..first_key])?
        };
        if first_key == tokens.len() {
            return Err(invalid("VLESS encryption requires at least one key"));
        }
        let mut keys = Vec::new();
        for (index, token) in tokens[first_key..].iter().enumerate() {
            let error = || invalid(format!("invalid VLESS encryption key {index}"));
            let sizes = match side {
                Side::Client => [43, 1579],
                Side::Server => [43, 86],
            };
            if !sizes.contains(&token.len()) {
                return Err(error());
            }
            let key = Zeroizing::new(URL_SAFE_NO_PAD.decode(token).map_err(|_| error())?);
            keys.push(key);
        }
        Ok((
            Self {
                mode,
                padding,
                keys,
            },
            tokens[2],
        ))
    }

    pub(crate) fn client(value: &str) -> io::Result<(Self, bool)> {
        let (config, rtt) = Self::parse(value, Side::Client)?;
        let resume = match rtt {
            "0rtt" => true,
            "1rtt" => false,
            _ => return Err(invalid("VLESS encryption requires 0rtt or 1rtt")),
        };
        Ok((config, resume))
    }

    pub(crate) fn server(value: &str) -> io::Result<(Self, Lifetime)> {
        let (config, lifetime) = Self::parse(value, Side::Server)?;
        Ok((config, lifetime.parse()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn setting(mode: &str, rtt: &str, padding: &str, sizes: &[usize]) -> String {
        let mut value = format!("{PREFIX}.{mode}.{rtt}.");
        if !padding.is_empty() {
            value.push_str(padding);
            value.push('.');
        }
        value.push_str(
            &sizes
                .iter()
                .map(|n| URL_SAFE_NO_PAD.encode(vec![1; *n]))
                .collect::<Vec<_>>()
                .join("."),
        );
        value
    }

    #[test]
    fn all_modes_and_ordered_chains() {
        for mode in ["native", "xorpub", "random"] {
            for rtt in ["0rtt", "1rtt"] {
                let (parsed, resume) =
                    ParsedConfig::client(&setting(mode, rtt, "", &[32, 1184, 1184, 32])).unwrap();
                assert_eq!(resume, rtt == "0rtt");
                assert_eq!(parsed.mode.to_string(), mode);
                assert_eq!(
                    parsed.keys.iter().map(|k| k.len()).collect::<Vec<_>>(),
                    [32, 1184, 1184, 32]
                );
            }
            ParsedConfig::server(&setting(mode, "600", "100-35-35", &[32, 64, 64, 32])).unwrap();
        }
    }

    #[test]
    fn long_padding_tokens_are_rejected_as_keys_like_the_peers() {
        for length in 20..43 {
            let padding = format!("100-{}35-35", "0".repeat(length - 9));
            assert_eq!(padding.len(), length);
            assert!(ParsedConfig::client(&setting("native", "0rtt", &padding, &[32])).is_err());
            assert!(ParsedConfig::server(&setting("native", "600s", &padding, &[32])).is_err());
        }
    }

    #[test]
    fn lifetime_bounds_and_canonical_suffix() {
        for (input, expected) in [
            ("600", "600s"),
            ("600s", "600s"),
            ("10-600", "10-600s"),
            ("10-600s", "10-600s"),
            ("0", "0s"),
            ("0-0s", "0-0s"),
            ("65535", "65535s"),
            ("65535-65535s", "65535-65535s"),
        ] {
            assert_eq!(input.parse::<Lifetime>().unwrap().to_string(), expected);
        }
        for invalid in [
            "600-1s", "10-0s", "65536s", "1-65536s", "-1s", "+1s", "1ss", "1-2-3s", "", "s",
        ] {
            assert!(invalid.parse::<Lifetime>().is_err(), "{invalid}");
        }
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..1000 {
            assert!((300..600).contains(&Lifetime::Scaled(600).sample(&mut rng)));
            assert!((10..600).contains(&Lifetime::Range(10, 600).sample(&mut rng)));
            assert_eq!(Lifetime::Range(10, 10).sample(&mut rng), 10);
        }
    }

    #[test]
    fn padding_validation() {
        for valid in [
            "100-35-35",
            "100-65553-65553",
            "100-35-36.100-30000-30000",
            DEFAULT_PADDING,
        ] {
            assert!(
                Padding::parse(&valid.split('.').collect::<Vec<_>>()).is_ok(),
                "{valid}"
            );
        }
        for invalid in [
            "",
            "100-34-35",
            "99-35-35",
            "101-35-35",
            "100-1000-1",
            "100-35-35.100-2-1",
            "100-65554-65554",
            "100-35-35.100-70000-70000",
            "100-35-35.0-0-30000.0-0-1.0-0-1",
            "100-35-35-35",
            "100--35",
            "100-35-4294967296",
            "100-35-35..100-35-35",
        ] {
            assert!(
                Padding::parse(&invalid.split('.').collect::<Vec<_>>()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn padding_sampling_is_half_open_and_keeps_trailing_gaps() {
        let padding =
            Padding::parse(&["100-35-36", "100-10-10", "100-100-102", "100-0-1"]).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        for _ in 0..1000 {
            let schedule = padding.sample(&mut rng);
            assert_eq!(schedule.lengths[0], 35);
            assert!((100..102).contains(&schedule.lengths[1]));
            assert_eq!(schedule.total, schedule.lengths.iter().sum::<usize>());
            assert_eq!(schedule.gaps, [Duration::from_millis(10), Duration::ZERO]);
        }
        let zero = PaddingEntry {
            probability: 0,
            min: 35,
            max: 35,
        };
        assert!((0..1000).any(|_| zero.sample(&mut rng) == 35));
    }

    #[test]
    fn malformed_grammar_never_discloses_credentials() {
        let valid = setting("native", "0rtt", "", &[32]);
        for value in [
            valid.replace(PREFIX, "other"),
            valid.replace("native", "secret-mode"),
            valid.replace("0rtt", "secret-rtt"),
            format!("{valid}.100-35-35"),
            format!("{valid}."),
            setting("native", "0rtt", "", &[31]),
            setting("native", "0rtt", "", &[64]),
            format!("{valid}="),
        ] {
            let error = ParsedConfig::client(&value).unwrap_err().to_string();
            assert!(!error.contains("secret"));
            assert!(!error.contains(&URL_SAFE_NO_PAD.encode([1; 32])));
        }
        assert!(ParsedConfig::server(&setting("native", "600s", "", &[1184])).is_err());
        let (config, _) = ParsedConfig::client(&valid).unwrap();
        assert!(!format!("{config:?}").contains(&URL_SAFE_NO_PAD.encode([1; 32])));
    }
}
