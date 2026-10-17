use std::io;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use super::{
    ClientEncryption, ServerEncryption,
    config::{Lifetime, Mode},
    keys::ServerKey,
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(crate) fn generate(args: &[String]) -> io::Result<(String, Zeroizing<String>)> {
    let mut auth = Vec::new();
    let mut mode = None;
    let mut rtt = None;
    let mut lifetime = None;
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| invalid("VLESS generator option requires a value"))?;
        match option.as_str() {
            "--auth" => match value.as_str() {
                "x25519" => auth.push(32),
                "mlkem768" => auth.push(64),
                _ => return Err(invalid("--auth must be x25519 or mlkem768")),
            },
            "--mode" if mode.is_none() => mode = Some(value.parse::<Mode>()?),
            "--rtt" if rtt.is_none() => match value.as_str() {
                "0rtt" | "1rtt" => rtt = Some(value.as_str()),
                _ => return Err(invalid("--rtt must be 0rtt or 1rtt")),
            },
            "--lifetime" if lifetime.is_none() => lifetime = Some(value.parse::<Lifetime>()?),
            _ => return Err(invalid("unknown or repeated VLESS generator option")),
        }
    }
    let mode = mode.unwrap_or(Mode::Native);
    let rtt = rtt.unwrap_or("0rtt");
    let lifetime = lifetime.unwrap_or(Lifetime::Scaled(600));
    if (rtt == "0rtt") != (lifetime.maximum() != 0) {
        return Err(invalid(
            "use --rtt 1rtt with --lifetime 0s, or --rtt 0rtt with a positive lifetime",
        ));
    }
    if auth.is_empty() {
        auth.push(64);
    }
    let mut encryption = format!("mlkem768x25519plus.{mode}.{rtt}");
    let mut decryption = Zeroizing::new(format!("mlkem768x25519plus.{mode}.{lifetime}"));
    for len in auth {
        let mut secret = Zeroizing::new(vec![0; len]);
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| io::Error::other("VLESS key generation failed"))?;
        let key = ServerKey::new(&secret)?;
        encryption.push('.');
        encryption.push_str(&URL_SAFE_NO_PAD.encode(&key.public));
        decryption.push('.');
        URL_SAFE_NO_PAD.encode_string(&*secret, &mut decryption);
    }
    ClientEncryption::new(&encryption)?;
    ServerEncryption::new(&decryption, Default::default())?;
    Ok((encryption, decryption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn generated_ordered_chains_exchange_in_every_mode() {
        for mode in ["native", "xorpub", "random"] {
            for auth in [
                vec![],
                vec!["x25519"],
                vec!["x25519", "mlkem768", "mlkem768", "x25519"],
            ] {
                let mut args = vec!["--mode".to_owned(), mode.to_owned()];
                for key in &auth {
                    args.extend(["--auth".to_owned(), (*key).to_owned()]);
                }
                let (encryption, decryption) = generate(&args).unwrap();
                let (parsed, _) = super::super::config::ParsedConfig::server(&decryption).unwrap();
                assert_eq!(
                    parsed.keys.iter().map(|k| k.len()).collect::<Vec<_>>(),
                    if auth.is_empty() {
                        vec![64]
                    } else {
                        auth.iter()
                            .map(|k| if *k == "x25519" { 32 } else { 64 })
                            .collect()
                    }
                );
                let client = ClientEncryption::new(&encryption).unwrap();
                let server = ServerEncryption::new(&decryption, Default::default()).unwrap();
                let (a, b) = tokio::io::duplex(64);
                let (written, read) = tokio::join!(
                    async {
                        let mut a = client.handshake(a).await?;
                        a.write_all(b"generated").await?;
                        a.flush().await?;
                        a.read_u8().await
                    },
                    async {
                        let mut b = server.handshake(b).await?;
                        let mut bytes = [0; 9];
                        b.read_exact(&mut bytes).await?;
                        b.write_all(&[1]).await?;
                        b.flush().await?;
                        Ok::<_, io::Error>(bytes)
                    }
                );
                written.unwrap();
                assert_eq!(&read.unwrap(), b"generated");
            }
        }
    }

    #[test]
    fn generator_rejects_ambiguous_options() {
        for args in [
            "--auth unknown",
            "--mode bad",
            "--rtt bad",
            "--lifetime 5-1s",
            "--rtt 1rtt",
            "--lifetime 0s",
            "--mode native --mode random",
            "--auth",
            "--unknown no",
            "--rtt 0rtt --rtt 1rtt",
        ] {
            assert!(
                generate(
                    &args
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                )
                .is_err(),
                "{args}"
            );
        }
        let (client, server) =
            generate(&["--rtt", "1rtt", "--lifetime", "0s"].map(str::to_owned)).unwrap();
        assert!(client.contains(".1rtt."));
        assert!(server.contains(".0s."));
    }
}
