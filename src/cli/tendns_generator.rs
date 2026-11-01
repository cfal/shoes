use anyhow::{Context, Result, bail, ensure};
use tendns::{
    names::{canonical_name, validate_label},
    protocol::{self, Entry, Publication, Secret, Value},
    resolver::{Clock, SystemClock},
};
use zeroize::Zeroizing;

pub(super) fn generate(args: &[String]) -> Result<String> {
    let key = Zeroizing::new(
        std::env::var("TENDNS_KEY")
            .map_err(|_| anyhow::anyhow!("TENDNS_KEY must be set to an unpadded base64url key"))?,
    );
    generate_at(args, &key, SystemClock.now()?)
}

fn generate_at(args: &[String], encoded_key: &str, issued_at: u64) -> Result<String> {
    let key = Secret::decode(encoded_key).context("invalid TENDNS_KEY")?;
    let mut owner = None;
    let mut valid_for = None;
    let mut entries = Vec::new();
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .context("tendns generator option requires a value")?;
        match option.as_str() {
            "--name" if owner.is_none() => owner = Some(canonical_name(value)?),
            "--valid-for-secs" if valid_for.is_none() => {
                valid_for = Some(value.parse::<u64>().context("invalid --valid-for-secs")?);
            }
            "--entry" => entries.push(parse_entry(value)?),
            _ => bail!("unknown or repeated tendns generator option"),
        }
    }
    let owner = owner.context("--name is required")?;
    let valid_for = valid_for.unwrap_or(86_400);
    ensure!(valid_for > 0, "--valid-for-secs must be positive");
    let publication = Publication {
        issued_at,
        expires_at: issued_at
            .checked_add(valid_for)
            .context("expiry overflows timestamp")?,
        entries,
    };
    protocol::encrypt(&publication, &key, &owner)
}

fn parse_entry(text: &str) -> Result<Entry> {
    let mut parts = text.splitn(3, ':');
    let label = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let kind = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let value = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    Ok(Entry {
        subdomain: if label == "@" {
            String::new()
        } else {
            validate_label(label)?;
            label.to_ascii_lowercase()
        },
        value: match kind.to_ascii_uppercase().as_str() {
            "A" => Value::A(value.parse().context("invalid A address")?),
            "AAAA" => Value::Aaaa(value.parse().context("invalid AAAA address")?),
            "CNAME" => Value::Cname(canonical_name(value)?),
            _ => bail!("entry type must be A, AAAA, or CNAME"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

    fn generate(args: &str) -> Result<String> {
        generate_at(
            &args
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            KEY,
            100,
        )
    }

    #[test]
    fn generated_publication_roundtrips_all_entry_types_and_owner_binding() {
        let args = "--name Example.COM --entry NAS:a:192.0.2.7 --entry nas:AAAA:2001:db8::7 --entry web:CNAME:Service.TEST --entry @:A:192.0.2.8 --valid-for-secs 60";
        let txt = generate(args).unwrap();
        let key = Secret::decode(KEY).unwrap();
        let owner = canonical_name("example.com").unwrap();
        let publication = protocol::decrypt(txt.as_bytes(), &key, &owner, 100).unwrap();
        assert_eq!(publication.issued_at, 100);
        assert_eq!(publication.expires_at, 160);
        assert_eq!(
            publication.entries,
            vec![
                Entry {
                    subdomain: "nas".into(),
                    value: Value::A("192.0.2.7".parse().unwrap())
                },
                Entry {
                    subdomain: "nas".into(),
                    value: Value::Aaaa("2001:db8::7".parse().unwrap())
                },
                Entry {
                    subdomain: "web".into(),
                    value: Value::Cname(canonical_name("service.test").unwrap())
                },
                Entry {
                    subdomain: String::new(),
                    value: Value::A("192.0.2.8".parse().unwrap())
                },
            ]
        );
        assert_ne!(txt, generate(args).unwrap());
        assert!(!txt.contains(KEY));
        assert!(
            protocol::decrypt(
                txt.as_bytes(),
                &key,
                &canonical_name("other.test").unwrap(),
                100
            )
            .is_err()
        );
        assert!(protocol::decrypt(txt.as_bytes(), &key, &owner, 160).is_err());
        let txt = generate("--name example.com --entry @:A:192.0.2.7").unwrap();
        assert_eq!(
            protocol::decrypt(txt.as_bytes(), &key, &owner, 100)
                .unwrap()
                .expires_at,
            86_500
        );
    }

    #[test]
    fn rejects_invalid_options_entries_and_expiry() {
        for args in [
            "",
            "--name example.com",
            "--name",
            "--unknown value",
            "--name example.com --name other.test --entry @:A:192.0.2.7",
            "--name example.com --entry nas:A",
            "--name example.com --entry :A:192.0.2.7",
            "--name example.com --entry nas:MX:mail.test",
            "--name example.com --entry nas:A:2001:db8::1",
            "--name example.com --entry nas:AAAA:192.0.2.1",
            "--name example.com --entry bad.label:A:192.0.2.7",
            "--name example.com --entry @:A:192.0.2.7 --entry @:CNAME:other.test",
            "--name example.com --entry @:A:192.0.2.7 --valid-for-secs 0",
            "--name example.com --entry @:A:192.0.2.7 --valid-for-secs invalid",
            "--name example.com --entry @:A:192.0.2.7 --valid-for-secs 18446744073709551615",
            "--name example.com --entry @:A:192.0.2.7 --valid-for-secs 60 --valid-for-secs 120",
        ] {
            assert!(generate(args).is_err(), "{args}");
        }
        let key = "invalid-key-must-not-appear";
        let error = generate_at(&[], key, 100).unwrap_err();
        assert!(!format!("{error:#}").contains(key));
    }
}
