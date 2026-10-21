use std::cell::Cell;
use std::io;

use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::TScalarStyle;

use super::YAML_PARSER_SCRATCH_BYTES as PARSER_SCRATCH;
use crate::rules::{Compiler, MAX_STRING_BYTES, invalid};

const READ_AHEAD: usize = 128 * 1024;

pub(super) fn decode(bytes: &[u8], budget: &mut Compiler) -> io::Result<Vec<String>> {
    budget.charge(PARSER_SCRATCH, 0)?;
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid UTF-8 provider"))?;
    if text.chars().any(|c| {
        matches!(c, '\0'..='\u{8}' | '\u{b}'..='\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}'..='\u{84}' | '\u{86}'..='\u{9f}')
    }) {
        return Err(invalid("invalid YAML control character"));
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let remaining = Cell::new(READ_AHEAD);
    let exceeded = Cell::new(false);
    let mut chars = text.chars();
    // The scanner can buffer complex keys before emitting an event. Bound input
    // consumed per event as well as the entries retained by this decoder.
    let input = std::iter::from_fn(|| {
        if exceeded.get() {
            return None;
        }
        let ch = chars.next()?;
        let Some(left) = remaining.get().checked_sub(ch.len_utf8()) else {
            exceeded.set(true);
            return None;
        };
        remaining.set(left);
        Some(ch)
    });
    let mut parser = Parser::new(input);
    let mut next = || -> io::Result<Event> {
        remaining.set(READ_AHEAD);
        let result = parser.next_token();
        if exceeded.get() {
            return Err(invalid("YAML parser read-ahead exceeds 128 KiB"));
        }
        result
            .map(|(event, _)| event)
            .map_err(|e| invalid(format!("Mihomo YAML: {e}")))
    };
    for expected in [
        Event::StreamStart,
        Event::DocumentStart,
        Event::MappingStart(0, None),
    ] {
        expect(next()?, expected)?;
    }
    match next()? {
        Event::Scalar(key, _, 0, None) if key == "payload" => {}
        _ => return Err(invalid("Mihomo YAML requires a payload field")),
    }
    expect(next()?, Event::SequenceStart(0, None))?;
    let mut entries = Vec::new();
    loop {
        match next()? {
            Event::SequenceEnd => break,
            Event::Scalar(value, style, 0, None) => {
                if value.len() > MAX_STRING_BYTES {
                    return Err(invalid("provider entry exceeds 64 KiB"));
                }
                // Preserve YAML's distinction between plain numbers/bools/null
                // and strings. Only this bounded scalar goes through serde_yaml.
                if style == TScalarStyle::Plain
                    && !matches!(
                        serde_yaml::from_str::<serde_yaml::Value>(&value),
                        Ok(serde_yaml::Value::String(_))
                    )
                {
                    return Err(invalid("Mihomo payload entries must be strings"));
                }
                budget.charge(value.capacity().saturating_mul(4).saturating_add(256), 1)?;
                entries.push(value);
            }
            _ => {
                return Err(invalid(
                    "Mihomo payload requires untagged strings without aliases",
                ));
            }
        }
    }
    for expected in [Event::MappingEnd, Event::DocumentEnd, Event::StreamEnd] {
        expect(next()?, expected)?;
    }
    Ok(entries)
}

fn expect(actual: Event, expected: Event) -> io::Result<()> {
    if actual != expected {
        return Err(invalid(
            "Mihomo YAML requires one mapping containing only a payload sequence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_and_flow_providers_preserve_string_values() {
        for text in [
            "payload: [example.com, '*.Example.com', \"123\"]",
            "\u{feff}---\npayload:\n  - example.com # comment\n  - '*.Example.com'\n  - \"123\"\n...\n",
        ] {
            assert_eq!(
                decode(text.as_bytes(), &mut Compiler::default()).unwrap(),
                ["example.com", "*.Example.com", "123"]
            );
        }
        assert!(
            decode(b"payload: []", &mut Compiler::default())
                .unwrap()
                .is_empty()
        );
        let entry = "a".repeat(64 * 1024);
        assert_eq!(
            decode(
                format!("payload: ['{entry}']").as_bytes(),
                &mut Compiler::default()
            )
            .unwrap(),
            [entry]
        );
    }

    #[test]
    fn rejects_non_string_entries_and_extra_structure() {
        for text in [
            "payload: [123]",
            "payload: [true]",
            "payload: [null]",
            "payload: [[]]",
            "payload: [{}]",
            "payload: [!tag name]",
            "payload: [&a name, *a]",
            "payload: []\nextra: []",
            "payload: []\npayload: []",
            "payload: []\n---\npayload: []",
            "payload: []\0junk",
        ] {
            assert!(
                decode(text.as_bytes(), &mut Compiler::default()).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn dense_flow_input_is_not_buffered_as_a_document() {
        let nested = format!("payload: [{}]", "[],".repeat(350_000));
        assert!(
            decode(nested.as_bytes(), &mut Compiler::default())
                .unwrap_err()
                .to_string()
                .contains("untagged strings")
        );
        let entries = format!("payload: [{}]", "a,".repeat(350_000));
        let mut budget = Compiler::default();
        budget
            .charge(512 * 1024 * 1024 - PARSER_SCRATCH - 4096, 0)
            .unwrap();
        assert!(
            decode(entries.as_bytes(), &mut budget)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        for text in [
            format!("{{[{}]: a}}", "a,".repeat(350_000)),
            format!("payload: ['{}']", "a".repeat(1_000_000)),
        ] {
            assert!(
                decode(text.as_bytes(), &mut Compiler::default())
                    .unwrap_err()
                    .to_string()
                    .contains("read-ahead")
            );
        }
    }
}
