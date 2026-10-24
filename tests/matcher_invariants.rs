use shoes::rules::{Compiler, Expression, Outcome};

// Fixed generator and seed make failures independent of rand crate versions.
fn next_port(state: &mut u64) -> u16 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*state >> 32) as u16
}

#[test]
fn port_range_union_matches_linear_oracle_and_boolean_composition() {
    let mut seed = 0x0051_10e5_2026_u64;
    for case in 0..128 {
        let mut ranges = Vec::new();
        for _ in 0..32 {
            let start = next_port(&mut seed);
            let end = start.saturating_add(next_port(&mut seed) % 256);
            ranges.push((start, end));
        }
        ranges.extend([(0, 0), (u16::MAX, u16::MAX), ranges[0]]);
        let expression = Expression::PortRanges(ranges.clone());
        let predicate = Compiler::default().compile(expression.clone()).unwrap();
        let inverted = Compiler::default()
            .compile(Expression::Not(Box::new(expression.clone())))
            .unwrap();
        let combined = Compiler::default()
            .compile(Expression::All(vec![
                expression.clone(),
                Expression::Any(vec![expression, Expression::Never]),
            ]))
            .unwrap();
        let queries = ranges
            .iter()
            .flat_map(|&(start, end)| [start.saturating_sub(1), start, end, end.saturating_add(1)])
            .chain((0..256).map(|_| next_port(&mut seed)));
        for port in queries {
            let matches = ranges
                .iter()
                .any(|&(start, end)| start <= port && port <= end);
            let (expected, inverted_expected) = if matches {
                (Outcome::Match, Outcome::Miss)
            } else {
                (Outcome::Miss, Outcome::Match)
            };
            assert_eq!(
                predicate.evaluate(None, None, port),
                expected,
                "case={case} port={port}"
            );
            assert_eq!(
                combined.evaluate(None, None, port),
                expected,
                "case={case} port={port}"
            );
            assert_eq!(
                inverted.evaluate(None, None, port),
                inverted_expected,
                "case={case} port={port}"
            );
        }
    }
}
