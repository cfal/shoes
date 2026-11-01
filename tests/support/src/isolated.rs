use std::process::{Command, Output};

/// Runs exactly one test in a child with an isolated environment marker.
pub fn run_isolated(name: &str, variable: &str, value: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(variable, value)
        .output()
        .unwrap();
    assert_one_test_passed(&output);
}

/// Rejects successful libtest exits that did not execute the requested test.
pub fn assert_one_test_passed(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated child failed: {}",
        output.status
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
        "isolated child did not run exactly one test"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_exact_child() {
        const CHILD: &str = "SHOES_ISOLATED_RUNNER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            run_isolated("isolated::tests::runs_exact_child", CHILD, "present");
            return;
        }
        assert_eq!(std::env::var(CHILD).unwrap(), "present");
    }

    #[test]
    #[should_panic(expected = "isolated child did not run exactly one test")]
    fn rejects_empty_filter() {
        run_isolated(
            "isolated::tests::nonexistent_test",
            "SHOES_ISOLATED_EMPTY_CHILD",
            "1",
        );
    }

    #[test]
    fn rejects_failed_child() {
        const CHILD: &str = "SHOES_ISOLATED_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            panic!("intentional child failure");
        }
        let panic = std::panic::catch_unwind(|| {
            run_isolated("isolated::tests::rejects_failed_child", CHILD, "1");
        })
        .expect_err("failed child was accepted");
        assert!(
            panic
                .downcast_ref::<String>()
                .unwrap()
                .contains("isolated child failed:")
        );
    }
}
