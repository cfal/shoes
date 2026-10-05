use std::sync::OnceLock;

static NUM_THREADS: OnceLock<usize> = OnceLock::new();

pub fn set_num_threads(num_threads: usize) {
    let _ = NUM_THREADS.set(num_threads.max(1));
}

pub fn get_num_threads() -> usize {
    NUM_THREADS.get().copied().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn library_callers_have_a_nonzero_thread_default() {
        if std::env::var_os("SHOES_THREAD_DEFAULT_TEST_CHILD").is_some() {
            assert!(super::NUM_THREADS.get().is_none());
            assert_eq!(super::get_num_threads(), 1);
            super::set_num_threads(2);
            assert_eq!(super::get_num_threads(), 2);
        } else {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "thread_util::tests::library_callers_have_a_nonzero_thread_default",
                    "--quiet",
                ])
                .env("SHOES_THREAD_DEFAULT_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
        }
    }
}
