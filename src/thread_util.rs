use std::sync::OnceLock;

static NUM_THREADS: OnceLock<usize> = OnceLock::new();

pub fn set_num_threads(num_threads: usize) {
    NUM_THREADS.set(num_threads).unwrap();
}

pub fn get_num_threads() -> usize {
    *NUM_THREADS.get().unwrap()
}
