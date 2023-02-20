use once_cell::sync::OnceCell;

static NUM_THREADS: OnceCell<usize> = OnceCell::new();

pub fn set_num_threads(num_threads: usize) {
    NUM_THREADS.set(num_threads).unwrap();
}

pub fn get_num_threads() -> usize {
    *NUM_THREADS.get().unwrap()
}
