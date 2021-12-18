#[inline]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

#[inline]
pub fn resize_vec<T>(v: &mut Vec<T>, required_len: usize) {
    let orig_len = v.len();
    let mut new_len = orig_len * 2;
    while new_len < required_len {
        new_len *= 2;
    }
    v.reserve(new_len - orig_len);
    unsafe {
        v.set_len(v.capacity());
    }
}
