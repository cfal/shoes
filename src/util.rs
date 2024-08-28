#[inline]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    let _remaining = ret.spare_capacity_mut();
    unsafe {
        ret.set_len(len);
    }
    ret
}
