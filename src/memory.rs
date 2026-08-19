//! Handing freed memory back to the operating system.
//!
//! Freeing an allocation does not shrink the process. Every general-purpose
//! allocator keeps the pages on a free list so the next allocation is cheap,
//! and none of them return spans eagerly — measured on the TUN stack, tearing
//! down 200 connections gave back none of the ~10 MiB they had touched.
//!
//! On a server that is correct behaviour and nobody notices. On a phone it is
//! the difference between an idle tunnel sitting at its floor and one sitting
//! at the high-water mark of the busiest thing the user did with it, which for
//! an iOS `NEPacketTunnelProvider` is measured against a hard ~50 MB limit that
//! kills rather than warns.
//!
//! Both mobile allocators can be asked to purge, and neither asks itself:
//! bionic's scudo takes `mallopt(M_PURGE_ALL)`, and Apple's libmalloc has
//! `malloc_zone_pressure_relief`. This is a slow call — it walks the heap — so
//! it belongs at a moment when nothing is in flight, which is why the only
//! caller is the tunnel shutdown path.

/// Ask the allocator to return what it is holding to the operating system.
///
/// A no-op where there is no such call, or nothing worth calling it for.
pub fn release_to_os() {
    #[cfg(target_os = "android")]
    {
        // M_PURGE_ALL, from bionic's malloc.h. Not in the libc crate, and the
        // numbering is bionic's own. M_PURGE (-101) purges only the calling
        // thread's arena; -104 covers every thread's, which is what a tunnel
        // that has just stopped several worker threads' worth of work wants.
        const M_PURGE_ALL: libc::c_int = -104;

        unsafe extern "C" {
            fn mallopt(param: libc::c_int, value: libc::c_int) -> libc::c_int;
        }

        // SAFETY: mallopt takes two ints and returns one; no memory is shared
        // with it. A parameter it does not recognise returns 0 and does
        // nothing, which is the failure mode on an older bionic.
        let purged = unsafe { mallopt(M_PURGE_ALL, 0) };
        log::debug!("mallopt(M_PURGE_ALL) returned {purged}");
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        unsafe extern "C" {
            fn malloc_zone_pressure_relief(
                zone: *mut std::ffi::c_void,
                goal_to_reclaim: usize,
            ) -> usize;
        }

        // SAFETY: a null zone means "every zone", and a goal of zero means
        // "reclaim as much as you can" — both documented in malloc/malloc.h.
        // It takes no ownership of anything of ours.
        let reclaimed = unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
        log::debug!("malloc_zone_pressure_relief reclaimed {reclaimed} bytes");
    }
}
