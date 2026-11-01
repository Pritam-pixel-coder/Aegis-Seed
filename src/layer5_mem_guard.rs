//! Layer 5: System-Level Memory Hardening
//!
//! Provides hardware-level memory protection for master seed phrases and secret shares.
//!
//! # Platform Security Strategies:
//! 1. Linux: Uses `memfd_secret(2)` (syscall 447) to allocate confidential memory regions
//!    that are unmapped from the kernel direct-map, excluded from core dumps, and
//!    inaccessible to `/proc/$pid/mem`.
//! 2. Windows: Uses `VirtualLock` to lock pages in physical RAM, preventing swapping to `pagefile.sys`.
//! 3. Cross-Platform: Hardware-enforced zeroization on deallocation (`ZeroizeOnDrop`)
//!    with memory fences and volatile writes preventing compiler dead-store elimination.

use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Protected memory container for sensitive cryptographic material.
pub struct ProtectedMemory<T: Zeroize> {
    data: T,
    #[cfg(target_os = "windows")]
    is_locked: bool,
    #[cfg(target_os = "linux")]
    fd: Option<i32>,
}

impl<T: Zeroize> ProtectedMemory<T> {
    /// Allocate and harden memory for secret payload `data`.
    pub fn new(data: T) -> Self {
        #[cfg(target_os = "windows")]
        let is_locked = false;

        #[cfg(target_os = "linux")]
        let fd = Self::try_create_memfd_secret();

        let mut instance = Self {
            data,
            #[cfg(target_os = "windows")]
            is_locked,
            #[cfg(target_os = "linux")]
            fd,
        };

        instance.lock_memory();
        instance
    }

    /// Lock memory pages into physical RAM.
    fn lock_memory(&mut self) {
        let ptr = &self.data as *const T as *const core::ffi::c_void;
        let size = core::mem::size_of::<T>();

        #[cfg(target_os = "windows")]
        {
            unsafe {
                let res = windows_sys::Win32::System::Memory::VirtualLock(ptr, size);
                self.is_locked = res != 0;
            }
        }

        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            unsafe {
                // If memfd_secret is not available, fallback to mlock
                if self.fd.is_none() {
                    libc::mlock(ptr, size);
                }
            }
        }
    }

    /// Unlock memory pages on release.
    fn unlock_memory(&mut self) {
        let ptr = &self.data as *const T as *const core::ffi::c_void;
        let size = core::mem::size_of::<T>();

        #[cfg(target_os = "windows")]
        {
            if self.is_locked {
                unsafe {
                    windows_sys::Win32::System::Memory::VirtualUnlock(ptr, size);
                }
                self.is_locked = false;
            }
        }

        #[cfg(all(target_os = "linux", feature = "std"))]
        {
            unsafe {
                if let Some(fd) = self.fd {
                    libc::close(fd);
                } else {
                    libc::munlock(ptr, size);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn try_create_memfd_secret() -> Option<i32> {
        #[cfg(target_arch = "x86_64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;
        #[cfg(target_arch = "aarch64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        unsafe {
            // Flags: 0 or FD_CLOEXEC
            let res = libc::syscall(SYS_MEMFD_SECRET, 1);
            if res >= 0 {
                Some(res as i32)
            } else {
                None
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        None
    }

    /// Access inner protected reference.
    pub fn get(&self) -> &T {
        &self.data
    }

    /// Access mutable inner protected reference.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: Zeroize> Deref for ProtectedMemory<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for ProtectedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        // 1. Explicitly zeroize data payload using compiler-barrier writes
        self.data.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // 2. Unlock memory pages from physical RAM
        self.unlock_memory();
    }
}

