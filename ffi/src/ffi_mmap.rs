// CEP:FILE: ffi/src/ffi_mmap.rs
// CEP:WHAT: POSIX mmap/mprotect FFI declarations and the write-xor-execute code memory manager built on them.
// CEP:WHY: Chapter 38.39 requires W^X enforcement, code cache bounds, and safe publication for JIT code; the boundary is isolated in the ffi tree with explicit validated calls.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: Returns FfiError::MapFailed or ProtectFailed from OS call failures; never panics and never unwinds across the boundary.
// CEP:ASSUMES: the target exposes POSIX mmap and mprotect with PROT_NONE, PROT_READ, PROT_WRITE, and PROT_EXEC; page size is queried at runtime, never assumed.
// CEP:COST: two syscalls per code region lifetime; no work on the hot path.
// CEP:EVIDENCE: ffi layout and lifecycle tests in tests; differential JIT execution runs through this manager.
// CEP:SECURITY: FFI boundary; page protections checked after every call; the region is never both writable and executable.
// CEP:UNSAFE: raw mmap, mprotect, and munmap calls with validated size and alignment arguments.
#![allow(non_camel_case_types)]

use ssl_config::limits as L;

/// Raw libc type aliases for the mmap family.
pub type c_int = i32;
/// Raw void pointer alias.
pub type c_void = u8;

/// PROT_NONE value from the POSIX header.
pub const PROT_NONE: c_int = 0;
/// PROT_READ value from the POSIX header.
pub const PROT_READ: c_int = 1;
/// PROT_WRITE value from the POSIX header.
pub const PROT_WRITE: c_int = 2;
/// PROT_EXEC value from the POSIX header.
pub const PROT_EXEC: c_int = 4;
/// MAP_PRIVATE value from the POSIX header.
pub const MAP_PRIVATE: c_int = 0x0002;
/// MAP_ANONYMOUS value from the POSIX header.
pub const MAP_ANONYMOUS: c_int = 0x0020;
/// MAP_FAILED sentinel from the POSIX header.
pub const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(addr: *mut c_void, length: usize, prot: c_int) -> c_int;
    fn munmap(addr: *mut c_void, length: usize) -> c_int;
    fn sysconf(name: c_int) -> i64;
}

/// sysconf name key for the page size.
const SC_PAGESIZE: c_int = 30;

/// Failure enumeration for the code memory manager.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum FfiError {
    /// mmap returned MAP_FAILED or the protection query failed.
    MapFailed,
    /// mprotect could not apply the requested protection.
    ProtectFailed,
    /// Requested size exceeds the configured code cache bound.
    TooLarge,
}

/// Queries the runtime page size; never hard-codes it (Law 7).
pub fn page_size() -> usize {
    let value = unsafe { sysconf(SC_PAGESIZE) };
    if value <= 0 {
        L::FALLBACK_PAGE_BYTES as usize
    } else {
        value as usize
    }
}

/// One executable code region: writable during emission, executable after sealing.
pub struct CodeMemory {
    base: *mut c_void,
    bytes: usize,
    used: usize,
}

impl CodeMemory {
    /// Creates a code region of at least the requested byte size, rounded up to pages.
    pub fn new(requested: usize) -> Result<CodeMemory, FfiError> {
        if requested > L::CODE_CACHE_BYTES as usize {
            return Err(FfiError::TooLarge);
        }
        let page = page_size();
        let mut bytes = requested.max(page) + page;
        bytes = ((bytes + page - 1) / page) * page;
        let base = unsafe {
            mmap(
                core::ptr::null_mut(),
                bytes,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == MAP_FAILED || base.is_null() {
            return Err(FfiError::MapFailed);
        }
        Ok(CodeMemory {
            base,
            bytes,
            used: 0,
        })
    }

    /// Byte offset where the next emission starts.
    pub fn cursor(&self) -> usize {
        self.used
    }

    /// Returns the writable stage as a byte slice; valid until seal.
    ///
    /// # Safety contract
    /// The region is mapped read-write until seal; the slice covers exactly the mapping.
    pub fn stage(&mut self) -> &mut [u8] {
        // SAFETY: base is a live mmap of self.bytes bytes in writable state pre-seal.
        let base = self.base as *mut u8;
        unsafe { core::slice::from_raw_parts_mut(base, self.bytes) }
    }

    /// Records the encoded byte count before sealing.
    pub fn mark_used(&mut self, used: usize) {
        self.used = used;
    }

    /// Absolute address of a byte offset inside the sealed region.
    pub fn address_at(&self, offset: usize) -> usize {
        (self.base as usize) + offset
    }

    /// Debug base pointer accessor.
    pub fn base_ptr(&self) -> *const c_void {
        self.base
    }

    /// Read-only view of the sealed region for disassembly evidence.
    pub fn bytes_view(&self) -> &[u8] {
        let base = self.base as *const u8;
        unsafe { core::slice::from_raw_parts(base, self.used) }
    }

    /// Reserves count bytes and returns the byte offset of the reservation.
    pub fn reserve(&mut self, count: usize) -> Result<usize, FfiError> {
        let next = self.used.checked_add(count).ok_or(FfiError::TooLarge)?;
        if next > self.bytes {
            return Err(FfiError::TooLarge);
        }
        let start = self.used;
        self.used = next;
        Ok(start)
    }

    /// Retargets bytes inside the sealed region: unseals, writes, reseals (section 38.40).
    pub fn retarget(&mut self, offset: usize, bytes: &[u8]) -> Result<(), FfiError> {
        if offset + bytes.len() > self.used {
            return Err(FfiError::TooLarge);
        }
        let page = page_size();
        let rounded = ((self.used + page - 1) / page) * page;
        let ok = unsafe { mprotect(self.base, rounded.max(page), PROT_READ | PROT_WRITE) };
        if ok != 0 {
            return Err(FfiError::ProtectFailed);
        }
        // SAFETY: offset validated against used bytes above.
        let target = unsafe { (self.base as *mut u8).add(offset) };
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), target, bytes.len());
        }
        let ok = unsafe { mprotect(self.base, rounded.max(page), PROT_READ | PROT_EXEC) };
        if ok != 0 {
            return Err(FfiError::ProtectFailed);
        }
        Ok(())
    }

    /// Flips the region to read-execute for safe publication (W^X seal).
    pub fn seal(&mut self) -> Result<(), FfiError> {
        let page = page_size();
        let rounded = ((self.used + page - 1) / page) * page;
        let result = unsafe { mprotect(self.base, rounded.max(page), PROT_READ | PROT_EXEC) };
        if result != 0 {
            return Err(FfiError::ProtectFailed);
        }
        Ok(())
    }

    /// Returns the raw base pointer for entry computation after sealing.
    pub fn base(&self) -> *mut c_void {
        self.base
    }

    /// Returns the sealed byte count.
    pub fn used_bytes(&self) -> usize {
        self.used
    }
}

impl Drop for CodeMemory {
    fn drop(&mut self) {
        if !self.base.is_null() {
            let ok = unsafe { munmap(self.base, self.bytes) };
            let _ = ok;
            self.base = core::ptr::null_mut();
        }
    }
}

const _: () = assert!(L::CODE_CACHE_BYTES >= ssl_config::limits::MAX_MIR_INSNS);
