// CEP:FILE: ffi/src/ffi_math.rs
// CEP:WHAT: Extern libm declarations and runtime addresses for the math helpers called by emitted traces.
// CEP:WHY: design.md Part 6 routes math calls to shared implementations; the FFI boundary is isolated in the ffi tree and the addresses of the exported approximations feed absolute thunks in the code buffer so interpreter and JIT agree bit-for-bit.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: Returns None for unknown function ids; callers fail compilation deterministically.
// CEP:ASSUMES: the exported helpers follow the SysV double ABI with xmm0 argument and result registers.
// CEP:COST: one indirect-address thunk per call site; libm latency dominates.
// CEP:EVIDENCE: differential tests against the interpreter math builtin semantics.
// CEP:SECURITY: no untrusted pointers cross this boundary; only addresses of linked library symbols are taken.
// CEP:UNSAFE: extern declarations and address-of for linked symbols.

/// Returns the address of one math helper by SSL builtin id.
pub fn helper_address(fnid: u8) -> Option<usize> {
    match fnid {
        ssl_config::limits::MATH_ID_SIN => Some(ssl_hot::math_ffi::ssl_sin as usize),
        ssl_config::limits::MATH_ID_COS => Some(ssl_hot::math_ffi::ssl_cos as usize),
        ssl_config::limits::MATH_ID_SQRT => Some(ssl_hot::math_ffi::ssl_sqrt as usize),
        ssl_config::limits::MATH_ID_ABS => Some(ssl_hot::math_ffi::ssl_fabs as usize),
        ssl_config::limits::MATH_ID_FLOOR => Some(ssl_hot::math_ffi::ssl_floor as usize),
        _ => None,
    }
}
