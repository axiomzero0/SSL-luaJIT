// CEP:FILE: hot/src/math_ffi.rs
// CEP:WHAT: FFI exports of the shared deterministic math builtins so the interpreter and emitted traces compute identical results.
// CEP:WHY: Differential testing (38.45) requires one implementation behind both execution paths; exporting the approximation functions gives emitted code call targets without pulling libm nondeterminism into the comparison.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: none; the wrappers cannot fail and never unwind.
// CEP:ASSUMES: the SysV double ABI passes arguments in xmm0 and returns in xmm0.
// CEP:COST: one function call plus the approximation cost documented in interp_step.
// CEP:EVIDENCE: differential tests interpreter versus JIT over the math corpus.
// CEP:SECURITY: FFI boundary; no pointers cross, only doubles.
// CEP:UNSAFE: none in this module; the exports are plain extern functions.

#[no_mangle]
pub extern "C" fn ssl_sin(x: f64) -> f64 {
    crate::interp_step::math_sin_public(x)
}

#[no_mangle]
pub extern "C" fn ssl_cos(x: f64) -> f64 {
    crate::interp_step::math_cos_public(x)
}

#[no_mangle]
pub extern "C" fn ssl_sqrt(x: f64) -> f64 {
    crate::interp_step::math_sqrt_public(x)
}

#[no_mangle]
pub extern "C" fn ssl_fabs(x: f64) -> f64 {
    crate::interp_step::math_fabs_public(x)
}

#[no_mangle]
pub extern "C" fn ssl_floor(x: f64) -> f64 {
    crate::interp_step::math_floor_public(x)
}
