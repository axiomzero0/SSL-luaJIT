# SSL-LuaJIT vs LuaJIT 2.1 benchmark

- runs per point: 7 (minimum kept), noop baseline subtracted
- noop baselines (s): ssljit-jit=0.0007, ssljit-interp=0.0008, luajit-jit=0.0006, luajit-interp=0.0006
- cross-VM numeric agreement: PASS
- jit engagement (traces>=1 in ssljit-jit): FAIL: mandel: traces=0 in jit mode; table_sum: traces=0 in jit mode; math_sin: traces=0 in jit mode
- KNOWN ISSUE (table_rw): read-modify-write through the traced table path: the machine trace computes t[i]+1 but the slot-backed store pipeline still miscompiles (t[1023] stays 1023); tracked as an open backend issue, timing reported for reference only
- KNOWN ISSUE (branch_mix): branchy loop with a loop-carried accumulator through the slot-backed store pipeline: the compiled trace reports 171 instead of 100 (same phi/slot-store family as table_rw); timing reported for reference only
- math_sin finite on all VMs: yes (values differ by design)

| program | ssljit-jit (s) | ssljit-interp (s) | luajit-jit (s) | luajit-interp (s) | JIT vs own interp | luajit-jit advantage |
|---|---|---|---|---|---|---|
| sum_int | 0.010 | 0.328 | 0.002 | 0.020 | 33.48x | 0.18x |
| fib_iloop | 0.352 | 0.259 | 0.001 | 0.025 | 0.73x | 0.00x |
| mandel | 0.502 | 0.504 | 0.003 | 0.051 | 1.00x | 0.00x |
| table_sum | 0.264 | 0.270 | 0.001 | 0.019 | 1.02x | 0.00x |
| table_rw | 0.177 | 0.162 | 0.001 | 0.018 | 0.91x | 0.00x |
| global_rw | 0.012 | 0.325 | 0.002 | 0.051 | 27.30x | 0.15x |
| math_sin | 0.101 | 0.102 | 0.002 | 0.008 | 1.01x | 0.01x |
| branch_mix | 0.562 | 0.446 | 0.012 | 0.038 | 0.79x | 0.02x |
