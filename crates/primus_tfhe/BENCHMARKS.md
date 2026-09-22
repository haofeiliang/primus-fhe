# Common PBS benchmark workloads

The four backend `pbs` benches share the geometry in
[`benchmark.rs`](../../test-support/tfhe/src/benchmark.rs). They exercise both
`u32` and `u64`; Fourier runs RustFFT and TfheFFT. These are reproducible
performance fixtures, not production security parameters.

| Workload | Small LWE dimension `n` | Polynomial length `N` | GLWE dimension `k` | Plaintext modulus `t` | Padded input domain |
| --- | ---: | ---: | ---: | ---: | --- |
| `boolean` | 800 | 1024 | 1 | 4 | 0–1 |
| `shortint_2_2` | 866 | 2048 | 1 | 32 | 0–15 |

The Boolean geometry retains the previous NTRU workload and gives GLWE the same
`n` and `N`. The second workload represents two message bits plus two carry bits
and a padding bit. It measures a 16-entry LUT; it does not implement a shortint
arithmetic API or carry tracking. Both measure complete PBS. Boolean also
measures AND, MUX, and 3/4-output interleaved PBS against separate calls.
GLWE measures BR and KS separately in both orders (`pbs_ks`, `ks_pbs`); NTRU
also measures server-key generation and binary/ternary input keys. NTRU's
multi-output comparison uses binary keys.

The `shortint_2_2` profile measures single-output PBS. Four interleaved lanes
coarsen rotation quantization by four; `n=866, N=2048, t=32` did not pass the
full-input-domain check with that geometry. Multi-output shortint needs its own
larger-polynomial/noise budget rather than reusing the single-output reference.

## Numerical parameters

NTT uses `q32 = 132120577` and `q64 = 1125899906826241`; Fourier uses the native
torus `q = 2^32` or `2^64`. The following choices apply to both workloads.
Decomposition pairs are `(base_log, level_count)`.

| Family / backend | Width | PBS decomposition | KS decomposition | Secret distribution |
| --- | --- | --- | --- | --- |
| GLWE NTT | u32 | (5, 5) | (2, 13) | Binary small LWE and GLWE |
| GLWE Fourier | u32 | (8, 3) | (2, 13) | Binary small LWE and GLWE |
| GLWE NTT / Fourier | u64 | (23, 1) | (3, 5) | Binary small LWE and GLWE |
| NTRU NTT / Fourier | u32 / u64 | Base log 9, full decomposition | Base log 9, full decomposition | Binary or ternary client; sparse ternary accumulator |

GLWE uses coefficient standard deviations
`sigma_lwe = q * 2.046151696979124e-6` and
`sigma_glwe = max(6.4, q * 2.845267479601915e-15)`.
The floor preserves nonzero coefficient noise in the smaller moduli. NTRU
retains its existing coefficient standard deviation `0.7` throughout; it is
an experimental workload with different noise/key-generation contracts.
Equal geometry therefore does not imply equal security or noise budgets.

The reference is pinned to
[TFHE-rs 1.8.1, `V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128`](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_8/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs#L5-L7).
In that release the V1_8 constant aliases V1_4. The
[resolved values in the same release](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_4/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs#L258-L280)
are unchanged, so updating the reference does not require changing this fixture's
numerical parameters.
The u64 GLWE workload borrows its dimensions, decomposition and normalized
Gaussian standard deviations. This project's API takes **coefficient-unit**
standard deviations, so multiplication by the ciphertext modulus is required.
The u32 choices use separate decomposition shapes instead of truncating the
u64 parameters. In particular, the former NTT `(7, 3)` PBS decomposition failed
a t=32 LUT output check; `(5, 5)` reduces digit-amplified key noise while keeping
more decomposition bits. NTRU's full decomposition means the maximum complete
levels accepted by `ApproxSignedBasis` (`None`), not necessarily zero dropped bits.

This is not a TFHE-rs parameter port: this project uses GLWE key switching,
supports both PBS orders, lacks the reference's centered-mean modulus-switch
noise reduction, and also uses explicit prime moduli. NTRU is a separate
construction. The reference's failure probability and security claim do not
transfer to these workloads.

## Selecting the TFHE-rs 1.8.1 counterpart

Choose the explicit Gaussian constant above for the current shortint comparison.
Our LWE/GLWE encryption APIs take Gaussian noise parameters. TFHE-rs 1.8.1's
[default `PARAM_MESSAGE_2_CARRY_2` alias](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/aliases.rs#L54-L60)
instead selects TUniform. These are distinct comparison targets:

| TFHE-rs 1.8.1 parameter | Width | `n` | `k` | `N` | PBS `(base_log, levels)` | KS `(base_log, levels)` |
| --- | --- | ---: | ---: | ---: | --- | --- |
| Explicit Gaussian 2+2 | u64 | 866 | 1 | 2048 | (23, 1) | (3, 5) |
| Default TUniform 2+2 | u64 | 918 | 1 | 2048 | (23, 1) | (4, 4) |
| Boolean `DEFAULT_PARAMETERS` | u32 | 805 | 3 | 512 | (10, 2) | (3, 5) |
| Boolean `DEFAULT_PARAMETERS_KS_PBS` | u32 | 739 | 3 | 512 | (10, 2) | (3, 4) |

The [TUniform 2+2 values](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_4/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs#L29-L47)
are reached through the
[V1_8 TUniform alias](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_8/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs#L5-L7).
They use `new_t_uniform(45)` for LWE and `new_t_uniform(17)` for GLWE. Those
arguments are TUniform parameters, not Gaussian standard deviations; copying
only `n=918` and KS `(4,4)` would not reproduce the default parameter set.

The [Boolean values](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/boolean/parameters/params.rs#L10-L45)
also differ from our common `boolean` fixture (`n=800, k=1, N=1024`). Keep that
fixture for regression and common GLWE/NTRU geometry; it is not a reproduction
of TFHE-rs's Boolean defaults. Likewise, NTT prime moduli, u32 shortint and NTRU
remain adaptations. Report the exact parameter name and PBS order alongside any
TFHE-rs timing, and distinguish a workload comparison from matching parameters.

## Running and comparing

Run the same command for `primus_tfhe_glwe_ntt`, `primus_tfhe_glwe_fourier`,
`primus_tfhe_ntru_ntt`, or `primus_tfhe_ntru_fourier`:

```sh
# Compile and execute each benchmark once, including setup correctness checks.
cargo bench -p primus_tfhe_glwe_ntt --bench pbs -- --test
# Time a workload; add /u64 or an operation name to the regex to narrow it.
cargo bench -p primus_tfhe_glwe_ntt --bench pbs -- 'shortint_2_2/u64/.*/complete_pbs_reused_output'
```

Criterion filters select measurements; fixture setup still runs. Keys use seed
42. Setup checks every padded input against the LUT oracle, including Boolean
separate/interleaved outputs, and checks AND/MUX before timing. This is a deterministic
regression check, not a failure-rate estimate. Inputs, tables, output storage and
scratch are prepared outside online timing. A complete-PBS iteration evaluates
one LUT; a multi-output iteration produces exactly 3 or 4 outputs.

Use a fixed CPU affinity, toolchain, feature set and profile when comparing
revisions. Build before collecting timing data and do not compile concurrently.
The workspace already sets `target-cpu=native`. SIMD invocation is documented
in the backend bench sources. The new names and GLWE geometry/noise differ from
the historical n=512 fixtures, so establish a new baseline. Specialized CBS,
sparse, ternary-GLWE and MVB benches retain their own fixtures.

Pending optimization candidates, measurement evidence and validation steps are
recorded in [TFHE performance optimization](../../docs/tfhe-performance-optimization.md).
