# TFHE benchmark workloads

The 18 targets below measure independent operations using the shared
[parameter profiles](../../guides/development/tfhe-parameters.md).
All retained workflows cover u32/u64; Fourier covers RustFFT and TFHE-FFT,
and complete GLWE workflows cover both PBS orders. These are arithmetic cost
fixtures, not assessed security parameters or equal-security comparisons.

## Targets and measurement boundaries

| Target | Question answered / one iteration |
| --- | --- |
| `primus_tfhe/lookup_table` | Compile and drop one public LUT: ordinary t32/k1, padded interleaving t16/k3, or tight cells t255/k4; N1024, Native/PowOf2 q24/Barrett |
| Four backends' `pbs` | One complete dense binary PBS at n800/N1024/t4 or n866/N2048/t32; ternary at n800/N1024/t4; one server-key generation per dense secret/word/backend |
| GLWE `pbs` stage IDs | One BR or one GLWE key switch at binary n800/N1024; excludes extraction and prerequisite operations |
| Four backends' `sparse_pbs` | One complete classic or bucket-sparse PBS, or one server-key generation, for the same n728/h32/N1024/t8 secret profile |
| Four backends' `mvb` | Produce k Scaled threshold bits from one input: D8/k3 compares independent PBS, interleaved ManyLUT and factorized MVB; D64/k17 compares independent and factorized because interleaving does not fit |
| Four backends' `circuit_bootstrap` | One ordinary CBS into a reused gadget ciphertext; GLWE also has sparse CBS, NTRU also compares full M4 and compact M-1 one-hot batches |
| `primus_tfhe_ntru_lut/pipeline` | One public LUT compilation/drop or one complete c8/d5/o8 lookup (16 input/output bits) at n800/N1024 |

MVB compares classic and sparse GLWE keys. NTRU sparse supports only ordinary
and interleaved PBS, so it has just the D8/k3 independent/interleaved pair.
Throughput for MVB and complete lookup counts **output ciphertexts**; latency
still measures the whole batch. NTRU output phases are decoded at external q24,
while their public coefficient tables are encoded at ring Q.

Repeated ManyLUT cases now live in `mvb`, not in both PBS files. Boolean AND/MUX
wrappers and the legacy two-CMux ternary implementation are no longer separate
timings. Ternary PBS itself remains. The former `ternary_pbs` targets have been
merged into `pbs`. One-hot belongs to the NTRU CBS target. The LUT pipeline uses
the public evaluator, without compiling a second copy of production sources to
access private stages. Primitive arithmetic remains in the lattice/scheme
benchmarks; additional stage probes should have a concrete diagnostic purpose.

## Numerical parameters

[Shared constructors](../../test-support/tfhe/src/parameters/mod.rs) separate
numerical choices from timing code. The parameter guide records every modulus,
noise unit, decomposition and secret distribution. Dense binary GLWE PBS
retains the profiles below; ternary uses the separate circuit profile and must
not be treated as a matched-parameter binary/ternary speed comparison.

| Dense binary GLWE | BR (log basis, levels) | KS (log basis, levels) |
| --- | --- | --- |
| u32 NTT Q27 | (5,5) | (2,13) |
| u32 Fourier Native32 | (8,3) | (2,13) |
| u64 NTT Q50 / Fourier Native64 | (23,1) | (3,5) |

NTRU uses independent `PowOf2Modulus(2^24)` external LWE and return keys.
The ring uses Q27 for ordinary u32 NTT PBS, Q30 for circuit products, Q50 for
u64 NTT, or Native32/64 for Fourier. Full internal decomposition uses log basis
2 for u32 and 8 for u64; return KS uses (3,8) at q24. Ring sigma is 0.7,
return-key sigma is 3.2, and external sigma follows the dense/fixed-weight
profile. These replace the former q=Q/base9/sigma0.7-everywhere benchmark.

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

```sh
# Listing does not generate keys, encrypt inputs, or execute correctness probes.
cargo bench -p primus_tfhe_glwe_ntt --bench pbs -- --list
# Run each selected ID once, including its untimed known-result checks.
cargo bench -p primus_tfhe_glwe_ntt --bench pbs -- --test
# Measure one complete workload; pin an available CPU for revision comparisons.
taskset -c 0 cargo bench -p primus_tfhe_glwe_ntt --bench pbs -- \
  'glwe/ntt/u64/binary/shortint_2_2/.*/BootstrapKeyswitch/complete$' \
  --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

Targets use Criterion's defaults unless overridden. Owned fixtures are created
inside the selected benchmark callback and cached across samples. Evaluators
borrow those fixtures locally. Encryption, table preparation, workspace/output
allocation and correctness probes stay outside online timing. Key-generation
IDs include generation allocations but use `iter_batched` so returned-key drop
is untimed. Compilation IDs explicitly include LUT allocation, filling and drop.

There is no manual repetition to amplify timings. Independent multi-output PBS
performs k calls because its real workload is k outputs. Dispatch between
algorithms occurs outside `b.iter`; inputs are fixed encrypted messages and
outputs/scratch are overwritten. Seed 42 establishes the client fixture; sparse
keygen uses seed 4242. A known-result probe checks the measured operation, while
exhaustive/phase-margin diagnostics remain in `validate_parameters` and tests.

Only the complete high-precision target reports retained requested heap and
asserts zero online allocations. Resource probes are untimed and allocation
counting is disabled during samples; heap does not mean RSS or peak generation
memory. See the [pipeline boundaries](../primus_tfhe_ntru_lut/IMPLEMENTATION.md#benchmark-fixture).

Build before timing and avoid concurrent compilation or benchmarks. Record CPU,
affinity, compiler, features, profile and exact ID. The repository already uses
`target-cpu=native`. Default FFT dependencies may still use SIMD internally;
the workspace `simd` feature is a distinct configuration.

For the SIMD benchmark configuration only:

```sh
taskset -c 0 cargo +nightly bench -p primus_tfhe_ntru_lut --bench pipeline --features simd -- \
  '/complete$' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

The [current measurement record](../../guides/development/tfhe-benchmarks.md)
records the baseline and storage experiment. Earlier n16/n64 lookup or
q=Q/base9 NTRU results have different work and cannot be divided by these
results to claim an implementation speedup or regression.
