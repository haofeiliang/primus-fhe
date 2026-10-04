//! Complete lookup through public/secret CMux layers and weighted blind rotation.
//! Polynomial contents are checked exhaustively in lookup_table.rs; encrypted
//! evaluation focuses on chunk digits, table boundaries and reused zero selectors.
#![cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]

use primus_encoding::RoundedCodec;
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_fft::{FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_ntru::{NlevParameters, NtruParametersInner, SecretKeyDistr};
#[cfg(feature = "ntt")]
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe::LweCiphertext;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheParameters};
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_tfhe_ntru_lut::FourierLookupTableEvaluator;
#[cfg(feature = "ntt")]
use primus_tfhe_ntru_lut::NttLookupTableEvaluator;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
const N: usize = 64;

// Small independent LWE secret at q=2^24; only the accumulator uses the transform.
fn parameters<T: FheUint, M: RingContext<T>>(
    modulus: M,
    distr: SecretKeyDistr,
    dimension: usize,
) -> TfheParameters<T, M, PowOf2Modulus<T>> {
    TfheParameters::try_from_config(primus_tfhe_ntru::TfheConfig {
        external_lwe: LweParametersInner::new(
            LweDimension::new(dimension),
            PowOf2Modulus::new(T::ONE << 24u32),
            distr,
            0.7,
        ),
        accumulator_modulus: modulus,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap()
}

// Independent lift basis, deliberately different from BR's logB=8.
// The same constructor supplies malformed ring metadata for binding checks.
fn lift_parameters<T: FheUint, M: RingContext<T>>(
    poly_length: PolyLength,
    modulus: M,
) -> NlevParameters<T, M> {
    let basis = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
    .try_build(modulus.explicit_value())
    .unwrap();
    NlevParameters::try_from_parts(
        std::sync::Arc::new(NtruParametersInner::new(
            poly_length,
            modulus,
            SecretKeyDistr::SparseTernary,
            0.7,
        )),
        basis,
    )
    .unwrap()
}

// Three retained levels leave precision for the CMux/rotation products in each word.
fn cbs<T: FheUint>() -> CircuitBootstrapConfig {
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if T::BITS == 32 {
                DecompositionBaseLog::new(4)
            } else {
                DecompositionBaseLog::new(8)
            },
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: full,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: full,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

// These small cases isolate pruning without multiplying the full geometry matrix.
#[derive(Clone, Copy, Debug)]
enum Mapping {
    Carries,
    Constant,
    Repeated,
    Mixed,
    Distinct,
    Shared,
    ReturnTile,
}

impl Mapping {
    // Cleartext digit oracle for each pruning case; Distinct uses the radix-two fixture.
    fn digit(self, x: usize, output: usize, radix: usize) -> u64 {
        match self {
            Self::Carries => digit(x, output, radix),
            // Nine distinct truth tables retain a complete eight-LWE tile
            // and a one-LWE tail even when equal output roots are deduplicated.
            Self::ReturnTile => {
                ([0x00u16, 0xff, 0x55, 0xaa, 0x33, 0xcc, 0x0f, 0xf0, 0x81][output] >> x & 1) as u64
            }
            Self::Constant => output as u64 % radix as u64,
            // Both outputs ignore the high chunks; the first still needs rotation.
            Self::Repeated => {
                if output == 0 {
                    (x % radix) as u64
                } else {
                    0
                }
            }
            Self::Mixed => {
                if output == 0 {
                    (x % radix) as u64
                } else {
                    ((x / radix) % radix) as u64
                }
            }
            // For M=2,d=1,c=3, the two coefficients spell the two-bit prefix.
            Self::Distinct => ((x / 2) >> (x % 2) & 1) as u64,
            // Radix two, c=4,d=1: shared subtrees, equal roots and skipped
            // middle chunks. Chunk 2 needs both public and encrypted choices.
            // Return a parent first: its later child outputs have no new nodes,
            // but still require their own rotations and LWE returns.
            Self::Shared => {
                let low = x & 1;
                let a = x >> 1 & 1;
                let b = x >> 2 & 1;
                let c = x >> 3 & 1;
                (low ^ match output {
                    0 | 4 => {
                        if c == 0 {
                            a
                        } else {
                            b
                        }
                    }
                    1 => a,
                    2 => b,
                    3 => a & b,
                    _ => a ^ c,
                }) as u64
            }
        }
    }
}

// Combines partition boundaries with small radix-two cases for sharing and pruning.
fn cases(radix: usize) -> Vec<(LookupTableConfig, Mapping)> {
    // Preserve the established geometry order and RNG stream across backends.
    let counts: &[(usize, usize, usize)] = if radix == 2 {
        // d=0 with a return-tile tail; d=c; mixed layers; finally K=N.
        &[(3, 9, 0), (3, 5, 3), (7, 3, 5), (7, 3, 6)]
    } else {
        // Also include a single public layer producing exactly one output.
        &[(3, 2, 1), (2, 3, 2), (2, 1, 1)]
    };
    let mut cases: Vec<_> = counts
        .iter()
        .map(
            |&(input_chunk_count, output_chunk_count, coefficient_chunk_count)| {
                (
                    LookupTableConfig {
                        input_chunk_count,
                        output_chunk_count,
                        coefficient_chunk_count,
                    },
                    if radix == 2 && output_chunk_count == 9 {
                        Mapping::ReturnTile
                    } else {
                        Mapping::Carries
                    },
                )
            },
        )
        .collect();
    if radix == 2 {
        for (mapping, d, o) in [
            (Mapping::Constant, 0, 2),
            (Mapping::Repeated, 1, 2),
            (Mapping::Mixed, 1, 2),
            (Mapping::Distinct, 1, 1),
        ] {
            cases.push((
                LookupTableConfig {
                    input_chunk_count: 3,
                    output_chunk_count: o,
                    coefficient_chunk_count: d,
                },
                mapping,
            ));
        }
    }
    if radix == 2 {
        cases.push((
            LookupTableConfig {
                input_chunk_count: 4,
                output_chunk_count: 6,
                coefficient_chunk_count: 1,
            },
            Mapping::Shared,
        ));
    }
    cases
}

// Check the circular phase error independently of the production decoder. This
// fixture uses q=2^24 and t=2*M, so all expected encodings are exact integers.
fn assert_phase<T: FheUint>(phase: T, expected: u64, radix: usize, case: &str) {
    let q = 1u64 << 24;
    let actual: u64 = phase.as_into();
    let target = q / (2 * radix as u64) * expected;
    let error = actual.abs_diff(target);
    let error = error.min(q - error);
    assert!(
        error < q / (4 * radix as u64),
        "{case}: phase error {error} exceeds decoding margin"
    );
}

// Cross-chunk carries make a wrong table prefix observable in the output digits.
fn digit(x: usize, output: usize, radix: usize) -> u64 {
    let result = 3 * x + x / 3 + x / 17 + 5;
    ((result >> (output * radix.trailing_zeros() as usize)) & (radix - 1)) as u64
}

// Keep every input for tiny domains. Larger domains cover every table boundary
// and every nonzero digit in each chunk, including leading-zero encodings.
fn inputs(radix: usize, config: LookupTableConfig) -> Vec<usize> {
    let domain = radix.pow(config.input_chunk_count as u32);
    if domain <= 16 {
        return (0..domain).rev().collect();
    }
    let entries = radix.pow(config.coefficient_chunk_count as u32);
    let mut values = vec![0, domain - 2, domain - 1];
    for prefix in 1..domain / entries {
        values.extend([prefix * entries - 1, prefix * entries]);
    }
    for chunk in 0..config.input_chunk_count {
        let weight = radix.pow(chunk as u32);
        values.push(weight - 1);
        values.extend((1..radix).map(|digit| digit * weight));
    }
    values.sort_unstable();
    values.dedup();
    values.reverse(); // Finish with all-zero selectors after nonzero evaluations.
    values
}

// Backends supply their own keys, representations and workspaces; this driver
// shares only input selection, integer expected digits and public shape checks.
fn exercise<T: FheUint>(
    case: &str,
    table: &HighPrecisionLookupTable<T>,
    mapping: Mapping,
    mut output: Vec<LweCiphertext<T>>,
    mut evaluate: impl FnMut(&[LweCiphertext<T>], &mut [LweCiphertext<T>]),
    mut encrypt: impl FnMut(T) -> LweCiphertext<T>,
    decrypt_phase: impl Fn(&LweCiphertext<T>) -> T,
) {
    let bits = table.chunk_bits();
    let radix = 1 << bits;
    let config = table.config();
    // Descending inputs require overwriting selectors, live result slots and outputs.
    for x in inputs(radix, config) {
        let input: Vec<_> = (0..config.input_chunk_count)
            .map(|i| encrypt(T::as_from((x >> (bits * i)) & (radix - 1))))
            .collect();
        let (_, allocation) = allocations::measure(|| evaluate(&input, &mut output));
        assert_eq!(
            allocation.count, 0,
            "{case}, radix={radix}, config={config:?}"
        );
        if matches!(mapping, Mapping::Shared) {
            // Equal roots reuse the completed LWE, including the same noise.
            assert_eq!(output[0], output[4]);
        }
        for (i, result) in output.iter().enumerate() {
            assert_phase(
                decrypt_phase(result),
                mapping.digit(x, i, radix),
                radix,
                &format!("{case}, {mapping:?}, x={x}, output={i}, config={config:?}"),
            );
        }
    }
    let input: Vec<_> = (0..config.input_chunk_count)
        .map(|_| encrypt(T::ZERO))
        .collect();
    let before = output.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| evaluate(
            &input[..input.len() - 1],
            &mut output
        )))
        .is_err()
    );
    assert_eq!(output, before);
    let mut bad_input = input.clone();
    *bad_input.last_mut().unwrap() = LweCiphertext::zero(1);
    assert!(catch_unwind(AssertUnwindSafe(|| evaluate(&bad_input, &mut output))).is_err());
    assert_eq!(output, before);
    let mut bad_output = output.clone();
    *bad_output.last_mut().unwrap() = LweCiphertext::zero(1);
    let bad_before = bad_output.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| evaluate(&input, &mut bad_output))).is_err());
    assert_eq!(bad_output, bad_before);
    let len = output.len();
    assert!(
        catch_unwind(AssertUnwindSafe(|| evaluate(
            &input,
            &mut output[..len - 1]
        )))
        .is_err()
    );
    assert_eq!(output, before);
    evaluate(&input, &mut output);
    for (i, result) in output.iter().enumerate() {
        assert_phase(
            decrypt_phase(result),
            mapping.digit(0, i, radix),
            radix,
            case,
        );
    }
}

// NTT keeps explicit prime arithmetic and exact coefficient representations.
#[cfg(feature = "ntt")]
fn ntt<T: FheUint, Table: MonomialNttTable<ValueT = T>>(q: T) {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        // One material set serves both t=4 and t=8 chunk programs.
        let context = primus_tfhe_ntru_ntt::TfheContext::<_, Table, _>::try_from_parameters(
            parameters(BarrettModulus::new(q), distr, 2),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(0x48504c5554);
        let (client, server) = context
            .try_generate_keys(Some(cbs::<T>()), &mut rng)
            .unwrap();
        // Generate NLEV[1] independently; reuse it only for plans with explicit Lift.
        let lift_params =
            lift_parameters(context.parameters().poly_length(), BarrettModulus::new(q));
        let mut lift_rng = StdRng::seed_from_u64(0x4c494654);
        let lift_secret = primus_ntru::NttNtruSecretKey::try_from_coeff_secret_key(
            client.accumulator_ntru_secret_key(),
            BarrettModulus::new(q),
            context.table(),
        )
        .unwrap();
        let mut lift = primus_ntru::NttNlevCiphertext::<Vec<T>>::zero(lift_params.nlev_len());
        lift_secret.encrypt_nlev_constant_to(
            T::ONE,
            &mut lift,
            &lift_params,
            context.table(),
            &mut lift_rng,
            &mut primus_ntru::NttNtruGadgetEncryptWorkspace::new(
                context.parameters().poly_length(),
            ),
        );
        for radix in [2, 4] {
            let input_codec = RoundedCodec::new(
                T::as_from((2 * radix) as u32),
                context.parameters().external_lwe().cipher_modulus(),
            );
            let encryptor = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            let decryptor = context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            for (config, mapping) in cases(radix) {
                let table = HighPrecisionLookupTable::try_new(
                    context.parameters(),
                    &input_codec,
                    config,
                    |x, o| T::as_from(mapping.digit(x, o, radix)),
                )
                .unwrap();
                // One existing pruned case exercises missing, short and foreign lift material.
                if radix == 2 && matches!(mapping, Mapping::Constant) {
                    assert!(table.needs_public_lift());
                    let bind = |public_lift| {
                        NttLookupTableEvaluator::try_from_parts(
                            &context,
                            server.blind_rotation_key(),
                            server.key_switching_key(),
                            server.circuit_bootstrap_key().unwrap(),
                            public_lift,
                            &table,
                        )
                    };
                    assert!(matches!(
                        bind(None),
                        Err(LookupTableError::MissingPublicLiftKey)
                    ));
                    let short = primus_ntru::NttNlevCiphertext::new(
                        &lift.as_ref()[..lift.as_ref().len() - 1],
                    );
                    assert!(matches!(
                        bind(Some((short, &lift_params))),
                        Err(LookupTableError::IncompatiblePublicLiftKey)
                    ));
                    let other_ring = lift_parameters(PolyLength::new(32), BarrettModulus::new(q));
                    let other_modulus = lift_parameters(
                        context.parameters().poly_length(),
                        BarrettModulus::new(T::as_from(65_537u32)),
                    );
                    // Exact lengths isolate metadata rejection from malformed storage.
                    let foreign_keys = [
                        vec![T::ZERO; other_ring.nlev_len()],
                        vec![T::ZERO; other_modulus.nlev_len()],
                    ];
                    for (parameters, values) in
                        [&other_ring, &other_modulus].into_iter().zip(&foreign_keys)
                    {
                        let key = primus_ntru::NttNlevCiphertext::new(values.as_slice());
                        assert!(matches!(
                            bind(Some((key, parameters))),
                            Err(LookupTableError::IncompatiblePublicLiftKey)
                        ));
                    }
                }
                if matches!(mapping, Mapping::Distinct) {
                    assert!(!table.needs_public_lift());
                }
                let mut evaluator = if radix == 2 {
                    NttLookupTableEvaluator::try_from_parts(
                        &context,
                        server.blind_rotation_key(),
                        server.key_switching_key(),
                        server.circuit_bootstrap_key().unwrap(),
                        table
                            .needs_public_lift()
                            .then(|| (lift.as_view(), &lift_params)),
                        &table,
                    )
                    .unwrap()
                } else {
                    NttLookupTableEvaluator::try_new(&context, &server, &table).unwrap()
                };
                let case = format!(
                    "{}/{}, {distr:?}",
                    std::any::type_name::<Table>(),
                    std::any::type_name::<T>()
                );
                exercise(
                    &case,
                    &table,
                    mapping,
                    evaluator.allocate_output(),
                    |input, output| evaluator.evaluate_to(input, output),
                    |m| encryptor.encrypt_padded(m, &mut rng).unwrap(),
                    |c| decryptor.decrypt_phase(c.as_view()).unwrap(),
                );
            }
            let config = cases(radix)[0].0;
            let other = primus_tfhe_ntru_ntt::TfheContext::<_, Table, _>::try_from_parameters(
                parameters(BarrettModulus::new(q), distr, 3),
            )
            .unwrap();
            let table = HighPrecisionLookupTable::try_new(
                other.parameters(),
                &input_codec,
                config,
                |_, _| T::ZERO,
            )
            .unwrap();
            assert!(matches!(
                NttLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::Evaluation(
                    primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey
                ))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(NativeModulus::new(), distr, 2),
                &input_codec,
                config,
                |_, _| T::ZERO,
            )
            .unwrap();
            assert!(matches!(
                NttLookupTableEvaluator::try_new(&context, &server, &table),
                Err(LookupTableError::IncompatibleParameters)
            ));
        }
    }
}

// Native torus tests keep both FFT tables and word widths; no PowOf2 ring is implied.
#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
fn fourier<T: TorusFftValue, Table: FftTable>() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        // One material set serves both t=4 and t=8 chunk programs.
        let context = primus_tfhe_ntru_fourier::TfheContext::<_, Table, _>::from_parameters(
            parameters(NativeModulus::new(), distr, 2),
        );
        let mut rng = StdRng::seed_from_u64(0x48504c5554);
        let (client, server) = context
            .try_generate_keys(Some(cbs::<T>()), &mut rng)
            .unwrap();
        // Fourier lifting uses the same table instance, with an independent logB=4 basis.
        let lift_params = lift_parameters(context.parameters().poly_length(), NativeModulus::new());
        let mut lift_rng = StdRng::seed_from_u64(0x4c494654);
        let mut fft = context.new_fft_engine();
        let lift_secret = primus_ntru::FourierNtruSecretKey::try_from_coeff_secret_key(
            client.accumulator_ntru_secret_key(),
            &mut fft,
        )
        .unwrap();
        let mut lift = primus_ntru::FourierNlevCiphertext::<Vec<primus_fft::Complex64>>::zero(
            lift_params.fourier_nlev_len(),
        );
        lift_secret.encrypt_nlev_constant_to(
            T::ONE,
            &mut lift,
            &lift_params,
            &mut fft,
            &mut lift_rng,
            &mut primus_ntru::FourierNtruGadgetEncryptWorkspace::new(
                context.parameters().poly_length(),
            ),
        );
        for radix in [2, 4] {
            let input_codec = RoundedCodec::new(
                T::as_from((2 * radix) as u32),
                context.parameters().external_lwe().cipher_modulus(),
            );
            let encryptor = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            let decryptor = context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap();
            for (config, mapping) in cases(radix) {
                let table = HighPrecisionLookupTable::try_new(
                    context.parameters(),
                    &input_codec,
                    config,
                    |x, o| T::as_from(mapping.digit(x, o, radix)),
                )
                .unwrap();
                // One existing pruned case exercises missing, short and foreign lift material.
                if radix == 2 && matches!(mapping, Mapping::Constant) {
                    assert!(table.needs_public_lift());
                    let bind = |public_lift| {
                        FourierLookupTableEvaluator::try_from_parts(
                            &context,
                            server.blind_rotation_key(),
                            server.key_switching_key(),
                            server.circuit_bootstrap_key().unwrap(),
                            public_lift,
                            &table,
                        )
                    };
                    assert!(matches!(
                        bind(None),
                        Err(LookupTableError::MissingPublicLiftKey)
                    ));
                    let short = primus_ntru::FourierNlevCiphertext::new(
                        &lift.as_ref()[..lift.as_ref().len() - 1],
                    );
                    assert!(matches!(
                        bind(Some((short, &lift_params))),
                        Err(LookupTableError::IncompatiblePublicLiftKey)
                    ));
                    let other_ring = lift_parameters(PolyLength::new(32), NativeModulus::new());
                    let values = vec![primus_fft::Complex64::ZERO; other_ring.fourier_nlev_len()];
                    let key = primus_ntru::FourierNlevCiphertext::new(values.as_slice());
                    assert!(matches!(
                        bind(Some((key, &other_ring))),
                        Err(LookupTableError::IncompatiblePublicLiftKey)
                    ));
                }
                if matches!(mapping, Mapping::Distinct) {
                    assert!(!table.needs_public_lift());
                }
                let mut evaluator = if radix == 2 {
                    FourierLookupTableEvaluator::try_from_parts(
                        &context,
                        server.blind_rotation_key(),
                        server.key_switching_key(),
                        server.circuit_bootstrap_key().unwrap(),
                        table
                            .needs_public_lift()
                            .then(|| (lift.as_view(), &lift_params)),
                        &table,
                    )
                    .unwrap()
                } else {
                    FourierLookupTableEvaluator::try_new(&context, &server, &table).unwrap()
                };
                let case = format!(
                    "{}/{}, {distr:?}",
                    std::any::type_name::<Table>(),
                    std::any::type_name::<T>()
                );
                exercise(
                    &case,
                    &table,
                    mapping,
                    evaluator.allocate_output(),
                    |input, output| evaluator.evaluate_to(input, output),
                    |m| encryptor.encrypt_padded(m, &mut rng).unwrap(),
                    |c| decryptor.decrypt_phase(c.as_view()).unwrap(),
                );
            }
            let config = cases(radix)[0].0;
            let other = primus_tfhe_ntru_fourier::TfheContext::<_, Table, _>::from_parameters(
                parameters(NativeModulus::new(), distr, 3),
            );
            let table = HighPrecisionLookupTable::try_new(
                other.parameters(),
                &input_codec,
                config,
                |_, _| T::ZERO,
            )
            .unwrap();
            assert!(matches!(
                FourierLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::Evaluation(
                    primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey
                ))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(BarrettModulus::new(T::as_from(998_244_353u32)), distr, 2),
                &input_codec,
                config,
                |_, _| T::ZERO,
            )
            .unwrap();
            assert!(matches!(
                FourierLookupTableEvaluator::try_new(&context, &server, &table),
                Err(LookupTableError::IncompatibleParameters)
            ));
        }
    }
}

// Checks the shared evaluation cases at both word widths with prime-modulus NTT.
#[cfg(feature = "ntt")]
#[test]
fn ntt_complete_chunk_lookup() {
    ntt::<u32, U32NttTable>(998_244_353);
    ntt::<u64, U64NttTable>(1_125_899_906_826_241);
}

// Checks the shared evaluation cases at both word widths with native-torus RustFFT.
#[cfg(feature = "rustfft")]
#[test]
fn rustfft_complete_chunk_lookup() {
    fourier::<u32, RustFftTable>();
    fourier::<u64, RustFftTable>();
}

// Checks the same native-torus cases with the alternative TfheFft transform.
#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_complete_chunk_lookup() {
    fourier::<u32, TfheFftTable>();
    fourier::<u64, TfheFftTable>();
}
