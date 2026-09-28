//! Complete lookup through public/secret CMux layers and weighted blind rotation.
//! Polynomial contents are checked exhaustively in lookup_table.rs; encrypted
//! evaluation focuses on chunk digits, table boundaries and reused zero selectors.
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheParameters};
use primus_tfhe_ntru_lut::{
    FourierLookupTableEvaluator, HighPrecisionLookupTable, LookupTableConfig, LookupTableError,
    NttLookupTableEvaluator,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
const N: usize = 64;

// Small independent LWE secret at q=2^24; only the accumulator uses the transform.
fn parameters<T: FheUint, M: RingContext<T>>(
    modulus: M,
    radix: usize,
    distr: SecretKeyDistr,
    dimension: usize,
) -> TfheParameters<T, M, PowOf2Modulus<T>> {
    let ring = NtruParameters::new(
        N,
        T::as_from(2 * radix),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    TfheParameters::try_new(
        LweParameters::new(
            dimension,
            T::as_from(2 * radix),
            PowOf2Modulus::new(T::ONE << 24u32),
            distr,
            0.7,
        ),
        NlevParameters::with_ntru_params(&ring, 8, None),
        DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        0.7,
    )
    .unwrap()
}

// Three retained levels leave precision for the CMux/rotation products in each word.
fn cbs<T: FheUint>() -> CircuitBootstrapConfig {
    let full = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if T::BITS == 32 { 4 } else { 8 },
            level_count: Some(3),
        },
        trace: full,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: full,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

// Cover d=0, d=c, mixed layers, unequal chunk counts and a full coefficient ring.
fn configs(radix: usize) -> Vec<LookupTableConfig> {
    let counts = if radix == 2 {
        // All table layers; no table layer; a domain larger than the ring,
        // with both public and encrypted table layers and several rotations;
        // finally fill every coefficient of the selected polynomial.
        vec![(3, 2, 0), (3, 5, 3), (7, 3, 5), (7, 3, 6)]
    } else {
        vec![(3, 2, 1), (2, 3, 2)]
    };
    counts
        .into_iter()
        .map(
            |(input_chunk_count, output_chunk_count, coefficient_chunk_count)| LookupTableConfig {
                input_chunk_count,
                output_chunk_count,
                coefficient_chunk_count,
            },
        )
        .collect()
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
    radix: usize,
    config: LookupTableConfig,
    mut output: Vec<LweCiphertext<T>>,
    mut evaluate: impl FnMut(&[LweCiphertext<T>], &mut [LweCiphertext<T>]),
    mut encrypt: impl FnMut(T) -> LweCiphertext<T>,
    decrypt: impl Fn(&LweCiphertext<T>) -> T,
) {
    let bits = radix.trailing_zeros() as usize;
    // Descending inputs require overwriting selectors, candidates and outputs.
    for x in inputs(radix, config) {
        let input: Vec<_> = (0..config.input_chunk_count)
            .map(|i| encrypt(T::as_from((x >> (bits * i)) & (radix - 1))))
            .collect();
        let (_, allocation) = allocations::measure(|| evaluate(&input, &mut output));
        assert_eq!(
            allocation.count, 0,
            "{case}, radix={radix}, config={config:?}"
        );
        for (i, result) in output.iter().enumerate() {
            assert_eq!(
                decrypt(result),
                T::as_from(digit(x, i, radix)),
                "{case}, x={x}, output={i}, radix={radix}, config={config:?}"
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
        assert_eq!(
            decrypt(result),
            T::as_from(digit(0, i, radix)),
            "{case}, recovery output={i}, radix={radix}, config={config:?}"
        );
    }
}

// NTT keeps explicit prime arithmetic and exact coefficient representations.
fn ntt<T: FheUint, Table: MonomialNttTable<ValueT = T>>(q: T) {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        for radix in [2, 4] {
            let context = primus_tfhe_ntru_ntt::TfheContext::<_, Table, _>::try_from_parameters(
                parameters(BarrettModulus::new(q), radix, distr, 2),
            )
            .unwrap();
            let mut rng = StdRng::seed_from_u64(0x48504c5554 + radix as u64);
            let (client, server) = context
                .try_generate_keys(Some(cbs::<T>()), &mut rng)
                .unwrap();
            let encryptor = context.encryptor(&client).unwrap();
            let decryptor = context.decryptor(&client).unwrap();
            for config in configs(radix) {
                let table =
                    HighPrecisionLookupTable::try_new(context.parameters(), config, |x, o| {
                        T::as_from(digit(x, o, radix))
                    })
                    .unwrap();
                let mut evaluator =
                    NttLookupTableEvaluator::try_new(&context, &server, &table).unwrap();
                let case = format!(
                    "{}/{}, {distr:?}",
                    std::any::type_name::<Table>(),
                    std::any::type_name::<T>()
                );
                exercise(
                    &case,
                    radix,
                    config,
                    evaluator.allocate_output(),
                    |input, output| evaluator.evaluate_to(input, output),
                    |m| encryptor.encrypt_padded(m, &mut rng).unwrap(),
                    |c| decryptor.decrypt(c).unwrap(),
                );
            }
            let config = configs(radix)[0];
            let other = primus_tfhe_ntru_ntt::TfheContext::<_, Table, _>::try_from_parameters(
                parameters(BarrettModulus::new(q), radix, distr, 3),
            )
            .unwrap();
            let table =
                HighPrecisionLookupTable::try_new(other.parameters(), config, |_, _| T::ZERO)
                    .unwrap();
            assert!(matches!(
                NttLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::OneHot(_))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(NativeModulus::new(), radix, distr, 2),
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
fn fourier<T: TorusFftValue, Table: FftTable>() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        for radix in [2, 4] {
            let context =
                primus_tfhe_ntru_fourier::TfheContext::<_, Table, _>::try_from_parameters(
                    parameters(NativeModulus::new(), radix, distr, 2),
                )
                .unwrap();
            let mut rng = StdRng::seed_from_u64(0x48504c5554 + radix as u64);
            let (client, server) = context
                .try_generate_keys(Some(cbs::<T>()), &mut rng)
                .unwrap();
            let encryptor = context.encryptor(&client).unwrap();
            let decryptor = context.decryptor(&client).unwrap();
            for config in configs(radix) {
                let table =
                    HighPrecisionLookupTable::try_new(context.parameters(), config, |x, o| {
                        T::as_from(digit(x, o, radix))
                    })
                    .unwrap();
                let mut evaluator =
                    FourierLookupTableEvaluator::try_new(&context, &server, &table).unwrap();
                let case = format!(
                    "{}/{}, {distr:?}",
                    std::any::type_name::<Table>(),
                    std::any::type_name::<T>()
                );
                exercise(
                    &case,
                    radix,
                    config,
                    evaluator.allocate_output(),
                    |input, output| evaluator.evaluate_to(input, output),
                    |m| encryptor.encrypt_padded(m, &mut rng).unwrap(),
                    |c| decryptor.decrypt(c).unwrap(),
                );
            }
            let config = configs(radix)[0];
            let other = primus_tfhe_ntru_fourier::TfheContext::<_, Table, _>::try_from_parameters(
                parameters(NativeModulus::new(), radix, distr, 3),
            )
            .unwrap();
            let table =
                HighPrecisionLookupTable::try_new(other.parameters(), config, |_, _| T::ZERO)
                    .unwrap();
            assert!(matches!(
                FourierLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::OneHot(_))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(
                    BarrettModulus::new(T::as_from(998_244_353u32)),
                    radix,
                    distr,
                    2,
                ),
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

#[test]
fn ntt_complete_chunk_lookup() {
    ntt::<u32, U32NttTable>(998_244_353);
    ntt::<u64, U64NttTable>(1_125_899_906_826_241);
}

#[test]
fn rustfft_complete_chunk_lookup() {
    fourier::<u32, RustFftTable>();
    fourier::<u64, RustFftTable>();
}

#[test]
fn tfhe_fft_complete_chunk_lookup() {
    fourier::<u32, TfheFftTable>();
    fourier::<u64, TfheFftTable>();
}
