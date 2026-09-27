use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::U64NttTable;
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
const Q: u64 = 1_125_899_906_826_241;

fn parameters<M: RingContext<u64>>(
    modulus: M,
    radix: usize,
    distr: SecretKeyDistr,
    dimension: usize,
) -> TfheParameters<u64, M, BarrettModulus<u64>> {
    let ring = NtruParameters::new(
        N,
        2 * radix as u64,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    TfheParameters::try_new(
        LweParameters::new(
            dimension,
            2 * radix as u64,
            BarrettModulus::new(1 << 24),
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

fn cbs() -> CircuitBootstrapConfig {
    let full = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        trace: full,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: full,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

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

fn digit(x: usize, output: usize, radix: usize) -> u64 {
    let result = 3 * x + x / 3 + x / 17 + 5;
    ((result >> (output * radix.trailing_zeros() as usize)) & (radix - 1)) as u64
}

fn exercise(
    radix: usize,
    config: LookupTableConfig,
    mut output: Vec<LweCiphertext<u64>>,
    mut evaluate: impl FnMut(&[LweCiphertext<u64>], &mut [LweCiphertext<u64>]),
    mut encrypt: impl FnMut(u64) -> LweCiphertext<u64>,
    decrypt: impl Fn(&LweCiphertext<u64>) -> u64,
) {
    let bits = radix.trailing_zeros() as usize;
    // Descending inputs require overwriting selectors, candidates and outputs.
    for x in (0..radix.pow(config.input_chunk_count as u32)).rev() {
        let input: Vec<_> = (0..config.input_chunk_count)
            .map(|i| encrypt(((x >> (bits * i)) & (radix - 1)) as u64))
            .collect();
        let (_, allocation) = allocations::measure(|| evaluate(&input, &mut output));
        assert_eq!(allocation.count, 0);
        for (i, result) in output.iter().enumerate() {
            assert_eq!(
                decrypt(result),
                digit(x, i, radix),
                "x={x}, output={i}, radix={radix}, config={config:?}"
            );
        }
    }
    let input: Vec<_> = (0..config.input_chunk_count).map(|_| encrypt(0)).collect();
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
        assert_eq!(decrypt(result), digit(0, i, radix));
    }
}

#[test]
fn ntt_complete_chunk_lookup() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        for radix in [2, 4] {
            let context =
                primus_tfhe_ntru_ntt::TfheContext::<_, U64NttTable, _>::try_from_parameters(
                    parameters(BarrettModulus::new(Q), radix, distr, 2),
                )
                .unwrap();
            let mut rng = StdRng::seed_from_u64(0x48504c5554 + radix as u64);
            let (client, server) = context.try_generate_keys(Some(cbs()), &mut rng).unwrap();
            let encryptor = context.encryptor(&client).unwrap();
            let decryptor = context.decryptor(&client).unwrap();
            for config in configs(radix) {
                let table =
                    HighPrecisionLookupTable::try_new(context.parameters(), config, |x, o| {
                        digit(x, o, radix)
                    })
                    .unwrap();
                let mut evaluator =
                    NttLookupTableEvaluator::try_new(&context, &server, &table).unwrap();
                exercise(
                    radix,
                    config,
                    evaluator.allocate_output(),
                    |input, output| evaluator.evaluate_to(input, output),
                    |m| encryptor.encrypt_padded(m, &mut rng).unwrap(),
                    |c| decryptor.decrypt(c).unwrap(),
                );
            }
            let config = configs(radix)[0];
            let other =
                primus_tfhe_ntru_ntt::TfheContext::<_, U64NttTable, _>::try_from_parameters(
                    parameters(BarrettModulus::new(Q), radix, distr, 3),
                )
                .unwrap();
            let table =
                HighPrecisionLookupTable::try_new(other.parameters(), config, |_, _| 0).unwrap();
            assert!(matches!(
                NttLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::OneHot(_))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(NativeModulus::new(), radix, distr, 2),
                config,
                |_, _| 0,
            )
            .unwrap();
            assert!(matches!(
                NttLookupTableEvaluator::try_new(&context, &server, &table),
                Err(LookupTableError::IncompatibleParameters)
            ));
        }
    }
}

fn fourier<Table: FftTable>() {
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
            let (client, server) = context.try_generate_keys(Some(cbs()), &mut rng).unwrap();
            let encryptor = context.encryptor(&client).unwrap();
            let decryptor = context.decryptor(&client).unwrap();
            for config in configs(radix) {
                let table =
                    HighPrecisionLookupTable::try_new(context.parameters(), config, |x, o| {
                        digit(x, o, radix)
                    })
                    .unwrap();
                let mut evaluator =
                    FourierLookupTableEvaluator::try_new(&context, &server, &table).unwrap();
                exercise(
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
                HighPrecisionLookupTable::try_new(other.parameters(), config, |_, _| 0).unwrap();
            assert!(matches!(
                FourierLookupTableEvaluator::try_new(&other, &server, &table),
                Err(LookupTableError::OneHot(_))
            ));
            let table = HighPrecisionLookupTable::try_new(
                &parameters(BarrettModulus::new(Q), radix, distr, 2),
                config,
                |_, _| 0,
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
fn rustfft_complete_chunk_lookup() {
    fourier::<RustFftTable>();
}

#[test]
fn tfhe_fft_complete_chunk_lookup() {
    fourier::<TfheFftTable>();
}
