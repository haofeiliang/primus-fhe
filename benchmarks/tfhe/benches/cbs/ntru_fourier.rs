//! One complete CBS into a reused gadget ciphertext; NTRU also measures full
//! and nonzero one-hot batches. Keygen, encryption, allocation and the CMux
//! correctness probe are outside timing. Ordinary CBS uses t4; one-hot uses t8.
//! Classic/sparse pairs share n728/h32/N1024 secrets and separately seeded inputs.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench cbs --features ntru-fourier,rustfft,tfhe-fft

use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_tfhe_benchmarks::parameters::{N, ntru};
use primus_tfhe_ntru_fourier::{KeyGenerator, OneHotEvaluator, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str, sparse: bool) {
    let kind = if sparse { "sparse" } else { "classic" };
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let input_modulus = T::as_from(4u32);
    let t_ring = T::as_from(4u32);
    let name = format!("{kind}/complete");
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_modulus, t_ring, sparse, T::ONE)
    });
    let mut verified = false;
    c.throughput(criterion::Throughput::Elements(1));
    let case = Case::new("ntru", backend, T::BITS, &name);
    c.bench_function(case.id(), |b| {
        let Fixture {
            parameters,
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        } = &*fixture;
        let mut evaluator = context.circuit_bootstrap_evaluator(server).unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input.as_view(), output.as_mut_view());
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(
                output.as_view(),
                lhs.as_view(),
                rhs.as_view(),
                selected.as_mut_view(),
            );
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(client.accumulator_ntru_secret_key(), t_ring)
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }

        metadata::record("cbs", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(parameters),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(ntru::cbs::<T>(), context.parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                "encoding": "rounded_padded",
                "plaintext_modulus": 4,
                "outputs": 1,
                "output_kind": "gadget",
                "fft_layout_fingerprint": metadata::fft_layout(context.table()),
            })
        });
        b.iter(|| {
            evaluator.circuit_bootstrap_to(
                black_box(input.as_view()),
                black_box(output.as_mut_view()),
            )
        });
    });
}

// The compact batch omits delta_0. Compare equal input geometry to isolate the
// saved selector work; one iteration produces M or M-1 complete NGSW controls.
fn one_hot<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str, sparse: bool) {
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let input_modulus = T::as_from(8u32);
    let t_ring = T::as_from(8u32);
    let br = if sparse { "sparse" } else { "classic" };
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_modulus, t_ring, sparse, T::TWO)
    });
    for compact in [false, true] {
        let kind = if compact { "nonzero" } else { "full" };
        let mut verified = false;
        let name = format!("one_hot/{br}/M4/{kind}");
        c.throughput(criterion::Throughput::Elements(if compact { 3 } else { 4 }));
        let case = Case::new("ntru", backend, T::BITS, &name);
        c.bench_function(case.id(), |b| {
            let Fixture {
                parameters,
                context,
                server,
                input,
                ..
            } = &*fixture;
            let mut evaluator = context.one_hot_evaluator(server).unwrap();
            let mut output = if compact {
                evaluator.allocate_nonzero_ngsw_output()
            } else {
                evaluator.allocate_ngsw_output()
            };
            if !verified {
                if compact {
                    evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut output);
                } else {
                    evaluator.one_hot_ngsw_to(input.as_view(), &mut output);
                }
                fixture.check_one_hot(&output, &mut evaluator, compact, t_ring);
                verified = true;
            }
            metadata::record("cbs", &case, || {
                serde_json::json!({
                    "parameters": metadata::ntru(parameters),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "cbs": metadata::cbs(ntru::cbs::<T>(), context.parameters().accumulator_ntru().noise_distribution().standard_deviation()),
                    "encoding": "rounded_padded",
                    "plaintext_modulus": 8,
                    "outputs": if compact { 3 } else { 4 },
                    "output_kind": "one_hot_ngsw",
                    "omits_zero": compact,
                    "fft_layout_fingerprint": metadata::fft_layout(context.table()),
                })
            });
            if compact {
                b.iter(|| {
                    evaluator.one_hot_nonzero_ngsw_to(
                        black_box(input.as_view()),
                        black_box(&mut output),
                    )
                });
            } else {
                b.iter(|| {
                    evaluator.one_hot_ngsw_to(
                        black_box(input.as_view()),
                        black_box(&mut output),
                    )
                });
            }
        });
    }
}

pub fn bench_cbs(c: &mut Group<'_>) {
    for sparse in [false, true] {
        #[cfg(feature = "rustfft")]
        {
            ordinary::<u64, RustFftTable>(c, "rustfft", sparse);
            one_hot::<u64, RustFftTable>(c, "rustfft", sparse);
        }
        #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
        {
            ordinary::<u64, TfheFftTable>(c, "tfhe_fft", sparse);
            one_hot::<u64, TfheFftTable>(c, "tfhe_fft", sparse);
        }
    }
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: TorusFftValue, Table: FftTable> {
    parameters: primus_tfhe_ntru_fourier::PbsParameters<T, PowOf2Modulus<T>>,
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_fourier::ClientKey<T>,
    server: primus_tfhe_ntru_fourier::CircuitBootstrapServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lhs: primus_ntru::NtruCiphertext<Vec<T>>,
    rhs: primus_ntru::NtruCiphertext<Vec<T>>,
}

impl<T: TorusFftValue, Table: FftTable> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_fourier::PbsParameters<T, PowOf2Modulus<T>>,
        input_modulus: T,
        t_ring: T,
        sparse: bool,
        message: T,
    ) -> Self {
        let parameters =
            parameters.with_messages(primus_tfhe::PbsMessageConfig::new(input_modulus));
        let context_parameters = &parameters;
        let context =
            TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(context_parameters.clone());
        let context = context
            .try_with_circuit_bootstrap(ntru::cbs::<T>())
            .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let client = generator.try_generate_client_key(&mut rng).unwrap();
        let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
        let server = generator
            .try_generate_circuit_bootstrap_server_key_with_parameters(
                context_parameters.key_switching(),
                &client,
                blind_rotation,
                context.cbs_parameters().unwrap().gadget(),
                &mut rng,
            )
            .unwrap();
        // Input/candidate encryption is identical across the two BR choices.
        let mut rng = StdRng::seed_from_u64(43);
        let input = context
            .encryptor(client.external_lwe_secret_key())
            .unwrap()
            .encrypt_padded(message, &mut rng)
            .unwrap();
        let mut ring = context
            .accumulator_client(client.accumulator_ntru_secret_key(), t_ring)
            .unwrap();
        let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
        let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
        Self {
            parameters,
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        }
    }

    /// Check each selector through a CMux, including the compact r-1 indexing.
    fn check_one_hot<'a>(
        &self,
        output: &[primus_fft::Complex64],
        evaluator: &mut OneHotEvaluator<'a, T, Table, PowOf2Modulus<T>>,
        compact: bool,
        t_ring: T,
    ) {
        let Self {
            context,
            client,
            lhs,
            rhs,
            ..
        } = self;
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![T::ZERO; N];
        let mut ring = context
            .accumulator_client(client.accumulator_ntru_secret_key(), t_ring)
            .unwrap();
        // Both views iterate mathematical r, even when storage omits delta_0.
        let selectors = if compact {
            evaluator.nonzero_ngsw_selectors(output)
        } else {
            evaluator.ngsw_selectors(output)
        };
        for (r, control) in selectors.iter() {
            evaluator.cmux_to(
                control,
                lhs.as_view(),
                rhs.as_view(),
                selected.as_mut_view(),
            );
            ring.decrypt_to(&selected, &mut decoded);
            let expected = if r == 2 { T::ONE } else { T::ZERO };
            assert!(decoded.iter().all(|&value| value == expected));
        }
    }
}
