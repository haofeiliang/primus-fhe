//! One complete CBS into a reused gadget ciphertext; NTRU also measures full
//! and nonzero one-hot batches. Keygen, encryption, allocation and the CMux
//! correctness probe are outside timing. Ordinary CBS uses t4; one-hot uses t8.
//! Classic/sparse pairs share n728/h32/N1024 secrets and separately seeded inputs.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench cbs --features ntru-fourier,rustfft,tfhe-fft

use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_lattice::ngsw::FourierNgswIter;
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_tfhe_benchmarks::parameters::{N, ntru};
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapEvaluator, KeyGenerator, OneHotCircuitBootstrapEvaluator, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str, sparse: bool) {
    let input_codec = RoundedCodec::new(T::as_from(4u32), PowOf2Modulus::new(T::ONE << 24u32));
    let kind = if sparse { "sparse" } else { "classic" };
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let name = format!("{kind}/complete");
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(parameters, input_codec, sparse, T::ONE)
    });
    let mut verified = false;
    c.throughput(criterion::Throughput::Elements(1));
    let case = Case::new("ntru", backend, T::BITS, &name);
    c.bench_function(case.id(), |b| {
        let Fixture {
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        } = &*fixture;
        let mut resources = context
            .bootstrap_resources(server.blind_rotation_key())
            .unwrap();
        let mut evaluator = CircuitBootstrapEvaluator::try_new(
            &resources,
            server.circuit_bootstrap_key().unwrap(),
            &input_codec,
        )
        .unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input.as_view(), &mut output, &mut resources);
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(&output, lhs, rhs, &mut selected, &mut resources);
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(
                    client.accumulator_ntru_secret_key(),
                    ScaledCodec::new(
                        input_codec.plaintext_modulus(),
                        context.parameters().accumulator_ntru().cipher_modulus(),
                    ),
                )
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }

        metadata::record("cbs", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(context.parameters()),
                "blind_rotation": metadata::blind_rotation(sparse),
                "cbs": metadata::cbs(ntru::cbs::<T>()),
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
                black_box(&mut output),
                &mut resources,
            )
        });
    });
}

// The compact batch omits delta_0. Compare equal input geometry to isolate the
// saved selector work; one iteration produces M or M-1 complete NGSW controls.
fn one_hot<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str, sparse: bool) {
    let input_codec = RoundedCodec::new(T::as_from(8u32), PowOf2Modulus::new(T::ONE << 24u32));
    let br = if sparse { "sparse" } else { "classic" };
    let fixture = std::cell::LazyCell::new(|| {
        Fixture::<T, Table>::new(
            ntru::diagnostic(NativeModulus::<T>::new()),
            input_codec,
            sparse,
            T::TWO,
        )
    });
    for compact in [false, true] {
        let kind = if compact { "nonzero" } else { "full" };
        let mut verified = false;
        let name = format!("one_hot/{br}/M4/{kind}");
        c.throughput(criterion::Throughput::Elements(if compact { 3 } else { 4 }));
        let case = Case::new("ntru", backend, T::BITS, &name);
        c.bench_function(case.id(), |b| {
            let Fixture {
                context,
                server,
                input,
                ..
            } = &*fixture;
            let mut resources = context
                .bootstrap_resources(server.blind_rotation_key())
                .unwrap();
            let mut evaluator = OneHotCircuitBootstrapEvaluator::try_new(
                &resources,
                server.circuit_bootstrap_key().unwrap(),
                &input_codec,
            )
            .unwrap();
            let mut output = if compact {
                evaluator.allocate_nonzero_ngsw_output()
            } else {
                evaluator.allocate_ngsw_output()
            };
            if !verified {
                if compact {
                    evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut output, &mut resources);
                } else {
                    evaluator.one_hot_ngsw_to(input.as_view(), &mut output, &mut resources);
                }
                fixture.check_one_hot(&output, &evaluator, &mut resources, compact, input_codec);
                verified = true;
            }
            metadata::record("cbs", &case, || {
                serde_json::json!({
                    "parameters": metadata::ntru(context.parameters()),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "cbs": metadata::cbs(ntru::cbs::<T>()),
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
                        &mut resources,
                    )
                });
            } else {
                b.iter(|| {
                    evaluator.one_hot_ngsw_to(
                        black_box(input.as_view()),
                        black_box(&mut output),
                        &mut resources,
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
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_fourier::ClientKey<T>,
    server: primus_tfhe_ntru_fourier::ServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lhs: primus_ntru::NtruCiphertext<Vec<T>>,
    rhs: primus_ntru::NtruCiphertext<Vec<T>>,
}

impl<T: TorusFftValue, Table: FftTable> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_fourier::TfheParameters<T, PowOf2Modulus<T>>,
        input_codec: primus_encoding::RoundedCodec<T, PowOf2Modulus<T>>,
        sparse: bool,
        message: T,
    ) -> Self {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters);
        let mut rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let client = generator.try_generate_client_key(&mut rng).unwrap();
        let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
        let server = generator
            .try_generate_server_key(&client, blind_rotation, Some(ntru::cbs::<T>()), &mut rng)
            .unwrap();
        // Input/candidate encryption is identical across the two BR choices.
        let mut rng = StdRng::seed_from_u64(43);
        let input = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .encrypt_padded(message, &mut rng)
            .unwrap();
        let mut ring = context
            .accumulator_client(
                client.accumulator_ntru_secret_key(),
                ScaledCodec::new(
                    input_codec.plaintext_modulus(),
                    context.parameters().accumulator_ntru().cipher_modulus(),
                ),
            )
            .unwrap();
        let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
        let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
        Self {
            context,
            client,
            server,
            input,
            lhs,
            rhs,
        }
    }

    /// Check each selector through a CMux, including the compact r-1 indexing.
    fn check_one_hot(
        &self,
        output: &[primus_fft::Complex64],
        evaluator: &OneHotCircuitBootstrapEvaluator<'_, T, Table, PowOf2Modulus<T>>,
        resources: &mut primus_tfhe_ntru_fourier::BootstrapResources<
            '_,
            T,
            Table,
            PowOf2Modulus<T>,
        >,
        compact: bool,
        input_codec: RoundedCodec<T, PowOf2Modulus<T>>,
    ) {
        let Self {
            context,
            client,
            lhs,
            rhs,
            ..
        } = self;
        let parameters = evaluator.parameters();
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![T::ZERO; N];
        let mut ring = context
            .accumulator_client(
                client.accumulator_ntru_secret_key(),
                ScaledCodec::new(
                    input_codec.plaintext_modulus(),
                    context.parameters().accumulator_ntru().cipher_modulus(),
                ),
            )
            .unwrap();
        // Semantic ciphertext iteration keeps selector boundaries tied
        // to the public CBS layout, including compact index r-1.
        for (index, control) in
            FourierNgswIter::new(output, evaluator.ngsw_selector_len()).enumerate()
        {
            let (fft, product) = resources.external_product_workspaces();
            control.cmux_to(
                lhs,
                rhs,
                &mut selected,
                parameters.output_basis(),
                fft,
                product,
            );
            ring.decrypt_to(&selected, &mut decoded);
            let expected = if index + usize::from(compact) == 2 {
                T::ONE
            } else {
                T::ZERO
            };
            assert!(decoded.iter().all(|&value| value == expected));
        }
    }
}
