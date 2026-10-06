//! Dense binary/ternary PBS. One iteration is one complete request.
//! LUTs, encryption, workspace/output allocation and validation are untimed.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_fourier --bench pbs --features rustfft

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod enabled {
    use std::hint::black_box;

    use criterion::{Criterion, criterion_group};
    use primus_encoding::RoundedCodec;
    #[cfg(feature = "rustfft")]
    use primus_fft::RustFftTable;
    #[cfg(feature = "tfhe-fft")]
    use primus_fft::TfheFftTable;
    use primus_fft::{FftTable, TorusFftValue};
    use primus_modulus::NativeModulus;
    use primus_modulus::PowOf2Modulus;
    use primus_ntru::SecretKeyDistr;
    use primus_tfhe_ntru_fourier::TfheContext;
    use primus_tfhe_test_support::{
        benchmark::{PBS_WORKLOADS, PbsWorkload},
        parameters::ntru,
    };
    use rand::{SeedableRng, rngs::StdRng};

    // The ternary profile has its own decomposition/noise budget. Its timing must
    // not be divided by the binary timing to claim a secret-distribution speedup.
    fn pbs<T: TorusFftValue, Table: FftTable>(
        c: &mut Criterion,
        backend: &str,
        workload: PbsWorkload,
        ternary: bool,
    ) {
        let secret = if ternary {
            SecretKeyDistr::UniformTernary
        } else {
            SecretKeyDistr::UniformBinary
        };
        let kind = if ternary { "ternary" } else { "binary" };
        let name = format!(
            "ntru/{backend}/u{}/{kind}/{}/n{}_N{}",
            T::BITS,
            workload.name,
            workload.lwe_dimension,
            workload.poly_length
        );
        let parameters = ntru::pbs(NativeModulus::<T>::new(), workload, secret);
        let input_codec = RoundedCodec::new(
            T::as_from(workload.plaintext_modulus),
            parameters.external_lwe().cipher_modulus(),
        );
        // Cached owned state avoids both eager setup during --list and repeated key
        // generation for each Criterion sample. Evaluators borrow this state locally.
        let mut fixture = None;
        let mut verified = false;
        c.bench_function(&format!("{name}/complete"), |b| {
            let (context, client, server, input, lut) = fixture.get_or_insert_with(|| {
                let context =
                    TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters.clone());
                let mut rng = StdRng::seed_from_u64(42);
                let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
                let input = context
                    .encryptor(client.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .encrypt_padded(T::ONE, &mut rng)
                    .unwrap();
                let domain = workload.plaintext_modulus as usize / 2;
                let lut = context
                    .parameters()
                    .lookup_table_compiler(&input_codec)
                    .unwrap()
                    .compile_fn(|x| T::as_from((x + domain - 1) % domain))
                    .unwrap();
                (context, client, server, input, lut)
            });
            let mut evaluator = context.evaluator(server).unwrap();
            let mut output = context.allocate_lwe_ciphertext();
            if !verified {
                evaluator.apply_lookup_table_to(input.as_view(), lut, output.as_mut_view());
                assert_eq!(
                    context
                        .decryptor(client.external_lwe_secret_key(), &input_codec)
                        .unwrap()
                        .decrypt(output.as_view())
                        .unwrap(),
                    T::ZERO
                );
                verified = true;
            }
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(lut),
                    black_box(output.as_mut_view()),
                )
            });
        });
    }

    // Register the primary engine's word and secret comparisons once.
    fn primary<Table: FftTable>(c: &mut Criterion, backend: &str) {
        let [boolean, shortint] = PBS_WORKLOADS;
        pbs::<u32, Table>(c, backend, boolean, false);
        pbs::<u64, Table>(c, backend, shortint, false);
        pbs::<u64, Table>(c, backend, boolean, true);
    }

    fn bench_pbs(c: &mut Criterion) {
        #[cfg(feature = "rustfft")]
        primary::<RustFftTable>(c, "rustfft");
        #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
        primary::<TfheFftTable>(c, "tfhe_fft");
        #[cfg(all(feature = "rustfft", feature = "tfhe-fft"))]
        pbs::<u64, TfheFftTable>(c, "tfhe_fft", PBS_WORKLOADS[1], false);
    }

    criterion_group!(benches, bench_pbs);
}

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_main!(enabled::benches);

#[cfg(not(any(feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    eprintln!("Enable rustfft or tfhe-fft to run this benchmark.");
}
