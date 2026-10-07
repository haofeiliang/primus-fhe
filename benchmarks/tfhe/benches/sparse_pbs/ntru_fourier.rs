//! Classic versus sparse PBS for the same fixed-weight secret: n728/h32/N1024.
//! One iteration is a complete PBS into reused output/workspace buffers.
//! Key generation, encryption and validation are outside timing.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench sparse_pbs --features ntru-fourier,rustfft,tfhe-fft

use primus_tfhe::PbsMessageConfig;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_tfhe_benchmarks::parameters::ntru;
use primus_tfhe_ntru_fourier::{KeyGenerator, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

fn pbs_pair<T: TorusFftValue, Table: FftTable>(c: &mut Group<'_>, backend: &str) {
    let parameters = ntru::diagnostic(NativeModulus::<T>::new());
    let codecs = parameters
        .pbs_codecs(PbsMessageConfig::new(T::as_from(8u32)))
        .unwrap();
    let name = "fixed_weight";
    // Hold one context/client pair, but build each server key only when selected.
    let fixture = std::cell::LazyCell::new(|| {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters);
        let mut rng = StdRng::seed_from_u64(42);
        let client = KeyGenerator::new(&context)
            .try_generate_client_key(&mut rng)
            .unwrap();
        (context, client)
    });
    for sparse in [false, true] {
        let kind = if sparse { "sparse" } else { "classic" };
        let server = std::cell::LazyCell::new(|| {
            let (context, client) = &*fixture;
            let mut generator = KeyGenerator::new(context);
            let mut rng = StdRng::seed_from_u64(4242);
            let blind_rotation = primus_tfhe_benchmarks::benchmark::blind_rotation(sparse);
            generator
                .try_generate_server_key(client, blind_rotation, None, &mut rng)
                .unwrap()
        });
        let mut verified = false;
        let case = Case::new("ntru", backend, T::BITS, format!("{name}/{kind}/complete"));
        c.bench_function(case.id(), |b| {
            let (context, client) = &*fixture;
            let server = &*server;
            let mut rng = StdRng::seed_from_u64(43);
            let input = context
                .encryptor(client.external_lwe_secret_key(), codecs.input_codec())
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let lut = context
                .parameters()
                .lookup_table_compiler(&codecs)
                .unwrap()
                .compile_fn(|m| T::as_from((m + 1) % 4))
                .unwrap();
            let mut evaluator = context.evaluator(server).unwrap();
            let mut output = context.allocate_lwe_ciphertext();
            if !verified {
                evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());
                assert_eq!(
                    context
                        .decryptor(client.external_lwe_secret_key(), codecs.output_codec())
                        .unwrap()
                        .decrypt(output.as_view())
                        .unwrap(),
                    T::TWO
                );
                verified = true;
            }

            metadata::record("sparse_pbs", &case, || {
                serde_json::json!({
                    "parameters": metadata::ntru(context.parameters()),
                    "blind_rotation": metadata::blind_rotation(sparse),
                    "plaintext_modulus": 8,
                    "encoding": "rounded_padded",
                    "outputs": 1,
                    "function": "(m+1)%4",
                    "client_seed": 42,
                    "key_seed": 4242,
                    "input_seed": 43,
                    "fft_layout_fingerprint": metadata::fft_layout(context.table()),
                })
            });
            b.iter(|| {
                evaluator.apply_lookup_table_to(
                    black_box(input.as_view()),
                    black_box(&lut),
                    black_box(output.as_mut_view()),
                )
            });
        });
    }
}

pub fn bench_sparse(c: &mut Group<'_>) {
    #[cfg(feature = "rustfft")]
    {
        pbs_pair::<u32, RustFftTable>(c, "rustfft");
        pbs_pair::<u64, RustFftTable>(c, "rustfft");
    }
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    {
        pbs_pair::<u32, TfheFftTable>(c, "tfhe_fft");
        pbs_pair::<u64, TfheFftTable>(c, "tfhe_fft");
    }
}
