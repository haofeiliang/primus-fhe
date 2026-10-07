//! Dense binary/ternary PBS. One iteration is one complete request.
//! LUTs, encryption, workspace/output allocation and validation are untimed.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench pbs --features ntru-fourier,rustfft,tfhe-fft

use primus_tfhe::BlindRotationConfig;
use primus_tfhe::{PbsMessageConfig, RoundedPbsCodecs};
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_benchmarks::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::ntru,
};
use primus_tfhe_ntru_fourier::TfheContext;
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn pbs<T: TorusFftValue, Table: FftTable>(
    c: &mut Group<'_>,
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
    let name = format!("{kind}/{}", workload.name);
    let parameters = ntru::pbs(NativeModulus::<T>::new(), workload, secret);
    let codecs = parameters
        .pbs_codecs(PbsMessageConfig::new(T::as_from(
            workload.plaintext_modulus,
        )))
        .unwrap();
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let fixture =
        std::cell::LazyCell::new(|| Fixture::<T, Table>::new(parameters, codecs, workload));
    let mut verified = false;
    let case = Case::new("ntru", backend, T::BITS, format!("{name}/complete"));
    c.bench_function(case.id(), |b| {
        let Fixture {
            context,
            client,
            server,
            input,
            lut,
        } = &*fixture;
        let mut evaluator = context.evaluator(server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        if !verified {
            evaluator.apply_lookup_table_to(input.as_view(), lut, output.as_mut_view());
            assert_eq!(
                context
                    .decryptor(client.external_lwe_secret_key(), codecs.output_codec())
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ZERO
            );
            verified = true;
        }

        metadata::record("pbs", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(context.parameters()),
                "blind_rotation": metadata::blind_rotation(false),
                "plaintext_modulus": workload.plaintext_modulus,
                "encoding": "rounded_padded",
                "outputs": 1,
                "function": "(m + domain - 1) % domain",
                "fft_layout_fingerprint": metadata::fft_layout(context.table()),
            })
        });
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
fn primary<Table: FftTable>(c: &mut Group<'_>, backend: &str) {
    let [boolean, shortint] = PBS_WORKLOADS;
    pbs::<u32, Table>(c, backend, boolean, false);
    pbs::<u64, Table>(c, backend, shortint, false);
    pbs::<u64, Table>(c, backend, boolean, true);
}

pub fn bench_pbs(c: &mut Group<'_>) {
    #[cfg(feature = "rustfft")]
    primary::<RustFftTable>(c, "rustfft");
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    primary::<TfheFftTable>(c, "tfhe_fft");
    #[cfg(all(feature = "rustfft", feature = "tfhe-fft"))]
    pbs::<u64, TfheFftTable>(c, "tfhe_fft", PBS_WORKLOADS[1], false);
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: TorusFftValue, Table: FftTable> {
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_fourier::ClientKey<T>,
    server: primus_tfhe_ntru_fourier::ServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lut: primus_tfhe::LookupTable<T>,
}

impl<T: TorusFftValue, Table: FftTable> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_fourier::TfheParameters<T, PowOf2Modulus<T>>,
        codecs: RoundedPbsCodecs<T, primus_modulus::NativeModulus<T>, PowOf2Modulus<T>>,
        workload: PbsWorkload,
    ) -> Self {
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(parameters);
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context
            .try_generate_keys(BlindRotationConfig::Classic, None, &mut rng)
            .unwrap();
        let input = context
            .encryptor(client.external_lwe_secret_key(), codecs.input_codec())
            .unwrap()
            .encrypt_padded(T::ONE, &mut rng)
            .unwrap();
        let domain = workload.plaintext_modulus as usize / 2;
        let lut = context
            .parameters()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_fn(|x| T::as_from((x + domain - 1) % domain))
            .unwrap();
        Self {
            context,
            client,
            server,
            input,
            lut,
        }
    }
}
