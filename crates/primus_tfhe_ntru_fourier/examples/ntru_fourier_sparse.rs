//! Compute x % 4 with sparse PBS; reuse the same LUT and evaluator.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_sparse --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::DecompositionBaseLog;
use primus_fft::RustFftTable as Table;
use primus_lattice::LweDimension;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_tfhe_ntru::{BlindRotationConfig, LweConfig};
use primus_tfhe_ntru_fourier::{
    BlindRotationAlgorithm, DecompositionConfig, GadgetEncryptionConfig, PbsMessageConfig,
    PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters);

    // Like basic PBS, input and output use the same message modulus.
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(32))
        .unwrap();

    // Client: generate sparse BR material from the fixed-weight secret.
    let mut rng = StdRng::seed_from_u64(42);
    // Three copies, 64 buckets. Map retries retain the same client secret.
    let (client_key, server_key) = context
        .try_generate_keys(
            BlindRotationAlgorithm::Sparse {
                copy_count: 3,
                bucket_count: 64,
            },
            None,
            &mut rng,
        )
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context
        .encryptor(external_secret, codecs.input_codec())
        .unwrap();
    let decryptor = context
        .decryptor(external_secret, codecs.output_codec())
        .unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: the ordinary PBS API also accepts sparse BR material.
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let lut = compiler.compile_fn(|x| (x % 4) as Word).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7, 2] {
        // Client -> server: send one encrypted, padded input.
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server -> client: reuse the LUT, evaluator and output buffer.
        evaluator.apply_lookup_table_to(input.as_view(), &lut, output.as_mut_view());

        // Client: decode with the configured output codec.
        let result = decryptor.decrypt(output.as_view()).unwrap();
        assert_eq!(result, message % 4);
        println!("f({message}) = {result}");
    }
}

// Key parameters: n=728, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> PbsParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    BlindRotationConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(728),
            cipher_modulus: PowOf2Modulus::new(lwe_modulus).into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            noise_standard_deviation: 3.2 * lwe_modulus as f64 / 16384.0,
        },
        acc_modulus: modulus.into(),
        acc_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationAlgorithm::Sparse {
            copy_count: 3,
            bucket_count: 64,
        },
    }
    .try_prepare()
    .and_then(|parameters| {
        // Return key switch in the external q domain.
        parameters.try_with_key_switching(GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(3),
                level_count: None,
            },
            noise_standard_deviation: 3.2,
        })
    })
    .unwrap()
}
