//! Use sparse NTRU PBS to return message, carry and parity from one encrypted input.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_sparse`
//! For u64, change Word to u64 and U32NttTable to U64NttTable.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_encoding::RoundedCodec;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable as Table;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Set false to run the same interleaved ManyLUT with classic PBS.
const SPARSE: bool = true;

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;

// Public parameters: n=728, N=1024, t=16; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus = if Word::BITS == 32 {
        132_120_577
    } else {
        1_125_899_906_826_241u64
    } as Word;
    let modulus = BarrettModulus::new(ring_modulus);
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            728,
            16, // Padded inputs occupy 0..8.
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * lwe_modulus as f64 / 16384.0,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: DecompositionConfig {
            log_basis: 3,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
    })
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();
    // The input uses padded t=16. Compile t=8 outputs at Q and decode at q.
    let table_codec =
        RoundedCodec::new(8, context.parameters().accumulator_ntru().cipher_modulus());
    let output_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());

    // Client: explicitly request sparse evaluation material from this fixed-weight secret.
    let mut rng = StdRng::seed_from_u64(42);
    let mut generator = KeyGenerator::new(&context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    // Three copies, 64 buckets. Map retries retain the same client secret.
    let server_key = if SPARSE {
        generator.try_generate_sparse_server_key(&client_key, 3, 64, &mut rng)
    } else {
        generator.try_generate_server_key(&client_key, None, &mut rng)
    }
    .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server: receive server_key; compile three public functions sharing one rotation.
    let lut = context
        .parameters()
        .compile_interleaved_lookup_table_with_codec_fn(&table_codec, 3, |m, i| match i {
            0 => (m % 4) as Word,
            1 => (m / 4) as Word,
            _ => (m % 2) as Word,
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 3];

    for message in [7 as Word, 2] {
        // Client -> server: send an encrypted padded input in 0..8.
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();

        // Server -> client: return message, carry and parity, reusing the evaluator.
        evaluator.apply_interleaved_lookup_table_to(&input, &lut, &mut outputs);

        // Client: decode with the output codec, not the input's t=16 codec.
        for (output, expected) in outputs.iter().zip([message % 4, message / 4, message % 2]) {
            let value = output_codec.decode_value(decryptor.decrypt_phase(output).unwrap());
            assert_eq!(value, expected);
        }
        println!("input {message}: message/carry/parity decoded correctly");
    }
}
