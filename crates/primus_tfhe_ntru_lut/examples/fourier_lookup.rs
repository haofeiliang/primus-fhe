//! Evaluate (x*x + 3*x + 7) mod 65536 on eight two-bit chunks: 16-bit input and output.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft`
//! To use TfheFftTable, switch the Table import, this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable as Table;
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_tfhe::{BlindRotationConfig, DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, DecompositionConfig, KeyGenerator, TfheConfig, TfheContext,
    TfheParameters,
};
use primus_tfhe_ntru_lut::{
    FourierLookupTableEvaluator, HighPrecisionLookupTable, LookupTableConfig,
};
use rand::{SeedableRng, rngs::StdRng};

// The same fixed-weight binary secret supports both choices. To select sparse BR,
// use BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 64 }.
const BLIND_ROTATION: BlindRotationConfig = BlindRotationConfig::Classic;

// This example uses u64 coefficients with the explicit parameters below.
type Word = u64;
const N: usize = 1024;

// M=4: eight input chunks represent 16 bits. Five low chunks fill N=1024
// coefficients; three high chunks select among 64 polynomials per output chunk.
const CONFIG: LookupTableConfig = LookupTableConfig {
    input_chunk_count: 8,
    output_chunk_count: 8,
    coefficient_chunk_count: 5,
};
const CHUNK_BITS: usize = 2;
const INPUT_BITS: usize = CHUNK_BITS * CONFIG.input_chunk_count;
const OUTPUT_BITS: usize = CHUNK_BITS * CONFIG.output_chunk_count;

// Return 16 bits and retain dependence on the high input chunks. Input and output
// chunk counts are independent; this example chooses eight for both.
fn function(x: usize) -> usize {
    // The cleartext polynomial can exceed u32 even for a 16-bit input.
    let x = x as u64;
    ((x * x + 3 * x + 7) % (1u64 << OUTPUT_BITS)) as usize
}

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweEncryptionParameters::new(
            LweDimension::new(800),
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
            lwe_modulus as f64 * 2.046151696979124e-6,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: PolyLength::new(N),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
    })
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

// Demonstrates client setup and repeated server lookups with one reusable evaluator.
fn main() {
    println!("f(x) = (x*x + 3*x + 7) mod {}", 1u64 << OUTPUT_BITS);
    println!("Input: {INPUT_BITS} bits; output: {OUTPUT_BITS} bits");

    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters);
    // Public message encoding at external q, chosen independently of key generation.
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());

    // Client: generate independent LWE/NTRU secrets plus CBS-enabled server material.
    let mut rng = StdRng::seed_from_u64(42);
    let mut generator = KeyGenerator::new(&context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    let server_key = generator
        .try_generate_server_key(
            &client_key,
            BLIND_ROTATION,
            Some(circuit_config()),
            &mut rng,
        )
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let decryptor = context.decryptor(external_secret, &input_codec).unwrap();
    let mut input: Vec<_> = (0..CONFIG.input_chunk_count)
        .map(|_| context.allocate_lwe_ciphertext())
        .collect();

    // Public preprocessing: the callback returns one output digit for a complete input x.
    let table = HighPrecisionLookupTable::try_new(
        context.parameters().poly_length(),
        context.parameters().accumulator_ntru().cipher_modulus(),
        &input_codec,
        CONFIG,
        |x, output| ((function(x) >> (CHUNK_BITS * output)) & 3) as Word,
    )
    .unwrap();

    // Client: generate NLEV[1] only for sparse plans with public lifts. Here its
    // basis/noise match BR (above, sigma=0.7); the ciphertext uses fresh randomness.
    // A separate NlevParameters value can select another lift basis or noise.
    let lift_parameters = context.parameters().blind_rotation();
    let lift = if matches!(BLIND_ROTATION, BlindRotationConfig::Sparse { .. })
        && table.needs_public_lift()
    {
        Some(
            generator
                .try_generate_public_lift_key(
                    client_key.accumulator_ntru_secret_key(),
                    lift_parameters,
                    &mut rng,
                )
                .unwrap(),
        )
    } else {
        None // Classic reuses its initializer; no-Lift plans need neither.
    };

    // Server: bind public material once and reuse all online buffers.
    let mut evaluator = FourierLookupTableEvaluator::try_new(
        &context,
        &server_key,
        lift.as_ref().map(|key| (key.as_view(), lift_parameters)),
        &table,
    )
    .unwrap();
    let mut output = evaluator.allocate_output();

    // Eight two-bit chunks, written most-significant first.
    for x in [0b10_10_10_11_11_00_11_01, 0] {
        // Client -> server: split before encryption, least-significant chunk first.
        for (i, chunk) in input.iter_mut().enumerate() {
            let digit = ((x >> (CHUNK_BITS * i)) & 3) as Word;
            encryptor
                .encrypt_padded_to(digit, chunk.as_mut_view(), &mut rng)
                .unwrap();
        }

        // Server -> client: select, rotate and return encrypted output chunks.
        evaluator.evaluate_to(&input, &mut output);

        // Client: decode and join chunks in the same least-significant-first order.
        let mut result = 0usize;
        for (i, chunk) in output.iter().enumerate() {
            let digit = decryptor.decrypt(chunk.as_view()).unwrap() as usize;
            result |= digit << (CHUNK_BITS * i);
        }
        assert_eq!(result, function(x));
        println!("f({x}) = {result}");
    }
}
