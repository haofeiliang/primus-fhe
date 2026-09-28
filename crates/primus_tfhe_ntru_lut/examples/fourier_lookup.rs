//! Evaluate (x*x + 3*x + 7) mod 65536 on eight two-bit chunks: 16-bit input and output.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup`
//! For u64, change Word to u64; for TFHE-FFT, use TfheFftTable as Table.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_fft::RustFftTable as Table;
use primus_lwe::LweParameters;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheContext, TfheParameters,
};
use primus_tfhe_ntru_lut::{
    FourierLookupTableEvaluator, HighPrecisionLookupTable, LookupTableConfig,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
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

// Public parameters: n=800, N=1024, t=8; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            800,
            8, // Padded inputs occupy 0..4.
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::UniformBinary,
            lwe_modulus as f64 * 2.046151696979124e-6,
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

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: if Word::BITS == 32 { 2 } else { 8 },
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if Word::BITS == 32 { 3 } else { 8 },
            level_count: Some(if Word::BITS == 32 { 4 } else { 3 }),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

fn main() {
    println!("f(x) = (x*x + 3*x + 7) mod {}", 1u64 << OUTPUT_BITS);
    println!("Input: {INPUT_BITS} bits; output: {OUTPUT_BITS} bits");

    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();

    // Client: generate independent LWE/NTRU secrets plus CBS-enabled server material.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(Some(circuit_config()), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input: Vec<_> = (0..CONFIG.input_chunk_count)
        .map(|_| context.allocate_lwe_ciphertext())
        .collect();

    // Server: the public callback returns one output digit for a complete input x.
    let table = HighPrecisionLookupTable::try_new(context.parameters(), CONFIG, |x, output| {
        ((function(x) >> (CHUNK_BITS * output)) & 3) as Word
    })
    .unwrap();
    let mut evaluator =
        FourierLookupTableEvaluator::try_new(&context, &server_key, &table).unwrap();
    let mut output = evaluator.allocate_output();

    // Eight two-bit chunks, written most-significant first.
    for x in [0b10_10_10_11_11_00_11_01, 0] {
        // Client -> server: split before encryption, least-significant chunk first.
        for (i, chunk) in input.iter_mut().enumerate() {
            let digit = ((x >> (CHUNK_BITS * i)) & 3) as Word;
            encryptor.encrypt_padded_to(digit, chunk, &mut rng).unwrap();
        }

        // Server -> client: select, rotate and return encrypted output chunks.
        evaluator.evaluate_to(&input, &mut output);

        // Client: decode and join chunks in the same least-significant-first order.
        let mut result = 0usize;
        for (i, chunk) in output.iter().enumerate() {
            let digit = decryptor.decrypt(chunk).unwrap() as usize;
            result |= digit << (CHUNK_BITS * i);
        }
        assert_eq!(result, function(x));
        println!("f({x}) = {result}");
    }
}
