//! Evaluate (x*x + 3*x + 7) mod 65536 on eight two-bit chunks: 16-bit input and output.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt`
//! Sparse BR and public-lift setup: see the crate README.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_encoding::RoundedCodec;
use primus_lattice::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_ntt::U64NttTable as Table;
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationAlgorithm;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{BlindRotationConfig, LweConfig};
use primus_tfhe_ntru_lut::{
    ChunkFormat, HighPrecisionLookupTable, LookupTableConfig, NttLookupTableEvaluator,
};
use primus_tfhe_ntru_ntt::{
    CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

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
const CHUNKS: ChunkFormat = ChunkFormat::new(2);

fn main() {
    let input_bits = CHUNKS.bit_count(CONFIG.input_chunk_count);
    let output_bits = CHUNKS.bit_count(CONFIG.output_chunk_count);
    println!("f(x) = (x*x + 3*x + 7) mod {}", 1u64 << output_bits);
    println!("Input: {input_bits} bits; output: {output_bits} bits");

    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::try_from_parameters(parameters).unwrap();
    // Public message encoding at external q, chosen independently of key generation.
    let input_codec = RoundedCodec::new(
        CHUNKS.plaintext_modulus(),
        context.parameters().external_lwe().cipher_modulus(),
    );

    // Client: generate independent LWE/NTRU secrets plus CBS-enabled server material.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_keys(
            BlindRotationAlgorithm::Classic,
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

    // Client: reuse cleartext buffers too; splitting/joining do not allocate.
    let mut input_digits = vec![Word::default(); CONFIG.input_chunk_count];
    let mut output_digits = vec![Word::default(); CONFIG.output_chunk_count];

    // Server: compile the public function independently of client secrets.
    let table = HighPrecisionLookupTable::try_from_parameters(
        context.parameters(),
        &input_codec,
        CONFIG,
        |x, output| CHUNKS.chunk(function(x as Word), output),
    )
    .unwrap();

    // Server: bind public material once and reuse all online buffers.
    let mut evaluator = NttLookupTableEvaluator::try_new(&context, &server_key, &table).unwrap();
    let mut output = evaluator.allocate_output();

    // Eight two-bit chunks, written most-significant first.
    for x in [0b10_10_10_11_11_00_11_01, 0] {
        // Client -> server: split before encryption, least-significant chunk first.
        CHUNKS.split_to(x, &mut input_digits);
        for (&digit, chunk) in input_digits.iter().zip(&mut input) {
            encryptor
                .encrypt_padded_to(digit, chunk.as_mut_view(), &mut rng)
                .unwrap();
        }

        // Server -> client: select, rotate and return encrypted output chunks.
        evaluator.evaluate_to(&input, &mut output);

        // Client: decode and join chunks in the same least-significant-first order.
        for (chunk, digit) in output.iter().zip(&mut output_digits) {
            *digit = decryptor.decrypt(chunk.as_view()).unwrap();
        }
        let result = CHUNKS.join(&output_digits);
        assert_eq!(result, function(x));
        println!("f({x}) = {result}");
    }
}

// Return 16 bits and retain dependence on the high input chunks. Input and output
// chunk counts are independent; this example chooses eight for both.
fn function(x: Word) -> Word {
    // The cleartext polynomial can exceed u32 even for a 16-bit input.
    (x * x + 3 * x + 7) & ((1u64 << CHUNKS.bit_count(CONFIG.output_chunk_count)) - 1)
}

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> PbsParameters<Word, PowOf2Modulus<Word>> {
    // NTT requires a prime admitting a 2N-th root, rather than a power-of-two modulus.
    let ring_modulus: Word = 1_125_899_906_826_241;
    let modulus = BarrettModulus::new(ring_modulus);
    let lwe_modulus: Word = 1 << 24;

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };

    BlindRotationConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(800),
            cipher_modulus: PowOf2Modulus::new(lwe_modulus).into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(800, 32),
            noise_standard_deviation: lwe_modulus as f64 * 2.046151696979124e-6,
        },
        acc_modulus: modulus.into(),
        acc_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationAlgorithm::Classic,
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

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CbsGadgetConfig {
    let internal = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: internal,
        scheme_switch: internal,
    }
}
