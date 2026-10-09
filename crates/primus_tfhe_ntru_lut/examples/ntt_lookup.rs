//! Evaluate (x*x + 3*x + 7) mod 65536 on eight two-bit chunks: 16-bit input and output.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt`
//! Sparse BR and public-lift setup: see the crate README.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, NttLookupTableEvaluator, experimental};
use primus_tfhe_ntru_ntt::TfheContext;
use rand::{SeedableRng, rngs::StdRng};

// The paired experimental entry fixes u64 coefficients, key domains and chunk layout.
type Word = u64;

fn main() {
    let config = experimental::NTT_CLASSIC_LOOKUP_U64;
    let parameters = config.try_prepare().unwrap();
    let chunks = parameters.chunk_format();
    // Eight two-bit chunks; five low chunks fill N=1024 coefficients,
    // and three high chunks select among 64 polynomials per output.
    let layout = parameters.layout();
    let input_bits = chunks.bit_count(layout.input_chunk_count);
    let output_bits = chunks.bit_count(layout.output_chunk_count);
    // Evaluate the cleartext function in u64; its intermediate can exceed u32.
    let function = |x: Word| (x * x + 3 * x + 7) & ((1u64 << output_bits) - 1);
    println!("f(x) = (x*x + 3*x + 7) mod {}", 1u64 << output_bits);
    println!("Input: {input_bits} bits; output: {output_bits} bits");

    let context =
        TfheContext::<Word, Table, _>::try_from_cbs_parameters(parameters.one_hot().clone())
            .unwrap();
    // The factory prepares chunk input/return codecs at q and LUT encoding at Q.
    let codecs = parameters.codecs();

    // Client: generate independent LWE/NTRU secrets plus CBS-enabled server material.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context
        .try_generate_circuit_bootstrap_keys_with_parameters(
            parameters.key_switching(),
            parameters.as_ref().algorithm(),
            parameters.one_hot().gadget(),
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
    let mut input: Vec<_> = (0..layout.input_chunk_count)
        .map(|_| context.allocate_lwe_ciphertext())
        .collect();

    // Client: reuse cleartext buffers too; splitting/joining do not allocate.
    let mut input_digits = vec![Word::default(); layout.input_chunk_count];
    let mut output_digits = vec![Word::default(); layout.output_chunk_count];

    // Server: compile the public function independently of client secrets.
    let table = HighPrecisionLookupTable::try_from_parameters(
        context.parameters(),
        codecs.input_codec(),
        layout,
        |x, output| chunks.chunk(function(x as Word), output),
    )
    .unwrap();

    // Server: bind public material once and reuse all online buffers.
    let mut evaluator =
        NttLookupTableEvaluator::try_new(&context, parameters.key_switching(), &server_key, &table)
            .unwrap();
    let mut output = evaluator.allocate_output();

    // Eight two-bit chunks, written most-significant first.
    for x in [0b10_10_10_11_11_00_11_01, 0] {
        // Client -> server: split before encryption, least-significant chunk first.
        chunks.split_to(x, &mut input_digits);
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
        let result = chunks.join(&output_digits);
        assert_eq!(result, function(x));
        println!("f({x}) = {result}");
    }
}
