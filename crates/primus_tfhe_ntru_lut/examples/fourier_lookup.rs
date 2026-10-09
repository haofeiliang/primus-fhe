//! Evaluate (x*x + 3*x + 7) mod 65536 on 16-bit input and output.
//!
//! Run: cargo run --release -p primus_tfhe_ntru_lut --example fourier_lookup --features rustfft
//! Experimental arithmetic configuration; see guides/development/tfhe-parameters.md.

use primus_fft::RustFftTable as Table;
use primus_tfhe_ntru_lut::{FourierHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    let context = FourierHighPrecLutContext::<Word, Table, _>::try_from_config(
        experimental::FOURIER_CLASSIC_LOOKUP_U64,
    )
    .unwrap();
    let function = |x: Word| (x * x + 3 * x + 7) & 0xffff;
    println!("f(x) = (x*x + 3*x + 7) mod 65536");
    println!(
        "Input: {} bits; output: {} bits",
        context.input_bits(),
        context.output_bits()
    );

    // Public, offline compilation: eight two-bit chunks; default d=5 fills N=1024.
    // The compiler extracts output chunks from the pure integer function.
    let table = context.compile_fn(function).unwrap();

    // Client: generate paired secrets and complete server material once.
    // The public plan determines whether sparse BR needs an extra NLEV[1] lift.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&table, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = encryptor.allocate_input();

    // Server: receives only public parameters/table, evaluation keys and request chunks.
    let mut evaluator = context.evaluator(&server_key, &table).unwrap();
    let mut output = evaluator.allocate_output();

    // Client/server exchange reuses all ciphertext buffers for both requests.
    for x in [0b10_10_10_11_11_00_11_01, 0] {
        encryptor.encrypt_to(x, &mut input, &mut rng).unwrap();
        evaluator.evaluate_to(&input, &mut output);
        let result: Word = decryptor.decrypt(&output).unwrap();
        assert_eq!(result, function(x));
        println!("f({x}) = {result}");
    }
}
