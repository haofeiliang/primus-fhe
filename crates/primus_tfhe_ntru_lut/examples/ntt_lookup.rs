//! Evaluate a piecewise fee on 16-bit encrypted input and return a 16-bit result.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt`
//! Experimental arithmetic configuration; see guides/development/tfhe-parameters.md.

use primus_ntt::U64NttTable as Table;
use primus_tfhe_ntru_lut::{NttHighPrecLutContext, experimental};
use rand::{SeedableRng, rngs::StdRng};

type Word = u64;

fn main() {
    let config = experimental::NTT_CLASSIC_LOOKUP_U64;
    let context = NttHighPrecLutContext::<Word, Table, _>::try_from_config(config).unwrap();
    let fee = |x: Word| {
        if x < 16_384 {
            x / 4
        } else if x < 49_152 {
            4_096 + (x - 16_384) / 2
        } else {
            20_480 + (x - 49_152)
        }
    };
    println!("fee(x) = x/4                       if x < 16384");
    println!("       = 4096 + (x-16384)/2         if 16384 <= x < 49152");
    println!("       = 20480 + (x-49152)          if 49152 <= x < 65536");
    println!(
        "Input: {} bits; output: {} bits",
        context.input_bits(),
        context.output_bits()
    );

    // Server, offline: compile the public function; no secrets are needed.
    // Eight two-bit input chunks: low five select a coefficient (N=1024),
    // high three select a polynomial. Output chunks are configured independently.
    let table = context.compile_fn(fee).unwrap();

    // Client: generate paired secrets and complete server material once.
    // The public plan determines whether sparse BR needs an extra NLEV[1] lift.
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(&table, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = encryptor.allocate_input();

    // Server, offline: prepare the reusable evaluator.
    let mut evaluator = context.evaluator(&server_key, &table).unwrap();
    let mut output = evaluator.allocate_output();

    // Check breakpoints, endpoints and an interior value against explicit results.
    for (x, expected) in [
        (0u64, 0u64),
        (16_383, 4_095),
        (16_384, 4_096),
        (0b10_10_10_11_11_00_11_01, 17_894),
        (49_151, 20_479),
        (49_152, 20_480),
        (65_535, 36_863),
    ] {
        // Client -> server: the integer client encrypts the input chunks at q.
        encryptor.encrypt_to(x, &mut input, &mut rng).unwrap();

        // Server, online: select/rotate at Q and return the result chunks at q.
        evaluator.evaluate_to(&input, &mut output);

        // Client: decode and join the returned chunks.
        let result: Word = decryptor.decrypt(&output).unwrap();
        assert_eq!(result, expected);
        println!("fee({x}) = {result}");
    }
}
