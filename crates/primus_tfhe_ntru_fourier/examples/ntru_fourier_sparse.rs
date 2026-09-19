//! Experimental fixed-weight NTRU PBS. Functional parameters, not a security recommendation.

use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn run<Table: FftTable>() {
    const DIMENSION: usize = 728;
    const WEIGHT: usize = 33;
    let modulus = NativeModulus::<u32>::new();
    let decomposition = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIMENSION,
            16,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
            0.7,
        ),
        poly_length: 1024,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: decomposition,
        key_switching: decomposition,
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, Table>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB803);
    let mut generator = KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    // Map retries keep this invertible client fixed; failure returns an error.
    let server = generator
        .try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, &mut rng)
        .unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let codec = RoundedCodec::new(8, modulus);
    let lut = context
        .parameters()
        .compile_interleaved_lookup_table_fn(&codec, 3, |m, i| match i {
            0 => (m % 4) as u32,
            1 => (m / 4) as u32,
            _ => (m % 2) as u32,
        })
        .unwrap();
    let input = context
        .encryptor(&client)
        .unwrap()
        .encrypt_padded(7, &mut rng)
        .unwrap();
    let mut outputs = vec![LweCiphertext::zero(DIMENSION); 3];
    evaluator.apply_interleaved_lookup_table_to(&input, &lut, &mut outputs);
    let decryptor = context.decryptor(&client).unwrap();
    for (output, expected) in outputs.iter().zip([3, 1, 1]) {
        assert_eq!(
            codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
            expected
        );
    }
    println!("Sparse NTRU/Fourier message, carry and parity succeeded");
}

fn main() {
    run::<RustFftTable>();
    run::<TfheFftTable>();
}
