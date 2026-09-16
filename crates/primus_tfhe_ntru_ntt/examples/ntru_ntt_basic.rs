//! Minimal complete NTRU/NTT programmable-bootstrap workflow.
//!
//! These small parameters are for demonstration only, not for production.

use primus_encoding::RoundedCodec;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_ntt::{BivariateLookupTable, NtruTfheParameters, TfheContext};

fn main() {
    const N: usize = 256;
    const LWE_DIMENSION: usize = 8;
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        16,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = NtruParameters::new(N, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let parameters = NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap();
    let table = U32NttTable::new(N.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();

    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    // Publish this LWE key to encrypt inputs; keep the client key for decryption.
    // These demonstration parameters have no public-key security/noise assessment.
    let public_key = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&public_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    // Input t=16 leaves programmable inputs 0..8. Encode message, carry and
    // parity with output t=4; three outputs occupy four interleaved slots.
    let output_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let lut = context
        .compile_interleaved_lookup_table_fn(&output_codec, 3, |input, output| match output {
            0 => (input % 4) as u32,
            1 => (input / 4) as u32,
            _ => (input % 2) as u32,
        })
        .unwrap();
    let mut input = LweCiphertext::zero(LWE_DIMENSION);
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![input.clone(); lut.output_count()];
    for message in [7u32, 2] {
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();
        evaluator.apply_interleaved_lookup_table_to(&input, &lut, &mut outputs);
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[0]).unwrap()),
            message % 4
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[1]).unwrap()),
            message / 4
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[2]).unwrap()),
            message % 2
        );
    }
    // Compare independent encrypted x in 0..3 and y in 0..2 via z=x+3*y.
    // Their common input scale is q/16; output bits use the q/4 codec above.
    let compare = BivariateLookupTable::try_new(
        3,
        2,
        N,
        context.parameters().external_lwe().plaintext_codec(),
        &output_codec,
        |x, y| u32::from(x > y),
    )
    .unwrap();
    for (x, y) in [(2u32, 1u32), (0, 1)] {
        let lhs = encryptor.encrypt_padded(x, &mut rng).unwrap();
        let rhs = encryptor.encrypt_padded(y, &mut rng).unwrap();
        compare.pack_to(&lhs, &rhs, &mut input);
        evaluator.apply_lookup_table_to(&input, compare.lookup_table(), &mut outputs[0]);
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&outputs[0]).unwrap()),
            u32::from(x > y)
        );
    }
    println!("NTRU/NTT programmable bootstrap succeeded");
}
