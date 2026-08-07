use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_ntru_ntt::{NtruTfheParameters, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const LWE_DIMENSION: usize = 64;
const PLAIN_MODULUS: u32 = 4;
const CIPHER_MODULUS: u32 = 132_120_577;

fn parameters() -> NtruTfheParameters<u32, BarrettModulus<u32>> {
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    let accumulator = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        0.7,
    );
    let client = NtruParameters::new(
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        0.7,
    );
    NtruTfheParameters::try_new(
        external_lwe,
        NlevParameters::with_ntru_params(&accumulator, 9, None),
        NlevParameters::with_ntru_params(&client, 9, None),
    )
    .unwrap()
}

#[test]
fn evaluates_nontrivial_lookup_table() {
    let parameters = parameters();
    let table = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        parameters.bootstrapping().ntru().cipher_modulus(),
    )
    .unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_5446_4845);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let lut = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    for input in 0..2u32 {
        let ciphertext = encryptor.encrypt_padded(input, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&ciphertext, &lut);
        assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1 - input);
    }
}
