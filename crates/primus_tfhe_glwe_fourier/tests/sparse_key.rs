use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{context::FourierGlweExternalProductContext, ggsw::FourierGgsw};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_tfhe::sparse::BucketMapError;
use primus_tfhe_glwe_fourier::{
    ClientKey, KeyGenerator, PbsOrder, SparseBootstrappingKeyError as Error, TfheContext,
    TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 128;

fn context<Table: FftTable>(distribution: SecretKeyDistr) -> TfheContext<u64, Table> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(16, 8, modulus, distribution, 0.7);
    let glwe = GlweParameters::new(1, N, 8, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let basis = ApproxSignedBasis::new(None, 8, Some(6));
    let parameters = TfheParameters::try_new(
        lwe,
        glwe,
        basis.clone(),
        basis,
        PbsOrder::KeyswitchBootstrap,
    )
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

fn check_selectors<Table: FftTable>() {
    let context = context::<Table>(SecretKeyDistr::fixed_hamming_weight_binary(16, 4));
    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(0x5350_4152_5345);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let glwe = context.parameters().accumulator_glwe();
    let mut accumulator_client = context.accumulator_client(&client).unwrap();
    let mut message = vec![0; N];
    message[0] = 1;
    message[N - 1] = 2;
    // Nontrivial masks and both ends of the polynomial exercise every GGSW row
    // and negacyclic multiplication after the coefficient/Fourier round trip.
    let input = accumulator_client.encrypt(&message, &mut rng);
    let size = context.parameters().blind_rotation_ggsw().size();
    let mut fft = context.new_fft_engine();
    let mut external_product = FourierGlweExternalProductContext::new(size);
    let mut control = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
    let mut product = accumulator_client.allocate_ciphertext();
    let mut decoded = vec![0; N];

    // The second map must have at least one bucket with no public entries.
    for (copy_count, bucket_count) in [(3, 8), (1, 17)] {
        let key = generator
            .try_generate_sparse_bootstrapping_key(&client, copy_count, bucket_count, &mut rng)
            .unwrap();
        assert_eq!(key.input_dimension(), 16);
        assert_eq!(key.hamming_weight(), 4);
        assert_eq!(key.copy_count(), copy_count);
        assert_eq!(key.bucket_count(), bucket_count);
        assert_eq!(key.cipher_modulus(), None);
        assert_eq!(key.input_modulus(), glwe.cipher_modulus());
        assert_eq!(key.size(), size);
        assert_eq!(
            key.basis(),
            context.parameters().blind_rotation_ggsw().basis()
        );
        assert_eq!(
            key.as_slice().len(),
            (16 * copy_count + bucket_count) * size.ggsw_len()
        );
        let mut copies = [0; 16];
        let mut selected = [0; 16];
        let mut dummy_count = 0;
        for bucket in 0..key.bucket_count() {
            let (indices, ciphertexts) = key.bucket(bucket);
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
            let mut bucket_selection_count = 0;
            let mut ciphertext_count = 0;
            for (slot, ciphertext) in ciphertexts.enumerate() {
                ciphertext_count += 1;
                ciphertext.write_fourier_form(&mut control, &mut fft);
                control.external_product_to(
                    &input,
                    &mut product,
                    key.basis(),
                    &mut fft,
                    &mut external_product,
                );
                accumulator_client.decrypt_to(&product, &mut decoded);
                let bit = decoded[0];
                assert!(bit <= 1);
                for (&actual, &expected) in decoded.iter().zip(&message) {
                    assert_eq!(actual, bit * expected);
                }
                bucket_selection_count += bit;
                if slot < indices.len() {
                    copies[indices[slot]] += 1;
                    selected[indices[slot]] += bit;
                } else {
                    dummy_count += bit;
                }
            }
            assert_eq!(ciphertext_count, indices.len() + 1);
            assert_eq!(bucket_selection_count, 1);
        }
        assert_eq!(copies, [copy_count; 16]);
        assert_eq!(selected.as_slice(), client.small_lwe_secret_key().as_ref());
        assert_eq!(dummy_count as usize, bucket_count - 4);
    }
}

#[test]
fn encrypted_selectors_and_dummies_work_with_both_fft_tables() {
    check_selectors::<RustFftTable>();
    check_selectors::<TfheFftTable>();
}

#[test]
fn sparse_key_errors_do_not_consume_randomness() {
    let distribution = SecretKeyDistr::fixed_hamming_weight_binary(16, 4);
    let context = context::<RustFftTable>(distribution);
    let client = ClientKey::generate(context.parameters(), &mut StdRng::seed_from_u64(42));
    let malformed = ClientKey::new(
        LweSecretKey::new(vec![2; 16], distribution),
        client.glwe_secret_key().clone(),
        client.pbs_order(),
    );
    let mut generator = KeyGenerator::new(&context);
    for (client, copies, buckets, error) in [
        (
            &client,
            0,
            8,
            Error::BucketMap(BucketMapError::InvalidBucketParameters),
        ),
        (&client, 3, usize::MAX, Error::StorageSizeOverflow),
        (&malformed, 3, 8, Error::InvalidSecretCoefficients),
    ] {
        let mut rng = StdRng::seed_from_u64(43);
        let result =
            generator.try_generate_sparse_bootstrapping_key(client, copies, buckets, &mut rng);
        assert_eq!(result.err(), Some(error));
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
    }
}
