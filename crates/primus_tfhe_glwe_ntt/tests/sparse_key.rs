use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweCiphertext, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::{context::NttGlweExternalProductContext, ggsw::NttGgsw, glwe::NttGlwe};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::PolynomialOwned;
use primus_tfhe::sparse::BucketMapError;
use primus_tfhe_glwe_ntt::{
    ClientKey, KeyGenerator, PbsOrder, SparseBootstrappingKeyError as Error, TfheContext,
    TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u32 = 132_120_577;

fn context(distribution: SecretKeyDistr) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(16, 8, modulus, distribution, 0.7);
    let glwe = GlweParameters::new(1, N, 8, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let basis = ApproxSignedBasis::new(Some(Q), 9, None);
    let parameters = TfheParameters::try_new(
        lwe,
        glwe,
        basis.clone(),
        basis,
        PbsOrder::KeyswitchBootstrap,
    )
    .unwrap();
    let ntt = U32NttTable::new(N.trailing_zeros(), modulus).unwrap();
    TfheContext::try_new(parameters, ntt).unwrap()
}

#[test]
fn encrypted_selections_cover_the_support_once_with_dummy_per_bucket() {
    let context = context(SecretKeyDistr::fixed_hamming_weight_binary(16, 4));
    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(0x5350_4152_5345);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let ntt = context.table();
    let glwe = context.parameters().accumulator_glwe();
    let output_key = NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), ntt);
    let mut message = PolynomialOwned::zero(N);
    message.as_mut()[0] = 1;
    message.as_mut()[N - 1] = 2;
    // A nontrivial encrypted mask exercises all GGSW rows through external product.
    let input = output_key
        .encrypt(&message, glwe, ntt, &mut rng)
        .into_coeff_form(ntt);
    let size = context.parameters().blind_rotation_ggsw().size();
    let mut external_product = NttGlweExternalProductContext::new(size);
    let mut control = NttGgsw::<Vec<u32>>::zero(size.ggsw_len());
    let mut product = GlweCiphertext::<Vec<u32>>::zero(size.glwe_len());
    let mut product_ntt = NttGlwe::<Vec<u32>>::zero(size.glwe_len());
    let mut decoded = PolynomialOwned::zero(N);

    // The second map must have at least one bucket with no public entries.
    for (copy_count, bucket_count) in [(3, 8), (1, 17)] {
        let key = generator
            .try_generate_sparse_bootstrapping_key(&client, copy_count, bucket_count, &mut rng)
            .unwrap();
        assert_eq!(key.input_dimension(), 16);
        assert_eq!(key.hamming_weight(), 4);
        assert_eq!(key.copy_count(), copy_count);
        assert_eq!(key.bucket_count(), bucket_count);
        assert_eq!(key.cipher_modulus(), Some(Q));
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
                ciphertext.write_ntt_form(&mut control, ntt);
                control.external_product_to(
                    &input,
                    &mut product,
                    key.basis(),
                    glwe.cipher_modulus(),
                    ntt,
                    &mut external_product,
                );
                product.write_ntt_form(&mut product_ntt, ntt);
                output_key.decrypt_to(&product_ntt, &mut decoded, glwe, ntt);
                let bit = decoded.as_ref()[0];
                assert!(bit <= 1);
                for (&actual, &expected) in decoded.as_ref().iter().zip(message.as_ref()) {
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
fn sparse_key_rejects_invalid_parameters_and_actual_secret_before_sampling() {
    let distribution = SecretKeyDistr::fixed_hamming_weight_binary(16, 4);
    let context = context(distribution);
    let mut generator = KeyGenerator::new(&context);
    let client = ClientKey::generate(context.parameters(), &mut StdRng::seed_from_u64(42));
    let mut check = |client: &ClientKey<u32>, copies, buckets, expected| {
        let mut rng = StdRng::seed_from_u64(43);
        let result =
            generator.try_generate_sparse_bootstrapping_key(client, copies, buckets, &mut rng);
        assert_eq!(result.err(), Some(expected));
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
    };
    for (copies, buckets) in [(0, 8), (9, 8), (3, 3)] {
        check(
            &client,
            copies,
            buckets,
            Error::BucketMap(BucketMapError::InvalidBucketParameters),
        );
    }
    for (copies, buckets) in [(usize::MAX, usize::MAX), (3, usize::MAX)] {
        check(&client, copies, buckets, Error::StorageSizeOverflow);
    }
    for data in [vec![0; 16], vec![1; 16], vec![2; 16]] {
        let malformed = ClientKey::new(
            LweSecretKey::new(data, distribution),
            client.glwe_secret_key().clone(),
            client.pbs_order(),
        );
        check(&malformed, 3, 8, Error::InvalidSecretCoefficients);
    }
    for (distribution, expected) in [
        (
            SecretKeyDistr::UniformBinary,
            Error::UnsupportedSecretDistribution,
        ),
        (
            SecretKeyDistr::SparseTernary,
            Error::UnsupportedSecretDistribution,
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(16, 0),
            Error::InvalidHammingWeight,
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(16, 16),
            Error::InvalidHammingWeight,
        ),
    ] {
        let context = self::context(distribution);
        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(44);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut rng = StdRng::seed_from_u64(45);
        let mut expected_rng = StdRng::seed_from_u64(45);
        let result = generator.try_generate_sparse_bootstrapping_key(&client, 3, 32, &mut rng);
        assert_eq!(result.err(), Some(expected));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
