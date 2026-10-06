//! The shared owner rejects incomplete storage before any bucket view is exposed.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe::sparse::{BucketMap, BucketMapError};
use primus_tfhe_ntru::{SparseBootstrappingKeyError as Error, SparseNtruBootstrappingKey};
use rand::{SeedableRng, rngs::StdRng};

fn map(bucket_count: usize) -> BucketMap {
    BucketMap::try_generate(4, 1, bucket_count, &[1], &mut StdRng::seed_from_u64(42))
        .unwrap()
        .0
}

#[test]
fn sparse_owner_rejects_incomplete_controls_and_incompatible_weight() {
    let ntru = NtruParameters::new(
        PolyLength::new(32),
        4,
        NativeModulus::<u64>::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let parameters = NlevParameters::with_ntru_params(
        &ntru,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(2)),
    );
    // Four public selections plus five dummies, with complete N*L controls.
    // Five buckets also force an empty public bucket, whose dummy cannot be omitted.
    let expected = 9 * 32 * 2;
    for actual in [0, expected - 1, expected + 1] {
        assert_eq!(
            SparseNtruBootstrappingKey::try_new(vec![0; actual], map(5), 1, &parameters).err(),
            Some(Error::StorageLengthMismatch { expected, actual })
        );
    }
    for weight in [0, 4] {
        assert_eq!(
            SparseNtruBootstrappingKey::try_new(Vec::new(), map(5), weight, &parameters).err(),
            Some(Error::InvalidHammingWeight)
        );
    }
    assert_eq!(
        SparseNtruBootstrappingKey::try_new(Vec::new(), map(1), 2, &parameters).err(),
        Some(Error::BucketMap(BucketMapError::InvalidBucketParameters))
    );
}
