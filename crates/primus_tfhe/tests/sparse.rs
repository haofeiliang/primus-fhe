use primus_tfhe::sparse::{BucketMap, BucketMapError as Error};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn invalid_mapping_inputs_are_rejected_before_sampling() {
    for (dimension, copies, buckets, nonzero_indices, error) in [
        (16, 0, 8, &[1, 3][..], Error::InvalidBucketParameters),
        (16, 9, 8, &[1, 3][..], Error::InvalidBucketParameters),
        (16, 1, 1, &[1, 3][..], Error::InvalidBucketParameters),
        (16, 3, 8, &[3, 1][..], Error::InvalidNonzeroIndices),
        (16, 3, 8, &[1, 1][..], Error::InvalidNonzeroIndices),
        (16, 3, 8, &[1, 16][..], Error::InvalidNonzeroIndices),
        (usize::MAX, 3, 8, &[1, 3][..], Error::StorageSizeOverflow),
        (16, 3, usize::MAX, &[1, 3][..], Error::StorageSizeOverflow),
        (
            usize::MAX / 2,
            1,
            8,
            &[1, 3][..],
            Error::StorageSizeOverflow,
        ),
    ] {
        let mut rng = StdRng::seed_from_u64(42);
        let result = BucketMap::try_generate(dimension, copies, buckets, nonzero_indices, &mut rng);
        assert_eq!(result.err(), Some(error));
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(42).next_u64());
    }
}
