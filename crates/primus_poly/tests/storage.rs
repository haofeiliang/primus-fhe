//! Storage capabilities are independent: collecting does not require consuming
//! iteration, and returning a buffer does not require owned constructors.

use std::sync::Arc;

use primus_distr::DiscreteGaussian;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn sampling_and_views_require_only_the_used_storage_capabilities() {
    // Arc supports collecting but has no consuming element iterator or DataOwned.
    // Sampling collects directly into either backend with the same seeded stream.
    let mut rng = StdRng::seed_from_u64(42);
    let mut same_rng = StdRng::seed_from_u64(42);
    let shared = Polynomial::<Arc<[u32]>>::random(8, NativeModulus::new(), &mut rng);
    let owned = Polynomial::<Vec<u32>>::random(8, NativeModulus::new(), &mut same_rng);
    assert_eq!(shared.as_view().as_ref(), owned.as_ref());

    // Returning owned or borrowed storage does not require DataOwned either.
    let storage = shared.into_inner();
    let borrowed = Polynomial::new(&storage).into_inner();
    assert!(core::ptr::eq(borrowed, &storage));
}

#[test]
fn gaussian_fill_matches_collection_without_touching_neighboring_storage() {
    // Exercise both CDT and Ziggurat while preserving FromIterator-only storage.
    for sigma in [3.2, 30.0] {
        let gaussian = DiscreteGaussian::<u32>::new(sigma, 1_008).unwrap();
        for length in [0, 17] {
            let mut expected_rng = StdRng::seed_from_u64(42);
            let expected =
                Polynomial::<Arc<[u32]>>::random_gaussian(length, &gaussian, &mut expected_rng);

            // Overwrite an offset slice of dirty storage, including an empty view.
            let mut storage = vec![u32::MAX; length + 2];
            let mut rng = StdRng::seed_from_u64(42);
            Polynomial::new(&mut storage[1..length + 1])
                .random_gaussian_assign(&gaussian, &mut rng);
            assert_eq!(&storage[1..length + 1], expected.as_ref());
            assert_eq!((storage[0], storage[length + 1]), (u32::MAX, u32::MAX));
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
}
