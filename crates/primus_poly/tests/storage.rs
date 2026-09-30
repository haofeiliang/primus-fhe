//! Storage capabilities are independent: collecting does not require consuming
//! iteration, and returning a buffer does not require owned constructors.

use std::sync::Arc;

use primus_modulus::NativeModulus;
use primus_poly::{ArrayBase, Polynomial};
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn construction_and_iteration_require_only_the_used_storage_capabilities() {
    // Arc supports collecting but has no consuming element iterator or DataOwned.
    let shared: ArrayBase<Arc<[u32]>> = [1, 2, 3].into_iter().collect();
    assert_eq!(shared.as_view().as_ref(), &[1, 2, 3]);
    let shared = shared.into_inner();
    let borrowed = Polynomial::new(&shared).into_inner();
    assert!(core::ptr::eq(borrowed, &shared));

    // Conversely, an array is consumable without supporting DataOwned.
    let values: Vec<_> = ArrayBase::new([1u32, 2, 3]).into_iter().collect();
    assert_eq!(values.as_slice(), shared.as_ref());

    // Sampling collects directly into either backend with the same seeded stream.
    let mut rng = StdRng::seed_from_u64(42);
    let mut same_rng = StdRng::seed_from_u64(42);
    let shared = Polynomial::<Arc<[u32]>>::random(8, NativeModulus::new(), &mut rng);
    let owned = Polynomial::<Vec<u32>>::random(8, NativeModulus::new(), &mut same_rng);
    assert_eq!(shared.as_ref(), owned.as_ref());
}
