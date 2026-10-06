//! Shared coefficient ownership checks require no NTT or Fourier engine.

use primus_decompose::{
    DecompositionBaseLog, DecompositionLevelCount, primitive::ApproxSignedBasis,
};
use primus_glwe::{GgswParameters, GlweEncryptionParameters, SecretKeyDistr};
use primus_lattice::{GlweDimension, GlweSize};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::sparse::{BucketMap, BucketMapError};
use primus_tfhe_glwe::{SparseBootstrappingKeyError as Error, SparseGlweBootstrappingKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

fn map(bucket_count: usize) -> BucketMap {
    BucketMap::try_generate(4, 1, bucket_count, &[1], &mut StdRng::seed_from_u64(42))
        .unwrap()
        .0
}

#[test]
fn sparse_owner_rejects_invalid_storage_weight_and_rotation_domain() {
    let encryption = Arc::new(GlweEncryptionParameters::new(
        NativeModulus::<u64>::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    ));
    let basis = ApproxSignedBasis::new(
        None,
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(1)),
    );
    let parameters = GgswParameters::try_from_parts(
        GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
        Arc::clone(&encryption),
        basis.clone(),
    )
    .unwrap();
    // Nine GGSWs, each with two rows, one level and two length-32 components.
    let expected = 9 * 2 * 2 * 32;
    for actual in [0, expected - 1, expected + 1] {
        assert_eq!(
            SparseGlweBootstrappingKey::try_new(vec![0; actual], map(5), 1, &parameters).err(),
            Some(Error::StorageLengthMismatch { expected, actual })
        );
    }
    for weight in [0, 4] {
        assert_eq!(
            SparseGlweBootstrappingKey::try_new(Vec::new(), map(5), weight, &parameters).err(),
            Some(Error::InvalidHammingWeight)
        );
    }
    assert_eq!(
        SparseGlweBootstrappingKey::try_new(Vec::new(), map(1), 2, &parameters).err(),
        Some(Error::BucketMap(BucketMapError::InvalidBucketParameters))
    );

    // A single layout fits usize, but nine GGSWs exceed addressable u64 storage.
    // Only metadata is constructed; no large ciphertext or secret is allocated.
    let large = GgswParameters::try_from_parts(
        GlweSize::new(
            GlweDimension::new(1 << (usize::BITS / 2 - 5)),
            PolyLength::new(32),
        ),
        encryption,
        basis,
    )
    .unwrap();
    assert_eq!(
        SparseGlweBootstrappingKey::try_new(Vec::new(), map(5), 1, &large).err(),
        Some(Error::StorageSizeOverflow)
    );

    // Gadget parameters alone allow N=2^15 at u16; BR also needs 2N to fit.
    let narrow = GgswParameters::try_from_parts(
        GlweSize::new(GlweDimension::new(1), PolyLength::new(1 << 15)),
        Arc::new(GlweEncryptionParameters::new(
            NativeModulus::<u16>::new(),
            SecretKeyDistr::UniformBinary,
            0.7,
        )),
        ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(1)),
        ),
    )
    .unwrap();
    assert_eq!(
        SparseGlweBootstrappingKey::try_new(Vec::new(), map(5), 1, &narrow).err(),
        Some(Error::RotationDomainTooLarge)
    );
}
