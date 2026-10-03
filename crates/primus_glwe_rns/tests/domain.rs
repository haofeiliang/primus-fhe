//! Bindings reject numerical mismatches even when ciphertext storage has the same shape.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweKeySwitchEvaluator,
    DcrtGlweKeySwitchingKey, DcrtGlwePublicKey, DcrtGlweSecretKey, GlweSecretKey,
    HybridRnsGlweKeySwitchEvaluator, HybridRnsGlweKeySwitchingKey, HybridRnsKeySwitchDomain,
    RnsDomainError, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::PolyLength;
use primus_rns::{HybridRNS, HybridRNSPartitioning};
use rand::{SeedableRng, rngs::StdRng};

// Small NTT primes keep construction tests cheap; no security or post-switch noise claim.
fn parameters(
    dimension: usize,
    n: usize,
    moduli: &[BarrettModulus<u32>],
) -> CrtGlweParameters<u32, BarrettModulus<u32>> {
    CrtGlweParameters::new(
        GlweDimension::new(dimension),
        n,
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        moduli,
        SecretKeyDistr::UniformBinary,
        1.0,
    )
}

#[test]
fn encryption_bindings_check_layout_and_ordered_moduli() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4249_4e44);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let public_key =
        DcrtGlwePublicKey::new(&key, params.inner(), params.base_q(), &table, &mut rng);
    assert!(key.try_bind(&params, &table).is_ok());
    assert!(public_key.try_bind(&params, &table).is_ok());

    // A valid table with a different N fails before the key's geometry is considered.
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &q).unwrap();
    assert!(matches!(
        key.try_bind(&params, &longer_table),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));
    let larger_dimension = parameters(2, n.get(), &q);
    assert!(matches!(
        key.try_bind(&larger_dimension, &table),
        Err(RnsDomainError::DimensionMismatch { .. })
    ));
    assert!(matches!(
        public_key.try_bind(&larger_dimension, &table),
        Err(RnsDomainError::DimensionMismatch { .. })
    ));

    // Each alternative parameter/table pair is itself valid and has the same shape.
    for values in [[769, 257], [257, 1153]] {
        let other_q = values.map(BarrettModulus::new);
        let other_params = parameters(1, n.get(), &other_q);
        let other_table = UintDcrtTable::new(n, &other_q).unwrap();
        // Independently supplied public-key sampling/base parts must be rejected
        // before sampling, even when the foreign base and table agree with each other.
        let mut rejected_rng = StdRng::seed_from_u64(19);
        let mut expected_rng = StdRng::seed_from_u64(19);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                DcrtGlwePublicKey::new(
                    &key,
                    params.inner(),
                    other_params.base_q(),
                    &other_table,
                    &mut rejected_rng,
                )
            }))
            .is_err()
        );
        assert_eq!(
            rand::Rng::next_u64(&mut rejected_rng),
            rand::Rng::next_u64(&mut expected_rng)
        );
        assert!(matches!(
            key.try_bind(&other_params, &other_table),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind(&other_params, &other_table),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        let gadget =
            CrtGlevParameters::with_glwe_params(&other_params, DecompositionBaseLog::new(4), None);
        let domain = DcrtGadgetDomain::try_new(&gadget, &other_table).unwrap();
        assert!(matches!(
            key.try_bind_gadget(&domain),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
        assert!(matches!(
            public_key.try_bind_gadget(&domain),
            Err(RnsDomainError::ModulusOrderMismatch { .. })
        ));
    }
}

#[test]
fn classic_switch_binding_checks_radix_and_retained_levels() {
    let n = PolyLength::new(32);
    let q = [257u32, 769].map(BarrettModulus::new);
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &q).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4741_4447);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let dcrt_secret = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let gadget = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let key =
        DcrtGlweKeySwitchingKey::generate(&secret, params.inner(), &dcrt_secret, &domain, &mut rng);
    assert!(DcrtGlweKeySwitchEvaluator::try_new(&key, &domain).is_ok());

    let other_radix = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(5),
        Some(DecompositionLevelCount::new(1)),
    );
    let other_domain = DcrtGadgetDomain::try_new(&other_radix, &table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::DecompositionBaseLogMismatch { .. })
    ));
    let other_levels = CrtGlevParameters::with_glwe_params(
        &params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(2)),
    );
    let other_domain = DcrtGadgetDomain::try_new(&other_levels, &table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::DecompositionLevelCountMismatch { .. })
    ));

    let reversed_q = [q[1], q[0]];
    let reversed_params = parameters(1, n.get(), &reversed_q);
    let reversed_table = UintDcrtTable::new(n, &reversed_q).unwrap();
    let reversed_gadget = CrtGlevParameters::with_glwe_params(
        &reversed_params,
        DecompositionBaseLog::new(4),
        Some(DecompositionLevelCount::new(1)),
    );
    let reversed_domain = DcrtGadgetDomain::try_new(&reversed_gadget, &reversed_table).unwrap();
    assert!(matches!(
        DcrtGlweKeySwitchEvaluator::try_new(&key, &reversed_domain),
        Err(RnsDomainError::ModulusOrderMismatch { .. })
    ));
}

#[test]
fn hybrid_binding_checks_qp_order_split_and_partition_width() {
    let n = PolyLength::new(32);
    let q = [257u32, 769, 1153, 3329].map(BarrettModulus::new);
    let p = [7681u32].map(BarrettModulus::new);
    let qp = [q[0], q[1], q[2], q[3], p[0]];
    let params = parameters(1, n.get(), &q);
    let table = UintDcrtTable::new(n, &qp).unwrap();
    let hybrid = HybridRNS::new(&q, &p, 2).unwrap();
    let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4859_4249);
    let secret = GlweSecretKey::generate(params.glwe_size(), params.secret_key_sampler(), &mut rng);
    let key =
        HybridRnsGlweKeySwitchingKey::generate(&secret, params.inner(), &secret, &domain, &mut rng);
    assert!(HybridRnsGlweKeySwitchEvaluator::try_new(&key, &domain).is_ok());

    // Both have two active partitions, but their actual Q ranges are 2+2 and 3+1.
    let other_partitioning = HybridRNSPartitioning::new(5, 2).unwrap();
    let other = HybridRNS::from_partitioning(&q, &p, other_partitioning).unwrap();
    assert_eq!(other.partition_count(), hybrid.partition_count());
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::PartitionWidthMismatch { .. })
    ));

    // The same flattened QP order with a different Q/P boundary is also incompatible.
    let other = HybridRNS::new(&q[..3], &[q[3], p[0]], 2).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::ModuliCountMismatch { .. })
    ));
    let other_p = [BarrettModulus::new(12289u32)];
    let other_qp = [q[0], q[1], q[2], q[3], other_p[0]];
    let other_table = UintDcrtTable::new(n, &other_qp).unwrap();
    let other = HybridRNS::new(&q, &other_p, 2).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&other, &other_table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::ModulusOrderMismatch { index: 4, .. })
    ));
    let longer_table = UintDcrtTable::new(PolyLength::new(64), &qp).unwrap();
    let other_domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &longer_table).unwrap();
    assert!(matches!(
        HybridRnsGlweKeySwitchEvaluator::try_new(&key, &other_domain),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));

    // Generation rejects an ordered-Q mismatch before consuming any coins.
    let reordered_q = [q[1], q[0], q[2], q[3]];
    let reordered_params = parameters(1, n.get(), &reordered_q);
    let mut generation_rng = StdRng::seed_from_u64(17);
    let mut expected_rng = StdRng::seed_from_u64(17);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            HybridRnsGlweKeySwitchingKey::generate(
                &secret,
                reordered_params.inner(),
                &secret,
                &domain,
                &mut generation_rng,
            )
        }))
        .is_err()
    );
    assert_eq!(
        rand::Rng::next_u64(&mut generation_rng),
        rand::Rng::next_u64(&mut expected_rng)
    );
}
