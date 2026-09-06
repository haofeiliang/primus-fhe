use primus_lattice::{lwe::Lwe, ntru::Ntru, rlwe::Rlwe};
use primus_modulus::BarrettModulus;
use primus_reduce::{ReduceDotProduct, ReduceSub};

#[test]
fn indexed_extraction_preserves_ntru_and_rlwe_phases() {
    const Q: u32 = 97;
    let modulus = BarrettModulus::new(Q);
    let ntru = Ntru::new(vec![13u32, 21, 34, 55, 8, 19, 27, 41]);
    let n = ntru.as_ref().len();
    let body: Vec<u32> = (0..n).map(|i| (i * 3 + 7) as u32).collect();
    let rlwe = Rlwe::new([ntru.as_ref(), &body].concat());
    // Active lengths exercise both sides of the indexed extraction split.
    for active in [1, 3, 5, n] {
        let secret: Vec<u32> = (0..n)
            .map(|i| if i < active { (i % 3 + 1) as u32 } else { 0 })
            .collect();
        let mut phase = vec![0i64; n];
        for (i, &a) in ntru.as_ref().iter().enumerate() {
            for (j, &b) in secret.iter().enumerate() {
                phase[(i + j) % n] += if i + j < n {
                    i64::from(a * b)
                } else {
                    -i64::from(a * b)
                };
            }
        }
        let phase: Vec<u32> = phase
            .into_iter()
            .map(|v| v.rem_euclid(i64::from(Q)) as u32)
            .collect();
        let mut full: Lwe<Vec<u32>> = Lwe::zero(n);
        let mut compact: Lwe<Vec<u32>> = Lwe::zero(active);
        for index in 0..n {
            ntru.extract_lwe_at_to(index, &mut full, modulus);
            ntru.extract_compact_lwe_at_to(index, &mut compact, modulus);
            assert_eq!(
                modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
                phase[index]
            );
            assert_eq!(
                modulus.reduce_sub(
                    compact.b(),
                    modulus.reduce_dot_product(compact.a(), &secret[..active])
                ),
                phase[index]
            );
            if index == 0 {
                ntru.extract_lwe_to(&mut full, modulus);
                ntru.extract_compact_lwe_to(&mut compact, modulus);
                assert_eq!(compact.a(), &full.a()[..active]);
            }
            rlwe.extract_lwe_at_to(index, &mut full, modulus);
            assert_eq!(rlwe.extract_lwe_at(index, modulus), full);
            rlwe.extract_compact_lwe_at_to(index, &mut compact, modulus);
            let expected = (body[index] + Q - phase[index]) % Q;
            assert_eq!(
                modulus.reduce_sub(full.b(), modulus.reduce_dot_product(full.a(), &secret)),
                expected
            );
            assert_eq!(
                modulus.reduce_sub(
                    compact.b(),
                    modulus.reduce_dot_product(compact.a(), &secret[..active])
                ),
                expected
            );
            if index == 0 {
                rlwe.extract_lwe_to(&mut full, modulus);
                rlwe.extract_compact_lwe_to(&mut compact, modulus);
                assert_eq!(compact.a(), &full.a()[..active]);
                assert_eq!(compact.b(), full.b());
            }
        }
    }
}
