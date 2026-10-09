//! Minimal-root selection, including orders smaller than the supported NTT rings.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, PrimitiveRoot};
use primus_reduce::FieldContext;

#[test]
fn minimal_primitive_roots_match_integer_oracle() {
    fn check<T: FheUint>()
    where
        BarrettModulus<T>: FieldContext<T>,
    {
        let modulus = BarrettModulus::new(T::as_from(257u64));
        for log_degree in 1..=8 {
            // Search canonical integers directly: w^(D/2) = -1 proves order D
            // when D is a power of two. This oracle does not use Shoup arithmetic.
            let half_degree = 1u32 << (log_degree - 1);
            let expected = (2..257u64)
                .find(|&candidate| {
                    (0..half_degree).fold(1, |power, _| power * candidate % 257) == 256
                })
                .unwrap();
            let actual = T::try_minimal_primitive_root(log_degree, modulus).unwrap();
            assert_eq!(actual, T::as_from(expected), "log_degree={log_degree}");
        }
        // Order 512 cannot divide 257-1; rejection happens before random search.
        assert!(matches!(T::try_minimal_primitive_root(9, modulus),
            Err(NttError::NoPrimitiveRoot { degree, modulus })
                if degree == T::as_from(512u64) && modulus == T::as_from(257u64)
        ));
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
}
