//! Native and Barrett add/sub slices agree with wide modular arithmetic.
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::{ReduceAddSlice, ReduceSubSlice};

#[test]
fn add_sub_slices_cover_unaligned_ranges_and_vector_tails() {
    macro_rules! check {
        ($t:ty, $modulus:expr, $q:expr) => {{
            let modulus = $modulus;
            let q: u128 = $q;
            for len in [0, 1, 7, 8, 15, 16, 17, 31, 1024, 1025] {
                let lhs: Vec<_> = (0..len + 3)
                    .map(|i| {
                        if i % 2 == 0 {
                            (q - 1 - i as u128 % q) as $t
                        } else {
                            (i as u128 % q) as $t
                        }
                    })
                    .collect();
                let rhs: Vec<_> = (0..len + 3)
                    .map(|i| ((i * 31 + 1) as u128 % q) as $t)
                    .collect();
                let (lhs, rhs) = (&lhs[1..len + 1], &rhs[3..]);
                let add: Vec<_> = lhs
                    .iter()
                    .zip(rhs)
                    .map(|(&a, &b)| ((a as u128 + b as u128) % q) as $t)
                    .collect();
                let sub: Vec<_> = lhs
                    .iter()
                    .zip(rhs)
                    .map(|(&a, &b)| ((a as u128 + q - b as u128) % q) as $t)
                    .collect();
                let mut storage = vec![7; len + 2];
                let output = &mut storage[1..len + 1];
                modulus.reduce_add_slice_to(lhs, rhs, output);
                assert_eq!(output, add);
                output.copy_from_slice(lhs);
                modulus.reduce_add_slice_assign(output, rhs);
                assert_eq!(output, add);
                modulus.reduce_sub_slice_to(lhs, rhs, output);
                assert_eq!(output, sub);
                output.copy_from_slice(lhs);
                modulus.reduce_sub_slice_assign(output, rhs);
                assert_eq!(output, sub);
                output.copy_from_slice(rhs);
                modulus.reduce_sub_slice_rev_assign(lhs, output);
                assert_eq!(output, sub);
                assert_eq!((storage[0], storage[len + 1]), (7, 7));
            }
        }};
    }
    check!(u32, NativeModulus::<u32>::new(), 1u128 << 32);
    check!(u64, NativeModulus::<u64>::new(), 1u128 << 64);
    for q in [2u32, 257, (1 << 30) - 1] {
        check!(u32, BarrettModulus::new(q), q as u128);
    }
    for q in [2u64, 257, (1 << 62) - 1] {
        check!(u64, BarrettModulus::new(q), q as u128);
    }
}
