use primus_lattice::rlwe::{NttRlwe, Rlwe};

#[test]
fn rlwe_views_borrow_disjoint_polynomial_halves() {
    macro_rules! check {
        ($cipher:ident) => {{
            let mut storage = [1u32, 2, 3, 4, 5, 6, 7, 8];
            let mut sample = $cipher::new(storage.as_mut_slice());
            assert_eq!(sample.a_b_slices(), (&[1, 2, 3, 4][..], &[5, 6, 7, 8][..]));
            let (a, b) = sample.a_b();
            assert_eq!(a.as_ref(), &[1, 2, 3, 4]);
            assert_eq!(b.as_ref(), &[5, 6, 7, 8]);
            let (a, b) = sample.a_b_mut_slices();
            a[3] = 9;
            b[0] = 10;
            let (mut a, mut b) = sample.a_b_mut();
            a.as_mut()[0] = 11;
            b.as_mut()[3] = 12;
            assert_eq!(storage, [11, 2, 3, 9, 10, 6, 7, 12]);
        }};
    }
    check!(Rlwe);
    check!(NttRlwe);
    #[cfg(feature = "rns")]
    {
        use primus_lattice::rlwe::{CrtRlwe, DcrtRlwe};
        check!(CrtRlwe);
        check!(DcrtRlwe);
    }
}
