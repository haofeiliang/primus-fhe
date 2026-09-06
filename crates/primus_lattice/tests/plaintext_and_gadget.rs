use primus_lattice::{GadgetSize, GlweSize};
use primus_lattice::{
    ggsw::{Ggsw, NttGgsw},
    glwe::{Glwe, NttGlwe},
    lwe::Lwe,
    rgsw::{NttRgsw, Rgsw},
    rlwe::{NttRlwe, Rlwe},
};
use primus_modulus::BarrettModulus;
use primus_poly::{NttPolynomial, Polynomial};

#[test]
fn encoded_plaintext_operations_preserve_masks_and_trivial_overwrites_them() {
    const N: usize = 32;
    const Q: u32 = 193;
    let modulus = BarrettModulus::new(Q);
    let plaintext: Vec<u32> = (0..N).map(|i| (i * 11 % Q as usize) as u32).collect();
    macro_rules! check {
        ($cipher:ident, $poly:ident, $components:expr) => {{
            let data: Vec<u32> = (0..N * $components)
                .map(|i| (i * 7 % Q as usize) as u32)
                .collect();
            let mut cipher = $cipher::new(data.clone());
            let plaintext = $poly::new(plaintext.as_slice());
            let mask_len = data.len() - N;
            cipher.add_plaintext_assign(&plaintext, modulus);
            assert_eq!(&cipher.as_ref()[..mask_len], &data[..mask_len]);
            assert_eq!(
                &cipher.as_ref()[mask_len..],
                data[mask_len..]
                    .iter()
                    .zip(plaintext.as_ref())
                    .map(|(&a, &b)| (a + b) % Q)
                    .collect::<Vec<_>>()
            );
            cipher.sub_plaintext_assign(&plaintext, modulus);
            assert_eq!(cipher.as_ref(), data);
            cipher.set_trivial(&plaintext);
            assert!(cipher.as_ref()[..mask_len].iter().all(|&x| x == 0));
            assert_eq!(&cipher.as_ref()[mask_len..], plaintext.as_ref());
        }};
    }
    check!(Glwe, Polynomial, 3);
    check!(Rlwe, Polynomial, 2);
    check!(NttGlwe, NttPolynomial, 3);
    check!(NttRlwe, NttPolynomial, 2);
    let mut lwe = Lwe::new(vec![11u32, 13, 190]);
    lwe.add_plaintext_assign(7, modulus);
    assert_eq!(lwe.as_ref(), &[11, 13, 4]);
    lwe.sub_plaintext_assign(7, modulus);
    assert_eq!(lwe.as_ref(), &[11, 13, 190]);
    lwe.set_trivial(7);
    assert_eq!(lwe.as_ref(), &[0, 0, 7]);
}

// Independent row/level/component oracle checks that only the requested
// diagonal level changes, including modulus-block order for RNS storage.
fn diagonal_oracle(
    data: &[u32],
    plaintext: &[u32],
    rows: usize,
    levels: usize,
    selected: usize,
    n: usize,
    qs: &[u32],
) -> Vec<u32> {
    let mut result = data.to_vec();
    let p = plaintext.len();
    for row in 0..rows {
        for level in 0..levels {
            for component in 0..rows {
                if row == component && level == selected {
                    for (i, &value) in plaintext.iter().enumerate() {
                        let offset = ((row * levels + level) * rows + component) * p + i;
                        result[offset] = (result[offset] + value) % qs[i / n];
                    }
                }
            }
        }
    }
    result
}

#[test]
fn gadget_injection_changes_only_the_selected_diagonal_level() {
    const N: usize = 32;
    const LEVELS: usize = 3;
    let modulus = BarrettModulus::new(193u32);
    let plaintext: Vec<_> = (0..N).map(|i| (i * 13 % 193) as u32).collect();
    macro_rules! check {
        ($cipher:ident, $poly:ident, $rows:expr) => {{
            let data: Vec<_> = (0..$rows * LEVELS * $rows * N)
                .map(|i| (i * 7 % 193) as u32)
                .collect();
            for selected in 0..LEVELS {
                let mut cipher = $cipher::new(data.clone());
                cipher.add_gadget_diagonal_assign(
                    &$poly::new(plaintext.as_slice()),
                    selected,
                    GadgetSize::new(GlweSize::new($rows - 1, N), LEVELS),
                    modulus,
                );
                assert_eq!(
                    cipher.as_ref(),
                    diagonal_oracle(&data, &plaintext, $rows, LEVELS, selected, N, &[193])
                );
            }
        }};
    }
    check!(Ggsw, Polynomial, 3);
    check!(NttGgsw, NttPolynomial, 3);
    check!(Rgsw, Polynomial, 2);
    check!(NttRgsw, NttPolynomial, 2);
}

#[cfg(feature = "rns")]
#[test]
fn rns_plaintext_and_gadget_operations_preserve_the_basis_layout() {
    use primus_lattice::{
        ggsw::{CrtGgsw, DcrtGgsw},
        glwe::{CrtGlwe, DcrtGlwe},
        rgsw::{CrtRgsw, DcrtRgsw},
        rlwe::{CrtRlwe, DcrtRlwe},
    };
    use primus_poly::{CrtPolynomial, DcrtPolynomial};
    const N: usize = 32;
    const LEVELS: usize = 3;
    let qs = [193u32, 257];
    let moduli = qs.map(BarrettModulus::new);
    let p = N * qs.len();
    let plaintext: Vec<u32> = (0..p).map(|i| (i * 13) as u32 % qs[i / N]).collect();
    macro_rules! body {
        ($cipher:ident, $poly:ident, $rows:expr) => {{
            let data: Vec<_> = (0..p * $rows)
                .map(|i| (i * 7) as u32 % qs[i / N % qs.len()])
                .collect();
            let mut cipher = $cipher::new(data.clone());
            let poly = $poly::new(plaintext.as_slice());
            cipher.add_plaintext_assign(&poly, N, &moduli);
            let split = data.len() - p;
            assert_eq!(&cipher.as_ref()[..split], &data[..split]);
            for (i, &value) in plaintext.iter().enumerate() {
                assert_eq!(
                    cipher.as_ref()[split + i],
                    (data[split + i] + value) % qs[i / N]
                );
            }
            cipher.sub_plaintext_assign(&poly, N, &moduli);
            assert_eq!(cipher.as_ref(), data);
            cipher.set_trivial(&poly);
            assert!(cipher.as_ref()[..split].iter().all(|&x| x == 0));
            assert_eq!(&cipher.as_ref()[split..], plaintext);
        }};
    }
    body!(CrtGlwe, CrtPolynomial, 3);
    body!(DcrtGlwe, DcrtPolynomial, 3);
    body!(CrtRlwe, CrtPolynomial, 2);
    body!(DcrtRlwe, DcrtPolynomial, 2);
    macro_rules! gadget {
        ($cipher:ident, $poly:ident, $rows:expr) => {{
            let data: Vec<_> = (0..$rows * LEVELS * $rows * p)
                .map(|i| (i * 7) as u32 % qs[i / N % qs.len()])
                .collect();
            for selected in 0..LEVELS {
                let mut cipher = $cipher::new(data.clone());
                cipher.add_gadget_diagonal_assign(
                    &$poly::new(plaintext.as_slice()),
                    selected,
                    primus_lattice::RnsGadgetSize::new(
                        primus_lattice::RnsGlweSize::new(GlweSize::new($rows - 1, N), qs.len()),
                        LEVELS,
                    ),
                    &moduli,
                );
                assert_eq!(
                    cipher.as_ref(),
                    diagonal_oracle(&data, &plaintext, $rows, LEVELS, selected, N, &qs)
                );
            }
        }};
    }
    gadget!(CrtGgsw, CrtPolynomial, 3);
    gadget!(DcrtGgsw, DcrtPolynomial, 3);
    gadget!(CrtRgsw, CrtPolynomial, 2);
    gadget!(DcrtRgsw, DcrtPolynomial, 2);
}

#[test]
fn fourier_body_and_gadget_operations_preserve_complex_entries() {
    use primus_fft::Complex64;
    use primus_lattice::{ggsw::FourierGgsw, glwe::FourierGlwe};
    use primus_poly::FourierPolynomial;
    const N: usize = 16;
    let plaintext: Vec<_> = (0..N)
        .map(|i| Complex64::new(i as f64, -(i as f64)))
        .collect();
    let poly = FourierPolynomial::new(plaintext.as_slice());
    let data: Vec<_> = (0..3 * N)
        .map(|i| Complex64::new((i * 3) as f64, 7.0))
        .collect();
    let mut glwe = FourierGlwe::new(data.clone());
    glwe.add_plaintext_assign(&poly);
    assert_eq!(&glwe.as_ref()[..2 * N], &data[..2 * N]);
    for (i, &p) in plaintext.iter().enumerate() {
        assert_eq!(glwe.as_ref()[2 * N + i], data[2 * N + i] + p);
    }
    glwe.sub_plaintext_assign(&poly);
    assert_eq!(glwe.as_ref(), data);
    glwe.set_trivial(&poly);
    assert!(
        glwe.as_ref()[..2 * N]
            .iter()
            .all(|&x| x == Complex64::default())
    );
    assert_eq!(&glwe.as_ref()[2 * N..], plaintext);
    let data: Vec<_> = (0..3 * 2 * 3 * N)
        .map(|i| Complex64::new((i * 3) as f64, 7.0))
        .collect();
    let mut ggsw = FourierGgsw::new(data.clone());
    ggsw.add_gadget_diagonal_assign(&poly, 1, GadgetSize::new(GlweSize::new(2, 2 * N), 2));
    for (i, &value) in data.iter().enumerate() {
        let row = i / (2 * 3 * N);
        let level = i / (3 * N) % 2;
        let component = i / N % 3;
        let expected = if level == 1 && component == row {
            value + plaintext[i % N]
        } else {
            value
        };
        assert_eq!(ggsw.as_ref()[i], expected);
    }
}
