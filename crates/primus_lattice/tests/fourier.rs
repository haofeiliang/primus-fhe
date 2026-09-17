//! Complex arithmetic and torus/integer scaling across both FFT backends.

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::glwe::Glwe;

#[test]
fn fourier_arithmetic_covers_all_components_and_matches_in_place() {
    use primus_lattice::{
        ggsw::FourierGgsw, glev::FourierGlev, glwe::FourierGlwe, ngsw::FourierNgsw,
        nlev::FourierNlev, ntru::FourierNtru,
    };

    let lhs = [
        Complex64::new(1.0, 2.0),
        Complex64::new(-3.0, 4.0),
        Complex64::new(5.0, -6.0),
        Complex64::new(-7.0, -8.0),
    ];
    let rhs = [Complex64::new(2.0, -1.0); 4];
    macro_rules! check {
        ($cipher:ident) => {{
            let input = $cipher::new(lhs.as_slice());
            let rhs = $cipher::new(rhs.as_slice());
            let mut storage = [Complex64::new(42.0, 42.0); 4];
            let mut output = $cipher::new(storage.as_mut_slice());
            input.add_to(&rhs, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x + Complex64::new(2.0, -1.0)));
            output.sub_assign(&rhs);
            assert_eq!(output.as_ref(), &lhs);
            input.sub_to(&rhs, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x - Complex64::new(2.0, -1.0)));
            output.add_assign(&rhs);
            assert_eq!(output.as_ref(), &lhs);
            input.neg_to(&mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| -x));
            output.neg_assign();
            assert_eq!(output.as_ref(), &lhs);
            input.mul_scalar_to(-2.0, &mut output);
            assert_eq!(output.as_ref(), &lhs.map(|x| x * -2.0));
            output.mul_scalar_assign(-0.5);
            assert_eq!(output.as_ref(), &lhs);
        }};
    }
    check!(FourierGlwe);
    check!(FourierNtru);
    check!(FourierGlev);
    check!(FourierGgsw);
    check!(FourierNlev);
    check!(FourierNgsw);
}

// Verify the integer-multiplier/torus-ciphertext scaling contract against
// independent negacyclic convolution, with both FFT evaluation orders.
fn polynomial_products<Table: FftTable>() {
    use primus_lattice::{
        ggsw::{FourierGgsw, Ggsw},
        glev::{FourierGlev, Glev},
        glwe::FourierGlwe,
        ngsw::{FourierNgsw, Ngsw},
        nlev::{FourierNlev, Nlev},
        ntru::{FourierNtru, Ntru},
    };
    use primus_poly::FourierPolynomial;
    let table = Table::new(5).unwrap();
    let mut fft = FftEngine::new(&table);
    let n = fft.poly_length();
    let multiplier: Vec<u32> = (0..n).map(|i| (i % 5) as u32).collect();
    let mut transformed = vec![Default::default(); fft.fourier_length()];
    fft.forward_as_integer(&multiplier, &mut transformed);
    let poly = FourierPolynomial(transformed);
    macro_rules! check {
        ($coeff:ident, $fourier:ident, $components:expr) => {{
            let input: Vec<u32> = (0..n * $components).map(|i| (i * 7 % 53) as u32).collect();
            let mut expected = vec![0u32; input.len()];
            for (input, output) in input.chunks_exact(n).zip(expected.chunks_exact_mut(n)) {
                for (i, &a) in input.iter().enumerate() {
                    for (j, &b) in multiplier.iter().enumerate() {
                        let k = (i + j) % n;
                        output[k] = if i + j < n {
                            output[k].wrapping_add(a * b)
                        } else {
                            output[k].wrapping_sub(a * b)
                        };
                    }
                }
            }
            let coeff = $coeff::new(input.clone());
            let mut fourier: $fourier<Vec<primus_fft::Complex64>> =
                $fourier::zero($components * fft.fourier_length());
            coeff.write_fourier_form(&mut fourier, &mut fft);
            let mut output = fourier.clone();
            fourier.mul_fourier_polynomial_to(&poly, &mut output);
            let mut recovered = $coeff::new(vec![0; input.len()]);
            output.write_torus_form(&mut recovered, &mut fft);
            assert_eq!(recovered.as_ref(), expected);
            output = fourier.clone();
            output.mul_fourier_polynomial_assign(&poly);
            output.write_torus_form(&mut recovered, &mut fft);
            assert_eq!(recovered.as_ref(), expected);
            output = fourier.clone();
            output.add_mul_fourier_polynomial_assign(&fourier, &poly);
            output.write_torus_form(&mut recovered, &mut fft);
            for (x, &a) in expected.iter_mut().zip(&input) {
                *x = x.wrapping_add(a);
            }
            assert_eq!(recovered.as_ref(), expected);
        }};
    }
    check!(Glwe, FourierGlwe, 3);
    check!(Glev, FourierGlev, 6);
    check!(Ggsw, FourierGgsw, 18);
    check!(Ntru, FourierNtru, 1);
    check!(Nlev, FourierNlev, 2);
    check!(Ngsw, FourierNgsw, 2);
}

#[test]
fn fourier_polynomial_products_preserve_torus_scale() {
    polynomial_products::<RustFftTable>();
    polynomial_products::<TfheFftTable>();
}

fn sub_mul_monomial<Table: FftTable>() {
    use primus_lattice::{
        GadgetSize, GlweSize,
        ggsw::{FourierGgsw, Ggsw},
    };
    let table = Table::new(4).unwrap();
    let mut fft = FftEngine::new(&table);
    let n = fft.poly_length();
    let size = GadgetSize::new(GlweSize::new(2, n), 2);
    let lhs = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
            .collect::<Vec<_>>(),
    );
    let rhs = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| (i as u32).wrapping_mul(0xa24b_aed5).wrapping_add(1))
            .collect::<Vec<_>>(),
    );
    let mut lhs_fourier = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
    let mut rhs_fourier = lhs_fourier.clone();
    lhs.write_fourier_form(&mut lhs_fourier, &mut fft);
    rhs.write_fourier_form(&mut rhs_fourier, &mut fft);
    let mut output = lhs_fourier.clone();
    let mut recovered = lhs.clone();
    let mut coefficient_scratch = vec![0u32; n];
    let mut fourier_scratch = vec![Complex64::default(); fft.fourier_length()];
    // Independent signed-index oracle across every row/level/component. Zero
    // comes last to check that it subtracts rhs after dirty scratch is reused.
    for exponent in (1..2 * n).chain([0]) {
        lhs_fourier.sub_mul_monomial_to(
            &rhs_fourier,
            exponent,
            &mut output,
            &mut fft,
            &mut coefficient_scratch,
            &mut fourier_scratch,
        );
        output.write_torus_form(&mut recovered, &mut fft);
        let mut expected = lhs.as_ref().to_vec();
        for (i, &value) in rhs.as_ref().iter().enumerate() {
            let position = (i % n + exponent) % (2 * n);
            let target = &mut expected[i / n * n + position % n];
            *target = if position < n {
                target.wrapping_sub(value)
            } else {
                target.wrapping_add(value)
            };
        }
        assert_eq!(recovered.as_ref(), expected, "exponent={exponent}");
    }
}

#[test]
fn fourier_ggsw_sub_mul_monomial_matches_coefficient_oracle() {
    sub_mul_monomial::<RustFftTable>();
    sub_mul_monomial::<TfheFftTable>();
}
