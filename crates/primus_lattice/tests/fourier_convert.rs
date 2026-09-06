use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::glwe::{FourierGlweOwned, Glwe};

fn roundtrip<Table: FftTable>() {
    let fft = Table::new(5).unwrap();
    let mut engine = FftEngine::new(&fft);
    let component_count = 3;
    let input: Vec<u32> = (0..component_count * fft.poly_length())
        .map(|i| (i as i32 * 19 - 200) as u32)
        .collect();
    let coeff = Glwe::new(input.clone());
    let mut fourier = FourierGlweOwned::zero(component_count * fft.fourier_length());
    coeff.write_fourier_form(&mut fourier, &mut engine);
    let mut output = Glwe::new(vec![0u32; input.len()]);
    fourier.write_torus_form(&mut output, &mut engine);
    assert_eq!(output.as_ref(), input);
}

#[test]
fn rustfft_glwe_roundtrip() {
    roundtrip::<RustFftTable>();
}

#[test]
fn tfhe_fft_glwe_roundtrip() {
    roundtrip::<TfheFftTable>();
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
