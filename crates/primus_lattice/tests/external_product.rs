use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    GadgetSize, GlweSize,
    context::{
        FourierExternalProductContext, FourierNtruExternalProductContext,
        NttNtruExternalProductContext,
    },
    ggsw::FourierGgswOwned,
    glwe::Glwe,
    ngsw::{FourierNgswOwned, Ngsw},
    nlev::{FourierNlevOwned, Nlev},
    ntru::Ntru,
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;

#[test]
fn zero_fourier_ggsw_produces_zero() {
    let fft = RustFftTable::new(4).unwrap();
    let mut engine = FftEngine::new(&fft);
    let dimension = 1;
    let component_count = dimension + 1;
    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(3));
    let level = basis.decompose_length();
    let input = Glwe::new(vec![1u32; component_count * fft.poly_length()]);
    let key =
        FourierGgswOwned::zero(component_count * level * component_count * fft.fourier_length());
    let mut output = Glwe::new(vec![u32::MAX; component_count * fft.poly_length()]);
    let mut context = FourierExternalProductContext::new(GadgetSize::new(
        GlweSize::new(dimension, fft.poly_length()),
        basis.decompose_length(),
    ));
    key.external_product_to(&input, &mut output, &basis, &mut engine, &mut context);
    assert!(output.as_ref().iter().all(|x| *x == 0));
}

#[test]
fn ntt_ntru_gadget_products_match_negacyclic_product() {
    const LOG_N: u32 = 4;
    const N: usize = 1 << LOG_N;
    const Q: u32 = 257;

    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::<u32>::new(LOG_N, modulus).unwrap();
    let basis = ApproxSignedBasis::new(Some(Q), 3, None);

    let alpha = Polynomial::<Vec<u32>>::new(vec![
        0, 1, 8, 63, 64, 127, 128, 192, 255, 256, 17, 33, 65, 129, 193, 241,
    ]);
    let mut beta = Polynomial::<Vec<u32>>::zero(N);
    beta.as_mut()[3] = 7;

    let make_nlev = |message: &Polynomial<Vec<u32>>| {
        let mut nlev = Nlev::<Vec<u32>>::zero(basis.decompose_length() * N);
        for (scalar, mut level) in basis.scalar_iter().zip(nlev.iter_ntru_mut(N)) {
            message.mul_scalar_to(scalar, &mut Polynomial(level.as_mut()), modulus);
        }
        nlev
    };

    let coeff_nlev = make_nlev(&beta);
    let coeff_ngsw = Ngsw::new(coeff_nlev.as_ref().to_vec());
    let ntt_nlev = coeff_nlev.into_ntt_form(&ntt);
    let ntt_ngsw = coeff_ngsw.into_ntt_form(&ntt);

    let mut expected = Polynomial::<Vec<u32>>::zero(N);
    alpha.naive_mul_to(&beta, &mut expected, modulus);

    let mut context = NttNtruExternalProductContext::new(N);

    let mut nlev_product = Ntru::new(vec![u32::MAX; N]);
    ntt_nlev.external_product_to(
        &alpha,
        &mut nlev_product,
        &basis,
        modulus,
        &ntt,
        &mut context,
    );
    assert_eq!(nlev_product.as_ref(), expected.as_ref());

    let input_ntru = Ntru::<Vec<u32>>::from_ref(&alpha);
    let mut ngsw_product = Ntru::new(vec![u32::MAX; N]);
    ntt_ngsw.external_product_to(
        &input_ntru,
        &mut ngsw_product,
        &basis,
        modulus,
        &ntt,
        &mut context,
    );
    assert_eq!(ngsw_product.as_ref(), expected.as_ref());

    let input_nlev = make_nlev(&alpha);
    let expected_nlev = make_nlev(&expected);
    let mut output_nlev = Nlev::<Vec<u32>>::zero(basis.decompose_length() * N);
    ntt_ngsw.external_product_nlev_to(
        &input_nlev,
        &mut output_nlev,
        &basis,
        modulus,
        &ntt,
        &mut context,
    );
    assert_eq!(output_nlev.as_ref(), expected_nlev.as_ref());
}

#[test]
fn fourier_ntru_gadget_products_match_negacyclic_product() {
    const LOG_N: u32 = 4;
    const N: usize = 1 << LOG_N;

    let modulus = NativeModulus::<u32>::new();
    let basis = ApproxSignedBasis::<u32>::new(None, 8, None);
    let fft = RustFftTable::new(LOG_N).unwrap();
    let mut engine = FftEngine::new(&fft);

    let alpha = Polynomial::<Vec<u32>>::new(vec![
        0x0123_4567,
        0x89ab_cdef,
        0xfedc_ba98,
        0x7654_3210,
        0x1357_9bdf,
        0x2468_ace0,
        0xffff_ffff,
        0x8000_0000,
        0x7fff_ffff,
        0xdead_beef,
        0xcafe_babe,
        0x1020_3040,
        0x5566_7788,
        0xaabb_ccdd,
        0x3141_5926,
        0x2718_2818,
    ]);
    let mut beta = Polynomial::<Vec<u32>>::zero(N);
    beta.as_mut()[5] = 1;

    let make_nlev = |message: &Polynomial<Vec<u32>>| {
        let mut nlev = Nlev::<Vec<u32>>::zero(basis.decompose_length() * N);
        for (scalar, mut level) in basis.scalar_iter().zip(nlev.iter_ntru_mut(N)) {
            message.mul_scalar_to(scalar, &mut Polynomial(level.as_mut()), modulus);
        }
        nlev
    };

    let coeff_nlev = make_nlev(&beta);
    let coeff_ngsw = Ngsw::new(coeff_nlev.as_ref().to_vec());

    let fourier_length = basis.decompose_length() * fft.fourier_length();
    let mut fourier_nlev = FourierNlevOwned::zero(fourier_length);
    coeff_nlev.write_fourier_form(&mut fourier_nlev, &mut engine);
    let mut fourier_ngsw = FourierNgswOwned::zero(basis.decompose_length() * fft.fourier_length());
    coeff_ngsw.write_fourier_form(&mut fourier_ngsw, &mut engine);

    let mut expected = Polynomial::<Vec<u32>>::zero(N);
    alpha.naive_mul_to(&beta, &mut expected, modulus);

    let mut context = FourierNtruExternalProductContext::new(N);

    let mut nlev_product = Ntru::new(vec![u32::MAX; N]);
    fourier_nlev.external_product_to(&alpha, &mut nlev_product, &basis, &mut engine, &mut context);
    assert_eq!(nlev_product.as_ref(), expected.as_ref());

    let input_ntru = Ntru::<Vec<u32>>::from_ref(&alpha);
    let mut ngsw_product = Ntru::new(vec![u32::MAX; N]);
    fourier_ngsw.external_product_to(
        &input_ntru,
        &mut ngsw_product,
        &basis,
        &mut engine,
        &mut context,
    );
    assert_eq!(ngsw_product.as_ref(), expected.as_ref());

    let input_nlev = make_nlev(&alpha);
    let expected_nlev = make_nlev(&expected);
    let mut output_nlev = Nlev::<Vec<u32>>::zero(basis.decompose_length() * N);
    fourier_ngsw.external_product_nlev_to(
        &input_nlev,
        &mut output_nlev,
        &basis,
        &mut engine,
        &mut context,
    );
    assert_eq!(output_nlev.as_ref(), expected_nlev.as_ref());
}
