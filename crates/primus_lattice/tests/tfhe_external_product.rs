use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_lattice::{
    context::TfheFftContext, ggsw::FourierGgswOwned, glwe::Glwe,
    tfhe::external_product::external_product_to,
};

#[test]
fn zero_fourier_ggsw_produces_zero() {
    let fft = RustFftTable::new(4).unwrap();
    let dimension = 1;
    let component_count = dimension + 1;
    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(3));
    let level = basis.decompose_length();
    let input = Glwe::new(vec![1u32; component_count * fft.poly_length()]);
    let key =
        FourierGgswOwned::zero(component_count * level * component_count * fft.fourier_length());
    let mut output = Glwe::new(vec![u32::MAX; component_count * fft.poly_length()]);
    let mut context = TfheFftContext::new(fft.poly_length(), fft.fourier_length(), dimension);
    external_product_to(
        &input,
        &key,
        &mut output,
        &basis,
        &fft,
        &mut context,
        dimension,
    );
    assert!(output.as_ref().iter().all(|x| *x == 0));
}
