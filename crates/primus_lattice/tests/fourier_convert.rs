use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lattice::glwe::{FourierGlweOwned, Glwe};

fn roundtrip<Table: FftTable>() {
    let fft = Table::new(5).unwrap();
    let component_count = 3;
    let input: Vec<u32> = (0..component_count * fft.poly_length())
        .map(|i| (i as i32 * 19 - 200) as u32)
        .collect();
    let coeff = Glwe::new(input.clone());
    let mut fourier = FourierGlweOwned::zero(component_count * fft.fourier_length());
    coeff.write_fourier_form(&mut fourier, &fft);
    let mut output = Glwe::new(vec![0u32; input.len()]);
    fourier.write_torus_form(&mut output, &fft);
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
