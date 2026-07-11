use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};

fn roundtrip<Table: FftTable>() {
    let fft = Table::new(5).unwrap();
    let input: Vec<u32> = (0..fft.poly_length())
        .map(|i| (i as i32 - 13) as u32)
        .collect();
    let mut fourier = vec![Complex64::default(); fft.fourier_length()];
    let mut output = vec![0u32; fft.poly_length()];
    fft.forward_as_torus(&input, &mut fourier);
    fft.backward_as_torus(&fourier, &mut output);
    assert_eq!(output, input);
}

#[test]
fn rustfft_roundtrip() {
    roundtrip::<RustFftTable>();
}

#[test]
fn tfhe_fft_roundtrip() {
    roundtrip::<TfheFftTable>();
}
