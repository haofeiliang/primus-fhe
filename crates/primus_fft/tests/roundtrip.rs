use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};

fn roundtrip<Table: FftTable>() {
    let fft = Table::new(5).unwrap();
    let mut engine = FftEngine::new(&fft);
    let input: Vec<u32> = (0..fft.poly_length())
        .map(|i| (i as i32 - 13) as u32)
        .collect();
    let mut fourier = vec![Complex64::default(); fft.fourier_length()];
    let mut output = vec![0u32; fft.poly_length()];
    engine.forward_as_torus(&input, &mut fourier);
    engine.backward_as_torus(&fourier, &mut output);
    assert_eq!(output, input);
}

fn concurrent_roundtrip<Table: FftTable>() {
    let fft = Table::new(8).unwrap();
    std::thread::scope(|scope| {
        for offset in 0..4u32 {
            let fft = &fft;
            scope.spawn(move || {
                let mut engine = FftEngine::new(fft);
                let input: Vec<u32> = (0..engine.poly_length())
                    .map(|index| (index as u32).wrapping_add(offset))
                    .collect();
                let mut fourier = vec![Complex64::default(); engine.fourier_length()];
                let mut output = vec![0u32; engine.poly_length()];
                engine.forward_as_torus(&input, &mut fourier);
                engine.backward_as_torus(&fourier, &mut output);
                assert_eq!(output, input);
            });
        }
    });
}

#[test]
fn rustfft_roundtrip() {
    roundtrip::<RustFftTable>();
}

#[test]
fn tfhe_fft_roundtrip() {
    roundtrip::<TfheFftTable>();
}

#[test]
fn rustfft_shared_table_runs_with_independent_scratch() {
    concurrent_roundtrip::<RustFftTable>();
}

#[test]
fn tfhe_fft_shared_table_runs_with_independent_scratch() {
    concurrent_roundtrip::<TfheFftTable>();
}
