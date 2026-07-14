use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};

fn negacyclic_reference(torus: &[u32], integer: &[u32]) -> Vec<u32> {
    let n = torus.len();
    let mut result = vec![0i128; n];
    for i in 0..n {
        for j in 0..n {
            let a = torus[i] as i32 as i128;
            let b = integer[j] as i32 as i128;
            if i + j < n {
                result[i + j] += a * b;
            } else {
                result[i + j - n] -= a * b;
            }
        }
    }
    result.into_iter().map(|x| x as u32).collect()
}

fn convolution<Table: FftTable>() {
    let fft = Table::new(4).unwrap();
    let mut engine = FftEngine::new(&fft);
    let torus: Vec<u32> = (0..16).map(|i| (1000i32 - 31 * i) as u32).collect();
    let integer: Vec<u32> = (0..16).map(|i| (i % 5 - 2) as u32).collect();
    let mut lhs = vec![Complex64::default(); 8];
    let mut rhs = vec![Complex64::default(); 8];
    engine.forward_as_torus(&torus, &mut lhs);
    engine.forward_as_integer(&integer, &mut rhs);
    for (x, y) in lhs.iter_mut().zip(rhs) {
        *x *= y;
    }
    let mut output = vec![0u32; 16];
    engine.backward_as_torus(&lhs, &mut output);
    assert_eq!(output, negacyclic_reference(&torus, &integer));
}

#[test]
fn rustfft_negacyclic_convolution() {
    convolution::<RustFftTable>();
}

#[test]
fn tfhe_fft_negacyclic_convolution() {
    convolution::<TfheFftTable>();
}
