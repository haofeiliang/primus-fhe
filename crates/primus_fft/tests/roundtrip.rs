use aligned_vec::{AVec, CACHELINE_ALIGN, avec};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};

fn roundtrip<Table: FftTable>() {
    for log_n in [2, 5, 10] {
        let fft = Table::new(log_n).unwrap();
        let mut engine = FftEngine::new(&fft);
        // Offset aligned allocations: public slices need only element alignment,
        // even though the table and its own workspace use cache-line alignment.
        let input = AVec::<u32>::from_iter(
            CACHELINE_ALIGN,
            (0..=fft.poly_length()).map(|i| (i as i32 - 13) as u32),
        );
        let mut fourier = avec![Complex64::default(); fft.fourier_length() + 1];
        let mut output = avec![0u32; fft.poly_length() + 1];
        engine.forward_as_torus(&input[1..], &mut fourier[1..]);
        engine.backward_as_torus(&fourier[1..], &mut output[1..]);
        assert_eq!(output[1..], input[1..]);
    }
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

#[test]
fn u64_torus_conversion_preserves_round_saturate_and_wrap() {
    use primus_fft::TorusFftValue;
    check_torus_conversion::<u64>(
        |x| ((x * u64::TORUS_SCALE_INVERSE).round() as i128) as u64,
        2.0f64.powi(63),
    );
}

#[test]
fn u32_torus_conversion_preserves_round_saturate_and_wrap() {
    use primus_fft::TorusFftValue;
    check_torus_conversion::<u32>(
        |x| ((x * u32::TORUS_SCALE_INVERSE).round() as i64) as u32,
        2.0f64.powi(31),
    );
}

fn check_torus_conversion<T: primus_fft::TorusFftValue>(
    reference: impl Fn(f64) -> T,
    saturation_edge: f64,
) {
    let check = |x: f64| {
        assert_eq!(
            T::from_torus_f64(x),
            reference(x),
            "input bits: {:016x}",
            x.to_bits()
        );
    };
    for value in [
        0.0,
        -0.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MAX,
        f64::MIN,
    ] {
        check(value);
    }
    // Half-integers in coefficient units, torus periods and saturation edges.
    for value in [
        0.5 * T::TORUS_SCALE,
        1.5 * T::TORUS_SCALE,
        3.5 * T::TORUS_SCALE,
        0.5,
        1.0,
        2.0,
        2.0f64.powi(52) * T::TORUS_SCALE,
        saturation_edge,
    ] {
        for bits in [value.to_bits() - 1, value.to_bits(), value.to_bits() + 1] {
            check(f64::from_bits(bits));
            check(-f64::from_bits(bits));
        }
    }
    // Every floating exponent with representative mantissas and both signs.
    for exponent in 0..=0x7ffu64 {
        for fraction in [0, 1, (1u64 << 51) - 1, 1u64 << 51, (1u64 << 52) - 1] {
            for sign in [0, 1u64 << 63] {
                check(f64::from_bits(sign | (exponent << 52) | fraction));
            }
        }
    }
    let mut bits = 42u64;
    for _ in 0..100_000 {
        bits ^= bits << 13;
        bits ^= bits >> 7;
        bits ^= bits << 17;
        check(f64::from_bits(bits));
    }
}
