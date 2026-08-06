use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    ngsw::{FourierNgswOwned, Ngsw},
    nlev::{FourierNlevOwned, Nlev},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

const LOG_N: u32 = 3;
const POLY_LENGTH: usize = 1 << LOG_N;
const LEVEL_COUNT: usize = 3;

fn input() -> Vec<u32> {
    (0..LEVEL_COUNT * POLY_LENGTH)
        .map(|i| (17 * i as u32 + 5) % 97)
        .collect()
}

#[test]
fn ntru_gadget_domain_conversions_preserve_levels() {
    let input = input();

    let modulus = BarrettModulus::new(97u32);
    let ntt = UintNttTable::<u32>::new(LOG_N, modulus).unwrap();

    let nlev = Nlev::new(input.clone());
    assert_eq!(nlev.iter_ntru(POLY_LENGTH).count(), LEVEL_COUNT);
    let ntt_nlev = nlev.into_ntt_form(&ntt);
    assert_eq!(ntt_nlev.iter_ntt_ntru(POLY_LENGTH).count(), LEVEL_COUNT);
    assert_eq!(ntt_nlev.into_coeff_form(&ntt).as_ref(), input);

    let ngsw = Ngsw::new(input.clone());
    assert_eq!(ngsw.iter_ntru(POLY_LENGTH).count(), LEVEL_COUNT);
    let ntt_ngsw = ngsw.into_ntt_form(&ntt);
    assert_eq!(ntt_ngsw.iter_ntt_ntru(POLY_LENGTH).count(), LEVEL_COUNT);
    assert_eq!(ntt_ngsw.into_coeff_form(&ntt).as_ref(), input);

    let fft = RustFftTable::new(LOG_N).unwrap();
    let mut engine = FftEngine::new(&fft);
    let fourier_len = LEVEL_COUNT * fft.fourier_length();

    let nlev = Nlev::new(input.clone());
    let mut fourier_nlev = FourierNlevOwned::zero(fourier_len);
    nlev.write_fourier_form(&mut fourier_nlev, &mut engine);
    assert_eq!(
        fourier_nlev.iter_ntru(fft.fourier_length()).count(),
        LEVEL_COUNT
    );
    let mut nlev_roundtrip = Nlev::<Vec<u32>>::zero(input.len());
    fourier_nlev.write_torus_form(&mut nlev_roundtrip, &mut engine);
    assert_eq!(nlev_roundtrip.as_ref(), input);

    let ngsw = Ngsw::new(input.clone());
    let mut fourier_ngsw = FourierNgswOwned::zero(fourier_len);
    ngsw.write_fourier_form(&mut fourier_ngsw, &mut engine);
    assert_eq!(
        fourier_ngsw.iter_ntru(fft.fourier_length()).count(),
        LEVEL_COUNT
    );
    let mut ngsw_roundtrip = Ngsw::<Vec<u32>>::zero(input.len());
    fourier_ngsw.write_torus_form(&mut ngsw_roundtrip, &mut engine);
    assert_eq!(ngsw_roundtrip.as_ref(), input);
}
