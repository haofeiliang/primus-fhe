//! Checked layouts, scratch compatibility, and gadget representation boundaries.

use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_lattice::{
    GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGlweSize,
    ngsw::{FourierNgswOwned, Ngsw},
    nlev::{FourierNlevOwned, Nlev},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

#[test]
fn checked_sizes_reject_empty_and_overflowing_layouts() {
    assert_eq!(GlweSize::try_new(0, 2), Err(GlweSizeError::ZeroDimension));
    assert_eq!(
        GlweSize::try_new(1, 0),
        Err(GlweSizeError::InvalidPolynomialLength)
    );
    assert!(GlweSize::try_new(1, MIN_POLY_LENGTH).is_ok());
    assert!(GlweSize::try_new(1, MAX_POLY_LENGTH).is_ok());
    assert_eq!(
        GlweSize::try_new(1, MAX_POLY_LENGTH << 1),
        Err(GlweSizeError::InvalidPolynomialLength)
    );

    let glwe = GlweSize::new(1, 2);
    assert_eq!(
        RnsGlweSize::try_new(glwe, 0),
        Err(GlweSizeError::ZeroModuliCount)
    );
    assert_eq!(
        GadgetSize::try_new(glwe, 0),
        Err(GlweSizeError::ZeroDecomposeLength)
    );
    assert!(matches!(
        GlweSize::try_new(usize::MAX, 2),
        Err(GlweSizeError::LengthOverflow(_))
    ));
    assert!(matches!(
        RnsGlweSize::try_new(glwe, usize::MAX),
        Err(GlweSizeError::LengthOverflow(_))
    ));
}

#[test]
fn ntru_gadget_domain_conversions_preserve_levels() {
    const LOG_N: u32 = 3;
    const POLY_LENGTH: usize = 1 << LOG_N;
    const LEVEL_COUNT: usize = 3;
    let input: Vec<u32> = (0..LEVEL_COUNT * POLY_LENGTH)
        .map(|i| (17 * i as u32 + 5) % 97)
        .collect();

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

#[cfg(feature = "rns")]
#[test]
fn dcrt_workspace_reuse_depends_on_layout_and_limb_width() {
    use primus_lattice::{RnsGadgetSize, context::DcrtGlevMulContext};
    use primus_rns::RNSBase;
    let size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 8), 2), 3);
    let small = RNSBase::new(&[17u32, 97].map(BarrettModulus::new)).unwrap();
    let other_small = RNSBase::new(&[19u32, 101].map(BarrettModulus::new)).unwrap();
    let large = RNSBase::new(&[65537u32, 65539].map(BarrettModulus::new)).unwrap();
    let context = DcrtGlevMulContext::new(size, &small);

    assert_eq!(small.big_uint_value_len(), 1);
    assert_eq!(large.big_uint_value_len(), 2);
    assert!(context.is_compatible(size, &small));
    assert!(context.is_compatible(size, &other_small));
    assert!(!context.is_compatible(size, &large));
    let other_size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 16), 2), 3);
    assert!(!context.is_compatible(other_size, &small));
}
