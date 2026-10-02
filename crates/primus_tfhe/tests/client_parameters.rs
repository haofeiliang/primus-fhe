//! Client parameter binding checks, without transform or evaluation keys.

use primus_distr::{DiscreteGaussian, SecretKeyDistr};
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, LweClientParameters};

fn check_noise_binding<M: RingContext<u32>>(modulus: M, other_modulus_minus_one: u32) {
    let lwe = LweParameters::new(
        LweDimension::new(3),
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let ordinary = LweClientParameters::new(&lwe);
    assert_eq!(ordinary.dimension(), lwe.dimension());
    assert!(std::ptr::eq(ordinary.codec(), lwe.plaintext_codec()));
    assert!(std::ptr::eq(ordinary.noise(), lwe.noise_distribution()));
    assert_eq!(ordinary.uniform(), modulus.uniform_distribution());

    // Small and large supports exercise CDT and Ziggurat modulus metadata.
    for deviation in [1.4, 300.0] {
        let noise = DiscreteGaussian::new(deviation, modulus.minus_one()).unwrap();
        let extracted =
            LweClientParameters::try_with_dimension_and_noise(&lwe, LweDimension::new(7), &noise)
                .unwrap();
        assert_eq!(extracted.dimension(), LweDimension::new(7));
        assert!(std::ptr::eq(extracted.codec(), ordinary.codec()));
        assert!(std::ptr::eq(extracted.noise(), &noise));
        assert_eq!(extracted.uniform(), ordinary.uniform());

        let wrong_noise = DiscreteGaussian::new(deviation, other_modulus_minus_one).unwrap();
        assert_eq!(
            LweClientParameters::try_with_dimension_and_noise(
                &lwe,
                LweDimension::new(7),
                &wrong_noise,
            )
            .err(),
            Some(ClientError::NoiseModulusMismatch),
        );
    }
}

/// Distinguishes Native, explicit power-of-two and general explicit domains.
#[test]
fn alternate_noise_is_bound_to_the_codec_modulus() {
    check_noise_binding(NativeModulus::new(), (1 << 20) - 1);
    check_noise_binding(PowOf2Modulus::new(1 << 20), u32::MAX);
    check_noise_binding(BarrettModulus::new(1_048_583), (1 << 20) - 1);
}
