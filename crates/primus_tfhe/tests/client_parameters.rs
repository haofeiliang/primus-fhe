//! Client parameter binding checks, without transform or evaluation keys.

use primus_distr::{DiscreteGaussian, SecretKeyDistr};
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
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
    assert_eq!(ordinary.codec().plaintext_modulus(), 4);
    assert!(std::ptr::eq(ordinary.noise(), lwe.noise_distribution()));
    assert_eq!(ordinary.uniform(), modulus.uniform_distribution());

    // Small and large supports exercise CDT and Ziggurat modulus metadata.
    for deviation in [1.4, 300.0] {
        let noise = DiscreteGaussian::new(deviation, modulus.minus_one()).unwrap();
        // The selected codec is local to binding; only the large sampler is
        // borrowed. Its different message domain survives after the codec drops.
        let (extracted, encoded_one) = {
            let codec = RoundedCodec::new(8, modulus);
            let encoded_one = codec.encode_value(1, PlaintextEmbedding::Unsigned);
            (
                LweClientParameters::try_from_parts(LweDimension::new(7), &codec, &noise).unwrap(),
                encoded_one,
            )
        };
        assert_eq!(extracted.dimension(), LweDimension::new(7));
        assert_eq!(extracted.codec().plaintext_modulus(), 8);
        assert_eq!(
            extracted
                .codec()
                .encode_value(1, PlaintextEmbedding::Unsigned),
            encoded_one
        );
        assert!(std::ptr::eq(extracted.noise(), &noise));
        assert_eq!(extracted.uniform(), ordinary.uniform());

        let wrong_noise = DiscreteGaussian::new(deviation, other_modulus_minus_one).unwrap();
        assert_eq!(
            LweClientParameters::try_from_parts(
                LweDimension::new(7),
                lwe.plaintext_codec(),
                &wrong_noise
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
