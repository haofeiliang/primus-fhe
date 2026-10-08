//! Numerical config boundaries retain the reducer's representation and sampling contract.

use primus_integer::FheUint;
use primus_lwe::{LweDimension, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_tfhe::{LweConfig, LweConfigError, ModulusConfig};

fn check_moduli<T: FheUint>() {
    for (value, valid) in [
        (T::ZERO, false),
        (T::ONE, false),
        (T::as_from(65_537u32), true),
        (T::ONE << (T::BITS - 2), false),
    ] {
        let result = ModulusConfig::<BarrettModulus<T>>::Explicit(value).try_build();
        assert_eq!(result.is_ok(), valid);
        if let Ok(modulus) = result {
            assert_eq!(modulus.value(), value);
        }
    }
    assert!(
        ModulusConfig::<BarrettModulus<T>>::Native
            .try_build()
            .is_err()
    );
    for (value, valid) in [
        (T::ZERO, false),
        (T::ONE, false),
        (T::as_from(3u8), false),
        (T::ONE << (T::BITS - 1), true),
    ] {
        let result = ModulusConfig::<PowOf2Modulus<T>>::Explicit(value).try_build();
        assert_eq!(result.is_ok(), valid);
        if let Ok(modulus) = result {
            assert_eq!(modulus.value(), value);
        }
    }
    assert!(
        ModulusConfig::<PowOf2Modulus<T>>::Native
            .try_build()
            .is_err()
    );
    assert!(
        ModulusConfig::<NativeModulus<T>>::Native
            .try_build()
            .is_ok()
    );
    assert!(
        ModulusConfig::<NativeModulus<T>>::Explicit(T::MAX)
            .try_build()
            .is_err()
    );

    let lwe = LweConfig::<PowOf2Modulus<T>> {
        dimension: LweDimension::new(2),
        cipher_modulus: ModulusConfig::Explicit(T::as_from(16u8)),
        secret_key_distr: SecretKeyDistr::UniformBinary,
        noise_standard_deviation: -1.0,
    };
    assert!(matches!(
        lwe.try_prepare(),
        Err(LweConfigError::Parameters(_))
    ));
    let bad_modulus = LweConfig {
        cipher_modulus: ModulusConfig::Explicit(T::as_from(3u8)),
        ..lwe
    };
    assert!(matches!(
        bad_modulus.try_prepare(),
        Err(LweConfigError::Modulus(_))
    ));
}

#[test]
fn numerical_descriptions_validate_moduli_and_sampling_before_use() {
    check_moduli::<u32>();
    check_moduli::<u64>();
}
