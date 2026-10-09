//! Numerical config boundaries retain the reducer's representation and sampling contract.

use primus_integer::FheUint;
use primus_lwe::{LweDimension, LweEncryptionParameters, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_tfhe::{LweConfig, LweConfigError, ModulusConfig};

fn check_moduli<T: FheUint>() {
    for (value, valid) in [
        (T::ZERO, false),
        (T::ONE, false),
        (T::as_from(65_537u32), true),
        (T::ONE << (T::BITS - 2), false),
    ] {
        let result = BarrettModulus::try_from(ModulusConfig::Explicit(value));
        assert_eq!(result.is_ok(), valid);
        if let Ok(modulus) = result {
            assert_eq!(modulus.value(), value);
        }
    }
    assert!(BarrettModulus::<T>::try_from(ModulusConfig::Native).is_err());
    for (value, valid) in [
        (T::ZERO, false),
        (T::ONE, false),
        (T::as_from(3u8), false),
        (T::ONE << (T::BITS - 1), true),
    ] {
        let result = PowOf2Modulus::try_from(ModulusConfig::Explicit(value));
        assert_eq!(result.is_ok(), valid);
        if let Ok(modulus) = result {
            assert_eq!(modulus.value(), value);
        }
    }
    assert!(PowOf2Modulus::<T>::try_from(ModulusConfig::Native).is_err());
    assert!(NativeModulus::<T>::try_from(ModulusConfig::Native).is_ok());
    assert!(NativeModulus::try_from(ModulusConfig::Explicit(T::MAX)).is_err());

    let lwe = LweConfig::<PowOf2Modulus<T>> {
        dimension: LweDimension::new(2),
        cipher_modulus: ModulusConfig::Explicit(T::as_from(16u8)),
        secret_key_distr: SecretKeyDistr::UniformBinary,
        noise_standard_deviation: -1.0,
    };
    assert!(matches!(
        LweEncryptionParameters::try_from(lwe),
        Err(LweConfigError::Parameters(_))
    ));
    let bad_modulus = LweConfig {
        cipher_modulus: ModulusConfig::Explicit(T::as_from(3u8)),
        ..lwe
    };
    assert!(matches!(
        LweEncryptionParameters::try_from(bad_modulus),
        Err(LweConfigError::Modulus(_))
    ));
}

#[test]
fn numerical_descriptions_validate_moduli_and_sampling_before_use() {
    check_moduli::<u32>();
    check_moduli::<u64>();
}
