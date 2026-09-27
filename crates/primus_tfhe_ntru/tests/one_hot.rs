use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_tfhe_ntru::{
    CircuitBootstrapConfig, CircuitBootstrapParameters, DecompositionConfig, OneHotBootstrapError,
    OneHotLookupTable, TfheParameters,
};

fn parameters<M: RingContext<u64>>(
    modulus: M,
    t: u64,
    levels: usize,
) -> (
    TfheParameters<u64, M, BarrettModulus<u64>>,
    CircuitBootstrapParameters<u64, M>,
) {
    let ring = NtruParameters::new(64, t, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let full = DecompositionConfig {
        log_basis: 3,
        level_count: None,
    };
    let tfhe = TfheParameters::try_new(
        LweParameters::new(
            4,
            t,
            BarrettModulus::new(1 << 20),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&ring, 3, None),
        full,
        0.7,
    )
    .unwrap();
    let cbs = CircuitBootstrapParameters::try_from_config(
        &tfhe,
        CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: 3,
                level_count: Some(levels),
            },
            trace: full,
            trace_noise_standard_deviation: 0.7,
            scheme_switch: full,
            scheme_switch_noise_standard_deviation: 0.7,
        },
    )
    .unwrap();
    (tfhe, cbs)
}

fn geometry<M: RingContext<u64>>(modulus: M, q: u128) {
    for t in [4, 8, 16] {
        for levels in [1, 3, 4] {
            let (tfhe, cbs) = parameters(modulus, t, levels);
            let lut = OneHotLookupTable::try_new(&tfhe, &cbs).unwrap();
            let n = 64i64;
            let m_count = (t / 2) as i64;
            let w = levels.next_power_of_two() as i64;
            let stride = n / m_count;
            let a = n / (2 * m_count * w);
            assert_eq!(lut.output_nlev_len(), m_count as usize * levels * 64);
            // Read a coefficient of X^(r*S-l-u_bar)*T directly from the
            // negacyclic extension, without production rotations or extraction.
            for message in 0..m_count {
                // Include both endpoints: -A belongs to this message, while
                // +A belongs to the next one. Past M-1, negacyclicity yields
                // the negative default selector, not a valid wrapped chunk.
                for error in -a..=a {
                    let u_bar = stride * message + w * error;
                    let expected_message = (u_bar + stride / 2).div_euclid(stride);
                    for selector in 0..m_count {
                        for level in 0..w {
                            let index = (u_bar - selector * stride + level).rem_euclid(2 * n);
                            let value = u128::from(lut.polynomial().as_ref()[(index % n) as usize]);
                            let actual = if index < n { value } else { (q - value) % q };
                            let expected = if selector == expected_message % m_count
                                && level < levels as i64
                            {
                                let scalar = u128::from(
                                    cbs.output_basis()
                                        .scalar_iter()
                                        .nth(level as usize)
                                        .unwrap(),
                                );
                                if expected_message < m_count {
                                    scalar
                                } else {
                                    (q - scalar) % q
                                }
                            } else {
                                0
                            };
                            assert_eq!(
                                actual, expected,
                                "m={message}, r={selector}, l={level}, e={error}"
                            );
                        }
                    }
                }
            }
        }
    }
    for t in [2, 6] {
        let (tfhe, cbs) = parameters(modulus, t, 3);
        assert_eq!(
            OneHotLookupTable::try_new(&tfhe, &cbs).unwrap_err(),
            OneHotBootstrapError::InvalidPlaintextModulus
        );
    }
    // Ordinary CBS fits exactly; one-hot additionally needs a nonempty guard.
    let (tfhe, cbs) = parameters(modulus, 32, 3);
    assert_eq!(
        OneHotLookupTable::try_new(&tfhe, &cbs).unwrap_err(),
        OneHotBootstrapError::InsufficientCapacity
    );
    let (other, _) = parameters(modulus, 8, 3);
    assert!(matches!(
        OneHotLookupTable::try_new(&other, &cbs),
        Err(OneHotBootstrapError::Evaluation(_))
    ));
}

#[test]
fn packed_polynomial_matches_negative_rotation_identity_with_padding_and_guard() {
    geometry(BarrettModulus::new(65_537u64), 65_537);
    geometry(NativeModulus::<u64>::new(), 1u128 << 64);
}
