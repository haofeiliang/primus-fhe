//! Separate q/Q domains and packed one-hot geometry; no key generation or transforms.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe::{BlindRotationMethod, DecompositionBaseLog, DecompositionLevelCount, PolyLength};
use primus_tfhe_ntru::{
    CbsGadgetConfig, CbsGadgetParameters, CbsParameters, CircuitBootstrapParameterError,
    DecompositionConfig, GadgetEncryptionConfig, LookupTableError, LweConfig, ModulusConfig,
    OneHotBootstrapError, OneHotLookupTable, PbsConfig, PbsMessageConfig, PbsParameters,
    TfheParameterError,
};

fn decomposition(base: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base),
        level_count: None,
    }
}

fn config() -> PbsConfig<u32, BarrettModulus<u32>, PowOf2Modulus<u32>> {
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: ModulusConfig::Explicit(1024),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 1.0,
        },
        acc_modulus: ModulusConfig::Explicit(12289),
        bsk_poly_length: PolyLength::new(64),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(2),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(2),
            noise_standard_deviation: 3.2,
        },
        algorithm: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(8).with_output_modulus(4),
    }
}

fn gadget() -> CbsGadgetConfig {
    CbsGadgetConfig {
        trace: decomposition(2),
        scheme_switch: decomposition(2),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(2),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    }
}

#[test]
fn return_and_codecs_use_external_q_while_lut_uses_ring_q() {
    let parameters = PbsParameters::try_from_config(config()).unwrap();
    let codecs = parameters.pbs_codecs(parameters.messages()).unwrap();
    let table = parameters
        .lookup_table_compiler(&codecs)
        .unwrap()
        .compile_fn(|x| (x % 4) as u32)
        .unwrap();
    // Plateau boundaries at t_in=8, encoded at t_out=4 and Q=12289.
    // Checking midpoints also catches accidentally using t_out for input centers.
    for (index, expected) in [(0, 0), (8, 3072), (24, 6145), (40, 9217), (56, 0)] {
        assert_eq!(table.polynomial().as_ref()[index], expected);
    }
    assert_eq!(codecs.output_codec().decode_value(256), 1);
    assert_eq!(parameters.key_switching().basis().modulus(), Some(1024));
    assert_eq!(
        parameters.key_switching().lwe().noise_standard_deviation(),
        3.2
    );
    for (q, big_q, expected) in [
        (2048, 12289, LookupTableError::InputModulusMismatch),
        (1024, 65537, LookupTableError::OutputModulusMismatch),
    ] {
        let wrong = parameters
            .messages()
            .try_rounded_codecs(PowOf2Modulus::new(q), BarrettModulus::new(big_q))
            .unwrap();
        assert!(
            matches!(parameters.lookup_table_compiler(&wrong), Err(error) if error == expected)
        );
    }
    let cbs = CbsParameters::try_with_config(parameters, gadget()).unwrap();
    let mut changed = config();
    changed.messages.output_modulus = 16;
    changed.key_switching.noise_standard_deviation = 2.0;
    assert!(
        cbs.clone()
            .try_with_pbs_parameters(PbsParameters::try_from_config(changed).unwrap())
            .is_ok()
    );
    changed.messages.input_modulus = 4;
    assert!(matches!(
        cbs.try_with_pbs_parameters(PbsParameters::try_from_config(changed).unwrap()),
        Err(TfheParameterError::IncompatibleComponents)
    ));
}

#[test]
fn independent_cbs_material_must_match_ring_and_trace_modulus() {
    let pbs = PbsParameters::try_from_config(config()).unwrap();
    let cbs = CbsGadgetParameters::try_from_config(&pbs, gadget()).unwrap();
    let foreign_basis = ApproxSignedBasis::new(Some(65537), DecompositionBaseLog::new(2), None);
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            foreign_basis,
            cbs.trace().clone(),
            cbs.scheme_switch().clone()
        ),
        Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch)
    ));
    let mut changed = config();
    changed.bsk_poly_length = PolyLength::new(32);
    let other = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            cbs.output_basis().clone(),
            other.blind_rotation().clone(),
            cbs.scheme_switch().clone()
        ),
        Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role: "trace" })
    ));
    changed = config();
    changed.acc_modulus = ModulusConfig::Explicit(65537);
    let other = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_new(
            &pbs,
            cbs.output_basis().clone(),
            cbs.trace().clone(),
            other.blind_rotation().clone()
        ),
        Err(CircuitBootstrapParameterError::CipherModulusMismatch {
            role: "scheme-switch"
        })
    ));
    changed.acc_modulus = ModulusConfig::Explicit(12288); // Valid even Barrett ring; modular trace cannot halve it.
    let even = PbsParameters::try_from_config(changed).unwrap();
    assert!(matches!(
        CbsGadgetParameters::try_from_config(&even, gadget()),
        Err(CircuitBootstrapParameterError::UnsupportedTraceModulus)
    ));
}

#[test]
fn one_hot_negative_rotation_has_left_closed_guard_and_zero_padding() {
    let cbs = CbsParameters::try_from_config(config(), gadget()).unwrap();
    let pbs = cbs.pbs_parameters();
    let table = OneHotLookupTable::try_new(pbs, cbs.gadget(), cbs.input_codec()).unwrap();
    let coefficients = table.polynomial().as_ref();
    let n = 64i32;
    let weights: Vec<_> = cbs.gadget().output_basis().scalar_iter().collect();
    // Read the constant term of X^power*T using signed negacyclic indexing.
    let constant = |power: i32| {
        let index = (-power).rem_euclid(2 * n) as usize;
        let value = coefficients[index % n as usize];
        if index < n as usize {
            value
        } else {
            (12289 - value) % 12289
        }
    };
    let w = 4;
    let stride = 16;
    let a = 2;
    for message in 0..4 {
        for error in -a..a {
            let phase = message * stride + w * error;
            for selector in 0..4 {
                for level in 0..w {
                    let expected = if selector == message && level < 3 {
                        weights[level as usize]
                    } else {
                        0
                    };
                    assert_eq!(constant(selector * stride - level - phase), expected);
                }
            }
        }
    }
    // The excluded right endpoint of m=0 belongs to m=1, including r=0's zero result.
    assert_eq!(constant(-w * a), 0);
    assert_eq!(constant(stride - w * a), weights[0]);
    let too_wide = RoundedCodec::new(32, pbs.external_lwe().cipher_modulus());
    assert!(matches!(
        OneHotLookupTable::try_new(pbs, cbs.gadget(), &too_wide),
        Err(OneHotBootstrapError::InsufficientCapacity)
    ));
}
