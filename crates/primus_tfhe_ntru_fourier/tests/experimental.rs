//! Check teaching config domains and operation pairing without large keys or transforms.

use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_reduce::Modulus;
use primus_tfhe_ntru_fourier::{
    CbsConfig, CbsParameters, OneHotLookupTable, PbsConfig, PbsParameters, experimental as presets,
};

/// Keep PBS q/Q separate and CBS free of numerical return state.
fn check_entries(
    pbs: [PbsConfig<u64, PowOf2Modulus<u64>>; 4],
    cbs: [CbsConfig<u64, PowOf2Modulus<u64>>; 2],
) {
    for (config, (n, length, input_t, output_t)) in pbs.into_iter().zip([
        (866, 2048, 32, 32),
        (728, 1024, 32, 32),
        (728, 1024, 16, 8),
        (728, 1024, 128, 2),
    ]) {
        let parameters = PbsParameters::try_from_config(config).unwrap();
        assert_eq!(parameters.as_ref().external_lwe().dimension().get(), n);
        assert_eq!(parameters.as_ref().poly_length().get(), length);
        assert_eq!(
            parameters.as_ref().external_lwe().cipher_modulus_value(),
            Some(1 << 24)
        );
        assert_eq!(
            parameters
                .as_ref()
                .accumulator_ntru()
                .noise_distribution()
                .standard_deviation(),
            0.7
        );
        assert_eq!(
            parameters.key_switching().lwe().noise_standard_deviation(),
            3.2
        );
        let messages = parameters.messages();
        assert_eq!(messages, config.messages);
        assert_eq!(parameters.as_ref().algorithm(), config.algorithm);
        assert_eq!(
            (messages.input_modulus, messages.output_modulus),
            (input_t, output_t)
        );
        if input_t == 128 {
            let codecs = parameters.as_ref().factorized_pbs_codecs(messages).unwrap();
            let factors = primus_tfhe::FactorizedLookupTable::try_new(
                64,
                parameters.as_ref().poly_length(),
                17,
                codecs.input_codec(),
                codecs.lut_output_codec(),
                |input, output| u64::from(input >= (output + 1) * 64 / 18),
            )
            .unwrap();
            assert_eq!(factors.output_count(), 17);
        } else {
            let codecs = parameters
                .as_ref()
                .pbs_codecs(messages.with_output_modulus(8))
                .unwrap();
            assert_eq!(
                codecs
                    .lut_output_codec()
                    .ciphertext_modulus()
                    .explicit_value(),
                parameters
                    .as_ref()
                    .accumulator_ntru()
                    .cipher_modulus_value()
            );
            assert_eq!(codecs.output_codec().ciphertext_modulus().value(), 1 << 24);
            let program = parameters
                .as_ref()
                .lookup_table_compiler(&codecs)
                .unwrap()
                .compile_fn(|_| 7)
                .unwrap();
            assert_eq!(program.input_domain_len(), input_t as usize / 2);
        }
        assert!(
            parameters
                .as_ref()
                .pbs_codecs(messages.with_output_modulus(1))
                .is_err()
        );
    }
    for (config, one_hot) in cbs.into_iter().zip([false, true]) {
        let parameters = CbsParameters::try_from_config(config.pbs, config.gadget).unwrap();
        assert_eq!(parameters.as_ref().algorithm(), config.pbs.algorithm);
        assert_eq!(
            parameters.input_codec().plaintext_modulus(),
            config.pbs.messages.input_modulus
        );
        assert_eq!(parameters.as_ref().external_lwe().dimension().get(), 800);
        assert_eq!(
            parameters.as_ref().external_lwe().secret_key_distr(),
            if one_hot {
                SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 32 }
            } else {
                SecretKeyDistr::UniformBinary
            }
        );
        assert_eq!(
            parameters
                .as_ref()
                .external_lwe()
                .noise_standard_deviation(),
            (1u64 << 24) as f64 * 2.046_151_696_979_124e-6
        );
        let (input, _) = parameters
            .as_ref()
            .circuit_bootstrap_codecs(config.pbs.messages.input_modulus, 8)
            .unwrap();
        let cbs = parameters.gadget();
        if one_hot {
            let table = OneHotLookupTable::try_new(parameters.as_ref(), cbs, &input).unwrap();
            assert_eq!(table.selector_count(), 4);
            assert_eq!(table.guard_radius(), 32);
        } else {
            let predicate = cbs
                .compile_lookup_table_fn(&input, |m| u64::from(m >= 2))
                .unwrap();
            assert_eq!(predicate.output_basis().decompose_length().get(), 3);
        }
    }
}

#[test]
fn experimental_configs_share_br_and_return_domains() {
    check_entries(
        [
            presets::CLASSIC_PBS_U64,
            presets::SPARSE_PBS_U64,
            presets::CLASSIC_MANY_LUT_U64,
            presets::CLASSIC_THRESHOLD_MVB_U64,
        ],
        [presets::CLASSIC_CBS_U64, presets::CLASSIC_ONE_HOT_U64],
    );
}
