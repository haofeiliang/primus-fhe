//! Check teaching config domains and operation pairing without large keys or transforms.

use primus_reduce::Modulus;
use primus_tfhe_glwe_ntt::CbsInput;
use primus_tfhe_glwe_ntt::{CbsConfig, PbsConfig, PbsOrder, experimental as presets};

/// Message domains and order are independent of the shared key domain.
fn check_entries(pbs: [PbsConfig<u64>; 4], cbs: [CbsConfig<u64>; 2]) {
    for (config, (n, length, input_t, output_t, order)) in pbs.into_iter().zip([
        (866, 2048, 32, 32, PbsOrder::BootstrapKeyswitch),
        (728, 1024, 32, 32, PbsOrder::BootstrapKeyswitch),
        (728, 1024, 16, 8, PbsOrder::BootstrapKeyswitch),
        (728, 1024, 128, 2, PbsOrder::KeyswitchBootstrap),
    ]) {
        let parameters = config.try_prepare().unwrap();
        assert_eq!(parameters.small_lwe().dimension().get(), n);
        assert_eq!(parameters.blind_rotation_ggsw().poly_length().get(), length);
        assert_eq!(parameters.pbs_order(), order);
        assert!(parameters.glwe_key_switching().is_some());
        let messages = config.messages;
        assert_eq!(
            (messages.input_modulus, messages.output_modulus),
            (input_t, output_t)
        );
        if input_t == 128 {
            let codecs = parameters.factorized_pbs_codecs(messages).unwrap();
            assert_eq!(codecs.output_codec().plaintext_modulus(), 2);
            let factors = primus_tfhe::FactorizedLookupTable::try_new(
                64,
                parameters.blind_rotation_ggsw().poly_length(),
                17,
                codecs.input_codec(),
                codecs.lut_output_codec(),
                |input, output| u64::from(input >= (output + 1) * 64 / 18),
            )
            .unwrap();
            assert_eq!(factors.output_count(), 17);
        } else {
            let codecs = parameters
                .pbs_codecs(messages.with_output_modulus(8))
                .unwrap();
            let program = parameters
                .lookup_table_compiler(&codecs)
                .unwrap()
                .compile_fn(|_| 7)
                .unwrap();
            assert_eq!(program.input_domain_len(), input_t as usize / 2);
        }
        assert!(
            parameters
                .pbs_codecs(messages.with_output_modulus(1))
                .is_err()
        );
    }
    for (config, n) in cbs.into_iter().zip([800, 728]) {
        let parameters = config.try_prepare().unwrap();
        assert_eq!(parameters.small_lwe().dimension().get(), n);
        assert!(parameters.glwe_key_switching().is_none());
        // CMux's candidate domain is explicitly chosen by the consumer, not CBS's output.
        let (input, candidates) = parameters
            .circuit_bootstrap_codecs(config.input_modulus, 8)
            .unwrap();
        assert_eq!(input.plaintext_modulus(), 8);
        assert_eq!(
            candidates.ciphertext_modulus().explicit_value(),
            parameters.cipher_modulus().explicit_value()
        );
        let cbs = config.try_cbs_parameters(&parameters).unwrap();
        let predicate = cbs
            .compile_lookup_table_fn(&input, |m| u64::from(m >= 2))
            .unwrap();
        assert_eq!(predicate.output_basis().decompose_length().get(), 2);
        assert_eq!(predicate.input_domain_len(), 4);
        assert_eq!(
            parameters.blind_rotation_ggsw().noise_standard_deviation(),
            6.4
        );
    }
}

#[test]
fn experimental_configs_preserve_domains_and_prepare_only_needed_ks() {
    check_entries(
        [
            presets::CLASSIC_PBS_U64,
            presets::SPARSE_PBS_U64,
            presets::CLASSIC_MANY_LUT_U64,
            presets::CLASSIC_THRESHOLD_MVB_U64,
        ],
        [presets::CLASSIC_CBS_U64, presets::SPARSE_CBS_U64],
    );
    // KS→BR CBS requires input KS but still has no ordinary output-return stage.
    let mut config = presets::CLASSIC_CBS_U64;
    config.input = CbsInput::Keyswitch {
        key_switching: presets::SPARSE_PBS_U64.key_switching,
    };
    let parameters = config.try_prepare().unwrap();
    assert_eq!(parameters.pbs_order(), PbsOrder::KeyswitchBootstrap);
    assert!(parameters.glwe_key_switching().is_some());
}
