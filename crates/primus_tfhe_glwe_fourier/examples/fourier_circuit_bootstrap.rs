//! Use an encrypted LWE bit to select between two encrypted ring messages via CBS and CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_glwe_fourier --example fourier_circuit_bootstrap --features rustfft`
//! For u64, change Word to u64. To use TfheFftTable, also switch this target's
//! required-features and the command above to tfhe-fft.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable as Table;
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParametersInner;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BootstrappingKey, CircuitBootstrapConfig, CircuitBootstrapEvaluator,
    CircuitBootstrapParameters, ClientKey, DecompositionConfig, KeyGenerator, PbsOrder, TfheConfig,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;
const ORDER: PbsOrder = PbsOrder::BootstrapKeyswitch;

// Key parameters: n=800, N=1024; LWE and GLWE share the ciphertext modulus.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word> {
    let modulus = NativeModulus::<Word>::new();
    let q = 2f64.powi(Word::BITS as i32);

    // None retains floor(modulus_bits / log_basis) levels; it need not cover every low bit.
    let full = DecompositionConfig {
        log_basis: if Word::BITS == 32 {
            DecompositionBaseLog::new(2)
        } else {
            DecompositionBaseLog::new(8)
        },
        level_count: None,
    };

    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParametersInner::new(
            LweDimension::new(800),
            modulus,
            SecretKeyDistr::UniformBinary,
            q * 2.046151696979124e-6,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: full,
        key_switching: full,
        pbs_order: ORDER,
    })
    .unwrap()
}

// CBS emits a gadget ciphertext; its output basis is separate from the two evaluation-key bases.
fn circuit_config() -> CircuitBootstrapConfig {
    let internal = DecompositionConfig {
        log_basis: if Word::BITS == 32 {
            DecompositionBaseLog::new(2)
        } else {
            DecompositionBaseLog::new(8)
        },
        level_count: None,
    };
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if Word::BITS == 32 {
                DecompositionBaseLog::new(3)
            } else {
                DecompositionBaseLog::new(8)
            },
            level_count: Some(if Word::BITS == 32 {
                DecompositionLevelCount::new(3)
            } else {
                DecompositionLevelCount::new(2)
            }),
        },
        trace: internal,
        trace_noise_standard_deviation: 6.4,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 6.4,
    }
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table>::from_parameters(parameters);

    // Public message encoding is independent of the evaluation keys.
    let input_codec = RoundedCodec::new(4 as Word, context.parameters().cipher_modulus());

    // Client: generate BR and CBS material from the same accumulator secret.
    // BR→KS CBS needs no return key; KS→BR still needs the input KS key.
    let mut rng = StdRng::seed_from_u64(42);
    let client_key = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let blind_rotation = BootstrappingKey::Classic(
        generator
            .try_generate_bootstrapping_key(&client_key, &mut rng)
            .unwrap(),
    );
    let circuit_parameters =
        CircuitBootstrapParameters::try_from_config(context.parameters(), circuit_config())
            .unwrap();
    let circuit_key = generator
        .try_generate_circuit_bootstrap_key(
            client_key.glwe_secret_key(),
            circuit_parameters,
            &mut rng,
        )
        .unwrap();
    let input_key_switching = (ORDER == PbsOrder::KeyswitchBootstrap).then(|| {
        generator
            .try_generate_glwe_key_switching_key(&client_key, &mut rng)
            .unwrap()
    });
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let mut ring_client = context
        .accumulator_client(
            client_key.glwe_secret_key(),
            primus_encoding::ScaledCodec::new(
                input_codec.plaintext_modulus(),
                input_codec.ciphertext_modulus(),
            ),
        )
        .unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1 as Word; N];
    let rhs_message = vec![3 as Word; N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: receive BR/CBS material, optional input KS, and encrypted candidates.
    let mut resources = context
        .bootstrap_resources(&blind_rotation, input_key_switching.as_ref())
        .unwrap();
    let mut cbs = CircuitBootstrapEvaluator::try_new(
        &resources,
        circuit_key.parameters(),
        &circuit_key,
        &input_codec,
    )
    .unwrap();
    let mut control = cbs.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();

    for bit in [1 as Word, 0] {
        // Client -> server: send the encrypted selection bit.
        encryptor
            .encrypt_padded_to(bit, input.as_mut_view(), &mut rng)
            .unwrap();

        // Server: CBS produces a gadget control; CMux selects rhs for 1, lhs for 0.
        cbs.circuit_bootstrap_to(input.as_view(), &mut control, &mut resources);
        cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources);

        // Client: decrypt the returned ring ciphertext, reusing the decoding buffer.
        ring_client.decrypt_to(&selected, &mut decoded);
        let expected = if bit == 0 { &lhs_message } else { &rhs_message };
        assert_eq!(&decoded, expected);
        println!("bit {bit}: selected coefficients {}", decoded[0]);
    }
}
