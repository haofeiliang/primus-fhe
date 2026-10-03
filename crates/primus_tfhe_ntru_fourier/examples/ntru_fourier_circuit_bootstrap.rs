//! Use an encrypted LWE bit to select between two encrypted ring messages via CBS and CMux.
//!
//! Run: `cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap`
//! For u64, change Word to u64; for TFHE-FFT, use TfheFftTable as Table.
//! Arithmetic profiles: guides/development/tfhe-parameters.md (not security presets).

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_fft::RustFftTable as Table;
use primus_lattice::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters,
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// The explicit parameters below select bases and moduli for this coefficient word.
type Word = u32;
const N: usize = 1024;

// Key parameters: n=800, N=1024; independent external LWE q=2^24.
// Noise sigmas below are in coefficient units; these are arithmetic examples, not security presets.
fn parameters() -> TfheParameters<Word, PowOf2Modulus<Word>> {
    let modulus = NativeModulus::<Word>::new();
    let lwe_modulus: Word = 1 << 24;

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
        external_lwe: LweParametersInner::new(
            LweDimension::new(800),
            PowOf2Modulus::new(lwe_modulus),
            SecretKeyDistr::UniformBinary,
            lwe_modulus as f64 * 2.046151696979124e-6,
        ),
        accumulator_modulus: modulus, // Ring Q; distinct from the external LWE q.
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full,
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 3.2, // Return key switch in the q domain.
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
                DecompositionLevelCount::new(4)
            } else {
                DecompositionLevelCount::new(3)
            }),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

fn main() {
    let parameters = parameters();
    let context = TfheContext::<Word, Table, _>::from_parameters(parameters);
    // Public message encoding at external q, chosen independently of key generation.
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());

    // Client: generate BR and CBS material; this ring-output workflow needs no return key.
    let mut rng = StdRng::seed_from_u64(42);
    let mut generator = KeyGenerator::new(&context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    let blind_rotation_key = generator
        .try_generate_blind_rotation_key(&client_key, &mut rng)
        .unwrap();
    let circuit_parameters =
        CircuitBootstrapParameters::try_from_config(context.parameters(), circuit_config())
            .unwrap();
    let circuit_key = generator
        .try_generate_circuit_bootstrap_key(
            client_key.accumulator_ntru_secret_key(),
            circuit_parameters,
            &mut rng,
        )
        .unwrap();
    // Ordinary messages borrow only the external secret from the setup bundle.
    let external_secret = client_key.external_lwe_secret_key();
    let encryptor = context.encryptor(external_secret, &input_codec).unwrap();
    let ring_codec = ScaledCodec::new(
        input_codec.plaintext_modulus(),
        context.parameters().accumulator_ntru().cipher_modulus(),
    );
    let mut ring_client = context
        .accumulator_client(client_key.accumulator_ntru_secret_key(), ring_codec)
        .unwrap();
    // Encrypt both candidates with the accumulator secret used by the CBS output.
    let lhs_message = vec![1 as Word; N];
    let rhs_message = vec![3 as Word; N];
    let lhs = ring_client.encrypt(&lhs_message, &mut rng);
    let rhs = ring_client.encrypt(&rhs_message, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let mut decoded = vec![0; N];

    // Server: receive the encrypted candidates; allocate the control and result.
    let mut resources = context.bootstrap_resources(&blind_rotation_key).unwrap();
    let mut cbs =
        CircuitBootstrapEvaluator::try_new(&resources, &circuit_key, &input_codec).unwrap();
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
