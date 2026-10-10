//! Exercise complete lookup through public keygen, integer clients and evaluate_to.
//! Small parameters isolate functional regressions, not security or failure rates.
#![cfg(feature = "ntt")]

use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{LweDimension, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::PolyLength;
use primus_tfhe::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionBaseLog, DecompositionConfig,
    DecompositionLevelCount, GadgetEncryptionConfig, LweConfig, ModulusConfig, PbsMessageConfig,
};
use primus_tfhe_ntru::{CbsConfig, PbsConfig};
use primus_tfhe_ntru_lut::{HighPrecLutConfig, NttHighPrecLutContext};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const SPARSE: BlindRotationMethod = BlindRotationMethod::Sparse {
    copy_count: 3,
    bucket_count: 8,
};

/// M=4, W=4 fit the one-hot guard in N=128. Return keys use independent q=2^24.
fn config<T: FheUint>(
    method: BlindRotationMethod,
    c: usize,
    d: usize,
    outputs: usize,
) -> HighPrecLutConfig<T, BarrettModulus<T>, PowOf2Modulus<T>> {
    let decomposition = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    };
    HighPrecLutConfig {
        one_hot: CbsConfig {
            pbs: PbsConfig {
                external_lwe: LweConfig {
                    dimension: LweDimension::new(8),
                    cipher_modulus: ModulusConfig::Explicit(T::as_from(1u32 << 24)),
                    secret_key_distr: SecretKeyDistr::FixedHammingWeightBinary {
                        hamming_weight: 2,
                    },
                    noise_standard_deviation: 1.0,
                },
                acc_modulus: ModulusConfig::Explicit(T::as_from(if T::BITS == 32 {
                    998_244_353u64
                } else {
                    1_125_899_906_826_241u64
                })),
                bsk_poly_length: PolyLength::new(128),
                bsk_secret_distr: SecretKeyDistr::SparseTernary,
                bsk_gadget: GadgetEncryptionConfig {
                    decomposition,
                    noise_standard_deviation: 0.7,
                },
                key_switching: GadgetEncryptionConfig {
                    decomposition,
                    noise_standard_deviation: 1.0,
                },
                algorithm: method,
                messages: PbsMessageConfig::new(T::as_from(8)),
            },
            gadget: CbsGadgetConfig {
                trace: decomposition,
                scheme_switch: decomposition,
                output: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(4),
                    level_count: Some(DecompositionLevelCount::new(3)),
                },
            },
        },
        input_chunk_count: c,
        coefficient_chunk_count: Some(d),
        output_chunk_count: outputs,
    }
}

/// Random, constant and repeated-output functions all use the same complete tree.
/// Expected values come from the plaintext mapping, never from compiled coefficients.
fn complete_lookup<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    method: BlindRotationMethod,
    c: usize,
    d: usize,
    outputs: usize,
) {
    let context =
        NttHighPrecLutContext::<T, Table, _>::try_from_config(config(method, c, d, outputs))
            .unwrap();
    // Client: separate the key/input seed from the public function's seed.
    let mut rng = StdRng::seed_from_u64(201);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let mut input = encryptor.allocate_input();

    let count = 1usize << context.input_bits();
    let output_limit = 1u64 << context.output_bits();
    let mut table_rng = StdRng::seed_from_u64(202);
    let random: Vec<u64> = (0..count)
        .map(|_| table_rng.random_range(0..output_limit))
        .collect();
    let repeated: Vec<u64> = (0..count)
        .map(|x| (0..outputs).map(|j| ((x % 4) as u64) << (2 * j)).sum())
        .collect();
    let constant = vec![output_limit - 1; count];
    for (kind, values) in [random, constant, repeated].into_iter().enumerate() {
        // Server: every logical prefix is stored/evaluated, even when values repeat.
        let table = context.compile_fn(|x: u64| values[x as usize]).unwrap();
        let mut evaluator = context.evaluator(&server, &table).unwrap();
        let mut output = evaluator.allocate_output();
        for x in [0, 1, 3, 4, 15, 16, 42, 63, 0]
            .into_iter()
            .filter(|&x| x < count)
        {
            encryptor
                .encrypt_to(x as u64, &mut input, &mut rng)
                .unwrap();
            evaluator.evaluate_to(&input, &mut output);
            assert_eq!(
                decryptor.decrypt::<u64>(&output).unwrap(),
                values[x],
                "{method:?}, c{c}/d{d}/o{outputs}, kind{kind}, input{x}"
            );
        }
    }
}

#[test]
fn classic_full_tree_u32() {
    complete_lookup::<u32, U32NttTable>(BlindRotationMethod::Classic, 3, 1, 2);
}

#[test]
fn sparse_no_rotation_u64() {
    complete_lookup::<u64, U64NttTable>(SPARSE, 3, 0, 3);
}

#[test]
fn classic_lift_u32() {
    complete_lookup::<u32, U32NttTable>(BlindRotationMethod::Classic, 2, 2, 1);
}

#[test]
fn sparse_independent_lift_u64() {
    complete_lookup::<u64, U64NttTable>(SPARSE, 2, 2, 2);
}
