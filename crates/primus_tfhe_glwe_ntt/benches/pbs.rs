//! Dense binary/ternary PBS. One iteration is one complete request.
//! LUTs, encryption, workspace/output allocation and validation are untimed.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_glwe_ntt --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{PbsOrder, TfheContext};
use primus_tfhe_test_support::parameters::ntt_circuit_modulus;
use primus_tfhe_test_support::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::glwe,
};
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn pbs<T, Table>(
    c: &mut Criterion,
    backend: &str,
    order: PbsOrder,
    workload: PbsWorkload,
    ternary: bool,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!(
        "glwe/{backend}/u{}/{kind}/{}/n{}_N{}/{order:?}",
        T::BITS,
        workload.name,
        workload.lwe_dimension,
        workload.poly_length
    );
    let parameters = if ternary {
        glwe::circuit(ntt_circuit_modulus::<T>(), order, secret)
    } else {
        glwe::ntt_pbs::<T>(order, workload)
    };
    let input_codec = primus_encoding::RoundedCodec::new(
        T::as_from(workload.plaintext_modulus),
        parameters.cipher_modulus(),
    );
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&format!("{name}/complete"), |b| {
        let (context, client, server, input, lut) = fixture.get_or_insert_with(|| {
            let context = TfheContext::<T, Table>::try_from_parameters(parameters.clone()).unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
            let input = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let domain = workload.plaintext_modulus as usize / 2;
            let lut = context
                .parameters()
                .lookup_table_compiler(&input_codec)
                .unwrap()
                .compile_fn(|x| T::as_from((x + domain - 1) % domain))
                .unwrap();
            (context, client, server, input, lut)
        });
        let mut evaluator = context.evaluator(server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        if !verified {
            evaluator.apply_lookup_table_to(input.as_view(), lut, output.as_mut_view());
            assert_eq!(
                context
                    .decryptor(client.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ZERO
            );
            verified = true;
        }
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input.as_view()),
                black_box(lut),
                black_box(output.as_mut_view()),
            )
        });
    });
}

fn bench_pbs(c: &mut Criterion) {
    use PbsOrder::{BootstrapKeyswitch, KeyswitchBootstrap};
    let [boolean, shortint] = PBS_WORKLOADS;
    pbs::<u32, U32NttTable>(c, "ntt", KeyswitchBootstrap, boolean, false);
    pbs::<u64, U64NttTable>(c, "ntt", KeyswitchBootstrap, shortint, false);
    pbs::<u64, U64NttTable>(c, "ntt", KeyswitchBootstrap, boolean, true);
    pbs::<u64, U64NttTable>(c, "ntt", BootstrapKeyswitch, shortint, false);
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
