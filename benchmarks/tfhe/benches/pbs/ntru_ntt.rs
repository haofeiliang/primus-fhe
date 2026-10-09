//! Dense binary/ternary PBS. One iteration is one complete request.
//! LUTs, encryption, workspace/output allocation and validation are untimed.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench pbs --features ntru-ntt

use primus_tfhe::PbsMessageConfig;
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use std::hint::black_box;

use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_benchmarks::parameters::ntt_modulus;
use primus_tfhe_benchmarks::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::ntru,
};
use primus_tfhe_ntru_ntt::TfheContext;
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn pbs<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    backend: &str,
    workload: PbsWorkload,
    ternary: bool,
) {
    let secret = if ternary {
        SecretKeyDistr::UniformTernary
    } else {
        SecretKeyDistr::UniformBinary
    };
    let kind = if ternary { "ternary" } else { "binary" };
    let name = format!("{kind}/{}", workload.name);
    let parameters = ntru::pbs(ntt_modulus::<T>(), workload, secret);
    let parameters = parameters.with_messages(PbsMessageConfig::new(T::as_from(
        workload.plaintext_modulus,
    )));
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let fixture = std::cell::LazyCell::new(|| Fixture::<T, Table>::new(parameters, workload));
    let mut verified = false;
    let case = Case::new("ntru", backend, T::BITS, format!("{name}/complete"));
    c.bench_function(case.id(), |b| {
        let Fixture {
            parameters,
            context,
            client,
            server,
            input,
            lut,
        } = &*fixture;
        let mut evaluator = context.evaluator(server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        if !verified {
            evaluator.apply_lookup_table_to(input.as_view(), lut, output.as_mut_view());
            assert_eq!(
                context
                    .pbs_decryptor(client.external_lwe_secret_key())
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ZERO
            );
            verified = true;
        }

        metadata::record("pbs", &case, || {
            serde_json::json!({
                "parameters": metadata::ntru(parameters),
                "blind_rotation": metadata::blind_rotation(false),
                "plaintext_modulus": workload.plaintext_modulus,
                "encoding": "rounded_padded",
                "outputs": 1,
                "function": "(m + domain - 1) % domain",
            })
        });
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(input.as_view()),
                black_box(lut),
                black_box(output.as_mut_view()),
            )
        });
    });
}

pub fn bench_pbs(c: &mut Group<'_>) {
    let [boolean, shortint] = PBS_WORKLOADS;
    pbs::<u32, U32NttTable>(c, "ntt", boolean, false);
    pbs::<u64, U64NttTable>(c, "ntt", shortint, false);
    pbs::<u64, U64NttTable>(c, "ntt", boolean, true);
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    parameters: primus_tfhe_ntru_ntt::PbsParameters<T, PowOf2Modulus<T>>,
    context: TfheContext<T, Table, PowOf2Modulus<T>>,
    client: primus_tfhe_ntru_ntt::ClientKey<T>,
    server: primus_tfhe_ntru_ntt::ServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lut: primus_tfhe::LookupTable<T>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_ntru_ntt::PbsParameters<T, PowOf2Modulus<T>>,
        workload: PbsWorkload,
    ) -> Self {
        let context_parameters = &parameters;
        let context = TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
            context_parameters.clone(),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(&mut rng).unwrap();
        let input = context
            .encryptor(client.external_lwe_secret_key())
            .unwrap()
            .encrypt_padded(T::ONE, &mut rng)
            .unwrap();
        let domain = workload.plaintext_modulus as usize / 2;
        let lut = context
            .pbs_lookup_table_compiler()
            .unwrap()
            .compile_fn(|x| T::as_from((x + domain - 1) % domain))
            .unwrap();
        Self {
            parameters,
            context,
            client,
            server,
            input,
            lut,
        }
    }
}
