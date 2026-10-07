//! Dense binary/ternary PBS. One iteration is one complete request.
//! LUTs, encryption, workspace/output allocation and validation are untimed.
//! Parameters: primus_tfhe_benchmarks::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt

use primus_tfhe::{PbsMessageConfig, RoundedPbsCodecs};
use std::hint::black_box;

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_benchmarks::measurement::{Case, Group, metadata};
use primus_tfhe_benchmarks::parameters::ntt_circuit_modulus;
use primus_tfhe_benchmarks::{
    benchmark::{PBS_WORKLOADS, PbsWorkload},
    parameters::glwe,
};
use primus_tfhe_glwe_ntt::{PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

// The ternary profile has its own decomposition/noise budget. Its timing must
// not be divided by the binary timing to claim a secret-distribution speedup.
fn pbs<T, Table>(
    c: &mut Group<'_>,
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
    let name = format!("{kind}/{}/{order:?}", workload.name);
    let parameters = if ternary {
        glwe::circuit(ntt_circuit_modulus::<T>(), order, secret)
    } else {
        glwe::ntt_pbs::<T>(order, workload)
    };
    let codecs = parameters
        .pbs_codecs(PbsMessageConfig::new(T::as_from(
            workload.plaintext_modulus,
        )))
        .unwrap();
    // Cached owned state avoids both eager setup during --list and repeated key
    // generation for each Criterion sample. Evaluators borrow this state locally.
    let fixture =
        std::cell::LazyCell::new(|| Fixture::<T, Table>::new(parameters, codecs, workload));
    let mut verified = false;
    let case = Case::new("glwe", backend, T::BITS, format!("{name}/complete"));
    c.bench_function(case.id(), |b| {
        let Fixture {
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
                    .decryptor(client.external_lwe_secret_key(), codecs.output_codec())
                    .unwrap()
                    .decrypt(output.as_view())
                    .unwrap(),
                T::ZERO
            );
            verified = true;
        }

        metadata::record("pbs", &case, || {
            serde_json::json!({
                "parameters": metadata::glwe(context.parameters()),
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
    use PbsOrder::{BootstrapKeyswitch, KeyswitchBootstrap};
    let [boolean, shortint] = PBS_WORKLOADS;
    pbs::<u32, U32NttTable>(c, "ntt", KeyswitchBootstrap, boolean, false);
    pbs::<u64, U64NttTable>(c, "ntt", KeyswitchBootstrap, shortint, false);
    pbs::<u64, U64NttTable>(c, "ntt", KeyswitchBootstrap, boolean, true);
    pbs::<u64, U64NttTable>(c, "ntt", BootstrapKeyswitch, shortint, false);
}

/// Owned keys and request data. Evaluators borrow this fixture and own their
/// scratch separately; constructing it is deferred until Criterion selects a case.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    context: TfheContext<T, Table>,
    client: primus_tfhe_glwe_ntt::ClientKey<T>,
    server: primus_tfhe_glwe_ntt::ServerKey<T>,
    input: primus_lwe::LweCiphertext<T>,
    lut: primus_tfhe::LookupTable<T>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Builds the fixed-seed request outside timing; key-generation order is
    /// preserved so the baseline keeps identical client and encryption randomness.
    fn new(
        parameters: primus_tfhe_glwe_ntt::TfheParameters<T>,
        codecs: RoundedPbsCodecs<T, primus_modulus::BarrettModulus<T>>,
        workload: PbsWorkload,
    ) -> Self {
        let context = TfheContext::<T, Table>::try_from_parameters(parameters).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
        let input = context
            .encryptor(client.external_lwe_secret_key(), codecs.input_codec())
            .unwrap()
            .encrypt_padded(T::ONE, &mut rng)
            .unwrap();
        let domain = workload.plaintext_modulus as usize / 2;
        let lut = context
            .parameters()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_fn(|x| T::as_from((x + domain - 1) % domain))
            .unwrap();
        Self {
            context,
            client,
            server,
            input,
            lut,
        }
    }
}
