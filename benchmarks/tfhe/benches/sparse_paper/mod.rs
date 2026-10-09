//! Paper-shaped GLWE NTT comparison using only existing public kernels.
//! Run only complete requests with:
//! `cargo bench -p primus_tfhe_benchmarks --bench sparse_paper --features glwe-ntt -- '/complete_ring_return/'`
//! `blind_rotation` excludes gate preprocessing, input lifting and return.
//! `complete_ring_return` includes them, using Primus's ring KS at Q, not the
//! cited OpenFHE's sampled LWE key switch at Q'. NAND and padded-function IDs
//! distinguish one-PBS workloads from OpenFHE's full-domain arbitrary functions.
//! `sparse_candidate_r2` separately changes copies/buckets and retained BR levels;
//! it is a consumer-validated arithmetic profile, not the paper configuration.

mod parameters;
mod request;

use std::hint::black_box;

use criterion::Bencher;
use primus_glwe::GlweCiphertext;
use primus_integer::FheUint;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_benchmarks::measurement::{Case as BenchmarkCase, Group, metadata};
use primus_tfhe_glwe_ntt::{
    BlindRotationKey, BlindRotationMethod, ClientKey, KeyGenerator, NttGlweBlindRotationWorkspace,
    ServerKey, SparseGlweBlindRotationWorkspace, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use parameters::{CASES, Case, Mode};
use request::Request;

/// Both words use the identical 28-bit prime; a 54-bit ring requires u64.
pub(super) fn benchmark(c: &mut Group<'_>) {
    for case in CASES {
        for mode in [
            Mode::DenseClassic,
            Mode::FixedWeightClassic,
            Mode::Sparse,
            Mode::SparseCandidate,
        ] {
            if matches!(mode, Mode::SparseCandidate) && case.candidate_br_levels.is_none() {
                continue;
            }
            if case.ring_modulus <= u64::from(u32::MAX) {
                benchmark_case::<u32, U32NttTable>(c, case, mode);
            }
            benchmark_case::<u64, U64NttTable>(c, case, mode);
        }
    }
}

/// Owned server resources and one request, cached across Criterion samples.
/// Client secrets are needed only for setup validation and are dropped afterward.
struct Fixture<T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    parameters: primus_tfhe_glwe_ntt::PbsParameters<T>,
    context: TfheContext<T, Table>,
    server: ServerKey<T>,
    request: Request<T>,
}

impl<T: FheUint, Table: MonomialNttTable<ValueT = T>> Fixture<T, Table> {
    /// Fixed-weight classic/sparse use identical client/input seeds. Keygen has
    /// its own RNG; a failed sparse map retries without replacing the secret.
    fn new(case: Case, mode: Mode, name: &str) -> Self {
        let parameters = case.parameters(mode);
        let context_parameters = &parameters;
        let context =
            TfheContext::<T, Table>::try_from_parameters(context_parameters.clone()).unwrap();
        let client = ClientKey::generate(context.parameters(), &mut StdRng::seed_from_u64(42));
        let choice = match mode.sparse_counts(case) {
            Some((copy_count, bucket_count)) => BlindRotationMethod::Sparse {
                copy_count,
                bucket_count,
            },
            None => BlindRotationMethod::Classic,
        };
        let server = KeyGenerator::new(&context)
            .try_generate_server_key_with_parameters(
                context_parameters.glwe_key_switching(),
                &client,
                choice,
                &mut StdRng::seed_from_u64(4242),
            )
            .unwrap();
        let mut request = Request::new(&context, case);
        request.validate(
            &mut context.evaluator(&server).unwrap(),
            &client,
            case,
            mode,
            name,
        );
        Self {
            parameters,
            context,
            server,
            request,
        }
    }
}

/// Lazy construction keeps --list and filtered-out IDs free of large keys.
/// Complete requests and raw BR share the same verified input, LUT and key.
fn benchmark_case<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Group<'_>,
    case: Case,
    mode: Mode,
) {
    let name = format!("{}/{}", case.name, mode.name());
    let mut fixture = None;

    for stage in ["complete_ring_return", "blind_rotation"] {
        let benchmark = BenchmarkCase::new("glwe", "ntt", T::BITS, format!("{name}/{stage}"));
        c.bench_function(benchmark.id(), |b| {
            let Fixture {
            parameters,
                context,
                server,
                request,
            } = fixture.get_or_insert_with(|| Fixture::<T, Table>::new(case, mode, &name));
            metadata::record("sparse_paper", &benchmark, || serde_json::json!({
                "parameters": metadata::glwe(parameters), "small_q": case.lwe_modulus,
                "small_q_sigma": 3.19, "plaintext_modulus": case.plaintext_modulus,
                "copy_bucket_counts": mode.sparse_counts(case), "stage": stage, "outputs": 1,
                "adaptation": "q -> Q -> ring KS at Q -> extraction -> q; not OpenFHE LWE KS at Qprime"
            }));
            if stage == "complete_ring_return" {
                let mut evaluator = context.evaluator(server).unwrap();
                b.iter(|| black_box(&mut *request).evaluate(&mut evaluator));
            } else {
                benchmark_blind_rotation(b, context, server, request);
            }
        });
    }
}

/// Time one raw BR, choosing its public kernel before entering the timer.
/// Lifting and accumulator/workspace allocation belong to untimed setup.
fn benchmark_blind_rotation<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    b: &mut Bencher,
    context: &TfheContext<T, Table>,
    server: &ServerKey<T>,
    request: &mut Request<T>,
) {
    request.lift_input();
    let modulus = context.parameters().cipher_modulus();
    let mut accumulator: GlweCiphertext<Vec<T>> =
        GlweCiphertext::zero(context.parameters().blind_rotation_params().glwe_len());
    match server.blind_rotation_key() {
        BlindRotationKey::Classic(key) => {
            let mut workspace = NttGlweBlindRotationWorkspace::new(key);
            b.iter(|| {
                key.ntt_blind_rotate_lookup_table_to(
                    black_box(&request.lifted),
                    black_box(request.lut.polynomial()),
                    black_box(&mut accumulator),
                    modulus,
                    context.table(),
                    &mut workspace,
                );
            });
        }
        BlindRotationKey::Sparse(key) => {
            let mut workspace = SparseGlweBlindRotationWorkspace::new(key);
            b.iter(|| {
                workspace.blind_rotate_lookup_table_to(
                    key,
                    black_box(&request.lifted),
                    black_box(request.lut.polynomial()),
                    black_box(&mut accumulator),
                    context.table(),
                );
            });
        }
    }
}
