//! One complete CBS into a reused gadget ciphertext; NTRU also measures full
//! and nonzero one-hot batches. Keygen, encryption, allocation and the CMux
//! correctness probe are outside timing. Ordinary CBS uses t4; one-hot uses t8.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_lattice::ngsw::NttNgswIter;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapEvaluator, OneHotCircuitBootstrapEvaluator, TfheContext,
};
use primus_tfhe_test_support::parameters::ntt_circuit_modulus;
use primus_tfhe_test_support::parameters::{N, ntru};
use rand::{SeedableRng, rngs::StdRng};

// CBS consumes a bit and emits a gadget control, not an LWE result. Verify
// that representation by selecting an encrypted ring message before timing.
fn ordinary<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    let kind = "classic";
    let dimension = 800;
    let parameters = ntru::circuit(ntt_circuit_modulus::<T>(), 4, SecretKeyDistr::UniformBinary);
    let name = format!(
        "ntru/{backend}/u{}/cbs/{kind}/n{dimension}_N1024/complete",
        T::BITS
    );
    let mut fixture = None;
    let mut verified = false;
    c.bench_function(&name, |b| {
        let (context, client, server, input, lhs, rhs) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters.clone())
                    .unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let (client, server) = context
                .try_generate_keys(Some(ntru::cbs::<T>()), &mut rng)
                .unwrap();
            let input = context
                .encryptor(&client)
                .unwrap()
                .encrypt_padded(T::ONE, &mut rng)
                .unwrap();
            let mut ring = context.accumulator_client(&client).unwrap();
            let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
            let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
            (context, client, server, input, lhs, rhs)
        });
        let mut evaluator = CircuitBootstrapEvaluator::try_new(context, server).unwrap();
        let mut output = evaluator.allocate_output();
        if !verified {
            evaluator.circuit_bootstrap_to(input, &mut output);
            let mut selected = context.allocate_accumulator_ciphertext();
            evaluator.cmux_to(&output, lhs, rhs, &mut selected);
            let mut decoded = vec![T::ZERO; N];
            context
                .accumulator_client(client)
                .unwrap()
                .decrypt_to(&selected, &mut decoded);
            assert!(decoded.iter().all(|&value| value == T::ONE));
            verified = true;
        }
        b.iter(|| evaluator.circuit_bootstrap_to(black_box(input), black_box(&mut output)));
    });
}

// The compact batch omits delta_0. Compare equal input geometry to isolate the
// saved selector work; one iteration produces M or M-1 complete NGSW controls.
fn one_hot<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    let mut fixture = None;
    for compact in [false, true] {
        let kind = if compact { "nonzero" } else { "full" };
        let mut verified = false;
        let name = format!("ntru/{backend}/u{}/one_hot/n800_N1024/M4/{kind}", T::BITS);
        c.bench_function(&name, |b| {
            let (context, client, server, input, lhs, rhs) = fixture.get_or_insert_with(|| {
                let parameters =
                    ntru::circuit(ntt_circuit_modulus::<T>(), 8, SecretKeyDistr::UniformBinary);
                let context =
                    TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters)
                        .unwrap();
                let mut rng = StdRng::seed_from_u64(42);
                let (client, server) = context
                    .try_generate_keys(Some(ntru::cbs::<T>()), &mut rng)
                    .unwrap();
                let input = context
                    .encryptor(&client)
                    .unwrap()
                    .encrypt_padded(T::TWO, &mut rng)
                    .unwrap();
                let mut ring = context.accumulator_client(&client).unwrap();
                let lhs = ring.encrypt(&[T::ZERO; N], &mut rng);
                let rhs = ring.encrypt(&[T::ONE; N], &mut rng);
                (context, client, server, input, lhs, rhs)
            });
            let mut evaluator = OneHotCircuitBootstrapEvaluator::try_new(context, server).unwrap();
            let mut output = if compact {
                evaluator.allocate_nonzero_ngsw_output()
            } else {
                evaluator.allocate_ngsw_output()
            };
            if !verified {
                if compact {
                    evaluator.one_hot_nonzero_ngsw_to(input, &mut output);
                } else {
                    evaluator.one_hot_ngsw_to(input, &mut output);
                }
                let parameters = evaluator.parameters();
                let mut selected = context.allocate_accumulator_ciphertext();
                let mut decoded = vec![T::ZERO; N];
                let mut ring = context.accumulator_client(client).unwrap();
                // Semantic ciphertext iteration keeps selector boundaries tied
                // to the public CBS layout, including compact index r-1.
                for (index, control) in
                    NttNgswIter::new(&output, parameters.output_nlev_len()).enumerate()
                {
                    control.cmux_to(
                        lhs,
                        rhs,
                        &mut selected,
                        parameters.output_basis(),
                        context.parameters().accumulator_ntru().cipher_modulus(),
                        context.table(),
                        evaluator.external_product_workspace(),
                    );
                    ring.decrypt_to(&selected, &mut decoded);
                    let expected = if index + usize::from(compact) == 2 {
                        T::ONE
                    } else {
                        T::ZERO
                    };
                    assert!(decoded.iter().all(|&value| value == expected));
                }
                verified = true;
            }
            if compact {
                b.iter(|| {
                    evaluator.one_hot_nonzero_ngsw_to(black_box(input), black_box(&mut output))
                });
            } else {
                b.iter(|| evaluator.one_hot_ngsw_to(black_box(input), black_box(&mut output)));
            }
        });
    }
}

fn bench_cbs(c: &mut Criterion) {
    ordinary::<u32, U32NttTable>(c, "ntt");
    ordinary::<u64, U64NttTable>(c, "ntt");
    one_hot::<u32, U32NttTable>(c, "ntt");
    one_hot::<u64, U64NttTable>(c, "ntt");
}

criterion_group!(benches, bench_cbs);
criterion_main!(benches);
