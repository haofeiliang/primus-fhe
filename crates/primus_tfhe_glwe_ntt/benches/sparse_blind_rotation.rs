//! Raw sparse/classic blind rotation with the same fixed-weight client secret.
//! Experimental P3 profiles: n/h/N = 16/4/256 and 512/32/1024, c=3, buckets=2h.
//! Keys, LUT, four encrypted inputs, output and scratch are prepared outside timing.
//! Each iteration processes one input; this excludes key switching and extraction.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench sparse_blind_rotation

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_glwe::{GlweParameters, NttGadgetEncryptContext, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::glwe::Glwe;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::Polynomial;
use primus_tfhe_glwe_ntt::{
    KeyGenerator, NttGlweBlindRotationContext, NttGlweBootstrappingKey, PbsOrder,
    SparseGlweBlindRotationContext, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const Q: u32 = 132_120_577;

fn bench_profile(c: &mut Criterion, input_dimension: usize, weight: usize, poly_length: usize) {
    let small = input_dimension == 16;
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(
        input_dimension,
        8,
        modulus,
        SecretKeyDistr::fixed_hamming_weight_binary(input_dimension, weight),
        if small {
            0.7
        } else {
            3.2 * f64::from(Q) / 16384.0
        },
    );
    let glwe = GlweParameters::new(
        1,
        poly_length,
        8,
        modulus,
        if small {
            SecretKeyDistr::UniformBinary
        } else {
            SecretKeyDistr::SparseTernary
        },
        if small { 0.7 } else { 6.4 },
    );
    let (br_basis, ks_basis) = if small {
        let basis = ApproxSignedBasis::new(Some(Q), 9, None);
        (basis.clone(), basis)
    } else {
        (
            ApproxSignedBasis::new(Some(Q), 7, Some(3)),
            ApproxSignedBasis::new(Some(Q), 2, Some(13)),
        )
    };
    let parameters =
        TfheParameters::try_new(lwe, glwe, br_basis, ks_basis, PbsOrder::BootstrapKeyswitch)
            .unwrap();
    let ntt = U32NttTable::new(poly_length.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, ntt).unwrap();
    let parameters = context.parameters();
    let ntt = context.table();
    let mut rng = StdRng::seed_from_u64(0x5034_4252 + input_dimension as u64);
    let mut generator = KeyGenerator::new(&context);
    let client = generator.generate_client_key(&mut rng);
    let sparse = generator
        .try_generate_sparse_bootstrapping_key(&client, 3, 2 * weight, &mut rng)
        .unwrap();
    let output_key = NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), ntt);
    let size = sparse.size();
    let classic = NttGlweBootstrappingKey::generate_ntt(
        client.small_lwe_secret_key(),
        parameters.small_lwe(),
        &output_key,
        parameters.bootstrapping(),
        ntt,
        &mut rng,
        &mut NttGadgetEncryptContext::new(size),
    );
    let inputs: Vec<_> = (0..4)
        .map(|m| {
            client
                .small_lwe_secret_key()
                .encrypt(m, parameters.small_lwe(), &mut rng)
        })
        .collect();
    let codec = RoundedCodec::new(8, modulus);
    let lut = context
        .compile_lookup_table_fn(&codec, |m| (3 * m as u32 + 1) % 8)
        .unwrap();
    let mut output = Glwe::<Vec<u32>>::zero(size.glwe_len());
    let mut sparse_scratch = SparseGlweBlindRotationContext::new(&sparse);
    let mut classic_scratch = NttGlweBlindRotationContext::new(size);
    // Check the benchmark's actual encrypted inputs, including the cost profile.
    for (message, input) in inputs.iter().enumerate() {
        for is_sparse in [false, true] {
            if is_sparse {
                sparse.ntt_blind_rotate_lookup_table_to(
                    input,
                    lut.polynomial(),
                    &mut output,
                    ntt,
                    &mut sparse_scratch,
                );
            } else {
                classic.ntt_blind_rotate_lookup_table_to(
                    input,
                    lut.polynomial(),
                    &mut output,
                    modulus,
                    ntt,
                    &mut classic_scratch,
                );
            }
            let mut phase = Polynomial::<Vec<u32>>::zero(poly_length);
            output_key.phase_to(&output.clone().into_ntt_form(ntt), &mut phase, modulus, ntt);
            assert_eq!(
                codec.decode_value(phase.as_ref()[0]),
                (3 * message as u32 + 1) % 8
            );
        }
    }
    let mut group = c.benchmark_group(format!(
        "sparse_br/u32/n{input_dimension}/h{weight}/N{poly_length}"
    ));
    group.sample_size(30);
    for is_sparse in [false, true] {
        let name = if is_sparse { "sparse" } else { "classic" };
        let mut next_input = 0;
        group.bench_function(name, |b| {
            b.iter(|| {
                let input = black_box(&inputs[next_input]);
                next_input = (next_input + 1) % inputs.len();
                if is_sparse {
                    black_box(&sparse).ntt_blind_rotate_lookup_table_to(
                        input,
                        black_box(lut.polynomial()),
                        &mut output,
                        ntt,
                        &mut sparse_scratch,
                    );
                } else {
                    black_box(&classic).ntt_blind_rotate_lookup_table_to(
                        input,
                        black_box(lut.polynomial()),
                        &mut output,
                        modulus,
                        ntt,
                        &mut classic_scratch,
                    );
                }
                black_box(&output);
            })
        });
    }
    group.finish();
}

fn bench_sparse(c: &mut Criterion) {
    for (n, h, poly_length) in [(16, 4, 256), (512, 32, 1024)] {
        bench_profile(c, n, h, poly_length);
    }
}
criterion_group!(benches, bench_sparse);
criterion_main!(benches);
