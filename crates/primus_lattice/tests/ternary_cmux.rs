use primus_decompose::primitive::ApproxSignedBasis;
use primus_lattice::{
    GadgetSize, GlweSize, context::NttGlweTernaryCmuxContext, ggsw::Ggsw, glwe::Glwe,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

const N: usize = 16;
const Q: u32 = 132_120_577;

// Independent signed-index oracle, applied to every GLWE component.
fn rotate(input: &[u32], exponent: isize) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    for (input, output) in input
        .as_chunks::<N>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<N>().0)
    {
        for (i, &value) in input.iter().enumerate() {
            let position = (i as isize + exponent).rem_euclid(2 * N as isize) as usize;
            output[position % N] = if position < N || value == 0 {
                value
            } else {
                Q - value
            };
        }
    }
    output
}

#[test]
fn ternary_rotation_matches_negacyclic_oracle_with_bounded_decomposition_error() {
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let glwe_size = GlweSize::new(2, N);
    let input = Glwe::new(
        (0..glwe_size.glwe_len())
            .map(|i| ((i as u64 * 0x9e37_79b9 + 1) % u64::from(Q)) as u32)
            .collect::<Vec<_>>(),
    );
    // Two truncation depths protect the residual on (X^a-1)C. With noiseless
    // diagonal controls each output coefficient has at most one such residual.
    for levels in [3, 2] {
        let basis = ApproxSignedBasis::new(Some(Q), 8, Some(levels));
        let size = GadgetSize::new(glwe_size, levels);
        let mut one = Ggsw::zero(size.ggsw_len());
        for row in 0..glwe_size.component_count() {
            for (level, scalar) in basis.scalar_iter().enumerate() {
                one.as_mut()[(row * levels + level) * glwe_size.glwe_len() + row * N] = scalar;
            }
        }
        let one = one.into_ntt_form(&ntt);
        let zero = Ggsw::new(vec![0u32; size.ggsw_len()]).into_ntt_form(&ntt);
        let mut context = NttGlweTernaryCmuxContext::new(size);
        let mut output = Glwe::new(vec![Q - 1; glwe_size.glwe_len()]);
        // Reuse dirty output/scratch across signs and wrap back to exponent zero.
        for secret in [1, -1, 0] {
            let positive = if secret == 1 { &one } else { &zero };
            let negative = if secret == -1 { &one } else { &zero };
            for exponent in (1..2 * N).chain([0]) {
                positive.cmux_ternary_monomial_to(
                    negative,
                    &input,
                    exponent,
                    &mut output,
                    &basis,
                    modulus,
                    &ntt,
                    &mut context,
                );
                let expected = rotate(input.as_ref(), exponent as isize * secret);
                let bound = if secret == 0 || exponent == 0 {
                    0
                } else {
                    basis.approximate_error_bound()
                };
                for (&actual, expected) in output.as_ref().iter().zip(expected) {
                    assert!(actual < Q);
                    let distance = actual.abs_diff(expected);
                    assert!(
                        distance.min(Q - distance) <= bound,
                        "s={secret}, exponent={exponent}, levels={levels}: {actual} != {expected}"
                    );
                }
            }
        }
    }
}
