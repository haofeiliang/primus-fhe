//! Bucket aggregation and reusable sparse blind-rotation workspace.

use super::SparseNtruBootstrappingKey;
use crate::PbsParameters;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{Nlev, NlevIter},
    ntru::Ntru,
};
use primus_modulus::BarrettModulus;
use primus_ntru::NttNtruExternalProductWorkspace;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceOnceSlice;

pub(crate) struct SparseWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductWorkspace<T>,
}

impl<T: FheUint> SparseWorkspace<T> {
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &PbsParameters<T, LM>,
    ) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension().get()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            external_product: NttNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// Additional state for a second sparse blind-rotation input.
/// Allocate through [`crate::OneHotCircuitBootstrapEvaluator::new_sparse_pair_workspace`].
/// Retains only exponents, an L*N coefficient aggregate and one N-coefficient
/// accumulator; the original resources provide shared transform/product scratch.
pub struct SparseBlindRotationPairWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    pub(crate) aggregate: Vec<T>,
    pub(crate) current: Ntru<Vec<T>>,
}

impl<T: FheUint> SparseBlindRotationPairWorkspace<T> {
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &PbsParameters<T, LM>,
    ) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension().get()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            current: Ntru::zero(parameters.poly_length().get()),
        }
    }
}

/// The evaluator established key/workspace/table compatibility and quantized every mask.
/// Every bucket is processed, including empty ones and zero exponents; its encrypted
/// dummy and zero selections still contribute noise. `scratch` initially holds the
/// public rotated LUT. Bucket zero lifts it with NLEV controls; later buckets use
/// NGSW controls. Final output stays in `current`, even with just one bucket.
pub(crate) fn rotate_buckets<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut SparseWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    let n = ntt.poly_length().get();
    // Start with public P in current. Bucket 0 uses NLEV[H_0] to lift P;
    // buckets >= 1 actually hold NGSW[H_j] = NLEV[f*H_j] and act on ciphertexts.
    // NLEV and NGSW external products have identical arithmetic, so all buckets
    // share this NLEV product call without a first-bucket branch.
    core::mem::swap(current, scratch);
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        aggregate_bucket(
            indices,
            data,
            [(
                &workspace.exponents,
                Nlev::new(workspace.aggregate.as_mut_slice()),
            )],
            n,
            modulus,
        );
        let aggregate = Nlev::new(workspace.aggregate.as_mut_slice()).into_ntt_form(ntt);
        aggregate.external_product_to(
            &Polynomial(current.as_ref()),
            scratch,
            basis,
            modulus,
            ntt,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}

/// Both current buffers hold their independently rotated public LUT on entry.
/// Each source-control group is consumed for both inputs before advancing;
/// transforms and external products then reuse the original shared scratch.
pub(crate) fn rotate_buckets_pair<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut SparseWorkspace<T>,
    second: &mut SparseBlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    let [current, scratch] = buffers;
    let n = ntt.poly_length().get();
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        aggregate_bucket(
            indices,
            data,
            [
                (
                    &workspace.exponents,
                    Nlev::new(workspace.aggregate.as_mut_slice()),
                ),
                (
                    &second.exponents,
                    Nlev::new(second.aggregate.as_mut_slice()),
                ),
            ],
            n,
            modulus,
        );
        // Bucket zero lifts both public LUTs with NLEV. Later NGSW controls
        // use the same external-product arithmetic, preserving every bucket.
        for (aggregate, current) in [
            (&mut workspace.aggregate, &mut *current),
            (&mut second.aggregate, &mut second.current),
        ] {
            let aggregate = Nlev::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            aggregate.external_product_to(
                &Polynomial(current.as_ref()),
                scratch,
                basis,
                modulus,
                ntt,
                &mut workspace.external_product,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Starts from the encrypted dummy and adds every selector in key order. Pairing
/// shares an accumulator traversal without skipping zero exponents or encrypted
/// zeros; an odd final selector uses the single-product kernel. For u64, pairs
/// retain [0,2q) residues until one final normalization before NTT; other widths
/// retain canonical updates. The key and workspace establish complete, equally
/// sized controls and canonical source residues.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_bucket<T: FheUint, const INPUTS: usize>(
    indices: &[usize],
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let control_len = inputs[0].1.as_ref().len();
    let (selections, dummy) = data.split_at(data.len() - control_len);
    for (_, aggregate) in &mut inputs {
        aggregate.as_mut().copy_from_slice(dummy);
    }
    let mut controls = indices.iter().zip(NlevIter::new(selections, control_len));
    while let Some((&first_index, first)) = controls.next() {
        if let Some((&second_index, second)) = controls.next() {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_pair_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        second.as_ref(),
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_pair_assign(
                        &first,
                        exponent,
                        &second,
                        exponents[second_index],
                        poly_length,
                        modulus,
                    );
                }
            }
        } else {
            for (exponents, aggregate) in &mut inputs {
                let exponent = exponents[first_index];
                if T::BITS == 64 {
                    primus_poly::lazy_add_mul_monomial_assign(
                        aggregate.as_mut(),
                        first.as_ref(),
                        exponent,
                        poly_length,
                        modulus,
                    );
                } else {
                    aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
                }
            }
        }
    }
    if T::BITS == 64 {
        for (_, aggregate) in &mut inputs {
            modulus.reduce_once_slice_assign(aggregate.as_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scatter every source coefficient independently of the pair kernel's
    // contiguous intervals. Nonconsecutive indices detect wrong mask lookup;
    // odd/empty buckets and dirty output detect dropped tails or dummy resets.
    fn check_bucket<T: FheUint + Into<u64>>(q: T) {
        const N: usize = 32;
        const CONTROL_LEN: usize = 3 * N;
        let indices = [1, 4, 6, 7, 9];
        let q_wide = u128::from(q.into());
        let mut actual = vec![q - T::ONE; CONTROL_LEN];
        for count in 0..=indices.len() {
            let data: Vec<T> = (0..(count + 1) * CONTROL_LEN)
                .map(|i| {
                    T::as_from(if i % 5 == 0 {
                        0
                    } else {
                        q_wide - 1 - (i % 13) as u128
                    })
                })
                .collect();
            for (a, b) in [
                (0, 0),
                (0, N - 1),
                (N, N),
                (N - 1, N),
                (2 * N - 1, 0),
                (2 * N - 1, 2 * N - 1),
            ] {
                let exponents: Vec<_> = (0..10).map(|i| if i % 2 == 0 { a } else { b }).collect();
                let mut expected: Vec<_> = data[count * CONTROL_LEN..]
                    .iter()
                    .map(|&v| u128::from(v.into()))
                    .collect();
                for (slot, &index) in indices[..count].iter().enumerate() {
                    for offset in 0..CONTROL_LEN {
                        let power = offset % N + exponents[index];
                        let dest = offset / N * N + power % N;
                        let value = u128::from(data[slot * CONTROL_LEN + offset].into());
                        let value = if (power / N).is_multiple_of(2) {
                            value
                        } else {
                            (q_wide - value) % q_wide
                        };
                        expected[dest] = (expected[dest] + value) % q_wide;
                    }
                }
                aggregate_bucket(
                    &indices[..count],
                    &data,
                    [(&exponents, Nlev::new(actual.as_mut_slice()))],
                    N,
                    BarrettModulus::new(q),
                );
                assert!(
                    actual
                        .iter()
                        .zip(&expected)
                        .all(|(&a, e)| u128::from(a.into()) == *e),
                    "count={count}, exponents=({a}, {b})"
                );
                // A second input negates every selector contribution but keeps
                // the same dummy. Compare both outputs with the independent sum.
                let second_exponents: Vec<_> =
                    exponents.iter().map(|&e| (e + N) % (2 * N)).collect();
                let mut second = vec![T::ZERO; CONTROL_LEN];
                aggregate_bucket(
                    &indices[..count],
                    &data,
                    [
                        (&exponents, Nlev::new(actual.as_mut_slice())),
                        (&second_exponents, Nlev::new(second.as_mut_slice())),
                    ],
                    N,
                    BarrettModulus::new(q),
                );
                for (i, ((&first, &second), &expected)) in
                    actual.iter().zip(&second).zip(&expected).enumerate()
                {
                    let dummy = u128::from(data[count * CONTROL_LEN + i].into());
                    assert_eq!(u128::from(first.into()), expected);
                    assert_eq!(
                        u128::from(second.into()),
                        (2 * dummy + q_wide - expected) % q_wide
                    );
                }
            }
        }
    }

    #[test]
    fn bucket_pairs_match_direct_negacyclic_sums() {
        check_bucket::<u32>(132_120_577);
        check_bucket::<u64>(1_125_899_906_826_241);
    }
}
