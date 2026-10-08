//! Bucket aggregation and reusable sparse blind-rotation workspace.

use super::SparseNtruBootstrappingKey;
use crate::PbsParameters;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    nlev::{FourierNlev, Nlev, NlevIter},
    ntru::Ntru,
};
use primus_modulus::NativeModulus;
use primus_ntru::FourierNtruExternalProductWorkspace;
use primus_poly::Polynomial;

pub(crate) struct SparseWorkspace<T: TorusFftValue> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    transformed: Vec<Complex64>,
    pub(crate) external_product: FourierNtruExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> SparseWorkspace<T> {
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &PbsParameters<T, LM>,
    ) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension().get()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            transformed: vec![Complex64::ZERO; parameters.blind_rotation().fourier_nlev_len()],
            external_product: FourierNtruExternalProductWorkspace::new(parameters.poly_length()),
        }
    }
}

/// Additional state for a second sparse blind-rotation input.
/// Allocate through [`crate::OneHotCircuitBootstrapEvaluator::new_sparse_pair_workspace`].
/// Retains only exponents, an L*N coefficient aggregate and one N-coefficient
/// accumulator; the original resources provide shared transform/product scratch.
pub struct SparseBlindRotationPairWorkspace<T: TorusFftValue> {
    pub(crate) exponents: Vec<usize>,
    pub(crate) aggregate: Vec<T>,
    pub(crate) current: Ntru<Vec<T>>,
}

impl<T: TorusFftValue> SparseBlindRotationPairWorkspace<T> {
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
pub(crate) fn rotate_buckets<T: TorusFftValue, Table: FftTable>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut SparseWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    let n = fft.poly_length().get();
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
        );
        let mut transformed = FourierNlev::new(workspace.transformed.as_mut_slice());
        Nlev::new(workspace.aggregate.as_slice()).write_fourier_form(&mut transformed, fft);
        transformed.external_product_to(
            &Polynomial(current.as_ref()),
            scratch,
            basis,
            fft,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}

/// Both current buffers hold their independently rotated public LUT on entry.
/// Each source-control group is consumed for both inputs before advancing;
/// transforms and external products then reuse the original shared scratch.
pub(crate) fn rotate_buckets_pair<T: TorusFftValue, Table: FftTable>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut SparseWorkspace<T>,
    second: &mut SparseBlindRotationPairWorkspace<T>,
    buffers: [&mut Ntru<Vec<T>>; 2],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
) {
    let [current, scratch] = buffers;
    let n = fft.poly_length().get();
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
        );
        // Bucket zero lifts both public LUTs with NLEV. Later NGSW controls
        // use the same external-product arithmetic, preserving every bucket.
        for (aggregate, current) in [
            (&mut workspace.aggregate, &mut *current),
            (&mut second.aggregate, &mut second.current),
        ] {
            let mut transformed = FourierNlev::new(workspace.transformed.as_mut_slice());
            Nlev::new(aggregate.as_slice()).write_fourier_form(&mut transformed, fft);
            transformed.external_product_to(
                &Polynomial(current.as_ref()),
                scratch,
                basis,
                fft,
                &mut workspace.external_product,
            );
            core::mem::swap(current, scratch);
        }
    }
}

/// Starts from the encrypted dummy and adds every selector in key order. For
/// u64, four controls share a coefficient traversal; u32 retains the pair path.
/// Remaining controls use pairs and a possible single tail. No zero exponent
/// or encrypted zero is skipped. The key/workspace establish complete, equally
/// sized controls, and native wrapping preserves the coefficient representation.
/// Instantiated only for one input or the fixed two-input window.
#[inline]
fn aggregate_bucket<T: TorusFftValue, const INPUTS: usize>(
    indices: &[usize],
    data: &[T],
    mut inputs: [(&[usize], Nlev<&mut [T]>); INPUTS],
    poly_length: usize,
) {
    let modulus = NativeModulus::new();
    let control_len = inputs[0].1.as_ref().len();
    let (selections, dummy) = data.split_at(data.len() - control_len);
    for (_, aggregate) in &mut inputs {
        aggregate.as_mut().copy_from_slice(dummy);
    }
    let mut controls = NlevIter::new(selections, control_len);
    let processed = if T::BITS == 64 {
        let (groups, _) = indices.as_chunks::<4>();
        for indices in groups {
            let sources: [Nlev<&[T]>; 4] =
                core::array::from_fn(|_| controls.next().expect("complete sparse controls"));
            for (exponents, aggregate) in &mut inputs {
                super::aggregation::add_four_rotations_assign(
                    aggregate.as_mut(),
                    sources.each_ref().map(|control| control.as_ref()),
                    indices.map(|i| exponents[i]),
                    poly_length,
                );
            }
        }
        4 * groups.len()
    } else {
        0
    };
    // Finish the u64 tail (0..3 controls); u32 uses this pair/single loop for
    // the whole bucket.
    let mut controls = indices[processed..].iter().zip(controls);
    while let Some((&first_index, first)) = controls.next() {
        let second = controls.next();
        for (exponents, aggregate) in &mut inputs {
            let exponent = exponents[first_index];
            if let Some((&second_index, ref second)) = second {
                aggregate.add_mul_monomial_pair_assign(
                    &first,
                    exponent,
                    second,
                    exponents[second_index],
                    poly_length,
                    modulus,
                );
            } else {
                aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scatter every source coefficient independently of the aggregation kernel's
    // contiguous intervals. Nonconsecutive indices detect wrong mask lookup;
    // odd/empty buckets and dirty output detect dropped tails or dummy resets.
    fn check_bucket<T: TorusFftValue + Into<u64>>() {
        const N: usize = 32;
        const CONTROL_LEN: usize = 3 * N;
        let indices = [1, 4, 6, 7, 9, 12, 15, 18, 19, 23, 24, 27, 29];
        let q_wide = 1u128 << T::BITS;
        let mut actual = vec![T::MAX; CONTROL_LEN];
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
            // Include all global-sign combinations and coincident/distinct
            // rotation points. Count 0..13 covers four-way boundaries and tails.
            for pattern in 0..16 {
                for shifts in [
                    [0, 0, 0, 0],
                    [0, 1, N / 2, N - 1],
                    [N - 1, 0, N - 1, 0],
                    [N - 1, N - 1, N - 1, N - 1],
                ] {
                    let mut exponents = vec![0; 30];
                    for (i, &index) in indices.iter().enumerate() {
                        exponents[index] =
                            shifts[i & 3] + if pattern & (1 << (i & 3)) == 0 { 0 } else { N };
                    }
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
                    );
                    assert!(
                        actual
                            .iter()
                            .zip(&expected)
                            .all(|(&a, e)| u128::from(a.into()) == *e),
                        "count={count}, pattern={pattern}, shifts={shifts:?}"
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
    }

    #[test]
    fn bucket_groups_match_direct_negacyclic_sums() {
        check_bucket::<u32>();
        check_bucket::<u64>();
    }
}
