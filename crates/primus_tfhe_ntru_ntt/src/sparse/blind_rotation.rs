//! Bucket aggregation and reusable sparse blind-rotation workspace.

use super::SparseNtruBootstrappingKey;
use crate::TfheParameters;
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

pub(crate) struct SparseWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductWorkspace<T>,
}

impl<T: FheUint> SparseWorkspace<T> {
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &TfheParameters<T, LM>,
    ) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension().get()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            external_product: NttNtruExternalProductWorkspace::new(parameters.poly_length()),
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
            &workspace.exponents,
            Nlev::new(workspace.aggregate.as_mut_slice()),
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

/// Starts from the encrypted dummy and adds every selector in key order. Pairing
/// shares an accumulator traversal without skipping zero exponents or encrypted
/// zeros; an odd final selector uses the single-product kernel. The key and
/// workspace establish complete, equally sized controls and canonical residues.
#[inline]
fn aggregate_bucket<T: FheUint>(
    indices: &[usize],
    data: &[T],
    exponents: &[usize],
    mut aggregate: Nlev<&mut [T]>,
    poly_length: usize,
    modulus: BarrettModulus<T>,
) {
    let control_len = aggregate.as_ref().len();
    let (selections, dummy) = data.split_at(data.len() - control_len);
    aggregate.as_mut().copy_from_slice(dummy);
    let mut controls = indices.iter().zip(NlevIter::new(selections, control_len));
    while let Some((&first_index, first)) = controls.next() {
        let exponent = exponents[first_index];
        if let Some((&second_index, second)) = controls.next() {
            aggregate.add_mul_monomial_pair_assign(
                &first,
                exponent,
                &second,
                exponents[second_index],
                poly_length,
                modulus,
            );
        } else {
            aggregate.add_mul_monomial_assign(&first, exponent, poly_length, modulus);
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
                    &exponents,
                    Nlev::new(actual.as_mut_slice()),
                    N,
                    BarrettModulus::new(q),
                );
                assert!(
                    actual
                        .iter()
                        .zip(expected)
                        .all(|(&a, e)| u128::from(a.into()) == e),
                    "count={count}, exponents=({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn bucket_pairs_match_direct_negacyclic_sums() {
        check_bucket::<u32>(132_120_577);
        check_bucket::<u64>(1_125_899_906_826_241);
    }
}
