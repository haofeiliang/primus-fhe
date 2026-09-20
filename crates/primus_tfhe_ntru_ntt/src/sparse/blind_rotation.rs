//! Bucket aggregation and reusable sparse blind-rotation workspace.

use super::SparseNtruBootstrappingKey;
use crate::TfheParameters;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{ngsw::Ngsw, ntru::Ntru};
use primus_modulus::BarrettModulus;
use primus_ntru::NttNtruExternalProductContext;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;

pub(crate) struct SparseWorkspace<T: FheUint> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductContext<T>,
}

impl<T: FheUint> SparseWorkspace<T> {
    pub(crate) fn new(parameters: &TfheParameters<T>) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            external_product: NttNtruExternalProductContext::new(parameters.poly_length()),
        }
    }
}

/// The evaluator established key/workspace/table compatibility and quantized every mask.
/// Every bucket is processed, including empty ones and zero exponents; its encrypted
/// dummy and zero selections still contribute noise. Final output stays in `current`.
pub(crate) fn rotate_buckets<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    key: &SparseNtruBootstrappingKey<T>,
    workspace: &mut SparseWorkspace<T>,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    basis: &ApproxSignedBasis<T>,
    modulus: BarrettModulus<T>,
    ntt: &Table,
) {
    let n = ntt.poly_length();
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        let (selections, dummy) = data.split_at(indices.len() * key.ngsw_len);
        workspace.aggregate.copy_from_slice(dummy);
        for (&i, selection) in indices.iter().zip(selections.chunks_exact(key.ngsw_len)) {
            for (acc, row) in workspace
                .aggregate
                .chunks_exact_mut(n)
                .zip(selection.chunks_exact(n))
            {
                Polynomial(acc).add_mul_monomial_assign(
                    &Polynomial(row),
                    workspace.exponents[i],
                    modulus,
                );
            }
        }
        Ngsw::new(workspace.aggregate.as_mut_slice())
            .into_ntt_form(ntt)
            .external_product_to(
                current,
                scratch,
                basis,
                modulus,
                ntt,
                &mut workspace.external_product,
            );
        core::mem::swap(current, scratch);
    }
}
