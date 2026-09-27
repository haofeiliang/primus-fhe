//! Bucket aggregation and reusable sparse blind-rotation workspace.

use super::SparseNtruBootstrappingKey;
use crate::TfheParameters;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    nlev::{FourierNlev, Nlev},
    ntru::Ntru,
};
use primus_modulus::NativeModulus;
use primus_ntru::FourierNtruExternalProductContext;
use primus_poly::Polynomial;

pub(crate) struct SparseWorkspace<T: TorusFftValue> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Vec<T>,
    transformed: Vec<Complex64>,
    pub(crate) external_product: FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> SparseWorkspace<T> {
    pub(crate) fn new(parameters: &TfheParameters<T>) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension()],
            aggregate: vec![T::ZERO; parameters.blind_rotation().nlev_len()],
            transformed: vec![Complex64::ZERO; parameters.blind_rotation().fourier_nlev_len()],
            external_product: FourierNtruExternalProductContext::new(parameters.poly_length()),
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
    let n = fft.poly_length();
    let modulus = NativeModulus::new();
    // Start with public P in current. Bucket 0 uses NLEV[H_0] to lift P;
    // buckets >= 1 actually hold NGSW[H_j] = NLEV[f*H_j] and act on ciphertexts.
    // NLEV and NGSW external products have identical arithmetic, so all buckets
    // share this NLEV product call without a first-bucket branch.
    core::mem::swap(current, scratch);
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        let (selections, dummy) = data.split_at(indices.len() * key.control_len);
        workspace.aggregate.copy_from_slice(dummy);
        for (&i, selection) in indices.iter().zip(selections.chunks_exact(key.control_len)) {
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
