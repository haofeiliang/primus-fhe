//! Coefficient-domain bucket selections for experimental sparse NTRU PBS.

use std::alloc::Layout;

use num_traits::{ConstOne, ConstZero};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    ngsw::{FourierNgsw, Ngsw, NgswIter},
    ntru::Ntru,
};
use primus_modulus::NativeModulus;
use primus_ntru::{
    FourierNtruExternalProductContext, FourierNtruKeySwitchingKey, FourierNtruSecretKey,
    SecretKeyDistr,
};
use primus_poly::Polynomial;
use primus_tfhe::sparse::BucketMap;
use zeroize::Zeroizing;

use crate::{
    ClientKey, KeyGenerationError, KeyGenerator, ServerKey, SparseBootstrappingKeyError,
    TfheParameters,
};

/// Coefficient NGSW selectors and public buckets for a fixed-weight binary client.
///
/// Each nonzero input is privately assigned to exactly one of its public copies.
/// Each bucket has an independently encrypted dummy, one when unoccupied and zero
/// otherwise. Only ciphertexts and the public map remain after generation.
/// The parent [`ServerKey`] carries the common NLev initializer, basis and return KSK.
///
/// Successful generation conditions both the client secret on NTRU invertibility
/// and Fourier inverse stability, and the public map on matching. These conditions
/// require independent security assessment; this representation does not certify a failure rate.
/// Each Fourier NGSW is recovered to Native coefficients before storage. This
/// conversion, the aggregate FFT and external products incur numerical error.
pub struct SparseNtruBootstrappingKey<T: TorusFftValue> {
    data: Vec<T>,
    map: BucketMap,
    input_dimension: usize,
    hamming_weight: usize,
    copy_count: usize,
    pub(crate) ngsw_len: usize,
}

impl<T: TorusFftValue> SparseNtruBootstrappingKey<T> {
    /// Returns the active client prefix length.
    #[must_use]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the declared number of nonzero binary input coefficients.
    #[must_use]
    pub fn hamming_weight(&self) -> usize {
        self.hamming_weight
    }

    /// Returns the number of distinct buckets containing every input index.
    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.copy_count
    }

    /// Returns the number of public buckets, including empty ones.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.map.bucket_count()
    }

    /// Returns `[bucket][entry...,dummy][level][coefficient]` storage.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Borrows increasing input indices and their coefficient NGSWs, with a dummy last.
    /// An empty bucket still contains its dummy. No plaintext assignment is exposed.
    ///
    /// # Panics
    /// Panics if `bucket >= self.bucket_count()`.
    #[must_use]
    pub fn bucket(&self, bucket: usize) -> (&[usize], NgswIter<'_, T>) {
        let (indices, data) = self.bucket_data(bucket);
        (indices, NgswIter::new(data, self.ngsw_len))
    }

    fn bucket_data(&self, bucket: usize) -> (&[usize], &[T]) {
        assert!(
            bucket < self.bucket_count(),
            "sparse bucket index out of bounds"
        );
        let start = self.map.bucket_offsets()[bucket];
        let end = self.map.bucket_offsets()[bucket + 1];
        (
            &self.map.input_indices()[start..end],
            &self.data[(start + bucket) * self.ngsw_len..(end + bucket + 1) * self.ngsw_len],
        )
    }
}

impl<T, Table> KeyGenerator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates sparse PBS material for an existing, fixed odd-weight binary client.
    ///
    /// Keeps the client secret fixed; only the public map retries, at most eight
    /// times. Encrypts each selector and dummy independently after matching succeeds.
    /// Requires `copy_count >= 1` and `bucket_count >= max(copy_count, h)`.
    /// Returns the same high-level server-key type as classic generation. Sparse
    /// CBS and MVB are not supported; this key contains no CBS material.
    ///
    /// # Errors
    /// Rejects incompatible keys, a non-fixed-binary distribution, `h` outside
    /// `0<h<n`, actual weight mismatch, invalid buckets, storage overflow, even
    /// declared weight, noninvertible secrets or unstable Fourier inverses before
    /// consuming randomness. Matching failure consumes only map randomness and
    /// returns no partial key. It never resamples the client.
    ///
    /// # Correctness
    /// Fourier material must use this context's FFT table instance.
    /// Budget NLev initialization, all bucket errors, input quantization and return
    /// key-switch noise, including coarser ManyLUT rotations. Matching is not
    /// constant-time; see [`SparseNtruBootstrappingKey`]'s distribution requirements.
    pub fn try_generate_sparse_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        use SparseBootstrappingKeyError as Error;
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;
        let SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } =
            parameters.external_lwe().secret_key_distr()
        else {
            return Err(Error::UnsupportedSecretDistribution.into());
        };
        let dimension = parameters.external_lwe_dimension();
        if hamming_weight == 0 || hamming_weight >= dimension {
            return Err(Error::InvalidHammingWeight.into());
        }
        if hamming_weight.is_multiple_of(2) {
            return Err(primus_ntru::NtruError::NonInvertibleSecretKey.into());
        }
        let ngsw_len = parameters.blind_rotation().nlev_len();
        let fourier_len = parameters.blind_rotation().fourier_nlev_len();
        Layout::array::<Complex64>(fourier_len).map_err(|_| Error::StorageSizeOverflow)?;
        let data_len = dimension
            .checked_mul(copy_count)
            .and_then(|n| n.checked_add(bucket_count))
            .and_then(|n| n.checked_mul(ngsw_len))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        let nonzero_indices = Zeroizing::new(
            client_key
                .external_lwe_secret_coefficients()
                .iter()
                .enumerate()
                .filter_map(|(i, &bit)| (bit == T::SignedInteger::ONE).then_some(i))
                .collect::<Vec<_>>(),
        );
        if nonzero_indices.len() != hamming_weight {
            return Err(Error::InvalidSecretWeight.into());
        }
        let client_fourier = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.client_ntru_secret_key(),
            &mut self.fft,
        )?;
        let accumulator_fourier = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;
        let (map, selected) =
            BucketMap::try_generate(dimension, copy_count, bucket_count, &nonzero_indices, rng)
                .map_err(Error::from)?;
        drop(nonzero_indices);
        let mut data = vec![T::ZERO; data_len];
        // Recover one independently encrypted control at a time. Keep only one
        // Fourier NGSW temporary rather than a second transformed bootstrapping key.
        let mut transformed = FourierNgsw::<Vec<Complex64>>::zero(fourier_len);
        for (bucket, &chosen) in selected.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            let output = &mut data[(start + bucket) * ngsw_len..(end + bucket + 1) * ngsw_len];
            for (&index, coefficients) in map.input_indices()[start..end]
                .iter()
                .chain(std::iter::once(&BucketMap::UNASSIGNED))
                .zip(output.chunks_exact_mut(ngsw_len))
            {
                let bit = if index == chosen {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                accumulator_fourier.encrypt_ngsw_signed_constant_batch_to(
                    &[bit],
                    transformed.as_mut(),
                    parameters.blind_rotation(),
                    &mut self.fft,
                    rng,
                    &mut self.gadget,
                );
                transformed.write_torus_form(&mut Ngsw::new(coefficients), &mut self.fft);
            }
        }
        drop(selected);
        let controls = SparseNtruBootstrappingKey {
            data,
            map,
            input_dimension: dimension,
            hamming_weight,
            copy_count,
            ngsw_len,
        };
        let initializer = self.generate_initializer(&accumulator_fourier, rng);
        let key_switching_key = FourierNtruKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            &client_fourier,
            parameters.ntru_key_switching(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        Ok(ServerKey::from_sparse(
            parameters,
            initializer,
            controls,
            key_switching_key,
        ))
    }
}

pub(crate) struct SparseWorkspace<T: TorusFftValue> {
    pub(crate) exponents: Vec<usize>,
    aggregate: Ngsw<Vec<T>>,
    transformed: FourierNgsw<Vec<Complex64>>,
    pub(crate) external_product: FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> SparseWorkspace<T> {
    pub(crate) fn new(parameters: &TfheParameters<T>) -> Self {
        Self {
            exponents: vec![0; parameters.external_lwe_dimension()],
            aggregate: Ngsw::zero(parameters.blind_rotation().nlev_len()),
            transformed: FourierNgsw::zero(parameters.blind_rotation().fourier_nlev_len()),
            external_product: FourierNtruExternalProductContext::new(parameters.poly_length()),
        }
    }
}

/// The evaluator established key/workspace/table compatibility and quantized every mask.
/// Every bucket is processed, including empty ones and zero exponents; its encrypted
/// dummy and zero selections still contribute noise. Final output stays in `current`.
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
    for bucket in 0..key.bucket_count() {
        let (indices, data) = key.bucket_data(bucket);
        let (selections, dummy) = data.split_at(indices.len() * key.ngsw_len);
        workspace.aggregate.as_mut().copy_from_slice(dummy);
        for (&i, selection) in indices.iter().zip(selections.chunks_exact(key.ngsw_len)) {
            for (acc, row) in workspace
                .aggregate
                .as_mut()
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
        workspace
            .aggregate
            .write_fourier_form(&mut workspace.transformed, fft);
        workspace.transformed.external_product_to(
            current,
            scratch,
            basis,
            fft,
            &mut workspace.external_product,
        );
        core::mem::swap(current, scratch);
    }
}
