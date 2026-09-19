use std::alloc::Layout;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweSecretKey, SecretKeyDistr};
use primus_lattice::{
    GadgetSize,
    ggsw::{FourierGgsw, Ggsw, GgswIter},
};
use primus_modulus::NativeModulus;
use primus_reduce::PrepareModulusSwitch;
use primus_tfhe::{rotation::RotationQuantizer, sparse::BucketMap};
use zeroize::Zeroizing;

use crate::{ClientKey, KeyGenerator, SparseBootstrappingKeyError};

/// Coefficient-domain GGSW selections for sparse blind rotation in the Fourier backend.
///
/// Each input index appears in `copy_count` distinct public buckets. Encrypted
/// selections cover each nonzero small-LWE coefficient exactly once and select
/// at most one entry per bucket. Every bucket also contains an independently
/// encrypted dummy: one for an unoccupied bucket, zero otherwise.
///
/// Generation retains only the public mapping and ciphertexts, never the support
/// or matching. Input and accumulator use the native modulus `2^T::BITS`.
/// Ciphertexts are generated in Fourier form and converted to torus coefficients;
/// this conversion can incur rounding error. Raw blind rotation is available via
/// [`Self::fourier_blind_rotate_lookup_table_to`].
/// [`KeyGenerator::try_generate_sparse_server_key`] pairs this key with the GLWE
/// KSK for ordinary/interleaved evaluation in [`crate::Evaluator`].
///
/// Successful mapping conditions the joint distribution of the public map and
/// secret. Fixed-weight security and complete PBS noise bounds need independent
/// assessment; eight retries do not establish a security level.
pub struct SparseGlweBootstrappingKey<T: TorusFftValue> {
    data: Vec<T>,
    map: BucketMap,
    input_dimension: usize,
    hamming_weight: usize,
    copy_count: usize,
    input_quantizer: RotationQuantizer<<NativeModulus<T> as PrepareModulusSwitch>::Prepared>,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> SparseGlweBootstrappingKey<T> {
    /// Returns the dimension of the actual blind-rotation input secret.
    #[must_use]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the public, fixed weight of the input binary secret.
    #[must_use]
    pub fn hamming_weight(&self) -> usize {
        self.hamming_weight
    }

    /// Returns the number of distinct buckets containing each input index.
    #[must_use]
    pub fn copy_count(&self) -> usize {
        self.copy_count
    }

    /// Returns the total number of buckets, including unoccupied buckets.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.map.bucket_count()
    }

    /// Returns the native input modulus, also used by the accumulator.
    #[must_use]
    pub fn input_modulus(&self) -> NativeModulus<T> {
        NativeModulus::new()
    }

    pub(super) fn input_quantizer(
        &self,
    ) -> RotationQuantizer<<NativeModulus<T> as PrepareModulusSwitch>::Prepared> {
        self.input_quantizer
    }

    /// Returns `None` for the native accumulator modulus `2^T::BITS`.
    #[must_use]
    pub fn cipher_modulus(&self) -> Option<T> {
        None
    }

    /// Returns the GGSW layout shared by all selections and dummies.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the decomposition basis, including its level order.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns coefficient storage in
    /// `[bucket][entry...,dummy][row][level][component][coefficient]` order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Borrows one bucket's increasing input indices and coefficient GGSWs.
    ///
    /// Ciphertexts follow the indices, with **one additional dummy last**.
    /// A bucket without public entries still returns its dummy ciphertext.
    /// This view contains no plaintext selection or occupancy information.
    ///
    /// # Panics
    ///
    /// Panics if `bucket_index >= self.bucket_count()`.
    #[must_use]
    pub fn bucket(&self, bucket_index: usize) -> (&[usize], GgswIter<'_, T>) {
        let (indices, ciphertexts) = self.bucket_data(bucket_index);
        (indices, GgswIter::new(ciphertexts, self.size.ggsw_len()))
    }

    /// Borrows a bucket's indices and contiguous GGSW storage, including its final
    /// dummy. Splitting the dummy off allows aggregation to start with a copy.
    pub(super) fn bucket_data(&self, bucket_index: usize) -> (&[usize], &[T]) {
        assert!(
            bucket_index < self.bucket_count(),
            "sparse bucket index out of bounds"
        );
        let start = self.map.bucket_offsets()[bucket_index];
        let end = self.map.bucket_offsets()[bucket_index + 1];
        let ggsw_len = self.size.ggsw_len();
        let ciphertexts =
            &self.data[(start + bucket_index) * ggsw_len..(end + bucket_index + 1) * ggsw_len];
        (&self.map.input_indices()[start..end], ciphertexts)
    }
}

impl<T, Table> KeyGenerator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates a sparse BSK from this client's fixed-weight small-LWE secret.
    ///
    /// Each input chooses `copy_count` distinct buckets uniformly. Complete
    /// matching retries at most eight independent maps, keeping the same secret.
    /// GGSW allocation and encryption start only after matching succeeds. The
    /// experimental profiles use `copy_count=3` and `bucket_count=2*h`.
    /// This operates on the small-LWE secret in both PBS orders.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible client keys, a distribution other than
    /// fixed-weight binary, `h` outside `0<h<n`, nonbinary/wrong-weight actual
    /// coefficients, invalid bucket counts, storage overflow, or eight failed
    /// maps. Validation errors consume no randomness; matching failure consumes
    /// mapping randomness only. No partial key or private assignment is returned.
    ///
    /// # Correctness
    ///
    /// The client's accumulator key must satisfy [`ClientKey`]'s secret-key
    /// contracts. This local key-generation procedure is not constant-time.
    /// Parameter validity and successful generation do not certify security or
    /// a PBS failure probability; see [`SparseGlweBootstrappingKey`].
    pub fn try_generate_sparse_bootstrapping_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        rng: &mut R,
    ) -> Result<SparseGlweBootstrappingKey<T>, SparseBootstrappingKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        use SparseBootstrappingKeyError as Error;

        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;
        let input = client_key.small_lwe_secret_key();
        let SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } = input.distr() else {
            return Err(Error::UnsupportedSecretDistribution);
        };
        let input_dimension = input.dimension();
        if hamming_weight == 0 || hamming_weight >= input_dimension {
            return Err(Error::InvalidHammingWeight);
        }
        let entry_count = input_dimension
            .checked_mul(copy_count)
            .ok_or(Error::StorageSizeOverflow)?;
        let size = parameters.blind_rotation_ggsw().size();
        let data_len = entry_count
            .checked_add(bucket_count)
            .and_then(|count| count.checked_mul(size.ggsw_len()))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<Complex64>(size.fourier_ggsw_len())
            .map_err(|_| Error::StorageSizeOverflow)?;

        let mut nonzero_indices = Zeroizing::new(Vec::with_capacity(hamming_weight));
        for (index, &coefficient) in input.as_ref().iter().enumerate() {
            if coefficient == T::ONE {
                if nonzero_indices.len() == hamming_weight {
                    return Err(Error::InvalidSecretCoefficients);
                }
                nonzero_indices.push(index);
            } else if coefficient != T::ZERO {
                return Err(Error::InvalidSecretCoefficients);
            }
        }
        if nonzero_indices.len() != hamming_weight {
            return Err(Error::InvalidSecretCoefficients);
        }
        let (map, selected_input_indices) = BucketMap::try_generate(
            input_dimension,
            copy_count,
            bucket_count,
            &nonzero_indices,
            rng,
        )?;
        drop(nonzero_indices);

        let output_key = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        let gadget = parameters.blind_rotation_ggsw();
        self.gadget.resize(size);
        let mut data = vec![T::ZERO; data_len];
        // A single transformed GGSW is reused; the full BSK is only stored in
        // coefficient form, without a second Fourier-sized key allocation.
        let mut transformed = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
        for (bucket, &selected_index) in selected_input_indices.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            let output =
                &mut data[(start + bucket) * size.ggsw_len()..(end + bucket + 1) * size.ggsw_len()];
            // The last entry is the dummy: it selects identity precisely when
            // the bucket has no assigned nonzero input.
            for (&index, ciphertext) in map.input_indices()[start..end]
                .iter()
                .chain(std::iter::once(&BucketMap::UNASSIGNED))
                .zip(output.chunks_exact_mut(size.ggsw_len()))
            {
                let constant = Zeroizing::new([if index == selected_index {
                    T::ONE
                } else {
                    T::ZERO
                }]);
                output_key.encrypt_ggsw_constant_batch_to(
                    constant.as_ref(),
                    transformed.as_mut(),
                    gadget,
                    &mut self.fft,
                    rng,
                    &mut self.gadget,
                );
                transformed.write_torus_form(&mut Ggsw::new(ciphertext), &mut self.fft);
            }
        }

        Ok(SparseGlweBootstrappingKey {
            data,
            map,
            input_dimension,
            hamming_weight,
            copy_count,
            input_quantizer: RotationQuantizer::new(
                NativeModulus::<T>::new(),
                2 * size.glwe_size().poly_length(),
                1,
            ),
            size,
            basis: gadget.basis().clone(),
        })
    }
}
