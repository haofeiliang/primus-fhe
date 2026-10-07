use std::alloc::Layout;

use primus_glwe::{NttGlweSecretKey, SecretKeyDistr};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_tfhe::sparse::BucketMap;
use zeroize::Zeroizing;

use crate::{
    ClientKey, KeyGenerationError, KeyGenerator, SparseBootstrappingKeyError,
    SparseGlweBootstrappingKey,
};

/// Validated bucket geometry and ciphertext allocation size, before secret sampling.
/// Kept only during setup; the map and key retain their own final metadata.
pub(crate) struct SparseKeyLayout {
    copy_count: usize,
    bucket_count: usize,
    hamming_weight: usize,
    data_len: usize,
}

impl<T, Table> KeyGenerator<'_, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Validates public sparse choices before allocating keys or consuming randomness.
    pub(crate) fn prepare_sparse_layout(
        &self,
        copy_count: usize,
        bucket_count: usize,
    ) -> Result<SparseKeyLayout, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let parameters = self.context.parameters();
        let input = parameters.small_lwe();
        let SecretKeyDistr::FixedHammingWeightBinary { hamming_weight } = input.secret_key_distr()
        else {
            return Err(Error::UnsupportedSecretDistribution.into());
        };
        let dimension = input.dimension().get();
        if hamming_weight == 0 || hamming_weight >= dimension {
            return Err(Error::InvalidHammingWeight.into());
        }
        let entries = dimension
            .checked_mul(copy_count)
            .ok_or(Error::StorageSizeOverflow)?;
        let offsets = bucket_count
            .checked_add(1)
            .ok_or(Error::StorageSizeOverflow)?;
        let data_len = entries
            .checked_add(bucket_count)
            .and_then(|count| count.checked_mul(parameters.blind_rotation_ggsw().size().ggsw_len()))
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<usize>(entries).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<usize>(offsets).map_err(|_| Error::StorageSizeOverflow)?;
        Layout::array::<T>(data_len).map_err(|_| Error::StorageSizeOverflow)?;
        if copy_count == 0 || bucket_count < copy_count.max(hamming_weight) {
            return Err(
                Error::from(primus_tfhe::sparse::BucketMapError::InvalidBucketParameters).into(),
            );
        }
        Ok(SparseKeyLayout {
            copy_count,
            bucket_count,
            hamming_weight,
            data_len,
        })
    }

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
    pub fn try_generate_sparse_blind_rotation_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        rng: &mut R,
    ) -> Result<SparseGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        client_key.check_compatible(self.context.parameters())?;
        let layout = self.prepare_sparse_layout(copy_count, bucket_count)?;
        let output_key = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        self.generate_sparse_bootstrapping_key_with_main(client_key, layout, &output_key, rng)
    }

    /// Reuses the accepted accumulator transform for BR and optional CBS.
    /// Only sparse support/matching checks remain after setup validation.
    pub(crate) fn generate_sparse_bootstrapping_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        layout: SparseKeyLayout,
        output_key: &NttGlweSecretKey<T>,
        rng: &mut R,
    ) -> Result<SparseGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError> {
        use SparseBootstrappingKeyError as Error;
        let SparseKeyLayout {
            copy_count,
            bucket_count,
            hamming_weight,
            data_len,
        } = layout;
        let parameters = self.context.parameters();
        let input = client_key.small_lwe_secret_key();
        let input_dimension = input.dimension();
        let size = parameters.blind_rotation_ggsw().size();
        let mut nonzero_indices = Zeroizing::new(Vec::with_capacity(hamming_weight));
        for (index, &coefficient) in input.as_ref().iter().enumerate() {
            if coefficient == T::ONE {
                if nonzero_indices.len() == hamming_weight {
                    return Err(Error::InvalidSecretCoefficients.into());
                }
                nonzero_indices.push(index);
            } else if coefficient != T::ZERO {
                return Err(Error::InvalidSecretCoefficients.into());
            }
        }
        if nonzero_indices.len() != hamming_weight {
            return Err(Error::InvalidSecretCoefficients.into());
        }
        let (map, selected_input_indices) = BucketMap::try_generate(
            input_dimension,
            copy_count,
            bucket_count,
            &nonzero_indices,
            rng,
        )
        .map_err(Error::from)?;
        drop(nonzero_indices);

        let ntt = self.context.table();
        let gadget = parameters.blind_rotation_ggsw();
        self.gadget.resize(size);
        let mut data = vec![T::ZERO; data_len];
        let max_bucket_len = map
            .bucket_offsets()
            .windows(2)
            .map(|pair| pair[1] - pair[0] + 1)
            .max()
            .unwrap();
        let mut constants = Zeroizing::new(Vec::with_capacity(max_bucket_len));
        for (bucket, &selected_index) in selected_input_indices.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            constants.clear();
            constants.extend(map.input_indices()[start..end].iter().map(|&index| {
                if index == selected_index {
                    T::ONE
                } else {
                    T::ZERO
                }
            }));
            constants.push(if selected_index == BucketMap::UNASSIGNED {
                T::ONE
            } else {
                T::ZERO
            });
            let output =
                &mut data[(start + bucket) * size.ggsw_len()..(end + bucket + 1) * size.ggsw_len()];
            output_key.encrypt_ggsw_constant_batch_coeff_to(
                &constants,
                output,
                gadget,
                ntt,
                rng,
                &mut self.gadget,
            );
        }

        Ok(SparseGlweBootstrappingKey::try_new(
            data,
            map,
            hamming_weight,
            gadget,
        )?)
    }
}
