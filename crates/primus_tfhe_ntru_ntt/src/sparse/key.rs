//! Coefficient-domain bucket selections for experimental sparse NTRU PBS.

use std::alloc::Layout;

use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_lattice::ngsw::NgswIter;
use primus_ntru::{NttNtruKeySwitchingKey, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::MonomialNttTable;
use primus_tfhe::sparse::BucketMap;
use zeroize::Zeroizing;

use crate::{ClientKey, KeyGenerationError, KeyGenerator, ServerKey, SparseBootstrappingKeyError};

/// Coefficient NGSW selectors and public buckets for a fixed-weight binary client.
///
/// Each nonzero input is privately assigned to exactly one of its public copies.
/// Each bucket has an independently encrypted dummy, one when unoccupied and zero
/// otherwise. Only ciphertexts and the public map remain after generation.
/// The parent [`ServerKey`] carries the common NLev initializer, basis and return KSK.
///
/// Successful generation conditions both the client secret on NTRU invertibility
/// and the public map on matching. These conditions require independent security
/// assessment; this experimental representation does not certify a failure rate.
pub struct SparseNtruBootstrappingKey<T: FheUint> {
    data: Vec<T>,
    map: BucketMap,
    input_dimension: usize,
    hamming_weight: usize,
    copy_count: usize,
    pub(crate) ngsw_len: usize,
}

impl<T: FheUint> SparseNtruBootstrappingKey<T> {
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

    pub(super) fn bucket_data(&self, bucket: usize) -> (&[usize], &[T]) {
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates sparse PBS material for an existing, fixed-weight binary client.
    ///
    /// Keeps the client secret fixed; only the public map retries, at most eight
    /// times. Encrypts each selector and dummy independently after matching succeeds.
    /// Returns the same high-level server-key type as classic generation. Sparse
    /// CBS and MVB are not supported; this key contains no CBS material.
    ///
    /// # Errors
    /// Rejects incompatible keys, a non-fixed-binary distribution, `h` outside
    /// `0<h<n`, actual weight mismatch, invalid buckets, storage overflow or
    /// noninvertible secrets before consuming randomness. Matching failure consumes
    /// only map randomness and returns no partial key. It never resamples the client.
    ///
    /// # Correctness
    /// Imported accumulator coefficients inherit
    /// [`NttNtruSecretKey::try_from_coeff_secret_key`]'s magnitude requirement.
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
        let ngsw_len = parameters.blind_rotation().nlev_len();
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
        let ntt = self.context.table();
        let modulus = parameters.accumulator_ntru().cipher_modulus();
        let client_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.client_ntru_secret_key(),
            modulus,
            ntt,
        )?;
        let accumulator_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            modulus,
            ntt,
        )?;
        let (map, selected) =
            BucketMap::try_generate(dimension, copy_count, bucket_count, &nonzero_indices, rng)
                .map_err(Error::from)?;
        drop(nonzero_indices);
        let mut data = vec![T::ZERO; data_len];
        // One bucket of secret constants at a time; no second transformed BSK.
        let max_entries = map
            .bucket_offsets()
            .windows(2)
            .map(|w| w[1] - w[0] + 1)
            .max()
            .unwrap();
        let mut constants = Zeroizing::new(Vec::with_capacity(max_entries));
        for (bucket, &chosen) in selected.iter().enumerate() {
            let start = map.bucket_offsets()[bucket];
            let end = map.bucket_offsets()[bucket + 1];
            constants.clear();
            constants.extend(map.input_indices()[start..end].iter().map(|&i| {
                if i == chosen {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                }
            }));
            constants.push(if chosen == BucketMap::UNASSIGNED {
                T::SignedInteger::ONE
            } else {
                T::SignedInteger::ZERO
            });
            let output = &mut data[(start + bucket) * ngsw_len..(end + bucket + 1) * ngsw_len];
            accumulator_ntt.encrypt_ngsw_signed_constant_batch_to(
                &constants,
                output,
                parameters.blind_rotation(),
                ntt,
                rng,
            );
            for polynomial in output.chunks_exact_mut(parameters.poly_length()) {
                ntt.inverse_transform_slice(polynomial);
            }
        }
        let controls = SparseNtruBootstrappingKey {
            data,
            map,
            input_dimension: dimension,
            hamming_weight,
            copy_count,
            ngsw_len,
        };
        let initializer = self.generate_initializer(&accumulator_ntt, rng);
        let key_switching_key = NttNtruKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            &client_ntt,
            parameters.ntru_key_switching(),
            ntt,
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
