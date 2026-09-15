use super::{LwePublicKey, ROWS_PER_BLOCK};
use crate::batch::{batch_len, check_batch};
use crate::{LweParameters, PlaintextEmbedding};
use primus_distr::{DiscreteGaussian, sample_sparse_ternary_values_to};
use primus_integer::FheUint;
use primus_lattice::lwe::LweIterMut;
use primus_reduce::RingContext;
use rand::distr::Distribution;

// At u32 dimensions 512/1024, 8 outperformed 4, while 16 lost cache
// locality at 1024. Keep this internal; remeasure with benches/public_key.rs.
const TILE_COUNT: usize = 8;

impl<T: FheUint> LwePublicKey<T> {
    /// Encrypts independent messages with unsigned embedding in one allocation.
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts.
    #[must_use]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_batch_with_embedding(messages, params, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts independent messages with unsigned embedding into existing storage.
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts.
    pub fn encrypt_batch_to<M, R>(
        &self,
        messages: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_batch_with_embedding_to(
            messages,
            output,
            params,
            rng,
            PlaintextEmbedding::Unsigned,
        );
    }

    /// Allocates a contiguous batch using unsigned or centered embedding.
    ///
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts. Also panics
    /// if the total storage length overflows.
    #[must_use]
    pub fn encrypt_batch_with_embedding<M, R>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), messages.len())];
        self.encrypt_batch_with_embedding_to(messages, &mut output, params, rng, embedding);
        output
    }

    /// Encodes and initializes messages within each tile, then accumulates public-key rows.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering is not guaranteed to match repeated single-message calls.
    /// Both embeddings accept canonical residues in `[0,t)`.
    /// Output contains `messages.len()` consecutive `[mask, body]` chunks of
    /// length `self.dimension() + 1`; empty output is valid for empty messages.
    ///
    /// # Correctness
    ///
    /// The key, modulus and noise must satisfy [`Self::encrypt_with_embedding_to`].
    /// The batch count is unrestricted by the LWE dimension.
    ///
    /// # Panics
    ///
    /// Parameter dimension, output length, or modulus mismatches, and length
    /// overflow, panic before writing or sampling.
    /// Message range or RNG failures may leave partial output
    /// and consumed randomness. An interrupted tile may contain only noise and
    /// encoded messages, without the public-key row contributions.
    pub fn encrypt_batch_with_embedding_to<M, R>(
        &self,
        messages: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(
            params.dimension(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        check_batch(output, self.dimension(), messages.len());
        self.check_modulus(params.cipher_modulus());
        let plaintexts = messages
            .iter()
            .map(|&message| params.plaintext_codec().encode_value(message, embedding));
        self.encrypt_batch_iter_to(
            plaintexts,
            output,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        );
    }
}

impl<T: FheUint> LwePublicKey<T> {
    /// Encrypts canonical encoded residues into one newly allocated batch.
    /// See [`Self::encrypt_encoded_batch_to`] for contracts. Also panics if
    /// the total storage length overflows.
    #[must_use]
    pub fn encrypt_encoded_batch<M, R>(
        &self,
        plaintexts: &[T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), plaintexts.len())];
        self.encrypt_encoded_batch_to(plaintexts, &mut output, modulus, noise, rng);
        output
    }

    /// Encrypts canonical encoded residues into existing batch storage.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering need not match repeated single-message encryption.
    /// Output must contain exactly `plaintexts.len() * (self.dimension() + 1)`
    /// coefficients, with one `[mask, body]` chunk per plaintext.
    ///
    /// # Correctness
    ///
    /// Every plaintext, the key and samplers must satisfy [`Self::encrypt_encoded_to`].
    ///
    /// # Panics
    ///
    /// Output length or modulus mismatches, and length overflow, panic before
    /// writing or sampling.
    /// A panicking RNG can leave partial output.
    pub fn encrypt_encoded_batch_to<M, R>(
        &self,
        plaintexts: &[T],
        output: &mut [T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        check_batch(output, self.dimension(), plaintexts.len());
        self.check_modulus(modulus);
        self.encrypt_batch_iter_to(plaintexts.iter().copied(), output, modulus, noise, rng);
    }
}

impl<T: FheUint> LwePublicKey<T> {
    /// Encodes one tile at a time before encrypting it.
    /// Layout and modulus must be validated; the iterator must yield exactly
    /// one canonical residue per output chunk. Lazy encoding avoids a separate
    /// pass over the full output. Body writes stay local to the current tile,
    /// and each public-key row is reused across it.
    fn encrypt_batch_iter_to<M, R>(
        &self,
        mut plaintexts: impl Iterator<Item = T>,
        output: &mut [T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let row_len = self.dimension + 1;
        // Clamp before multiplication: even enormous dimensions cannot overflow
        // the tile length when a smaller output fits the validated allocation.
        let tile_count = (output.len() / row_len).min(TILE_COUNT);
        if tile_count == 0 {
            return;
        }
        for tile in output.chunks_mut(tile_count * row_len) {
            // Put the finite tile iterator first so zip never consumes a value
            // intended for the next tile when this tile is exhausted.
            for (mut ciphertext, plaintext) in
                LweIterMut::new(tile, row_len).zip(plaintexts.by_ref())
            {
                *ciphertext.b_mut() = plaintext;
            }
            self.encrypt_tile_bodies_assign(tile, modulus, noise, rng);
        }
    }

    /// Encrypts the encoded bodies in one validated tile. Separating this
    /// kernel keeps message-iterator state out of sampling and row accumulation.
    /// The tile contains 1..=TILE_COUNT ciphertexts. Sample all its Gaussian
    /// errors first, then ternary coefficients in row-major/ciphertext order.
    /// Discard unused random bits before the next tile's Gaussian sampling.
    fn encrypt_tile_bodies_assign<M, R>(
        &self,
        tile: &mut [T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let row_len = self.dimension + 1;
        for mut ciphertext in LweIterMut::new(tile, row_len) {
            let (mask, body) = ciphertext.a_b_mut();
            noise.sample_to(mask, rng);
            modulus.reduce_add_assign(body, noise.sample(rng));
        }
        let tile_count = tile.len() / row_len;
        let block_len = self.dimension.min(ROWS_PER_BLOCK) * row_len;
        let mut ephemeral = [0i8; ROWS_PER_BLOCK * TILE_COUNT];
        for rows in self.data.chunks(block_len) {
            // Sixteen rows use whole words even for a short ciphertext tile.
            let coefficients = &mut ephemeral[..rows.len() / row_len * tile_count];
            sample_sparse_ternary_values_to(coefficients, -1, rng);
            for (row, coefficients) in rows
                .chunks_exact(row_len)
                .zip(coefficients.chunks_exact(tile_count))
            {
                for (ciphertext, &coefficient) in tile.chunks_exact_mut(row_len).zip(coefficients) {
                    match coefficient {
                        1 => modulus.reduce_add_slice_assign(ciphertext, row),
                        -1 => modulus.reduce_sub_slice_assign(ciphertext, row),
                        _ => {}
                    }
                }
            }
        }
    }
}
