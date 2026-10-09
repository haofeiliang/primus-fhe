//! Shared client-side chunk packing; no table or transform state is retained.

use primus_integer::{FheUint, UnsignedInteger};
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweCiphertext};
use primus_tfhe_ntru::{ClientKey, PbsParameters, TfheClientError};

use crate::{ChunkFormat, config::LookupDomain};

/// Invalid complete integer/chunk request or incompatible external LWE client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HighPrecLutClientError {
    /// The external secret, encoding or ciphertext dimension is incompatible.
    #[error(transparent)]
    Client(#[from] TfheClientError),
    /// A request supplied the wrong complete chunk count.
    #[error("chunk count mismatch: expected {expected}, got {actual}")]
    ChunkCountMismatch {
        /// Configured input or output count.
        expected: usize,
        /// Supplied count.
        actual: usize,
    },
    /// The chosen integer cannot hold the complete configured value.
    #[error("value needs {required} bits, but the integer holds {available}")]
    WordCapacity {
        /// Configured complete value width.
        required: u32,
        /// Chosen cleartext integer capacity.
        available: u32,
    },
    /// An integer exceeds the complete input domain.
    #[error("value exceeds the input bit count")]
    ValueOutOfRange,
    /// A supplied or decoded digit is outside 0..M.
    #[error("chunk {index} is outside the unsigned radix")]
    ChunkOutOfRange {
        /// Least-significant-first digit index.
        index: usize,
    },
}

impl From<ClientError> for HighPrecLutClientError {
    fn from(error: ClientError) -> Self {
        Self::Client(error.into())
    }
}

/// Encrypts one integer as independently encrypted least-significant-first chunks.
/// Borrows only the external secret and its fresh noise sampler; no LUT, ring
/// secret, transform, server key or digit buffer is retained.
pub struct HighPrecLutEncryptor<'a, T: FheUint, LM: RingContext<T>> {
    inner: Encryptor<'a, T, LM>,
    chunks: ChunkFormat,
    chunk_count: usize,
    bit_count: u32,
    dimension: usize,
}

impl<T: FheUint, LM: RingContext<T>> HighPrecLutEncryptor<'_, T, LM> {
    /// Allocates zero LWE storage for the complete input; this does not encrypt.
    #[must_use]
    pub fn allocate_input(&self) -> Vec<LweCiphertext<T>> {
        (0..self.chunk_count)
            .map(|_| LweCiphertext::zero(self.dimension))
            .collect()
    }

    /// Splits and encrypts an unsigned integer without an intermediate digit buffer.
    /// W is independent of the ciphertext coefficient type.
    /// Count, dimension, capacity and value errors leave output and RNG unchanged.
    /// Does not allocate; reuse allocate_input's result across requests.
    ///
    /// # Correctness
    /// The complete request inherits one-hot CBS's quantized-phase guard and
    /// Encryptor::encrypt_padded_to's fresh-noise requirements.
    ///
    /// # Panics
    /// A panicking RNG can leave partially encrypted output.
    pub fn encrypt_to<W: UnsignedInteger, R: rand::Rng + rand::CryptoRng>(
        &self,
        value: W,
        output: &mut [LweCiphertext<T>],
        rng: &mut R,
    ) -> Result<(), HighPrecLutClientError> {
        check_capacity::<W>(self.bit_count)?;
        if self.bit_count < W::BITS && value >> self.bit_count != W::ZERO {
            return Err(HighPrecLutClientError::ValueOutOfRange);
        }
        check_ciphertexts(output, self.chunk_count, self.dimension)?;
        for (index, ciphertext) in output.iter_mut().enumerate() {
            let digit: usize = self
                .chunks
                .chunk(value, index)
                .try_into()
                .expect("host-sized radix");
            self.inner
                .encrypt_padded_to(T::as_from(digit), ciphertext.as_mut_view(), rng)?;
        }
        Ok(())
    }

    /// Encrypts a complete digit slice, including values wider than one integer.
    /// Validates every digit and ciphertext before writing or consuming RNG.
    /// Shares encrypt_to's noise and RNG-panic contracts; allocates nothing.
    pub fn encrypt_chunks_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        input: &[T],
        output: &mut [LweCiphertext<T>],
        rng: &mut R,
    ) -> Result<(), HighPrecLutClientError> {
        check_count(input.len(), self.chunk_count)?;
        check_ciphertexts(output, self.chunk_count, self.dimension)?;
        let radix = T::as_from(self.chunks.radix());
        for (index, &digit) in input.iter().enumerate() {
            if digit >= radix {
                return Err(HighPrecLutClientError::ChunkOutOfRange { index });
            }
        }
        for (&digit, ciphertext) in input.iter().zip(output) {
            self.inner
                .encrypt_padded_to(digit, ciphertext.as_mut_view(), rng)?;
        }
        Ok(())
    }
}

/// Decodes returned chunks at q and joins them without a temporary digit buffer.
/// Copies the prepared Rounded decoder and borrows only the external secret.
/// Construction and decryption do not depend on a public function or LUT.
pub struct HighPrecLutDecryptor<'a, T: FheUint, LM: RingContext<T>> {
    inner: Decryptor<'a, T, LM>,
    chunks: ChunkFormat,
    chunk_count: usize,
    bit_count: u32,
    dimension: usize,
}

impl<T: FheUint, LM: RingContext<T>> HighPrecLutDecryptor<'_, T, LM> {
    /// Decodes a complete unsigned integer of the chosen cleartext type W.
    /// Exact word capacity is legal; rejects narrow W and decoded digits >=M.
    /// Does not silently truncate, mask invalid digits or allocate.
    ///
    /// # Correctness
    /// Inputs must use the paired external secret and canonical q-domain residues.
    /// Every digit must satisfy the lookup's joint decoding budget, including CBS,
    /// lift/products/rotations, Q→q return and key-switch noise.
    pub fn decrypt<W: UnsignedInteger>(
        &self,
        input: &[LweCiphertext<T>],
    ) -> Result<W, HighPrecLutClientError> {
        check_capacity::<W>(self.bit_count)?;
        check_ciphertexts(input, self.chunk_count, self.dimension)?;
        let mut value = W::ZERO;
        for (index, ciphertext) in input.iter().enumerate() {
            let digit = self.decode_digit(ciphertext, index)?;
            let digit: usize = digit.try_into().expect("host-sized radix");
            value |= W::try_from(digit).expect("checked word capacity")
                << (index as u32 * self.chunks.bits());
        }
        Ok(value)
    }

    /// Decodes into caller-owned least-significant-first digits, allowing wide outputs.
    /// All counts/dimensions are checked before writing. An invalid decoded digit
    /// leaves the preceding digits written; callers must discard that partial result.
    /// Shares decrypt's numerical requirements; allocates nothing.
    pub fn decrypt_chunks_to(
        &self,
        input: &[LweCiphertext<T>],
        output: &mut [T],
    ) -> Result<(), HighPrecLutClientError> {
        check_count(output.len(), self.chunk_count)?;
        check_ciphertexts(input, self.chunk_count, self.dimension)?;
        for (index, (ciphertext, digit)) in input.iter().zip(output).enumerate() {
            *digit = self.decode_digit(ciphertext, index)?;
        }
        Ok(())
    }

    /// Rejects the unused padded half; masking it would turn a decoding failure into a value.
    fn decode_digit(
        &self,
        ciphertext: &LweCiphertext<T>,
        index: usize,
    ) -> Result<T, HighPrecLutClientError> {
        let digit = self.inner.decrypt(ciphertext.as_view())?;
        if digit >= T::as_from(self.chunks.radix()) {
            return Err(HighPrecLutClientError::ChunkOutOfRange { index });
        }
        Ok(digit)
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> LookupDomain<T, M, LM> {
    /// Binds the existing input codec/sampler and checks only the selected external secret.
    pub(crate) fn encryptor<'a>(
        &self,
        parameters: &'a PbsParameters<T, M, LM>,
        key: &'a ClientKey<T>,
    ) -> Result<HighPrecLutEncryptor<'a, T, LM>, HighPrecLutClientError> {
        Ok(HighPrecLutEncryptor {
            inner: parameters
                .encryptor_with_codec(key.external_lwe_secret_key(), self.codecs.input_codec())?,
            chunks: self.layout.chunk_format,
            chunk_count: self.layout.config.input_chunk_count,
            bit_count: self.layout.input_bits,
            dimension: parameters.external_lwe_dimension().get(),
        })
    }

    /// Copies output decoding state; the returned client need not borrow the context or table.
    pub(crate) fn decryptor<'a>(
        &self,
        parameters: &PbsParameters<T, M, LM>,
        key: &'a ClientKey<T>,
    ) -> Result<HighPrecLutDecryptor<'a, T, LM>, HighPrecLutClientError> {
        Ok(HighPrecLutDecryptor {
            inner: parameters
                .decryptor_with_codec(key.external_lwe_secret_key(), self.codecs.output_codec())?,
            chunks: self.layout.chunk_format,
            chunk_count: self.layout.config.output_chunk_count,
            bit_count: self.layout.output_bits,
            dimension: parameters.external_lwe_dimension().get(),
        })
    }
}

/// Checks complete representation capacity before any shift or output write.
fn check_capacity<W: UnsignedInteger>(required: u32) -> Result<(), HighPrecLutClientError> {
    if required > W::BITS {
        return Err(HighPrecLutClientError::WordCapacity {
            required,
            available: W::BITS,
        });
    }
    Ok(())
}

/// Checks the full batch, including a malformed last ciphertext, before starting encryption.
fn check_ciphertexts<T: FheUint>(
    input: &[LweCiphertext<T>],
    count: usize,
    dimension: usize,
) -> Result<(), HighPrecLutClientError> {
    check_count(input.len(), count)?;
    for ciphertext in input {
        if ciphertext.as_ref().len() != dimension + 1 {
            return Err(ClientError::CiphertextDimensionMismatch {
                expected: dimension,
                actual: ciphertext.as_ref().len().saturating_sub(1),
            }
            .into());
        }
    }
    Ok(())
}

/// Count checks precede zip, which would otherwise silently consume only a common prefix.
fn check_count(actual: usize, expected: usize) -> Result<(), HighPrecLutClientError> {
    if actual != expected {
        return Err(HighPrecLutClientError::ChunkCountMismatch { expected, actual });
    }
    Ok(())
}
