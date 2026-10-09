//! CBS programs keep their gadget basis so binding cannot confuse equal level
//! counts with equal scales. Polynomial geometry comes from the ManyLUT compiler.

use core::cell::Cell;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_poly::{PolyLength, PolynomialOwned};
use primus_reduce::RingContext;

use super::{InterleavedLookupTable, front_half_domain_len};
use crate::LookupTableError;

/// A gadget-scaled CBS program computing one integer function `F(m)`.
///
/// Lane `j` contains `g_j * F(m) mod Q` for output basis scalar `g_j`.
/// The unsigned Rounded input domain is exactly `0..ceil(t_in/2)`; its q and
/// accumulator Q may differ. Interleaving, repetitions and zero padding use
/// [`InterleavedLookupTable`]'s geometry. The polynomial and basis cannot be
/// independently replaced, so a raw message LUT cannot be bound as a CBS program.
///
/// Results are canonical ring integers, not Rounded/Scaled codec outputs.
/// CMux requires `F(m)` in `{0, 1}` throughout the programmed input domain.
/// Other results can be consumed by external products with an appropriate
/// multiplication/noise budget. Compilation does not establish such a budget.
#[derive(Clone, Debug)]
pub struct CircuitBootstrapLookupTable<T: FheUint> {
    lookup_table: InterleavedLookupTable<T>,
    output_basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> CircuitBootstrapLookupTable<T> {
    /// Compiles `F(m)` into all output gadget lanes.
    ///
    /// Checks the basis modulus, input geometry and interleaved capacity before
    /// calling `function`. It is called once per input in increasing order.
    /// Explicit Q requires each result `< Q`; Native accepts every word value.
    /// Invalid results return [`LookupTableError::EncodedOutputOutOfRange`].
    /// No partial program is returned. Prefer the family CBS parameter factory,
    /// which also supplies its accumulator geometry and output basis.
    pub fn try_from_fn<LM, M, F>(
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        LM: RingContext<T>,
        M: RingContext<T>,
        F: Fn(usize) -> T,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        Self::compile(
            domain_len,
            poly_length,
            input_codec,
            output_basis,
            coefficient_modulus,
            function,
        )
    }

    /// Compiles the complete `F(0), ..., F(ceil(t_in/2)-1)` slice.
    /// Inherits [`Self::try_from_fn`]'s result and geometry contracts; rejects
    /// both missing and extra entries with [`LookupTableError::DomainLengthMismatch`].
    pub fn try_from_slice<LM, M>(
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        values: &[T],
    ) -> Result<Self, LookupTableError>
    where
        LM: RingContext<T>,
        M: RingContext<T>,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        if values.len() != domain_len {
            return Err(LookupTableError::DomainLengthMismatch {
                expected: domain_len,
                actual: values.len(),
            });
        }
        Self::compile(
            domain_len,
            poly_length,
            input_codec,
            output_basis,
            coefficient_modulus,
            |input| values[input],
        )
    }

    /// Uses the checked input-major ManyLUT callback to evaluate each input only
    /// at its first lane. Reusing that value makes all levels represent the same
    /// F(m), even if the supplied Fn observes interior mutable state.
    fn compile<LM, M, F>(
        domain_len: usize,
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, LM>,
        output_basis: &ApproxSignedBasis<T>,
        coefficient_modulus: M,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        LM: RingContext<T>,
        M: RingContext<T>,
        F: Fn(usize) -> T,
    {
        let q = coefficient_modulus.explicit_value();
        if output_basis.modulus() != q {
            return Err(LookupTableError::OutputBasisModulusMismatch);
        }
        let scalars: Vec<T> = output_basis.scalar_iter().collect();
        let value = Cell::new(T::ZERO);
        let lookup_table = InterleavedLookupTable::try_new(
            domain_len,
            poly_length,
            scalars.len(),
            input_codec.plaintext_modulus(),
            input_codec.ciphertext_modulus(),
            coefficient_modulus,
            |input, level| {
                if level == 0 {
                    let result = function(input);
                    // Check F itself: modular multiplication would hide an
                    // out-of-range result in an otherwise canonical coefficient.
                    if q.is_some_and(|q| result >= q) {
                        return Err(LookupTableError::EncodedOutputOutOfRange { input });
                    }
                    value.set(result);
                }
                Ok(coefficient_modulus.reduce_mul(scalars[level], value.get()))
            },
        )?;
        Ok(Self {
            lookup_table,
            output_basis: output_basis.clone(),
        })
    }

    /// Checks accumulator geometry, external q, ring Q and the exact gadget basis.
    /// Input t and the complete front-half geometry were fixed at compilation.
    /// This does not establish ciphertext encoding, secret/transform identity or noise.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: PolyLength,
        input_ciphertext_modulus: Option<T>,
        output_basis: &ApproxSignedBasis<T>,
    ) -> bool {
        self.output_basis == *output_basis
            && self.lookup_table.is_compatible_with_ciphertext_domain(
                poly_length,
                input_ciphertext_modulus,
                output_basis.modulus(),
            )
    }

    /// Returns the interleaved gadget-scaled coefficient polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        self.lookup_table.polynomial()
    }

    /// Returns the complete programmed input-domain length `ceil(t_in/2)`.
    #[must_use]
    #[inline]
    pub fn input_domain_len(&self) -> usize {
        self.lookup_table.input_domain_len()
    }

    /// Returns the Rounded input message modulus that fixes this program's intervals.
    /// A default Context binding compares this with its configured input encoding;
    /// equal domain lengths alone do not establish the same intervals.
    #[must_use]
    pub fn input_plaintext_modulus(&self) -> T {
        self.lookup_table.input_plaintext_modulus()
    }

    /// Returns the rotation stride, including padding after the effective gadget levels.
    #[must_use]
    #[inline]
    pub fn padded_output_count(&self) -> usize {
        self.lookup_table.padded_output_count()
    }

    /// Returns the gadget basis used to compile every output lane.
    #[must_use]
    #[inline]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }
}
