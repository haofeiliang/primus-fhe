//! Compiled lookup tables, their construction APIs and encoding metadata.

mod compile;

use core::fmt;

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};

use crate::LookupTableError;
use compile::{compile_encoded_polynomial, validate_compilation};

pub use compile::lookup_table_domain_len;

/// A lookup table compiled into an encoded negacyclic polynomial.
///
/// An execution backend embeds this polynomial into its accumulator
/// representation when blind rotation begins. Compilation binds the input's
/// unsigned rounded encoding and both ciphertext moduli. Output residues may
/// use a different scale, as required by Boolean and circuit bootstrapping.
/// The table does not bind a secret key, ciphertext dimension or backend.
#[derive(Clone)]
pub struct LookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    input_domain_len: usize,
    encoding: LookupTableEncoding<T>,
}

impl<T: FheUint> fmt::Debug for LookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("input_domain_len", &self.input_domain_len)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> LookupTable<T> {
    /// Compiles already encoded outputs into a negacyclic lookup-table polynomial.
    ///
    /// The input uses unsigned rounded encoding with
    /// `input_plaintext_modulus` and `lwe_modulus`; raw outputs must be canonical
    /// accumulator residues but may use any output scale. `domain_len` is a non-empty
    /// prefix of the independently programmable front half. Only `0..domain_len`
    /// has callback-defined values; the unprogrammed tail is not an additional
    /// function domain. Invalid encoding, layout, rotation centers or outputs return
    /// an error.
    pub fn try_new<LM, M, F>(
        domain_len: usize,
        poly_length: usize,
        input_plaintext_modulus: T,
        lwe_modulus: LM,
        accumulator_modulus: M,
        encoded_output_at: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
        F: Fn(usize) -> Result<T, LookupTableError>,
    {
        validate_compilation(
            domain_len,
            poly_length,
            input_plaintext_modulus,
            lwe_modulus.explicit_value(),
        )?;
        let polynomial = compile_encoded_polynomial(
            domain_len,
            poly_length,
            1,
            input_plaintext_modulus,
            lwe_modulus,
            accumulator_modulus,
            |input, _| encoded_output_at(input),
        )?;
        Ok(Self {
            polynomial,
            input_domain_len: domain_len,
            encoding: LookupTableEncoding {
                input_plaintext_modulus,
                input_ciphertext_modulus: lwe_modulus.explicit_value(),
                accumulator_modulus: accumulator_modulus.explicit_value(),
            },
        })
    }

    /// Returns the length of the programmed input prefix `0..D`.
    #[must_use]
    #[inline]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Checks the polynomial length and input/accumulator encoding domains.
    ///
    /// Output scale is not compared: raw Boolean and gadget-scaled outputs
    /// need not use the input plaintext codec. This does not validate the key,
    /// noise or actual plaintext of a raw input ciphertext. The caller must
    /// respect the table's [`Self::input_domain_len`], which may be a shorter prefix.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        accumulator_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length
            && self.encoding.is_compatible(
                input_plaintext_modulus,
                input_ciphertext_modulus,
                accumulator_modulus,
            )
    }

    /// Returns the encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Decomposes this table into its encoded polynomial.
    #[must_use]
    #[inline]
    pub fn into_polynomial(self) -> PolynomialOwned<T> {
        self.polynomial
    }
}

/// Multiple lookup tables interleaved into one negacyclic accumulator.
///
/// For `k = output_count` outputs, the stride is `s = next_power_of_two(k)`.
/// Blind rotation quantizes every rotation exponent to a multiple of `s`, so
/// each residue class contains an
/// independently programmable lookup table. This reduces the rotation resolution
/// and increases per-coefficient modulus-switch rounding error; it does not make
/// arbitrary full-domain functions programmable. Outputs are extracted at
/// coefficients `0..k`; padding slots `k..s` contain zero.
#[derive(Clone)]
pub struct InterleavedLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    input_domain_len: usize,
    encoding: LookupTableEncoding<T>,
    output_count: usize,
}

impl<T: FheUint> fmt::Debug for InterleavedLookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterleavedLookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("input_domain_len", &self.input_domain_len)
            .field("encoding", &self.encoding)
            .field("output_count", &self.output_count)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> InterleavedLookupTable<T> {
    /// Compiles encoded multi-output values into an interleaved negacyclic lookup
    /// table.
    ///
    /// Inherits [`LookupTable::try_new`]'s encoding and output contracts.
    /// `output_count` must be nonzero. Its next power of two is the interleaving
    /// stride `s`, and the programmed input domain must fit in `poly_length / s`.
    /// Each row contains the `output_count` function values followed by zero
    /// padding up to `s` slots. The callback runs once per effective output and
    /// input, in input-major order; it is never called for padding slots.
    /// Callback errors and noncanonical outputs stop compilation; no partial
    /// table is returned.
    pub fn try_new<LM, M, F>(
        domain_len: usize,
        poly_length: usize,
        output_count: usize,
        input_plaintext_modulus: T,
        lwe_modulus: LM,
        accumulator_modulus: M,
        encoded_output_at: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
        F: Fn(usize, usize) -> Result<T, LookupTableError>,
    {
        validate_compilation(
            domain_len,
            poly_length,
            input_plaintext_modulus,
            lwe_modulus.explicit_value(),
        )?;
        if output_count == 0 {
            return Err(LookupTableError::EmptyOutputs);
        }
        if output_count > poly_length {
            return Err(LookupTableError::OutputCountTooLarge {
                output_count,
                poly_length,
            });
        }

        let stride = output_count.next_power_of_two();
        let virtual_poly_length = poly_length / stride;
        if domain_len > virtual_poly_length {
            return Err(LookupTableError::PlaintextDomainTooLarge {
                domain_len,
                rotation_domain_len: virtual_poly_length,
            });
        }

        let polynomial = compile_encoded_polynomial(
            domain_len,
            poly_length,
            output_count,
            input_plaintext_modulus,
            lwe_modulus,
            accumulator_modulus,
            encoded_output_at,
        )?;

        Ok(Self {
            polynomial,
            input_domain_len: domain_len,
            encoding: LookupTableEncoding {
                input_plaintext_modulus,
                input_ciphertext_modulus: lwe_modulus.explicit_value(),
                accumulator_modulus: accumulator_modulus.explicit_value(),
            },
            output_count,
        })
    }

    /// Returns the length of the programmed input prefix `0..D`.
    #[must_use]
    #[inline]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Checks the polynomial length and input/accumulator encoding domains.
    ///
    /// Output scale is not compared: raw Boolean and gadget-scaled outputs
    /// need not use the input plaintext codec. This does not validate the key,
    /// noise or actual plaintext of a raw input ciphertext. The caller must
    /// respect the table's [`Self::input_domain_len`], which may be a shorter prefix.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        accumulator_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length
            && self.encoding.is_compatible(
                input_plaintext_modulus,
                input_ciphertext_modulus,
                accumulator_modulus,
            )
    }

    /// Returns the interleaved encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns the number of independently programmable outputs.
    #[must_use]
    #[inline]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// Returns the power-of-two spacing between rows of output slots.
    #[must_use]
    #[inline]
    pub fn stride(&self) -> usize {
        self.output_count.next_power_of_two()
    }

    /// Decomposes this table into its polynomial and effective output count.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (PolynomialOwned<T>, usize) {
        (self.polynomial, self.output_count)
    }
}

// The input encoding determines rotation centers; the accumulator modulus
// determines coefficient arithmetic. Output scale is deliberately independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LookupTableEncoding<T: FheUint> {
    input_plaintext_modulus: T,
    input_ciphertext_modulus: Option<T>,
    accumulator_modulus: Option<T>,
}

impl<T: FheUint> LookupTableEncoding<T> {
    fn is_compatible(
        &self,
        input_plaintext_modulus: T,
        input_modulus: Option<T>,
        accumulator_modulus: Option<T>,
    ) -> bool {
        self.input_plaintext_modulus == input_plaintext_modulus
            && self.input_ciphertext_modulus == input_modulus
            && self.accumulator_modulus == accumulator_modulus
    }
}
