use num_complex::Complex64;

use crate::{FftError, TorusFftValue};

/// Negacyclic FFT wrapper for polynomials modulo `X^N + 1`.
pub trait FftTable: Send + Sync {
    /// Backend-specific reusable transform workspace.
    type Scratch;

    /// Creates a table for `N = 2^log_n` coefficients.
    fn new(log_n: u32) -> Result<Self, FftError>
    where
        Self: Sized;
    /// Returns the coefficient polynomial length `N`.
    fn poly_length(&self) -> usize;
    /// Returns the number of complex Fourier values, `N / 2`.
    fn fourier_length(&self) -> usize;
    /// Allocates a workspace compatible with this table.
    fn new_scratch(&self) -> Self::Scratch;
    /// Transforms torus coefficients, scaled by `2^-BITS`, to Fourier form.
    fn forward_as_torus<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    );
    /// Transforms signed integer bit patterns without torus scaling.
    fn forward_as_integer<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    );
    /// Transforms ordinary integer-valued floating point coefficients.
    fn forward_integer_f64(
        &self,
        input: &[f64],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    );
    /// Converts Fourier form back to torus coefficients.
    fn backward_as_torus<T: TorusFftValue>(
        &self,
        input: &[Complex64],
        output: &mut [T],
        scratch: &mut Self::Scratch,
    );
}

/// An immutable FFT table bound to one reusable scratch allocation.
///
/// Multiple engines may share the same table across threads without locking
/// transform calls.
pub struct FftEngine<'a, Table: FftTable + ?Sized> {
    table: &'a Table,
    scratch: Table::Scratch,
}

impl<'a, Table: FftTable + ?Sized> FftEngine<'a, Table> {
    /// Creates an engine with a fresh backend workspace.
    #[inline]
    pub fn new(table: &'a Table) -> Self {
        Self {
            table,
            scratch: table.new_scratch(),
        }
    }

    /// Creates an engine from an existing compatible workspace.
    #[inline]
    pub fn from_scratch(table: &'a Table, scratch: Table::Scratch) -> Self {
        Self { table, scratch }
    }

    /// Returns the shared immutable table.
    #[inline]
    pub fn table(&self) -> &'a Table {
        self.table
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.table.poly_length()
    }

    /// Returns the number of complex Fourier values.
    #[inline]
    pub fn fourier_length(&self) -> usize {
        self.table.fourier_length()
    }

    /// Transforms torus coefficients to Fourier form.
    #[inline]
    pub fn forward_as_torus<T: TorusFftValue>(&mut self, input: &[T], output: &mut [Complex64]) {
        self.table
            .forward_as_torus(input, output, &mut self.scratch);
    }

    /// Transforms signed integer bit patterns without torus scaling.
    #[inline]
    pub fn forward_as_integer<T: TorusFftValue>(&mut self, input: &[T], output: &mut [Complex64]) {
        self.table
            .forward_as_integer(input, output, &mut self.scratch);
    }

    /// Transforms ordinary integer-valued floating point coefficients.
    #[inline]
    pub fn forward_integer_f64(&mut self, input: &[f64], output: &mut [Complex64]) {
        self.table
            .forward_integer_f64(input, output, &mut self.scratch);
    }

    /// Converts Fourier form back to torus coefficients.
    #[inline]
    pub fn backward_as_torus<T: TorusFftValue>(&mut self, input: &[Complex64], output: &mut [T]) {
        self.table
            .backward_as_torus(input, output, &mut self.scratch);
    }

    /// Splits the engine into its table reference and reusable workspace.
    #[inline]
    pub fn into_parts(self) -> (&'a Table, Table::Scratch) {
        (self.table, self.scratch)
    }
}
