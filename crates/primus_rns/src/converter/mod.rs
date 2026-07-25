mod exact;
mod fast;
pub use exact::ExactConversionContext;

use primus_integer::FheUint;
use primus_modulo::Modulo;
use primus_reduce::FieldContext;

use crate::RNSBase;

/// Precomputed converter between two RNS bases.
///
/// The converter owns cloned input and output bases and stores the matrix
/// `(Q / q_i) mod p_j`, where `q_i` are input-base moduli, `p_j` are output-base
/// moduli, and `Q` is the input-base product.
///
/// Batched conversion APIs take input and output residue arrays in modulus-major
/// layout. Their scratch buffer uses a different coefficient-major layout:
/// chunk `j` of length `input_moduli_count()` stores all adjusted input
/// residues for coefficient `j`.
#[derive(Clone)]
pub struct BaseConverter<T: FheUint, M: FieldContext<T>> {
    /// Source basis for incoming residues.
    input_base: RNSBase<T, M>,
    /// Destination basis for converted residues.
    output_base: RNSBase<T, M>,
    /// Row-major output-by-input base-change matrix.
    ///
    /// The slice length is `input_moduli_count() * output_moduli_count()`.
    /// Row `j` contains coefficients for output modulus `output_base.moduli()[j]`.
    base_change_matrix: Vec<T>,
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Creates a converter from references; clones both bases.
    ///
    /// See [`from_owned_bases`](Self::from_owned_bases) for the owned variant.
    pub fn new(input_base: &RNSBase<T, M>, output_base: &RNSBase<T, M>) -> Self {
        Self::from_owned_bases(input_base.clone(), output_base.clone())
    }

    /// Creates a converter from owned bases.
    ///
    /// Takes ownership of `input_base` and `output_base` instead of cloning,
    /// avoiding two `RNSBase` allocations when the caller already owns them.
    ///
    /// # Panics
    ///
    /// Panics if the base-change matrix length overflows `usize`.
    pub fn from_owned_bases(input_base: RNSBase<T, M>, output_base: RNSBase<T, M>) -> Self {
        let input_moduli_count = input_base.moduli_count();
        let output_moduli_count = output_base.moduli_count();

        assert!(
            input_moduli_count
                .checked_mul(output_moduli_count)
                .is_some(),
            "the len can not be too large!"
        );

        let mut base_change_matrix = vec![T::ZERO; input_moduli_count * output_moduli_count];

        for (row, &pj) in base_change_matrix
            .chunks_exact_mut(input_moduli_count)
            .zip(output_base.moduli())
        {
            for (q_div_qi_mod_pj, q_div_qi) in
                row.iter_mut().zip(input_base.iter_punctured_product())
            {
                *q_div_qi_mod_pj = q_div_qi.modulo(pj);
            }
        }

        Self {
            input_base,
            output_base,
            base_change_matrix,
        }
    }

    /// Returns the input basis.
    pub fn input_base(&self) -> &RNSBase<T, M> {
        &self.input_base
    }

    /// Returns the output basis.
    pub fn output_base(&self) -> &RNSBase<T, M> {
        &self.output_base
    }

    /// Returns the number of moduli in the input basis.
    pub fn input_moduli_count(&self) -> usize {
        self.input_base.moduli_count()
    }

    /// Returns the number of moduli in the output basis.
    pub fn output_moduli_count(&self) -> usize {
        self.output_base.moduli_count()
    }

    /// Iterates over the output-by-input base-change matrix rows.
    ///
    /// The iterator yields `output_moduli_count()` rows. Each row has
    /// `input_moduli_count()` entries and corresponds to one output modulus.
    fn iter_base_change_matrix(&self) -> std::slice::ChunksExact<'_, T> {
        self.base_change_matrix
            .chunks_exact(self.input_moduli_count())
    }
}
