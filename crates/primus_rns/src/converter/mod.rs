mod exact;
mod fast;
pub use exact::ExactConversionContext;
pub(crate) use fast::FastConversionLimb;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::RNSBase;

/// Precomputation selected from the source-base shape.
///
/// For a one-modulus source base, both the inverse punctured product and every
/// base-change matrix entry are one. Storing the general matrix in that case
/// would only allocate a vector of ones and route conversion through
/// one-element dot products.
#[derive(Clone)]
enum BaseConversionKernel<T> {
    SingleInput,
    General { base_change_matrix: Vec<T> },
}

/// Precomputed converter between two RNS bases.
///
/// The converter owns cloned input and output bases. A multi-modulus source
/// stores the matrix `(Q / q_i) mod p_j`, where `q_i` are input-base moduli,
/// `p_j` are output-base moduli, and `Q` is the input-base product. A
/// one-modulus source uses a direct-reduction kernel and stores no matrix.
///
/// # Fast conversion semantics
///
/// Let `a_i` be the input residues and define
/// `u_i = [a_i (Q / q_i)^(-1)] mod q_i`. For an input base with more than one
/// modulus, the [`Self::fast_convert`], [`Self::fast_convert_array`], and
/// [`Self::fast_convert_array_to_pair_iter`] methods compute
///
/// ```text
/// y_j = [sum_i u_i (Q / q_i)] mod p_j = [x + kQ] mod p_j
/// ```
///
/// for some integer `k`, where `x` has residues `a_i` in the input base. These
/// methods omit the quotient correction needed to select the canonical lift of
/// `x`, so `y_j` is not generally equal to `x mod p_j`. This SEAL-style
/// approximate conversion is intended for algorithms such as Hybrid ModDown
/// that cancel the multiple-of-`Q` term. For a one-modulus input base, the
/// specialized kernel directly reduces the input residue and is exact.
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
    kernel: BaseConversionKernel<T>,
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

        let kernel = if input_moduli_count == 1 {
            BaseConversionKernel::SingleInput
        } else {
            let mut base_change_matrix = vec![T::ZERO; input_moduli_count * output_moduli_count];

            for (row, &pj) in base_change_matrix
                .chunks_exact_mut(input_moduli_count)
                .zip(output_base.moduli())
            {
                for (q_div_qi_mod_pj, q_div_qi) in
                    row.iter_mut().zip(input_base.iter_punctured_product())
                {
                    *q_div_qi_mod_pj = pj.reduce(q_div_qi.digits());
                }
            }

            BaseConversionKernel::General { base_change_matrix }
        };

        Self {
            input_base,
            output_base,
            kernel,
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
    ///
    /// # Panics
    ///
    /// Panics when called for the single-input kernel, which has no matrix.
    fn iter_base_change_matrix(&self) -> std::slice::ChunksExact<'_, T> {
        let base_change_matrix = match &self.kernel {
            BaseConversionKernel::SingleInput => {
                panic!("single-input base conversion has no base-change matrix")
            }
            BaseConversionKernel::General { base_change_matrix } => base_change_matrix,
        };
        base_change_matrix.chunks_exact(self.input_moduli_count())
    }

    #[inline]
    fn uses_single_input_kernel(&self) -> bool {
        matches!(&self.kernel, BaseConversionKernel::SingleInput)
    }
}
