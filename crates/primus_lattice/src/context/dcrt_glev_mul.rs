use primus_integer::FheUint;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::RnsGadgetSize;

/// Reusable workspace for DCRT GLev decomposition and recomposition.
///
/// Each operation overwrites the internal buffers. A context may be reused
/// with another parameter set when all required workspace lengths match.
pub struct DcrtGlevMulContext<T: FheUint> {
    size: RnsGadgetSize,
    adjust_big_uint_values: Vec<T>,
    decomposed_unsigned_values: Vec<T>,
    carries: Vec<bool>,
    multi_residues: Vec<T>,
    compose_buffer: Vec<T>,
}

/// A mutable reference view of [`DcrtGlevMulContext`] fields, used to borrow all buffers simultaneously.
pub(crate) struct DcrtGlevMulContextRefMut<'a, T: FheUint> {
    /// Buffer for big integer values adjusted during decomposition.
    pub(crate) adjust_big_uint_values: &'a mut [T],
    /// Buffer for unsigned decomposed values.
    pub(crate) decomposed_unsigned_values: &'a mut [T],
    /// Buffer tracking carries during decomposition.
    pub(crate) carries: &'a mut [bool],
    /// Buffer for multi-residue values after CRT decomposition.
    pub(crate) multi_residues: &'a mut [T],
    /// Buffer for composing values across moduli.
    pub(crate) compose_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlevMulContext<T> {
    /// Creates reusable workspace for a checked RNS gadget layout and basis.
    pub fn new<M>(size: RnsGadgetSize, rns_base: &RNSBase<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let rns_glwe_size = size.rns_glwe_size();
        assert_eq!(rns_glwe_size.moduli_count(), rns_base.moduli_count());
        let poly_length = rns_glwe_size.poly_length();
        let big_uint_poly_len = poly_length * rns_base.big_uint_value_len();

        Self {
            size,
            adjust_big_uint_values: vec![T::ZERO; big_uint_poly_len],
            decomposed_unsigned_values: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            multi_residues: vec![T::ZERO; rns_glwe_size.rns_poly_len()],
            compose_buffer: vec![T::ZERO; rns_base.moduli_count()],
        }
    }

    /// Returns the RNS gadget sizes bound to this workspace.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGadgetSize {
        self.size
    }

    /// Returns a [`DcrtGlevMulContextRefMut`] that borrows all internal buffers mutably.
    #[inline]
    pub(crate) fn as_mut<'a>(&'a mut self) -> DcrtGlevMulContextRefMut<'a, T> {
        DcrtGlevMulContextRefMut {
            adjust_big_uint_values: &mut self.adjust_big_uint_values,
            decomposed_unsigned_values: &mut self.decomposed_unsigned_values,
            carries: &mut self.carries,
            multi_residues: &mut self.multi_residues,
            compose_buffer: &mut self.compose_buffer,
        }
    }

    /// Resets all buffers to their zero values.
    pub fn clear(&mut self) {
        self.adjust_big_uint_values.fill(T::ZERO);
        self.decomposed_unsigned_values.fill(T::ZERO);
        self.carries.fill(false);
        self.multi_residues.fill(T::ZERO);
        self.compose_buffer.fill(T::ZERO);
    }

    /// Returns a mutable reference to the compose buffer.
    pub fn compose_buffer_mut(&mut self) -> &mut [T] {
        &mut self.compose_buffer
    }
}
