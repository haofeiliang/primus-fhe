//! Hybrid RNS gadget infrastructure for key switching.
//!
//! The module provides [`HybridRNS`], which partitions an RNS ciphertext
//! modulus basis `Q` into groups and pairs each group with an auxiliary
//! modulus basis `P`.  Together they enable digit-based key switching that
//! operates entirely in the CRT domain (no big-integer reconstruction).
//!
//! # References
//!
//! - OpenFHE `keyswitch-hybrid.cpp` (`KeySwitchHYBRID`)
//! - SEAL `rns.h` (`RNSTool`, `BaseConverter`)

use core::ops::Range;

use primus_integer::{BigUint, FheUint};
use primus_modulo::prelude::*;
use primus_reduce::FieldContext;

use crate::base::RNSBase;
use crate::converter::BaseConverter;
use crate::error::RNSError;

/// A contiguous group of `Q`-basis modulus indices.
#[derive(Clone, Debug)]
pub struct Partition {
    /// Index range into the `Q` basis moduli slice.
    pub q_indices: Range<usize>,
}

/// Precomputed hybrid RNS parameters for gadget key switching.
///
/// `HybridRNS` owns three bases (`Q`, auxiliary `P`, and the combined `QP`),
/// a partition of `Q` into `D` groups, and all ModUp / ModDown converters
/// needed by the online key-switching procedure.
#[derive(Clone)]
pub struct HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// The original ciphertext-modulus basis.
    q_base: RNSBase<T, M>,

    /// The auxiliary basis (product `P`).
    p_base: RNSBase<T, M>,

    /// The combined `Q ∪ P` basis.
    qp_base: RNSBase<T, M>,

    /// Partition of the `Q` modulus indices.
    partitions: Vec<Partition>,

    // ---- gadget scalars --------------------------------------------------
    /// Flat array of gadget scalar CRT residues for every partition.
    ///
    /// Length = `D * qp_moduli_count`.  Row `j` stores `λ_j`: `P mod q_i`
    /// on its own partition's `q` limbs and 0 elsewhere.
    gadget_scalar_residues: Vec<T>,

    // ---- precomputed constants --------------------------------------------
    /// `P mod q_i` for each `q_i` in the `Q` basis.
    p_mod_q: Vec<T>,

    /// `P⁻¹ mod q_i` for each `q_i` in the `Q` basis (used in ModDown).
    p_inv_mod_q: Vec<T>,

    // ---- converters -------------------------------------------------------
    /// One converter per partition: `Q_j → complement(Q) ∪ P`.
    mod_up_converters: Vec<BaseConverter<T, M>>,

    /// Converter for ModDown: `P → Q`.
    mod_down_converter: BaseConverter<T, M>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a hybrid RNS gadget from `Q`-basis and `P`-basis moduli.
    ///
    /// `num_part_q` controls how many partitions the `Q` modulus indices are
    /// split into.  Each partition gets roughly `⌈L / num_part_q⌉` moduli,
    /// where `L` is the number of `Q` moduli.
    pub fn new(q_moduli: &[M], p_moduli: &[M], num_part_q: usize) -> Result<Self, RNSError> {
        let q_base = RNSBase::new(q_moduli)?;
        let p_base = RNSBase::new(p_moduli)?;

        // Build QP = Q ∪ P
        let qp_moduli: Vec<M> = q_moduli.iter().chain(p_moduli.iter()).copied().collect();
        let qp_base = RNSBase::new(&qp_moduli)?;

        let l = q_moduli.len();
        let d = num_part_q.min(l);
        if d == 0 {
            return Err(RNSError::EmptyBase);
        }

        // --- partitions ----------------------------------------------------
        let bucket_size = l.div_ceil(d);
        let partitions: Vec<Partition> = (0..d)
            .map(|j| {
                let start = bucket_size * j;
                let end = (start + bucket_size).min(l);
                Partition {
                    q_indices: start..end,
                }
            })
            .collect();

        // --- P mod q_i, P⁻¹ mod q_i ---------------------------------------
        let BigUint(p_limbs) = p_base.moduli_product();
        let mut p_mod_q = vec![T::ZERO; l];
        let mut p_inv_mod_q = vec![T::ZERO; l];
        for i in 0..l {
            let modulus = q_moduli[i];
            let p_mod = p_limbs.modulo(modulus);
            p_mod_q[i] = p_mod;
            p_inv_mod_q[i] = p_mod
                .try_inv_modulo(modulus)
                .expect("P and every q_i must be coprime");
        }

        // --- gadget scalar residues ----------------------------------------
        let qp_count = qp_base.moduli_count(); // L + K
        let mut gadget_scalar_residues = vec![T::ZERO; d * qp_count];
        for (j, part) in partitions.iter().enumerate() {
            let row = &mut gadget_scalar_residues[j * qp_count..][..qp_count];
            for q_idx in part.q_indices.clone() {
                row[q_idx] = p_mod_q[q_idx];
            }
        }

        // --- ModUp converters: Q_j → complement(Q) ∪ P --------------------
        let mut mod_up_converters = Vec::with_capacity(d);
        for part in &partitions {
            let qj_moduli = &q_moduli[part.q_indices.clone()];
            let qj_base = RNSBase::new(qj_moduli)?;

            let complement_q: Vec<M> = q_moduli[..part.q_indices.start]
                .iter()
                .chain(q_moduli[part.q_indices.end..].iter())
                .copied()
                .collect();
            let output_moduli: Vec<M> = complement_q
                .iter()
                .chain(p_moduli.iter())
                .copied()
                .collect();
            let output_base = RNSBase::new(&output_moduli)?;

            mod_up_converters.push(BaseConverter::new(&qj_base, &output_base));
        }

        // --- ModDown converter: P → Q -------------------------------------
        let mod_down_converter = BaseConverter::new(&p_base, &q_base);

        Ok(Self {
            q_base,
            p_base,
            qp_base,
            partitions,
            gadget_scalar_residues,
            p_mod_q,
            p_inv_mod_q,
            mod_up_converters,
            mod_down_converter,
        })
    }
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------
impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Number of partitions (`D`).
    #[inline]
    pub fn num_parts(&self) -> usize {
        self.partitions.len()
    }

    /// Returns the `j`-th partition.
    #[inline]
    pub fn partition(&self, j: usize) -> &Partition {
        &self.partitions[j]
    }

    /// All partitions.
    #[inline]
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }

    /// The original `Q` basis.
    #[inline]
    pub fn q_base(&self) -> &RNSBase<T, M> {
        &self.q_base
    }

    /// The auxiliary `P` basis.
    #[inline]
    pub fn p_base(&self) -> &RNSBase<T, M> {
        &self.p_base
    }

    /// The combined `QP = Q ∪ P` basis.
    #[inline]
    pub fn qp_base(&self) -> &RNSBase<T, M> {
        &self.qp_base
    }

    /// Number of moduli in the `Q` basis.
    #[inline]
    pub fn q_moduli_count(&self) -> usize {
        self.q_base.moduli_count()
    }

    /// Number of moduli in the `P` basis.
    #[inline]
    pub fn p_moduli_count(&self) -> usize {
        self.p_base.moduli_count()
    }

    /// Number of moduli in the `QP` basis (`L + K`).
    #[inline]
    pub fn qp_moduli_count(&self) -> usize {
        self.qp_base.moduli_count()
    }

    /// `P mod q_i` for each `Q` modulus.
    #[inline]
    pub fn p_mod_q(&self) -> &[T] {
        &self.p_mod_q
    }

    /// `P⁻¹ mod q_i` for each `Q` modulus.
    #[inline]
    pub fn p_inv_mod_q(&self) -> &[T] {
        &self.p_inv_mod_q
    }

    /// Returns an iterator over gadget scalar residue rows (one per partition).
    pub fn iter_gadget_scalar_residues(&self) -> impl Iterator<Item = &[T]> {
        let qp_count = self.qp_moduli_count();
        self.gadget_scalar_residues.chunks_exact(qp_count)
    }

    /// Returns all ModUp converters (one per partition).
    pub fn mod_up_converters(&self) -> &[BaseConverter<T, M>] {
        &self.mod_up_converters
    }

    /// Returns the ModDown `P → Q` converter.
    pub fn mod_down_converter(&self) -> &BaseConverter<T, M> {
        &self.mod_down_converter
    }

    /// Centers a BigUint value `r ∈ [0, P)` to `(-P/2, P/2]` using `P` limbs.
    /// Centers `r ∈ [0, P)` to `(-P/2, P/2]`.
    pub fn center_mod_p(&self, r: &[T], p_limbs: &[T]) -> Vec<T> {
        centered_biguint_from_slices(r, p_limbs)
    }
}

// ---------------------------------------------------------------------------
// Scalar-level ModUp / ModDown
// ---------------------------------------------------------------------------
impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// ModUp a single value from a partition's RNS residues to the
    /// complement-`Q` + `P` residues (coefficient domain).
    #[inline]
    pub fn mod_up_scalar(
        &self,
        partition_j: usize,
        residues_in: &[T],
        residues_out: &mut [T],
        scratch: &mut [T],
    ) {
        self.mod_up_converters[partition_j].fast_convert(residues_in, residues_out, scratch);
    }

    /// ModDown a single value from `QP` residues to `Q` residues (coefficient domain).
    ///
    /// `residues_qp` has length `L + K` (all `QP` moduli).
    /// `residues_q`  has length `L` (`Q` moduli only).
    /// `r_p_buf`   scratch buffer, length `K`.
    /// `mod_down_scratch` scratch buffer, length `K`.
    pub fn mod_down_scalar(
        &self,
        residues_qp: &[T],
        residues_q: &mut [T],
        r_p_buf: &mut [T],
        mod_down_scratch: &mut [T],
    ) {
        let l = self.q_moduli_count();
        let k = self.p_moduli_count();
        debug_assert_eq!(residues_qp.len(), l + k);
        debug_assert_eq!(residues_q.len(), l);
        debug_assert_eq!(r_p_buf.len(), k);
        debug_assert_eq!(mod_down_scratch.len(), k);

        // 1. Compose P residues → integer r, then center to (-P/2, P/2]
        let p_residues = &residues_qp[l..];
        let r_biguint = self.p_base.compose(p_residues);
        let BigUint(p_limbs) = self.p_base.moduli_product();
        let BigUint(r_view) = r_biguint.view();
        let r_centered = centered_biguint_from_slices(r_view, p_limbs);

        // 2. Decompose centered r into P residues
        self.p_base
            .decompose_to(BigUint(r_centered.as_slice()), r_p_buf);

        // 3. Base-extend r from P → Q
        //    fast_convert(r_p_buf → r_q_scratch, but we need output of L elements)
        //    So we extend directly into residues_q (length L) with a temp scratch
        let mut convert_scratch = vec![T::ZERO; k];
        self.mod_down_converter
            .fast_convert(r_p_buf, residues_q, &mut convert_scratch);

        // 4. Compute (z_i - r_i) * P⁻¹ mod q_i
        let q_residues = &residues_qp[..l];
        let q_moduli = self.q_base.moduli();
        for i in 0..l {
            let modulus = q_moduli[i];
            let z = q_residues[i];
            let r = residues_q[i];
            let diff = if z >= r {
                z - r
            } else {
                unsafe { modulus.value_unchecked() - r + z }
            };
            residues_q[i] = diff.mul_modulo(self.p_inv_mod_q[i], modulus);
        }
    }
}

/// Returns `r` if `r ≤ ⌊P/2⌋`, else `r - P` (centered representative mod P).
fn centered_biguint_from_slices<T: FheUint>(r: &[T], p: &[T]) -> Vec<T> {
    // Compute ⌊P/2⌋ via right-shift by 1
    let p_half: Vec<T> = {
        let mut v: Vec<T> = p.to_vec();
        let mut carry = T::ZERO;
        for limb in v.iter_mut().rev() {
            let new_carry = *limb & T::ONE;
            *limb = limb.wrapping_shr(1) | (carry << (T::BITS - 1));
            carry = new_carry;
        }
        v
    };

    let r_gt_half = r > p_half.as_slice();

    if r_gt_half {
        // r - P
        let mut result = r.to_vec();
        let mut borrow = false;
        for (r_limb, &p_limb) in result.iter_mut().zip(p.iter()) {
            let (sub, b) = r_limb.borrowing_sub(p_limb, borrow);
            *r_limb = sub;
            borrow = b;
        }
        result
    } else {
        r.to_vec()
    }
}

// ---------------------------------------------------------------------------
// Polynomial-level ModUp (Phase 2 — coefficient domain, per-coefficient loop)
// ---------------------------------------------------------------------------
impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// ModUp a CRT polynomial from partition `j` to complement-`Q` + `P` basis
    /// (coefficient domain, per-coefficient loop).
    ///
    /// `crt_poly` is on the full `Q` basis (modulus-major).
    /// `poly_out` receives modulus-major residues on the complement + `P` basis.
    /// `scratch` length = partition moduli count.
    pub fn mod_up_polynomial_coeff(
        &self,
        partition_j: usize,
        crt_poly: &[T],
        poly_out: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let part = &self.partitions[partition_j];
        let converter = &self.mod_up_converters[partition_j];
        let part_count = part.q_indices.len();
        let output_count = converter.output_moduli_count();

        debug_assert_eq!(crt_poly.len(), self.q_moduli_count() * poly_length);
        debug_assert_eq!(poly_out.len(), output_count * poly_length);
        debug_assert_eq!(scratch.len(), part_count);

        // Gather partition residues for each coefficient, then fast_convert.
        // `fast_convert` writes one coefficient in output-modulus order, while
        // `poly_out` is modulus-major, so scatter each converted residue into
        // its output-modulus polynomial.
        let mut converted = vec![T::ZERO; output_count];
        let mut convert_scratch = vec![T::ZERO; part_count];
        for c in 0..poly_length {
            for (local, global) in part.q_indices.clone().enumerate() {
                scratch[local] = crt_poly[global * poly_length + c];
            }

            converter.fast_convert(scratch, &mut converted, &mut convert_scratch);
            for (output_modulus, &value) in converted.iter().enumerate() {
                poly_out[output_modulus * poly_length + c] = value;
            }
        }
    }

    /// Batch ModUp using `fast_convert_array` — one call per partition.
    ///
    /// Extracts partition residues into a modulus-major input, calls
    /// `fast_convert_array`, and writes modulus-major output directly.
    /// `array_scratch` must be at least `part_count * poly_length` elements
    /// (coefficient-major layout used by `fast_convert_array`).
    pub fn mod_up_polynomial_batch(
        &self,
        partition_j: usize,
        crt_poly: &[T],
        poly_out: &mut [T],
        poly_length: usize,
        array_scratch: &mut [T],
    ) {
        let part = &self.partitions[partition_j];
        let converter = &self.mod_up_converters[partition_j];
        let part_count = part.q_indices.len();
        let output_count = converter.output_moduli_count();

        debug_assert_eq!(crt_poly.len(), self.q_moduli_count() * poly_length);
        debug_assert_eq!(poly_out.len(), output_count * poly_length);
        debug_assert!(array_scratch.len() >= part_count * poly_length);

        // Copy partition residues into contiguous modulus-major input
        let mut input = vec![T::ZERO; part_count * poly_length];
        for (local, global) in part.q_indices.clone().enumerate() {
            input[local * poly_length..][..poly_length]
                .copy_from_slice(&crt_poly[global * poly_length..][..poly_length]);
        }

        converter.fast_convert_array(&input, poly_out, poly_length, array_scratch);
    }
}
