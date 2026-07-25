//! Hybrid RNS gadget decomposition for key switching.
//!
//! [`HybridRNS`] splits the ciphertext basis `Q` into non-empty contiguous
//! partitions. Each [`HybridRNSPartition`] owns the precomputation for the
//! approximate basis extension from that partition to its complement and the
//! auxiliary basis `P`. The resulting digits live in the combined `QP` basis.
//!
//! The polynomial APIs use modulus-major storage and caller-owned scratch
//! buffers. They do not allocate in the online key-switching path.
//!
//! # References
//!
//! - OpenFHE `KeySwitchHYBRID` and `DCRTPoly::ApproxModDown`
//! - SEAL `BaseConverter`

use core::ops::Range;

use itertools::izip;
use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use crate::{BaseConverter, RNSBase, RNSError};

/// One non-empty, contiguous partition of the ciphertext basis `Q`.
#[derive(Clone)]
pub struct HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_range: Range<usize>,
    mod_up_converter: BaseConverter<T, M>,
}

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the indices of this partition in the full `Q` basis.
    #[inline]
    pub fn q_range(&self) -> Range<usize> {
        self.q_range.clone()
    }

    /// Returns the number of `Q` moduli in this partition.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.q_range.len()
    }

    /// Returns the approximate base converter from this partition to
    /// `complement(Q_j) ∪ P`.
    #[inline]
    pub fn mod_up_converter(&self) -> &BaseConverter<T, M> {
        &self.mod_up_converter
    }

    /// Extends this partition of a `Q`-basis polynomial into one full `QP`
    /// hybrid digit.
    ///
    /// Both input and output use modulus-major layout. `scratch` uses
    /// coefficient-major layout and must have `moduli_count() * poly_length`
    /// elements. The partition limbs are copied exactly; the other limbs are
    /// produced by approximate RNS base conversion.
    pub fn approx_mod_up(
        &self,
        polynomial_q: &[T],
        digit_qp: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let partition_elements = self
            .moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid partition polynomial length overflow");
        let input_start = self.q_range.start * poly_length;
        let input_end = input_start + partition_elements;
        let expected_qp_len = (self.mod_up_converter.output_moduli_count() + self.moduli_count())
            .checked_mul(poly_length)
            .expect("hybrid QP polynomial length overflow");

        assert!(input_end <= polynomial_q.len());
        assert_eq!(digit_qp.len(), expected_qp_len);
        assert_eq!(scratch.len(), partition_elements);

        let partition_q = &polynomial_q[input_start..input_end];
        let (prefix_q, partition_and_suffix) = digit_qp.split_at_mut(input_start);
        let (partition_out, suffix_qp) = partition_and_suffix.split_at_mut(partition_elements);

        partition_out.copy_from_slice(partition_q);

        let output_polynomials = prefix_q
            .chunks_exact_mut(poly_length)
            .chain(suffix_qp.chunks_exact_mut(poly_length));
        self.mod_up_converter.fast_convert_array_to_polynomials(
            partition_q,
            output_polynomials,
            poly_length,
            scratch,
        );
    }
}

/// Precomputed bases and converters for hybrid RNS key switching.
#[derive(Clone)]
pub struct HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_base: RNSBase<T, M>,
    p_base: RNSBase<T, M>,
    qp_base: RNSBase<T, M>,
    partitions: Vec<HybridRNSPartition<T, M>>,
    p_mod_q: Vec<T>,
    inv_p_mod_q: Vec<T>,
    mod_down_converter: BaseConverter<T, M>,
}

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates hybrid RNS precomputations for bases `Q` and `P`.
    ///
    /// `requested_partitions` is an upper bound. The actual number can be
    /// smaller because all partitions are non-empty and have the same maximum
    /// size, matching OpenFHE's `alpha`/`beta` partitioning rule.
    pub fn new(
        q_moduli: &[M],
        p_moduli: &[M],
        requested_partitions: usize,
    ) -> Result<Self, RNSError> {
        if requested_partitions == 0 {
            return Err(RNSError::InvalidPartitionCount);
        }

        let q_base = RNSBase::new(q_moduli)?;
        let p_base = RNSBase::new(p_moduli)?;
        let qp_base = q_base.extend_with(&p_base)?;

        let partition_size = q_moduli
            .len()
            .div_ceil(requested_partitions.min(q_moduli.len()));
        let mut partitions = Vec::with_capacity(q_moduli.len().div_ceil(partition_size));

        for (partition_index, partition_moduli) in q_moduli.chunks(partition_size).enumerate() {
            let start = partition_index * partition_size;
            let end = start + partition_moduli.len();
            let partition_base = RNSBase::from_owned_moduli(partition_moduli.to_vec())?;
            let complement_moduli = q_moduli[..start]
                .iter()
                .chain(&q_moduli[end..])
                .chain(p_moduli)
                .copied()
                .collect();
            let complement_base = RNSBase::from_owned_moduli(complement_moduli)?;

            partitions.push(HybridRNSPartition {
                q_range: start..end,
                mod_up_converter: BaseConverter::from_owned_bases(partition_base, complement_base),
            });
        }

        let BigUint(p) = p_base.moduli_product();
        let mut p_mod_q = Vec::with_capacity(q_moduli.len());
        let mut inv_p_mod_q = Vec::with_capacity(q_moduli.len());
        for qi in q_moduli {
            let p_mod_qi = qi.reduce(p);
            p_mod_q.push(p_mod_qi);
            inv_p_mod_q.push(qi.reduce_inv(p_mod_qi));
        }

        let mod_down_converter = BaseConverter::new(&p_base, &q_base);

        Ok(Self {
            q_base,
            p_base,
            qp_base,
            partitions,
            p_mod_q,
            inv_p_mod_q,
            mod_down_converter,
        })
    }

    /// Returns the ciphertext basis `Q`.
    #[inline]
    pub fn q_base(&self) -> &RNSBase<T, M> {
        &self.q_base
    }

    /// Returns the auxiliary basis `P`.
    #[inline]
    pub fn p_base(&self) -> &RNSBase<T, M> {
        &self.p_base
    }

    /// Returns the combined basis `Q ∪ P`.
    #[inline]
    pub fn qp_base(&self) -> &RNSBase<T, M> {
        &self.qp_base
    }

    /// Returns the number of moduli in `Q`.
    #[inline]
    pub fn q_moduli_count(&self) -> usize {
        self.q_base.moduli_count()
    }

    /// Returns the number of moduli in `P`.
    #[inline]
    pub fn p_moduli_count(&self) -> usize {
        self.p_base.moduli_count()
    }

    /// Returns the number of moduli in `QP`.
    #[inline]
    pub fn qp_moduli_count(&self) -> usize {
        self.qp_base.moduli_count()
    }

    /// Iterates over the non-empty `Q` partitions in basis order.
    #[inline]
    pub fn partitions(&self) -> impl ExactSizeIterator<Item = &HybridRNSPartition<T, M>> {
        self.partitions.iter()
    }

    /// Returns the actual number of non-empty partitions.
    #[inline]
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Returns the largest partition size.
    #[inline]
    pub fn max_partition_moduli_count(&self) -> usize {
        self.partitions
            .first()
            .map_or(0, HybridRNSPartition::moduli_count)
    }

    /// Returns `P mod q_i` in `Q`-basis order.
    #[inline]
    pub fn p_mod_q(&self) -> &[T] {
        &self.p_mod_q
    }

    /// Returns `P^-1 mod q_i` in `Q`-basis order.
    #[inline]
    pub fn inv_p_mod_q(&self) -> &[T] {
        &self.inv_p_mod_q
    }

    /// Returns the approximate base converter from `P` to `Q`.
    #[inline]
    pub fn mod_down_converter(&self) -> &BaseConverter<T, M> {
        &self.mod_down_converter
    }

    /// Approximately divides a coefficient-domain `QP` polynomial by `P` and
    /// leaves the result in its `Q` limbs.
    ///
    /// `converted_p` must hold `q_moduli_count() * poly_length` elements and
    /// `scratch` must hold `p_moduli_count() * poly_length` elements. The `P`
    /// limbs of `polynomial_qp` are left unchanged.
    pub fn approx_mod_down(
        &self,
        polynomial_qp: &mut [T],
        poly_length: usize,
        converted_p: &mut [T],
        scratch: &mut [T],
    ) {
        let q_len = self.q_moduli_count() * poly_length;
        let p_len = self.p_moduli_count() * poly_length;
        assert_eq!(polynomial_qp.len(), q_len + p_len);
        assert_eq!(converted_p.len(), q_len);
        assert_eq!(scratch.len(), p_len);

        let (polynomial_q, polynomial_p) = polynomial_qp.split_at_mut(q_len);
        self.mod_down_converter
            .fast_convert_array(polynomial_p, converted_p, poly_length, scratch);

        izip!(
            polynomial_q.chunks_exact_mut(poly_length),
            converted_p.chunks_exact(poly_length),
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(q_limb, converted_p_limb, modulus, &inv_p)| {
            q_limb
                .iter_mut()
                .zip(converted_p_limb)
                .for_each(|(value, &p_value)| {
                    *value = modulus.reduce_mul(modulus.reduce_sub(*value, p_value), inv_p);
                });
        });
    }

    /// Approximately divides one `QP` residue vector by `P`.
    ///
    /// `scratch` must contain `p_moduli_count()` elements.
    pub fn approx_mod_down_scalar(
        &self,
        residues_qp: &[T],
        residues_q: &mut [T],
        scratch: &mut [T],
    ) {
        let (q_residues, p_residues) = residues_qp.split_at(self.q_moduli_count());
        assert_eq!(p_residues.len(), self.p_moduli_count());
        assert_eq!(residues_q.len(), self.q_moduli_count());
        assert_eq!(scratch.len(), self.p_moduli_count());

        self.mod_down_converter
            .fast_convert(p_residues, residues_q, scratch);
        izip!(
            residues_q,
            q_residues,
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(result, &value, modulus, &inv_p)| {
            *result = modulus.reduce_mul(modulus.reduce_sub(value, *result), inv_p);
        });
    }
}
