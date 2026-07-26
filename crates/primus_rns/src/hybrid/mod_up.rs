use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::converter::FastConversionLimb;

use super::HybridRNSPartition;

enum HybridModUpLimbSource<'a, T, M> {
    Partition(&'a [T]),
    Converted(FastConversionLimb<'a, T, M>),
}

/// One coefficient-domain polynomial limb produced by streaming Hybrid ModUp.
///
/// The limb carries its position in the full `QP` basis. It borrows either an
/// existing partition limb or the prepared base-conversion data required to
/// produce one complementary limb.
pub struct HybridModUpLimb<'a, T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    qp_modulus_index: usize,
    source: HybridModUpLimbSource<'a, T, M>,
}

impl<T, M> HybridModUpLimb<'_, T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns this limb's modulus index in the full `QP` basis.
    #[inline]
    pub fn qp_modulus_index(&self) -> usize {
        self.qp_modulus_index
    }

    /// Writes this coefficient-domain polynomial limb to `output`.
    #[inline]
    pub fn write_to(self, output: &mut [T]) {
        match self.source {
            HybridModUpLimbSource::Partition(input) => {
                assert_eq!(output.len(), input.len());
                output.copy_from_slice(input);
            }
            HybridModUpLimbSource::Converted(conversion) => conversion.write_to(output),
        }
    }
}

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the minimum scratch length required by
    /// [`approx_mod_up`](Self::approx_mod_up).
    #[inline]
    pub fn mod_up_scratch_len(&self, poly_length: usize) -> usize {
        self.mod_up_converter
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Streams this partition's approximate ModUp result in full `QP` basis
    /// order.
    ///
    /// Adjusted partition residues are prepared once in `scratch`. Each
    /// returned [`HybridModUpLimb`] then writes exactly one `poly_length`
    /// coefficient-domain polynomial, so callers can consume it immediately
    /// without materializing a complete `QP` digit. A singleton partition
    /// ignores scratch.
    pub fn approx_mod_up_limbs<'a>(
        &'a self,
        polynomial_mod_q: &'a [T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl ExactSizeIterator<Item = HybridModUpLimb<'a, T, M>> + 'a {
        let expected_input_len = self
            .q_moduli_count
            .checked_mul(poly_length)
            .expect("hybrid Q polynomial length overflow");
        assert_eq!(polynomial_mod_q.len(), expected_input_len);

        let partition_start = self.q_range.start * poly_length;
        let partition_end = self.q_range.end * poly_length;
        let partition_mod_q = &polynomial_mod_q[partition_start..partition_end];
        let mut converted_limbs =
            self.mod_up_converter
                .fast_convert_array_limbs(partition_mod_q, poly_length, scratch);
        let partition_start_index = self.q_range.start;
        let partition_end_index = self.q_range.end;
        let qp_moduli_count = self.mod_up_converter.output_moduli_count() + self.moduli_count();

        (0..qp_moduli_count).map(move |qp_modulus_index| {
            let source = if (partition_start_index..partition_end_index).contains(&qp_modulus_index)
            {
                let partition_index = qp_modulus_index - partition_start_index;
                let coefficient_start = partition_index * poly_length;
                HybridModUpLimbSource::Partition(
                    &partition_mod_q[coefficient_start..coefficient_start + poly_length],
                )
            } else {
                HybridModUpLimbSource::Converted(
                    converted_limbs
                        .next()
                        .expect("missing complementary ModUp limb"),
                )
            };

            HybridModUpLimb {
                qp_modulus_index,
                source,
            }
        })
    }

    /// Extends this partition of a `Q`-basis polynomial into one full `QP`
    /// hybrid digit.
    ///
    /// Both input and output use modulus-major layout. `scratch.len()` must be
    /// at least [`mod_up_scratch_len`](Self::mod_up_scratch_len). The partition
    /// limbs are copied exactly; the other limbs are produced by approximate
    /// RNS base conversion. A singleton partition ignores scratch.
    pub fn approx_mod_up(
        &self,
        polynomial_mod_q: &[T],
        digit_mod_qp: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let expected_digit_len = (self.mod_up_converter.output_moduli_count()
            + self.moduli_count())
        .checked_mul(poly_length)
        .expect("hybrid QP polynomial length overflow");

        assert_eq!(digit_mod_qp.len(), expected_digit_len);
        self.approx_mod_up_limbs(polynomial_mod_q, poly_length, scratch)
            .for_each(|limb| {
                let limb_start = limb.qp_modulus_index() * poly_length;
                limb.write_to(&mut digit_mod_qp[limb_start..limb_start + poly_length]);
            });
    }
}
