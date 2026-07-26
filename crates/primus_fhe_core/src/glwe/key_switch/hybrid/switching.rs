use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomial;
use primus_reduce::FieldContext;
use primus_rns::HybridRNS;

use super::{
    HybridRnsGlweKeySwitchingKey,
    layout::{QpGlweMut, QpGlweRef},
    mod_down::approx_mod_down_ntt,
};
use crate::{CrtGlweCiphertext, DcrtGlweCiphertext};

impl<T: FheUint> HybridRnsGlweKeySwitchingKey<T> {
    /// Returns the number of QP-basis moduli per polynomial.
    pub fn qp_rns_poly_len(&self) -> usize {
        self.qp_rns_poly_len
    }

    /// Returns the number of partitions (gadget levels).
    pub fn partition_count(&self) -> usize {
        self.partition_count
    }

    fn validate_key_switch<M, Table>(
        &self,
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let poly_length = self.poly_length;
        let q_moduli_count = hybrid_params.q_moduli_count();
        let qp_rns_poly_len = self.qp_rns_poly_len;

        assert_eq!(table.poly_length(), poly_length);
        assert_eq!(table.moduli_count(), hybrid_params.qp_moduli_count());
        assert!(
            table
                .ntt_tables()
                .iter()
                .zip(hybrid_params.qp_base().moduli())
                .all(|(ntt_table, modulus)| ntt_table.modulus()
                    == unsafe { modulus.value_unchecked() })
        );
        assert_eq!(
            qp_rns_poly_len,
            poly_length * hybrid_params.qp_moduli_count()
        );
        assert_eq!(self.partition_count, hybrid_params.partition_count());
        assert_eq!(context.output_dimension, self.output_dimension);
        assert_eq!(context.poly_length, poly_length);
        assert_eq!(context.q_moduli_count, q_moduli_count);
        assert_eq!(context.qp_moduli_count, hybrid_params.qp_moduli_count());
    }

    fn accumulate_coefficient_mask<M, Table>(
        &self,
        mask_mod_q: &[T],
        key_for_secret: &[T],
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let poly_length = self.poly_length;
        let qp_moduli_count = hybrid_params.qp_moduli_count();
        let qp_moduli = hybrid_params.qp_base().moduli();
        let HybridRnsGlweKeySwitchingContext {
            accumulator_qp,
            mod_up_limb: mod_up_limb_buffer,
            mod_up_scratch,
            ..
        } = context;

        for (partition, glwe) in hybrid_params
            .partitions()
            .zip(key_for_secret.chunks_exact(self.qp_rns_glwe_len))
        {
            let scratch_len = partition.mod_up_scratch_len(poly_length);
            let mod_up_limbs = partition.approx_mod_up_limbs(
                mask_mod_q,
                poly_length,
                &mut mod_up_scratch[..scratch_len],
            );
            let key_glwe = QpGlweRef::new(glwe, poly_length, qp_moduli_count);

            for mod_up_limb in mod_up_limbs {
                let modulus_index = mod_up_limb.qp_modulus_index();
                mod_up_limb.write_to(mod_up_limb_buffer);
                table.ntt_tables()[modulus_index].transform_slice(mod_up_limb_buffer);
                add_qp_glwe_product(
                    accumulator_qp,
                    key_glwe,
                    mod_up_limb_buffer,
                    poly_length,
                    qp_moduli_count,
                    modulus_index,
                    &qp_moduli[modulus_index],
                );
            }
        }
    }

    fn accumulate_ntt_mask<M, Table>(
        &self,
        mask_mod_q_ntt: &[T],
        key_for_secret: &[T],
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let poly_length = self.poly_length;
        let q_moduli_count = hybrid_params.q_moduli_count();
        let qp_moduli_count = hybrid_params.qp_moduli_count();
        let qp_moduli = hybrid_params.qp_base().moduli();
        let HybridRnsGlweKeySwitchingContext {
            accumulator_qp,
            q_scratch,
            mod_up_limb: mod_up_limb_buffer,
            mod_up_scratch,
            ..
        } = context;

        assert_eq!(mask_mod_q_ntt.len(), q_moduli_count * poly_length);
        q_scratch.copy_from_slice(mask_mod_q_ntt);
        table.ntt_tables()[..q_moduli_count]
            .iter()
            .zip(q_scratch.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.inverse_transform_slice(q_limb));

        for (partition, glwe) in hybrid_params
            .partitions()
            .zip(key_for_secret.chunks_exact(self.qp_rns_glwe_len))
        {
            let partition_range = partition.q_range();
            let scratch_len = partition.mod_up_scratch_len(poly_length);
            let mod_up_limbs = partition.approx_mod_up_limbs(
                q_scratch,
                poly_length,
                &mut mod_up_scratch[..scratch_len],
            );
            let key_glwe = QpGlweRef::new(glwe, poly_length, qp_moduli_count);

            for mod_up_limb in mod_up_limbs {
                let modulus_index = mod_up_limb.qp_modulus_index();
                if partition_range.contains(&modulus_index) {
                    let limb_start = modulus_index * poly_length;
                    let mask_limb_ntt = &mask_mod_q_ntt[limb_start..limb_start + poly_length];
                    add_qp_glwe_product(
                        accumulator_qp,
                        key_glwe,
                        mask_limb_ntt,
                        poly_length,
                        qp_moduli_count,
                        modulus_index,
                        &qp_moduli[modulus_index],
                    );
                } else {
                    mod_up_limb.write_to(mod_up_limb_buffer);
                    table.ntt_tables()[modulus_index].transform_slice(mod_up_limb_buffer);
                    add_qp_glwe_product(
                        accumulator_qp,
                        key_glwe,
                        mod_up_limb_buffer,
                        poly_length,
                        qp_moduli_count,
                        modulus_index,
                        &qp_moduli[modulus_index],
                    );
                }
            }
        }
    }

    fn mod_down_and_write_negated_accumulator<M, Table, B>(
        &self,
        c_out: &mut DcrtGlweCiphertext<B>,
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) -> usize
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.poly_length;
        let q_moduli_count = hybrid_params.q_moduli_count();
        let qp_rns_poly_len = self.qp_rns_poly_len;
        let q_rns_poly_len = poly_length * q_moduli_count;

        for accumulator in context.accumulator_qp.chunks_exact_mut(qp_rns_poly_len) {
            approx_mod_down_ntt(
                hybrid_params,
                table,
                accumulator,
                poly_length,
                &mut context.q_scratch,
                &mut context.mod_down_scratch,
            );
        }

        c_out.set_zero();
        let accumulator_body_start = context.accumulator_qp.len() - qp_rns_poly_len;
        let (accumulator_mask, accumulator_body) =
            context.accumulator_qp.split_at(accumulator_body_start);
        let (a_out, b_out) = c_out.a_b_mut_slices(q_rns_poly_len);
        a_out
            .chunks_exact_mut(q_rns_poly_len)
            .zip(accumulator_mask.chunks_exact(qp_rns_poly_len))
            .for_each(|(output, accumulator)| {
                output.copy_from_slice(&accumulator[..q_rns_poly_len]);
            });
        b_out.copy_from_slice(&accumulator_body[..q_rns_poly_len]);
        c_out.neg_assign(q_rns_poly_len, poly_length, hybrid_params.q_base().moduli());
        q_rns_poly_len
    }

    /// Hybrid RNS key switching from an NTT-domain `Q`-basis ciphertext.
    ///
    /// Each input mask polynomial is transformed to coefficient form once for
    /// cross-modulus conversion. Its partition-owned limbs and the input body
    /// remain in the NTT domain and are consumed directly.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        c_in: &DcrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.validate_key_switch(hybrid_params, table, context);

        let (mask_in, body_in) = c_in.a_b(self.input_rns_poly_len);
        assert_eq!(mask_in.len(), self.key.len() / self.qp_rns_gadget_len);

        context.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in
            mask_in.zip(self.key.chunks_exact(self.qp_rns_gadget_len))
        {
            self.accumulate_ntt_mask(
                mask_polynomial.as_slice(),
                key_for_secret,
                hybrid_params,
                table,
                context,
            );
        }

        let q_rns_poly_len =
            self.mod_down_and_write_negated_accumulator(c_out, hybrid_params, table, context);
        let (_, b_out) = c_out.a_b_mut_slices(q_rns_poly_len);
        DcrtPolynomial(b_out).add_assign(
            &body_in,
            self.poly_length,
            hybrid_params.q_base().moduli(),
        );
    }

    /// Reference hybrid RNS key switching from coefficient-domain input.
    ///
    /// This entry point is useful for validating the NTT-domain implementation.
    pub fn key_switch_coeff_to<M, Table, A, B>(
        &self,
        c_in: &CrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.validate_key_switch(hybrid_params, table, context);

        let (mask_in, body_in) = c_in.a_b(self.input_rns_poly_len);
        assert_eq!(mask_in.len(), self.key.len() / self.qp_rns_gadget_len);

        context.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in
            mask_in.zip(self.key.chunks_exact(self.qp_rns_gadget_len))
        {
            self.accumulate_coefficient_mask(
                mask_polynomial.as_slice(),
                key_for_secret,
                hybrid_params,
                table,
                context,
            );
        }

        let q_rns_poly_len =
            self.mod_down_and_write_negated_accumulator(c_out, hybrid_params, table, context);
        let q_moduli_count = hybrid_params.q_moduli_count();
        let body_scratch = context.q_scratch.as_mut_slice();
        body_scratch.copy_from_slice(body_in.as_slice());
        table.ntt_tables()[..q_moduli_count]
            .iter()
            .zip(body_scratch.chunks_exact_mut(self.poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.transform_slice(q_limb));
        let (_, b_out) = c_out.a_b_mut_slices(q_rns_poly_len);
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(body_scratch),
            self.poly_length,
            hybrid_params.q_base().moduli(),
        );
    }
}

#[inline]
fn add_qp_glwe_product<T, M>(
    accumulator_qp: &mut [T],
    key_glwe: QpGlweRef<'_, T>,
    digit_limb: &[T],
    poly_length: usize,
    qp_moduli_count: usize,
    modulus_index: usize,
    modulus: &M,
) where
    T: FheUint,
    M: FieldContext<T>,
{
    QpGlweMut::new(accumulator_qp, poly_length, qp_moduli_count)
        .modulus_limbs_mut(modulus_index)
        .zip(key_glwe.modulus_limbs(modulus_index))
        .for_each(|(accumulator_limb, key_limb)| {
            modulus.reduce_add_mul_slice_assign(accumulator_limb, digit_limb, key_limb);
        });
}

/// Reusable scratch space for hybrid RNS key switching.
///
/// All temporary buffers used in the hot path are allocated once here
/// and reused across [`HybridRnsGlweKeySwitchingKey::key_switch_to`] calls.
pub struct HybridRnsGlweKeySwitchingContext<T: FheUint> {
    accumulator_qp: Vec<T>,
    // Reused for one coefficient-domain Q polynomial and mixed ModDown output.
    q_scratch: Vec<T>,
    // One streamed coefficient-domain ModUp limb before its forward NTT.
    mod_up_limb: Vec<T>,
    mod_up_scratch: Vec<T>,
    mod_down_scratch: Vec<T>,
    poly_length: usize,
    q_moduli_count: usize,
    qp_moduli_count: usize,
    output_dimension: usize,
}

impl<T: FheUint> HybridRnsGlweKeySwitchingContext<T> {
    /// Creates reusable scratch space sized from the hybrid parameters.
    pub fn new<M>(
        key_switching_key: &HybridRnsGlweKeySwitchingKey<T>,
        hybrid_params: &HybridRNS<T, M>,
    ) -> Self
    where
        M: FieldContext<T>,
    {
        assert_eq!(
            key_switching_key.partition_count,
            hybrid_params.partition_count()
        );
        assert_eq!(
            key_switching_key.qp_rns_poly_len % hybrid_params.qp_moduli_count(),
            0
        );

        let poly_length = key_switching_key.poly_length;
        let output_dimension = key_switching_key.output_dimension;
        let q_moduli_count = hybrid_params.q_moduli_count();
        let qp_moduli_count = hybrid_params.qp_moduli_count();
        let qp_poly_len = qp_moduli_count * poly_length;

        Self {
            accumulator_qp: vec![T::ZERO; (output_dimension + 1) * qp_poly_len],
            q_scratch: vec![T::ZERO; q_moduli_count * poly_length],
            mod_up_limb: vec![T::ZERO; poly_length],
            mod_up_scratch: vec![T::ZERO; hybrid_params.max_mod_up_scratch_len(poly_length)],
            mod_down_scratch: vec![T::ZERO; hybrid_params.mod_down_scratch_len(poly_length)],
            poly_length,
            q_moduli_count,
            qp_moduli_count,
            output_dimension,
        }
    }
}
