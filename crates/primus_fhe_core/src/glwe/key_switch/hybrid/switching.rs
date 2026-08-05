use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomial;
use primus_reduce::FieldContext;
use primus_rns::{HybridRNS, HybridRNSPartition};

use super::{HybridRnsGlweKeySwitchingKey, mod_down::approx_mod_down_ntt};
use crate::{DcrtGlweCiphertext, HybridRnsKeySwitchDomain};

#[cfg(test)]
use crate::CrtGlweCiphertext;

impl<T: FheUint> HybridRnsGlweKeySwitchingKey<T> {
    fn accumulate_ntt_mask<M, Table>(
        &self,
        mask_mod_q_ntt: &[T],
        key_for_secret: &[T],
        hybrid_rns: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let poly_length = self.input_size.poly_length();
        let q_moduli_count = self.input_size.moduli_count();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let qp_glwe_len = self.qp_size.rns_glwe_len();
        let HybridRnsGlweKeySwitchingContext {
            accumulator_qp,
            q_scratch,
            mod_up_limb,
            mod_up_scratch,
            ..
        } = context;

        q_scratch.copy_from_slice(mask_mod_q_ntt);
        table.ntt_tables()[..q_moduli_count]
            .iter()
            .zip(q_scratch.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.inverse_transform_slice(q_limb));

        accumulate_partitions(
            q_scratch,
            Some(mask_mod_q_ntt),
            key_for_secret,
            hybrid_rns,
            table,
            accumulator_qp,
            mod_up_limb,
            mod_up_scratch,
            poly_length,
            qp_poly_len,
            qp_glwe_len,
        );
    }

    fn mod_down_and_write_negated_accumulator<M, Table, B>(
        &self,
        c_out: &mut DcrtGlweCiphertext<B>,
        hybrid_rns: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.input_size.poly_length();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let q_poly_len = self.output_size.rns_poly_len();

        for accumulator in context.accumulator_qp.chunks_exact_mut(qp_poly_len) {
            approx_mod_down_ntt(
                hybrid_rns,
                table,
                accumulator,
                poly_length,
                &mut context.q_scratch,
                &mut context.mod_down_scratch,
            );
        }

        let (accumulator_mask, accumulator_body) =
            context.accumulator_qp.split_at(self.qp_size.rns_mask_len());
        let (a_out, b_out) = c_out.a_b_mut_slices(q_poly_len);
        for (output, accumulator) in a_out
            .chunks_exact_mut(q_poly_len)
            .zip(accumulator_mask.chunks_exact(qp_poly_len))
        {
            output.copy_from_slice(&accumulator[..q_poly_len]);
        }
        b_out.copy_from_slice(&accumulator_body[..q_poly_len]);
        c_out.neg_assign(q_poly_len, poly_length, hybrid_rns.q_base().moduli());
    }

    /// Hybrid RNS key switching from an NTT-domain `Q`-basis ciphertext.
    ///
    /// Each input mask polynomial is transformed to coefficient form once for
    /// cross-modulus conversion. Its partition-owned limbs and the input body
    /// remain in the NTT domain and are consumed directly.
    ///
    /// # Panics
    ///
    /// Panics if the input, output, or reusable context has a layout that is
    /// incompatible with this key.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        c_in: &DcrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, Table>,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(c_in.as_ref().len(), self.input_size.rns_glwe_len());
        assert_eq!(c_out.as_ref().len(), self.output_size.rns_glwe_len());
        assert!(
            context.input_size == self.input_size && context.output_size == self.output_size,
            "hybrid key-switching key and context use incompatible layouts"
        );
        let hybrid_rns = domain.hybrid_rns();
        let table = domain.table();
        let qp_gadget_len = self
            .partition_count
            .checked_mul(self.qp_size.rns_glwe_len())
            .expect("hybrid QP gadget length overflow");
        let (mask_in, body_in) = c_in.a_b(self.input_size.rns_poly_len());

        context.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in mask_in.zip(self.key.chunks_exact(qp_gadget_len)) {
            self.accumulate_ntt_mask(
                mask_polynomial.as_slice(),
                key_for_secret,
                hybrid_rns,
                table,
                context,
            );
        }

        self.mod_down_and_write_negated_accumulator(c_out, hybrid_rns, table, context);
        let (_, b_out) = c_out.a_b_mut_slices(self.output_size.rns_poly_len());
        DcrtPolynomial(b_out).add_assign(
            &body_in,
            self.input_size.poly_length(),
            hybrid_rns.q_base().moduli(),
        );
    }

    #[cfg(test)]
    fn key_switch_coeff_reference_to<M, Table, A, B>(
        &self,
        c_in: &CrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, Table>,
        context: &mut HybridRnsGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let hybrid_rns = domain.hybrid_rns();
        let table = domain.table();
        let poly_length = self.input_size.poly_length();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let qp_glwe_len = self.qp_size.rns_glwe_len();
        let qp_gadget_len = self
            .partition_count
            .checked_mul(qp_glwe_len)
            .expect("hybrid QP gadget length overflow");
        let (mask_in, body_in) = c_in.a_b(self.input_size.rns_poly_len());

        context.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in mask_in.zip(self.key.chunks_exact(qp_gadget_len)) {
            let HybridRnsGlweKeySwitchingContext {
                accumulator_qp,
                mod_up_limb,
                mod_up_scratch,
                ..
            } = &mut *context;
            accumulate_partitions(
                mask_polynomial.as_slice(),
                None,
                key_for_secret,
                hybrid_rns,
                table,
                accumulator_qp,
                mod_up_limb,
                mod_up_scratch,
                poly_length,
                qp_poly_len,
                qp_glwe_len,
            );
        }

        self.mod_down_and_write_negated_accumulator(c_out, hybrid_rns, table, context);
        context.q_scratch.copy_from_slice(body_in.as_slice());
        table.ntt_tables()[..self.input_size.moduli_count()]
            .iter()
            .zip(context.q_scratch.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.transform_slice(q_limb));
        let (_, b_out) = c_out.a_b_mut_slices(self.output_size.rns_poly_len());
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(context.q_scratch.as_slice()),
            poly_length,
            hybrid_rns.q_base().moduli(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn accumulate_partitions<T, M, Table>(
    mask_mod_q: &[T],
    mask_mod_q_ntt: Option<&[T]>,
    key_for_secret: &[T],
    hybrid_rns: &HybridRNS<T, M>,
    table: &Table,
    accumulator_qp: &mut [T],
    mod_up_limb: &mut [T],
    mod_up_scratch: &mut [T],
    poly_length: usize,
    qp_poly_len: usize,
    qp_glwe_len: usize,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    let qp_moduli = hybrid_rns.qp_base().moduli();
    for (partition, key_glwe) in hybrid_rns
        .partitions()
        .zip(key_for_secret.chunks_exact(qp_glwe_len))
    {
        accumulate_partition(
            partition,
            mask_mod_q,
            mask_mod_q_ntt,
            key_glwe,
            table,
            accumulator_qp,
            mod_up_limb,
            mod_up_scratch,
            poly_length,
            qp_poly_len,
            qp_moduli,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn accumulate_partition<T, M, Table>(
    partition: &HybridRNSPartition<T, M>,
    mask_mod_q: &[T],
    mask_mod_q_ntt: Option<&[T]>,
    key_glwe: &[T],
    table: &Table,
    accumulator_qp: &mut [T],
    mod_up_limb: &mut [T],
    mod_up_scratch: &mut [T],
    poly_length: usize,
    qp_poly_len: usize,
    qp_moduli: &[M],
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    let partition_range = partition.q_range();
    let scratch_len = partition.mod_up_scratch_len(poly_length);
    for mod_up in
        partition.approx_mod_up_limbs(mask_mod_q, poly_length, &mut mod_up_scratch[..scratch_len])
    {
        let modulus_index = mod_up.qp_modulus_index();
        if let Some(mask_ntt) = mask_mod_q_ntt.filter(|_| partition_range.contains(&modulus_index))
        {
            let limb_start = modulus_index * poly_length;
            add_qp_glwe_product(
                accumulator_qp,
                key_glwe,
                &mask_ntt[limb_start..limb_start + poly_length],
                qp_poly_len,
                modulus_index,
                &qp_moduli[modulus_index],
            );
        } else {
            mod_up.write_to(mod_up_limb);
            table.ntt_tables()[modulus_index].transform_slice(mod_up_limb);
            add_qp_glwe_product(
                accumulator_qp,
                key_glwe,
                mod_up_limb,
                qp_poly_len,
                modulus_index,
                &qp_moduli[modulus_index],
            );
        }
    }
}

#[inline]
fn add_qp_glwe_product<T, M>(
    accumulator_qp: &mut [T],
    key_glwe: &[T],
    digit_limb: &[T],
    qp_poly_len: usize,
    modulus_index: usize,
    modulus: &M,
) where
    T: FheUint,
    M: FieldContext<T>,
{
    let limb_start = modulus_index * digit_limb.len();
    let limb_end = limb_start + digit_limb.len();
    for (accumulator_poly, key_poly) in accumulator_qp
        .chunks_exact_mut(qp_poly_len)
        .zip(key_glwe.chunks_exact(qp_poly_len))
    {
        modulus.reduce_add_mul_slice_assign(
            &mut accumulator_poly[limb_start..limb_end],
            digit_limb,
            &key_poly[limb_start..limb_end],
        );
    }
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
    input_size: RnsGlweSize,
    output_size: RnsGlweSize,
}

impl<T: FheUint> HybridRnsGlweKeySwitchingContext<T> {
    /// Creates reusable scratch space for a compatible hybrid key and Domain.
    ///
    /// # Panics
    ///
    /// Panics if the key and Domain use different polynomial, RNS, output, or
    /// partition layouts.
    pub fn new<M, Table>(
        key_switching_key: &HybridRnsGlweKeySwitchingKey<T>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, Table>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let hybrid_rns = domain.hybrid_rns();
        assert!(
            key_switching_key.partition_count == hybrid_rns.partition_count()
                && key_switching_key.input_size.poly_length() == domain.table().poly_length()
                && key_switching_key.input_size.moduli_count() == hybrid_rns.q_moduli_count()
                && key_switching_key.output_size.moduli_count() == hybrid_rns.q_moduli_count()
                && key_switching_key.qp_size.moduli_count() == hybrid_rns.qp_moduli_count(),
            "hybrid key-switching key and Domain use incompatible layouts"
        );

        let poly_length = key_switching_key.input_size.poly_length();
        Self {
            accumulator_qp: vec![T::ZERO; key_switching_key.qp_size.rns_glwe_len()],
            q_scratch: vec![T::ZERO; key_switching_key.input_size.rns_poly_len()],
            mod_up_limb: vec![T::ZERO; poly_length],
            mod_up_scratch: vec![T::ZERO; hybrid_rns.max_mod_up_scratch_len(poly_length)],
            mod_down_scratch: vec![T::ZERO; hybrid_rns.mod_down_scratch_len(poly_length)],
            input_size: key_switching_key.input_size,
            output_size: key_switching_key.output_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use primus_lattice::glwe::DcrtGlwe;
    use primus_modulus::BarrettModulus;
    use primus_ntt::{DcrtTable, UintDcrtTable};
    use primus_poly::Polynomial;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, RingSecretKeyType,
    };

    #[test]
    fn coefficient_and_ntt_hybrid_key_switch_match() {
        type Value = u64;

        let dimension = 2;
        let poly_length: usize = 512;
        let log_n = poly_length.trailing_zeros();
        let plaintext_modulus = BarrettModulus::new(12289);
        let gamma = BarrettModulus::new(2305843009213554689);
        let q_moduli =
            [1125899906826241, 1125899906629633, 1125899906031617].map(BarrettModulus::new);
        let p_moduli = [1125899905036289].map(BarrettModulus::new);
        let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_moduli).copied().collect();
        let q_table = UintDcrtTable::new(log_n, &q_moduli).unwrap();
        let qp_table = UintDcrtTable::new(log_n, &qp_moduli).unwrap();
        let parameters = CrtGlweParameters::new(
            dimension,
            poly_length,
            plaintext_modulus,
            gamma,
            &q_moduli,
            RingSecretKeyType::Ternary,
            3.20,
        );
        let hybrid = HybridRNS::new(&q_moduli, &p_moduli, 2).unwrap();
        let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &qp_table).unwrap();
        let mut rng = StdRng::seed_from_u64(0x4859_4252_4944);
        let input_key = GlweSecretKey::generate(&parameters, &mut rng);
        let output_key = GlweSecretKey::generate(&parameters, &mut rng);
        let input_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&input_key, &q_table);
        let switching_key = HybridRnsGlweKeySwitchingKey::generate(
            &input_key,
            &parameters,
            &output_key,
            &domain,
            &mut rng,
        );

        let plaintext: Polynomial<Vec<Value>> =
            Polynomial::random(poly_length, plaintext_modulus, &mut rng);
        let mut input: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        input_dcrt_key.encrypt_plaintext_inplace(
            &plaintext,
            &mut input,
            &parameters,
            &q_table,
            &mut rng,
        );
        let input_coeff = input.clone().into_coeff_form(&q_table);
        let mut from_ntt: DcrtGlwe<Vec<Value>> =
            DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let mut from_coeff: DcrtGlwe<Vec<Value>> =
            DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let mut ntt_context = HybridRnsGlweKeySwitchingContext::new(&switching_key, &domain);
        let mut coeff_context = HybridRnsGlweKeySwitchingContext::new(&switching_key, &domain);

        switching_key.key_switch_to(&input, &mut from_ntt, &domain, &mut ntt_context);
        switching_key.key_switch_coeff_reference_to(
            &input_coeff,
            &mut from_coeff,
            &domain,
            &mut coeff_context,
        );

        assert_eq!(from_ntt.as_ref(), from_coeff.as_ref());
    }
}
