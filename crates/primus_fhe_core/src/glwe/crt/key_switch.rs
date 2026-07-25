use primus_data::{Data, DataMut, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_distr::{sample_crt_gaussian_values_to, sample_crt_uniform_values_to};
use primus_integer::FheUint;
use primus_lattice::{
    context::DcrtGlevContext,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::{HybridRNS, RNSBase};
use rand::distr::Uniform;

use crate::{
    CrtGlevParameters, CrtGlweCiphertext, CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext,
    DcrtGlweSecretKey,
};

pub struct CrtGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    poly_length: usize,
    rns_poly_len: usize,
    rns_glev_len: usize,
    input_rns_glwe_mid: usize,
    output_rns_glwe_mid: usize,
}

impl<T: FheUint> CrtGlweKeySwitchingKey<T> {
    pub fn new<R, M, Table>(
        input_sk: &CrtGlweSecretKey<T>,
        input_params: &CrtGlweParameters<T, M>,
        output_sk: &DcrtGlweSecretKey<T>,
        ksk_params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        debug_assert_eq!(input_params.poly_length(), ksk_params.poly_length());
        debug_assert_eq!(input_params.cipher_modulus(), ksk_params.cipher_modulus());

        let dcrt_glev_len = ksk_params.rns_glev_len();
        let mut key: Vec<T> = vec![T::ZERO; input_params.dimension() * dcrt_glev_len];

        let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

        input_sk
            .iter_crt_poly()
            .zip(key_iter)
            .for_each(|(si, mut dcrt_glev)| {
                output_sk.encrypt_crt_msg_to_dcrt_glev_inplace(
                    &si,
                    &mut dcrt_glev,
                    ksk_params,
                    table,
                    rng,
                );
            });

        let poly_length = input_params.poly_length();
        let rns_poly_len = input_params.rns_poly_len();
        let input_rns_glwe_mid = input_params.rns_glwe_mid();
        let output_rns_glwe_mid = ksk_params.rns_glwe_mid();
        Self {
            key,
            poly_length,
            rns_poly_len,
            rns_glev_len: dcrt_glev_len,
            input_rns_glwe_mid,
            output_rns_glwe_mid,
        }
    }

    pub fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.rns_glev_len)
    }

    pub fn key_swithching_inplace<M, Table, A, B>(
        &self,
        c_in: &CrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut CrtGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.poly_length;

        let (a_in, b_in) = c_in.a_b(self.input_rns_glwe_mid);

        let (big_uint_poly, crt_poly, glev_context) = context.as_mut();

        c_out.set_zero();
        self.iter_dcrt_glev().zip(a_in).for_each(|(ki, ai)| {
            rns_base.compose_polynomial_to(
                &ai,
                big_uint_poly,
                poly_length,
                glev_context.compose_buffer_mut(),
            );

            c_out.add_dcrt_glev_mul_big_uint_poly_assign(
                &ki,
                big_uint_poly,
                basis,
                table,
                rns_base,
                glev_context,
            );
        });

        crt_poly.copy_from(&b_in);
        table.transform_slice(crt_poly.as_mut());
        c_out.neg_assign(self.rns_poly_len, poly_length, rns_base.moduli());

        let (_, b_out) = c_out.a_b_mut_slices(self.output_rns_glwe_mid);
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(crt_poly.as_ref()),
            poly_length,
            rns_base.moduli(),
        );
    }
}

pub struct CrtGlweKeySwitchingContext<T: FheUint> {
    big_uint_poly: BigUintPolynomial<Vec<T>>,
    crt_poly: CrtPolynomial<Vec<T>>,
    glev_context: DcrtGlevContext<T>,
}

impl<T: FheUint> CrtGlweKeySwitchingContext<T> {
    pub fn new(
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let big_uint_poly = BigUintPolynomial::zero(big_uint_poly_len);
        let crt_poly = CrtPolynomial::zero(crt_poly_len);
        let glev_context =
            DcrtGlevContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        Self {
            big_uint_poly,
            crt_poly,
            glev_context,
        }
    }

    pub fn as_mut(
        &mut self,
    ) -> (
        &mut BigUintPolynomial<Vec<T>>,
        &mut CrtPolynomial<Vec<T>>,
        &mut DcrtGlevContext<T>,
    ) {
        (
            &mut self.big_uint_poly,
            &mut self.crt_poly,
            &mut self.glev_context,
        )
    }
}

// ===========================================================================
// Hybrid RNS Gadget Key Switching
// ===========================================================================

/// Key-switching key for hybrid RNS gadget decomposition.
///
/// Unlike [`CrtGlweKeySwitchingKey`] which uses bit decomposition, this key
/// uses partition-based gadget decomposition over the extended `QP` basis
/// (`Q` = ciphertext modulus, `P` = auxiliary modulus).
///
/// The KSK stores, for each old-secret component `u` and each partition `j`,
/// a GLWE ciphertext over the `QP` basis encrypting `λ_j · s_u`.
pub struct HybridCrtGlweKeySwitchingKey<T: FheUint> {
    /// Flat storage: [old_secret_component][partition] = QP-basis GLWE
    key: Vec<T>,
    poly_length: usize,
    /// Polynomial length in QP basis: `poly_length * qp_moduli_count`
    qp_rns_poly_len: usize,
    /// GLWE length (mask + body) in QP basis
    qp_rns_glwe_len: usize,
    /// Total KSK entry length: `num_partitions * qp_rns_glwe_len`
    qp_rns_glev_len: usize,
    num_partitions: usize,
    input_rns_glwe_mid: usize,
    output_qp_rns_glwe_mid: usize,
}

impl<T: FheUint> HybridCrtGlweKeySwitchingKey<T> {
    /// Creates a hybrid KSK.
    ///
    /// For each input secret polynomial `s_u` and each partition `j`, a
    /// `QP`-basis GLWE ciphertext is generated encrypting `λ_j · s_u`.
    ///
    /// The generated key is stored in the NTT domain over `QP`.
    pub fn new<R, M, QpTable>(
        input_sk: &CrtGlweSecretKey<T>,
        input_params: &CrtGlweParameters<T, M>,
        output_sk: &DcrtGlweSecretKey<T>,
        hybrid_params: &HybridRNS<T, M>,
        qp_table: &QpTable,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        QpTable: DcrtTable<ValueT = T>,
    {
        let poly_length = input_params.poly_length();
        let qp_moduli = hybrid_params.qp_base().moduli();
        assert_eq!(input_sk.rns_poly_len, input_params.rns_poly_len());
        assert_eq!(output_sk.rns_poly_len, input_params.rns_poly_len());
        assert_eq!(qp_table.poly_length(), poly_length);
        assert_eq!(qp_table.moduli_count(), hybrid_params.qp_moduli_count());
        assert!(
            input_params
                .cipher_moduli()
                .iter()
                .zip(hybrid_params.q_base().moduli())
                .all(|(input_modulus, hybrid_modulus)| unsafe {
                    input_modulus.value_unchecked() == hybrid_modulus.value_unchecked()
                })
        );
        assert!(
            qp_table
                .ntt_tables()
                .iter()
                .zip(qp_moduli)
                .all(|(ntt_table, modulus)| ntt_table.modulus()
                    == unsafe { modulus.value_unchecked() })
        );
        let qp_moduli_values: Vec<T> = qp_moduli
            .iter()
            .map(|m| unsafe { m.value_unchecked() })
            .collect();
        let p_mod_q = hybrid_params.p_mod_q();
        let num_partitions = hybrid_params.partition_count();
        let input_dim = input_sk.key.len() / input_sk.rns_poly_len;
        let output_dim = output_sk.key.len() / output_sk.rns_poly_len;

        let l = hybrid_params.q_moduli_count();
        let k = hybrid_params.p_moduli_count();
        let qp_count = l + k;

        // Build per-modulus uniform distributions for QP basis
        let qp_uniform_distrs: Vec<Uniform<T>> = qp_moduli_values
            .iter()
            .map(|&m| Uniform::new(T::ZERO, m).expect("modulus must be > 0"))
            .collect();

        // Extend output secret key from Q to QP basis
        let t_qp = extend_dcrt_secret_to_qp(output_sk, poly_length, l, k, qp_moduli, qp_table);

        // Noise distribution (reuse from input params)
        let noise_distr = input_params.noise_distribution().clone();

        // KSK layout: [old_secret][partition] = one QP-basis GLWE
        // QP-basis GLWE len = (output_dim + 1) * poly_length * qp_count
        let qp_rns_poly_len = poly_length * qp_count;
        let qp_rns_glwe_len = (output_dim + 1) * qp_rns_poly_len;
        let qp_rns_glev_len = num_partitions * qp_rns_glwe_len;

        let mut key = vec![T::ZERO; input_dim * qp_rns_glev_len];

        for (s_u, key_for_secret) in input_sk
            .iter_crt_poly()
            .zip(key.chunks_exact_mut(qp_rns_glev_len))
        {
            for (partition, glwe) in hybrid_params
                .partitions()
                .zip(key_for_secret.chunks_exact_mut(qp_rns_glwe_len))
            {
                let a_len = output_dim * qp_rns_poly_len;
                let (a_region, b_region) = glwe.split_at_mut(a_len);

                // b: sample Gaussian noise + add message (coefficient domain)
                sample_crt_gaussian_values_to(
                    b_region,
                    poly_length,
                    &qp_moduli_values,
                    &noise_distr,
                    rng,
                );

                // Add P * s_u on this partition's Q limbs.
                let partition_range = partition.q_range();
                let partition_elements =
                    partition_range.start * poly_length..partition_range.end * poly_length;
                for (((s_u_q, b_q), modulus), &scalar) in s_u.as_slice()[partition_elements.clone()]
                    .chunks_exact(poly_length)
                    .zip(b_region[partition_elements].chunks_exact_mut(poly_length))
                    .zip(&qp_moduli[partition_range.clone()])
                    .zip(&p_mod_q[partition_range])
                {
                    for (bv, &sv) in b_q.iter_mut().zip(s_u_q.iter()) {
                        let prod = modulus.reduce_mul(scalar, sv);
                        *bv = modulus.reduce_add(*bv, prod);
                    }
                }

                // NTT-transform b
                qp_table.transform_slice(b_region);

                // For each output secret component v: a_v = uniform, b += a_v * t_v
                let mut b_poly = DcrtPolynomial(b_region);
                for (a_slot, t_v) in a_region
                    .chunks_exact_mut(qp_rns_poly_len)
                    .zip(t_qp.chunks_exact(qp_rns_poly_len))
                {
                    sample_crt_uniform_values_to(a_slot, poly_length, &qp_uniform_distrs, rng);
                    b_poly.add_mul_assign(
                        &DcrtPolynomial(a_slot),
                        &DcrtPolynomial(t_v),
                        poly_length,
                        qp_moduli,
                    );
                }
            }
        }

        let input_rns_glwe_mid = input_params.rns_glwe_mid();
        let output_qp_rns_glwe_mid = output_dim * qp_rns_poly_len;

        Self {
            key,
            poly_length,
            qp_rns_poly_len,
            qp_rns_glwe_len,
            qp_rns_glev_len,
            num_partitions,
            input_rns_glwe_mid,
            output_qp_rns_glwe_mid,
        }
    }

    /// Returns the number of QP-basis moduli per polynomial.
    pub fn qp_rns_poly_len(&self) -> usize {
        self.qp_rns_poly_len
    }

    /// Returns the number of partitions (gadget levels).
    pub fn partition_count(&self) -> usize {
        self.num_partitions
    }

    /// Hybrid RNS key switching.
    ///
    /// Converts `c_in` (encrypted under the old secret key, coefficient
    /// domain, `Q` basis) to `c_out` (encrypted under the new secret key,
    /// NTT domain, `Q` basis) using partition-based gadget decomposition
    /// over the extended `QP` basis.
    pub fn key_switch_inplace<M, Table, A, B>(
        &self,
        c_in: &CrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        hybrid_params: &HybridRNS<T, M>,
        table: &Table,
        context: &mut HybridCrtGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.poly_length;
        let q_count = hybrid_params.q_moduli_count();
        let qp_rns_poly_len = self.qp_rns_poly_len;
        let q_rns_poly_len = poly_length * q_count;
        let output_dim = self.output_qp_rns_glwe_mid / qp_rns_poly_len;

        assert_eq!(table.poly_length(), poly_length);
        assert_eq!(table.moduli_count(), hybrid_params.qp_moduli_count());
        assert_eq!(
            qp_rns_poly_len,
            poly_length * hybrid_params.qp_moduli_count()
        );
        assert_eq!(self.num_partitions, hybrid_params.partition_count());
        assert_eq!(context.output_dimension, output_dim);
        assert_eq!(context.poly_length, poly_length);
        assert_eq!(context.q_moduli_count, q_count);
        assert_eq!(context.qp_moduli_count, hybrid_params.qp_moduli_count());

        // Split input into mask and body (coefficient domain, Q basis)
        let (a_in, b_in) = c_in.a_b(self.input_rns_glwe_mid);
        assert_eq!(a_in.len(), self.key.len() / self.qp_rns_glev_len);

        context.accumulator_qp.fill(T::ZERO);

        // --- Phase 1: ModUp + QP MAC ---
        for (a_u, key_for_secret) in a_in.zip(self.key.chunks_exact(self.qp_rns_glev_len)) {
            for (partition, glwe) in hybrid_params
                .partitions()
                .zip(key_for_secret.chunks_exact(self.qp_rns_glwe_len))
            {
                let scratch_len = partition.moduli_count() * poly_length;
                partition.approx_mod_up(
                    a_u.as_slice(),
                    &mut context.digit_qp,
                    poly_length,
                    &mut context.mod_up_scratch[..scratch_len],
                );
                table.transform_slice(&mut context.digit_qp);

                for (accumulator, key_polynomial) in context
                    .accumulator_qp
                    .chunks_exact_mut(qp_rns_poly_len)
                    .zip(glwe.chunks_exact(qp_rns_poly_len))
                {
                    DcrtPolynomial(accumulator).add_mul_assign(
                        &DcrtPolynomial(context.digit_qp.as_slice()),
                        &DcrtPolynomial(key_polynomial),
                        poly_length,
                        hybrid_params.qp_base().moduli(),
                    );
                }
            }
        }

        // --- Phase 2: ModDown QP → Q ---
        let moduli_q = hybrid_params.q_base().moduli();
        for accumulator in context.accumulator_qp.chunks_exact_mut(qp_rns_poly_len) {
            table.inverse_transform_slice(accumulator);
            hybrid_params.approx_mod_down(
                accumulator,
                poly_length,
                &mut context.digit_qp[..q_rns_poly_len],
                &mut context.mod_down_scratch,
            );
            table.ntt_tables()[..q_count]
                .iter()
                .zip(accumulator[..q_rns_poly_len].chunks_exact_mut(poly_length))
                .for_each(|(ntt_table, q_limb)| ntt_table.transform_slice(q_limb));
        }

        // --- Phase 3: Finalize output ---
        // Match the proven pattern from CrtGlweKeySwitchingKey::key_swithching_inplace
        c_out.set_zero();

        // Q-basis midpoint for output ciphertext
        let output_rns_glwe_mid = output_dim * q_rns_poly_len;

        let (accumulator_mask, accumulator_body) = context
            .accumulator_qp
            .split_at(output_dim * qp_rns_poly_len);
        let (a_out, b_out) = c_out.a_b_mut_slices(output_rns_glwe_mid);
        a_out
            .chunks_exact_mut(q_rns_poly_len)
            .zip(accumulator_mask.chunks_exact(qp_rns_poly_len))
            .for_each(|(output, accumulator)| {
                output.copy_from_slice(&accumulator[..q_rns_poly_len]);
            });
        b_out.copy_from_slice(&accumulator_body[..q_rns_poly_len]);

        // Negate the full accumulator
        c_out.neg_assign(q_rns_poly_len, poly_length, moduli_q);

        // NTT input body and add (reuse context buffer)
        let body_q = &mut context.digit_qp[..q_rns_poly_len];
        body_q.copy_from_slice(b_in.as_slice());
        table.ntt_tables()[..q_count]
            .iter()
            .zip(body_q.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.transform_slice(q_limb));
        let (_, b_out) = c_out.a_b_mut_slices(output_rns_glwe_mid);
        DcrtPolynomial(b_out).add_assign(&DcrtPolynomial(body_q), poly_length, moduli_q);
    }
}

/// Reusable scratch space for hybrid RNS key switching.
///
/// All temporary buffers used in the hot path are allocated once here
/// and reused across [`HybridCrtGlweKeySwitchingKey::key_switch_inplace`] calls.
pub struct HybridCrtGlweKeySwitchingContext<T: FheUint> {
    accumulator_qp: Vec<T>,
    digit_qp: Vec<T>,
    mod_up_scratch: Vec<T>,
    mod_down_scratch: Vec<T>,
    poly_length: usize,
    q_moduli_count: usize,
    qp_moduli_count: usize,
    output_dimension: usize,
}

impl<T: FheUint> HybridCrtGlweKeySwitchingContext<T> {
    /// Creates reusable scratch space sized from the hybrid parameters.
    pub fn new<M>(
        key_switching_key: &HybridCrtGlweKeySwitchingKey<T>,
        hybrid_params: &HybridRNS<T, M>,
    ) -> Self
    where
        M: FieldContext<T>,
    {
        assert_eq!(
            key_switching_key.num_partitions,
            hybrid_params.partition_count()
        );
        assert_eq!(
            key_switching_key.qp_rns_poly_len % hybrid_params.qp_moduli_count(),
            0
        );

        let poly_length = key_switching_key.poly_length;
        let output_dimension =
            key_switching_key.output_qp_rns_glwe_mid / key_switching_key.qp_rns_poly_len;
        let q_moduli_count = hybrid_params.q_moduli_count();
        let p_moduli_count = hybrid_params.p_moduli_count();
        let qp_moduli_count = hybrid_params.qp_moduli_count();
        let qp_poly_len = qp_moduli_count * poly_length;

        Self {
            accumulator_qp: vec![T::ZERO; (output_dimension + 1) * qp_poly_len],
            digit_qp: vec![T::ZERO; qp_poly_len],
            mod_up_scratch: vec![T::ZERO; hybrid_params.max_partition_moduli_count() * poly_length],
            mod_down_scratch: vec![T::ZERO; p_moduli_count * poly_length],
            poly_length,
            q_moduli_count,
            qp_moduli_count,
            output_dimension,
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: extend DCRT secret key from Q to QP basis
// ---------------------------------------------------------------------------

/// Extends a DCRT secret key from `Q` basis to `QP` basis.
///
/// `Q` limbs are copied directly (already NTT). `P` limbs are computed by
/// interpreting the first `Q`-limb residues as signed coefficients (valid for
/// ternary/small secrets), reducing modulo each `P` modulus, and NTT
/// transforming.
fn extend_dcrt_secret_to_qp<T, M, QpTable>(
    sk_q: &DcrtGlweSecretKey<T>,
    poly_length: usize,
    q_moduli_count: usize,
    p_moduli_count: usize,
    qp_moduli: &[M],
    qp_table: &QpTable,
) -> Vec<T>
where
    T: FheUint,
    M: FieldContext<T>,
    QpTable: DcrtTable<ValueT = T>,
{
    let dim = sk_q.key.len() / sk_q.rns_poly_len;
    let qp_rns_poly_len = poly_length * (q_moduli_count + p_moduli_count);
    let mut result = vec![T::ZERO; dim * qp_rns_poly_len];

    let q_rns_poly_len = poly_length * q_moduli_count;

    for (poly_in, poly_out) in sk_q
        .iter_dcrt_poly()
        .zip(result.chunks_exact_mut(qp_rns_poly_len))
    {
        let (poly_out_mod_q, poly_out_mod_p) = poly_out.split_at_mut(q_rns_poly_len);

        // Copy Q limbs (NTT form)
        poly_out_mod_q.copy_from_slice(poly_in.as_slice());

        // INTT the first Q limb to recover the small signed coefficients.
        let mut coefficients = poly_in.as_slice()[..poly_length].to_vec();
        qp_table.ntt_tables()[0].inverse_transform_slice(&mut coefficients);

        let q0_mod = unsafe { qp_moduli[0].value_unchecked() };
        let half_q0 = (q0_mod + T::ONE) / T::TWO;

        // Build P limbs from signed coefficients
        for ((p_limb, pi), table) in poly_out_mod_p
            .chunks_exact_mut(poly_length)
            .zip(&qp_moduli[q_moduli_count..])
            .zip(&qp_table.ntt_tables()[q_moduli_count..])
        {
            let p_mod = unsafe { pi.value_unchecked() };

            for (c, &coeff_c) in p_limb.iter_mut().zip(coefficients.iter()) {
                let signed_mod_p = if coeff_c > half_q0 {
                    p_mod.wrapping_sub(q0_mod.wrapping_sub(coeff_c))
                } else {
                    pi.reduce(coeff_c)
                };
                *c = signed_mod_p;
            }

            table.transform_slice(p_limb);
        }
    }

    result
}
