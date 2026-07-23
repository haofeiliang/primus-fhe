use primus_data::{Data, DataMut, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_distr::{sample_crt_gaussian_values_to, sample_crt_uniform_values_to};
use primus_integer::FheUint;
use primus_lattice::{
    context::DcrtGlevContext,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
};
use primus_modulo::prelude::*;
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
    /// Total KSK entry length: `num_parts * qp_rns_glwe_len`
    qp_rns_glev_len: usize,
    input_rns_glwe_mid: usize,
    output_qp_rns_glwe_mid: usize,
}

impl<T: FheUint> HybridCrtGlweKeySwitchingKey<T> {
    /// Creates a hybrid KSK.
    ///
    /// For each input secret polynomial `s_u` and each partition `j`, a
    /// `QP`-basis GLWE ciphertext is generated encrypting `λ_j · s_u`.
    ///
    /// The key is stored in coefficient domain (no NTT) for simplicity;
    /// NTT-domain optimisation is deferred to a later phase.
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
        let qp_moduli_values: Vec<T> = qp_moduli
            .iter()
            .map(|m| unsafe { m.value_unchecked() })
            .collect();
        let p_mod_q = hybrid_params.p_mod_q();
        let num_parts = hybrid_params.num_parts();
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
        let qp_rns_glev_len = num_parts * qp_rns_glwe_len;

        let mut key = vec![T::ZERO; input_dim * qp_rns_glev_len];

        for (u, s_u) in input_sk.iter_crt_poly().enumerate() {
            let ksk_u_start = u * qp_rns_glev_len;

            for (part_idx, part) in hybrid_params.partitions().iter().enumerate() {
                let glwe_start = ksk_u_start + part_idx * qp_rns_glwe_len;
                let a_len = output_dim * qp_rns_poly_len;

                let (a_region, b_region) =
                    key[glwe_start..glwe_start + qp_rns_glwe_len].split_at_mut(a_len);

                // b: sample Gaussian noise + add message (coefficient domain)
                sample_crt_gaussian_values_to(
                    b_region,
                    poly_length,
                    &qp_moduli_values,
                    &noise_distr,
                    rng,
                );

                // Add message: on this partition's q limbs
                let part_indices = &part.q_indices;
                for q_idx in part_indices.clone() {
                    let s_u_q = &s_u.as_slice()[q_idx * poly_length..][..poly_length];
                    let b_q = &mut b_region[q_idx * poly_length..][..poly_length];
                    let modulus = qp_moduli[q_idx];
                    let scalar = p_mod_q[q_idx];
                    for (bv, &sv) in b_q.iter_mut().zip(s_u_q.iter()) {
                        let prod = modulus.reduce_mul(scalar, sv);
                        *bv = modulus.reduce_add(*bv, prod);
                    }
                }

                // NTT-transform b
                qp_table.transform_slice(b_region);

                // For each output secret component v: a_v = uniform, b += a_v * t_v
                // Sample a_v into a temp vec to avoid borrow conflicts
                let mut a_temp = vec![T::ZERO; qp_rns_poly_len];
                let mut b_poly = DcrtPolynomial(b_region);
                for (v, t_v) in t_qp.chunks_exact(qp_rns_poly_len).enumerate() {
                    sample_crt_uniform_values_to(&mut a_temp, poly_length, &qp_uniform_distrs, rng);

                    // Copy a_temp into the key storage
                    let a_slot = &mut a_region[v * qp_rns_poly_len..][..qp_rns_poly_len];
                    a_slot.copy_from_slice(&a_temp);

                    // b += a_temp * t_v (pointwise, NTT domain)
                    b_poly.add_mul_assign(
                        &DcrtPolynomial(a_temp.as_slice()),
                        &DcrtPolynomial(t_v),
                        poly_length,
                        qp_moduli,
                    );
                }
                let _ = b_poly; // ensure b_poly lives long enough
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
            input_rns_glwe_mid,
            output_qp_rns_glwe_mid,
        }
    }

    /// Returns the number of QP-basis moduli per polynomial.
    pub fn qp_rns_poly_len(&self) -> usize {
        self.qp_rns_poly_len
    }

    /// Returns the number of partitions (gadget levels).
    pub fn num_parts(&self) -> usize {
        self.qp_rns_glev_len / self.qp_rns_glwe_len
    }

    /// Hybrid RNS key switching.
    ///
    /// Converts `c_in` (encrypted under the old secret key, coefficient
    /// domain, `Q` basis) to `c_out` (encrypted under the new secret key,
    /// NTT domain, `Q` basis) using partition-based gadget decomposition
    /// over the extended `QP` basis.
    pub fn key_switch_hybrid_inplace<M, Table, A, B>(
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
        let p_count = hybrid_params.p_moduli_count();
        let qp_rns_poly_len = self.qp_rns_poly_len; // N * qp_count
        let q_rns_poly_len = poly_length * q_count;
        let output_dim = self.output_qp_rns_glwe_mid / qp_rns_poly_len;

        // Split input into mask and body (coefficient domain, Q basis)
        let (a_in, b_in) = c_in.a_b(self.input_rns_glwe_mid);

        context.clear_accumulator(output_dim + 1, qp_rns_poly_len);
        let acc = &mut context.accumulator_qp;

        // --- Phase 1: ModUp + QP MAC ---
        // Use pre-allocated context buffers — no heap alloc in hot path.
        let digit_qp_coeff = &mut context.digit_qp_coeff;
        let digit_qp_ntt = &mut context.digit_qp_ntt;
        let mod_up_out = &mut context.mod_up_out;

        for (u, a_u) in a_in.enumerate() {
            let ksk_u = &self.key[u * self.qp_rns_glev_len..];
            let a_u_slice = a_u.as_slice();

            for (part_idx, part) in hybrid_params.partitions().iter().enumerate() {
                let part_size = part.q_indices.len();

                // 1a. ModUp: partition residues → complement+P (batch, modulus-major)
                let converter = &hybrid_params.mod_up_converters()[part_idx];
                let compl_count = converter.output_moduli_count();
                debug_assert!(
                    compl_count * poly_length <= mod_up_out.len(),
                    "mod_up_out buffer too small"
                );
                hybrid_params.mod_up_polynomial_batch(
                    part_idx,
                    a_u_slice,
                    &mut mod_up_out[..compl_count * poly_length],
                    poly_length,
                    &mut context.mod_up_array_scratch[..part_size * poly_length],
                );

                // 1b. Assemble QP digit in coefficient domain
                digit_qp_coeff.fill(T::ZERO);
                for global in part.q_indices.clone() {
                    digit_qp_coeff[global * poly_length..][..poly_length]
                        .copy_from_slice(&a_u_slice[global * poly_length..][..poly_length]);
                }
                for out_idx in 0..compl_count {
                    let qp_pos = if out_idx < part.q_indices.start {
                        out_idx
                    } else if out_idx < q_count - part_size {
                        out_idx + part_size
                    } else {
                        q_count + (out_idx - (q_count - part_size))
                    };
                    digit_qp_coeff[qp_pos * poly_length..][..poly_length]
                        .copy_from_slice(&mod_up_out[out_idx * poly_length..][..poly_length]);
                }

                // 1c. NTT the full QP digit
                digit_qp_ntt.copy_from_slice(digit_qp_coeff);
                table.transform_slice(digit_qp_ntt);

                // 1d. MAC: acc += digit_qp_ntt * KSK[u][part_idx]
                let glwe_start = part_idx * self.qp_rns_glwe_len;
                let glwe = &ksk_u[glwe_start..glwe_start + self.qp_rns_glwe_len];
                let (a_entries, b_entry) = glwe.split_at(self.output_qp_rns_glwe_mid);
                let qp_moduli = hybrid_params.qp_base().moduli();

                // acc_body += digit_qp_ntt * KSK_b
                DcrtPolynomial(acc[output_dim].as_mut_slice()).add_mul_assign(
                    &DcrtPolynomial(digit_qp_ntt.as_slice()),
                    &DcrtPolynomial(b_entry),
                    poly_length,
                    qp_moduli,
                );

                // acc_v += digit_qp_ntt * KSK_a_v
                for (v, ksk_a_chunk) in
                    a_entries.chunks_exact(qp_rns_poly_len).enumerate()
                {
                    DcrtPolynomial(acc[v].as_mut_slice()).add_mul_assign(
                        &DcrtPolynomial(digit_qp_ntt.as_slice()),
                        &DcrtPolynomial(ksk_a_chunk),
                        poly_length,
                        qp_moduli,
                    );
                }
            }
        }

        // --- Phase 2: ModDown QP → Q ---
        let moduli_q = hybrid_params.q_base().moduli();
        let p_inv = hybrid_params.p_inv_mod_q();
        let r_p_buf = &mut context.r_p_buf;
        let conv_scratch = &mut context.conv_scratch;
        let fcs = &mut context.fcs;

        for acc_poly in acc.iter_mut() {
            table.inverse_transform_slice(&mut acc_poly[..qp_rns_poly_len]);
            let (q_limbs, p_limbs) = acc_poly.split_at_mut(q_rns_poly_len);

            for c in 0..poly_length {
                for (i, r_p) in r_p_buf[..p_count].iter_mut().enumerate() {
                    *r_p = p_limbs[i * poly_length + c];
                }
                hybrid_params.mod_down_converter().fast_convert(
                    &r_p_buf[..p_count],
                    &mut conv_scratch[..q_count],
                    &mut fcs[..p_count],
                );
                for qi in 0..q_count {
                    let r_mod_q = conv_scratch[qi];
                    let z = q_limbs[qi * poly_length + c];
                    let diff = if z >= r_mod_q {
                        z - r_mod_q
                    } else {
                        unsafe { moduli_q[qi].value_unchecked() - r_mod_q + z }
                    };
                    q_limbs[qi * poly_length + c] = diff.mul_modulo(p_inv[qi], moduli_q[qi]);
                }
            }

            let qp_full = &mut acc_poly[..qp_rns_poly_len];
            qp_full[q_rns_poly_len..].fill(T::ZERO);
            table.transform_slice(qp_full);
        }

        // --- Phase 3: Finalize output ---
        // Match the proven pattern from CrtGlweKeySwitchingKey::key_swithching_inplace
        c_out.set_zero();

        // Q-basis midpoint for output ciphertext
        let output_rns_glwe_mid = output_dim * q_rns_poly_len;

        // Write accumulator mask components
        let (a_out, _) = c_out.a_b_mut_slices(output_rns_glwe_mid);
        for (v, acc_v) in acc.iter().take(output_dim).enumerate() {
            let dst = &mut a_out[v * q_rns_poly_len..][..q_rns_poly_len];
            dst.copy_from_slice(&acc_v[..q_rns_poly_len]);
        }
        // Write accumulator body
        let (_, b_out) = c_out.a_b_mut_slices(output_rns_glwe_mid);
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(&acc[output_dim][..q_rns_poly_len]),
            poly_length,
            moduli_q,
        );

        // Negate the full accumulator
        c_out.neg_assign(q_rns_poly_len, poly_length, moduli_q);

        // NTT input body and add (reuse context buffer)
        let body_qp = &mut context.body_qp;
        body_qp.fill(T::ZERO);
        body_qp[..q_rns_poly_len].copy_from_slice(b_in.as_slice());
        table.transform_slice(&mut body_qp[..]);
        let (_, b_out) = c_out.a_b_mut_slices(output_rns_glwe_mid);
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(&body_qp[..q_rns_poly_len]),
            poly_length,
            moduli_q,
        );
    }
}

/// Reusable scratch space for hybrid RNS key switching.
///
/// All temporary buffers used in the hot path are allocated once here
/// and reused across `key_switch_hybrid_inplace` calls.
pub struct HybridCrtGlweKeySwitchingContext<T: FheUint> {
    /// QP-basis accumulator: [mask_0, ..., mask_{k-1}, body]
    pub(crate) accumulator_qp: Vec<Vec<T>>,

    // ---- Phase 1 buffers -------------------------------------------------
    /// QP digit (coefficient domain), len = qp_count * N
    digit_qp_coeff: Vec<T>,
    /// QP digit (NTT domain), len = qp_count * N
    digit_qp_ntt: Vec<T>,
    /// ModUp output (complement + P residues, modulus-major)
    mod_up_out: Vec<T>,
    /// ModUp array scratch (coefficient-major), len = max_part_size * N
    mod_up_array_scratch: Vec<T>,

    // ---- Phase 2 buffers -------------------------------------------------
    /// P-residue gather buffer, len = P moduli count
    r_p_buf: Vec<T>,
    /// Fast-convert output (Q residues), len = Q moduli count
    conv_scratch: Vec<T>,
    /// Fast-convert scratch, len = P moduli count
    fcs: Vec<T>,

    // ---- Phase 3 buffers -------------------------------------------------
    /// Body NTT buffer (QP-padded), len = qp_count * N
    body_qp: Vec<T>,
}

impl<T: FheUint> HybridCrtGlweKeySwitchingContext<T> {
    /// Creates a hybrid key switching context with all buffers pre-allocated.
    pub fn new(
        max_part_moduli_count: usize,
        q_moduli_count: usize,
        p_moduli_count: usize,
        poly_length: usize,
        max_dimension: usize,
    ) -> Self {
        let qp_count = q_moduli_count + p_moduli_count;
        let qp_poly_len = qp_count * poly_length;
        let max_compl_p = (q_moduli_count - 1) + p_moduli_count;

        Self {
            accumulator_qp: Vec::with_capacity(max_dimension + 1),
            digit_qp_coeff: vec![T::ZERO; qp_poly_len],
            digit_qp_ntt: vec![T::ZERO; qp_poly_len],
            mod_up_out: vec![T::ZERO; max_compl_p * poly_length],
            mod_up_array_scratch: vec![T::ZERO; max_part_moduli_count * poly_length],
            r_p_buf: vec![T::ZERO; p_moduli_count],
            conv_scratch: vec![T::ZERO; q_moduli_count],
            fcs: vec![T::ZERO; p_moduli_count],
            body_qp: vec![T::ZERO; qp_poly_len],
        }
    }

    /// Ensures the accumulator has `rows` entries of at least `len` elements, zeroed.
    pub(crate) fn clear_accumulator(&mut self, rows: usize, len: usize) {
        self.accumulator_qp.resize(rows, vec![]);
        for entry in self.accumulator_qp.iter_mut().take(rows) {
            if entry.len() < len {
                *entry = vec![T::ZERO; len];
            } else {
                entry.truncate(len);
                entry.fill(T::ZERO);
            }
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

    for (i, poly) in sk_q.iter_dcrt_poly().enumerate() {
        let out = &mut result[i * qp_rns_poly_len..][..qp_rns_poly_len];

        // Copy Q limbs (NTT form)
        out[..q_rns_poly_len].copy_from_slice(poly.as_slice());

        // INTT the first Q limb to recover the small signed coefficients.
        let mut coefficients = poly.as_slice()[..poly_length].to_vec();
        qp_table.ntt_tables()[0].inverse_transform_slice(&mut coefficients);

        let q0_mod = unsafe { qp_moduli[0].value_unchecked() };
        let half_q0 = (q0_mod + T::ONE) / T::TWO;

        // Build P limbs from signed coefficients
        for p_idx in 0..p_moduli_count {
            let p_start = q_rns_poly_len + p_idx * poly_length;
            let p_mod = unsafe { qp_moduli[q_moduli_count + p_idx].value_unchecked() };

            let p_limb = &mut out[p_start..p_start + poly_length];
            for c in 0..poly_length {
                let coeff_c = coefficients[c];
                let signed_mod_p = if coeff_c > half_q0 {
                    p_mod.wrapping_sub(q0_mod.wrapping_sub(coeff_c))
                } else {
                    coeff_c % p_mod
                };
                p_limb[c] = signed_mod_p;
            }

            qp_table.ntt_tables()[q_moduli_count + p_idx].transform_slice(p_limb);
        }
    }

    result
}
