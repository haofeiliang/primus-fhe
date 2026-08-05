use itertools::izip;
use primus_factor::FactorMul;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweParameters, CrtGlweTraceContext, CrtGlweTraceKey, DcrtGadgetDomain,
    DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweRevTraceContext, DcrtGlweRevTraceKey,
    DcrtGlweSecretKey, DcrtGlweTraceContext, DcrtGlweTraceKey, GlweSecretKey, RingSecretKeyType,
};
use primus_integer::BigUint;
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial, Polynomial};
use primus_reduce::prelude::*;

/// Test GLWE trace in the coefficient (CRT) domain.
///
/// Trace decrypts the constant coefficient m₀ of a ciphertext:
///   Trace(c) → Enc(N · m₀),  where N = poly_length.
///
/// Multiplying the input ciphertext by N⁻¹ before the trace recovers
/// the original m₀ directly (without the N factor).
/// Both variants are verified.
#[test]
fn test_crt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // ── Trace key (CRT domain) ──────────────────────────────────
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = CrtGlweTraceKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut trace_context = CrtGlweTraceContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Standard trace: output encrypts N · m₀ ──────────────────
    let mut c1 = c1.into_coeff_form(&table);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    // trace_msg[0] = N · input1[0]  (mod t)
    assert_eq!(
        mod_t.reduce_mul(input1[0], poly_length as ValueT),
        trace_msg[0]
    );
    // Other coefficients are zero.
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    // ── After multiplying input by N⁻¹, trace recovers m₀ directly ──
    let scalar_residue = base_q
        .wrapping_decompose(poly_length as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(&scalar_residue, poly_length, rns_poly_len, &moduli);

    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::new(c2.0);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test GLWE trace in the NTT (DCRT) domain.
///
/// Same as [`test_crt_glwe_trace`] but the ciphertext stays in NTT domain.
#[test]
fn test_dcrt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    // ── Trace key (DCRT domain) ─────────────────────────────────
    let trace_key = DcrtGlweTraceKey::new(&domain, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut trace_context = DcrtGlweTraceContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Standard trace: output encrypts N · m₀ ──────────────────
    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(
        mod_t.reduce_mul(input1[0], poly_length as ValueT),
        trace_msg[0]
    );
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    // ── Multiply by N⁻¹ → trace recovers m₀ directly ────────────
    let scalar_residue = base_q
        .wrapping_decompose(poly_length as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(&scalar_residue, poly_length, rns_poly_len, &moduli);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test reverse-homomorphic trace in the NTT (DCRT) domain.
///
/// RevHomTrace directly produces an encryption of m₀ (without the N factor),
/// unlike the standard trace which produces N · m₀.
#[test]
fn test_dcrt_glwe_rev_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let rev_trace_key = DcrtGlweRevTraceKey::new(&domain, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut trace_context = DcrtGlweRevTraceContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── RevHomTrace: output encrypts m₀ directly (no N factor) ──
    rev_trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Measure and compare noise growth for standard trace vs. RevHomTrace.
///
/// Encrypts a random plaintext, applies both trace variants, extracts the
/// phase (noisy plaintext in CRT form), and computes the noise as
///   e = phase − δ·m  (centered in [-Q/2, Q/2)).
///
/// Asserts that both trace variants leave enough decryption budget.
#[test]
fn test_dcrt_glwe_rev_trace_noise() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 2048;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let moduli_count = glwe_params.cipher_moduli_count();
    let rns_poly_len = glwe_params.rns_poly_len();
    let big_uint_poly_len = glwe_params.big_uint_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let big_uint_value_len = glwe_params.big_uint_value_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = DcrtGlweTraceKey::new(&domain, &dcrt_sk, &mut rng);
    let rev_trace_key = DcrtGlweRevTraceKey::new(&domain, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut trace_context = DcrtGlweRevTraceContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    // ═══════════════════════════════════════════════════════════════
    //  Noise measurement helpers
    // ═══════════════════════════════════════════════════════════════

    let q_big = base_q.moduli_product();
    let delta_factor_mod_q = glwe_params.codec().delta_factor_mod_q();
    let moduli_values = glwe_params.codec().moduli_values();

    // Q/2 for centering noise into [-Q/2, Q/2)
    let mut half_q = BigUint(q_big.0.to_vec());
    half_q.right_shift_assign(1);

    // BigUint (little-endian u64 limbs) → f64
    let biguint_to_f64 = |v: BigUint<&[ValueT]>| -> f64 {
        v.digits()
            .iter()
            .rev()
            .fold(0.0f64, |acc, &limb| acc * 2.0f64.powi(64) + limb as f64)
    };

    // Compute noise statistics from a phase (already INTT'd to CRT coeff form)
    // and an expected plaintext polynomial.
    //   phase(X) = δ·m(X) + e(X)  mod Q
    //   noise  e = phase − δ·m    mod Q, centered in [-Q/2, Q/2)
    // Returns (std_dev, log2_std, log2_max).
    let measure_noise = |phase_crt_data: &[ValueT], expected_msg: &[ValueT]| -> (f64, f64, f64) {
        // ── Encode expected message into CRT residues: δ_i · m_j mod q_i ──
        let mut expected_crt = vec![0u64; rns_poly_len];
        let mut compose_buffer = vec![0; moduli_count];
        for (chunk, delta_factor, &modulus_value) in izip!(
            expected_crt.chunks_exact_mut(poly_length),
            delta_factor_mod_q,
            moduli_values,
        ) {
            for (slot, value) in chunk.iter_mut().zip(expected_msg) {
                *slot = delta_factor.factor_mul_modulo(*value, modulus_value);
            }
        }

        // ── CRT → BigUint polynomial (exact integer representation) ──
        let mut big_phase: BigUintPolynomial<Vec<ValueT>> =
            BigUintPolynomial::zero(big_uint_poly_len);
        let mut big_expected: BigUintPolynomial<Vec<ValueT>> =
            BigUintPolynomial::zero(big_uint_poly_len);
        base_q.compose_polynomial_to(
            &CrtPolynomial(phase_crt_data),
            &mut big_phase,
            poly_length,
            &mut compose_buffer,
        );
        base_q.compose_polynomial_to(
            &CrtPolynomial(expected_crt.as_slice()),
            &mut big_expected,
            poly_length,
            &mut compose_buffer,
        );

        // ── noise = (phase − expected) mod Q, coefficient-wise ──
        let mut big_noise: BigUintPolynomial<Vec<ValueT>> =
            BigUintPolynomial::zero(big_uint_poly_len);
        big_phase.sub_to(&big_expected, &mut big_noise, &q_big);

        // ── Center each coefficient into [-Q/2, Q/2) and compute stats ──
        let mut sum_sq: f64 = 0.0;
        let mut max_abs: f64 = 0.0;
        for noise_j in big_noise.iter(big_uint_value_len) {
            let abs_f64 = if noise_j.cmp(&half_q).is_gt() {
                // Negative noise: |e| = Q − noise
                let mut neg = BigUint(q_big.0.to_vec());
                let _ = neg.sub_assign(&noise_j);
                biguint_to_f64(neg.view())
            } else {
                biguint_to_f64(noise_j)
            };
            sum_sq += abs_f64 * abs_f64;
            if abs_f64 > max_abs {
                max_abs = abs_f64;
            }
        }
        let std_dev = (sum_sq / poly_length as f64).sqrt();
        (std_dev, std_dev.log2(), max_abs.log2())
    };

    // ═══════════════════════════════════════════════════════════════
    //  Measure fresh ciphertext noise (baseline)
    // ═══════════════════════════════════════════════════════════════
    let mut phase: DcrtPolynomial<Vec<ValueT>> = DcrtPolynomial::zero(rns_poly_len);
    dcrt_sk.phase_inplace(&c1, &mut phase, &glwe_params);
    table.inverse_transform_slice(phase.as_mut());

    let fresh_msg: Vec<ValueT> = input1.0.clone();
    let (_, fresh_log2, _) = measure_noise(phase.as_ref(), &fresh_msg);

    let mut c1_clone = c1.clone();

    // ═══════════════════════════════════════════════════════════════
    //  Standard DcrtGlweTrace noise
    // ═══════════════════════════════════════════════════════════════

    // Multiply by N⁻¹ so standard trace outputs m₀ without N factor,
    // making noise comparison fair against RevHomTrace.
    let scalar_residue = base_q
        .wrapping_decompose(poly_length as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1_clone.mul_scalar_assign(&scalar_residue, poly_length, rns_poly_len, &moduli);

    trace_key.trace_inplace(&c1_clone, &mut c2, &domain, &mut trace_context);

    // Verify correctness
    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    // Extract phase and measure noise
    dcrt_sk.phase_inplace(&c2, &mut phase, &glwe_params);
    table.inverse_transform_slice(phase.as_mut());

    // Standard trace: expected plaintext is (m_0, 0, …, 0)
    let mut std_trace_msg = vec![0u64; poly_length];
    std_trace_msg[0] = input1[0];
    let (_, std_trace_log2, std_trace_max_log2) = measure_noise(phase.as_ref(), &std_trace_msg);

    // ═══════════════════════════════════════════════════════════════
    //  RevHomTrace noise
    // ═══════════════════════════════════════════════════════════════
    rev_trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_context);

    // Verify correctness
    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    dcrt_sk.phase_inplace(&c2, &mut phase, &glwe_params);
    table.inverse_transform_slice(phase.as_mut());

    let mut rev_trace_msg = vec![0u64; poly_length];
    rev_trace_msg[0] = input1[0];
    let (_, rev_trace_log2, rev_trace_max_log2) = measure_noise(phase.as_ref(), &rev_trace_msg);

    // ═══════════════════════════════════════════════════════════════
    //  Report and assertions
    // ═══════════════════════════════════════════════════════════════
    let log2_q = biguint_to_f64(q_big).log2();
    let log2_budget = log2_q - (t as f64).log2();
    println!(
        "=== Trace Noise Analysis (N={poly_length}, k={dimension}, log(N)={log_n}, t=2^{}, log2(Q)={log2_q:.1}) ===",
        (t as f64).log2() as u32
    );
    println!("  Fresh encrypt: log2(std) = {:>6.2}", fresh_log2);
    println!(
        "  Std trace:     log2(std) = {:>6.2},  log2(max) = {:>6.2}",
        std_trace_log2, std_trace_max_log2,
    );
    println!(
        "  Rev trace:     log2(std) = {:>6.2},  log2(max) = {:>6.2}",
        rev_trace_log2, rev_trace_max_log2,
    );
    println!(
        "  Budget log2(Q/t) = {log2_budget:.1},  remaining(std) = {:.1} / remaining(rev) = {:.1}",
        log2_budget - std_trace_log2,
        log2_budget - rev_trace_log2,
    );

    // Assert noise is within the decryption budget (with comfortable margin).
    assert!(
        log2_budget - rev_trace_log2 > 5.0,
        "RevHomTrace noise exceeds budget: log2(std) = {rev_trace_log2:.2}, log2(Q/t) = {log2_budget:.1}"
    );
    assert!(
        log2_budget - std_trace_log2 > 5.0,
        "Standard trace noise exceeds budget: log2(std) = {std_trace_log2:.2}, log2(Q/t) = {log2_budget:.1}"
    );
}
