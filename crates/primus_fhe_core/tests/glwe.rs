use primus_fhe_core::{
    glwe::{GlweSecretKey, RingSecretKeyType},
    rns_fhe::{CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey},
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;
use rand::distr::Uniform;

type ValueT = u64;

const DIMENSION: usize = 2;
const POLY_LENGTH: usize = 512;
const NOISE_STANDARD_DEVIATION: f64 = 3.2;
const SECRET_KEY_GAUSSIAN_STANDARD_DEVIATION: f64 = 3.2;
const PLAIN_MODULI: [ValueT; 3] = [256, 257, 12_289];
const GAMMA_MODULUS: ValueT = 2_305_843_009_213_554_689;
const CIPHER_MODULI: [ValueT; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
const SECRET_KEY_TYPES: [RingSecretKeyType; 3] = [
    RingSecretKeyType::Binary,
    RingSecretKeyType::Ternary,
    RingSecretKeyType::Gaussian(SECRET_KEY_GAUSSIAN_STANDARD_DEVIATION),
];

/// Construct a deterministic test pattern: m_i = i mod t
fn message_polynomial(plain_modulus: ValueT) -> Polynomial<Vec<ValueT>> {
    Polynomial::random_with_distribution(
        POLY_LENGTH,
        &Uniform::new(0, plain_modulus).unwrap(),
        &mut rand::rng(),
    )
}

/// Manually decompose a polynomial into CRT form (centered lifting, no delta scaling).
/// Used to test the low-level `encrypt_inplace` API directly.
fn decompose_message<M>(
    message: &Polynomial<Vec<ValueT>>,
    params: &CrtGlweParameters<ValueT, M>,
) -> CrtPolynomial<Vec<ValueT>>
where
    M: FieldContext<ValueT>,
{
    let mut decomposed: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(params.rns_poly_len());
    params.base_q().wrapping_decompose_small_polynomial_to(
        message,
        &mut decomposed,
        POLY_LENGTH,
        params.plain_modulus_value(),
    );
    decomposed
}

/// Parametric correctness test: encrypt → decrypt round-trip for all embedding modes.
///
/// Tests four encryption paths:
/// 1. `encrypt_plaintext_inplace` — unsigned encoding (codec-managed)
/// 2. `encrypt_centered_plaintext_inplace` — centered encoding (codec-managed)
/// 3. `encrypt_inplace` with manual `decompose_message` — low-level API
/// 4. `encrypt_zeros_inplace` — zero plaintext
fn assert_dcrt_glwe_secret_key_enc_dec(secret_key_type: RingSecretKeyType, plain_modulus: ValueT) {
    let mod_t = BarrettModulus::new(plain_modulus);
    let mod_gamma = BarrettModulus::new(GAMMA_MODULUS);
    let moduli = CIPHER_MODULI.map(BarrettModulus::new);
    let table = UintDcrtTable::new(POLY_LENGTH.trailing_zeros(), &moduli).unwrap();
    let mut rng = rand::rng();

    let params = CrtGlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        mod_t,
        mod_gamma,
        &moduli,
        secret_key_type,
        NOISE_STANDARD_DEVIATION,
    );

    let secret_key = GlweSecretKey::generate(&params, &mut rng);
    let secret_key = DcrtGlweSecretKey::from_coeff_secret_key(&secret_key, &table);
    let mut decrypt_context = DcrtGlweDecryptContext::new(params.size());

    let message = message_polynomial(plain_modulus);

    // ── 1. Unsigned encoding (codec) ────────────────────────────
    let mut ciphertext: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(params.rns_glwe_len());

    secret_key.encrypt_plaintext_inplace(&message, &mut ciphertext, &params, &table, &mut rng);

    let decrypted = secret_key.decrypt(&ciphertext, &params, &table, &mut decrypt_context);
    assert_eq!(decrypted.as_ref(), message.as_ref());

    // ── 2. Centered encoding (codec) ────────────────────────────
    let mut ciphertext: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(params.rns_glwe_len());
    secret_key.encrypt_centered_plaintext_inplace(
        &message,
        &mut ciphertext,
        &params,
        &table,
        &mut rng,
    );

    let decrypted = secret_key.decrypt(&ciphertext, &params, &table, &mut decrypt_context);
    assert_eq!(decrypted.as_ref(), message.as_ref());

    // ── 3. Low-level: manual decompose + encrypt_inplace ─────────
    // Tests the CrtPolynomial-based API directly.
    let decomposed_message = decompose_message(&message, &params);
    let mut ciphertext: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(params.rns_glwe_len());
    secret_key.encrypt_inplace(
        &decomposed_message,
        &mut ciphertext,
        &params,
        &table,
        &mut rng,
    );

    let decrypted = secret_key.decrypt(&ciphertext, &params, &table, &mut decrypt_context);
    assert_eq!(decrypted.as_ref(), message.as_ref());

    // ── 4. Zero encryption ──────────────────────────────────────
    let mut ciphertext: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(params.rns_glwe_len());
    secret_key.encrypt_zeros_inplace(&mut ciphertext, &params, &table, &mut rng);

    let decrypted = secret_key.decrypt(&ciphertext, &params, &table, &mut decrypt_context);
    assert_eq!(decrypted.as_ref(), vec![0; POLY_LENGTH]);
}

#[test]
fn test_dcrt_glwe_secret_key_enc_dec_crt_modulus() {
    for secret_key_type in SECRET_KEY_TYPES {
        for plain_modulus in PLAIN_MODULI {
            assert_dcrt_glwe_secret_key_enc_dec(secret_key_type, plain_modulus);
        }
    }
}

/// Test homomorphic ciphertext operations: add, sub, mul-by-constant, negate.
///
/// Encrypts three plaintexts m₀, m₁, m₂, then verifies:
///   - c₀ + c₁  decrypts to  m₀ + m₁
///   - c₁ − c₀  decrypts to  m₁ − m₀
///   - c₁ ⊡ msg₂  decrypts to  m₁ · m₂  (external product with CRT polynomial)
///   - −c₁  decrypts to  −m₁
#[test]
fn test_dcrt_glwe_secret_key_ciphertext_ops_crt_modulus() {
    let plain_modulus = 12_289;
    let mod_t = BarrettModulus::new(plain_modulus);
    let mod_gamma = BarrettModulus::new(GAMMA_MODULUS);
    let moduli = CIPHER_MODULI.map(BarrettModulus::new);
    let table = UintDcrtTable::new(POLY_LENGTH.trailing_zeros(), &moduli).unwrap();
    let mut rng = rand::rng();

    let params = CrtGlweParameters::new(
        DIMENSION,
        POLY_LENGTH,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        NOISE_STANDARD_DEVIATION,
    );

    let rns_poly_len = params.rns_poly_len();
    let rns_glwe_len = params.rns_glwe_len();
    let secret_key = GlweSecretKey::generate(&params, &mut rng);
    let secret_key = DcrtGlweSecretKey::from_coeff_secret_key(&secret_key, &table);
    let mut decrypt_context = DcrtGlweDecryptContext::new(params.size());

    // ── Three test plaintexts ────────────────────────────────────
    // m₂: alternating 0/1 (binary for CRT multiplication)
    let m0 = message_polynomial(plain_modulus);
    let mut m1 = message_polynomial(plain_modulus);
    let m2 = Polynomial::random_binary(POLY_LENGTH, &mut rng);

    // msg₂ is kept in coefficient form for the multiplication step;
    // it will be converted to NTT domain later.
    let msg2 = decompose_message(&m2, &params);

    let mut c0: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    // ── Encrypt m₀, m₁ using unsigned encoding ──────────────────
    secret_key.encrypt_plaintext_inplace(&m0, &mut c0, &params, &table, &mut rng);
    let mut decrypted = secret_key.decrypt(&c0, &params, &table, &mut decrypt_context);
    assert_eq!(decrypted.as_ref(), m0.as_ref());

    secret_key.encrypt_plaintext_inplace(&m1, &mut c1, &params, &table, &mut rng);

    // ── Add: c₁ += c₀  →  m₁ + m₀ ──────────────────────────────
    c1.add_element_wise_assign(&c0, POLY_LENGTH, rns_poly_len, &moduli);
    m1.add_assign(&m0, mod_t);

    secret_key.decrypt_inplace(&c1, &mut decrypted, &params, &table, &mut decrypt_context);
    assert_eq!(m1, decrypted);

    // ── Sub: c₁ −= c₀  →  back to m₁ ───────────────────────────
    c1.sub_element_wise_assign(&c0, POLY_LENGTH, rns_poly_len, &moduli);
    m1.sub_assign(&m0, mod_t);

    secret_key.decrypt_inplace(&c1, &mut decrypted, &params, &table, &mut decrypt_context);
    assert_eq!(m1, decrypted);

    // ── Mul-by-constant: c₁ ⊡ NTT(msg₂)  →  m₁ · m₂ ────────────
    let msg2 = table.transform_inplace(msg2);
    let mut expected_product: Polynomial<Vec<ValueT>> = Polynomial::zero(POLY_LENGTH);

    c1.mul_dcrt_polynomial_to(&msg2, &mut c2, POLY_LENGTH, &moduli);
    m1.naive_mul_to(&m2, &mut expected_product, mod_t);

    secret_key.decrypt_inplace(&c2, &mut decrypted, &params, &table, &mut decrypt_context);
    assert_eq!(expected_product, decrypted);

    // ── Negate: −c₁  →  −m₁ ────────────────────────────────────
    c1.neg_assign(rns_poly_len, POLY_LENGTH, &moduli);
    m1.neg_assign(mod_t);

    secret_key.decrypt_inplace(&c1, &mut decrypted, &params, &table, &mut decrypt_context);
    assert_eq!(m1, decrypted);
}
