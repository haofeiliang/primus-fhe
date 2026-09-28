//! Acceptance budgets shared by the explicit backend checks.
//! Decoded outputs use q/(4*t); raw gadget phases use gadget_scalar/8.
//! The one-hot guard instead checks membership in the exact rotation cell.

use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Checks every observation against a fixed budget and reports its worst fraction.
/// These observed margins are not failure-probability estimates.
pub struct ErrorMargin<'a> {
    name: &'a str,
    seed: u64,
    maximum: f64,
    count: usize,
}

/// Checks the quantized phase lies in the message's left-closed one-hot cell.
/// BR rounds each coefficient separately. Checking only the original LWE phase
/// would miss accumulated mask rounding and the padded gadget stride.
/// This client-side diagnostic requires the secret key and known message;
/// it is not a validation step the server can perform on an encrypted input.
#[allow(clippy::too_many_arguments)]
pub fn one_hot_guard<T: FheUint>(
    input: &primus_tfhe::LweCiphertext<T>,
    secret: &[T],
    modulus: primus_modulus::PowOf2Modulus<T>,
    message: usize,
    poly_length: usize,
    rotation_step: usize,
    message_count: usize,
    name: &str,
    seed: u64,
) {
    let quantizer =
        primus_tfhe::rotation::RotationQuantizer::new(modulus, 2 * poly_length, rotation_step);
    let mut phase = quantizer.exponent(input.b()) as i128;
    let q: i128 = modulus.value().as_into();
    for (&a, &s) in input.a().iter().zip(secret) {
        // External ternary keys encode -1 as q-1; rotation exponents use signed s.
        let s: i128 = s.as_into();
        let s = if s > q / 2 { s - q } else { s };
        phase -= quantizer.exponent(a) as i128 * s;
    }
    // Message m is centered at m*N/M in the 2N rotation domain. The LUT cells
    // include their left edge and exclude their right edge: -N/(2M) <= e < N/(2M).
    let n = poly_length as i128;
    let message = message as i128;
    let error = (phase - message * (poly_length / message_count) as i128 + n).rem_euclid(2 * n) - n;
    let radius = (poly_length / (2 * message_count)) as i128;
    assert!(
        error >= -radius && error < radius,
        "{name},seed={seed},one-hot guard error={error},radius={radius}"
    );
}

impl<'a> ErrorMargin<'a> {
    /// Starts one report identified by its backend/workload label and fixed seed.
    pub fn new(name: &'a str, seed: u64) -> Self {
        Self {
            name,
            seed,
            maximum: 0.0,
            count: 0,
        }
    }

    /// Checks a decoded-output phase within half the decoding radius q/(2*t).
    /// `expected` is the encoded plaintext phase, not the plaintext integer.
    pub fn decoded<T: FheUint, M: RingContext<T>>(
        &mut self,
        actual: T,
        expected: T,
        modulus: M,
        plaintext_modulus: usize,
    ) {
        let q = modulus
            .explicit_value()
            .map_or(1i128 << T::BITS, |q| q.as_into());
        // Reserve half the rounded/scaled decoding radius.
        self.observe(
            actual,
            expected.as_into(),
            q,
            q / (4 * plaintext_modulus) as i128,
        );
    }

    /// Checks raw gadget error below scalar/8, including every polynomial coefficient.
    /// The signed expected phase may contain a secret coefficient and is reduced mod q.
    pub fn gadget<T: FheUint, M: RingContext<T>>(
        &mut self,
        actual: T,
        expected: i128,
        modulus: M,
        scalar: i128,
    ) {
        let q = modulus
            .explicit_value()
            .map_or(1i128 << T::BITS, |q| q.as_into());
        self.observe(actual, expected, q, scalar / 8);
    }

    /// Uses circular distance so errors near zero and q have the same magnitude.
    /// i128 holds the signed intermediate for every u32/u64 profile, including native q.
    fn observe<T: FheUint>(&mut self, actual: T, expected: i128, q: i128, limit: i128) {
        let actual: i128 = actual.as_into();
        let distance = (actual - expected).rem_euclid(q);
        let error = distance.min(q - distance);
        assert!(
            error < limit,
            "{}, seed={}, error={error}, limit={limit}",
            self.name,
            self.seed
        );
        self.maximum = self.maximum.max(error as f64 / limit as f64);
        self.count += 1;
    }

    /// Prints the worst budget fraction and rejects accidentally empty checks.
    pub fn report(&self) {
        assert!(self.count > 0);
        println!(
            "{},seed={},samples={},max_budget_fraction={:.6e}",
            self.name, self.seed, self.count, self.maximum
        );
    }
}
