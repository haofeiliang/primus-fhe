use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::ntru::FourierNtru;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomialIter, PolynomialIter, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use super::Evaluator;
use crate::{ServerKey, TfheContext, TfheEvaluationError};

/// Native even-scale MVB program prepared for one borrowed Fourier context.
///
/// V stays in coefficient form. Factors are stored contiguously as Fourier
/// transforms of signed integers, without torus scaling. Their coefficient
/// storage is discarded after preparation. Context identity protects the FFT
/// layout and ordering, which polynomial length alone cannot establish.
pub struct FourierFactorizedLookupTable<'a, T: TorusFftValue, Table: FftTable> {
    context: &'a TfheContext<T, Table>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<Complex64>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T: TorusFftValue, Table: FftTable> FourierFactorizedLookupTable<'a, T, Table> {
    /// Consumes a compatible Native coefficient program and transforms its factors.
    ///
    /// Uses the signed lifts of the factor residues. Floating-point conversion,
    /// FFT and later multiplication introduce error; this constructor does not
    /// establish a noise budget, even when the integer lifts fit exactly in f64.
    ///
    /// # Panics
    ///
    /// Panics before transforming unless T is u32/u64 and the program's ring
    /// length, input encoding and coefficient modulus match this context.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table>, lookup_table: FactorizedLookupTable<T>) -> Self {
        assert!(
            matches!(T::BITS, 32 | 64),
            "Fourier MVB requires u32 or u64 coefficients"
        );
        let parameters = context.parameters();
        let n = parameters.accumulator_ntru().poly_length();
        assert!(
            lookup_table.is_compatible(
                n,
                parameters.plain_modulus_value(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "MVB lookup-table encoding or polynomial length mismatch"
        );
        let input_domain_len = lookup_table.input_domain_len();
        let output_plaintext_modulus = lookup_table.output_plaintext_modulus();
        let (common_polynomial, coefficients) = lookup_table.into_polynomials();
        let mut factors = vec![Complex64::default(); coefficients.len() / 2];
        let mut fft = context.new_fft_engine();
        for (input, output) in
            PolynomialIter::new(&coefficients, n).zip(factors.chunks_exact_mut(n / 2))
        {
            fft.forward_as_integer(input.as_ref(), output);
        }
        Self {
            context,
            common_polynomial,
            factors,
            input_domain_len,
            output_plaintext_modulus,
        }
    }

    /// Returns the programmed input prefix length.
    #[must_use]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the exact output count, without interleaved padding.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.factors.len() / self.context.table().fourier_length()
    }

    /// Returns the plaintext modulus of the shared unsigned Scaled output codec.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for Native even-scale NTRU MVB.
///
/// Initializes V with `NLev[1]`, shares one blind rotation at step one, then
/// multiplies each factor before switching to the client secret and extracting
/// compact LWE. Extra workspace consists of two Fourier NTRU polynomials
/// (N complex values), independent of output count. Coefficient products and
/// key switching reuse the ordinary evaluator's buffers and key material.
pub struct FactorizedEvaluator<'a, T: TorusFftValue, Table: FftTable> {
    evaluator: Evaluator<'a, T, Table>,
    shared_rotation: FourierNtru<Vec<Complex64>>,
    product: FourierNtru<Vec<Complex64>>,
}

impl<'a, T: TorusFftValue, Table: FftTable> FactorizedEvaluator<'a, T, Table> {
    /// Creates workspace after checking the server key.
    /// Rejects sparse keys; sparse MVB needs a separate numerical/noise validation.
    ///
    /// # Correctness
    /// Inherits [`Evaluator::try_new`]'s Fourier table requirements.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_from_bootstrapper(Evaluator::try_new(context, server_key)?)
    }

    /// Consumes ordinary PBS workspace and allocates only the additional MVB buffers.
    /// The underlying key, context and existing allocations are preserved.
    pub fn try_from_bootstrapper(
        evaluator: Evaluator<'a, T, Table>,
    ) -> Result<Self, TfheEvaluationError> {
        if evaluator.server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        let context = evaluator.context;
        Ok(Self {
            evaluator,
            shared_rotation: FourierNtru::zero(context.parameters().poly_length() / 2),
            product: FourierNtru::zero(context.parameters().poly_length() / 2),
        })
    }

    /// Borrows ordinary single-output and interleaved PBS operations without allocation.
    /// The opaque borrow prevents replacing the bound evaluator and invalidating MVB scratch.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> impl primus_tfhe::ProgrammableBootstrap<T>
    + primus_tfhe::ProgrammableBootstrapInterleaved<T>
    + use<'_, 'a, T, Table> {
        &mut self.evaluator
    }

    /// Releases the extra MVB buffers and recovers the original PBS workspace without allocation.
    #[must_use]
    pub fn into_bootstrapper(self) -> Evaluator<'a, T, Table> {
        self.evaluator
    }

    /// Evaluates the program, allocating one LWE ciphertext per output.
    /// Inherits [`Self::apply_lookup_table_to`]'s correctness and panic contracts.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
    ) -> Vec<LweCiphertext<T>> {
        let dimension = self.evaluator.context.parameters().external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension); lookup_table.output_count()];
        self.apply_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input must use the server key's external client secret and unsigned Rounded
    /// encoding, with a message in `0..lookup_table.input_domain_len()`. Input
    /// noise and coefficient-wise quantization must keep the rotation in that
    /// message's LUT interval. Each integer factor W amplifies both NLev
    /// initialization and BR noise. Public FFT multiplication adds phase error
    /// `f_acc * delta_c`; each product then incurs client NTRU key-switch error.
    /// Budget these together: the Scaled recovery condition for result y is
    /// `abs((t*delta-q)*y + t*e) < q/2`, q=2^BITS. No noise bound is checked.
    /// Decode output phases with the unsigned Scaled codec used to compile the
    /// program, which may differ from the parameter input codec.
    ///
    /// # Panics
    ///
    /// Panics before output writes unless the program was prepared by this exact
    /// context, input and every output have the external LWE dimension, and the
    /// output slice length equals the program's output count.
    pub fn apply_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let evaluator = &mut self.evaluator;
        assert!(
            core::ptr::eq(evaluator.context, lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = evaluator.context.parameters();
        let dimension = parameters.external_lwe_dimension();
        assert_eq!(input.dimension(), dimension, "MVB input dimension mismatch");
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "MVB output count mismatch"
        );
        assert!(
            outputs.iter().all(|out| out.dimension() == dimension),
            "MVB output ciphertext dimension mismatch"
        );

        let n = parameters.poly_length();
        evaluator.blind_rotate(input, &lookup_table.common_polynomial, 1);
        evaluator
            .blind_rotation
            .current
            .write_fourier_form(&mut self.shared_rotation, &mut evaluator.fft);
        for (factor, output) in
            FourierPolynomialIter::new(&lookup_table.factors, n / 2).zip(outputs)
        {
            // Preserve the shared rotation; restore each product to coefficient
            // form in current before the ordinary NTRU key switch consumes it.
            self.shared_rotation
                .mul_fourier_polynomial_to(&factor, &mut self.product);
            self.product
                .write_torus_form(&mut evaluator.blind_rotation.current, &mut evaluator.fft);
            evaluator.key_switch_accumulator();
            evaluator
                .blind_rotation
                .scratch
                .extract_compact_lwe_to(output, NativeModulus::new());
        }
    }
}
