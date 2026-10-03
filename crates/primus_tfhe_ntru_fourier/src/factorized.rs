//! Prepared factorized MVB programs and their reusable evaluator.

use primus_encoding::ScaledCodec;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::ntru::FourierNtru;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, FourierPolynomialIter, PolynomialIter, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use crate::{Evaluator, LookupTableError, Lwe, ServerKey, TfheContext, TfheEvaluationError};

/// Native even-scale MVB program prepared for one borrowed Fourier context.
///
/// V stays in coefficient form. Factors are stored contiguously as Fourier
/// transforms of signed integers, without torus scaling. Their coefficient
/// storage is discarded after preparation. Context identity protects the FFT
/// layout and ordering, which polynomial length alone cannot establish.
pub struct FourierFactorizedLookupTable<
    'a,
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T> = NativeModulus<T>,
> {
    context: &'a TfheContext<T, Table, LM>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<Complex64>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T: TorusFftValue, Table: FftTable, LM: primus_reduce::RingContext<T>>
    FourierFactorizedLookupTable<'a, T, Table, LM>
{
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
    pub fn new(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        assert!(
            matches!(T::BITS, 32 | 64),
            "Fourier MVB requires u32 or u64 coefficients"
        );
        let parameters = context.parameters();
        let n = parameters.accumulator_ntru().poly_length().get();
        assert!(
            lookup_table.is_compatible(
                parameters.accumulator_ntru().poly_length(),
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
/// multiplies each factor. Each product is independently converted Q→q and
/// extracted, then small LWE tiles share key switching to the external secret.
/// Extra workspace consists of two Fourier NTRU polynomials
/// (N complex values), independent of output count. Coefficient products and
/// key switching reuse the ordinary evaluator's buffers and key material.
pub struct FactorizedEvaluator<
    'a,
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T> = NativeModulus<T>,
> {
    evaluator: Evaluator<'a, T, Table, LM>,
    shared_rotation: FourierNtru<Vec<Complex64>>,
    product: FourierNtru<Vec<Complex64>>,
}

impl<'a, T: TorusFftValue, Table: FftTable, LM: primus_reduce::RingContext<T>>
    FactorizedEvaluator<'a, T, Table, LM>
{
    /// Creates workspace after checking the server key.
    /// Rejects sparse keys; sparse MVB needs a separate numerical/noise validation.
    ///
    /// # Correctness
    /// Inherits [`Evaluator::try_new`]'s Fourier table requirements.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_from_bootstrapper(Evaluator::try_new(context, server_key)?)
    }

    /// Consumes ordinary PBS workspace and allocates only the additional MVB buffers.
    /// The underlying key, context and existing allocations are preserved.
    pub fn try_from_bootstrapper(
        evaluator: Evaluator<'a, T, Table, LM>,
    ) -> Result<Self, TfheEvaluationError> {
        evaluator
            .engine
            .workspace
            .rotation
            .classic_controls()
            .ok_or(TfheEvaluationError::UnsupportedSparseBootstrapping)?;
        let context = evaluator.engine.context;
        Ok(Self {
            evaluator,
            shared_rotation: FourierNtru::zero(
                context.parameters().poly_length().fourier_poly_len(),
            ),
            product: FourierNtru::zero(context.parameters().poly_length().fourier_poly_len()),
        })
    }

    /// Borrows ordinary single-output and interleaved PBS operations without allocation.
    /// The opaque borrow prevents replacing the bound evaluator and invalidating MVB scratch.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> impl primus_tfhe::ProgrammableBootstrap<T>
    + primus_tfhe::ProgrammableBootstrapInterleaved<T>
    + use<'_, 'a, T, Table, LM> {
        &mut self.evaluator
    }

    /// Releases the extra MVB buffers and recovers the original PBS workspace without allocation.
    /// Discards any unfinished return tile left by an interrupted evaluation.
    #[must_use]
    pub fn into_bootstrapper(mut self) -> Evaluator<'a, T, Table, LM> {
        self.evaluator.lwe_return.discard_batch();
        self.evaluator
    }

    /// Evaluates the program, allocating one LWE ciphertext per output.
    /// Inherits [`Self::apply_lookup_table_to`]'s correctness and panic contracts.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table, LM>,
    ) -> Vec<LweCiphertext<T>> {
        let context = self.evaluator.engine.context;
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension.get()); lookup_table.output_count()];
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
    /// `f_acc * delta_c`; each product then incurs modulus conversion and LWE key-switch errors.
    /// Before returning, the Scaled recovery condition is
    /// `abs((t*delta-Q)*y + t*e) < Q/2`, Q=2^BITS. Return conversion rescales
    /// delta by q/Q and adds rounding and key-switch errors. Decode using a
    /// Scaled codec at external q with the same plaintext modulus; also budget
    /// the difference between the rescaled delta and round(q/t). No noise bound
    /// is checked.
    ///
    /// # Panics
    ///
    /// Panics before output writes unless the program was prepared by this exact
    /// context, input and every output have the external LWE dimension, and the
    /// output slice length equals the program's output count.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table, LM>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        self.check_io(input.as_view(), lookup_table, outputs);
        self.prepare_shared_rotation(input, &lookup_table.common_polynomial);

        let n = self
            .evaluator
            .engine
            .context
            .parameters()
            .poly_length()
            .get();
        let batch_size = self.evaluator.lwe_return.batch_capacity();
        let mut factors = FourierPolynomialIter::new(&lookup_table.factors, n / 2);
        for outputs in outputs.chunks_mut(batch_size) {
            self.evaluator.lwe_return.begin_batch();
            for factor in factors.by_ref().take(outputs.len()) {
                self.prepare_factor_return(factor);
            }
            self.evaluator.lwe_return.return_batch_to(outputs);
        }
    }

    /// Validate context identity and every ciphertext before BR mutates scratch.
    /// The prepared program fixes factor count and transform layout for this context.
    fn check_io(
        &self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table, LM>,
        outputs: &[LweCiphertext<T>],
    ) {
        let evaluator = &self.evaluator;
        assert!(
            core::ptr::eq(evaluator.engine.context, lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = evaluator.engine.context.parameters();
        let dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            dimension.get(),
            "MVB input dimension mismatch"
        );
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "MVB output count mismatch"
        );
        assert!(
            outputs.iter().all(|out| out.dimension() == dimension.get()),
            "MVB output ciphertext dimension mismatch"
        );
    }

    /// Preserve the common blind rotation in transform form for all factors.
    /// Individual products can then overwrite the coefficient accumulator.
    fn prepare_shared_rotation(&mut self, input: Lwe<&[T]>, common: &PolynomialOwned<T>) {
        let engine = &mut self.evaluator.engine;
        engine.blind_rotate(input, common, 1);
        engine
            .workspace
            .current
            .write_fourier_form(&mut self.shared_rotation, &mut engine.fft);
    }

    /// Multiply one factor and extract its independently rounded q-domain sample.
    /// Only the LWE slot survives; the next factor may overwrite the product buffers.
    fn prepare_factor_return(&mut self, factor: FourierPolynomial<&[Complex64]>) {
        let evaluator = &mut self.evaluator;
        let engine = &mut evaluator.engine;
        self.shared_rotation
            .mul_fourier_polynomial_to(&factor, &mut self.product);
        self.product
            .write_torus_form(&mut engine.workspace.current, &mut engine.fft);
        evaluator
            .lwe_return
            .append_at(engine.workspace.current.as_view(), 0);
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates NTRU MVB workspace. Inherits
    /// [`FactorizedEvaluator::try_new`]'s key and Fourier table requirements.
    pub fn factorized_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<FactorizedEvaluator<'a, T, Table, LM>, TfheEvaluationError> {
        FactorizedEvaluator::try_new(self, server_key)
    }

    /// Compiles and Fourier-prepares a Native even-scale MVB program.
    ///
    /// `input_domain_len` selects a nonempty prefix of the parameter codec's
    /// front half; `output_count` is positive and unpadded. The output codec
    /// must use Native and have an even scale, including for nonbinary plaintext
    /// moduli. Callback order follows [`FactorizedLookupTable::try_new`].
    /// The result is bound to this context; factor amplification and FFT error
    /// must satisfy [`FactorizedEvaluator::apply_lookup_table_to`]'s noise budget.
    ///
    /// # Panics
    /// Panics for coefficient types other than u32/u64.
    pub fn compile_factorized_lookup_table_fn<OM, F>(
        &self,
        output_codec: &ScaledCodec<T, OM>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FourierFactorizedLookupTable<'_, T, Table, LM>, LookupTableError>
    where
        OM: primus_reduce::RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        if output_codec.ciphertext_modulus().explicit_value()
            != self.parameters().accumulator_ntru().cipher_modulus_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let lookup_table = FactorizedLookupTable::try_new(
            input_domain_len,
            self.parameters().accumulator_ntru().poly_length(),
            output_count,
            self.parameters().input_plaintext_codec(),
            output_codec,
            function,
        )?;
        Ok(FourierFactorizedLookupTable::new(self, lookup_table))
    }
}
