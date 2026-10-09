//! Prepared factorized MVB programs and their reusable evaluator.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::glwe::FourierGlwe;
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, FourierPolynomialIter, PolynomialIter, PolynomialOwned};
use primus_reduce::Modulus;
use primus_tfhe::{FactorizedLookupTable, FactorizedPbsCodecs};

use crate::{Evaluator, LookupTableError, Lwe, TfheContext};

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
    /// length, input modulus and coefficient modulus match this context.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table>, lookup_table: FactorizedLookupTable<T>) -> Self {
        assert!(
            matches!(T::BITS, 32 | 64),
            "Fourier MVB requires u32 or u64 coefficients"
        );
        let parameters = context.parameters();
        let n = parameters.blind_rotation_params().poly_length().get();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.blind_rotation_params().poly_length(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.cipher_modulus().explicit_value(),
            ),
            "MVB lookup-table modulus or polynomial length mismatch"
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

/// Reusable workspace for Native even-scale MVB with classic binary/ternary or sparse binary BR.
///
/// Both PBS orders retain their usual external secrets and dimensions. BK does
/// KS after each product; KB switches the input once before the shared BR.
/// In addition to the ordinary evaluator, this allocates one Fourier GLWE and
/// one Fourier polynomial: `(d+2)*N/2` complex values, independent of output count.
/// The product is inverse-transformed one component at a time into the existing
/// coefficient GLWE. The caller retains PBS ownership and lends it only during
/// each request, including its single FFT engine and return stage.
pub struct FactorizedEvaluator<'a, T: TorusFftValue, Table: FftTable> {
    context: &'a TfheContext<T, Table>,
    shared_rotation: FourierGlwe<Vec<Complex64>>,
    product: FourierPolynomial<Vec<Complex64>>,
}

impl<'a, T: TorusFftValue, Table: FftTable> FactorizedEvaluator<'a, T, Table> {
    /// Allocates the shared Fourier GLWE and one component-sized product.
    /// Common input/BR/FFT and return resources stay in PBS and are borrowed per
    /// request. Supports classic/sparse keys and both orders; inherits
    /// [`Evaluator::try_new`]'s material requirements.
    #[must_use]
    pub fn new(evaluator: &Evaluator<'a, T, Table>) -> Self {
        let context = evaluator.resources.context;
        Self {
            context,
            shared_rotation: FourierGlwe::zero(
                context.parameters().blind_rotation_params().glwe_len() / 2,
            ),
            product: FourierPolynomial::zero(
                context
                    .parameters()
                    .blind_rotation_params()
                    .poly_length()
                    .fourier_poly_len(),
            ),
        }
    }

    /// Evaluates the program, allocating one LWE ciphertext per output.
    /// Inherits [`Self::apply_lookup_table_to`]'s correctness and panic contracts.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
        evaluator: &mut Evaluator<'a, T, Table>,
    ) -> Vec<LweCiphertext<T>> {
        let context = self.context;
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension.get()); lookup_table.output_count()];
        self.apply_lookup_table_to(input, lookup_table, &mut outputs, evaluator);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input must use this context's external secret and unsigned Rounded
    /// encoding, with a message in `0..lookup_table.input_domain_len()`. Input
    /// noise, pre-BR KS (for KB), and coefficient-wise quantization must keep
    /// the rotation in that message's LUT interval. Each integer factor W
    /// amplifies BR noise, including encrypted-zero/dummy aggregation for sparse
    /// keys. Public FFT multiplication adds phase error
    /// `delta_b - sum(delta_a[j]*s[j])`, followed by output KS error for BK.
    /// Budget these together: the Scaled recovery condition for result y is
    /// `abs((t*delta-q)*y + t*e) < q/2`, q=2^BITS. No noise bound is checked.
    /// Decode output phases with the unsigned Scaled codec used to compile the
    /// program, which may differ from the parameter input codec.
    ///
    /// # Panics
    ///
    /// Panics before output writes unless the program was prepared by this exact
    /// context, input and every output have the external LWE dimension, and the
    /// output slice length equals the program's output count. The borrowed
    /// evaluator must use the context selected at construction.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
        evaluator: &mut Evaluator<'a, T, Table>,
    ) {
        evaluator.resources.check_context(self.context);
        assert!(
            core::ptr::eq(evaluator.resources.context, lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = evaluator.resources.context.parameters();
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

        let glwe = parameters.blind_rotation_params();
        let n = glwe.poly_length().get();
        let resources = &mut evaluator.resources;
        resources.blind_rotate(input, &lookup_table.common_polynomial, 1);
        resources
            .accumulator
            .write_fourier_form(&mut self.shared_rotation, &mut resources.fft);
        for (factor, output) in
            FourierPolynomialIter::new(&lookup_table.factors, n / 2).zip(outputs)
        {
            let resources = &mut evaluator.resources;
            // Keep the shared result intact; only one component-sized Fourier
            // product is needed before overwriting its coefficient destination.
            for (component, destination) in
                FourierPolynomialIter::new(self.shared_rotation.as_ref(), n / 2)
                    .zip(resources.accumulator.as_mut().chunks_exact_mut(n))
            {
                component.mul_to(&factor, &mut self.product);
                resources
                    .fft
                    .backward_as_torus(self.product.as_ref(), destination);
            }
            evaluator.return_accumulator_to(core::iter::once(output.as_mut_view()));
        }
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Compiles and Fourier-prepares a Native even-scale MVB program from prepared codecs.
    ///
    /// The prepared codecs must use this context's ciphertext modulus.
    /// `input_domain_len` selects a nonempty prefix of the input codec's
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
        codecs: &FactorizedPbsCodecs<T, OM, NativeModulus<T>>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FourierFactorizedLookupTable<'_, T, Table>, LookupTableError>
    where
        OM: primus_reduce::RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        let lookup_table = self.parameters().compile_factorized_lookup_table_fn(
            codecs,
            input_domain_len,
            output_count,
            function,
        )?;
        Ok(FourierFactorizedLookupTable::new(self, lookup_table))
    }
}
