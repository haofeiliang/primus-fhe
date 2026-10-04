//! Prepared factorized MVB programs and their reusable evaluator.

use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_lattice::ntru::NttNtru;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, PolynomialIterMut, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use crate::{Evaluator, LookupTableError, Lwe, TfheContext};

/// A factorized MVB program prepared for one borrowed NTT context.
///
/// The common polynomial stays in coefficient form; the contiguous factor buffer
/// is transformed once in place, one polynomial at a time. No coefficient-domain
/// duplicate is retained. Context identity protects the NTT root/order
/// convention, which cannot be inferred from the modulus and length alone.
pub struct NttFactorizedLookupTable<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<T>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T, Table, LM> NttFactorizedLookupTable<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Consumes a coefficient program and prepares its factors with `context`.
    ///
    /// # Panics
    ///
    /// Panics if the program's polynomial length or input/coefficient encoding
    /// does not match the context, before performing any transforms.
    #[must_use]
    pub fn new(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        let parameters = context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.accumulator_ntru().poly_length(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "MVB lookup-table encoding or polynomial length mismatch"
        );
        let input_domain_len = lookup_table.input_domain_len();
        let output_plaintext_modulus = lookup_table.output_plaintext_modulus();
        let (common_polynomial, mut factors) = lookup_table.into_polynomials();
        for mut factor in PolynomialIterMut::new(&mut factors, common_polynomial.len()) {
            context.table().transform_slice(factor.as_mut());
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
        self.factors.len() / self.common_polynomial.len()
    }

    /// Returns the plaintext modulus of the unsigned Scaled output encoding.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for fixed-scale factorized MVB.
///
/// Lifts and blind-rotates V using the selected classic or sparse PBS key at
/// rotation step one, then multiplies each public factor. Each product is
/// independently converted Q→q and extracted, then small LWE tiles share key
/// switching to the external secret.
/// Only one extra NTT polynomial is allocated beyond the ordinary evaluator's
/// workspace, regardless of output count. The ordinary evaluator remains owned
/// by the caller and is borrowed per request. Outputs use the same external secret
/// and dimension as [`Evaluator`].
pub struct FactorizedEvaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    binding: crate::bootstrap::BootstrapBinding<'a, T, Table, LM>,
    shared_rotation: NttNtru<Vec<T>>,
}

impl<'a, T, Table, LM> FactorizedEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares one extra NTT polynomial for MVB. Common BR and return resources
    /// stay in `evaluator` and are borrowed only while executing.
    /// Both classic and sparse PBS keys use the same factor/return path.
    #[must_use]
    pub fn new(evaluator: &Evaluator<'a, T, Table, LM>) -> Self {
        let context = evaluator.resources.context;
        Self {
            binding: evaluator.resources.binding(),
            shared_rotation: NttNtru::zero(context.parameters().poly_length().get()),
        }
    }

    /// Evaluates the program, allocating one LWE per output.
    ///
    /// Inherits [`Self::apply_lookup_table_to`]'s encoding, key, noise and context
    /// requirements, including its panic conditions.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table, LM>,
        evaluator: &mut Evaluator<'a, T, Table, LM>,
    ) -> Vec<LweCiphertext<T>> {
        let context = self.binding.context;
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = (0..lookup_table.output_count())
            .map(|_| LweCiphertext::zero(dimension.get()))
            .collect::<Vec<_>>();
        self.apply_lookup_table_to(input, lookup_table, &mut outputs, evaluator);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical under the context's modulus and use
    /// its external client secret and unsigned Rounded encoding, with a message
    /// in `0..lookup_table.input_domain_len()`. Input noise and coefficient-wise
    /// quantization error must stay within that message's LUT interval. Each
    /// difference factor amplifies the shared public-lift and BR noise, including
    /// sparse bucket aggregation. Modulus conversion and LWE key-switch errors
    /// follow each product. These conditions are not checked. The output scale
    /// is q/Q times the compilation scale. Decode using a Scaled
    /// codec at q with the same plaintext modulus, budgeting the difference
    /// between that rescaled scale and round(q/t_out). See
    /// [`FactorizedLookupTable`] for the factorization and noise bound.
    ///
    /// # Panics
    ///
    /// Panics before any output write unless the program was prepared by the
    /// same context instance, input and all outputs have the external LWE
    /// dimension, and the output slice has exactly the program's output count.
    /// The borrowed evaluator must use the context and BR key references selected
    /// at construction. A new valid request supersedes pending return samples
    /// from a previous interrupted MVB request.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table, LM>,
        outputs: &mut [LweCiphertext<T>],
        evaluator: &mut Evaluator<'a, T, Table, LM>,
    ) {
        self.binding.check(&evaluator.resources);
        self.check_io(input.as_view(), lookup_table, outputs);
        self.prepare_shared_rotation(input, &lookup_table.common_polynomial, evaluator);

        let n = self.binding.context.parameters().poly_length().get();
        let batch_size = evaluator.batch_return.batch_capacity();
        let mut factors = NttPolynomialIter::new(&lookup_table.factors, n);
        for outputs in outputs.chunks_mut(batch_size) {
            evaluator.batch_return.begin_batch();
            for factor in factors.by_ref().take(outputs.len()) {
                self.prepare_factor_return(factor, evaluator);
            }
            evaluator
                .lwe_return
                .return_batch_to(outputs, &mut evaluator.batch_return);
        }
    }

    /// Validate context identity and every ciphertext before BR mutates scratch.
    /// The prepared program fixes factor count and transform layout for this context.
    fn check_io(
        &self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table, LM>,
        outputs: &[LweCiphertext<T>],
    ) {
        assert!(
            core::ptr::eq(self.binding.context, lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = self.binding.context.parameters();
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
            outputs
                .iter()
                .all(|output| output.dimension() == dimension.get()),
            "MVB output ciphertext dimension mismatch"
        );
    }

    /// Preserve the common blind rotation in transform form for all factors.
    /// Individual products can then overwrite the coefficient accumulator.
    fn prepare_shared_rotation(
        &mut self,
        input: Lwe<&[T]>,
        common: &PolynomialOwned<T>,
        evaluator: &mut Evaluator<'a, T, Table, LM>,
    ) {
        let resources = &mut evaluator.resources;
        resources.blind_rotate(input, common, 1);
        resources
            .workspace
            .current
            .write_ntt_form(&mut self.shared_rotation, resources.context.table());
    }

    /// Multiply one factor and extract its independently rounded q-domain sample.
    /// Only the LWE slot survives; the next factor may overwrite the product buffers.
    fn prepare_factor_return(
        &mut self,
        factor: NttPolynomial<&[T]>,
        evaluator: &mut Evaluator<'a, T, Table, LM>,
    ) {
        let resources = &mut evaluator.resources;
        let parameters = resources.context.parameters();
        let mut product = NttNtru::new(resources.workspace.current.as_mut());
        self.shared_rotation.mul_ntt_polynomial_to(
            &factor,
            &mut product,
            parameters.accumulator_ntru().cipher_modulus(),
        );
        product.into_coeff_form(resources.context.table());
        evaluator.lwe_return.append_at(
            resources.workspace.current.as_view(),
            0,
            &mut evaluator.batch_return,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Compiles and NTT-prepares a fixed-scale MVB program for this context.
    ///
    /// `input_domain_len` selects a nonempty prefix of the parameter codec's
    /// front half; `output_count` is positive and unpadded. Outputs must lie in
    /// the supplied Scaled codec's domain, and its ciphertext modulus must match
    /// the accumulator. Callback order and noise requirements follow
    /// [`FactorizedLookupTable::try_new`]. The result borrows this context and
    /// may only be evaluated by its [`FactorizedEvaluator`]. The input codec must
    /// use external q; the output codec must use accumulator Q.
    pub fn compile_factorized_lookup_table_fn<OM, F>(
        &self,
        input_codec: &RoundedCodec<T, LM>,
        output_codec: &ScaledCodec<T, OM>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<NttFactorizedLookupTable<'_, T, Table, LM>, LookupTableError>
    where
        OM: primus_reduce::RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        if input_codec.ciphertext_modulus().explicit_value()
            != self.parameters().external_lwe().cipher_modulus_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        if output_codec.ciphertext_modulus().explicit_value()
            != self.parameters().accumulator_ntru().cipher_modulus_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let lookup_table = FactorizedLookupTable::try_new(
            input_domain_len,
            self.parameters().poly_length(),
            output_count,
            input_codec,
            output_codec,
            function,
        )?;
        Ok(NttFactorizedLookupTable::new(self, lookup_table))
    }
}
