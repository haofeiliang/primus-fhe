use primus_glwe::NttGlweCiphertext;
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomial, NttPolynomialOwned, PolynomialOwned};
use primus_tfhe::FactorizedLookupTable;

use super::Evaluator;
use crate::{PbsOrder, ServerKey, TfheContext, TfheEvaluationError};

/// A factorized MVB program prepared for one borrowed NTT context.
///
/// The common polynomial stays in coefficient form; each difference factor is
/// transformed once in its original allocation. No coefficient-domain duplicate
/// of the factors is retained. Context identity protects the NTT root/order
/// convention, which cannot be inferred from the modulus and length alone.
pub struct NttFactorizedLookupTable<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<NttPolynomialOwned<T>>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T, Table> NttFactorizedLookupTable<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Consumes a coefficient program and prepares its factors with `context`.
    ///
    /// # Panics
    ///
    /// Panics if the program's polynomial length or input/coefficient encoding
    /// does not match the context, before performing any transforms.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table>, lookup_table: FactorizedLookupTable<T>) -> Self {
        let parameters = context.parameters();
        assert!(
            lookup_table.is_compatible(
                parameters.glwe().poly_length(),
                parameters.plain_modulus_value(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.glwe().cipher_modulus_value(),
            ),
            "MVB lookup-table encoding or polynomial length mismatch"
        );
        let input_domain_len = lookup_table.input_domain_len();
        let output_plaintext_modulus = lookup_table.output_plaintext_modulus();
        let (common_polynomial, factors) = lookup_table.into_polynomials();
        let factors = factors
            .into_iter()
            .map(|mut factor| {
                context.table().transform_slice(factor.as_mut());
                NttPolynomial::new(factor.into_owned())
            })
            .collect();
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
        self.factors.len()
    }

    /// Returns the plaintext modulus of the unsigned Scaled output encoding.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for fixed-scale factorized MVB.
///
/// Shares one classic or sparse blind rotation at step one. Each output then
/// multiplies by its public difference factor. BootstrapKeyswitch performs KS
/// after each product; KeyswitchBootstrap switches the input once before BR.
/// External secrets and dimensions are the same as for [`Evaluator`].
/// Only one extra full GLWE in NTT form is allocated beyond the ordinary
/// evaluator's workspace, independently of the number of outputs.
pub struct FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    evaluator: Evaluator<'a, T, Table>,
    shared_rotation: NttGlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates the workspace after validating the server key's parameters.
    ///
    /// # Correctness
    ///
    /// The server key must use this context's NTT representation and the paired
    /// client secrets. Layout checks do not establish transform or secret identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Ok(Self {
            evaluator: Evaluator::try_new(context, server_key)?,
            shared_rotation: NttGlweCiphertext::zero(context.parameters().glwe().glwe_len()),
        })
    }

    /// Evaluates the program, allocating one LWE per output.
    ///
    /// Inherits [`Self::apply_lookup_table_to`]'s encoding, key, noise and context
    /// requirements, including its panic conditions.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
    ) -> Vec<LweCiphertext<T>> {
        let dimension = self
            .evaluator
            .context
            .parameters()
            .ciphertext_lwe_dimension();
        let mut outputs = (0..lookup_table.output_count())
            .map(|_| LweCiphertext::zero(dimension))
            .collect::<Vec<_>>();
        self.apply_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical under the context's modulus and use
    /// its external client secret and unsigned Rounded encoding, with a message
    /// in `0..lookup_table.input_domain_len()`. Input noise, any pre-BR KS noise,
    /// and coefficient-wise quantization error must stay within that message's
    /// LUT interval. Each difference factor amplifies the shared BR noise; BK
    /// adds a separate KS error after multiplication. These conditions are not
    /// checked. Decode each output phase with the unsigned Scaled codec used at
    /// compilation, not necessarily the parameter codec. See
    /// [`FactorizedLookupTable`] for the factorization and noise bound.
    ///
    /// # Panics
    ///
    /// Panics before any output write unless the program was prepared by the
    /// same context instance, input and all outputs have the external LWE
    /// dimension, and the output slice has exactly the program's output count.
    pub fn apply_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let evaluator = &mut self.evaluator;
        assert!(
            core::ptr::eq(evaluator.context, lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = evaluator.context.parameters();
        let dimension = parameters.ciphertext_lwe_dimension();
        assert_eq!(input.dimension(), dimension, "MVB input dimension mismatch");
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "MVB output count mismatch"
        );
        assert!(
            outputs.iter().all(|output| output.dimension() == dimension),
            "MVB output ciphertext dimension mismatch"
        );

        let glwe = parameters.glwe();
        let table = evaluator.context.table();
        evaluator.blind_rotate(input, &lookup_table.common_polynomial, 1);
        evaluator
            .main_glwe
            .write_ntt_form(&mut self.shared_rotation, table);
        for (factor, output) in lookup_table.factors.iter().zip(outputs) {
            // Borrow the existing main buffer in NTT form, then restore its
            // coefficient representation before KS/extraction. The shared BR
            // result remains intact for the next output.
            let mut product = NttGlweCiphertext::new(evaluator.main_glwe.as_mut());
            self.shared_rotation
                .mul_ntt_polynomial_to(factor, &mut product, glwe.cipher_modulus());
            product.into_coeff_form(table);
            match parameters.pbs_order() {
                PbsOrder::BootstrapKeyswitch => {
                    evaluator.keyswitch_accumulator();
                    evaluator.switched.extract_compact_lwe_to(
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
                PbsOrder::KeyswitchBootstrap => {
                    evaluator.main_glwe.extract_lwe_to(
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }
}
