use primus_integer::FheUint;
use primus_lattice::ntru::NttNtru;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomialIter, PolynomialIterMut, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use super::Evaluator;
use crate::{ServerKey, TfheContext, TfheEvaluationError};

/// A factorized MVB program prepared for one borrowed NTT context.
///
/// The common polynomial stays in coefficient form; the contiguous factor buffer
/// is transformed once in place, one polynomial at a time. No coefficient-domain
/// duplicate is retained. Context identity protects the NTT root/order
/// convention, which cannot be inferred from the modulus and length alone.
pub struct NttFactorizedLookupTable<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<T>,
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
                parameters.accumulator_ntru().poly_length(),
                parameters.plain_modulus_value(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "MVB lookup-table encoding or polynomial length mismatch"
        );
        let input_domain_len = lookup_table.input_domain_len();
        let output_plaintext_modulus = lookup_table.output_plaintext_modulus();
        let (common_polynomial, mut factors) = lookup_table.into_polynomials();
        for mut factor in PolynomialIterMut::new(&mut factors, common_polynomial.poly_length()) {
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
        self.factors.len() / self.common_polynomial.poly_length()
    }

    /// Returns the plaintext modulus of the unsigned Scaled output encoding.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for fixed-scale factorized MVB.
///
/// Initializes V with `NLev[1]`, shares one blind rotation at step one, then
/// multiplies each public factor before switching from the accumulator secret
/// to the client secret and extracting compact LWE. Only one extra NTT polynomial
/// is allocated beyond the ordinary evaluator's workspace, regardless of the
/// output count. Outputs use the same external secret and dimension as [`Evaluator`].
pub struct FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    evaluator: Evaluator<'a, T, Table>,
    shared_rotation: NttNtru<Vec<T>>,
}

impl<'a, T, Table> FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates the workspace after validating the server key's parameters.
    /// Rejects sparse keys; sparse MVB requires a separate noise validation.
    ///
    /// # Correctness
    ///
    /// The server key must use this context's NTT representation and the paired
    /// client secrets. Layout checks do not establish transform or secret identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        Ok(Self {
            evaluator: Evaluator::try_new(context, server_key)?,
            shared_rotation: NttNtru::zero(context.parameters().poly_length()),
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
        let dimension = self.evaluator.context.parameters().external_lwe_dimension();
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
    /// in `0..lookup_table.input_domain_len()`. Input noise and coefficient-wise
    /// quantization error must stay within that message's LUT interval. Each
    /// difference factor amplifies the shared initialization and BR noise;
    /// a separate NTRU key-switch error follows each product. These conditions are not
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
        let dimension = parameters.external_lwe_dimension();
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

        let modulus = parameters.accumulator_ntru().cipher_modulus();
        let table = evaluator.context.table();
        evaluator.blind_rotate(input, &lookup_table.common_polynomial, 1);
        evaluator
            .blind_rotation
            .current
            .write_ntt_form(&mut self.shared_rotation, table);
        let factors = NttPolynomialIter::new(&lookup_table.factors, parameters.poly_length());
        for (factor, output) in factors.zip(outputs) {
            // Reuse current for the NTT product, then restore coefficient form
            // before key switching. The shared BR result remains intact.
            let mut product = NttNtru::new(evaluator.blind_rotation.current.as_mut());
            self.shared_rotation
                .mul_ntt_polynomial_to(&factor, &mut product, modulus);
            product.into_coeff_form(table);
            evaluator.key_switch_accumulator();
            evaluator
                .blind_rotation
                .scratch
                .extract_compact_lwe_to(output, modulus);
        }
    }
}
