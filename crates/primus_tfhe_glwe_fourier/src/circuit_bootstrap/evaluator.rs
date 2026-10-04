use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::GlweCiphertext;
use primus_glwe::{FourierGlweTraceWorkspace, GlevCiphertext};
use primus_lattice::ggsw::FourierGgsw;
use primus_modulus::NativeModulus;
use primus_tfhe::InterleavedLookupTable;

use super::key::CircuitBootstrapBinding;

use crate::{
    BootstrapResources, CircuitBootstrapKey, CircuitBootstrapParameters, Lwe, TfheContext,
    TfheEvaluationError,
};

/// Classic binary/ternary or sparse binary CBS producing Fourier GGSW controls.
///
/// Owns the programmed LUT and projection buffers. Common input/BR/FFT/EP
/// resources are borrowed per call; both BR variants share trace and scheme switching.
/// After construction, [`Self::circuit_bootstrap_to`] performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: InterleavedLookupTable<T>,
    trace: FourierGlweTraceWorkspace<T>,
    projected: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Prepares CBS using the circuit key's output parameters.
    /// Common resources may come from a PBS evaluator or be prepared independently;
    /// they are borrowed only for construction and each online operation.
    /// Both classic and sparse BR and both PBS orders are supported.
    ///
    /// Use [`Self::try_with_parameters`] to select a different compatible output basis.
    ///
    /// # Correctness
    /// Inherits [`Self::try_with_parameters`]'s secret, representation and noise requirements.
    pub fn try_new(
        resources: &BootstrapResources<'a, T, Table>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_with_parameters(
            resources,
            circuit_key.parameters(),
            circuit_key,
            input_codec,
        )
    }

    /// Checks CBS material, compiles the gadget identity LUT and allocates projection buffers.
    /// `parameters` may select another output basis with the same layout; trace and
    /// scheme-switch parameters must still match the circuit key. Prefer [`Self::try_new`]
    /// when using the key's original output basis.
    /// Common resources are borrowed only for construction and each online operation.
    /// Both classic and sparse BR and both PBS orders are supported.
    ///
    /// # Correctness
    /// CBS and resource keys must use the same paired secrets and this context's
    /// FFT table instance. Compatibility checks do not establish these identities
    /// or a noise margin; see [`primus_glwe::FourierGlweSchemeSwitchKey::apply_to`].
    pub fn try_with_parameters(
        resources: &BootstrapResources<'a, T, Table>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = resources.context;
        let tfhe = context.parameters();
        let circuit = CircuitBootstrapBinding::try_new(tfhe, parameters, circuit_key)?;

        let glwe = tfhe.blind_rotation_ggsw();
        let lookup_table = parameters.compile_lookup_table(input_codec)?;

        let glwe_size = glwe.glwe_size();

        Ok(Self {
            context,
            circuit,
            lookup_table,
            trace: FourierGlweTraceWorkspace::new(glwe_size),
            projected: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
    }

    /// Allocates a zeroed Fourier GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> FourierGgsw<Vec<Complex64>> {
        FourierGgsw::zero(self.circuit.parameters.output_size().fourier_ggsw_len())
    }

    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// Fourier controls must use the bound FFT table instance.
    /// See [`FourierGgsw::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
        control: &FourierGgsw<A>,
        lhs: &GlweCiphertext<B>,
        rhs: &GlweCiphertext<C>,
        output: &mut GlweCiphertext<D>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch, fft| {
            control.cmux_to(lhs, rhs, output, parameters.output_basis(), fft, scratch);
        });
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`FourierGgsw::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn external_product_to<A, B, C>(
        &mut self,
        control: &FourierGgsw<A>,
        input: &GlweCiphertext<B>,
        output: &mut GlweCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len
            ),
            "external-product ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch, fft| {
            control.external_product_to(input, output, parameters.output_basis(), fft, scratch);
        });
    }

    /// Allocates a Fourier GGSW output. Inherits [`Self::circuit_bootstrap_to`]'s
    /// encoding, secret, FFT representation, noise and borrowing contracts.
    #[must_use]
    pub fn circuit_bootstrap(
        &mut self,
        input: Lwe<&[T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) -> FourierGgsw<Vec<Complex64>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output, resources);
        output
    }

    /// Writes a Fourier GGSW encrypting the input message under the accumulator
    /// GLWE secret, with the configured output gadget scalars.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::try_new`]'s paired-secret and FFT table requirements.
    /// Input must use the external client secret paired with the bound BR/KS material and
    /// unsigned rounded encoding with a plaintext in `0..ceil(t/2)`, where `t`
    /// is the selected input codec's plaintext modulus. Noise must fit the coarser interleaved-LUT
    /// rotation intervals. Trace and scheme-switch errors, including native
    /// halving and FFT rounding, must fit the independent CBS error budget;
    /// see [`CircuitBootstrapParameters`]. Sparse keys also require aggregation
    /// noise from every bucket, including zero selections and dummies, and the
    /// aggregate FFT error to fit that budget. CMUX consumption requires message
    /// 0 or 1. The output uses gadget scales rather than ordinary LWE encoding.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input dimension or output Fourier
    /// GGSW length is wrong, or resources belong to a different context.
    /// LUT parameters are fixed during construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = Complex64>>(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut FourierGgsw<S>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let circuit_key = self.circuit.key;
        assert_eq!(
            input.dimension(),
            resources
                .context
                .parameters()
                .external_lwe_dimension()
                .get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_size().fourier_ggsw_len(),
            "circuit-bootstrap output Fourier GGSW layout mismatch"
        );

        let (accumulator, fft) = resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );
        // ManyLUT messages can have nonzero tails, so prefix expansion cannot
        // replace full coefficient projection here.
        circuit_key.trace_key().project_prefix_coefficients_to(
            accumulator,
            parameters.output_basis().decompose_length().get(),
            self.projected.as_mut(),
            fft,
            &mut self.trace,
        );
        // CMUX can bind the same buffers to a different output decomposition.
        resources.with_external_product(parameters.scheme_switch().size(), |scratch, fft| {
            circuit_key
                .scheme_switch_key()
                .apply_to(&self.projected, output, fft, scratch);
        });
    }
}
