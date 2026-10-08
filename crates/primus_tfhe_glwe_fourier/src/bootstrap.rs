use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BlindRotationKey, FourierGlweBlindRotationWorkspace, FourierGlweBootstrappingKey, Lwe,
    ServerKey, SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey, TfheContext,
};

/// Borrowed ring key-switch key with owned scratch and switched output.
/// The selected PBS order places this complete resource set before or after BR;
/// the lower-level key-switch workspace contains only reusable buffers.
pub(crate) struct KeySwitchingResources<'a, T: TorusFftValue> {
    pub(crate) key: &'a FourierGlweKeySwitchingKey<T>,
    pub(crate) scratch: FourierGlweKeySwitchingWorkspace<T>,
    pub(crate) switched: GlweCiphertext<Vec<T>>,
}

impl<'a, T: TorusFftValue> KeySwitchingResources<'a, T> {
    #[must_use]
    pub(crate) fn new(
        parameters: &crate::TfheParameters<T>,
        key: &'a FourierGlweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            key,
            scratch: FourierGlweKeySwitchingWorkspace::new(
                parameters.glwe_key_switching().output().glwe_size(),
            ),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
        }
    }
}

/// Borrowed BR key paired with the selected algorithm's owned scratch.
/// Only classic or sparse storage is allocated; no key data is copied.
enum BlindRotationResources<'a, T: TorusFftValue> {
    Classic {
        key: &'a FourierGlweBootstrappingKey<T, NativeModulus<T>>,
        scratch: FourierGlweBlindRotationWorkspace<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T, NativeModulus<T>>,
        scratch: SparseGlweBlindRotationWorkspace<T>,
    },
}

/// KS→BR requires a compact small-LWE input; BR→KS consumes the external input directly.
enum InputPreparation<'a, T: TorusFftValue> {
    Direct,
    Keyswitch {
        key_switching: KeySwitchingResources<'a, T>,
        small_lwe: LweCiphertext<T>,
    },
}

/// Common input preparation, blind-rotation, FFT and external-product resources.
///
/// KS→BR includes input KS and a compact small LWE. BR→KS consumes input directly
/// and includes no output KS. Ordinary [`crate::Evaluator`] owns these resources;
/// standalone CBS can prepare and borrow them without the ordinary return stage.
/// Context and keys are borrowed; accumulator and scratch buffers are owned here.
/// Serial operations can lend one instance to each other. Concurrent requests
/// need independent mutable resources and may share the immutable context/keys.
pub struct BootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) fft: FftEngine<'a, Table>,
    blind_rotation: BlindRotationResources<'a, T>,
    input: InputPreparation<'a, T>,
    // Coefficient GLWE under the accumulator secret after either BR order.
    pub(crate) accumulator: GlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> BootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Checks BR and supplied input KS material before allocating reusable storage.
    /// `input_key_switching_key` is required for KS→BR. BR→KS accepts `None`;
    /// a supplied key is checked but not retained, and no output KS is allocated.
    ///
    /// # Correctness
    /// Keys must use the same paired secrets and this context's FFT table instance.
    /// Layout, basis and modulus checks do not establish these identities.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        input_key_switching_key: Option<&'a FourierGlweKeySwitchingKey<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !blind_rotation_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }

        // Validate supplied material even when BR→KS does not use it for input preparation.
        // KS→BR must reject missing material before allocating any scratch.
        if let Some(key) = input_key_switching_key {
            crate::key::check_glwe_key_switching_key(parameters, key)?;
        } else if parameters.pbs_order() == PbsOrder::KeyswitchBootstrap {
            return Err(TfheEvaluationError::MissingGlweKeySwitchingKey);
        }

        Ok(Self {
            context,
            fft: context.new_fft_engine(),
            blind_rotation: match blind_rotation_key {
                BlindRotationKey::Classic(key) => BlindRotationResources::Classic {
                    key,
                    scratch: FourierGlweBlindRotationWorkspace::new(key),
                },
                BlindRotationKey::Sparse(key) => BlindRotationResources::Sparse {
                    key,
                    scratch: SparseGlweBlindRotationWorkspace::new(key),
                },
            },
            input: match parameters.pbs_order() {
                PbsOrder::BootstrapKeyswitch => InputPreparation::Direct,
                PbsOrder::KeyswitchBootstrap => InputPreparation::Keyswitch {
                    key_switching: KeySwitchingResources::new(
                        parameters,
                        input_key_switching_key.expect("KS→BR material was checked above"),
                    ),
                    small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension().get()),
                },
            },
            accumulator: GlweCiphertext::zero(parameters.blind_rotation_ggsw().glwe_len()),
        })
    }

    /// Borrows the context that fixes the order, geometry and transform representation.
    #[must_use]
    pub fn context(&self) -> &'a TfheContext<T, Table> {
        self.context
    }

    /// Operations retain geometry/transform state, not BR controls. Any resource
    /// instance from the same context is allowed; actual paired secrets remain
    /// the caller's responsibility, including when replacing compatible KS material.
    pub(crate) fn check_context(&self, context: &TfheContext<T, Table>) {
        assert!(
            core::ptr::eq(self.context, context),
            "bootstrap resources use a different context"
        );
    }

    /// Rebind a checked compatible KS key without replacing input scratch.
    /// The owning composition/rebinding boundary validates the replacement first.
    pub(crate) fn rebind_input_key_switching_key(
        &mut self,
        key: &'a FourierGlweKeySwitchingKey<T>,
    ) {
        if let InputPreparation::Keyswitch { key_switching, .. } = &mut self.input {
            key_switching.key = key;
        }
    }

    /// Temporarily bind product scratch to the requested decomposition layout.
    /// CBS and BR can use different level counts; restore the BR layout on return
    /// or unwind, retaining the same GLWE geometry, allocations and FFT engine.
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(
            &mut primus_lattice::workspace::FourierGlweExternalProductWorkspace<T>,
            &mut FftEngine<'a, Table>,
        ) -> R,
    ) -> R {
        let fft = &mut self.fft;
        let operation =
            |scratch: &mut primus_lattice::workspace::FourierGlweExternalProductWorkspace<T>| {
                operation(scratch, fft)
            };
        match &mut self.blind_rotation {
            BlindRotationResources::Classic { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
            BlindRotationResources::Sparse { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
        }
    }

    /// Prepare the small input for the bound order and write coefficient-domain
    /// BR under the accumulator secret. The boundary checked input/LUT geometry.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) -> (&GlweCiphertext<Vec<T>>, &mut FftEngine<'a, Table>) {
        let parameters = self.context.parameters();
        let small_lwe = match &mut self.input {
            InputPreparation::Direct => input,
            InputPreparation::Keyswitch {
                key_switching: ks,
                small_lwe,
            } => {
                let glwe = parameters.blind_rotation_ggsw();
                input.inverse_extract_glwe_to(
                    &mut self.accumulator,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                ks.key.key_switch_to(
                    &self.accumulator,
                    &mut ks.switched,
                    &mut self.fft,
                    &mut ks.scratch,
                );
                ks.switched.extract_compact_lwe_to(
                    small_lwe,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                small_lwe.as_view()
            }
        };
        match &mut self.blind_rotation {
            BlindRotationResources::Classic { key, scratch } => key
                .fourier_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    &mut self.fft,
                    scratch,
                ),
            BlindRotationResources::Sparse { key, scratch } => scratch
                .blind_rotate_interleaved_lookup_table_kernel_to(
                    key,
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    &mut self.fft,
                ),
        }
        (&self.accumulator, &mut self.fft)
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Prepares common resources from a complete PBS key bundle.
    /// Selects input KS only for KS→BR; BR→KS borrows only the BR key and allocates
    /// no output-KS scratch. For independently generated material, use
    /// [`Self::bootstrap_resources`]. CBS material is bound separately by its evaluator.
    ///
    /// # Correctness
    /// Inherits [`BootstrapResources::try_new`]'s secret and transform requirements.
    pub fn bootstrap_resources_from_server_key<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError> {
        let input_key_switching_key = (self.parameters().pbs_order()
            == PbsOrder::KeyswitchBootstrap)
            .then_some(server_key.glwe_key_switching_key());
        self.bootstrap_resources(server_key.blind_rotation_key(), input_key_switching_key)
    }

    /// Prepares BR/EP resources and the input KS required by KS→BR.
    /// Inherits [`BootstrapResources::try_new`]'s material requirements.
    pub fn bootstrap_resources<'a>(
        &'a self,
        blind_rotation_key: &'a BlindRotationKey<T>,
        input_key_switching_key: Option<&'a FourierGlweKeySwitchingKey<T>>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError> {
        BootstrapResources::try_new(self, blind_rotation_key, input_key_switching_key)
    }
}
