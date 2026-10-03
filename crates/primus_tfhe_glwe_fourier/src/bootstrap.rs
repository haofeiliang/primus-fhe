use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingWorkspace, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BootstrappingKey, Evaluator, FourierGlweBlindRotationWorkspace, FourierGlweBootstrappingKey,
    Lwe, ServerKey, SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey, TfheContext,
};

/// Reusable ring key-switch scratch shared by input preparation and result return.
/// Its caller chooses the stage at construction, not through missing resources.
pub(crate) struct KeySwitchingWorkspace<T: TorusFftValue> {
    pub(crate) scratch: FourierGlweKeySwitchingWorkspace<T>,
    pub(crate) switched: GlweCiphertext<Vec<T>>,
}

impl<T: TorusFftValue> KeySwitchingWorkspace<T> {
    #[must_use]
    pub(crate) fn new(parameters: &crate::TfheParameters<T>) -> Self {
        Self {
            scratch: FourierGlweKeySwitchingWorkspace::new(
                parameters.glwe_key_switching().output().glwe_size(),
            ),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
        }
    }
}

/// Pair each selected key with its own scratch; only one algorithm is allocated.
enum BlindRotation<'a, T: TorusFftValue> {
    Classic {
        key: &'a FourierGlweBootstrappingKey<T, NativeModulus<T>>,
        scratch: FourierGlweBlindRotationWorkspace<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T>,
        scratch: SparseGlweBlindRotationWorkspace<T>,
    },
}

/// KS→BR requires a compact small-LWE input; BR→KS consumes the external input directly.
enum InputPreparation<T: TorusFftValue> {
    Direct,
    Keyswitch {
        workspace: KeySwitchingWorkspace<T>,
        small_lwe: LweCiphertext<T>,
    },
}

/// Owns the input preparation, selected BR algorithm, accumulator and transform scratch.
/// Independent CBS does not require the ordinary PBS output stage.
pub(crate) struct BlindRotationEngine<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) server_key: &'a ServerKey<T>,
    pub(crate) fft: FftEngine<'a, Table>,
    blind_rotation: BlindRotation<'a, T>,
    input: InputPreparation<T>,
    // Coefficient GLWE under the accumulator secret after either BR order.
    pub(crate) accumulator: GlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> BlindRotationEngine<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !server_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }

        Ok(Self {
            context,
            server_key,
            fft: context.new_fft_engine(),
            blind_rotation: match server_key.bootstrapping_key() {
                BootstrappingKey::Classic(key) => BlindRotation::Classic {
                    key,
                    scratch: FourierGlweBlindRotationWorkspace::new(key),
                },
                BootstrappingKey::Sparse(key) => BlindRotation::Sparse {
                    key,
                    scratch: SparseGlweBlindRotationWorkspace::new(key),
                },
            },
            input: match parameters.pbs_order() {
                PbsOrder::BootstrapKeyswitch => InputPreparation::Direct,
                PbsOrder::KeyswitchBootstrap => InputPreparation::Keyswitch {
                    workspace: KeySwitchingWorkspace::new(parameters),
                    small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension().get()),
                },
            },
            accumulator: GlweCiphertext::zero(parameters.blind_rotation_ggsw().glwe_len()),
        })
    }

    /// Bind product scratch to the requested basis without allocating; CBS and
    /// BR may use different compatible bases, so each operation establishes it.
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
            BlindRotation::Classic { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
            BlindRotation::Sparse { scratch, .. } => scratch.with_external_product(size, operation),
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
                workspace: ks,
                small_lwe,
            } => {
                let glwe = parameters.blind_rotation_ggsw();
                input.inverse_extract_glwe_to(
                    &mut self.accumulator,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                self.server_key.glwe_key_switching_key().key_switch_to(
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
            BlindRotation::Classic { key, scratch } => key
                .fourier_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    &mut self.fft,
                    scratch,
                ),
            BlindRotation::Sparse { key, scratch } => key
                .fourier_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    &mut self.fft,
                    scratch,
                ),
        }
        (&self.accumulator, &mut self.fft)
    }
}

/// Standalone BR→KS CBS omits only output KS; KS→BR already has all PBS resources.
/// A CBS constructed from PBS retains that complete evaluator for reuse/recovery.
pub(crate) enum CircuitBootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    Standalone(BlindRotationEngine<'a, T, Table>),
    Bootstrapper(Evaluator<'a, T, Table>),
}

impl<'a, T, Table> CircuitBootstrapResources<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let engine = BlindRotationEngine::try_new(context, server_key)?;
        Ok(match context.parameters().pbs_order() {
            PbsOrder::BootstrapKeyswitch => Self::Standalone(engine),
            PbsOrder::KeyswitchBootstrap => Self::Bootstrapper(Evaluator::from_engine(engine)),
        })
    }

    #[must_use]
    pub(crate) fn engine(&self) -> &BlindRotationEngine<'a, T, Table> {
        match self {
            Self::Standalone(engine) => engine,
            Self::Bootstrapper(pbs) => &pbs.engine,
        }
    }

    #[must_use]
    pub(crate) fn engine_mut(&mut self) -> &mut BlindRotationEngine<'a, T, Table> {
        match self {
            Self::Standalone(engine) => engine,
            Self::Bootstrapper(pbs) => &mut pbs.engine,
        }
    }

    #[must_use]
    pub(crate) fn bootstrapper_mut(&mut self) -> Option<&mut Evaluator<'a, T, Table>> {
        match self {
            Self::Standalone(_) => None,
            Self::Bootstrapper(pbs) => Some(pbs),
        }
    }

    /// Only standalone BR→KS must allocate an output KS workspace here.
    #[must_use]
    pub(crate) fn into_bootstrapper(self) -> Evaluator<'a, T, Table> {
        match self {
            Self::Standalone(engine) => Evaluator::from_engine(engine),
            Self::Bootstrapper(pbs) => pbs,
        }
    }
}
