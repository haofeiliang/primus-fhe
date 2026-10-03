use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BootstrappingKey, Evaluator, Lwe, NttGlweBlindRotationWorkspace, NttGlweBootstrappingKey,
    ServerKey, SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey, TfheContext,
};

/// Reusable ring key-switch scratch shared by input preparation and result return.
/// Its caller chooses the stage at construction, not through missing resources.
pub(crate) struct KeySwitchingWorkspace<T: FheUint> {
    pub(crate) scratch: NttGlweKeySwitchingWorkspace<T>,
    pub(crate) switched: GlweCiphertext<Vec<T>>,
}

impl<T: FheUint> KeySwitchingWorkspace<T> {
    #[must_use]
    pub(crate) fn new(parameters: &crate::TfheParameters<T>) -> Self {
        Self {
            scratch: NttGlweKeySwitchingWorkspace::new(
                parameters.glwe_key_switching().output().glwe_size(),
            ),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
        }
    }
}

/// Pair each selected key with its own scratch; only one algorithm is allocated.
enum BlindRotation<'a, T: FheUint> {
    Classic {
        key: &'a NttGlweBootstrappingKey<T, primus_modulus::BarrettModulus<T>>,
        scratch: NttGlweBlindRotationWorkspace<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T>,
        scratch: SparseGlweBlindRotationWorkspace<T>,
    },
}

/// KS→BR requires a compact small-LWE input; BR→KS consumes the external input directly.
enum InputPreparation<T: FheUint> {
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) server_key: &'a ServerKey<T>,
    blind_rotation: BlindRotation<'a, T>,
    input: InputPreparation<T>,
    // Coefficient GLWE under the accumulator secret after either BR order.
    pub(crate) accumulator: GlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> BlindRotationEngine<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
            blind_rotation: match server_key.bootstrapping_key() {
                BootstrappingKey::Classic(key) => BlindRotation::Classic {
                    key,
                    scratch: NttGlweBlindRotationWorkspace::new(key),
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
            accumulator: GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len()),
        })
    }

    /// Bind product scratch to the requested basis without allocating; CBS and
    /// BR may use different compatible bases, so each operation establishes it.
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut primus_lattice::workspace::NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
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
    ) -> &GlweCiphertext<Vec<T>> {
        let parameters = self.context.parameters();
        let small_lwe = match &mut self.input {
            InputPreparation::Direct => input,
            InputPreparation::Keyswitch {
                workspace: ks,
                small_lwe,
            } => {
                let glwe = parameters.accumulator_glwe();
                input.inverse_extract_glwe_to(
                    &mut self.accumulator,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                self.server_key.glwe_key_switching_key().key_switch_to(
                    &self.accumulator,
                    &mut ks.switched,
                    glwe.cipher_modulus(),
                    self.context.table(),
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
                .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    parameters.accumulator_glwe().cipher_modulus(),
                    self.context.table(),
                    scratch,
                ),
            BlindRotation::Sparse { key, scratch } => key
                .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    rotation_step,
                    self.accumulator.as_mut_view(),
                    self.context.table(),
                    scratch,
                ),
        }
        &self.accumulator
    }
}

/// Standalone BR→KS CBS omits only output KS; KS→BR already has all PBS resources.
/// A CBS constructed from PBS retains that complete evaluator for reuse/recovery.
pub(crate) enum CircuitBootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    Standalone(BlindRotationEngine<'a, T, Table>),
    Bootstrapper(Evaluator<'a, T, Table>),
}

impl<'a, T, Table> CircuitBootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
