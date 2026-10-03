use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BootstrappingKey, Evaluator, Lwe, NttGlweBlindRotationWorkspace, NttGlweBootstrappingKey,
    SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey, TfheContext,
};

/// Ring key-switch material bound to its reusable scratch and output.
/// The selected PBS order places this complete stage before or after BR.
pub(crate) struct KeySwitchingWorkspace<'a, T: FheUint> {
    pub(crate) key: &'a NttGlweKeySwitchingKey<T>,
    pub(crate) scratch: NttGlweKeySwitchingWorkspace<T>,
    pub(crate) switched: GlweCiphertext<Vec<T>>,
}

impl<'a, T: FheUint> KeySwitchingWorkspace<'a, T> {
    #[must_use]
    pub(crate) fn new(
        parameters: &crate::TfheParameters<T>,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            key,
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
        key: &'a NttGlweBootstrappingKey<T, BarrettModulus<T>>,
        scratch: NttGlweBlindRotationWorkspace<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T>,
        scratch: SparseGlweBlindRotationWorkspace<T>,
    },
}

/// KS→BR requires a compact small-LWE input; BR→KS consumes the external input directly.
enum InputPreparation<'a, T: FheUint> {
    Direct,
    Keyswitch {
        workspace: KeySwitchingWorkspace<'a, T>,
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
    blind_rotation: BlindRotation<'a, T>,
    input: InputPreparation<'a, T>,
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
        bootstrapping_key: &'a BootstrappingKey<T>,
        key_switching_key: Option<&'a NttGlweKeySwitchingKey<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !bootstrapping_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }

        // Validate supplied material even when BR→KS does not use it in this engine.
        // KS→BR must reject missing material before allocating any scratch.
        if let Some(key) = key_switching_key {
            crate::key::check_glwe_key_switching_key(parameters, key)?;
        } else if parameters.pbs_order() == PbsOrder::KeyswitchBootstrap {
            return Err(TfheEvaluationError::MissingGlweKeySwitchingKey);
        }

        Ok(Self {
            context,
            blind_rotation: match bootstrapping_key {
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
                    workspace: KeySwitchingWorkspace::new(
                        parameters,
                        key_switching_key.expect("KS→BR material was checked above"),
                    ),
                    small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension().get()),
                },
            },
            accumulator: GlweCiphertext::zero(parameters.blind_rotation_ggsw().glwe_len()),
        })
    }

    /// Rebind a checked compatible KS key without replacing input scratch.
    /// Used only when converting CBS back to PBS with explicitly supplied material.
    pub(crate) fn rebind_input_key_switching_key(&mut self, key: &'a NttGlweKeySwitchingKey<T>) {
        if let InputPreparation::Keyswitch { workspace, .. } = &mut self.input {
            workspace.key = key;
        }
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
                let glwe = parameters.blind_rotation_ggsw();
                input.inverse_extract_glwe_to(
                    &mut self.accumulator,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                ks.key.key_switch_to(
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
                    parameters.blind_rotation_ggsw().cipher_modulus(),
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
        bootstrapping_key: &'a BootstrappingKey<T>,
        key_switching_key: Option<&'a NttGlweKeySwitchingKey<T>>,
    ) -> Result<Self, TfheEvaluationError> {
        let engine = BlindRotationEngine::try_new(context, bootstrapping_key, key_switching_key)?;
        Ok(match context.parameters().pbs_order() {
            PbsOrder::BootstrapKeyswitch => Self::Standalone(engine),
            PbsOrder::KeyswitchBootstrap => Self::Bootstrapper(Evaluator::from_engine(
                engine,
                key_switching_key.expect("KS→BR engine requires KS material"),
            )),
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

    /// Check the explicit KS material, retaining existing PBS buffers when present.
    /// Only standalone BR→KS allocates its missing output KS workspace.
    pub(crate) fn try_into_bootstrapper(
        self,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        crate::key::check_glwe_key_switching_key(self.engine().context.parameters(), key)?;
        Ok(match self {
            Self::Standalone(engine) => Evaluator::from_engine(engine, key),
            Self::Bootstrapper(mut pbs) => {
                pbs.rebind_key_switching_key(key);
                pbs
            }
        })
    }
}
