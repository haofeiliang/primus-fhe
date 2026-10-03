use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;

use crate::{
    BlindRotationKey, Evaluator, Lwe, TfheContext,
    blind_rotation::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Binds the selected BR controls, accumulator and scratch to one context.
/// CBS can own this without allocating client-return buffers.
pub(crate) struct BlindRotationEngine<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) blind_rotation_key: &'a BlindRotationKey<T>,
    pub(crate) workspace: BlindRotationWorkspace<'a, T>,
    pub(crate) fft: FftEngine<'a, Table>,
}

impl<'a, T, Table, LM> BlindRotationEngine<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !blind_rotation_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }
        Ok(Self {
            context,
            blind_rotation_key,
            workspace: BlindRotationWorkspace::new(context.parameters(), blind_rotation_key),
            fft: context.new_fft_engine(),
        })
    }

    /// Writes the coefficient-domain BR result under the accumulator secret.
    /// The owning boundary checked input/LUT geometry; no client return occurs.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) {
        let parameters = self.context.parameters();
        blind_rotate_lookup_table_to(
            self.blind_rotation_key,
            input,
            lookup_table.as_view(),
            rotation_step,
            &mut self.workspace,
            parameters,
            &mut self.fft,
        );
    }
}

/// Standalone CBS owns only BR resources; conversion from PBS retains its full
/// evaluator for allocation-free alternation and recovery.
pub(crate) enum CircuitBootstrapResources<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    Standalone(BlindRotationEngine<'a, T, Table, LM>),
    Bootstrapper(Evaluator<'a, T, Table, LM>),
}

impl<'a, T, Table, LM> CircuitBootstrapResources<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    #[must_use]
    pub(crate) fn engine(&self) -> &BlindRotationEngine<'a, T, Table, LM> {
        match self {
            Self::Standalone(engine) => engine,
            Self::Bootstrapper(pbs) => &pbs.engine,
        }
    }

    #[must_use]
    pub(crate) fn engine_mut(&mut self) -> &mut BlindRotationEngine<'a, T, Table, LM> {
        match self {
            Self::Standalone(engine) => engine,
            Self::Bootstrapper(pbs) => &mut pbs.engine,
        }
    }

    #[must_use]
    pub(crate) fn bootstrapper_mut(&mut self) -> Option<&mut Evaluator<'a, T, Table, LM>> {
        match self {
            Self::Standalone(_) => None,
            Self::Bootstrapper(pbs) => Some(pbs),
        }
    }

    /// Binds the requested return material. Recovering a retained PBS under a
    /// compatible key reuses its buffers; standalone CBS prepares missing return buffers.
    pub(crate) fn try_into_bootstrapper(
        self,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<Evaluator<'a, T, Table, LM>, TfheEvaluationError> {
        self.engine()
            .context
            .parameters()
            .check_lwe_return_key(return_key)?;
        Ok(match self {
            Self::Standalone(engine) => Evaluator::from_engine(engine, return_key),
            Self::Bootstrapper(mut pbs) => {
                // Compatibility fixes N and target dimension, so only the binding
                // changes. Pending samples belong to the previous binding.
                pbs.batch_return.discard_batch();
                pbs.lwe_return = crate::LweReturnEvaluator::new(
                    return_key,
                    pbs.engine
                        .context
                        .parameters()
                        .external_lwe()
                        .cipher_modulus(),
                );
                pbs
            }
        })
    }
}
