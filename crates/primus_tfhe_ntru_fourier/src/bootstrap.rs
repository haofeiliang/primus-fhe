use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;
use primus_tfhe::{LweCiphertext, TfheEvaluationError};

use crate::{
    Evaluator, ServerKey, TfheContext,
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
    pub(crate) server_key: &'a ServerKey<T>,
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
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !server_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }
        Ok(Self {
            context,
            server_key,
            workspace: BlindRotationWorkspace::new(context.parameters(), server_key),
            fft: context.new_fft_engine(),
        })
    }

    /// Writes the coefficient-domain BR result under the accumulator secret.
    /// The owning boundary checked input/LUT geometry; no client return occurs.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) {
        let parameters = self.context.parameters();
        blind_rotate_lookup_table_to(
            self.server_key,
            input.as_view(),
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

    /// Complete only the standalone state; a retained PBS is moved unchanged.
    #[must_use]
    pub(crate) fn into_bootstrapper(self) -> Evaluator<'a, T, Table, LM> {
        match self {
            Self::Standalone(engine) => Evaluator::from_engine(engine),
            Self::Bootstrapper(pbs) => pbs,
        }
    }
}
