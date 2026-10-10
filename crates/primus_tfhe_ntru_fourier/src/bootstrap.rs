//! Shared input/BR bindings and reusable storage for serial PBS/CBS composition.
//! Standalone resources omit the ordinary PBS output-return stage.

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;

use crate::{
    Lwe, TfheContext,
    blind_rotation::{BlindRotationResources, blind_rotate_lookup_table_to},
    key::BlindRotationKey,
};

/// Shared Fourier blind-rotation, coefficient, FFT and external-product resources.
///
/// Ordinary [`crate::Evaluator`] owns these. Standalone CBS/one-hot callers can
/// prepare them directly and borrow them for each operation. No return buffers
/// are included, and reusing these resources online requires no allocation.
/// Context, keys and the FFT table are borrowed; BR buffers and the FFT engine
/// are owned here.
/// Serial operations can lend one instance to each other; concurrent requests
/// need independent mutable resources and may share the immutable context/keys.
pub struct BootstrapResources<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) blind_rotation_key: &'a BlindRotationKey<T>,
    pub(crate) blind_rotation: BlindRotationResources<'a, T>,
    pub(crate) fft: FftEngine<'a, Table>,
}

impl<'a, T, Table, LM> BootstrapResources<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Allocates shared BR/coefficient/FFT/external-product storage after checking the BR key.
    /// Includes classic or sparse scratch, but no return, CBS projection or MVB buffers.
    ///
    /// # Correctness
    /// The key must use this context's FFT table instance and intended secrets;
    /// parameter compatibility does not establish this identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !blind_rotation_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }
        Ok(Self {
            context,
            blind_rotation_key,
            blind_rotation: BlindRotationResources::new(context.parameters(), blind_rotation_key),
            fft: context.new_fft_engine(),
        })
    }

    /// Borrows the bound context; the same context/key binding can have multiple
    /// independent resource instances, for example one per worker.
    #[must_use]
    pub fn context(&self) -> &'a TfheContext<T, Table, LM> {
        self.context
    }

    /// Borrows the FFT engine and external-product scratch for serial products
    /// between BR/CBS calls. Subsequent operations overwrite scratch before reading it.
    ///
    /// # Correctness
    /// Preserve the engine's table identity and both workspaces' polynomial lengths.
    /// Scratch does not establish a product's key, basis or scale compatibility.
    #[must_use]
    pub fn external_product_workspaces(
        &mut self,
    ) -> (
        &mut FftEngine<'a, Table>,
        &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
    ) {
        (
            &mut self.fft,
            self.blind_rotation.rotation.external_product(),
        )
    }

    /// Rejects a different context before scratch/output writes. Prepared CBS,
    /// one-hot and MVB state depends on the context, not individual BR controls.
    /// Classic/sparse resources may be interchanged only when actual secrets
    /// match; pointer equality does not establish that secret identity.
    pub(crate) fn check_context(&self, context: &TfheContext<T, Table, LM>) {
        assert!(
            core::ptr::eq(self.context, context),
            "bootstrap resources use a different context binding"
        );
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
            &mut self.blind_rotation,
            parameters,
            &mut self.fft,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares shared BR/FFT/EP resources without any LWE return buffers.
    /// Inherits [`BootstrapResources::try_new`]'s key/transform requirements.
    pub fn bootstrap_resources<'a>(
        &'a self,
        key: &'a BlindRotationKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table, LM>, TfheEvaluationError> {
        BootstrapResources::try_new(self, key)
    }
}
