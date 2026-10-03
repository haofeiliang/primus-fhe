use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::TfheEvaluationError;

use crate::{
    BlindRotationKey, Lwe, TfheContext,
    blind_rotation::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Shared NTT blind-rotation, coefficient and external-product resources.
///
/// Ordinary [`crate::Evaluator`] owns these. Standalone CBS/one-hot callers can
/// prepare them directly and borrow them for each operation. No return buffers
/// are included, and reusing these resources online requires no allocation.
pub struct BootstrapResources<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) blind_rotation_key: &'a BlindRotationKey<T>,
    pub(crate) workspace: BlindRotationWorkspace<'a, T>,
}

impl<'a, T, Table, LM> BootstrapResources<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Allocates shared BR/coefficient/external-product storage after checking the BR key.
    /// Includes classic or sparse scratch, but no return, CBS projection or MVB buffers.
    ///
    /// # Correctness
    /// The key must use this context's NTT representation and intended secrets;
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
            workspace: BlindRotationWorkspace::new(context.parameters(), blind_rotation_key),
        })
    }

    /// Borrows the bound context; the same context/key binding can have multiple
    /// independent resource instances, for example one per worker.
    #[must_use]
    pub fn context(&self) -> &'a TfheContext<T, Table, LM> {
        self.context
    }

    /// Borrows shared external-product scratch between BR/CBS operations.
    /// The next operation overwrites scratch before reading it.
    ///
    /// # Correctness
    /// Preserve its polynomial length and the called kernel's modulus, basis,
    /// transform and secret requirements. Scratch alone proves none of these.
    #[must_use]
    pub fn external_product_workspace(
        &mut self,
    ) -> &mut primus_ntru::NttNtruExternalProductWorkspace<T> {
        self.workspace.rotation.external_product()
    }

    /// Records which parameter/control binding an operation's prepared buffers use.
    pub(crate) fn binding(&self) -> BootstrapBinding<'a, T, Table, LM> {
        BootstrapBinding {
            context: self.context,
            blind_rotation_key: self.blind_rotation_key,
        }
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
            self.context.table(),
        );
    }
}

/// Read-only binding retained by CBS/one-hot/MVB while common buffers are borrowed
/// only during execution. Pointer checks protect the prepared geometry/control
/// choice, not the mathematical identity of independently generated material.
pub(crate) struct BootstrapBinding<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    blind_rotation_key: &'a BlindRotationKey<T>,
}

impl<T, Table, LM> BootstrapBinding<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Check the new public resource-borrow boundary before any scratch/output writes.
    /// Separate resource instances prepared from these same references are allowed.
    pub(crate) fn check(&self, resources: &BootstrapResources<'_, T, Table, LM>) {
        assert!(
            core::ptr::eq(self.context, resources.context)
                && core::ptr::eq(self.blind_rotation_key, resources.blind_rotation_key),
            "bootstrap resources use a different context or blind-rotation key binding"
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares shared BR/EP resources without any LWE return buffers.
    /// Inherits [`BootstrapResources::try_new`]'s key/transform requirements.
    pub fn bootstrap_resources<'a>(
        &'a self,
        key: &'a BlindRotationKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table, LM>, TfheEvaluationError> {
        BootstrapResources::try_new(self, key)
    }
}
